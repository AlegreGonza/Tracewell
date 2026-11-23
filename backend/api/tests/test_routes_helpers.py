"""Tests directos de los helpers de backend/api/routes/analysis.py y backend/api/routes/live.py."""
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.routes.analysis import Filters, FiltersDep, PageDep, _analyze_path, _json_attachment, _partial_stats
from backend.api.routes.live import (
    LiveStartRequest, _make_capture, _release_previous, _start_or_cleanup, _stop_and_analyze,
)
from backend.controllers.state import Ctx, _State, summary
from backend.domain.analysis.analyzer import MAX_PAGE, analyze
from backend.domain.pcap.live import CaptureError, CaptureStateError, LiveCapture, PermissionDenied
from backend.domain.pcap.reader import iter_packets
from backend.domain.rules.engine import load_rules
from backend.domain.sessions.query import compute_stats

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "samples" / "demo.pcap"


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "rules")


@pytest.fixture(scope="module")
def an(rules):
    return analyze(DEMO, rules)


class FakeSource:
    def __init__(self, start_exc=None):
        self.start_exc = start_exc
        self.on_packet = None

    def start(self, on_packet):
        if self.start_exc:
            raise self.start_exc
        self.on_packet = on_packet

    def stop(self):
        pass


def make_ctx(rules, live_dir=None, source=None):
    return Ctx(state=_State(), rules=rules, samples_dir=ROOT / "samples", live_dir=live_dir,
               make_source=lambda iface: source or FakeSource(), interface_lister=None, analyze=analyze)


# ---------------------------------------------------------------- Filters / Page

@pytest.fixture
def mini():
    app = FastAPI()

    @app.get("/f")
    def f(filters: FiltersDep):
        return {"given": filters.given(), "all": [filters.protocol, filters.ip, filters.port]}

    @app.get("/p")
    def p(page: PageDep):
        return {"limit": page.limit, "offset": page.offset}

    return TestClient(app)


def test_filters_defaults(mini):
    # sin parámetros, Filters no tiene ningún filtro dado
    assert mini.get("/f").json() == {"given": {}, "all": [None, None, None]}


def test_filters_given_solo_los_mandados(mini):
    # given() devuelve solo los filtros enviados (port=0 cuenta)
    r = mini.get("/f", params={"protocol": "TCP", "port": 0}).json()
    assert r["given"] == {"protocol": "TCP", "port": 0}


@pytest.mark.parametrize("port,code", [(0, 200), (65535, 200), (-1, 422), (65536, 422), ("x", 422)])
def test_filters_limites_de_port(mini, port, code):
    # port acepta 0..65535 y rechaza el resto con 422
    assert mini.get("/f", params={"port": port}).status_code == code


def test_page_defaults(mini):
    # Page por defecto: limit=100, offset=0
    assert mini.get("/p").json() == {"limit": 100, "offset": 0}


@pytest.mark.parametrize("params,code", [
    ({"limit": 1}, 200), ({"limit": MAX_PAGE}, 200), ({"limit": 0}, 422),
    ({"limit": MAX_PAGE + 1}, 422), ({"offset": 0}, 200), ({"offset": -1}, 422),
])
def test_page_limites(mini, params, code):
    # limit en 1..MAX_PAGE y offset >= 0, si no 422
    assert mini.get("/p", params=params).status_code == code


def test_max_page_es_1000():
    # MAX_PAGE (tope del limit) vale 1000
    assert MAX_PAGE == 1000


# ---------------------------------------------------------------- _partial_stats / _json_attachment / _analyze_path

def test_partial_stats_copia_truncated_y_untracked(an):
    # _partial_stats toma truncated/untracked de la captura, no de lo filtrado
    fake = SimpleNamespace(result=SimpleNamespace(sessions=an.result.sessions, truncated=True, untracked_packets=7))
    out = _partial_stats(fake, Filters(protocol="TCP", ip=None, port=None))
    assert out["truncated"] is True and out["untracked_packets"] == 7


def test_partial_stats_cifras_del_filtro(an):
    # las cifras de _partial_stats corresponden a las sesiones filtradas
    f = Filters(protocol="TCP", ip=None, port=None)
    expected = compute_stats(f.apply(an))
    assert _partial_stats(an, f)["sessions"] == expected.sessions


def test_json_attachment_cabeceras():
    # _json_attachment: media type JSON, Content-Disposition con nombre fijo y cuerpo intacto
    r = _json_attachment('{"a": 1}')
    assert r.media_type == "application/json"
    assert r.headers["content-disposition"] == 'attachment; filename="tracewell-report.json"'
    assert json.loads(r.body) == {"a": 1}


def test_analyze_path_ok_deja_analisis_actual(rules):
    # _analyze_path devuelve el summary y lo deja como análisis actual
    ctx = make_ctx(rules)
    out = _analyze_path(ctx, DEMO)
    assert out == summary(ctx.state.analysis) and out["source"] == "demo.pcap"


def test_analyze_path_inexistente(rules, tmp_path):
    # ruta inexistente -> FileNotFoundError y el análisis actual no cambia
    ctx = make_ctx(rules)
    with pytest.raises(FileNotFoundError):
        _analyze_path(ctx, tmp_path / "no.pcap")
    assert ctx.state.analysis is None


def test_analyze_path_carpeta(rules, tmp_path):
    # una carpeta -> IsADirectoryError (o PermissionError en Windows al abrirla)
    ctx = make_ctx(rules)
    with pytest.raises((IsADirectoryError, PermissionError)):
        _analyze_path(ctx, tmp_path)


# ---------------------------------------------------------------- routes_live

def test_make_capture_usa_live_dir_con_nombre_unico(rules, tmp_path):
    # con live_dir el pcap va ahí con nombre live-*.pcap, distinto en cada captura
    ctx = make_ctx(rules, live_dir=tmp_path)
    req = LiveStartRequest(interface="eth0")
    a = _make_capture(ctx, req)
    b = _make_capture(ctx, req)
    assert a.path.parent == tmp_path and a.path.name.startswith("live-") and a.path.suffix == ".pcap"
    assert a.path != b.path and a.temp_dir is None


def test_make_capture_sin_live_dir_usa_temp_propia(rules):
    # sin live_dir LiveCapture crea su carpeta temporal propia
    cap = _make_capture(make_ctx(rules), LiveStartRequest(interface="eth0"))
    try:
        assert cap.temp_dir is not None and cap.temp_dir.exists()
    finally:
        cap.cleanup()


def test_make_capture_limites_por_defecto_y_custom(rules, tmp_path):
    # sin límites usa los defaults; con límites los respeta; no inicia la captura
    ctx = make_ctx(rules, live_dir=tmp_path)
    cap = _make_capture(ctx, LiveStartRequest(interface="eth0", max_packets=5, max_seconds=2.5))
    assert (cap._max_packets, cap._max_seconds) == (5, 2.5) and not cap.running
    assert _make_capture(ctx, LiveStartRequest(interface="eth0"))._max_packets > 5


def test_make_capture_pasa_la_interfaz_a_la_fuente(rules, tmp_path):
    # la interfaz pedida llega a make_source
    seen = []
    ctx = make_ctx(rules, live_dir=tmp_path)
    ctx.make_source = lambda i: seen.append(i) or FakeSource()
    _make_capture(ctx, LiveStartRequest(interface="wlan9"))
    assert seen == ["wlan9"]


def test_release_previous_sin_captura_previa():
    # sin captura previa no hace nada
    _release_previous(_State())


def test_release_previous_rechaza_si_corre(rules):
    # una captura previa en curso -> CaptureStateError
    state = _State()
    state.live = _make_capture(make_ctx(rules), LiveStartRequest(interface="e"))
    state.live.start()
    try:
        with pytest.raises(CaptureStateError):
            _release_previous(state)
    finally:
        state.live.stop()
        state.live.cleanup()


def test_release_previous_borra_temp_de_captura_terminada(rules):
    # captura terminada cuya carpeta no usa el análisis -> se borra
    state = _State()
    cap = _make_capture(make_ctx(rules), LiveStartRequest(interface="e"))
    cap.start()
    cap.stop()
    state.live = cap
    _release_previous(state)
    assert not cap.temp_dir.exists()


def test_release_previous_no_borra_carpeta_del_analisis_actual(rules):
    # si el análisis actual depende de la carpeta temporal, NO se borra
    state = _State()
    cap = _make_capture(make_ctx(rules), LiveStartRequest(interface="e"))
    cap.start()
    cap.stop()
    state.live, state.owned_dir = cap, cap.temp_dir
    try:
        _release_previous(state)
        assert cap.temp_dir.exists()
    finally:
        cap.cleanup()


def test_start_or_cleanup_ok_inicia(rules):
    # start OK deja la captura corriendo y la carpeta temporal intacta
    cap = _make_capture(make_ctx(rules), LiveStartRequest(interface="e"))
    try:
        _start_or_cleanup(cap)
        assert cap.running and cap.temp_dir.exists()
    finally:
        cap.stop()
        cap.cleanup()


@pytest.mark.parametrize("exc", [PermissionDenied("sin permiso"), CaptureError("falla"), KeyboardInterrupt()])
def test_start_or_cleanup_falla_limpia_y_relanza(rules, exc):
    # si start() falla, borra la carpeta temporal y relanza la misma excepción
    ctx = make_ctx(rules, source=FakeSource(start_exc=exc))
    cap = _make_capture(ctx, LiveStartRequest(interface="e"))
    temp = cap.temp_dir
    assert temp.exists()
    with pytest.raises(type(exc)):
        _start_or_cleanup(cap)
    assert not temp.exists() and not cap.running


def _feed(cap, n=5):
    for i, p in enumerate(iter_packets(DEMO)):
        if i >= n:
            break
        cap._source.on_packet(p.ts, p.data)


def test_stop_and_analyze_arma_respuesta(rules, tmp_path):
    # detiene, analiza el pcap, guarda live_result y fija owned_dir
    ctx = make_ctx(rules)
    cap = _make_capture(ctx, LiveStartRequest(interface="e"))
    cap.start()
    _feed(cap, 5)
    out = _stop_and_analyze(ctx, cap)
    assert out is ctx.state.live_result
    assert out["capture"]["packets"] == 5 and out["capture"]["reason"] == "manual"
    assert set(out["capture"]) == {"packets", "bytes", "seconds", "reason", "warning"}
    assert out["analysis"]["source"] == "live.pcap"
    assert ctx.state.owned_dir == cap.temp_dir and ctx.state.analysis is not None
    ctx.state.analysis = None
    cap.cleanup()


def test_stop_and_analyze_idempotente_sobre_captura(rules):
    # llamarlo dos veces sobre la misma captura ya detenida no falla y da el mismo resumen
    ctx = make_ctx(rules)
    cap = _make_capture(ctx, LiveStartRequest(interface="e"))
    cap.start()
    _feed(cap, 3)
    a = _stop_and_analyze(ctx, cap)
    b = _stop_and_analyze(ctx, cap)
    assert a["capture"] == b["capture"] and a["analysis"] == b["analysis"]
    assert ctx.state.owned_dir == cap.temp_dir and cap.temp_dir.exists()
    cap.cleanup()


def test_stop_and_analyze_sin_iniciar(rules):
    # una captura nunca iniciada -> CaptureStateError y el estado queda intacto
    ctx = make_ctx(rules)
    cap = LiveCapture(FakeSource(), out_path=None)
    try:
        with pytest.raises(CaptureStateError):
            _stop_and_analyze(ctx, cap)
        assert ctx.state.live_result is None and ctx.state.analysis is None
    finally:
        cap.cleanup()


def test_live_start_request_validacion():
    # LiveStartRequest rechaza interfaz vacía y límites no positivos
    for bad in ({"interface": ""}, {"interface": "e", "max_seconds": 0}, {"interface": "e", "max_packets": 0},
                {"interface": "e", "max_seconds": 3601}):
        with pytest.raises(ValueError):
            LiveStartRequest(**bad)


def test_make_capture_200_nombres_distintos(rules, tmp_path):
    # uuid4: 200 capturas seguidas, sin pausas, nunca repiten nombre
    ctx = make_ctx(rules, live_dir=tmp_path)
    req = LiveStartRequest(interface="eth0")
    names = [_make_capture(ctx, req).path.name for _ in range(200)]
    assert len(set(names)) == 200
    assert all(re.fullmatch(r"live-[0-9a-f]{32}\.pcap", n) for n in names)
