"""Ciclo de vida de la captura en vivo: idempotencia de stop, archivos temporales, lifespan."""
import tempfile
import threading

import pytest
from fastapi.testclient import TestClient

import backend.api.app as app_mod
from backend.api.app import create_app
from backend.api.tests.test_api import make_pcap
from backend.api.tests.test_live_api import DEMO, Env, FakeSource, start
from backend.api.tests.test_live_api import env  # noqa: F401  (fixture)
from backend.domain.pcap.live import CaptureError, PermissionDenied


@pytest.fixture
def tmpdirs(tmp_path, monkeypatch):
    """Dirige tempfile.mkdtemp a una carpeta observable."""
    d = tmp_path / "sys_tmp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


def tw_dirs(d):
    return sorted(d.glob("tracewell_*"))


def make_client(start_exc=None):
    """Cliente sin live_dir (cada captura usa su carpeta temporal)."""
    sources = []

    def factory(iface):
        s = FakeSource(start_exc)
        sources.append(s)
        return s

    app = create_app(source_factory=factory, sampler_factory=None)
    return TestClient(app), sources


def go(c):
    return c.post("/api/live/start", json={"interface": "eth0"})


# ---------------------------------------------------------- stop idempotente
def test_stop_repetido_mismo_json_y_analiza_una_vez(env, monkeypatch):  # noqa: F811
    calls = []
    real = app_mod.analyze

    def spy(*a, **k):
        calls.append(a)
        return real(*a, **k)

    monkeypatch.setattr(app_mod, "analyze", spy)
    start(env)
    env.src.feed_demo(10)
    rs = [env.client.post("/api/live/stop") for _ in range(3)]
    assert all(r.status_code == 200 for r in rs)
    assert rs[0].json() == rs[1].json() == rs[2].json()
    assert len(calls) == 1


def test_stop_no_pisa_otro_analisis(env, tmp_path):  # noqa: F811
    start(env)
    env.src.feed_demo(10)
    assert env.client.post("/api/live/stop").status_code == 200
    otro = make_pcap(tmp_path / "otro.pcap")
    assert env.client.post("/api/analyze", json={"path": str(otro)}).json()["source"] == "otro.pcap"
    r = env.client.post("/api/live/stop")
    assert r.status_code == 200 and r.json()["capture"]["packets"] == 10
    assert env.client.get("/api/capture").json()["source"] == "otro.pcap"


def test_stop_tras_demo_no_pisa_el_demo(env):  # noqa: F811
    start(env)
    env.src.feed_demo(5)
    env.client.post("/api/live/stop")
    env.client.post("/api/demo")
    env.client.post("/api/live/stop")
    assert env.client.get("/api/capture").json()["source"] == "demo.pcap"


def test_nueva_captura_resetea_el_resultado_cacheado(env):  # noqa: F811
    start(env)
    env.src.feed_demo(5)
    assert env.client.post("/api/live/stop").json()["capture"]["packets"] == 5
    start(env)
    env.src.feed_demo(9)
    assert env.client.post("/api/live/stop").json()["capture"]["packets"] == 9


# ------------------------------------------------------------ con live_dir
def test_live_dir_cada_captura_un_pcap_distinto(env, tmp_path):  # noqa: F811
    start(env)
    env.src.feed_demo(5)
    env.client.post("/api/live/stop")
    start(env)
    env.src.feed_demo(8)
    env.client.post("/api/live/stop")
    pcaps = sorted(tmp_path.glob("live-*.pcap"))
    assert len(pcaps) == 2 and pcaps[0].name != pcaps[1].name
    assert not (tmp_path / "live.pcap").exists()


def test_live_dir_no_se_borra_al_reemplazar_el_analisis(env, tmp_path):  # noqa: F811
    start(env)
    env.src.feed_demo(5)
    env.client.post("/api/live/stop")
    env.client.post("/api/demo")
    assert len(list(tmp_path.glob("live-*.pcap"))) == 1  # carpeta del usuario: no es nuestra


def test_live_dir_se_conserva_al_cerrar(tmp_path):
    e = Env(tmp_path)
    with e.client as c:
        go(c)
        e.src.feed_demo(3)
        c.post("/api/live/stop")
    assert len(list(tmp_path.glob("live-*.pcap"))) == 1


# --------------------------------------------------------- sin live_dir
def test_temporal_vive_hasta_reemplazar_con_demo(tmpdirs):
    c, src = make_client()
    assert go(c).status_code == 200
    src[0].feed_demo(20)
    assert c.post("/api/live/stop").status_code == 200
    dirs = tw_dirs(tmpdirs)
    assert len(dirs) == 1 and (dirs[0] / "live.pcap").exists()
    # el detalle de paquetes relee el archivo temporal
    assert c.get("/api/packets/0").status_code == 200
    assert c.get("/api/sessions/0/packets").status_code == 200
    assert c.post("/api/demo").status_code == 200
    assert tw_dirs(tmpdirs) == []


def test_temporal_se_borra_al_reemplazar_con_analyze(tmpdirs, tmp_path):
    c, src = make_client()
    go(c)
    src[0].feed_demo(5)
    c.post("/api/live/stop")
    assert len(tw_dirs(tmpdirs)) == 1
    assert c.post("/api/analyze", json={"path": str(make_pcap(tmp_path / "x.pcap"))}).status_code == 200
    assert tw_dirs(tmpdirs) == []


def test_segunda_captura_reemplaza_y_borra_la_temporal_previa(tmpdirs):
    c, src = make_client()
    go(c)
    src[0].feed_demo(5)
    c.post("/api/live/stop")
    first = tw_dirs(tmpdirs)
    assert len(first) == 1
    # la carpeta 1 sostiene el análisis actual: no se borra al iniciar la 2da
    assert go(c).status_code == 200
    assert first[0].exists()
    assert c.get("/api/packets/0").status_code == 200
    src[1].feed_demo(6)
    c.post("/api/live/stop")
    now = tw_dirs(tmpdirs)
    assert len(now) == 1 and now != first


def test_start_limpia_carpeta_de_captura_terminada_que_nadie_usa(tmpdirs):
    c, src = make_client()
    assert go(c).status_code == 200  # captura 1 nunca se detiene ni analiza
    src[0].feed_demo(3)
    # la fuerzo a terminar sola por límite de tiempo/paquetes: max_packets
    c2, src2 = make_client()
    r = c2.post("/api/live/start", json={"interface": "eth0", "max_packets": 2})
    assert r.status_code == 200
    src2[0].feed_demo(10)
    for _ in range(300):
        if c2.get("/api/live/status").json()["state"] == "finished":
            break
        threading.Event().wait(0.01)
    assert c2.get("/api/live/status").json()["state"] == "finished"
    antes = set(tw_dirs(tmpdirs))
    assert len(antes) == 2  # la de c (en curso) y la de c2 (terminada, sin analizar)
    assert go(c2).status_code == 200
    despues = set(tw_dirs(tmpdirs))
    assert len(despues) == 2 and len(antes - despues) == 1  # la de c2 vieja se borró
    c.post("/api/live/stop")
    c2.post("/api/live/stop")


@pytest.mark.parametrize("exc", [PermissionDenied("sin permiso"), CaptureError("interfaz mala")])
def test_start_fallido_no_deja_carpeta(tmpdirs, exc):
    c, _ = make_client(start_exc=exc)
    r = go(c)
    assert r.status_code in (403, 503)
    assert tw_dirs(tmpdirs) == []
    assert c.get("/api/live/status").json()["state"] == "idle"


def test_start_fallido_tras_captura_previa_no_borra_el_analisis(tmpdirs):
    fail = {"on": False}
    srcs = []

    def factory(iface):
        s = FakeSource(PermissionDenied("no") if fail["on"] else None)
        srcs.append(s)
        return s

    c = TestClient(create_app(source_factory=factory, sampler_factory=None))
    go(c)
    srcs[0].feed_demo(5)
    c.post("/api/live/stop")
    fail["on"] = True
    assert go(c).status_code == 403
    assert c.get("/api/packets/0").status_code == 200  # el pcap del análisis sigue ahí
    assert len(tw_dirs(tmpdirs)) == 1


# ---------------------------------------------------------------- lifespan
def test_cierre_borra_temporal_del_analisis(tmpdirs):
    c, src = make_client()
    with c:
        go(c)
        src[0].feed_demo(5)
        c.post("/api/live/stop")
        assert len(tw_dirs(tmpdirs)) == 1
    assert tw_dirs(tmpdirs) == []


def test_cierre_detiene_captura_en_curso_y_borra_carpeta(tmpdirs):
    c, src = make_client()
    with c:
        assert go(c).status_code == 200
        src[0].feed_demo(5)
        assert len(tw_dirs(tmpdirs)) == 1
    assert tw_dirs(tmpdirs) == []


def test_cierre_sin_nada_no_falla():
    with TestClient(create_app(sampler_factory=None)) as c:
        assert c.get("/api/health").status_code == 200


def test_cierre_con_demo_no_borra_samples():
    with TestClient(create_app(sampler_factory=None)) as c:
        c.post("/api/demo")
    assert DEMO.exists()


# ------------------------------------------------------------------ stats
def test_stats_truncated_y_untracked_con_demo():
    c = TestClient(create_app(sampler_factory=None))
    c.post("/api/demo")
    cap = c.get("/api/capture").json()["stats"]
    st = c.get("/api/stats").json()
    for s in (cap, st):
        assert s["truncated"] is False and s["untracked_packets"] == 0


def test_stats_filtrado_incluye_los_campos():
    c = TestClient(create_app(sampler_factory=None))
    c.post("/api/demo")
    st = c.get("/api/stats", params={"protocol": "TCP"}).json()
    assert st["truncated"] is False and st["untracked_packets"] == 0


# ------------------------------------------- captura truncada (analysis a mano)
def _truncated_client(monkeypatch):
    from backend.api import app as app_mod
    from backend.domain.analysis.analyzer import Analysis
    from backend.domain.pcap.reader import CaptureInfo
    from backend.domain.sessions.grouper import GroupingResult, Session

    sessions = [
        Session("TCP", "10.0.0.1", 1000, "10.0.0.2", 80, packets=3, bytes=300, first_ts=1.0, last_ts=2.0,
                key=("k", 1)),
        Session("UDP", "10.0.0.3", 5000, "10.0.0.4", 53, packets=2, bytes=100, first_ts=1.0, last_ts=1.5,
                key=("k", 2)),
    ]
    res = GroupingResult(sessions=sessions, truncated=True, untracked_packets=7)
    fake = Analysis(DEMO, CaptureInfo("pcap", 1, 65535), res, [], [])
    monkeypatch.setattr(app_mod, "analyze", lambda path, rules: fake)
    c = TestClient(create_app(sampler_factory=None))
    assert c.post("/api/demo").status_code == 200
    return c


def test_truncated_en_capture_y_stats_sin_filtros(monkeypatch):
    c = _truncated_client(monkeypatch)
    for st in (c.get("/api/capture").json()["stats"], c.get("/api/stats").json()):
        assert st["truncated"] is True and st["untracked_packets"] == 7


@pytest.mark.parametrize("params", [{"protocol": "TCP"}, {"ip": "10.0.0.3"}, {"port": 53}])
def test_truncated_se_copia_en_stats_con_filtros(monkeypatch, params):
    c = _truncated_client(monkeypatch)
    st = c.get("/api/stats", params=params).json()
    assert st["truncated"] is True and st["untracked_packets"] == 7
    assert st["sessions"] == 1  # las cifras sí son de lo filtrado


def test_truncated_en_export_con_y_sin_filtros(monkeypatch):
    c = _truncated_client(monkeypatch)
    for params in ({}, {"protocol": "TCP"}):
        r = c.get("/api/export", params=params)
        assert r.status_code == 200
        st = r.json()["stats"]
        assert st["truncated"] is True and st["untracked_packets"] == 7, params
