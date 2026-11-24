"""Política de errores de la API: handler global, cierre robusto, 404 sin contexto, socket de arranque."""
import logging
import socket
import tempfile

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.api import app as app_mod
from backend.api import server as srv
from backend.api.app import ROOT, create_app
from backend.api.server import ServerStartError, start_in_thread
from backend.domain.pcap.live import CaptureError
from backend.domain.rules.engine import RuleError

SECRETO = r"C:\Users\juan.perez\secretos\clave.pcap"


def _app(tmp_path):
    return create_app(rules_dir=ROOT / "rules", samples_dir=ROOT / "samples",
                      frontend_dir=tmp_path / "no_existe", sampler_factory=None)


@pytest.fixture
def client(tmp_path):
    app = _app(tmp_path)

    @app.get("/boom")
    def boom():
        raise RuntimeError(f"fallo leyendo {SECRETO}")

    @app.get("/http")
    def http():
        raise HTTPException(418, "tetera")

    @app.get("/mapeado")
    def mapeado():
        raise FileNotFoundError("no está")

    return TestClient(app, raise_server_exceptions=False, base_url="http://127.0.0.1")


# ---------------------------------------------------------- handler global

def test_inesperado_da_500_json_generico(client):
    # RuntimeError -> 500 JSON {"detail": "error interno"}
    r = client.get("/boom")
    assert r.status_code == 500
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {"detail": "error interno"}


def test_inesperado_no_filtra_mensaje_ni_ruta(client):
    # el cuerpo no contiene ni el mensaje ni la ruta del usuario
    r = client.get("/boom")
    assert "juan.perez" not in r.text and "fallo leyendo" not in r.text and "clave.pcap" not in r.text


def test_inesperado_loguea_traceback(client, caplog):
    # el traceback (exc_info) llega al logger "tracewell"
    with caplog.at_level(logging.ERROR, logger="tracewell"):
        client.get("/boom")
    recs = [r for r in caplog.records if r.name == "tracewell" and r.exc_info]
    assert recs and recs[0].exc_info[0] is RuntimeError
    assert SECRETO in str(recs[0].exc_info[1])
    assert "/boom" in recs[0].getMessage()


def test_http_exception_no_la_pisa_el_global(client):
    # HTTPException sigue con su código y mensaje
    r = client.get("/http")
    assert r.status_code == 418 and r.json() == {"detail": "tetera"}


def test_error_mapeado_no_lo_pisa_el_global(client):
    # FileNotFoundError sigue siendo 404 con su mensaje
    r = client.get("/mapeado")
    assert r.status_code == 404 and r.json() == {"detail": "no está"}


def test_mapeados_reales_conservan_codigo(client):
    # 404 (archivo), 422 (validación) y 409 (captura no iniciada) intactos
    assert client.post("/api/analyze", json={"path": str(tempfile.gettempdir()) + "/no/existe.pcap"}).status_code == 404
    assert client.post("/api/analyze", json={}).status_code == 422
    r = client.post("/api/live/stop")
    assert r.status_code == 409 and r.json()["detail"]


# ---------------------------------------------------------------- _shutdown

class _Cap:
    def __init__(self, stop_exc=None, cleanup_exc=None, running=True):
        self.running, self.stop_exc, self.cleanup_exc = running, stop_exc, cleanup_exc
        self.calls = []

    def stop(self):
        self.calls.append("stop")
        if self.stop_exc:
            raise self.stop_exc

    def cleanup(self):
        self.calls.append("cleanup")
        if self.cleanup_exc:
            raise self.cleanup_exc


def _state(cap, owned="DIR"):
    s = app_mod._State()
    s.live, s.owned_dir = cap, owned
    return s


@pytest.fixture
def rm(monkeypatch):
    llamadas = []
    monkeypatch.setattr(app_mod, "_rmtree", lambda d: llamadas.append(d))
    return llamadas


def test_shutdown_stop_falla_warning_y_borra_igual(rm, caplog):
    # cap.stop() lanza CaptureError -> warning y _rmtree igual
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        app_mod._shutdown(_state(_Cap(stop_exc=CaptureError("x"))))
    assert rm == ["DIR"]
    assert any(r.levelno == logging.WARNING and r.exc_info for r in caplog.records)


def test_shutdown_cleanup_falla_warning_y_borra_igual(rm, caplog):
    # cap.cleanup() lanza CaptureError -> warning y _rmtree igual
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        app_mod._shutdown(_state(_Cap(cleanup_exc=CaptureError("x"), running=False)))
    assert rm == ["DIR"]
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_shutdown_sin_captura_no_falla(rm):
    # sin captura solo borra la carpeta propia
    app_mod._shutdown(_state(None))
    assert rm == ["DIR"]


def test_shutdown_ok_detiene_limpia_y_borra(rm, caplog):
    # camino feliz: stop + cleanup + rmtree, sin warnings
    cap = _Cap()
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        app_mod._shutdown(_state(cap))
    assert cap.calls == ["stop", "cleanup"] and rm == ["DIR"] and not caplog.records


def test_shutdown_error_inesperado_igual_borra(rm):
    # un error que no es CaptureError se propaga, pero el try/finally borra igual
    with pytest.raises(RuntimeError):
        app_mod._shutdown(_state(_Cap(stop_exc=RuntimeError("zas"))))
    assert rm == ["DIR"]


# ------------------------------------------------------ 404 con `from None`

def test_404_paquete_y_sesion_tras_demo(tmp_path):
    # tras POST /api/demo, índices inexistentes dan 404 con su mensaje
    with TestClient(_app(tmp_path), base_url="http://127.0.0.1") as c:
        assert c.post("/api/demo").status_code == 200
        r = c.get("/api/packets/9999")
        assert r.status_code == 404 and r.json() == {"detail": "el paquete no existe"}
        r = c.get("/api/sessions/999/packets")
        assert r.status_code == 404 and r.json() == {"detail": "la sesión no existe"}


# ----------------------------------------------------- start_in_thread / socket

def test_reglas_rotas_no_abren_socket(monkeypatch, tmp_path):
    # create_app falla (RuleError) antes de bind_local_socket
    (tmp_path / "mala.yaml").write_text("id: [esto no es una regla\n", encoding="utf-8")
    llamadas = []
    monkeypatch.setattr(srv, "bind_local_socket", lambda *a, **k: llamadas.append(1))
    with pytest.raises(RuleError):
        start_in_thread(rules_dir=tmp_path, samples_dir=ROOT / "samples")
    assert llamadas == []


@pytest.mark.parametrize("donde", ["_launch", "_wait_ready"])
def test_fallo_de_arranque_cierra_socket_y_propaga(monkeypatch, tmp_path, donde):
    # si _launch / _wait_ready fallan, el socket real queda cerrado (fileno -1)
    socks = []
    orig = srv.bind_local_socket

    def bind(port=0):
        socks.append(orig(port))
        return socks[-1]

    monkeypatch.setattr(srv, "bind_local_socket", bind)
    if donde == "_launch":
        def falla(*a, **k):
            raise ServerStartError("boom")
    else:
        def falla(handle, timeout):
            handle.server.should_exit = True  # no dejar el hilo de uvicorn vivo
            handle.thread.join(5)
            raise ServerStartError("boom")

    monkeypatch.setattr(srv, donde, falla)
    with pytest.raises(ServerStartError):
        start_in_thread(rules_dir=ROOT / "rules", samples_dir=ROOT / "samples",
                        frontend_dir=tmp_path / "no")
    assert len(socks) == 1 and socks[0].fileno() == -1


def test_arranque_normal_no_cierra_socket(monkeypatch, tmp_path):
    # camino feliz: el socket sigue abierto y el servidor responde
    reales = []
    orig = srv.bind_local_socket

    def bind(port=0):
        reales.append(orig(port))
        return reales[-1]

    monkeypatch.setattr(srv, "bind_local_socket", bind)
    h = start_in_thread(rules_dir=ROOT / "rules", samples_dir=ROOT / "samples",
                        frontend_dir=tmp_path / "no")
    try:
        assert reales[0].fileno() != -1
        with socket.create_connection(("127.0.0.1", h.port), timeout=1):
            pass
    finally:
        h.stop()
