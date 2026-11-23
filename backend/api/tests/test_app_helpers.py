"""Tests directos de los helpers de backend/api/app.py."""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.app import ROOT, _make_lifespan, _mount_frontend, _shutdown, create_app
from backend.controllers.state import VERSION, _State
from backend.domain.pcap.live import CaptureError, LiveCapture

REAL = ROOT / "rules"


class FakeSource:
    def start(self, on_packet):
        pass

    def stop(self):
        pass


class BoomCap:
    """Captura que falla al detenerse/limpiar: _shutdown debe tragarse CaptureError."""
    running = True

    def stop(self):
        raise CaptureError("x")

    def cleanup(self):
        raise CaptureError("y")


def test_shutdown_estado_vacio():
    # _shutdown sin captura ni carpeta no hace nada
    _shutdown(_State())


def test_shutdown_detiene_captura_y_borra_temp():
    # con captura corriendo: la detiene, limpia su carpeta y borra owned_dir
    st = _State()
    st.live = LiveCapture(FakeSource())
    st.live.start()
    temp = st.live.temp_dir
    _shutdown(st)
    assert not st.live.running and not temp.exists()


def test_shutdown_borra_owned_dir(tmp_path):
    # _shutdown borra la carpeta propia del análisis actual
    d = tmp_path / "own"
    d.mkdir()
    st = _State()
    st.owned_dir = d
    _shutdown(st)
    assert not d.exists()


def test_shutdown_tolera_captura_ya_terminada():
    # captura ya detenida: solo limpia, sin error
    st = _State()
    st.live = LiveCapture(FakeSource())
    st.live.start()
    st.live.stop()
    _shutdown(st)
    assert not st.live.temp_dir.exists()


def test_shutdown_traga_capture_error(tmp_path):
    # un CaptureError al detener/limpiar no impide borrar owned_dir
    d = tmp_path / "own"
    d.mkdir()
    st = _State()
    st.live, st.owned_dir = BoomCap(), d
    _shutdown(st)
    assert not d.exists()


def test_lifespan_no_hace_nada_al_arrancar_y_limpia_al_cerrar(tmp_path):
    # el lifespan no toca nada al entrar y ejecuta _shutdown al salir
    d = tmp_path / "own"
    d.mkdir()
    st = _State()
    st.owned_dir = d

    async def run():
        async with _make_lifespan(st)(None):
            assert d.exists()
        assert not d.exists()

    asyncio.run(run())


def test_lifespan_via_testclient_limpia_al_cerrar(tmp_path):
    # con TestClient como context manager
    app = create_app(source_factory=lambda i: FakeSource(), frontend_dir=tmp_path / "nada", sampler_factory=None)
    with TestClient(app) as c:
        assert c.post("/api/live/start", json={"interface": "e"}).status_code == 200
        cap = app.state.ctx.state.live
        assert cap.temp_dir.exists()
        c.post("/api/live/stop")
    assert not cap.temp_dir.exists()


def test_mount_frontend_con_carpeta(tmp_path):
    # con carpeta existente sirve index.html en / y /api sigue funcionando
    (tmp_path / "index.html").write_text("<h1>hola</h1>")
    app = FastAPI()

    @app.get("/api/ping")
    def ping():
        return {"ok": 1}

    _mount_frontend(app, tmp_path)
    c = TestClient(app)
    assert "hola" in c.get("/").text and c.get("/api/ping").json() == {"ok": 1}


def test_mount_frontend_sin_carpeta(tmp_path):
    # sin carpeta no monta nada y no falla (/ da 404)
    app = FastAPI()
    _mount_frontend(app, tmp_path / "no_existe")
    assert TestClient(app).get("/").status_code == 404


def test_mount_frontend_acepta_str(tmp_path):
    # frontend_dir como str también funciona
    (tmp_path / "index.html").write_text("ok-str")
    app = FastAPI()
    _mount_frontend(app, str(tmp_path))
    assert "ok-str" in TestClient(app).get("/").text


def test_mount_frontend_archivo_no_carpeta(tmp_path):
    # si la ruta es un archivo (no carpeta) no se monta
    f = tmp_path / "f.txt"
    f.write_text("x")
    app = FastAPI()
    _mount_frontend(app, f)
    assert TestClient(app).get("/").status_code == 404


def test_create_app_health_y_version(tmp_path):
    # create_app con rules/samples reales arma una app que responde /api/health con VERSION
    app = create_app(rules_dir=REAL, samples_dir=ROOT / "samples", frontend_dir=tmp_path / "x", sampler_factory=None)
    r = TestClient(app).get("/api/health")
    assert r.json() == {"status": "ok", "version": VERSION} and app.version == VERSION


def test_create_app_reglas_invalidas_falla_al_crear(tmp_path):
    # una carpeta de reglas inexistente/rota falla en create_app, no a mitad de uso
    with pytest.raises(Exception):
        create_app(rules_dir=tmp_path / "no_existe")


def test_create_app_estado_independiente():
    # cada create_app tiene su propio estado
    a, b = create_app(sampler_factory=None), create_app(sampler_factory=None)
    assert a.state.ctx.state is not b.state.ctx.state
