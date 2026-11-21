"""Servidor local en hilo (backend/api/server.py): puerto, loopback, ciclo de vida y errores de arranque."""
import socket
import threading

import httpx
import pytest
import uvicorn
from fastapi import FastAPI

from backend.api import server as srv
from backend.api.app import ROOT
from backend.api.server import ServerHandle, ServerStartError, bind_local_socket, start_in_thread
from backend.domain.rules.engine import RuleError

KW = dict(rules_dir=ROOT / "rules", samples_dir=ROOT / "samples")


def _hilos_api():
    return [t for t in threading.enumerate() if t.name == "tracewell-api" and t.is_alive()]


@pytest.fixture
def servers(tmp_path):
    """Arranca servidores y los detiene siempre al terminar."""
    handles = []

    def make(**kw):
        opts = dict(KW, frontend_dir=tmp_path / "no_existe")
        opts.update(kw)
        h = start_in_thread(**opts)
        handles.append(h)
        return h

    yield make
    for h in handles:
        h.stop()


@pytest.fixture(autouse=True)
def _sin_hilos_colgados():
    yield
    for t in _hilos_api():
        t.join(5)
    assert not _hilos_api()


def _puerto_responde(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


# ------------------------------------------------------------------ socket

def test_bind_puerto_cero_da_loopback_y_puerto_real():
    # puerto 0: el SO elige uno libre en 127.0.0.1
    s = bind_local_socket(0)
    try:
        host, port = s.getsockname()
        assert host == "127.0.0.1" and port > 0
    finally:
        s.close()


def test_bind_dos_veces_da_puertos_distintos():
    # dos sockets abiertos a la vez no comparten puerto
    a, b = bind_local_socket(0), bind_local_socket(0)
    try:
        assert a.getsockname()[1] != b.getsockname()[1]
    finally:
        a.close()
        b.close()


def test_bind_puerto_ocupado_lanza_oserror_y_cierra(monkeypatch):
    # si el bind falla se cierra el socket recién creado (sin fugas)
    ocupado = bind_local_socket(0)
    ocupado.listen()
    creados = []
    real = socket.socket

    class Espia(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            creados.append(self)

    monkeypatch.setattr(srv.socket, "socket", Espia)
    try:
        with pytest.raises(OSError):
            bind_local_socket(ocupado.getsockname()[1])
        assert len(creados) == 1 and creados[0].fileno() == -1
    finally:
        ocupado.close()


def test_start_in_thread_puerto_ocupado_propaga_oserror():
    # start_in_thread con puerto ocupado falla con OSError, sin dejar hilo
    ocupado = bind_local_socket(0)
    ocupado.listen()
    try:
        with pytest.raises(OSError):
            start_in_thread(port=ocupado.getsockname()[1], **KW)
    finally:
        ocupado.close()
    assert not _hilos_api()


# ------------------------------------------------------------------ servidor real

def test_health_a_traves_del_servidor_real(servers):
    # el servidor real responde /api/health con 200 y status ok
    h = servers()
    r = httpx.get(h.url + "/api/health", timeout=5)
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_url_es_loopback(servers):
    # la URL del handle apunta a 127.0.0.1 con el puerto del handle
    h = servers()
    assert h.url.startswith("http://127.0.0.1:") and h.url.endswith(f":{h.port}")


def test_escucha_solo_en_loopback(servers):
    # config.host y el socket real están atados a 127.0.0.1, no a 0.0.0.0
    h = servers()
    assert h.server.config.host == "127.0.0.1"
    socks = [s for sv in h.server.servers for s in sv.sockets]
    assert socks and all(s.getsockname()[0] == "127.0.0.1" for s in socks)
    assert socks[0].getsockname()[1] == h.port


def test_demo_funciona_por_servidor_real(servers):
    # POST /api/demo corre un análisis completo a través del servidor real
    h = servers()
    r = httpx.post(h.url + "/api/demo", timeout=30)
    assert r.status_code == 200
    assert isinstance(r.json(), dict) and r.json()


def test_host_malicioso_da_400(servers):
    # el control de Host sigue activo con uvicorn real (DNS rebinding)
    h = servers()
    r = httpx.get(h.url + "/api/health", headers={"Host": "evil.com"}, timeout=5)
    assert r.status_code == 400


def test_origin_malicioso_da_403(servers):
    # el control de Origin sigue activo con uvicorn real (CSRF)
    h = servers()
    r = httpx.get(h.url + "/api/health", headers={"Origin": "http://evil.com"}, timeout=5)
    assert r.status_code == 403


def test_dos_servidores_a_la_vez(servers):
    # dos servidores simultáneos usan puertos distintos y ambos responden
    a, b = servers(), servers()
    assert a.port != b.port
    assert httpx.get(a.url + "/api/health", timeout=5).status_code == 200
    assert httpx.get(b.url + "/api/health", timeout=5).status_code == 200


def test_app_inyectado_tambien_sirve(servers):
    # un FastAPI mínimo inyectado se sirve igual (sin create_app)
    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"pong": 1}

    h = servers(app=app)
    r = httpx.get(h.url + "/ping", timeout=5)
    assert r.status_code == 200 and r.json() == {"pong": 1}


def test_puerto_explicito_libre(servers):
    # un puerto concreto libre se respeta
    s = bind_local_socket(0)
    puerto = s.getsockname()[1]
    s.close()
    h = servers(port=puerto)
    assert h.port == puerto


# ------------------------------------------------------------------ parada

def test_stop_termina_hilo_y_puerto(servers):
    # stop() apaga el hilo y el puerto deja de aceptar conexiones
    h = servers()
    h.stop()
    assert not h.thread.is_alive()
    assert not _puerto_responde(h.port)


def test_stop_dos_veces_no_falla(servers):
    # stop() es idempotente
    h = servers()
    h.stop()
    h.stop()
    assert not h.thread.is_alive()


def test_stop_marca_should_exit_y_usa_timeout():
    # stop() levanta should_exit y pasa el timeout a join
    class T:
        def join(self, timeout=None):
            self.t = timeout

    class S:
        should_exit = False

    t = T()
    h = ServerHandle(S(), t, 1)
    h.stop(2.5)
    assert h.server.should_exit is True and t.t == 2.5


# ------------------------------------------------------------------ errores de arranque

def _espiar_make_server(monkeypatch):
    capturado = {}
    original = srv._make_server

    def make(app):
        s = original(app)
        capturado["s"] = s
        return s

    monkeypatch.setattr(srv, "_make_server", make)
    return capturado


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_hilo_muere_antes_de_estar_listo(monkeypatch):
    # si uvicorn muere al arrancar: ServerStartError y should_exit True
    capturado = _espiar_make_server(monkeypatch)

    def run_muere(self, sockets=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(uvicorn.Server, "run", run_muere)
    with pytest.raises(ServerStartError):
        start_in_thread(app=FastAPI())
    assert capturado["s"].should_exit is True
    assert not _hilos_api()


def test_timeout_si_nunca_marca_started(monkeypatch):
    # run que no marca started ni termina: vence READY_TIMEOUT -> ServerStartError
    parar = threading.Event()
    capturado = _espiar_make_server(monkeypatch)

    def run_colgado(self, sockets=None):
        parar.wait(10)

    monkeypatch.setattr(uvicorn.Server, "run", run_colgado)
    monkeypatch.setattr(srv, "READY_TIMEOUT", 0.2)
    try:
        with pytest.raises(ServerStartError):
            start_in_thread(app=FastAPI())
        assert capturado["s"].should_exit is True
    finally:
        parar.set()


def test_create_app_roto_propaga_ruleerror_sin_hilos(tmp_path):
    # reglas con YAML roto: RuleError al arrancar y ningún hilo lanzado
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "mala.yaml").write_text("id: [sin cerrar\n  - : :", encoding="utf-8")
    with pytest.raises(RuleError):
        start_in_thread(rules_dir=rules, samples_dir=ROOT / "samples")
    assert not _hilos_api()


def test_no_quedan_hilos_tracewell_api(servers):
    # tras stop() no queda ningún hilo 'tracewell-api' vivo
    for _ in range(2):
        servers().stop()
    assert not _hilos_api()
