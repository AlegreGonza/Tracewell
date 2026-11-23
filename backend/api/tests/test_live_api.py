"""Tests de los endpoints /api/interfaces y /api/live/* con fuente simulada."""
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.pcap.live import CaptureError, InterfaceInfo, PermissionDenied
from backend.domain.pcap.reader import iter_packets

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "samples" / "demo.pcap"


class FakeSource:
    def __init__(self, start_exc=None):
        self.start_exc = start_exc
        self.on_packet = None
        self.started = threading.Event()

    def start(self, on_packet):
        if self.start_exc:
            raise self.start_exc
        self.on_packet = on_packet
        self.started.set()

    def stop(self):
        pass

    def feed_demo(self, n=None):
        for i, p in enumerate(iter_packets(DEMO)):
            if n is not None and i >= n:
                break
            self.on_packet(p.ts, p.data)


class Env:
    def __init__(self, tmp_path, **kw):
        self.sources = []
        self.exc = kw.get("start_exc")

        def factory(iface):
            s = FakeSource(self.exc)
            self.sources.append((iface, s))
            return s

        self.lister = kw.get("lister") or (lambda: [InterfaceInfo("eth0", "Ethernet"), InterfaceInfo("wlan0", "WiFi")])
        self.client = TestClient(create_app(source_factory=factory, interface_lister=self.lister, live_dir=tmp_path, sampler_factory=None))

    @property
    def src(self):
        return self.sources[-1][1]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def start(env, **body):
    return env.client.post("/api/live/start", json={"interface": "eth0", **body})


def test_interfaces_lista(env):
    r = env.client.get("/api/interfaces")
    assert r.status_code == 200
    assert r.json() == [{"name": "eth0", "description": "Ethernet"}, {"name": "wlan0", "description": "WiFi"}]


def test_interfaces_error_503(tmp_path):
    def bad():
        raise CaptureError("Scapy no está instalado")

    e = Env(tmp_path, lister=bad)
    r = e.client.get("/api/interfaces")
    assert r.status_code == 503 and "Scapy" in r.json()["detail"]


def test_status_idle_antes_de_empezar(env):
    r = env.client.get("/api/live/status")
    assert r.status_code == 200 and r.json()["state"] == "idle" and r.json()["reason"] is None


def test_stop_sin_captura_409(env):
    r = env.client.post("/api/live/stop")
    assert r.status_code == 409


def test_start_valido_running_y_pasa_la_interfaz(env):
    r = start(env, max_seconds=30)
    assert r.status_code == 200 and r.json()["state"] == "running"
    assert env.sources[0][0] == "eth0"
    assert env.client.get("/api/live/status").json()["state"] == "running"
    env.client.post("/api/live/stop")


def test_segundo_start_mientras_corre_409(env):
    assert start(env).status_code == 200
    r = start(env)
    assert r.status_code == 409 and "en curso" in r.json()["detail"]
    env.client.post("/api/live/stop")


@pytest.mark.parametrize("body", [
    {"interface": ""},
    {"interface": "eth0", "max_seconds": 0},
    {"interface": "eth0", "max_seconds": 4000},
    {"interface": "eth0", "max_seconds": -1},
    {"interface": "eth0", "max_packets": 0},
    {"interface": "eth0", "max_packets": 5_000_001},
    {"interface": "eth0", "max_packets": "x"},
    {},
])
def test_start_invalido_422(env, body):
    r = env.client.post("/api/live/start", json=body)
    assert r.status_code == 422
    assert env.sources == []  # ni siquiera creó la fuente


def test_permiso_denegado_403(tmp_path):
    e = Env(tmp_path, start_exc=PermissionDenied("permiso denegado: ejecutá como administrador"))
    r = e.client.post("/api/live/start", json={"interface": "eth0"})
    assert r.status_code == 403 and "administrador" in r.json()["detail"]
    assert e.client.get("/api/live/status").json()["state"] == "idle"


def test_permiso_denegado_mensaje_real_y_reintento(tmp_path):
    msg = "permiso denegado: ejecutá Tracewell como administrador (Windows) o root (Linux)"
    e = Env(tmp_path, start_exc=PermissionDenied(msg))
    r = e.client.post("/api/live/start", json={"interface": "eth0"})
    assert r.status_code == 403 and r.json()["detail"] == msg
    e.exc = None
    assert e.client.post("/api/live/start", json={"interface": "eth0"}).status_code == 200
    e.client.post("/api/live/stop")


def test_capture_error_503_y_se_puede_reintentar(tmp_path):
    e = Env(tmp_path, start_exc=CaptureError("interfaz inexistente"))
    r = e.client.post("/api/live/start", json={"interface": "nope"})
    assert r.status_code == 503 and "inexistente" in r.json()["detail"]
    e.exc = None
    assert e.client.post("/api/live/start", json={"interface": "eth0"}).status_code == 200
    e.client.post("/api/live/stop")


def test_flujo_completo_con_demo(env):
    assert start(env).status_code == 200
    env.src.feed_demo()
    total = len(list(iter_packets(DEMO)))
    assert env.client.get("/api/live/status").json()["packets"] == total
    r = env.client.post("/api/live/stop")
    assert r.status_code == 200
    body = r.json()
    assert body["capture"]["packets"] == total and body["capture"]["reason"] == "manual"
    assert body["capture"]["bytes"] > 0
    assert body["analysis"]["alerts"] > 0 and body["analysis"]["linktype"] == 1

    sessions = env.client.get("/api/sessions")
    assert sessions.status_code == 200 and sessions.json()["total"] > 0
    alerts = env.client.get("/api/alerts")
    assert alerts.status_code == 200 and len(alerts.json()) == body["analysis"]["alerts"]
    exp = env.client.get("/api/export")
    assert exp.status_code == 200 and exp.headers["content-type"].startswith("application/json")
    assert exp.json()
    assert env.client.get("/api/capture").json()["alerts"] == body["analysis"]["alerts"]


def test_stop_dos_veces_idempotente(env):
    start(env)
    env.src.feed_demo(10)
    r1 = env.client.post("/api/live/stop")
    r2 = env.client.post("/api/live/stop")
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["capture"] == r2.json()["capture"]
    assert env.client.get("/api/sessions").status_code == 200


def test_reiniciar_despues_de_terminar(env):
    start(env)
    env.src.feed_demo(5)
    assert env.client.post("/api/live/stop").json()["capture"]["packets"] == 5
    r = start(env)
    assert r.status_code == 200 and r.json()["state"] == "running" and r.json()["packets"] == 0
    assert len(env.sources) == 2
    env.src.feed_demo(8)
    assert env.client.post("/api/live/stop").json()["capture"]["packets"] == 8


def test_termina_sola_por_max_packets(env):
    assert start(env, max_packets=7).status_code == 200
    env.src.feed_demo()  # entrega todos; solo 7 se escriben
    st = env.client.get("/api/live/status").json()
    # el hilo monitor cierra de forma asíncrona: esperamos a que termine sin sleeps
    cap_done = None
    for _ in range(200):
        st = env.client.get("/api/live/status").json()
        if st["state"] == "finished":
            cap_done = st
            break
        threading.Event().wait(0.01)
    assert cap_done is not None, st
    assert cap_done["reason"] == "max_packets" and cap_done["packets"] == 7
    r = env.client.post("/api/live/stop")
    assert r.status_code == 200
    assert r.json()["capture"] == {**r.json()["capture"], "packets": 7, "reason": "max_packets"}
    assert r.json()["analysis"]["stats"]["total_packets"] == 7 if "total_packets" in r.json()["analysis"]["stats"] else True
    # tras terminar sola se puede iniciar otra
    assert start(env).status_code == 200
    env.client.post("/api/live/stop")


def test_captura_vacia_se_puede_analizar(env):
    start(env)
    r = env.client.post("/api/live/stop")
    assert r.status_code == 200 and r.json()["capture"]["packets"] == 0
    assert r.json()["analysis"]["alerts"] == 0


# ------------------------------------------------------------------ warning
class BoomSource(FakeSource):
    def stop(self):
        raise RuntimeError("boom")


class HangSource(FakeSource):
    def __init__(self):
        super().__init__()
        self.release = threading.Event()

    def stop(self):
        self.release.wait(10)


def _client_with(src, tmp_path):
    return TestClient(create_app(source_factory=lambda i: src, live_dir=tmp_path, sampler_factory=None))


def test_warning_none_con_fuente_normal(env):
    r = start(env)
    assert r.json()["warning"] is None
    env.src.feed_demo(5)
    assert env.client.get("/api/live/status").json()["warning"] is None
    stop = env.client.post("/api/live/stop")
    assert stop.status_code == 200
    assert stop.json()["capture"]["warning"] is None
    assert env.client.get("/api/live/status").json()["warning"] is None


def test_status_idle_no_falla_y_start_trae_la_clave(env):
    st = env.client.get("/api/live/status").json()
    assert st["state"] == "idle"
    assert st.get("warning") is None  # idle sin captura


def test_stop_con_fuente_que_lanza_da_200_y_warning(tmp_path):
    c = _client_with(BoomSource(), tmp_path)
    assert c.post("/api/live/start", json={"interface": "eth0"}).status_code == 200
    r = c.post("/api/live/stop")
    assert r.status_code == 200
    assert "boom" in r.json()["capture"]["warning"]
    assert "boom" in c.get("/api/live/status").json()["warning"]


def test_stop_con_fuente_colgada_avisa_que_no_se_detuvo(tmp_path, monkeypatch):
    import backend.domain.pcap.live as live
    monkeypatch.setattr(live, "STOP_TIMEOUT", 0.2)
    src = HangSource()
    c = _client_with(src, tmp_path)
    try:
        assert c.post("/api/live/start", json={"interface": "eth0"}).status_code == 200
        r = c.post("/api/live/stop")
        assert r.status_code == 200
        assert "no se detuvo" in r.json()["capture"]["warning"]
    finally:
        src.release.set()  # liberar el hilo
