"""API de «Soporte de red → Red»"""
import pytest
from fastapi.testclient import TestClient

from backend.api import app as app_mod
from backend.api.routes import support as RS
from backend.api.app import create_app
from backend.controllers.state import _State
from backend.domain.support.monitor import Monitor


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def fake(monkeypatch):
    """Cada función de backend.domain.support devuelve un dict con su nombre y los argumentos recibidos."""
    calls = {}

    def mk(name):
        def f(*a, **k):
            calls[name] = (a, k)
            return {"fn": name, "args": list(a)}
        return f

    for mod, names in ((RS.checks, ["internet_check", "latency_test", "ping", "traceroute", "port_check", "rdp_check", "time_offset"]),
                       (RS.devices, ["list_devices"]), (RS.wifi, ["wifi_status", "wifi_history"]), (RS.dupip, ["check_duplicate_ip"]),
                       (RS.netinfo, ["network_config", "raw_config"])):
        for n in names:
            monkeypatch.setattr(mod, n, mk(n))
    m = Monitor()
    monkeypatch.setattr(RS, "monitor", m)
    monkeypatch.setattr(m, "start", lambda interval=2.0: calls.setdefault("start", interval))
    monkeypatch.setattr(m, "stop", lambda: calls.setdefault("stop", True))
    monkeypatch.setattr(m, "clear", lambda: calls.setdefault("clear", True))
    return calls


GETS = [("config", "network_config"), ("config/raw", "raw_config"), ("internet", "internet_check"), ("latency", "latency_test"),
        ("ping?host=1.1.1.1", "ping"), ("traceroute?host=1.1.1.1", "traceroute"), ("ports?host=1.1.1.1&ports=22,80", "port_check"),
        ("rdp?host=1.1.1.1", "rdp_check"), ("time", "time_offset"), ("devices", "list_devices"), ("wifi", "wifi_status"),
        ("wifi/history", "wifi_history"), ("duplicate-ip", "check_duplicate_ip")]


@pytest.mark.parametrize("path,fn", GETS)
def test_lecturas_200_y_no_store(client, fake, path, fn):
    r = client.get("/api/support/" + path)
    assert r.status_code == 200 and r.json()["fn"] == fn and r.headers["cache-control"] == "no-store"


def test_monitor_get(client, fake):
    r = client.get("/api/support/monitor")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.json()["running"] is False and r.json()["outages"] == []


def test_argumentos_se_pasan(client, fake):
    client.get("/api/support/ports?host=h.local&ports=22, 80,443")
    assert fake["port_check"][0] == ("h.local", [22, 80, 443])
    client.get("/api/support/devices?scan=true")
    assert fake["list_devices"][0] == (True,)


@pytest.mark.parametrize("path", [
    "ping?host=1.1.1.1&count=21", "ping?host=1.1.1.1&count=0", "ports?host=1.1.1.1&ports=abc", "ports?host=1.1.1.1",
    "latency?samples=2", "latency?samples=31", "latency?port=0", "traceroute?host=1.1.1.1&max_hops=31", "rdp?host=1.1.1.1&port=70000",
    "wifi/history?limit=0", "wifi/history?limit=301",
])
def test_valores_invalidos_422(client, fake, path):
    assert client.get("/api/support/" + path).status_code == 422


def test_validacion_del_core_es_422(client, monkeypatch):
    """Sin falsos: valid_host / servidor de hora no permitido salen como 422 con el motivo, y."""
    r = client.get("/api/support/ping", params={"host": "a;b"})
    assert r.status_code == 422 and "válido" in r.json()["detail"]
    for bad in ("a|b", "-n", "a$b", "a b"):
        assert client.get("/api/support/ping", params={"host": bad}).status_code == 422
    r = client.get("/api/support/time", params={"server": "evil.example.com"})
    assert r.status_code == 422 and "no permitido" in r.json()["detail"]
    assert client.get("/api/support/ports", params={"host": "1.1.1.1", "ports": "abc"}).status_code == 422


def test_monitor_intervalo_invalido(client, fake):
    assert client.post("/api/support/monitor/start?interval=0.5").status_code == 422
    assert client.post("/api/support/monitor/start?interval=31").status_code == 422


def test_monitor_post(client, fake):
    assert client.post("/api/support/monitor/start?interval=5").status_code == 200 and fake["start"] == 5.0
    assert client.post("/api/support/monitor/start").status_code == 200 and fake["start"] == 5.0  # setdefault: ya estaba; la llamada igual fue 200
    assert client.post("/api/support/monitor/stop").json()["running"] is False and fake["stop"]
    assert client.post("/api/support/monitor/clear").status_code == 200 and fake["clear"]


@pytest.mark.parametrize("p", ["start", "stop", "clear"])
def test_monitor_get_a_post_es_405(fake, p):
    # app mínima solo con el router
    from fastapi import FastAPI
    mini = FastAPI()
    mini.include_router(RS.router)
    assert TestClient(mini).get("/api/support/monitor/" + p).status_code == 405


@pytest.mark.parametrize("path", ["config", "internet", "monitor"])
def test_las_lecturas_no_aceptan_post(fake, path):
    from fastapi import FastAPI
    mini = FastAPI()
    mini.include_router(RS.router)
    assert TestClient(mini).post("/api/support/" + path).status_code == 405


def test_shutdown_detiene_el_monitor_aunque_falle_la_captura(monkeypatch):
    stopped = []
    monkeypatch.setattr(app_mod, "monitor", type("M", (), {"stop": lambda self: stopped.append(1)})())

    def boom(cap):
        raise RuntimeError("no se pudo detener")

    monkeypatch.setattr(app_mod, "_stop_live", boom)
    state = _State()
    with pytest.raises(RuntimeError):
        app_mod._shutdown(state)
    assert stopped == [1]
    monkeypatch.setattr(app_mod, "_stop_live", lambda cap: None)
    app_mod._shutdown(_State())
    assert stopped == [1, 1]
