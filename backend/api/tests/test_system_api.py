"""API de «Soporte de red → Sistema»: solo lectura, sin captura, con psutil falso (y un humo real al final)."""
import json
import sys

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.system import autostart, net, overview, procs
from backend.domain.system.common import SystemUnavailable
from backend.domain.system.tests.fakes import FakeProcess, FakePsutil, FakeService, addr, conn, patch_psutil

READ_ROUTES = ["/api/system/overview", "/api/system/processes", "/api/system/processes/5", "/api/system/processes/5/file", "/api/system/ports",
               "/api/system/connections", "/api/system/services", "/api/system/startup"]


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def fake(monkeypatch, tmp_path):
    exe = tmp_path / "prog.bin"
    exe.write_bytes(b"contenido")
    monkeypatch.setattr(procs.time, "sleep", lambda s: None)
    monkeypatch.setattr(procs, "IS_WINDOWS", False)
    monkeypatch.setattr(autostart, "IS_WINDOWS", True)
    monkeypatch.setattr(autostart, "IS_LINUX", False)
    five = FakeProcess(5, name="app", exe=str(exe), rss=900, cpu=8.0, conns=[conn(addr("10.0.0.5", 4000), addr("8.8.8.8", 443), "ESTABLISHED")],
                       open_files=["/a"], maps=["/lib/x.so"])
    ps = FakePsutil(
        procs=[FakeProcess(0, name="Idle"), five, FakeProcess(6, name="otro", rss=100, exe="/tmp/evil"), FakeProcess(7, name="sin_exe", exe=None, rss=50)],
        connections=[conn(addr("0.0.0.0", 80), None, "LISTEN", pid=5), conn(addr("10.0.0.5", 4000), addr("8.8.8.8", 443), "ESTABLISHED", pid=5)],
        services=[FakeService(name="Spooler", display_name="Cola", status="running", start_type="automatic", pid=9, username="SYSTEM", binpath="C:\\x.exe")],
    )
    patch_psutil(monkeypatch, ps)
    return ps


# ------------------------------------------------------------------ lecturas
def test_overview(client, fake):
    r = client.get("/api/system/overview")
    assert r.status_code == 200 and r.json()["memory"]["used"] == 5000 and r.json()["process_count"] == 4


def test_processes_por_defecto_ordena_por_ram_y_omite_pid_0(client, fake):
    j = client.get("/api/system/processes").json()
    assert [p["pid"] for p in j["items"]] == [5, 6, 7] and j["total"] == 3 and j["ncpu"] == 4
    assert j["items"][1]["hints"][0]["code"] == "carpeta_temporal"


@pytest.mark.parametrize("sort,first", [("ram", 5), ("cpu", 5), ("name", 5), ("pid", 5)])
def test_processes_sorts_validos(client, fake, sort, first):
    r = client.get("/api/system/processes", params={"sort": sort})
    assert r.status_code == 200 and r.json()["items"][0]["pid"] == first


def test_processes_orden_por_nombre_y_pid(client, fake):
    assert [p["name"] for p in client.get("/api/system/processes", params={"sort": "name"}).json()["items"]] == ["app", "otro", "sin_exe"]
    assert [p["pid"] for p in client.get("/api/system/processes", params={"sort": "pid"}).json()["items"]] == [5, 6, 7]


@pytest.mark.parametrize("params", [{"sort": "RAM"}, {"sort": "xyz"}, {"sort": ""}, {"sort": "ram;ls"}, {"limit": 0}, {"limit": -1}, {"limit": 2001}, {"limit": "abc"}, {"limit": 1.5}])
def test_processes_parametros_invalidos_422(client, fake, params):
    assert client.get("/api/system/processes", params=params).status_code == 422


@pytest.mark.parametrize("limit", [1, 2, 300, 2000])
def test_processes_limit_valido(client, fake, limit):
    r = client.get("/api/system/processes", params={"limit": limit})
    assert r.status_code == 200 and len(r.json()["items"]) == min(limit, 3)


def test_process_detail(client, fake):
    j = client.get("/api/system/processes/5").json()
    assert j["pid"] == 5 and j["name"] == "app" and j["open_files"] == ["/a"] and j["modules"] == ["/lib/x.so"]
    assert j["connections"][0]["owner"] == "Google"


@pytest.mark.parametrize("pid", [999, 12345678])
def test_process_detail_inexistente_404(client, fake, pid):
    r = client.get(f"/api/system/processes/{pid}")
    assert r.status_code == 404 and "no existe" in r.json()["detail"]


def test_process_detail_id_no_numerico_422(client, fake):
    assert client.get("/api/system/processes/abc").status_code == 422
    assert client.get("/api/system/processes/abc/file").status_code == 422


def test_process_file(client, fake):
    import hashlib
    j = client.get("/api/system/processes/5/file").json()
    assert j["available"] is True and j["sha256"] == hashlib.sha256(b"contenido").hexdigest() and j["size"] == 9
    assert "solo está disponible en Windows" in j["signature"]["text"]


def test_process_file_sin_exe_es_200_con_available_false(client, fake):
    j = client.get("/api/system/processes/7/file").json()
    assert client.get("/api/system/processes/7/file").status_code == 200 and j["available"] is False and j["reason"]


def test_process_file_pid_inexistente_no_inventa_rutas(client, fake):
    j = client.get("/api/system/processes/999/file").json()
    assert j["available"] is False


def test_ports(client, fake):
    j = client.get("/api/system/ports").json()
    assert j["total"] == 1 and j["items"][0]["port"] == 80 and j["items"][0]["process"] == "app" and j["limited"] is False


def test_connections(client, fake):
    j = client.get("/api/system/connections").json()
    assert j["total"] == 1 and j["items"][0]["owner"] == "Google" and j["items"][0]["process"] == "app"


def test_services(client, fake):
    j = client.get("/api/system/services").json()
    assert j["supported"] is True and j["items"][0]["name"] == "Spooler" and j["items"][0]["start"] == "Automático"


def test_startup_plataforma_sin_soporte(client, fake, monkeypatch):
    monkeypatch.setattr(autostart, "IS_WINDOWS", False)
    monkeypatch.setattr(autostart, "IS_LINUX", False)
    j = client.get("/api/system/startup").json()
    assert j["supported"] is False and j["reason"] and j["items"] == []


# ------------------------------------------------------------------ sin psutil: 503
@pytest.mark.parametrize("url", READ_ROUTES)
def test_sin_psutil_503_con_texto(client, monkeypatch, url):
    def missing():
        raise SystemUnavailable("Falta la librería psutil (pip install psutil) para ver el sistema.")
    for mod in (autostart, net, overview, procs):
        monkeypatch.setattr(mod, "psutil_or_raise", missing)
    monkeypatch.setattr(autostart, "IS_WINDOWS", True)
    monkeypatch.setattr(autostart, "IS_LINUX", False)
    if url.endswith("/startup"):
        pytest.skip("los programas de inicio no usan psutil")
    r = client.get(url)
    assert r.status_code == 503 and "psutil" in r.json()["detail"]


def test_psutil_realmente_ausente_da_503(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)
    r = client.get("/api/system/overview")
    assert r.status_code == 503 and "psutil" in r.json()["detail"] and "pip install" in r.json()["detail"]


# ------------------------------------------------------------------ solo lectura
@pytest.mark.parametrize("url", ["/api/system/overview", "/api/system/processes", "/api/system/processes/5", "/api/system/processes/5/file", "/api/system/ports",
                                 "/api/system/connections", "/api/system/services", "/api/system/startup", "/api/system", "/api/system/kill", "/api/system/processes/5/kill"])
@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_ninguna_ruta_acepta_metodos_que_modifican(client, fake, url, method):
    r = getattr(client, method)(url)
    assert r.status_code in (404, 405), (method, url, r.status_code)
    if url != "/api/system/kill" and url != "/api/system" and url != "/api/system/processes/5/kill":
        assert r.status_code == 405


def test_ninguna_ruta_del_router_tiene_metodos_de_escritura():
    paths = create_app(sampler_factory=None).openapi()["paths"]
    system = {p: set(m.upper() for m in ops) for p, ops in paths.items() if p.startswith("/api/system")}
    assert len(system) == 8
    for path, methods in system.items():
        assert methods == {"GET"}, path


def test_las_lecturas_no_llaman_a_funciones_que_modifican(client, fake):
    for url in READ_ROUTES:
        assert client.get(url).status_code in (200, 404)  # el fake lanza AssertionError si algo modifica


# ------------------------------------------------------------------ independencia de la captura
def test_funcionan_sin_captura_cargada(client, fake):
    assert client.get("/api/capture").status_code == 409
    for url in READ_ROUTES:
        assert client.get(url).status_code == 200


def test_con_captura_cargada_siguen_igual(client, fake):
    client.post("/api/demo")
    assert client.get("/api/system/overview").status_code == 200
    assert client.get("/api/capture").status_code == 200


def test_cerrar_la_captura_no_afecta(client, fake):
    client.post("/api/demo")
    client.delete("/api/capture")
    assert client.get("/api/system/ports").status_code == 200


# ------------------------------------------------------------------ seguridad (host local)
@pytest.mark.parametrize("url", READ_ROUTES)
def test_host_ajeno_400(fake, url):
    c = TestClient(create_app(sampler_factory=None), base_url="http://evil.com")
    r = c.get(url)
    assert r.status_code == 400 and r.text == "Invalid host header"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "127.0.0.1:8000"])
def test_host_local_ok(fake, host):
    c = TestClient(create_app(sampler_factory=None), base_url=f"http://{host}")
    assert c.get("/api/system/overview").status_code == 200


def test_rebinding_parecido_400(fake):
    c = TestClient(create_app(sampler_factory=None), base_url="http://127.0.0.1.evil.com")
    assert c.get("/api/system/processes").status_code == 400


def test_la_api_no_filtra_variables_de_entorno_ni_rutas_ajenas(client, fake):
    body = json.dumps([client.get(u).json() for u in READ_ROUTES])
    assert "PATH=" not in body and "SECRET" not in body


def test_nombres_hostiles_viajan_como_datos(client, monkeypatch, fake):
    fake.procs[:] = [FakeProcess(5, name="<script>alert(1)</script>", exe="C:\\x\\<img src=x onerror=alert(1)>.exe")]
    r = client.get("/api/system/processes")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert r.json()["items"][0]["name"] == "<script>alert(1)</script>"


# ------------------------------------------------------------------ humo REAL (sin mocks) en esta máquina
psutil = pytest.importorskip("psutil")


@pytest.fixture
def real_client():
    return TestClient(create_app(sampler_factory=None))


def test_humo_overview(real_client):
    j = real_client.get("/api/system/overview").json()
    assert j["memory"]["total"] > 0 and 0 <= j["memory"]["percent"] <= 100 and j["cpu_count"] >= 1 and j["process_count"] >= 1
    assert isinstance(j["disks"], list)


def test_humo_processes(real_client):
    j = real_client.get("/api/system/processes", params={"limit": 20}).json()
    assert j["total"] >= 1 and 1 <= len(j["items"]) <= 20 and j["ncpu"] >= 1
    pids = [p["pid"] for p in j["items"]]
    assert 0 not in pids
    assert all(set(p) >= {"pid", "name", "rss", "hints", "connections"} for p in j["items"])
    import os
    mine = real_client.get("/api/system/processes", params={"limit": 2000}).json()["items"]
    assert any(p["pid"] == os.getpid() for p in mine)


def test_humo_process_detail_del_proceso_actual(real_client):
    import os
    d = real_client.get(f"/api/system/processes/{os.getpid()}").json()
    assert d["pid"] == os.getpid() and d["name"] and isinstance(d["children"], list) and isinstance(d["connections"], list)
    assert real_client.get("/api/system/processes/999999999").status_code == 404


def test_humo_file_del_proceso_actual(real_client):
    import os
    j = real_client.get(f"/api/system/processes/{os.getpid()}/file").json()
    assert "available" in j
    if j["available"]:
        assert j["path"] and (j["sha256"] is None or len(j["sha256"]) == 64)


def test_humo_ports_y_connections(real_client):
    ports = real_client.get("/api/system/ports").json()
    conns = real_client.get("/api/system/connections").json()
    assert isinstance(ports["items"], list) and isinstance(ports["limited"], bool)
    assert all(r["exposure"] in {"local", "todas", "especifica"} and r["proto"] in {"TCP", "UDP"} for r in ports["items"])
    assert isinstance(conns["items"], list)
    assert all(r["scope"] in {"interna", "publica", "multicast", None} for r in conns["items"])


def test_humo_services(real_client):
    j = real_client.get("/api/system/services").json()
    assert isinstance(j["supported"], bool) and isinstance(j["items"], list) and j["total"] >= len(j["items"])
    if not j["supported"]:
        assert j["reason"]  # p. ej. Linux sin systemd: es normal, no un fallo


def test_humo_startup(real_client):
    j = real_client.get("/api/system/startup").json()
    assert isinstance(j["supported"], bool) and isinstance(j["items"], list)
    if not j["supported"]:
        assert j["reason"]
    for it in j["items"]:
        assert set(it) == {"where", "name", "command", "hints"}
