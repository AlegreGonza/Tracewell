"""API: GET /api/sessions/{id}/stream."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.analysis.tests.test_analyzer import write_pcap
from backend.domain.sessions.tests.test_grouper import tcp_eth, udp_eth


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


def sid_of(c, pred):
    items = c.get("/api/sessions", params={"limit": 500}).json()["items"]
    return next(s["id"] for s in items if pred(s))


def test_sin_analisis_409(client):
    r = client.get("/api/sessions/0/stream")
    assert r.status_code == 409 and "no hay una captura analizada" in r.json()["detail"]


@pytest.mark.parametrize("sid", [9999, 32, -1])
def test_sesion_inexistente_404(loaded, sid):
    r = loaded.get(f"/api/sessions/{sid}/stream")
    assert r.status_code == 404 and r.json()["detail"] == "la sesión no existe"


def test_id_no_numerico_422(loaded):
    assert loaded.get("/api/sessions/abc/stream").status_code == 422


def test_sesion_no_tcp_422_con_mensaje(loaded):
    sid = sid_of(loaded, lambda s: s["protocol"] != "TCP")
    r = loaded.get(f"/api/sessions/{sid}/stream")
    assert r.status_code == 422 and "TCP" in r.json()["detail"]


def test_udp_e_icmp_en_captura_propia(client, tmp_path):
    import dpkt
    from backend.domain.sessions.tests.test_grouper import eth_ip
    icmp = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"x"))
    p = write_pcap(tmp_path / "u.pcap", [bytes(udp_eth("10.0.0.1", 1, "10.0.0.2", 2)), bytes(eth_ip(icmp, 1))])
    client.post("/api/analyze", json={"path": str(p)})
    for item in client.get("/api/sessions").json()["items"]:
        assert client.get(f"/api/sessions/{item['id']}/stream").status_code == 422


def test_demo_ftp_cuatro_bloques_alternados(loaded):
    sid = sid_of(loaded, lambda s: s["dst_port"] == 21 and s["packets"] > 1)
    r = loaded.get(f"/api/sessions/{sid}/stream")
    assert r.status_code == 200
    j = r.json()
    assert set(j) == {"chunks", "origin_bytes", "destination_bytes", "encrypted", "truncated"}
    assert [(c["from"], c["text"]) for c in j["chunks"]] == [
        ("destino", "220 FTP ready\r\n"), ("origen", "USER admin\r\n"),
        ("destino", "331 Password required\r\n"), ("origen", "PASS hunter2\r\n")]
    assert [c["bytes"] for c in j["chunks"]] == [15, 12, 23, 14]
    assert (j["origin_bytes"], j["destination_bytes"], j["encrypted"], j["truncated"]) == (26, 38, False, False)


def test_demo_http(loaded):
    sid = sid_of(loaded, lambda s: s["dst_port"] == 80 and s["packets"] > 1)
    j = loaded.get(f"/api/sessions/{sid}/stream").json()
    assert j["chunks"][0] == {"from": "origen", "bytes": 41, "text": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"}
    assert j["chunks"][1]["from"] == "destino" and j["chunks"][1]["text"].endswith("hello")


def test_sesion_tcp_sin_datos_devuelve_chunks_vacios(loaded):
    sid = sid_of(loaded, lambda s: s["dst_port"] == 21 and s["packets"] == 1)
    j = loaded.get(f"/api/sessions/{sid}/stream").json()
    assert j["chunks"] == [] and j["origin_bytes"] == 0


def test_texto_hostil_viaja_como_dato_json(client, tmp_path):
    p = write_pcap(tmp_path / "h.pcap", [bytes(tcp_eth("10.0.0.1", 5, "10.0.0.2", 80, b"<img src=x onerror=alert(1)>"))])
    client.post("/api/analyze", json={"path": str(p)})
    j = client.get("/api/sessions/0/stream").json()
    assert j["chunks"][0]["text"] == "<img src=x onerror=alert(1)>"
    assert "application/json" in client.get("/api/sessions/0/stream").headers["content-type"]


def test_solo_get(loaded):
    assert loaded.post("/api/sessions/0/stream").status_code == 405
