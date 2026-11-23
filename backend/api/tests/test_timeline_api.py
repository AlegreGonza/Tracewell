"""API: GET /api/timeline."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.analysis.tests.test_analyzer import write_pcap
from backend.domain.pcap.reader import iter_packets
from backend.domain.sessions.tests.test_grouper import tcp_eth

EMPTY = {"start": 0.0, "bucket_seconds": 1.0, "packets": [], "bytes": []}


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


def test_timeline_sin_analisis_409(client):
    r = client.get("/api/timeline")
    assert r.status_code == 409 and "no hay una captura analizada" in r.json()["detail"]


def test_timeline_demo(client):
    from backend.api.app import ROOT
    client.post("/api/demo")
    j = client.get("/api/timeline").json()
    assert set(j) == {"start", "bucket_seconds", "packets", "bytes"}
    assert sum(j["packets"]) == sum(1 for _ in iter_packets(ROOT / "samples" / "demo.pcap")) == 46
    assert len(j["packets"]) == len(j["bytes"]) <= 120 and j["bucket_seconds"] >= 1
    assert all(isinstance(x, int) for x in j["packets"] + j["bytes"])


def test_timeline_captura_sin_paquetes_forma_vacia(client, tmp_path):
    p = write_pcap(tmp_path / "e.pcap", [])
    assert client.post("/api/analyze", json={"path": str(p)}).status_code == 200
    assert client.get("/api/timeline").json() == EMPTY


def test_timeline_valores_exactos(client, tmp_path):
    raw = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"x" * 20))
    p = write_pcap(tmp_path / "t.pcap", [raw, raw, raw])  # ts 1, 2, 3
    client.post("/api/analyze", json={"path": str(p)})
    assert client.get("/api/timeline").json() == {
        "start": 1.0, "bucket_seconds": 1.0, "packets": [1, 1, 1], "bytes": [len(raw)] * 3}


def test_timeline_cambia_con_la_nueva_captura(client, tmp_path):
    client.post("/api/demo")
    raw = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2))
    client.post("/api/analyze", json={"path": str(write_pcap(tmp_path / "n.pcap", [raw]))})
    assert client.get("/api/timeline").json()["packets"] == [1]


def test_timeline_solo_get(client):
    client.post("/api/demo")
    assert client.post("/api/timeline").status_code == 405
