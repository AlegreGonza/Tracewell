"""GET /api/case-timeline sobre el demo: unión de alertas, DNS sospechoso, notas e IOC, en orden."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app


@pytest.fixture
def demo():
    client = TestClient(create_app(sampler_factory=None))
    assert client.post("/api/demo").status_code == 200
    return client


def test_sin_analisis_409():
    assert TestClient(create_app(sampler_factory=None)).get("/api/case-timeline").status_code == 409


def test_demo_trae_las_alertas_en_orden_cronologico(demo):
    j = demo.get("/api/case-timeline").json()
    alerts = [e for e in j["items"] if e["kind"] == "alerta"]
    assert len(alerts) == 3
    ts = [e["ts"] for e in j["items"]]
    assert ts == sorted(ts) and j["total"] == len(j["items"]) and j["truncated"] is False


def test_una_nota_aparece_como_sesion_marcada(demo):
    sid = demo.get("/api/sessions?limit=1").json()["items"][0]["id"]
    assert demo.put(f"/api/sessions/{sid}/note", json={"note": "visto en el caso", "reviewed": True}).status_code == 200
    items = demo.get("/api/case-timeline").json()["items"]
    marked = [e for e in items if e["kind"] == "sesion"]
    assert len(marked) == 1 and marked[0]["session_id"] == sid and "visto en el caso" in marked[0]["detail"]


def test_un_ioc_aparece_en_la_cronologia(demo, tmp_path):
    first = demo.get("/api/sessions?limit=1").json()["items"][0]
    f = tmp_path / "iocs.txt"
    f.write_text(first["dst_ip"] + "\n", encoding="utf-8")
    assert demo.post("/api/iocs", json={"path": str(f)}).status_code == 200
    hits = [e for e in demo.get("/api/case-timeline").json()["items"] if e["kind"] == "ioc"]
    assert hits and all(first["dst_ip"] in " ".join(e["ips"]) for e in hits)


def test_filtro_por_host_deja_solo_lo_suyo(demo):
    scan = next(a for a in demo.get("/api/alerts").json() if a["rule_id"] == "port_scan")
    j = demo.get("/api/case-timeline", params={"host": scan["src_ip"]}).json()
    assert j["host"] == scan["src_ip"] and j["items"] and all(scan["src_ip"] in e["ips"] for e in j["items"])


def test_host_invalido_422(demo):
    assert demo.get("/api/case-timeline", params={"host": "no-es-ip"}).status_code == 422


def test_limit_fuera_de_rango_422(demo):
    assert demo.get("/api/case-timeline", params={"limit": 0}).status_code == 422
    assert demo.get("/api/case-timeline", params={"limit": 5000}).status_code == 422


def test_limit_corta_y_avisa(demo):
    j = demo.get("/api/case-timeline", params={"limit": 1}).json()
    assert len(j["items"]) == 1 and j["truncated"] is True and j["total"] >= 3


def test_la_timeline_de_paquetes_existente_sigue_igual(demo):
    t = demo.get("/api/timeline").json()
    assert set(t) == {"start", "bucket_seconds", "packets", "bytes"}
