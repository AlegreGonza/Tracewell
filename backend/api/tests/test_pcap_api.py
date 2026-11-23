"""API: descargas de .pcap (una sesion y filtrado)."""
import io

import dpkt
import pytest
from fastapi.testclient import TestClient

import backend.domain.export.pcap_export as PE
from backend.api.app import create_app
from backend.domain.analysis.tests.test_analyzer import write_pcap
from backend.domain.sessions.tests.test_grouper import tcp_eth


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


def parse(resp):
    r = dpkt.pcap.Reader(io.BytesIO(resp.content))
    return r.datalink(), list(r)


# ------------------------------------------------------------------ /api/sessions/{id}/pcap

def test_sesion_ftp_da_exactamente_sus_6_paquetes(loaded):
    r = loaded.get("/api/sessions/5/pcap")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert r.headers["content-disposition"] == 'attachment; filename="tracewell-sesion-5.pcap"'
    assert "x-tracewell-truncated" not in r.headers
    link, pkts = parse(r)
    assert link == 1 and len(pkts) == 6
    assert loaded.get("/api/sessions", params={"limit": 100}).json()["items"][5]["packets"] == 6


def test_el_nombre_lleva_el_id(loaded):
    assert 'filename="tracewell-sesion-3.pcap"' in loaded.get("/api/sessions/3/pcap").headers["content-disposition"]


def test_todas_las_sesiones_del_demo_se_pueden_descargar(loaded):
    items = loaded.get("/api/sessions", params={"limit": 100}).json()["items"]
    for it in items:
        r = loaded.get(f"/api/sessions/{it['id']}/pcap")
        assert r.status_code == 200 and len(parse(r)[1]) == it["packets"]


@pytest.mark.parametrize("sid", [32, 9999, -1, -100])
def test_sesion_inexistente_404(loaded, sid):
    r = loaded.get(f"/api/sessions/{sid}/pcap")
    assert r.status_code == 404 and r.json()["detail"] == "la sesión no existe"


def test_id_no_numerico_422(loaded):
    assert loaded.get("/api/sessions/abc/pcap").status_code == 422


def test_sin_analisis_409(client):
    for url in ("/api/sessions/0/pcap", "/api/pcap"):
        r = client.get(url)
        assert r.status_code == 409 and "no hay una captura analizada" in r.json()["detail"]


def test_solo_get(loaded):
    assert loaded.post("/api/sessions/5/pcap").status_code == 405
    assert loaded.post("/api/pcap").status_code == 405


# ------------------------------------------------------------------ /api/pcap

def test_filtrado_por_ip_da_7_paquetes(loaded):
    r = loaded.get("/api/pcap", params={"ip": "192.168.1.20"})
    assert r.status_code == 200
    assert r.headers["content-disposition"] == 'attachment; filename="tracewell-filtrado.pcap"'
    assert r.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert len(parse(r)[1]) == 7


def test_filtrado_coincide_con_la_suma_de_las_sesiones_filtradas(loaded):
    for params in ({"ip": "192.168.1.20"}, {"protocol": "UDP"}, {"port": 53}, {"protocol": "tcp", "port": 21}):
        total = sum(s["packets"] for s in loaded.get("/api/sessions", params={"limit": 500, **params}).json()["items"])
        assert len(parse(loaded.get("/api/pcap", params=params))[1]) == total, params


def test_sin_filtros_trae_todo_lo_que_tiene_sesion(loaded):
    total = sum(s["packets"] for s in loaded.get("/api/sessions", params={"limit": 500}).json()["items"])
    assert len(parse(loaded.get("/api/pcap"))[1]) == total


def test_los_paquetes_salen_en_orden_de_captura(loaded):
    ts = [t for t, _ in parse(loaded.get("/api/pcap"))[1]]
    assert ts == sorted(ts)


def test_nada_coincide_404(loaded):
    r = loaded.get("/api/pcap", params={"ip": "9.9.9.9"})
    assert r.status_code == 404 and "no hay paquetes" in r.json()["detail"]
    assert loaded.get("/api/pcap", params={"port": 1}).status_code == 404


@pytest.mark.parametrize("params", [
    {"ip": "no-es-ip"}, {"ip": "300.1.1.1"}, {"ip": "fe80::1%eth0"}, {"port": 70000}, {"port": -1}, {"port": "abc"}, {"protocol": " "},
])
def test_filtros_invalidos_422_como_en_sessions(loaded, params):
    assert loaded.get("/api/sessions", params=params).status_code == 422
    assert loaded.get("/api/pcap", params=params).status_code == 422


def test_filtro_ip_con_espacios_se_acepta_igual_que_en_sessions(loaded):
    a = loaded.get("/api/sessions", params={"ip": " 192.168.1.20 "}).status_code
    b = loaded.get("/api/pcap", params={"ip": " 192.168.1.20 "}).status_code
    assert a == b == 200


# ------------------------------------------------------------------ truncado

def test_cabecera_truncated_solo_cuando_se_alcanza_el_tope(loaded, monkeypatch):
    monkeypatch.setattr(PE, "MAX_PACKETS", 3)
    r = loaded.get("/api/pcap")
    assert r.status_code == 200 and r.headers["x-tracewell-truncated"] == "true"
    assert len(parse(r)[1]) == 3
    r2 = loaded.get("/api/sessions/5/pcap")  # 6 paquetes > 3 tambien se trunca
    assert r2.headers["x-tracewell-truncated"] == "true" and len(parse(r2)[1]) == 3
    r3 = loaded.get("/api/sessions/4/pcap")  # sesion de 1 paquete: no
    assert "x-tracewell-truncated" not in r3.headers


def test_sin_tope_no_hay_cabecera(loaded):
    assert "x-tracewell-truncated" not in loaded.get("/api/pcap").headers


# ------------------------------------------------------------------ captura propia / tras cerrar

def test_captura_propia_ida_y_vuelta_con_payload(client, tmp_path):
    frames = [bytes(tcp_eth("10.0.0.1", 1111, "10.0.0.2", 80, b"hola")), bytes(tcp_eth("10.0.0.9", 2222, "10.0.0.2", 80, b"otro"))]
    client.post("/api/analyze", json={"path": str(write_pcap(tmp_path / "c.pcap", frames))})
    pk = parse(client.get("/api/sessions/0/pcap"))[1]
    assert [d for _, d in pk] == [frames[0]]
    assert [d for _, d in parse(client.get("/api/pcap", params={"ip": "10.0.0.2"}))[1]] == frames


def test_despues_de_cerrar_vuelve_a_409(loaded):
    loaded.delete("/api/capture")
    assert loaded.get("/api/pcap").status_code == 409
    assert loaded.get("/api/sessions/5/pcap").status_code == 409
