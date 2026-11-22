"""API del filtro de Wireshark: campo nuevo en /explain y /alerts, y endpoint por IP."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app


@pytest.fixture
def demo():
    client = TestClient(create_app(sampler_factory=None))
    assert client.post("/api/demo").status_code == 200
    return client


def test_explain_incluye_el_filtro_de_la_sesion(demo):
    s = demo.get("/api/sessions?limit=1").json()["items"][0]
    j = demo.get(f"/api/sessions/{s['id']}/explain").json()
    f = j["wireshark_filter"]
    assert s["src_ip"] in f and s["dst_ip"] in f
    # las claves anteriores siguen ahí
    assert {"protocol", "outcome", "summary", "steps"} <= j.keys()


def test_explain_tcp_lleva_los_puertos(demo):
    items = demo.get("/api/sessions?protocol=TCP&limit=5").json()["items"]
    s = items[0]
    f = demo.get(f"/api/sessions/{s['id']}/explain").json()["wireshark_filter"]
    assert f"tcp.port=={s['dst_port']}" in f


def test_alertas_traen_su_filtro(demo):
    alerts = demo.get("/api/alerts").json()
    assert alerts and all("wireshark_filter" in a for a in alerts)
    scan = next(a for a in alerts if a["rule_id"] == "port_scan")
    assert "tcp.flags.syn==1" in scan["wireshark_filter"] and scan["src_ip"] in scan["wireshark_filter"]


def test_el_json_exportado_no_cambia(demo):
    j = demo.get("/api/export").json()
    assert j["schema_version"] == 1
    assert all("wireshark_filter" not in a for a in j["alerts"])


def test_filtro_por_ip(demo):
    assert demo.get("/api/wireshark-filter?ip=10.0.0.5").json() == {"ip": "10.0.0.5", "wireshark_filter": "ip.addr==10.0.0.5"}
    assert demo.get("/api/wireshark-filter", params={"ip": "2001:db8::1"}).json()["wireshark_filter"] == "ipv6.addr==2001:db8::1"


@pytest.mark.parametrize("ip", ["no-es-ip", "300.1.1.1"])
def test_filtro_por_ip_invalida_422(demo, ip):
    assert demo.get("/api/wireshark-filter", params={"ip": ip}).status_code == 422


def test_filtro_por_ip_sin_parametro_422(demo):
    assert demo.get("/api/wireshark-filter").status_code == 422


def test_filtro_por_ip_no_necesita_captura():
    client = TestClient(create_app(sampler_factory=None))
    assert client.get("/api/wireshark-filter?ip=1.2.3.4").status_code == 200


# ---------------------------------------------- guía de la regla en la alerta (tarea 4)
def test_alerta_de_port_scan_trae_la_guia_de_la_regla(demo):
    scan = next(a for a in demo.get("/api/alerts").json() if a["rule_id"] == "port_scan")
    g = scan["guide"]
    assert g["false_positives"] and g["investigation_steps"] and g["wireshark_filter"].startswith("tcp.flags.syn")


def test_alerta_sin_campos_en_su_regla_no_trae_guia(demo):
    others = [a for a in demo.get("/api/alerts").json() if a["rule_id"] != "port_scan"]
    assert others and all("guide" not in a for a in others)


def test_la_guia_no_va_al_json_exportado(demo):
    j = demo.get("/api/export").json()
    assert all("guide" not in a and "false_positives" not in a for a in j["alerts"])


# ------------------------------------------------------------ dirección (tarea 5)
def test_cada_sesion_trae_su_direccion(demo):
    items = demo.get("/api/sessions?limit=100").json()["items"]
    valid = {"Interno→Externo", "Externo→Interno", "Interno→Interno (lateral)", "Externo→Externo", "Multicast"}
    assert items and all(i["direction"] in valid for i in items)


def test_la_direccion_no_va_al_json_exportado(demo):
    j = demo.get("/api/export").json()
    assert all("direction" not in s for s in j["sessions"])
