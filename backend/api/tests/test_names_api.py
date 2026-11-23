"""API: nombre de sitio (host) por sesion, IOC de dominio por nombres y capas de /api/packets/{i}."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.analysis.tests.test_analyzer import write_pcap
from backend.domain.pcap.tests.test_layers import REFERENCE
from backend.domain.analysis.tests.test_names import client_hello, dns_response, eth4, eth6, tcp, udp


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


def frames():
    return [
        # 0: respuesta DNS (UDP 8.8.8.8:53 -> 10.0.0.5)
        eth4(udp(53, 40000, dns_response("Cdn.Evil.COM", [("A", "93.184.216.34"), ("AAAA", "2001:db8::77")])), 17, "8.8.8.8", "10.0.0.5"),
        # 1: ClientHello con SNI a esa misma IP
        eth4(tcp(50000, 443, client_hello("login.evil.com")), 6, "10.0.0.5", "93.184.216.34"),
        # 2: otra sesion a la misma IP, sin SNI -> nombre por DNS del destino
        eth4(tcp(50001, 443, b"datos"), 6, "10.0.0.5", "93.184.216.34"),
        # 3: sesion sin ningun nombre conocido
        eth4(tcp(50002, 80, b"GET /"), 6, "10.0.0.5", "198.51.100.9"),
        # 4: nombre por la IP de ORIGEN (el servidor inicia)
        eth4(tcp(4444, 50003, b"hey"), 6, "93.184.216.34", "10.0.0.6"),
        # 5: IPv6 con DNS AAAA
        eth6(tcp(6000, 443, b"x"), 6, "2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0077"),
        # 6: SNI de otro sitio parecido (no debe coincidir con evil.com)
        eth4(tcp(50004, 443, client_hello("notevil.com")), 6, "10.0.0.7", "203.0.113.5"),
    ]


@pytest.fixture
def loaded(client, tmp_path):
    p = write_pcap(tmp_path / "n.pcap", frames())
    assert client.post("/api/analyze", json={"path": str(p)}).status_code == 200
    return client


def sessions(c, **params):
    r = c.get("/api/sessions", params={"limit": 100, **params})
    assert r.status_code == 200
    return {(s["src_ip"], s["src_port"], s["dst_ip"], s["dst_port"]): s for s in r.json()["items"]}


def load_ioc(c, tmp_path, text):
    f = tmp_path / "ioc.txt"
    f.write_text(text, encoding="utf-8")
    r = c.post("/api/iocs", json={"path": str(f)})
    assert r.status_code == 200, r.text
    return r.json()


K_SNI = ("10.0.0.5", 50000, "93.184.216.34", 443)
K_DNS_DST = ("10.0.0.5", 50001, "93.184.216.34", 443)
K_NONE = ("10.0.0.5", 50002, "198.51.100.9", 80)
K_DNS_SRC = ("93.184.216.34", 4444, "10.0.0.6", 50003)
K_V6 = ("2001:db8::1", 6000, "2001:db8::77", 443)
K_NOT = ("10.0.0.7", 50004, "203.0.113.5", 443)


# ------------------------------------------------------------------- host
def test_host_sni_primero_luego_dns_destino_luego_dns_origen(loaded):
    s = sessions(loaded)
    assert s[K_SNI]["host"] == "login.evil.com"
    assert s[K_DNS_DST]["host"] == "cdn.evil.com"
    assert s[K_DNS_SRC]["host"] == "cdn.evil.com"
    assert s[K_V6]["host"] == "cdn.evil.com"  # IPv6 normalizada
    assert s[K_NOT]["host"] == "notevil.com"


def test_host_ausente_si_no_se_conoce(loaded):
    s = sessions(loaded)
    assert "host" not in s[K_NONE]
    assert "host" not in s[("8.8.8.8", 53, "10.0.0.5", 40000)]  # el resolvedor no tiene nombre


def test_host_con_filtros_y_paginado(loaded):
    got = sessions(loaded, ip="93.184.216.34")
    assert len(got) == 3 and all(x["host"] for x in got.values())
    r = loaded.get("/api/sessions", params={"limit": 1, "offset": 1})
    assert r.status_code == 200 and len(r.json()["items"]) == 1


def test_host_el_demo_no_rompe(client):
    assert client.post("/api/demo").status_code == 200
    items = client.get("/api/sessions", params={"limit": 500}).json()["items"]
    assert len(items) == 32 and all(isinstance(i.get("host", ""), str) for i in items)


def test_host_viaja_como_dato_sin_escapar(client, tmp_path):
    """Un SNI no puede traer espacios ni no-ASCII, pero si < y >: va como dato en el JSON."""
    p = write_pcap(tmp_path / "h.pcap", [eth4(tcp(5, 443, client_hello(raw_name=b"<img/src=x>.test")), 6)])
    client.post("/api/analyze", json={"path": str(p)})
    assert client.get("/api/sessions").json()["items"][0]["host"] == "<img/src=x>.test"


# ------------------------------------------------------------------- IOC de dominio
def test_ioc_dominio_coincide_por_sni_dns_y_subdominio(loaded, tmp_path):
    summary = load_ioc(loaded, tmp_path, "evil.com\n")
    s = sessions(loaded)
    marked = {k for k, v in s.items() if v.get("ioc")}
    assert marked == {K_SNI, K_DNS_DST, K_DNS_SRC, K_V6}
    assert all(s[k]["ioc"] == ["dominio:evil.com"] for k in marked)
    assert "ioc" not in s[K_NOT]  # notevil.com NO es subdominio de evil.com
    assert summary["domains"] == 1 and summary["sessions"] == 4  # coincidencias solo por dominio
    assert loaded.get("/api/iocs").json() == summary


def test_ioc_dominio_exacto_del_sni_y_no_el_resto(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "login.evil.com\n")
    assert [k for k, v in sessions(loaded).items() if v.get("ioc")] == [K_SNI]
    assert loaded.get("/api/iocs").json()["sessions"] == 1


def test_ioc_dominio_mayusculas_en_la_lista(loaded, tmp_path):
    assert load_ioc(loaded, tmp_path, "NotEvil.COM\n")["sessions"] == 1


def test_ioc_dominio_que_no_aparece(loaded, tmp_path):
    r = load_ioc(loaded, tmp_path, "ausente.org\n")
    assert r["sessions"] == 0 and all("ioc" not in v for v in sessions(loaded).values())


def test_ioc_mixto_ip_y_dominio_no_duplica_sesiones(loaded, tmp_path):
    r = load_ioc(loaded, tmp_path, "93.184.216.34\nevil.com\n")
    s = sessions(loaded)
    assert s[K_SNI]["ioc"] == ["dominio:evil.com", "ip:93.184.216.34"]
    assert s[K_V6]["ioc"] == ["dominio:evil.com"]
    assert r["sessions"] == sum(1 for v in s.values() if v.get("ioc")) == 4


def test_ioc_solo_ip_sigue_funcionando_sin_dominios(loaded, tmp_path):
    r = load_ioc(loaded, tmp_path, "198.51.100.9\n")
    assert r["sessions"] == 1 and r["domains"] == 0


def test_ioc_quitar_la_lista_quita_las_marcas(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "evil.com\n")
    loaded.delete("/api/iocs")
    assert all("ioc" not in v for v in sessions(loaded).values())


def test_ioc_cargado_antes_de_analizar_se_aplica_a_la_captura_nueva(client, tmp_path):
    load_ioc(client, tmp_path, "evil.com\n")
    p = write_pcap(tmp_path / "later.pcap", frames())
    client.post("/api/analyze", json={"path": str(p)})
    assert client.get("/api/iocs").json()["sessions"] == 4


def test_informe_html_incluye_sesiones_con_ioc_solo_por_dominio(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "evil.com\n")
    h = loaded.get("/api/report").text
    assert "dominio:evil.com" in h and "sesiones con coincidencias: <strong>4</strong>" in h
    assert "10.0.0.6" in h  # una sesion marcada solo por dominio aparece
    assert "notevil" not in h


def test_informe_sin_ioc_no_trae_dominio(loaded):
    assert "dominio:" not in loaded.get("/api/report").text


# ------------------------------------------------------------------- capas
def test_packet_incluye_layers(loaded):
    j = loaded.get("/api/packets/1").json()
    assert [x["name"] for x in j["layers"]] == ["Ethernet", "IPv4", "TCP", "Datos"]
    assert j["layers"][2]["fields"][1]["value"] == "443 (HTTPS)"
    assert j["layers"][3]["end"] == j["caplen"]
    assert set(j["layers"][0]) == {"name", "start", "end", "fields", "note"}


def test_packet_layers_en_paquetes_del_demo(client):
    client.post("/api/demo")
    for i in (0, 1, 10, 45):
        j = client.get(f"/api/packets/{i}").json()
        assert j["layers"] and j["layers"][0]["name"] == "Ethernet"


def test_packet_layers_referencia(client, tmp_path):
    p = write_pcap(tmp_path / "ref.pcap", [REFERENCE])
    client.post("/api/analyze", json={"path": str(p)})
    ls = client.get("/api/packets/0").json()["layers"]
    assert [(x["name"], x["start"], x["end"]) for x in ls] == [
        ("Ethernet", 0, 14), ("IPv4", 14, 34), ("TCP", 34, 54), ("Datos", 54, 55)]


def test_packet_inexistente_sigue_404(loaded):
    assert loaded.get("/api/packets/999").status_code == 404
