"""Tests de la API HTTP (sin red ni captura real). No cubre /api/live/* ni /api/interfaces."""
import json
import shutil
import socket
from urllib.parse import quote

import dpkt
import pytest
from fastapi.testclient import TestClient

from backend.api.app import ROOT, create_app
from backend.domain.rules.engine import RuleError

DEMO = ROOT / "samples" / "demo.pcap"


def _udp_eth(src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=2222):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=b"hi")
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(data=ip))


def make_pcap(path, linktype=1, frames=None):
    frames = frames or [_udp_eth()]
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=linktype)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1700000000 + i)
    return path


def make_pcapng(path):
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f, linktype=1)
        w.writepkt(_udp_eth(), ts=1700000000)
    return path


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


# ------------------------------------------------------------------ health
def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": "0.3.0"}


# ------------------------------------------------- sin análisis cargado
@pytest.mark.parametrize("url", [
    "/api/capture", "/api/sessions", "/api/stats", "/api/alerts", "/api/export",
    "/api/sessions/0/packets", "/api/packets/0",
])
def test_sin_analisis_409(client, url):
    r = client.get(url)
    assert r.status_code == 409
    assert "no hay una captura analizada" in r.json()["detail"]


# -------------------------------------------------------------------- demo
def test_demo_resumen(client):
    r = client.post("/api/demo")
    assert r.status_code == 200
    j = r.json()
    assert j["source"] == "demo.pcap"
    assert j["stats"]["sessions"] == 32
    assert j["stats"]["non_ip"] == 1
    assert j["alerts"] == 3
    assert len(j["rules"]) == 9
    assert {"ftp_cleartext", "port_scan", "dns_suspicious"} <= {x["id"] for x in j["rules"]}
    assert client.get("/api/capture").json() == j


def test_demo_sin_archivo_404(tmp_path):
    c = TestClient(create_app(samples_dir=tmp_path, sampler_factory=None))
    r = c.post("/api/demo")
    assert r.status_code == 404
    assert "demo.pcap" in r.json()["detail"]


# ----------------------------------------------------------------- analyze
def test_analyze_pcap_valido(client, tmp_path):
    p = tmp_path / "copia.pcap"
    shutil.copy(DEMO, p)
    r = client.post("/api/analyze", json={"path": str(p)})
    assert r.status_code == 200
    assert r.json()["source"] == "copia.pcap"
    assert r.json()["stats"]["sessions"] == 32


def test_analyze_pcapng(client, tmp_path):
    p = make_pcapng(tmp_path / "x.pcapng")
    r = client.post("/api/analyze", json={"path": str(p)})
    assert r.status_code == 200, r.text
    assert r.json()["format"] == "pcapng"
    assert r.json()["stats"]["sessions"] == 1


def test_analyze_inexistente_404(client, tmp_path):
    r = client.post("/api/analyze", json={"path": str(tmp_path / "nada.pcap")})
    assert r.status_code == 404


def test_analyze_carpeta_400(client, tmp_path):
    r = client.post("/api/analyze", json={"path": str(tmp_path)})
    assert r.status_code == 400


def test_analyze_vacio_422(client, tmp_path):
    p = tmp_path / "vacio.pcap"
    p.write_bytes(b"")
    assert client.post("/api/analyze", json={"path": str(p)}).status_code == 422


def test_analyze_basura_422(client, tmp_path):
    p = tmp_path / "basura.pcap"
    p.write_bytes(b"esto no es un pcap, ni de casualidad" * 10)
    assert client.post("/api/analyze", json={"path": str(p)}).status_code == 422


@pytest.mark.parametrize("body", [{}, {"path": ""}, {"path": 123}, {"path": None}, {"path": ["a"]}])
def test_analyze_body_invalido_422(client, body):
    assert client.post("/api/analyze", json=body).status_code == 422


def test_analyze_body_no_json_422(client):
    h = {"content-type": "application/json"}
    assert client.post("/api/analyze", content=b"no json", headers=h).status_code == 422
    assert client.post("/api/analyze", content=b"path=x").status_code == 422


def test_analyze_path_demasiado_largo_422(client):
    assert client.post("/api/analyze", json={"path": "a" * 5000}).status_code == 422


@pytest.mark.parametrize("kind", ["inexistente", "carpeta", "vacio", "basura", "linktype"])
def test_analyze_errores_no_filtran_ruta(client, tmp_path, kind):
    base = tmp_path / "carpeta_secreta_usuario"
    base.mkdir()
    if kind == "inexistente":
        p = base / "no.pcap"
    elif kind == "carpeta":
        p = base
    elif kind == "vacio":
        p = base / "v.pcap"
        p.write_bytes(b"")
    elif kind == "basura":
        p = base / "b.pcap"
        p.write_bytes(b"xx" * 100)
    else:
        p = make_pcap(base / "l.pcap", linktype=101)
    r = client.post("/api/analyze", json={"path": str(p)})
    assert r.status_code in (400, 404, 422)
    assert "carpeta_secreta_usuario" not in r.text
    assert str(tmp_path) not in r.text
    assert "Users" not in r.text


def test_analyze_linktype_no_ethernet_422(client, tmp_path):
    p = make_pcap(tmp_path / "raw.pcap", linktype=101, frames=[b"\x45" + b"\x00" * 30])
    r = client.post("/api/analyze", json={"path": str(p)})
    assert r.status_code == 422
    assert r.json()["detail"]


def test_cambiar_de_captura_reemplaza(client, tmp_path):
    client.post("/api/demo")
    assert client.get("/api/stats").json()["sessions"] == 32
    p = make_pcap(tmp_path / "chico.pcap")
    assert client.post("/api/analyze", json={"path": str(p)}).status_code == 200
    assert client.get("/api/stats").json()["sessions"] == 1
    assert client.get("/api/capture").json()["source"] == "chico.pcap"
    assert client.get("/api/alerts").json() == []


# ---------------------------------------------------------------- sessions
def test_sessions_total_y_paginacion(loaded):
    j = loaded.get("/api/sessions?limit=1000").json()
    assert j["total"] == 32 and len(j["items"]) == 32
    assert [x["id"] for x in j["items"]] == list(range(32))
    j = loaded.get("/api/sessions").json()
    assert j["total"] == 32 and len(j["items"]) == 32
    j = loaded.get("/api/sessions?limit=10&offset=30").json()
    assert j["total"] == 32 and [x["id"] for x in j["items"]] == [30, 31]
    assert len(loaded.get("/api/sessions?limit=1").json()["items"]) == 1
    j = loaded.get("/api/sessions?offset=32").json()
    assert j["items"] == [] and j["total"] == 32
    assert loaded.get("/api/sessions?offset=99999").json()["items"] == []


@pytest.mark.parametrize("q", ["limit=0", "limit=1001", "limit=-1", "offset=-1", "limit=x", "offset=x"])
def test_sessions_paginacion_invalida_422(loaded, q):
    assert loaded.get(f"/api/sessions?{q}").status_code == 422


@pytest.mark.parametrize("proto,n", [("tcp", 27), ("TCP", 27), ("Tcp", 27), ("udp", 4), ("icmp", 1), ("sctp", 0)])
def test_sessions_filtro_protocol(loaded, proto, n):
    j = loaded.get(f"/api/sessions?protocol={proto}&limit=1000").json()
    assert j["total"] == n and len(j["items"]) == n
    assert all(x["protocol"] == proto.upper() for x in j["items"])


def test_sessions_filtro_ip_port_y_combinados(loaded):
    all_ = {x["id"]: x for x in loaded.get("/api/sessions?limit=1000").json()["items"]}
    j = loaded.get("/api/sessions?ip=192.168.1.66&limit=1000").json()
    assert j["total"] == 25
    assert all("192.168.1.66" in (x["src_ip"], x["dst_ip"]) for x in j["items"])
    for x in j["items"]:
        assert all_[x["id"]] == x  # ids originales conservados
    j = loaded.get("/api/sessions?port=21&limit=1000").json()
    assert j["total"] >= 1
    assert all(21 in (x["src_port"], x["dst_port"]) for x in j["items"])
    assert any(x["id"] != i for i, x in enumerate(j["items"]))  # no re-numerados
    j = loaded.get("/api/sessions?protocol=tcp&ip=192.168.1.66&port=21&limit=1000").json()
    assert j["total"] == 1 and j["items"][0]["dst_port"] == 21
    assert loaded.get("/api/sessions?protocol=udp&port=53").json()["total"] == 4
    j = loaded.get("/api/sessions?protocol=udp&port=80").json()
    assert j["total"] == 0 and j["items"] == []
    assert loaded.get("/api/sessions?ip=8.8.8.8").json()["total"] == 0


def test_sessions_filtro_con_paginacion(loaded):
    j = loaded.get("/api/sessions?protocol=tcp&limit=5&offset=25").json()
    assert j["total"] == 27 and len(j["items"]) == 2


@pytest.mark.parametrize("q", ["ip=999.1.1.1", "ip=abc", "ip=", "ip=fe80::1%25eth0",
                               "port=70000", "port=-1", "port=abc", "port=", "protocol="])
def test_sessions_filtros_invalidos_422(loaded, q):
    r = loaded.get(f"/api/sessions?{q}")
    assert r.status_code == 422
    assert r.json()["detail"]


def test_sessions_ip_invalida_detail_claro(loaded):
    assert "999.1.1.1" in loaded.get("/api/sessions?ip=999.1.1.1").json()["detail"]


# ------------------------------------------------------------------- stats
def test_stats_sin_filtros(loaded):
    j = loaded.get("/api/stats").json()
    assert j["sessions"] == 32 and j["non_ip"] == 1 and j["packets"] == 45
    assert j["by_protocol"]["TCP"]["sessions"] == 27


def test_stats_con_filtro(loaded):
    j = loaded.get("/api/stats?protocol=tcp").json()
    assert j["sessions"] == 27
    assert set(j["by_protocol"]) == {"TCP"}
    sess = loaded.get("/api/sessions?protocol=tcp&limit=1000").json()["items"]
    assert j["packets"] == sum(s["packets"] for s in sess)
    assert j["bytes"] == sum(s["bytes"] for s in sess)
    assert j["non_ip"] == 0


def test_stats_filtro_sin_coincidencias(loaded):
    j = loaded.get("/api/stats?ip=8.8.8.8").json()
    assert j["sessions"] == 0 and j["by_protocol"] == {}


@pytest.mark.parametrize("q", ["ip=999.1.1.1", "port=70000", "protocol="])
def test_stats_filtros_invalidos_422(loaded, q):
    assert loaded.get(f"/api/stats?{q}").status_code == 422


# ------------------------------------------------------------------ alerts
def test_alerts_todas(loaded):
    j = loaded.get("/api/alerts").json()
    assert {a["rule_id"] for a in j} == {"ftp_cleartext", "port_scan", "dns_suspicious"}


def test_alerts_por_severidad(loaded):
    h = loaded.get("/api/alerts?severity=high").json()
    assert [a["rule_id"] for a in h] == ["port_scan"]
    m = loaded.get("/api/alerts?severity=medium").json()
    assert {a["rule_id"] for a in m} == {"ftp_cleartext", "dns_suspicious"}
    assert loaded.get("/api/alerts?severity=low").json() == []
    assert loaded.get("/api/alerts?severity=critical").json() == []


@pytest.mark.parametrize("sev", ["urgent", "HIGH", "", "x" * 500])
def test_alerts_severidad_invalida_422(loaded, sev):
    assert loaded.get("/api/alerts", params={"severity": sev}).status_code == 422


def test_alerts_no_filtra_password(loaded):
    r = loaded.get("/api/alerts")
    assert "hunter2" not in r.text
    ftp = next(a for a in r.json() if a["rule_id"] == "ftp_cleartext")
    assert ftp["evidence"]["password"] == "<oculta>"


# --------------------------------------------------------- session packets
def test_session_packets_paginacion(loaded):
    j = loaded.get("/api/sessions/0/packets").json()
    assert len(j["items"]) == 2 and j["has_more"] is False
    j = loaded.get("/api/sessions/0/packets?limit=1").json()
    assert len(j["items"]) == 1 and j["has_more"] is True
    j2 = loaded.get("/api/sessions/0/packets?limit=1&offset=1").json()
    assert len(j2["items"]) == 1 and j2["has_more"] is False
    assert j["items"][0]["index"] != j2["items"][0]["index"]
    assert loaded.get("/api/sessions/0/packets?offset=5").json() == {"items": [], "has_more": False}
    assert set(j["items"][0]) == {"index", "ts", "caplen", "origlen", "snaplen_limited"}


@pytest.mark.parametrize("sid", ["999", "-1", "32"])
def test_session_packets_inexistente_404(loaded, sid):
    assert loaded.get(f"/api/sessions/{sid}/packets").status_code == 404


def test_session_packets_id_no_numerico_422(loaded):
    assert loaded.get("/api/sessions/abc/packets").status_code == 422


@pytest.mark.parametrize("q", ["limit=0", "limit=1001", "limit=-1", "offset=-1", "limit=x"])
def test_session_packets_paginacion_invalida_422(loaded, q):
    assert loaded.get(f"/api/sessions/0/packets?{q}").status_code == 422


def test_session_packets_ultima_sesion(loaded):
    assert loaded.get("/api/sessions/31/packets").status_code == 200


# ----------------------------------------------------------------- packets
def test_packet_detalle(loaded):
    j = loaded.get("/api/packets/1").json()
    assert j["index"] == 1
    assert j["endpoints"]["src_ip"] == "192.168.1.10"
    assert j["endpoints"]["protocol"] == "UDP"
    assert j["session_id"] == 0
    assert isinstance(j["hexdump"], str) and j["hexdump"]
    assert j["caplen"] == 75


def test_packet_arp_sin_endpoints(loaded):
    j = loaded.get("/api/packets/0").json()
    assert j["endpoints"] is None
    assert j["session_id"] is None
    assert j["hexdump"]


def test_packet_ultimo_y_fuera_de_rango(loaded):
    assert loaded.get("/api/packets/45").status_code == 200  # 46 paquetes: 0..45
    assert loaded.get("/api/packets/46").status_code == 404
    assert loaded.get("/api/packets/9999").status_code == 404


def test_packet_indice_negativo_es_404(loaded):
    # Documentado: -1 es un int válido para FastAPI y core lo rechaza con IndexError -> 404.
    assert loaded.get("/api/packets/-1").status_code == 404


def test_packet_indice_no_numerico_422(loaded):
    assert loaded.get("/api/packets/abc").status_code == 422
    assert loaded.get("/api/packets/1.5").status_code == 422


# ------------------------------------------------------------------ export
def test_export_completo(loaded):
    r = loaded.get("/api/export")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-type"].startswith("application/json")
    j = json.loads(r.text)
    assert j["schema_version"] == 1
    assert len(j["sessions"]) == 32 and len(j["alerts"]) == 3
    assert j["filters"] == {}
    assert j["source"]["file"] == "demo.pcap"
    assert "hunter2" not in r.text


def test_export_source_solo_nombre(client, tmp_path):
    p = tmp_path / "sub" / "x.pcap"
    p.parent.mkdir()
    make_pcap(p)
    client.post("/api/analyze", json={"path": str(p)})
    r = client.get("/api/export")
    assert r.json()["source"]["file"] == "x.pcap"
    assert str(tmp_path) not in r.text


def test_export_con_filtros(loaded):
    j = loaded.get("/api/export?protocol=udp&port=53").json()
    assert j["filters"] == {"protocol": "udp", "port": 53}
    assert len(j["sessions"]) == 4 < 32
    assert j["stats"]["sessions"] == 4
    full = {x["id"]: x for x in loaded.get("/api/sessions?limit=1000").json()["items"]}
    # `direction` es una clave extra de la API
    assert all({k: v for k, v in full[s["id"]].items() if k != "direction"} == s for s in j["sessions"])
    assert len(j["alerts"]) == 3  # las alertas no se filtran


def test_export_filtro_sin_coincidencias(loaded):
    j = loaded.get("/api/export?ip=8.8.8.8").json()
    assert j["sessions"] == [] and j["filters"] == {"ip": "8.8.8.8"}


@pytest.mark.parametrize("q", ["ip=999.1.1.1", "port=70000", "protocol=", "port=abc"])
def test_export_filtros_invalidos_422(loaded, q):
    assert loaded.get(f"/api/export?{q}").status_code == 422


# ------------------------------------------------------------- create_app
def test_rules_dir_invalido_lanza_rule_error(tmp_path):
    (tmp_path / "rota.yaml").write_text("id: [esto no cierra\n  :::", encoding="utf-8")
    with pytest.raises(RuleError):
        create_app(rules_dir=tmp_path)


def test_frontend_dir_existente(tmp_path):
    (tmp_path / "index.html").write_text("<html><body>hola tracewell</body></html>", encoding="utf-8")
    c = TestClient(create_app(frontend_dir=tmp_path, sampler_factory=None))
    r = c.get("/")
    assert r.status_code == 200 and "hola tracewell" in r.text
    assert c.get("/api/health").json()["status"] == "ok"
    assert c.get("/api/capture").status_code == 409  # /api no queda tapado


def test_frontend_dir_inexistente(tmp_path):
    c = TestClient(create_app(frontend_dir=tmp_path / "nope", sampler_factory=None))
    assert c.get("/").status_code == 404
    assert c.get("/api/health").status_code == 200


# -------------------------------------------------------------------- fuzz
RAROS = ["%", "%00", "%zz", "ñandú", "💥", "a" * 10000, "1e3", "x", "-0", "0x10", "' OR 1=1--",
         "../../etc/passwd", "999.1.1.1", "::1", "::ffff:1.2.3.4", " 192.168.1.1 ", "NaN", "inf",
         "99999999999999999999999"]


def _no_500(r, url):
    assert r.status_code < 500, f"{url} -> {r.status_code}: {r.text[:200]}"


@pytest.mark.parametrize("val", RAROS)
def test_fuzz_query_params(loaded, val):
    for path in ["/api/sessions", "/api/stats", "/api/export"]:
        for name in ["ip", "port", "protocol", "limit", "offset"]:
            if name in ("limit", "offset") and path != "/api/sessions":
                continue
            _no_500(loaded.get(path, params={name: val}), f"{path}?{name}")
    _no_500(loaded.get("/api/alerts", params={"severity": val}), "alerts")
    for name in ("limit", "offset"):
        _no_500(loaded.get("/api/sessions/0/packets", params={name: val}), "sp")


@pytest.mark.parametrize("val", RAROS)
def test_fuzz_path_params(loaded, val):
    v = quote(val, safe="")
    _no_500(loaded.get(f"/api/sessions/{v}/packets"), "sessions/x/packets")
    _no_500(loaded.get(f"/api/packets/{v}"), "packets/x")


@pytest.mark.parametrize("val", RAROS)
def test_fuzz_analyze_path(client, val):
    _no_500(client.post("/api/analyze", json={"path": val}), "analyze")


def test_fuzz_sin_analisis(client):
    for val in RAROS:
        _no_500(client.get("/api/sessions", params={"ip": val}), "s")
