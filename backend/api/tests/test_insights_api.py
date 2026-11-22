"""API de 'entender la captura': equipos, grafo, DNS, explicación, HTTP, archivos y TLS."""
import base64
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.api.tests.test_processes_api import make_env
from backend.domain.analysis.tests.convo import conversation
from backend.domain.analysis.tests.test_http import chunked, req, resp
from backend.domain.analysis.tests.test_tls import cert, cert_message, client_hello, d_name, real_client_hello, server_hello, ext
from backend.domain.analysis.tests.test_dns_log import msg
from backend.domain.analysis.tests.test_names import eth4, udp

EVIL = "x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1.evil-c2.example"
PASSWORD = "Hunter2-SECRETO"
TOKEN = "tok3n-SECRETO-xyz"
BASIC_PASS = "basicpw-SECRETO"
EXE = b"MZ\x90\x00\x03" + bytes(range(256)) * 8


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def demo(client):
    assert client.post("/api/demo").status_code == 200
    return client


def write_at(path, frames, t0=1_750_000_000.0):
    import dpkt
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=t0 + i)
    return path


def load(client, tmp_path, frames, name="x.pcap"):
    r = client.post("/api/analyze", json={"path": str(write_at(tmp_path / name, frames))})
    assert r.status_code == 200, r.text
    return client


# todas las rutas nuevas
ROUTES = ["/api/hosts", "/api/graph", "/api/dns", "/api/http", "/api/sessions/0/explain", "/api/sessions/0/http",
          "/api/sessions/0/http/0/body", "/api/sessions/0/tls"]


@pytest.mark.parametrize("url", ROUTES)
def test_sin_analisis_409(client, url):
    r = client.get(url)
    assert r.status_code == 409 and "no hay una captura analizada" in r.json()["detail"]


@pytest.mark.parametrize("url", ROUTES)
def test_despues_de_cerrar_vuelve_a_409(demo, url):
    demo.delete("/api/capture")
    assert demo.get(url).status_code == 409


# ------------------------------------------------------------------ hosts / graph

def test_hosts_demo_forma_y_orden(demo):
    j = demo.get("/api/hosts").json()
    assert j["total"] == len(j["items"]) >= 5
    assert set(j["items"][0]) == {"ip", "kind", "sessions", "packets", "bytes", "initiated", "received", "peers", "protocols", "services",
                                  "name", "alerts", "alert_rules", "ioc", "role", "role_label", "owner", "note", "roles", "mac"}
    assert [h["bytes"] for h in j["items"]] == sorted((h["bytes"] for h in j["items"]), reverse=True)
    sessions = demo.get("/api/sessions", params={"limit": 500}).json()["total"]
    assert sum(h["sessions"] for h in j["items"]) == 2 * sessions


def test_hosts_alertas_en_el_escaneador(demo):
    by = {h["ip"]: h for h in demo.get("/api/hosts", params={"limit": 500}).json()["items"]}
    assert by["192.168.1.66"]["alerts"] >= 1 and "port_scan" in by["192.168.1.66"]["alert_rules"]
    assert by["192.168.1.66"]["kind"] == "interna"


def test_hosts_el_servidor_ftp_ofrece_el_puerto_21(demo):
    by = {h["ip"]: h for h in demo.get("/api/hosts", params={"limit": 500}).json()["items"]}
    assert {"protocol": "TCP", "port": 21} == {k: by["192.168.1.5"]["services"][0][k] for k in ("protocol", "port")}


@pytest.mark.parametrize("limit,status", [(1, 200), (500, 200), (0, 422), (501, 422), (-1, 422), ("x", 422)])
def test_hosts_limit(demo, limit, status):
    assert demo.get("/api/hosts", params={"limit": limit}).status_code == status


def test_hosts_limit_recorta_pero_total_es_el_real(demo):
    j = demo.get("/api/hosts", params={"limit": 2}).json()
    assert len(j["items"]) == 2 and j["total"] > 2


def test_hosts_marca_ioc(demo, tmp_path):
    f = tmp_path / "ioc.txt"
    f.write_text("93.184.216.34\n", encoding="utf-8")
    demo.post("/api/iocs", json={"path": str(f)})
    by = {h["ip"]: h for h in demo.get("/api/hosts", params={"limit": 500}).json()["items"]}
    assert by["93.184.216.34"]["ioc"] == ["ip:93.184.216.34"] and by["192.168.1.10"]["ioc"] == []
    node = {n["ip"]: n for n in demo.get("/api/graph").json()["nodes"]}["93.184.216.34"]
    assert node["ioc"] is True


def test_graph_demo(demo):
    j = demo.get("/api/graph", params={"limit": 60}).json()
    assert set(j) == {"nodes", "edges", "truncated"}
    ips = {n["ip"] for n in j["nodes"]}
    assert all(e["a"] in ips and e["b"] in ips and e["a"] < e["b"] for e in j["edges"])
    assert [e["bytes"] for e in j["edges"]] == sorted((e["bytes"] for e in j["edges"]), reverse=True)


@pytest.mark.parametrize("limit,status", [(2, 200), (60, 200), (1, 422), (0, 422), (61, 422), ("x", 422)])
def test_graph_limit(demo, limit, status):
    assert demo.get("/api/graph", params={"limit": limit}).status_code == status


def test_graph_limit_recorta_nodos_y_marca_truncated(demo):
    j = demo.get("/api/graph", params={"limit": 2}).json()
    assert len(j["nodes"]) == 2 and j["truncated"] is True


# ------------------------------------------------------------------ DNS

def test_dns_demo(demo):
    j = demo.get("/api/dns").json()
    s = j["summary"]
    assert (s["names"], s["queries"], s["responses"], s["flagged"]) == (4, 4, 3, 1) and s["dropped"] == 0
    flagged = [r for r in j["items"] if r["hints"]]
    assert [r["name"] for r in flagged] == [EVIL]
    assert any("al azar" in h for h in flagged[0]["hints"])
    assert {"name", "qtype", "queries", "responses", "rcodes", "answers", "clients", "first_ts", "last_ts", "min_ttl", "hints"} == set(j["items"][0])


def test_dns_filtro_q_y_limit(demo):
    assert [r["name"] for r in demo.get("/api/dns", params={"q": "evil-c2"}).json()["items"]] == [EVIL]
    assert demo.get("/api/dns", params={"q": "EVIL-C2"}).json()["items"][0]["name"] == EVIL
    assert demo.get("/api/dns", params={"q": "zzz-no"}).json()["items"] == []
    assert len(demo.get("/api/dns", params={"limit": 1}).json()["items"]) == 1
    assert demo.get("/api/dns", params={"q": "zzz"}).json()["summary"]["names"] == 4  # el resumen es de toda la captura


@pytest.mark.parametrize("params,status", [({"limit": 0}, 422), ({"limit": 1001}, 422), ({"limit": 1000}, 200), ({"q": "a" * 253}, 200), ({"q": "a" * 254}, 422)])
def test_dns_validacion(demo, params, status):
    assert demo.get("/api/dns", params=params).status_code == status


def test_dns_captura_propia_con_nxdomain_y_cname(client, tmp_path):
    frames = [
        eth4(udp(40000, 53, msg("gone.test")), 17, "10.0.0.5", "8.8.8.8"),
        eth4(udp(53, 40000, msg("gone.test", qr=1, rcode=3)), 17, "8.8.8.8", "10.0.0.5"),
        eth4(udp(53, 40001, msg("www.ok.test", qr=1, answers=[("CNAME", "Edge.CDN.Net."), ("A", "1.2.3.4")], ttl=10)), 17, "8.8.8.8", "10.0.0.5"),
    ]
    load(client, tmp_path, frames)
    j = client.get("/api/dns").json()
    assert j["summary"] == {"names": 2, "queries": 1, "responses": 2, "nxdomain": 1, "flagged": 2, "dropped": 0}
    by = {r["name"]: r for r in j["items"]}
    assert by["gone.test"]["rcodes"] == {"NXDOMAIN": 1} and by["www.ok.test"]["answers"] == ["edge.cdn.net", "1.2.3.4"]
    assert any("TTL" in h for h in by["www.ok.test"]["hints"])


def test_dns_captura_sin_dns(client, tmp_path):
    load(client, tmp_path, conversation())
    assert client.get("/api/dns").json() == {"summary": {"names": 0, "queries": 0, "responses": 0, "nxdomain": 0, "flagged": 0, "dropped": 0}, "items": []}


# ------------------------------------------------------------------ explain

def test_explain_demo(demo):
    expected = {3: "cerrada", 5: "abierta", 7: "sin_respuesta"}
    for sid, outcome in expected.items():
        j = demo.get(f"/api/sessions/{sid}/explain").json()
        assert j["protocol"] == "TCP" and j["outcome"] == outcome and j["summary"] and isinstance(j["steps"], list)
    http = demo.get("/api/sessions/3/explain").json()
    assert [s["label"] for s in http["steps"]][:5] == ["SYN", "SYN+ACK", "ACK", "Datos", "Datos"]
    assert any("Es HTTP sin cifrar" in s for s in http["summary"])


def test_explain_udp_e_icmp_sin_resultado(demo):
    items = demo.get("/api/sessions", params={"limit": 500}).json()["items"]
    for it in [i for i in items if i["protocol"] != "TCP"][:5]:
        j = demo.get(f"/api/sessions/{it['id']}/explain").json()
        assert j["outcome"] is None and j["steps"] == [] and j["summary"]


@pytest.mark.parametrize("sid", [999, 32, -1])
def test_explain_inexistente_404(demo, sid):
    assert demo.get(f"/api/sessions/{sid}/explain").status_code == 404


def test_explain_incluye_el_proceso_si_hay_tabla(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    j = env.client.get("/api/sessions/3/explain").json()
    assert any("chrome.exe (PID 100)" in s for s in j["summary"])


def test_explain_sin_tabla_no_menciona_procesos(demo):
    assert not any("PID" in s for s in demo.get("/api/sessions/3/explain").json()["summary"])


def test_explain_el_nombre_del_sitio_va_al_servidor(client, tmp_path):
    frames = conversation(s_ip="93.184.216.34", sport=443, turns=[("c", client_hello()), ("s", b"\x16\x03\x03\x00\x02ab")])
    load(client, tmp_path, frames)
    assert "www.example.com (93.184.216.34)" in client.get("/api/sessions/0/explain").json()["summary"][0]


# ------------------------------------------------------------------ HTTP

def http_capture():
    login = req("POST", f"/login?apikey={TOKEN}", {"Content-Type": "application/x-www-form-urlencoded",
                                                      "Authorization": "Basic " + base64.b64encode(f"ana:{BASIC_PASS}".encode()).decode()},
                f"user=ana&password={PASSWORD}".encode())
    dl = req("GET", "/files/setup.exe", host="dl.example.com")
    chunked_get = req("GET", "/c")
    return (
        conversation(cport=40000, turns=[("c", login), ("s", resp(302, "Found", {"Location": "/home"}, b""))])
        + conversation(cport=40001, c_isn=300, s_isn=900, turns=[("c", dl), ("s", resp(200, "OK", {"Content-Type": "application/octet-stream"}, EXE))])
        + conversation(cport=40002, c_isn=40, s_isn=90, turns=[("c", chunked_get), ("s", resp(200, "OK", {"Transfer-Encoding": "chunked"}, chunked(b"hel", b"lo")))])
        + conversation(cport=40003, s_ip="10.0.0.9", sport=22, c_isn=5, s_isn=6, turns=[("c", b"SSH-2.0-x\r\n")])
    )


@pytest.fixture
def web(client, tmp_path):
    return load(client, tmp_path, http_capture())


def sid_by_port(c, port):
    return next(i["id"] for i in c.get("/api/sessions", params={"limit": 100}).json()["items"] if i["src_port"] == port)


def test_http_de_una_sesion(web):
    sid = sid_by_port(web, 40001)
    j = web.get(f"/api/sessions/{sid}/http").json()
    assert j["incomplete"] is False and len(j["exchanges"]) == 1
    ex = j["exchanges"][0]
    assert (ex["method"], ex["host"], ex["target"], ex["status"]) == ("GET", "dl.example.com", "/files/setup.exe", 200)
    f = ex["file"]
    assert f["name"] == "setup.exe" and f["size"] == len(EXE) and f["sha256"] == hashlib.sha256(EXE).hexdigest() and f["risky"] is True
    assert "Windows" in f["kind"] and f["direction"] == "descarga" and f["complete"] is True


def test_http_sesion_no_http_da_vacio(web):
    sid = sid_by_port(web, 40003)
    assert web.get(f"/api/sessions/{sid}/http").json() == {"exchanges": [], "incomplete": False}


def test_http_404_y_422(web, demo):
    assert web.get("/api/sessions/999/http").status_code == 404
    assert web.get("/api/sessions/-1/http").status_code == 404
    web.post("/api/demo")
    udp_id = next(i["id"] for i in web.get("/api/sessions", params={"limit": 500}).json()["items"] if i["protocol"] == "UDP")
    r = web.get(f"/api/sessions/{udp_id}/http")
    assert r.status_code == 422 and "TCP" in r.json()["detail"]
    assert web.get(f"/api/sessions/{udp_id}/http/0/body").status_code == 422
    assert web.get(f"/api/sessions/{udp_id}/tls").status_code == 422


def test_http_demo(demo):
    j = demo.get("/api/sessions/3/http").json()
    assert j["exchanges"][0]["host"] == "www.example.com" and j["exchanges"][0]["status"] == 200
    assert demo.get("/api/sessions/5/http").json()["exchanges"] == []


def test_http_resumen_global(web):
    j = web.get("/api/http").json()
    assert j["capped"] is False and j["scanned"] == 3
    targets = {(i["session_id"], i["target"].split("?")[0]) for i in j["items"]}
    assert {t for _, t in targets} == {"/login", "/files/setup.exe", "/c"}
    login = next(i for i in j["items"] if i["target"].startswith("/login"))
    assert login["sensitive_fields"] == ["apikey", "password"] and login["auth"] == {"scheme": "Basic", "user": "ana"}
    assert login["src"].startswith("10.0.0.1:") and login["dst"].endswith(":80")


def test_ningun_secreto_se_filtra_en_ninguna_salida(web):
    sid = sid_by_port(web, 40000)
    urls = ["/api/http", f"/api/sessions/{sid}/http", f"/api/sessions/{sid}/explain", "/api/report", "/api/export", "/api/sessions?limit=100",
            "/api/hosts", "/api/dns", "/api/alerts", f"/api/sessions/{sid}/tls", "/api/timeline"]
    for url in urls:
        r = web.get(url)
        assert r.status_code == 200, url
        body = r.text + json.dumps(dict(r.headers))
        assert PASSWORD not in body, url
        assert BASIC_PASS not in body, url
        assert base64.b64encode(f"ana:{BASIC_PASS}".encode()).decode() not in body, url


def test_el_secreto_de_la_url_solo_aparece_como_parte_del_target(web):
    """El valor del token viaja dentro de la URL pedida (es el pedido literal); los campos sensibles solo traen NOMBRES."""
    j = web.get("/api/http").json()
    login = next(i for i in j["items"] if i["target"].startswith("/login"))
    assert login["sensitive_fields"] == ["apikey", "password"]
    assert PASSWORD not in json.dumps(login) and BASIC_PASS not in json.dumps(login)


def test_descarga_del_cuerpo(web):
    sid = sid_by_port(web, 40001)
    r = web.get(f"/api/sessions/{sid}/http/0/body")
    assert r.status_code == 200 and r.content == EXE
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"] == 'attachment; filename="setup.exe.bin"'
    assert r.headers["x-content-type-options"] == "nosniff"


def test_descarga_del_cuerpo_chunked_decodificado(web):
    sid = sid_by_port(web, 40002)
    r = web.get(f"/api/sessions/{sid}/http/0/body")
    assert r.status_code == 200 and r.content == b"hello"
    assert r.headers["content-disposition"] == 'attachment; filename="c.bin"'


def test_descarga_404_si_no_hay_archivo_o_indice_malo(web):
    sid = sid_by_port(web, 40000)  # el login 302 sin cuerpo
    assert web.get(f"/api/sessions/{sid}/http/0/body").status_code == 404
    assert web.get(f"/api/sessions/{sid_by_port(web, 40001)}/http/5/body").status_code == 404
    assert web.get(f"/api/sessions/{sid_by_port(web, 40001)}/http/-1/body").status_code == 404
    assert web.get("/api/sessions/999/http/0/body").status_code == 404


def test_nombre_de_descarga_saneado_aunque_el_servidor_mienta(client, tmp_path):
    evil = resp(200, "OK", {"Content-Disposition": 'attachment; filename="..\\..\\Windows\\evil<script>.exe"'}, b"MZ" + b"\x00" * 10)
    load(client, tmp_path, conversation(turns=[("c", req()), ("s", evil)]))
    r = client.get("/api/sessions/0/http/0/body")
    assert r.status_code == 200
    cd = r.headers["content-disposition"]
    assert cd.endswith('.bin"') and "\\" not in cd and "<" not in cd and ".." not in cd.split("filename=")[1].strip('"')


def test_captura_sin_http_scan_vacio(client, tmp_path):
    load(client, tmp_path, conversation(sport=443, turns=[("c", client_hello())]))
    assert client.get("/api/http").json() == {"scanned": 0, "capped": False, "items": []}


def test_http_incompleto_por_huecos(client, tmp_path):
    frames = conversation(turns=[("c", req()), ("s", resp(200, body=b"x" * 5000))], mss=500)
    frames = frames[:6] + frames[7:]  # falta un segmento de datos de la respuesta
    load(client, tmp_path, frames)
    j = client.get("/api/sessions/0/http").json()
    assert j["incomplete"] is True


# ------------------------------------------------------------------ TLS

def tls_capture(server_frames=True):
    ch = real_client_hello("www.example.com")
    srv = server_hello(0xC02F, 0x0303) + cert_message(cert(subject=d_name(cn="www.example.com"), issuer=d_name(cn="www.example.com"),
                                                           nb=("240101000000Z", False), na=("20990101000000Z", True)))
    return conversation(sport=443, turns=[("c", ch)] + ([("s", srv)] if server_frames else []), mss=1500)


def test_tls_ruta_completa(client, tmp_path):
    load(client, tmp_path, tls_capture())
    j = client.get("/api/sessions/0/tls").json()
    assert j["tls"] is True and j["incomplete"] is False
    assert j["client"]["sni"] == "www.example.com" and j["client"]["alpn"] == "h2" and j["client"]["complete"] is True
    assert j["client"]["ja4"].startswith("t13d") and j["client"]["ja4"].count("_") == 2
    assert j["server"] == {"version": "TLS 1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}
    assert j["certificate_hidden"] is False
    assert j["certificate"]["subject"] == "www.example.com" and j["certificate"]["self_signed"] is True
    assert j["certificate"]["expired"] is False and j["certificate"]["not_yet_valid"] is False


def test_tls_sin_respuesta_del_servidor(client, tmp_path):
    load(client, tmp_path, tls_capture(server_frames=False))
    j = client.get("/api/sessions/0/tls").json()
    assert j["tls"] is True and j["server"] == {"version": None, "cipher": None} and j["certificate"] is None


def test_tls13_oculta_certificado(client, tmp_path):
    sh = server_hello(0x1301, 0x0303, exts=[ext(0x2B, b"\x03\x04")])
    load(client, tmp_path, conversation(sport=443, turns=[("c", real_client_hello()), ("s", sh)], mss=1500))
    j = client.get("/api/sessions/0/tls").json()
    assert j["server"]["version"] == "TLS 1.3" and j["certificate_hidden"] is True and j["certificate"] is None


def test_tls_con_el_origen_invertido(client, tmp_path):
    """Captura iniciada a mitad: el primer paquete visto es del servidor, asi que el 'origen' es el servidor."""
    full = tls_capture()
    ch_frames = [f for f in full]
    # ponemos la respuesta del servidor ANTES que el hello del cliente, sin saludo de 3 pasos
    inv = conversation(sport=443, handshake=False, close=None, turns=[("s", server_hello(0xC02F, 0x0303)), ("c", real_client_hello())], mss=1500)
    load(client, tmp_path, inv)
    j = client.get("/api/sessions/0/tls").json()
    assert j["tls"] is True and j["client"]["sni"] == "www.example.com" and j["server"]["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert ch_frames


def test_tls_hello_partido_en_segmentos_se_reconstruye(client, tmp_path):
    ch = real_client_hello()
    load(client, tmp_path, conversation(sport=443, turns=[("c", ch)], mss=200))
    j = client.get("/api/sessions/0/tls").json()
    assert j["client"]["complete"] is True and j["client"]["ja4"] is not None and j["incomplete"] is False


def test_tls_con_huecos_marca_incomplete(client, tmp_path):
    frames = conversation(sport=443, turns=[("c", real_client_hello())], mss=150)
    frames = frames[:4] + frames[5:]
    load(client, tmp_path, frames)
    j = client.get("/api/sessions/0/tls").json()
    assert j["incomplete"] is True


def test_demo_sin_tls(demo):
    for sid in (3, 5, 7):
        j = demo.get(f"/api/sessions/{sid}/tls").json()
        assert j["tls"] is False and "incomplete" in j and j["incomplete"] in (True, False)


@pytest.mark.parametrize("sid", [999, -1])
def test_tls_inexistente_404(demo, sid):
    assert demo.get(f"/api/sessions/{sid}/tls").status_code == 404


def test_tls_certificado_vencido_segun_el_momento_de_la_sesion(client, tmp_path):
    expired = cert_message(cert(nb=("100101000000Z", False), na=("101231000000Z", False)))
    load(client, tmp_path, conversation(sport=443, turns=[("c", real_client_hello()), ("s", server_hello(0xC02F, 0x0303) + expired)], mss=1500))
    j = client.get("/api/sessions/0/tls").json()
    assert j["certificate"]["expired"] is True


def test_solo_get_en_las_rutas_nuevas(demo):
    for url in ("/api/hosts", "/api/graph", "/api/dns", "/api/http", "/api/sessions/3/explain", "/api/sessions/3/http", "/api/sessions/3/tls"):
        assert demo.post(url).status_code == 405


# ------------------------------------------------------------------ roles y duenos en /api/hosts y /api/graph

def roles_capture():
    return (
        conversation(c_ip="192.168.1.10", s_ip="160.79.104.10", sport=443, turns=[("c", b"x")], close=None)
        + conversation(c_ip="192.168.1.10", cport=40001, s_ip="142.250.1.1", sport=443, c_isn=9, s_isn=7, turns=[("c", b"y")], close=None)
        + [eth4(udp(5353, 5353, b"mdns"), 17, "192.168.1.10", "224.0.0.251")]
    )


def test_hosts_devuelve_rol_dueno_y_nota(client, tmp_path):
    load(client, tmp_path, roles_capture())
    by = {h["ip"]: h for h in client.get("/api/hosts").json()["items"]}
    assert (by["192.168.1.10"]["role"], by["192.168.1.10"]["role_label"], by["192.168.1.10"]["owner"]) == ("red_local", "Equipo de tu red", None)
    assert by["160.79.104.10"]["owner"] == "Anthropic" and by["160.79.104.10"]["role"] == "publica"
    assert by["142.250.1.1"]["owner"] == "Google"
    assert by["224.0.0.251"]["role"] == "multicast" and by["224.0.0.251"]["note"].startswith("mDNS") and by["224.0.0.251"]["owner"] is None


def test_graph_devuelve_los_campos_nuevos_en_cada_nodo(client, tmp_path):
    load(client, tmp_path, roles_capture())
    nodes = {n["ip"]: n for n in client.get("/api/graph").json()["nodes"]}
    for n in nodes.values():
        assert {"name", "role", "role_label", "owner", "note", "label"} <= set(n)
    assert nodes["160.79.104.10"]["owner"] == "Anthropic" and nodes["160.79.104.10"]["name"] is None
    assert nodes["224.0.0.251"]["role"] == "multicast"


def test_hosts_demo_todos_con_rol_valido(demo):
    items = demo.get("/api/hosts", params={"limit": 500}).json()["items"]
    assert all(h["role"] in {"red_local", "ipv6_local", "multicast", "publica"} and h["role_label"] for h in items)
    assert {h["role"] for h in items if h["ip"].startswith("192.168.")} == {"red_local"}


def test_hosts_el_nombre_de_la_captura_sigue_junto_al_dueno(client, tmp_path):
    frames = conversation(c_ip="192.168.1.10", s_ip="160.79.104.10", sport=443, turns=[("c", real_client_hello("backend.api.anthropic.com"))], close=None, mss=1500)
    load(client, tmp_path, frames)
    h = {h["ip"]: h for h in client.get("/api/hosts").json()["items"]}["160.79.104.10"]
    assert h["name"] == "backend.api.anthropic.com" and h["owner"] == "Anthropic"
    n = {n["ip"]: n for n in client.get("/api/graph").json()["nodes"]}["160.79.104.10"]
    assert n["label"] == "backend.api.anthropic.com" and n["name"] == "backend.api.anthropic.com"


# ------------------------------------------------------------------ sonda keep-alive en /explain

def test_explain_muestra_la_frase_de_la_sonda(client, tmp_path):
    from backend.domain.analysis.tests.convo import ACK, PSH, frame
    frames = [frame("10.0.0.1", 40000, "93.184.216.34", 80, 1000, PSH, b"\x00"), frame("93.184.216.34", 80, "10.0.0.1", 40000, 5000, ACK, b"")]
    load(client, tmp_path, frames)
    j = client.get("/api/sessions/0/explain").json()
    assert j["outcome"] == "en_curso"
    assert sum("Probable keep-alive" in s for s in j["summary"]) == 1


def test_explain_sin_sonda_no_trae_la_frase(demo):
    for sid in (3, 5, 7):
        assert not any("Probable keep-alive" in s for s in demo.get(f"/api/sessions/{sid}/explain").json()["summary"])


def test_explain_dos_keepalives_usa_la_frase_vieja(client, tmp_path):
    from backend.domain.analysis.tests.convo import PSH, frame
    frames = [frame("10.0.0.1", 40000, "93.184.216.34", 80, 1000, PSH, b"\x00"), frame("10.0.0.1", 40000, "93.184.216.34", 80, 1001, PSH, b"\x00")]
    load(client, tmp_path, frames)
    summary = client.get("/api/sessions/0/explain").json()["summary"]
    assert any("son un keep-alive" in s for s in summary) and not any("Probable keep-alive" in s for s in summary)
