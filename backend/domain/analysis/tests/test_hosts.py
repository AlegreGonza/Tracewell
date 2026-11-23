"""Tests de backend/domain/analysis/hosts.py: vista por equipo y grafo."""
import pytest

import backend.domain.analysis.hosts as H
from backend.domain.analysis.hosts import Host, _server_is_src, build_graph, build_hosts, classify
from backend.domain.rules.iocs import IocSet
from backend.domain.analysis.names import NameBook
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import Session


def S(src, sport, dst, dport, proto="TCP", packets=1, nbytes=100, key=None):
    return Session(proto, src, sport, dst, dport, packets, nbytes, 1.0, 2.0, key=key)


def alert(src, dst, rule="r1"):
    return Alert(rule, rule, "high", "T1", "n", "t", "d", src, dst, 1.0)


# ------------------------------------------------------------------ classify

@pytest.mark.parametrize("ip,kind", [
    ("10.0.0.1", "interna"), ("192.168.1.5", "interna"), ("172.16.0.1", "interna"), ("172.31.255.255", "interna"),
    ("127.0.0.1", "interna"), ("169.254.1.1", "interna"), ("fe80::1", "interna"), ("fd00::1", "interna"), ("::1", "interna"),
    ("8.8.8.8", "publica"), ("93.184.216.34", "publica"), ("2a00:1450::1", "publica"), ("172.32.0.1", "publica"),
    ("224.0.0.251", "multicast"), ("239.255.255.250", "multicast"), ("ff02::fb", "multicast"),
])
def test_classify(ip, kind):
    assert classify(ip) == kind


@pytest.mark.parametrize("junk", ["", "no-ip", "999.1.1.1", None, "10.0.0", "abc::zzz"])
def test_classify_basura_es_publica(junk):
    assert classify(junk) == "publica"


def test_classify_quita_zona_ipv6():
    assert classify("fe80::1%eth0") == "interna"
    assert classify("ff02::1%12") == "multicast"


# ------------------------------------------------------------------ _server_is_src

@pytest.mark.parametrize("s,expected", [
    (S("10.0.0.1", 50000, "8.8.8.8", 443), False),  # cliente efimero -> servidor en destino
    (S("8.8.8.8", 443, "10.0.0.1", 50000), True),  # captura a mitad: el servidor es el origen
    (S("10.0.0.1", 22, "10.0.0.2", 40000), True),
    (S("10.0.0.1", 40000, "10.0.0.2", 22), False),
])
def test_server_is_src_por_puerto(s, expected):
    assert _server_is_src(s) is expected


def test_server_is_src_puertos_ambos_altos_usa_la_red():
    assert _server_is_src(S("8.8.8.8", 40000, "10.0.0.1", 50000)) is True  # el publico es el servidor
    assert _server_is_src(S("10.0.0.1", 40000, "8.8.8.8", 50000)) is False


def test_server_is_src_ambos_internos_o_ambos_publicos_es_destino():
    assert _server_is_src(S("10.0.0.1", 40000, "10.0.0.2", 50000)) is False
    assert _server_is_src(S("8.8.8.8", 40000, "1.1.1.1", 50000)) is False


def test_server_is_src_ambos_bajos_o_sin_puertos():
    assert _server_is_src(S("10.0.0.1", 80, "8.8.8.8", 443)) is False  # ninguno decide por puerto; el interno es src
    assert _server_is_src(S("8.8.8.8", None, "10.0.0.1", None, proto="ICMP")) is True  # sin puertos: por la red
    assert _server_is_src(S("10.0.0.1", None, "8.8.8.8", None, proto="ICMP")) is False


# ------------------------------------------------------------------ build_hosts

def test_vacio():
    assert build_hosts([]) == []


def test_una_sesion_cuenta_para_los_dos_extremos():
    hosts = build_hosts([S("10.0.0.1", 50000, "8.8.8.8", 443, packets=5, nbytes=500)])
    assert len(hosts) == 2
    for h in hosts:
        assert (h.sessions, h.packets, h.bytes, h.peers) == (1, 5, 500, 1) and h.protocols == ["TCP"]
    by = {h.ip: h for h in hosts}
    assert (by["10.0.0.1"].initiated, by["10.0.0.1"].received) == (1, 0)
    assert (by["8.8.8.8"].initiated, by["8.8.8.8"].received) == (0, 1)
    assert by["10.0.0.1"].kind == "interna" and by["8.8.8.8"].kind == "publica"


def test_suma_de_sesiones_por_host_es_el_doble_de_las_sesiones():
    sessions = [S("10.0.0.1", 40000 + i, f"8.8.8.{i}", 443) for i in range(7)] + [S("10.0.0.2", 5, "10.0.0.1", 53, "UDP")]
    hosts = build_hosts(sessions)
    assert sum(h.sessions for h in hosts) == 2 * len(sessions)
    assert sum(h.initiated + h.received for h in hosts) == 2 * len(sessions)


def test_orden_bytes_desc_luego_sesiones_luego_ip():
    sessions = [
        S("10.0.0.9", 1, "10.0.0.8", 2, nbytes=500),  # ambos 500
        S("10.0.0.5", 1, "10.0.0.6", 2, nbytes=100), S("10.0.0.5", 3, "10.0.0.6", 4, nbytes=100),  # 200, 2 sesiones
        S("10.0.0.3", 1, "10.0.0.4", 2, nbytes=200),  # 200, 1 sesion
    ]
    assert [h.ip for h in build_hosts(sessions)] == ["10.0.0.8", "10.0.0.9", "10.0.0.5", "10.0.0.6", "10.0.0.3", "10.0.0.4"]


def test_iniciadas_y_recibidas_son_literales_por_origen_y_destino():
    sessions = [S("10.0.0.1", 40000, "10.0.0.2", 80), S("10.0.0.1", 40001, "10.0.0.2", 80), S("10.0.0.2", 80, "10.0.0.1", 40002)]
    by = {h.ip: h for h in build_hosts(sessions)}
    assert (by["10.0.0.1"].initiated, by["10.0.0.1"].received) == (2, 1)
    assert (by["10.0.0.2"].initiated, by["10.0.0.2"].received) == (1, 2)


def test_servicios_solo_del_lado_servidor_y_top_5():
    sessions = [S("10.0.0.1", 40000 + i, "8.8.8.8", port) for i, port in enumerate([443, 443, 443, 80, 80, 53, 22, 25, 110, 143])]
    by = {h.ip: h for h in build_hosts(sessions)}
    assert by["10.0.0.1"].services == []  # el cliente no ofrece servicios
    svc = by["8.8.8.8"].services
    assert len(svc) == 5 and svc[0] == {"protocol": "TCP", "port": 443, "sessions": 3} and svc[1] == {"protocol": "TCP", "port": 80, "sessions": 2}


def test_servicios_distinguen_protocolo():
    hosts = build_hosts([S("10.0.0.1", 40000, "10.0.0.2", 53, "UDP"), S("10.0.0.1", 40001, "10.0.0.2", 53, "TCP")])
    srv = next(h for h in hosts if h.ip == "10.0.0.2")
    assert {(s["protocol"], s["port"]) for s in srv.services} == {("UDP", 53), ("TCP", 53)}


def test_sesion_invertida_no_etiqueta_al_cliente():
    """Captura a mitad: el 'origen' es el servidor 443."""
    s = S("93.184.216.34", 443, "10.0.0.1", 51000)
    names = NameBook(sni={("k",): "example.com"})
    s.key = ("k",)
    by = {h.ip: h for h in build_hosts([s], names)}
    assert by["93.184.216.34"].name == "example.com" and by["93.184.216.34"].services == [{"protocol": "TCP", "port": 443, "sessions": 1}]
    assert by["10.0.0.1"].name is None and by["10.0.0.1"].services == []


def test_nombre_va_al_servidor_normal():
    s = S("10.0.0.1", 51000, "93.184.216.34", 443, key=("k",))
    by = {h.ip: h for h in build_hosts([s], NameBook(sni={("k",): "example.com"}))}
    assert by["93.184.216.34"].name == "example.com" and by["10.0.0.1"].name is None


def test_nombre_mas_frecuente_del_servidor():
    sessions = [S("10.0.0.1", 40000 + i, "1.2.3.4", 443, key=("k", i)) for i in range(3)]
    names = NameBook(sni={("k", 0): "a.test", ("k", 1): "b.test", ("k", 2): "b.test"})
    assert next(h for h in build_hosts(sessions, names) if h.ip == "1.2.3.4").name == "b.test"


def test_nombre_de_respaldo_por_dns_de_la_ip():
    s = S("10.0.0.1", 40000, "10.0.0.2", 50000)  # ningun nombre de sesion
    names = NameBook(dns={"10.0.0.2": "nas.local"})
    by = {h.ip: h for h in build_hosts([s], names)}
    # best_name(s) usa DNS del destino
    assert by["10.0.0.2"].name == "nas.local"
    assert by["10.0.0.1"].name is None


def test_names_none_no_rompe():
    assert all(h.name is None for h in build_hosts([S("10.0.0.1", 1, "8.8.8.8", 443)], None))


def test_peers_distintos_y_repetidos():
    sessions = [S("10.0.0.1", 40000 + i, "8.8.8.8" if i % 2 else "8.8.4.4", 443) for i in range(10)]
    assert next(h for h in build_hosts(sessions) if h.ip == "10.0.0.1").peers == 2


def test_max_peers_acota_pero_sigue_contando(monkeypatch):
    monkeypatch.setattr(H, "MAX_PEERS", 3)
    sessions = [S("10.0.0.1", 40000 + i, f"45.0.0.{i}", 443) for i in range(10)]
    h = next(h for h in build_hosts(sessions) if h.ip == "10.0.0.1")
    assert h.peers == 10 and h.sessions == 10  # 3 recordados + 7 de desborde


def test_max_peers_repetido_no_cuenta_desborde(monkeypatch):
    monkeypatch.setattr(H, "MAX_PEERS", 2)
    sessions = [S("10.0.0.1", 40000 + i, f"45.0.0.{i % 2}", 443) for i in range(10)]
    assert next(h for h in build_hosts(sessions) if h.ip == "10.0.0.1").peers == 2


def test_alertas_por_ip_reglas_ordenadas_y_unica_cuenta():
    sessions = [S("10.0.0.1", 1, "8.8.8.8", 443)]
    alerts = [alert("10.0.0.1", "8.8.8.8", "b_rule"), alert("10.0.0.1", "8.8.8.8", "a_rule"), alert("10.0.0.1", "10.0.0.1", "self")]
    by = {h.ip: h for h in build_hosts(sessions, None, alerts)}
    assert by["10.0.0.1"].alerts == 3 and by["10.0.0.1"].alert_rules == ["a_rule", "b_rule", "self"]  # src==dst cuenta una vez
    assert by["8.8.8.8"].alerts == 2 and by["8.8.8.8"].alert_rules == ["a_rule", "b_rule"]


def test_alerta_de_una_ip_sin_sesiones_no_crea_host():
    assert build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2)], None, [alert("9.9.9.9", "10.0.0.1")])[0].alerts in (0, 1)
    assert "9.9.9.9" not in {h.ip for h in build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2)], None, [alert("9.9.9.9", "10.0.0.1")])}


def test_alertas_aceptan_generador():
    h = build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2)], None, (a for a in [alert("10.0.0.1", "10.0.0.2")]))
    assert all(x.alerts == 1 for x in h)


def test_ioc_por_match_ip():
    ioc = IocSet(ips=frozenset({"8.8.8.8"}))
    by = {h.ip: h for h in build_hosts([S("10.0.0.1", 1, "8.8.8.8", 443)], None, (), ioc)}
    assert by["8.8.8.8"].ioc == ["ip:8.8.8.8"] and by["10.0.0.1"].ioc == []


def test_ioc_por_red_y_sin_ioc():
    ioc = IocSet(networks=(__import__("ipaddress").ip_network("10.0.0.0/8"),))
    assert all(h.ioc for h in build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2)], None, (), ioc))
    assert all(h.ioc == [] for h in build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2)], None, (), None))


def test_protocolos_ordenados():
    hosts = build_hosts([S("10.0.0.1", 1, "10.0.0.2", 2, "UDP"), S("10.0.0.1", 3, "10.0.0.2", 4, "TCP"), S("10.0.0.1", None, "10.0.0.2", None, "ICMP")])
    assert hosts[0].protocols == ["ICMP", "TCP", "UDP"]


def test_ip_ilegible_es_publica_y_no_rompe():
    hosts = build_hosts([S("raro", 1, "10.0.0.1", 80)])
    assert {h.ip: h.kind for h in hosts} == {"raro": "publica", "10.0.0.1": "interna"}


def test_host_es_dataclass_serializable():
    from dataclasses import asdict
    d = asdict(build_hosts([S("10.0.0.1", 1, "8.8.8.8", 443)])[0])
    assert set(d) == {"ip", "kind", "sessions", "packets", "bytes", "initiated", "received", "peers", "protocols", "services",
                      "name", "alerts", "alert_rules", "ioc", "role", "role_label", "owner", "note", "roles", "mac"}
    assert isinstance(Host("x", "publica"), Host)


# ------------------------------------------------------------------ build_graph

def graph_sessions():
    return [
        S("10.0.0.1", 40000, "8.8.8.8", 443, nbytes=1000), S("8.8.8.8", 443, "10.0.0.1", 40001, "UDP", nbytes=500),  # misma pareja
        S("10.0.0.1", 40002, "10.0.0.2", 22, nbytes=300),
        S("10.0.0.1", 1, "10.0.0.1", 2, nbytes=999),  # lazo propio
        S("10.0.0.3", 40003, "1.1.1.1", 443, nbytes=50),
    ]


def test_grafo_basico_pares_sin_orientar_y_protocolos():
    ss = graph_sessions()
    g = build_graph(ss, build_hosts(ss), 10)
    by_pair = {(e["a"], e["b"]): e for e in g["edges"]}
    e = by_pair[("10.0.0.1", "8.8.8.8")]
    assert (e["bytes"], e["sessions"], e["protocols"]) == (1500, 2, ["TCP", "UDP"])
    assert all(e["a"] < e["b"] for e in g["edges"])
    assert not any(e["a"] == e["b"] for e in g["edges"])  # sin lazos propios


def test_aristas_ordenadas_por_bytes():
    ss = graph_sessions()
    g = build_graph(ss, build_hosts(ss), 10)
    assert [e["bytes"] for e in g["edges"]] == sorted((e["bytes"] for e in g["edges"]), reverse=True)


def test_limit_elige_los_de_mas_trafico_y_solo_aristas_entre_ellos():
    ss = graph_sessions()
    hosts = build_hosts(ss)
    g = build_graph(ss, hosts, 2)
    ips = [n["ip"] for n in g["nodes"]]
    assert ips == [h.ip for h in hosts[:2]]
    assert all(e["a"] in ips and e["b"] in ips for e in g["edges"])
    assert g["truncated"] is True


def test_truncated_false_si_caben_todos():
    ss = graph_sessions()
    hosts = build_hosts(ss)
    assert build_graph(ss, hosts, len(hosts))["truncated"] is False


def test_max_edges_acota_y_marca_truncated(monkeypatch):
    monkeypatch.setattr(H, "MAX_EDGES", 3)
    ss = [S("10.0.0.1", 40000 + i, f"10.0.1.{i}", 80, nbytes=100 + i) for i in range(10)]
    g = build_graph(ss, build_hosts(ss), 60)
    assert len(g["edges"]) == 3 and g["truncated"] is True
    assert [e["bytes"] for e in g["edges"]] == [109, 108, 107]  # las de mas trafico


def test_nodos_con_etiqueta_nombre_o_ip_y_banderas():
    s = S("10.0.0.1", 40000, "8.8.8.8", 443, key=("k",))
    hosts = build_hosts([s], NameBook(sni={("k",): "dns.google"}), [alert("10.0.0.1", "8.8.8.8")], IocSet(ips=frozenset({"8.8.8.8"})))
    nodes = {n["ip"]: n for n in build_graph([s], hosts, 5)["nodes"]}
    assert nodes["8.8.8.8"]["label"] == "dns.google" and nodes["8.8.8.8"]["ioc"] is True and nodes["8.8.8.8"]["alerts"] == 1
    assert nodes["10.0.0.1"]["label"] == "10.0.0.1" and nodes["10.0.0.1"]["ioc"] is False
    assert set(nodes["8.8.8.8"]) == {"ip", "kind", "label", "bytes", "sessions", "alerts", "ioc", "name", "role", "role_label", "owner", "note"}


def test_grafo_vacio():
    assert build_graph([], [], 5) == {"nodes": [], "edges": [], "truncated": False}


def test_grafo_limit_cero_no_tiene_nodos():
    ss = graph_sessions()
    g = build_graph(ss, build_hosts(ss), 0)
    assert g["nodes"] == [] and g["edges"] == [] and g["truncated"] is True
