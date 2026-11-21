"""Tests de backend/domain/analysis/owners.py y de los campos de dueño/rol en hosts y grafo."""
import ipaddress

import pytest

import backend.domain.analysis.owners as O
from backend.domain.analysis.hosts import Host, build_graph, build_hosts, classify
from backend.domain.analysis.owners import ROLE_LABELS, describe_ip, owner_of
from backend.domain.analysis.names import NameBook
from backend.domain.sessions.grouper import Session


def S(src, sport, dst, dport, proto="TCP", nbytes=100, key=None):
    return Session(proto, src, sport, dst, dport, 1, nbytes, 1.0, 2.0, key=key)


# ------------------------------------------------------------------ owner_of

@pytest.mark.parametrize("ip,owner", [
    ("142.250.1.1", "Google"), ("142.251.30.5", "Google"), ("8.8.8.8", "Google"), ("8.8.4.4", "Google"), ("74.125.200.1", "Google"),
    ("104.18.1.1", "Cloudflare"), ("1.1.1.1", "Cloudflare"), ("172.67.1.1", "Cloudflare"),
    ("160.79.104.10", "Anthropic"), ("160.79.105.255", "Anthropic"),
    ("150.171.1.1", "Microsoft"), ("40.84.1.1", "Microsoft"), ("20.1.2.3", "Microsoft"),
    ("18.97.1.1", "Amazon AWS"), ("52.1.2.3", "Amazon AWS"),
    ("151.101.1.1", "Fastly"), ("157.240.1.1", "Meta (Facebook / WhatsApp)"), ("17.253.1.1", "Apple"), ("140.82.113.4", "GitHub"),
    ("9.9.9.9", "Quad9 (DNS)"), ("208.67.222.222", "OpenDNS (DNS)"),
    ("2607:f8b0:4005::1", "Google"), ("2a00:1450:4001::1", "Google"), ("2606:4700:4700::1111", "Cloudflare"),
])
def test_owner_of_rangos_conocidos(ip, owner):
    assert owner_of(ip) == owner


@pytest.mark.parametrize("ip", [
    "93.184.216.34", "192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.251", "255.255.255.255",
    "142.249.255.255", "142.252.0.0", "160.79.103.255", "160.79.106.0", "104.15.255.255", "104.24.0.0", "2001:db8::1", "fe80::1", "::1", "ff02::fb",
])
def test_owner_of_sin_dueno(ip):
    assert owner_of(ip) is None


@pytest.mark.parametrize("bad", ["", "no-ip", "999.1.1.1", None, "1.2.3", "gggg::1", 42, b"x"])
def test_owner_of_basura_no_lanza(bad):
    assert owner_of(bad) is None


def test_owner_of_quita_zona_ipv6():
    assert owner_of("2a00:1450:4001::1%eth0") == "Google"


def test_owner_of_ipv4_mapeada_no_lanza():
    assert owner_of("::ffff:8.8.8.8") in (None, "Google")


def test_los_rangos_de_la_tabla_son_validos_y_no_se_pisan_entre_duenos():
    nets = [(o, ipaddress.ip_network(c)) for o, cs in O._OWNER_RANGES for c in cs]
    assert len(nets) == len(O._NETS)
    for i, (o1, n1) in enumerate(nets):
        assert n1.prefixlen > 0
        for o2, n2 in nets[i + 1:]:
            if o1 != o2 and n1.version == n2.version:
                assert not n1.overlaps(n2), (o1, n1, o2, n2)


def test_ningun_rango_cubre_direcciones_privadas_ni_especiales():
    for _, net in O._NETS:
        for probe in ("10.0.0.1", "192.168.0.1", "127.0.0.1", "169.254.0.1", "224.0.0.251", "fe80::1", "ff02::1"):
            a = ipaddress.ip_address(probe)
            assert not (a.version == net.version and a in net), (net, probe)


# ------------------------------------------------------------------ describe_ip

def test_describe_red_local():
    assert describe_ip("192.168.1.10", "interna") == {"role": "red_local", "role_label": ROLE_LABELS["red_local"], "owner": None, "note": None}


def test_describe_publica_con_y_sin_dueno():
    assert describe_ip("160.79.104.10", "publica") == {"role": "publica", "role_label": "Servidor en internet", "owner": "Anthropic", "note": None}
    assert describe_ip("93.184.216.34", "publica")["owner"] is None


@pytest.mark.parametrize("ip,fragment", [
    ("ff02::16", "MLD"), ("224.0.0.251", "mDNS"), ("224.0.0.22", "IGMP"), ("255.255.255.255", "Difusión"), ("224.0.0.1", "Todos los equipos"),
    ("224.0.0.252", "LLMNR"), ("239.255.255.250", "SSDP"), ("ff02::fb", "mDNS"), ("ff02::1", "Todos los equipos"), ("ff02::2", "routers"),
    ("ff02::1:2", "DHCPv6"), ("ff02::1:3", "LLMNR"),
])
def test_describe_direcciones_especiales_son_multicast_con_nota(ip, fragment):
    d = describe_ip(ip, classify(ip))
    assert d["role"] == "multicast" and d["role_label"] == ROLE_LABELS["multicast"] and d["owner"] is None
    assert fragment in d["note"]


def test_describe_broadcast_es_multicast_aunque_classify_diga_otra_cosa():
    assert describe_ip("255.255.255.255", "interna")["role"] == "multicast"
    assert describe_ip("255.255.255.255", "publica")["role"] == "multicast"


def test_describe_multicast_sin_nota_conocida():
    d = describe_ip("239.1.2.3", "multicast")
    assert d["role"] == "multicast" and d["note"] is None


@pytest.mark.parametrize("ip", ["fe80::1", "fd00::1", "::1", "fe80::1%eth0"])
def test_describe_ipv6_local(ip):
    d = describe_ip(ip, "interna")
    assert d["role"] == "ipv6_local" and d["role_label"] == ROLE_LABELS["ipv6_local"] and d["owner"] is None


def test_describe_ipv6_publica_con_y_sin_dueno():
    assert describe_ip("2a00:1450:4001::1", "publica")["owner"] == "Google"
    assert describe_ip("2001:db8::1", "publica")["owner"] is None


def test_describe_el_dueno_solo_se_da_a_las_publicas():
    assert describe_ip("8.8.8.8", "interna")["owner"] is None
    assert describe_ip("8.8.8.8", "multicast")["owner"] is None


@pytest.mark.parametrize("bad", ["", "no-ip", "999.1.1.1", None, "gggg::1"])
def test_describe_basura_es_publica_sin_nada(bad):
    assert describe_ip(bad, "publica") == {"role": "publica", "role_label": ROLE_LABELS["publica"], "owner": None, "note": None}


def test_todo_rol_tiene_etiqueta_y_los_textos_son_planos():
    assert set(ROLE_LABELS) == {"red_local", "ipv6_local", "multicast", "publica"}
    for text in list(ROLE_LABELS.values()) + list(O._SPECIAL.values()) + [o for o, _ in O._OWNER_RANGES]:
        assert text.strip() and "<" not in text


def test_describe_siempre_devuelve_las_cuatro_claves():
    for ip, k in [("10.0.0.1", "interna"), ("8.8.8.8", "publica"), ("ff02::1", "multicast"), ("fe80::1", "interna"), ("x", "publica")]:
        assert set(describe_ip(ip, k)) == {"role", "role_label", "owner", "note"}


# ------------------------------------------------------------------ build_hosts / build_graph

def test_hosts_traen_rol_dueno_y_nota():
    sessions = [
        S("192.168.1.10", 51000, "160.79.104.10", 443),
        S("192.168.1.10", 5353, "224.0.0.251", 5353, "UDP"),
        S("fe80::1", 40000, "ff02::16", 5000, "UDP"),
        S("fe80::1", 40001, "2a00:1450:4001::1", 443),
    ]
    by = {h.ip: h for h in build_hosts(sessions)}
    assert (by["192.168.1.10"].role, by["192.168.1.10"].role_label, by["192.168.1.10"].owner) == ("red_local", "Equipo de tu red", None)
    assert (by["160.79.104.10"].role, by["160.79.104.10"].owner, by["160.79.104.10"].note) == ("publica", "Anthropic", None)
    assert (by["224.0.0.251"].role, by["224.0.0.251"].note) == ("multicast", "mDNS (descubrir equipos por nombre)")
    assert by["ff02::16"].role == "multicast" and "MLD" in by["ff02::16"].note
    assert by["fe80::1"].role == "ipv6_local" and by["fe80::1"].owner is None
    assert by["2a00:1450:4001::1"].owner == "Google"


def test_el_nombre_de_la_captura_convive_con_el_dueno():
    s = S("10.0.0.1", 50000, "160.79.104.10", 443, key=("k",))
    h = {h.ip: h for h in build_hosts([s], NameBook(sni={("k",): "backend.api.anthropic.com"}))}["160.79.104.10"]
    assert h.name == "backend.api.anthropic.com" and h.owner == "Anthropic"


def test_host_por_defecto_es_publica_sin_dueno():
    h = Host("1.2.3.4", "publica")
    assert (h.role, h.role_label, h.owner, h.note) == ("publica", "", None, None)


def test_nodos_del_grafo_traen_nombre_rol_dueno_y_nota():
    ss = [S("192.168.1.10", 51000, "160.79.104.10", 443, key=("k",)), S("192.168.1.10", 5353, "224.0.0.251", 5353, "UDP")]
    hosts = build_hosts(ss, NameBook(sni={("k",): "backend.api.anthropic.com"}))
    nodes = {n["ip"]: n for n in build_graph(ss, hosts, 10)["nodes"]}
    assert nodes["160.79.104.10"]["name"] == "backend.api.anthropic.com" and nodes["160.79.104.10"]["owner"] == "Anthropic"
    assert nodes["160.79.104.10"]["label"] == "backend.api.anthropic.com" and nodes["160.79.104.10"]["role"] == "publica"
    assert nodes["192.168.1.10"]["name"] is None and nodes["192.168.1.10"]["role"] == "red_local" and nodes["192.168.1.10"]["owner"] is None
    assert nodes["224.0.0.251"]["role"] == "multicast" and nodes["224.0.0.251"]["note"].startswith("mDNS")
    assert nodes["224.0.0.251"]["role_label"] == ROLE_LABELS["multicast"]


def test_nodo_sin_nombre_de_captura_conserva_label_ip_y_dueno_aparte():
    ss = [S("192.168.1.10", 51000, "142.250.1.1", 443)]
    n = {n["ip"]: n for n in build_graph(ss, build_hosts(ss), 5)["nodes"]}["142.250.1.1"]
    assert n["label"] == "142.250.1.1" and n["name"] is None and n["owner"] == "Google"
