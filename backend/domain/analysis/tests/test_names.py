"""Tests de backend/domain/analysis/names.py: nombres de sitio desde DNS y SNI (paquetes armados con dpkt/bytes, sin red)."""
import socket
from types import SimpleNamespace

import dpkt
import pytest

import backend.domain.analysis.names as names_mod
from backend.domain.analysis.names import (
    MAX_NAME_LEN, NameBook, _clean_name, _first_host_name, _norm, collect_names, dns_names,
    sni_from_client_hello,
)
from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import Session, _key

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"


# ------------------------------------------------------------ constructores

def client_hello(sni="example.com", *, session_id=b"", before=(), after=(), name_type=0,
                 sni_ext=True, raw_name=None, tls_minor=3):
    """ClientHello TLS armado a mano. `before`/`after`: extensiones (tipo, cuerpo) antes/después del SNI."""
    exts = b""
    for kind, body in before:
        exts += kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    if sni_ext:
        name = sni.encode() if raw_name is None else raw_name
        entry = bytes([name_type]) + len(name).to_bytes(2, "big") + name
        lst = len(entry).to_bytes(2, "big") + entry
        exts += b"\x00\x00" + len(lst).to_bytes(2, "big") + lst
    for kind, body in after:
        exts += kind.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    body = b"\x03\x03" + b"\x11" * 32
    body += bytes([len(session_id)]) + session_id
    body += b"\x00\x04\x13\x01\x13\x02"  # 2 cipher suites
    body += b"\x01\x00"  # compresión: solo null
    body += len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03" + bytes([tls_minor]) + len(hs).to_bytes(2, "big") + hs


def dns_response(qname="example.com", answers=(), *, rcode=0, qr=1, qtype=dpkt.dns.DNS_A, no_question=False):
    """Mensaje DNS. `answers`: lista de ('A'|'AAAA'|'CNAME', valor)."""
    msg = dpkt.dns.DNS(id=1, qr=qr, rcode=rcode)
    if not no_question:
        msg.qd = [dpkt.dns.DNS.Q(name=qname, type=qtype)]
    for kind, val in answers:
        rr = dpkt.dns.DNS.RR(name=qname, ttl=60)
        if kind == "A":
            rr.type, rr.ip = dpkt.dns.DNS_A, socket.inet_pton(socket.AF_INET, val)
        elif kind == "AAAA":
            rr.type, rr.ip6 = dpkt.dns.DNS_AAAA, socket.inet_pton(socket.AF_INET6, val)
        else:
            rr.type, rr.cname = dpkt.dns.DNS_CNAME, val
        msg.an.append(rr)
    return bytes(msg)


def eth4(l4, proto, src="10.0.0.1", dst="10.0.0.2", vlan=None):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, data=l4)
    ip.len = len(bytes(ip))
    raw = bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
    if vlan is not None:
        raw = raw[:12] + b"\x81\x00" + vlan.to_bytes(2, "big") + raw[12:]
    return raw


def eth6(l4, nxt, src="2001:db8::1", dst="2001:db8::2"):
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src), dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=nxt, plen=len(bytes(l4)), data=l4)
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip))


def tcp(sport, dport, payload):
    return dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)


def udp(sport, dport, payload):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = len(bytes(u))
    return u


def pk(raw, ts=1.0):
    return Packet(ts, raw, len(raw))


# ------------------------------------------------------------ _clean_name / _norm

@pytest.mark.parametrize("raw,expected", [
    (b"Example.COM", "example.com"),
    (b"example.com.", "example.com"),
    (b"  a.b  ", "a.b"),
    ("Ejemplo.Org", "ejemplo.org"),
    (bytearray(b"X.Y"), "x.y"),
])
def test_clean_name_normaliza(raw, expected):
    """Minúsculas, sin punto final ni espacios de los extremos."""
    assert _clean_name(raw) == expected


@pytest.mark.parametrize("raw", [
    b"", b".", b"   ", b"a b.com", b"caf\xc3\xa9.com", b"\xff\xfe", b"a\x00b.com", b"a\nb.com",
    b"a" * (MAX_NAME_LEN + 1),
])
def test_clean_name_rechaza(raw):
    """Vacío, con espacios, no ASCII, no imprimible o demasiado largo -> None."""
    assert _clean_name(raw) is None


def test_clean_name_largo_maximo_es_valido():
    assert _clean_name(b"a" * MAX_NAME_LEN) == "a" * MAX_NAME_LEN


def test_clean_name_str_no_ascii_pasa_como_texto():
    """Un str (ya decodificado) no se valida como ASCII: solo imprimible."""
    assert _clean_name("café.com") == "café.com"


def test_norm_ipv6_y_zona_y_basura():
    assert _norm("2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert _norm("fe80::1%eth0") == "fe80::1"
    assert _norm("10.0.0.1") == "10.0.0.1"
    assert _norm("no-es-ip") == "no-es-ip"


# ------------------------------------------------------------ DNS

def test_dns_respuesta_a():
    assert dns_names(dns_response("Example.COM", [("A", "93.184.216.34")])) == [("93.184.216.34", "example.com")]


def test_dns_respuesta_aaaa_normaliza_ipv6():
    got = dns_names(dns_response("v6.test", [("AAAA", "2001:0db8:0000:0000:0000:0000:0000:0001")]))
    assert got == [("2001:db8::1", "v6.test")]


def test_dns_varias_respuestas_a_y_aaaa():
    got = dns_names(dns_response("m.test", [("A", "1.1.1.1"), ("AAAA", "::2"), ("A", "2.2.2.2")]))
    assert got == [("1.1.1.1", "m.test"), ("::2", "m.test"), ("2.2.2.2", "m.test")]


def test_dns_cname_usa_el_nombre_consultado_no_el_canonico():
    """www.x.com -> CNAME cdn.net -> A: la IP queda con el nombre que se PIDIÓ."""
    msg = dns_response("www.x.com", [("CNAME", "edge.cdn.net"), ("A", "9.9.9.9")])
    assert dns_names(msg) == [("9.9.9.9", "www.x.com")]


def test_dns_solo_cname_no_da_nada():
    assert dns_names(dns_response("www.x.com", [("CNAME", "edge.cdn.net")])) == []


def test_dns_nxdomain_y_otros_rcode_se_ignoran():
    for rcode in (3, 2, 5):
        assert dns_names(dns_response("x.com", [("A", "1.2.3.4")], rcode=rcode)) == []


def test_dns_consulta_qr0_se_ignora():
    assert dns_names(dns_response("x.com", [("A", "1.2.3.4")], qr=0)) == []


def test_dns_sin_pregunta_se_ignora():
    assert dns_names(dns_response("x.com", [("A", "1.2.3.4")], no_question=True)) == []


def test_dns_nombre_invalido_en_pregunta_da_vacio():
    assert dns_names(dns_response("", [("A", "1.2.3.4")])) == []


def test_dns_nombre_con_mayusculas():
    msg = dns_response("WWW.Example.Com", [("A", "5.5.5.5")])
    assert dns_names(msg) == [("5.5.5.5", "www.example.com")]


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x00" * 11, b"\xff" * 12, b"\xff" * 64, b"basura" * 5])
def test_dns_basura_no_lanza(payload):
    assert dns_names(payload) == []


def test_dns_truncado_en_cada_longitud_no_lanza():
    msg = dns_response("example.com", [("A", "1.2.3.4"), ("AAAA", "::1")])
    for n in range(len(msg) + 1):
        out = dns_names(msg[:n])
        assert isinstance(out, list)
    assert dns_names(msg[:-1]) == [] or isinstance(dns_names(msg[:-1]), list)


def test_dns_registro_a_con_ip_corta_no_invalida_los_demas(monkeypatch):
    """Un registro raro se salta; los demás siguen valiendo."""
    bad = SimpleNamespace(type=dpkt.dns.DNS_A, ip=b"\x01\x02")
    good = SimpleNamespace(type=dpkt.dns.DNS_A, ip=socket.inet_aton("7.7.7.7"))
    noattr = SimpleNamespace(type=dpkt.dns.DNS_AAAA)
    assert names_mod._answer_ips(SimpleNamespace(an=[bad, noattr, good])) == ["7.7.7.7"]


# ------------------------------------------------------------ SNI

def test_sni_basico():
    assert sni_from_client_hello(client_hello("example.com")) == "example.com"


def test_sni_se_normaliza():
    assert sni_from_client_hello(client_hello("WWW.Example.COM.")) == "www.example.com"


def test_sni_con_session_id():
    assert sni_from_client_hello(client_hello("a.test", session_id=b"\xaa" * 32)) == "a.test"


def test_sni_con_extensiones_antes_y_despues():
    hello = client_hello("mid.test", before=[(0x000a, b"\x00\x02\x00\x1d"), (0x000b, b"\x01\x00")],
                         after=[(0x0010, b"\x00\x03\x02h2"), (0xff01, b"\x00")])
    assert sni_from_client_hello(hello) == "mid.test"


def test_sni_primera_o_ultima_extension():
    assert sni_from_client_hello(client_hello("first.test", after=[(0x0017, b"")])) == "first.test"
    assert sni_from_client_hello(client_hello("last.test", before=[(0x0017, b"")])) == "last.test"


def test_sni_sin_extension_server_name():
    assert sni_from_client_hello(client_hello(sni_ext=False, before=[(0x000a, b"\x00\x02\x00\x1d")])) is None


def test_sni_sin_ninguna_extension():
    assert sni_from_client_hello(client_hello(sni_ext=False)) is None


def test_sni_name_type_distinto_de_cero():
    assert sni_from_client_hello(client_hello("x.test", name_type=1)) is None


def test_sni_nombre_vacio():
    assert sni_from_client_hello(client_hello(raw_name=b"")) is None


@pytest.mark.parametrize("raw", [b"has space.test", b"caf\xc3\xa9.test", b"a" * 300, b"\x00\x01"])
def test_sni_nombre_invalido(raw):
    assert sni_from_client_hello(client_hello(raw_name=raw)) is None


def test_sni_largos_enormes_no_lanzan():
    """Largos declarados mayores que el paquete: None, nunca excepción."""
    h = bytearray(client_hello("big.test"))
    for pos in (3, 4, 6, 7, 8, 9):  # largo del registro y del handshake
        g = bytearray(h)
        g[pos] = 0xFF
        sni_from_client_hello(bytes(g))
    # session_id gigante
    g = bytearray(h)
    g[5 + 4 + 2 + 32] = 0xFF
    assert sni_from_client_hello(bytes(g)) is None


def test_sni_largo_de_extension_enorme_analiza_lo_que_haya():
    """El largo de las extensiones excede el paquete: se lee lo disponible."""
    h = bytearray(client_hello("cut.test"))
    exts_len_pos = 5 + 4 + 2 + 32 + 1 + 2 + 4 + 2
    h[exts_len_pos:exts_len_pos + 2] = b"\xff\xff"
    assert sni_from_client_hello(bytes(h)) == "cut.test"


def test_sni_largo_de_extension_individual_enorme():
    """Una extensión previa con largo desbordado: no encuentra SNI y no lanza."""
    h = client_hello("zz.test", before=[(0x000a, b"\x00\x02\x00\x1d")])
    h = bytearray(h)
    idx = h.index(b"\x00\x0a\x00\x04")
    h[idx + 2:idx + 4] = b"\xff\xff"
    assert sni_from_client_hello(bytes(h)) is None


@pytest.mark.parametrize("hello", [
    client_hello("t.test"),
    client_hello("t.test", session_id=b"\x01" * 32, before=[(0x000a, b"\x00\x02\x00\x1d")], after=[(0x0010, b"\x00")]),
])
def test_sni_truncado_en_cada_longitud_no_lanza(hello):
    """Cortar el ClientHello en CADA longitud: nunca lanza; lo que dé es el nombre o un prefijo suyo."""
    for n in range(len(hello) + 1):
        out = sni_from_client_hello(hello[:n])
        assert out is None or "t.test".startswith(out)
    assert sni_from_client_hello(hello) == "t.test"


def test_sni_cortado_dentro_del_nombre_no_devuelve_nombre_parcial():
    hello = client_hello("t.test")
    assert sni_from_client_hello(hello[:-3]) is None


def test_sni_truncado_justo_en_el_nombre_se_recorta_o_none():
    """Si se corta dentro del nombre, no debe devolver un nombre falso más largo."""
    hello = client_hello("abcdef.test")
    cut = hello[:-3]  # corta los últimos 3 bytes del nombre (último campo)
    out = sni_from_client_hello(cut)
    assert out is None or "abcdef.test".startswith(out)


@pytest.mark.parametrize("payload", [
    b"", b"\x16", b"\x16\x03", b"\x16\x03\x03\x00\x05", b"\x17\x03\x03\x00\x05\x01",
    b"\x16\x02\x00\x00\x00\x01", b"\x16\x03\x03\x00\x05\x02" + b"\x00" * 50, b"GET / HTTP/1.1\r\n",
    b"\x16\x03\x01\x00\x30\x01" + b"\x00" * 3,
])
def test_sni_no_es_client_hello(payload):
    assert sni_from_client_hello(payload) is None


def test_sni_ServerHello_no_vale():
    h = bytearray(client_hello("x.test"))
    h[5] = 0x02
    assert sni_from_client_hello(bytes(h)) is None


def test_sni_version_tls_distinta_de_la_ultima_se_acepta():
    assert sni_from_client_hello(client_hello("old.test", tls_minor=1)) == "old.test"


def test_sni_fuzz_con_semilla_no_lanza():
    import random
    rnd = random.Random(99)
    base = client_hello("fz.test", session_id=b"\x07" * 8, before=[(0x0017, b"")], after=[(0x0010, b"\x00\x03\x02h2")])
    for _ in range(3000):
        b = bytearray(base)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        out = sni_from_client_hello(bytes(b)[:rnd.randint(0, len(b))])
        assert out is None or isinstance(out, str)


def test_first_host_name_bordes():
    assert _first_host_name(b"") is None
    assert _first_host_name(b"\x00\x04\x00\x00") is None  # muy corto
    assert _first_host_name(b"\x00\x04\x00\x00\x00") is None  # largo 0 (size==0 -> None)
    assert _first_host_name(b"\x00\x06\x00\x00\x03abc") == "abc"
    assert _first_host_name(b"\x00\x06\x00\x00\x09abc") is None  # largo declarado excede: nombre cortado, se descarta
    assert _first_host_name(b"\x00\x08\x00\x00\x03abcde") == "abc"  # bytes de más al final: se ignoran


# ------------------------------------------------------------ NameBook

def sess(src="10.0.0.1", sport=1111, dst="10.0.0.2", dport=443, proto=6, key="auto"):
    k = _key(src, sport, dst, dport, proto) if key == "auto" else key
    return Session("TCP", src, sport, dst, dport, key=k)


def test_namebook_vacio():
    b = NameBook()
    s = sess()
    assert b.names_for(s) == [] and b.best_name(s) is None


def test_namebook_sni_primero_luego_dns_destino_luego_origen():
    s = sess()
    b = NameBook(dns={"10.0.0.2": "dst.test", "10.0.0.1": "src.test"}, sni={s.key: "sni.test"})
    assert b.names_for(s) == ["sni.test", "dst.test", "src.test"]
    assert b.best_name(s) == "sni.test"


def test_namebook_sin_sni_gana_dns_del_destino():
    s = sess()
    b = NameBook(dns={"10.0.0.2": "dst.test", "10.0.0.1": "src.test"})
    assert b.best_name(s) == "dst.test"


def test_namebook_solo_dns_del_origen():
    s = sess()
    assert NameBook(dns={"10.0.0.1": "src.test"}).names_for(s) == ["src.test"]


def test_namebook_deduplica_manteniendo_orden():
    s = sess()
    b = NameBook(dns={"10.0.0.2": "same.test", "10.0.0.1": "same.test"}, sni={s.key: "same.test"})
    assert b.names_for(s) == ["same.test"]
    b2 = NameBook(dns={"10.0.0.2": "b.test", "10.0.0.1": "a.test"}, sni={s.key: "b.test"})
    assert b2.names_for(s) == ["b.test", "a.test"]


def test_namebook_session_key_none_no_consulta_sni():
    s = sess(key=None)
    b = NameBook(dns={"10.0.0.2": "dst.test"}, sni={None: "no-debe.test"})
    assert b.names_for(s) == ["dst.test"]


def test_namebook_ipv6_se_normaliza_al_buscar():
    s = sess(src="2001:0db8:0:0:0:0:0:1", dst="2001:DB8::0002")
    b = NameBook(dns={"2001:db8::2": "v6.test"})
    assert b.best_name(s) == "v6.test"


def test_namebook_ip_no_valida_busca_texto_tal_cual():
    s = sess(src="raro", dst="tambien-raro")
    assert NameBook(dns={"tambien-raro": "x.test"}).best_name(s) == "x.test"


def test_namebook_instancias_no_comparten_tablas():
    a, b = NameBook(), NameBook()
    a.dns["1.1.1.1"] = "x"
    assert b.dns == {}


# ------------------------------------------------------------ collect_names

def test_collect_dns_y_sni_sobre_frames_reales():
    dns_pkt = pk(eth4(udp(53, 40000, dns_response("Shop.Example.com", [("A", "93.184.216.34")])),
                      dpkt.ip.IP_PROTO_UDP, "8.8.8.8", "10.0.0.5"))
    hello_pkt = pk(eth4(tcp(50000, 443, client_hello("secure.test")), dpkt.ip.IP_PROTO_TCP, "10.0.0.5", "93.184.216.34"))
    book = collect_names([dns_pkt, hello_pkt])
    assert book.dns == {"93.184.216.34": "shop.example.com"}
    key = _key("10.0.0.5", 50000, "93.184.216.34", 443, 6)
    assert book.sni == {key: "secure.test"}
    s = Session("TCP", "10.0.0.5", 50000, "93.184.216.34", 443, key=key)
    assert book.names_for(s) == ["secure.test", "shop.example.com"]


def test_collect_la_clave_es_la_misma_en_ambos_sentidos():
    """El SNI se asocia a la sesión sin importar el orden de los extremos."""
    hello = pk(eth4(tcp(50000, 443, client_hello("dir.test")), dpkt.ip.IP_PROTO_TCP, "10.0.0.5", "1.2.3.4"))
    book = collect_names([hello])
    rev = _key("1.2.3.4", 443, "10.0.0.5", 50000, 6)
    assert book.sni.get(rev) == "dir.test"


def test_collect_ipv6():
    dns_pkt = pk(eth6(udp(53, 4000, dns_response("v6.test", [("AAAA", "2001:db8::99")])), 17))
    hello_pkt = pk(eth6(tcp(5000, 443, client_hello("v6tls.test")), 6, "2001:db8::a", "2001:db8::b"))
    book = collect_names([dns_pkt, hello_pkt])
    assert book.dns == {"2001:db8::99": "v6.test"}
    assert list(book.sni.values()) == ["v6tls.test"]
    s = Session("TCP", "2001:db8::a", 5000, "2001:db8::b", 443, key=next(iter(book.sni)))
    assert book.best_name(s) == "v6tls.test"


def test_collect_vlan():
    raw = eth4(tcp(50000, 443, client_hello("vlan.test")), dpkt.ip.IP_PROTO_TCP, vlan=0x0064)
    raw_dns = eth4(udp(53, 4000, dns_response("vdns.test", [("A", "3.3.3.3")])), dpkt.ip.IP_PROTO_UDP, vlan=0x0064)
    book = collect_names([pk(raw), pk(raw_dns)])
    assert list(book.sni.values()) == ["vlan.test"] and book.dns == {"3.3.3.3": "vdns.test"}


def test_collect_primero_visto_gana():
    r1 = pk(eth4(udp(53, 1, dns_response("first.test", [("A", "4.4.4.4")])), dpkt.ip.IP_PROTO_UDP))
    r2 = pk(eth4(udp(53, 1, dns_response("second.test", [("A", "4.4.4.4")])), dpkt.ip.IP_PROTO_UDP))
    assert collect_names([r1, r2]).dns == {"4.4.4.4": "first.test"}
    h1 = pk(eth4(tcp(5, 443, client_hello("one.test")), 6))
    h2 = pk(eth4(tcp(5, 443, client_hello("two.test")), 6))
    assert list(collect_names([h1, h2]).sni.values()) == ["one.test"]


def test_collect_ignora_lo_que_no_aplica():
    pkts = [
        pk(eth4(udp(4000, 53, dns_response("q.test", [("A", "6.6.6.6")])), 17)),  # puerto origen != 53 (consulta/respuesta al revés)
        pk(eth4(udp(53, 4000, dns_response("q.test", [("A", "6.6.6.6")], qr=0)), 17)),  # consulta
        pk(eth4(udp(53, 4000, dns_response("nx.test", [("A", "6.6.6.6")], rcode=3)), 17)),
        pk(eth4(udp(53, 4000, b""), 17)),  # sin payload
        pk(eth4(tcp(5, 443, b""), 6)),  # TCP sin payload
        pk(eth4(tcp(5, 443, b"GET / HTTP/1.1\r\n\r\n"), 6)),  # no es TLS
        pk(eth4(tcp(5, 443, client_hello(sni_ext=False)), 6)),  # sin SNI
        pk(eth4(tcp(53, 4000, dns_response("t.test", [("A", "6.6.6.6")])), 6)),  # DNS por TCP no se mira
        pk(eth4(udp(5, 443, client_hello("udp.test")), 17)),  # TLS sobre UDP no cuenta
        pk(eth4(dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"x")), 1)),
        pk(bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28))),
    ]
    book = collect_names(pkts)
    assert book.dns == {} and book.sni == {}


def test_collect_paquetes_malformados_no_lanzan():
    good = pk(eth4(tcp(5, 443, client_hello("ok.test")), 6))
    bad = [
        pk(b""), pk(b"\x00"), pk(MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00"),
        pk(MAC_B + MAC_A + b"\x86\xdd" + b"`\x00"), pk(MAC_B + MAC_A + b"\x12\x34" + b"\xff" * 30),
        pk(good.data[:20]), pk(good.data[:38]), pk(good.data[:54]),
    ]
    book = collect_names(bad + [good] + bad)
    assert list(book.sni.values()) == ["ok.test"]


def test_collect_fuzz_sobre_frames_no_lanza():
    import random
    rnd = random.Random(7)
    base = [eth4(tcp(5, 443, client_hello("f.test")), 6), eth4(udp(53, 9, dns_response("d.test", [("A", "1.1.1.1")])), 17),
            eth6(udp(53, 9, dns_response("d6.test", [("AAAA", "::1")])), 17)]
    pkts = []
    for _ in range(1500):
        b = bytearray(rnd.choice(base))
        for _ in range(rnd.randint(0, 3)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        pkts.append(pk(bytes(b)[:rnd.randint(0, len(b))]))
    assert isinstance(collect_names(pkts), NameBook)


def test_collect_acepta_generador():
    gen = (p for p in [pk(eth4(udp(53, 1, dns_response("g.test", [("A", "8.8.4.4")])), 17))])
    assert collect_names(gen).dns == {"8.8.4.4": "g.test"}


def test_collect_tope_max_names(monkeypatch):
    monkeypatch.setattr(names_mod, "MAX_NAMES", 2)
    pkts = [pk(eth4(udp(53, 1, dns_response(f"h{i}.test", [("A", f"9.9.9.{i}")])), 17)) for i in range(1, 6)]
    book = collect_names(pkts)
    assert book.dns == {"9.9.9.1": "h1.test", "9.9.9.2": "h2.test"}
    hellos = [pk(eth4(tcp(1000 + i, 443, client_hello(f"s{i}.test")), 6)) for i in range(5)]
    assert len(collect_names(hellos).sni) == 2


def test_put_no_pisa_aunque_haya_espacio():
    t = {}
    names_mod._put(t, "k", "a")
    names_mod._put(t, "k", "b")
    assert t == {"k": "a"}


def test_collect_dns_con_cname_en_frame_real():
    msg = dns_response("www.cdn-site.test", [("CNAME", "x.edge.net"), ("A", "11.11.11.11")])
    book = collect_names([pk(eth4(udp(53, 3333, msg), 17))])
    assert book.dns == {"11.11.11.11": "www.cdn-site.test"}


def test_l4_payload_none_en_icmp_y_no_ip():
    assert names_mod._l4_payload(b"") is None
    assert names_mod._l4_payload(eth4(dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"x")), 1)) is None
