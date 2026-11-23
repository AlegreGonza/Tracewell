"""Tests de backend/domain/analysis/dns_log.py y de NameBook.dns_log."""
import socket
from types import SimpleNamespace

import dpkt
import pytest

import backend.domain.analysis.dns_log as D
from backend.domain.analysis.dns_log import DnsLog, _entropy
from backend.domain.analysis.names import NameCollector, collect_names
from backend.domain.analysis.tests.test_names import eth4, eth6, pk, tcp, udp

CLIENT, RESOLVER = "10.0.0.5", "8.8.8.8"


def msg(name="example.com", qtype=dpkt.dns.DNS_A, *, qr=0, rcode=0, answers=(), ttl=300, no_question=False):
    m = dpkt.dns.DNS(id=7, qr=qr, rcode=rcode)
    if not no_question:
        m.qd = [dpkt.dns.DNS.Q(name=name, type=qtype)]
    for kind, val in answers:
        rr = dpkt.dns.DNS.RR(name=name, ttl=ttl)
        if kind == "A":
            rr.type, rr.ip = dpkt.dns.DNS_A, socket.inet_pton(socket.AF_INET, val)
        elif kind == "AAAA":
            rr.type, rr.ip6 = dpkt.dns.DNS_AAAA, socket.inet_pton(socket.AF_INET6, val)
        elif kind == "BADA":
            rr.type, rr.ip = dpkt.dns.DNS_A, b"\x01\x02\x03"  # direccion de largo invalido
        else:
            rr.type, rr.cname = dpkt.dns.DNS_CNAME, val
        m.an.append(rr)
    return bytes(m)


def query(log, name="example.com", qtype=dpkt.dns.DNS_A, ts=1.0, src=CLIENT, dst=RESOLVER):
    log.add(ts, src, dst, msg(name, qtype))


def response(log, name="example.com", answers=(("A", "1.2.3.4"),), ts=2.0, rcode=0, ttl=300, qtype=dpkt.dns.DNS_A, src=RESOLVER, dst=CLIENT):
    log.add(ts, src, dst, msg(name, qtype, qr=1, rcode=rcode, answers=answers, ttl=ttl))


def only(log):
    return next(iter(log.entries.values()))


# ------------------------------------------------------------------ add

def test_consulta_cuenta_y_el_cliente_es_el_origen():
    log = DnsLog()
    query(log)
    e = only(log)
    assert (e.name, e.qtype, e.queries, e.responses, e.clients, e.first_ts, e.last_ts) == ("example.com", "A", 1, 0, [CLIENT], 1.0, 1.0)


def test_respuesta_cuenta_el_cliente_es_el_destino_y_guarda_rcode_ttl_respuestas():
    log = DnsLog()
    response(log, answers=[("A", "1.2.3.4"), ("A", "5.6.7.8")], ttl=120)
    e = only(log)
    assert (e.queries, e.responses, e.clients, e.min_ttl) == (0, 1, [CLIENT], 120)
    assert e.answers == ["1.2.3.4", "5.6.7.8"] and dict(e.rcodes) == {"NOERROR": 1}


def test_consulta_y_respuesta_se_juntan_en_la_misma_fila():
    log = DnsLog()
    query(log, ts=1.0)
    response(log, ts=3.5)
    e = only(log)
    assert (e.queries, e.responses, e.first_ts, e.last_ts) == (1, 1, 1.0, 3.5) and e.clients == [CLIENT]
    assert len(log.entries) == 1


def test_nombre_en_minusculas_y_sin_punto_final():
    log = DnsLog()
    query(log, "WWW.Example.COM")
    assert only(log).name == "www.example.com"


def test_filas_por_nombre_y_tipo():
    log = DnsLog()
    query(log, "a.test", dpkt.dns.DNS_A)
    query(log, "a.test", dpkt.dns.DNS_AAAA)
    query(log, "a.test", dpkt.dns.DNS_A)
    assert {k: v.queries for k, v in log.entries.items()} == {("a.test", "A"): 2, ("a.test", "AAAA"): 1}


@pytest.mark.parametrize("code,name", [(1, "A"), (2, "NS"), (5, "CNAME"), (6, "SOA"), (12, "PTR"), (15, "MX"), (16, "TXT"),
                                       (28, "AAAA"), (33, "SRV"), (65, "HTTPS"), (255, "ANY"), (99, "99")])
def test_nombres_de_tipo(code, name):
    log = DnsLog()
    query(log, "t.test", code)
    assert only(log).qtype == name


@pytest.mark.parametrize("rcode,name", [(0, "NOERROR"), (1, "FORMERR"), (2, "SERVFAIL"), (3, "NXDOMAIN"), (4, "NOTIMP"), (5, "REFUSED"), (9, "9")])
def test_rcodes(rcode, name):
    log = DnsLog()
    response(log, answers=[], rcode=rcode)
    assert dict(only(log).rcodes) == {name: 1}


def test_varios_rcodes_contados():
    log = DnsLog()
    response(log, "x.test", [], rcode=3)
    response(log, "x.test", [], rcode=3)
    response(log, "x.test", [], rcode=0)
    assert dict(only(log).rcodes) == {"NXDOMAIN": 2, "NOERROR": 1}


def test_respuestas_aaaa_y_cname_se_normalizan_en_minuscula():
    log = DnsLog()
    response(log, "v6.test", [("AAAA", "2001:0DB8:0:0:0:0:0:1"), ("CNAME", "Edge.CDN.Net."), ("A", "9.9.9.9")])
    assert only(log).answers == ["2001:db8::1", "edge.cdn.net", "9.9.9.9"]


def test_respuestas_repetidas_se_deduplican_y_hay_tope():
    log = DnsLog()
    for i in range(3):
        response(log, answers=[("A", "1.2.3.4")], ts=float(i))
    assert only(log).answers == ["1.2.3.4"]
    log2 = DnsLog()
    response(log2, answers=[("A", f"10.0.0.{i}") for i in range(1, 20)])
    assert len(only(log2).answers) == D.MAX_LIST and only(log2).answers[0] == "10.0.0.1"


def test_clientes_deduplicados_y_con_tope():
    log = DnsLog()
    for i in range(30):
        query(log, src=f"10.0.1.{i}")
        query(log, src="10.0.1.0")
    e = only(log)
    assert len(e.clients) == D.MAX_LIST and e.clients[0] == "10.0.1.0"


def test_min_ttl_es_el_menor_visto():
    log = DnsLog()
    response(log, answers=[("A", "1.1.1.1")], ttl=300)
    response(log, answers=[("A", "1.1.1.2")], ttl=20)
    response(log, answers=[("A", "1.1.1.3")], ttl=500)
    assert only(log).min_ttl == 20


def test_sin_respuestas_min_ttl_none():
    log = DnsLog()
    query(log)
    assert only(log).min_ttl is None


def test_first_y_last_ts_con_llegadas_desordenadas():
    log = DnsLog()
    query(log, ts=5.0)
    query(log, ts=2.0)
    query(log, ts=9.0)
    e = only(log)
    assert (e.first_ts, e.last_ts) == (2.0, 9.0)


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\xff" * 12, b"\xff" * 64, b"basura" * 10, b"\x00" * 11])
def test_basura_se_ignora(payload):
    log = DnsLog()
    log.add(1.0, CLIENT, RESOLVER, payload)
    assert log.entries == {} and log.dropped == 0


def test_mensaje_sin_pregunta_se_ignora():
    log = DnsLog()
    log.add(1.0, CLIENT, RESOLVER, msg(no_question=True, qr=1, answers=[("A", "1.2.3.4")]))
    assert log.entries == {}


def test_truncado_en_cada_longitud_no_lanza():
    log = DnsLog()
    data = msg("example.com", qr=1, answers=[("A", "1.2.3.4"), ("CNAME", "x.y.z")])
    for n in range(len(data) + 1):
        log.add(1.0, CLIENT, RESOLVER, data[:n])


def test_nombre_demasiado_largo_o_no_imprimible_se_ignora():
    log = DnsLog()
    log.add(1.0, CLIENT, RESOLVER, msg(("a" * 60 + ".") * 5 + "com"))  # > 253
    log.add(1.0, CLIENT, RESOLVER, msg(""))  # vacio
    log.add(1.0, CLIENT, RESOLVER, msg("a\x01b.com"))
    assert log.entries == {}


def test_nombre_de_253_es_valido():
    name = ".".join(["a" * 61] * 4 + ["b" * 5])[:253].strip(".")
    log = DnsLog()
    log.add(1.0, CLIENT, RESOLVER, msg(name))
    assert len(log.entries) <= 1


def test_registro_con_direccion_de_largo_invalido_se_ignora_y_los_demas_valen():
    """Bug real encontrado por un fuzz: un A con 3 bytes tumbaba ip_address; debe saltarse ese registro."""
    log = DnsLog()
    response(log, "bad.test", [("BADA", ""), ("A", "7.7.7.7")])
    e = only(log)
    assert e.answers == ["7.7.7.7"] and e.responses == 1


def test_ip_cruda_de_un_registro_hostil_no_lanza():
    log = DnsLog()
    entry = log._entry("h.test", "A")
    for raw in (b"", b"\x01", b"\x01" * 5, b"\x01" * 15, b"\x01" * 17, b"\xff" * 32):
        rr = SimpleNamespace(ttl=10, ip=raw)
        log._add_response(entry, SimpleNamespace(rcode=0, an=[rr]), CLIENT)
    assert entry.answers == []


def test_ttl_no_entero_se_ignora():
    log = DnsLog()
    entry = log._entry("h.test", "A")
    log._add_response(entry, SimpleNamespace(rcode=0, an=[SimpleNamespace(ttl="x", ip=b"\x01\x02\x03\x04"), SimpleNamespace(ip=b"\x05\x06\x07\x08")]), CLIENT)
    assert entry.min_ttl is None and entry.answers == ["1.2.3.4", "5.6.7.8"]


def test_max_entries_y_dropped(monkeypatch):
    monkeypatch.setattr(D, "MAX_ENTRIES", 3)
    log = DnsLog()
    for i in range(8):
        query(log, f"n{i}.test")
    assert len(log.entries) == 3 and log.dropped == 5
    query(log, "n0.test")  # una fila ya existente sigue acumulando
    assert log.entries[("n0.test", "A")].queries == 2 and log.dropped == 5
    assert log.summary()["dropped"] == 5


# ------------------------------------------------------------------ hints

def hint_of(**kw):
    log = DnsLog()
    name = kw.pop("name", "example.com")
    if kw.get("rcode") is not None or kw.get("ttl") is not None:
        response(log, name, kw.get("answers", [("A", "1.1.1.1")]), rcode=kw.get("rcode", 0), ttl=kw.get("ttl", 300))
    else:
        query(log, name)
    return log.hints(only(log))


def test_sin_pistas_para_un_nombre_normal():
    assert hint_of(rcode=0, ttl=300) == []


def test_pista_nxdomain():
    h = hint_of(rcode=3, answers=[])
    assert len(h) == 1 and "NXDOMAIN" in h[0]


def test_pista_nombre_aleatorio_umbrales():
    random_label = "x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1"
    assert any("al azar" in x for x in hint_of(name=f"{random_label}.evil-c2.example"))
    assert _entropy(random_label) >= 3.5
    assert not any("al azar" in x for x in hint_of(name="a" * 30 + ".test"))  # largo pero entropia 0
    assert not any("al azar" in x for x in hint_of(name="x9f3a7c1e5b2d804.test"))  # < 20 caracteres
    assert not any("al azar" in x for x in hint_of(name="mail.example.com"))


def test_pista_ttl_bajo_borde():
    assert any("TTL" in x for x in hint_of(rcode=0, ttl=30))
    assert any("TTL" in x for x in hint_of(rcode=0, ttl=0))
    assert not any("TTL" in x for x in hint_of(rcode=0, ttl=31))


def test_pistas_combinadas_y_orden():
    h = hint_of(name="x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1.evil.example", rcode=3, ttl=5, answers=[("A", "1.1.1.1")])
    assert len(h) == 3 and "NXDOMAIN" in h[0] and "al azar" in h[1] and "TTL" in h[2]


def test_entropy():
    assert _entropy("") == 0.0 and _entropy("aaaa") == 0.0
    assert _entropy("ab") == pytest.approx(1.0)
    assert _entropy("abcd") == pytest.approx(2.0)


# ------------------------------------------------------------------ rows / summary

def filled():
    log = DnsLog()
    for _ in range(3):
        query(log, "busy.test")
    query(log, "Google.com")
    query(log, "backend.api.google.com")
    response(log, "dead.test", [], rcode=3)
    return log


def test_rows_ordenadas_por_actividad_luego_nombre():
    rows = filled().rows()
    assert [r["name"] for r in rows] == ["busy.test", "backend.api.google.com", "dead.test", "google.com"]


def test_rows_forma_y_hints():
    row = next(r for r in filled().rows() if r["name"] == "dead.test")
    assert set(row) == {"name", "qtype", "queries", "responses", "rcodes", "answers", "clients", "first_ts", "last_ts", "min_ttl", "hints"}
    assert row["rcodes"] == {"NXDOMAIN": 1} and len(row["hints"]) == 1 and isinstance(row["rcodes"], dict)


def test_rows_filtro_subcadena_sin_mayusculas_y_con_espacios():
    log = filled()
    assert [r["name"] for r in log.rows("GOOGLE")] == ["backend.api.google.com", "google.com"]
    assert [r["name"] for r in log.rows("  google ")] == ["backend.api.google.com", "google.com"]
    assert [r["name"] for r in log.rows("oogle.c")] == ["backend.api.google.com", "google.com"]
    assert log.rows("zzz") == []


def test_rows_filtro_vacio_o_none_trae_todo():
    log = filled()
    assert len(log.rows("")) == len(log.rows(None)) == len(log.rows("   ")) == 4


def test_rows_limit():
    log = filled()
    assert len(log.rows(limit=2)) == 2 and log.rows(limit=0) == []
    assert [r["name"] for r in log.rows(limit=1)] == ["busy.test"]


def test_rows_filtro_con_caracteres_especiales_no_rompe():
    assert filled().rows("(.*[") == []


def test_summary():
    s = filled().summary()
    assert s == {"names": 4, "queries": 5, "responses": 1, "nxdomain": 1, "flagged": 1, "dropped": 0}


def test_summary_vacio():
    assert DnsLog().summary() == {"names": 0, "queries": 0, "responses": 0, "nxdomain": 0, "flagged": 0, "dropped": 0}


def test_summary_names_cuenta_nombres_unicos_no_filas():
    log = DnsLog()
    query(log, "a.test", dpkt.dns.DNS_A)
    query(log, "a.test", dpkt.dns.DNS_AAAA)
    assert log.summary()["names"] == 1 and len(log.entries) == 2


# ------------------------------------------------------------------ NameBook.dns_log desde paquetes

def test_collect_names_llena_dns_log_con_consulta_y_respuesta():
    q = pk(eth4(udp(40000, 53, msg("shop.example.com")), 17, CLIENT, RESOLVER), 1.0)
    r = pk(eth4(udp(53, 40000, msg("shop.example.com", qr=1, answers=[("A", "93.184.216.34")])), 17, RESOLVER, CLIENT), 2.0)
    book = collect_names([q, r])
    e = book.dns_log.entries[("shop.example.com", "A")]
    assert (e.queries, e.responses, e.clients, e.answers) == (1, 1, [CLIENT], ["93.184.216.34"])
    assert book.dns == {"93.184.216.34": "shop.example.com"}  # la tabla vieja sigue funcionando


def test_consulta_con_puerto_destino_53_y_respuesta_con_puerto_origen_53():
    book = collect_names([pk(eth4(udp(5555, 53, msg("a.test")), 17, CLIENT, RESOLVER)), pk(eth4(udp(53, 5555, msg("b.test", qr=1, answers=[("A", "1.1.1.1")])), 17, RESOLVER, CLIENT))])
    assert {k[0] for k in book.dns_log.entries} == {"a.test", "b.test"}


def test_puerto_ni_origen_ni_destino_53_no_entra():
    book = collect_names([pk(eth4(udp(5353, 5353, msg("mdns.test")), 17))])
    assert book.dns_log.entries == {}


def test_dns_sobre_tcp_no_entra():
    assert collect_names([pk(eth4(tcp(40000, 53, msg("t.test")), 6))]).dns_log.entries == {}


def test_dns_sobre_ipv6():
    q = pk(eth6(udp(40000, 53, msg("v6.test")), 17, "2001:db8::1", "2001:db8::53"))
    e = collect_names([q]).dns_log.entries[("v6.test", "A")]
    assert e.clients == ["2001:db8::1"]


def test_udp_sin_payload_o_basura_en_el_puerto_53_no_rompe():
    pkts = [pk(eth4(udp(40000, 53, b""), 17)), pk(eth4(udp(40000, 53, b"\xff" * 20), 17)), pk(b"\x00" * 10)]
    assert collect_names(pkts).dns_log.entries == {}


def test_name_collector_incremental_equivale_a_collect_names():
    pkts = [pk(eth4(udp(40000, 53, msg("x.test")), 17), float(i)) for i in range(3)]
    c = NameCollector()
    for p in pkts:
        c.add(p)
    assert c.book.dns_log.entries[("x.test", "A")].queries == 3 == collect_names(pkts).dns_log.entries[("x.test", "A")].queries


def test_instancias_de_namebook_no_comparten_dns_log():
    from backend.domain.analysis.names import NameBook
    a, b = NameBook(), NameBook()
    a.dns_log.add(1.0, CLIENT, RESOLVER, msg("a.test"))
    assert b.dns_log.entries == {}


def test_fuzz_con_semilla_no_lanza():
    import random
    rnd = random.Random(11)
    base = msg("fuzz.example.com", qr=1, answers=[("A", "1.2.3.4"), ("AAAA", "::1"), ("CNAME", "a.b.c")])
    log = DnsLog()
    for _ in range(3000):
        b = bytearray(base)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        log.add(1.0, CLIENT, RESOLVER, bytes(b)[:rnd.randint(0, len(b))])
    assert isinstance(log.summary(), dict) and isinstance(log.rows(), list)
