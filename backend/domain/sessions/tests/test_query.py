"""Tests de backend.domain.sessions.query (filter_sessions y compute_stats)."""
import dpkt
import pytest

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import GroupingResult, Session, group_packets
from backend.domain.sessions.query import InvalidFilter, Stats, compute_stats, filter_sessions


def S(proto="TCP", src="10.0.0.1", sport=1000, dst="10.0.0.2", dport=80, packets=1, bytes_=100):
    return Session(protocol=proto, src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                   packets=packets, bytes=bytes_)


@pytest.fixture
def sessions():
    return [
        S("TCP", "10.0.0.1", 1000, "10.0.0.2", 80, 10, 1000),
        S("UDP", "10.0.0.3", 5353, "10.0.0.4", 53, 2, 200),
        S("ICMP", "10.0.0.1", None, "10.0.0.9", None, 4, 400),
        S("TCP", "10.0.0.5", 443, "10.0.0.1", 50000, 6, 600),
    ]


# ---------- filter_sessions: normal ----------

def test_sin_criterios_devuelve_todo(sessions):
    assert filter_sessions(sessions) == sessions


def test_filtro_solo_protocolo(sessions):
    assert [s.protocol for s in filter_sessions(sessions, protocol="udp")] == ["UDP"]


def test_filtro_solo_ip(sessions):
    assert len(filter_sessions(sessions, ip="10.0.0.1")) == 3


def test_filtro_solo_puerto(sessions):
    assert filter_sessions(sessions, port=53) == [sessions[1]]


def test_combinacion_and(sessions):
    res = filter_sessions(sessions, protocol="tcp", ip="10.0.0.1", port=80)
    assert res == [sessions[0]]
    assert filter_sessions(sessions, protocol="udp", ip="10.0.0.1") == []


def test_ip_coincide_origen_y_destino(sessions):
    res = filter_sessions(sessions, ip="10.0.0.1", protocol="TCP")
    assert sessions[0] in res and sessions[3] in res  # origen en la 0, destino en la 3


def test_puerto_coincide_origen_y_destino(sessions):
    assert filter_sessions(sessions, port=1000) == [sessions[0]]  # origen
    assert filter_sessions(sessions, port=80) == [sessions[0]]  # destino


@pytest.mark.parametrize("proto", ["tcp", "TCP", " Tcp ", "tCp"])
def test_protocolo_sin_distinguir_mayusculas(sessions, proto):
    assert len(filter_sessions(sessions, protocol=proto)) == 2


def test_ipv6_notaciones_equivalentes():
    s6 = S("TCP", "::1", 1, "2001:db8::2", 2)
    for ip in ("::1", "0:0:0:0:0:0:0:1", "0000::0001", " ::1 "):
        assert filter_sessions([s6], ip=ip) == [s6]
    assert filter_sessions([s6], ip="2001:0db8:0:0:0:0:0:2") == [s6]


def test_conserva_orden(sessions):
    res = filter_sessions(sessions, ip="10.0.0.1")
    assert res == [sessions[0], sessions[2], sessions[3]]


def test_no_modifica_lista_original(sessions):
    copia = list(sessions)
    res = filter_sessions(sessions, protocol="tcp")
    assert sessions == copia
    assert res is not sessions
    assert filter_sessions(sessions) is not sessions  # lista nueva aun sin criterios


def test_acepta_generador(sessions):
    gen = (s for s in sessions)
    assert filter_sessions(gen, protocol="tcp") == [sessions[0], sessions[3]]


# ---------- filter_sessions: borde ----------

def test_lista_vacia():
    assert filter_sessions([], protocol="tcp", ip="1.1.1.1", port=1) == []


def test_sin_coincidencias(sessions):
    assert filter_sessions(sessions, ip="8.8.8.8") == []
    assert filter_sessions(sessions, port=9999) == []


def test_icmp_puertos_none_filtro_por_puerto(sessions):
    icmp = [sessions[2]]
    assert filter_sessions(icmp, port=0) == []
    assert filter_sessions(icmp, port=80) == []


@pytest.mark.parametrize("port", [0, 65535])
def test_puertos_limite_validos(port):
    s = S(sport=port, dport=1234)
    assert filter_sessions([s], port=port) == [s]
    assert filter_sessions([S(sport=1, dport=port)], port=port) != []


def test_sesion_ipv6_con_filtro_ipv4_no_revienta():
    s6 = S("TCP", "::1", 1, "fe80::2", 2)
    assert filter_sessions([s6], ip="10.0.0.1") == []


def test_sesion_ipv4_con_filtro_ipv6_no_revienta(sessions):
    assert filter_sessions(sessions, ip="::1") == []


def test_ipv4_mapeado_en_ipv6_no_equivale_a_ipv4():
    # Documenta: ::ffff:10.0.0.1 NO se considera igual a 10.0.0.1.
    s = S("TCP", "::ffff:10.0.0.1", 1, "::2", 2)
    assert filter_sessions([s], ip="10.0.0.1") == []


# ---------- filter_sessions: InvalidFilter ----------

@pytest.mark.parametrize("ip", ["999.1.1.1", "abc", "", "1.2.3", " ", "10.0.0.1/24", "1.2.3.4.5"])
def test_ip_invalida(sessions, ip):
    with pytest.raises(InvalidFilter):
        filter_sessions(sessions, ip=ip)


@pytest.mark.parametrize("port", [-1, 65536, "80", 80.5, True, False, 80.0, [80]])
def test_puerto_invalido(sessions, port):
    with pytest.raises(InvalidFilter):
        filter_sessions(sessions, port=port)


def test_validacion_previa_con_lista_vacia():
    with pytest.raises(InvalidFilter):
        filter_sessions([], ip="abc")
    with pytest.raises(InvalidFilter):
        filter_sessions([], port=70000)


def test_validacion_previa_no_consume_generador(sessions):
    gen = (s for s in sessions)
    with pytest.raises(InvalidFilter):
        filter_sessions(gen, ip="abc")
    assert len(list(gen)) == len(sessions)  # el generador no se tocó


def test_invalidfilter_es_valueerror():
    assert issubclass(InvalidFilter, ValueError)
    with pytest.raises(ValueError):
        filter_sessions([], port=-1)


def test_mensaje_incluye_valor():
    with pytest.raises(InvalidFilter, match="999.1.1.1"):
        filter_sessions([], ip="999.1.1.1")


# ---------- comportamiento real de inputs raros (documentado) ----------

def test_ip_con_espacios_se_recorta(sessions):
    assert len(filter_sessions(sessions, ip="  10.0.0.1  ")) == 3


def test_ip_none_y_protocol_none_no_filtran(sessions):
    assert filter_sessions(sessions, ip=None) == sessions
    assert filter_sessions(sessions, protocol=None) == sessions
    assert filter_sessions(sessions, ip=None, protocol=None, port=None) == sessions
    with pytest.raises(InvalidFilter):
        filter_sessions(sessions, ip="")


def test_ip_zona_ipv6_es_invalidfilter():
    # Antes: se aceptaba y nunca coincidía (devolvía [] en silencio). Ahora falla fuerte.
    s = S("TCP", "fe80::1", 1, "fe80::2", 2)
    with pytest.raises(InvalidFilter):
        filter_sessions([s], ip="fe80::1%eth0")
    assert filter_sessions([s], ip="fe80::1") == [s]  # sin zona sigue andando


@pytest.mark.parametrize("proto", ["", "   ", "\t\n"])
def test_protocolo_vacio_es_invalidfilter(sessions, proto):
    # Antes: devolvía [] sin avisar. "" no es "sin filtro" (eso es None).
    with pytest.raises(InvalidFilter):
        filter_sessions(sessions, protocol=proto)


@pytest.mark.parametrize("kwargs", [
    {"ip": 123}, {"ip": 0}, {"ip": ["10.0.0.1"]}, {"ip": b"10.0.0.1"},
    {"protocol": 6}, {"protocol": ["tcp"]}, {"protocol": b"tcp"},
])
def test_tipos_no_str_son_invalidfilter(sessions, kwargs):
    # Antes: AttributeError crudo (.strip) o, con bytes, IP empaquetada aceptada.
    with pytest.raises(InvalidFilter):
        filter_sessions(sessions, **kwargs)


def test_ip_bytes_de_4_octetos_ya_no_se_acepta():
    # Antes matcheaba como dirección empaquetada 1.2.3.4; ahora es InvalidFilter.
    s = S(src="1.2.3.4", dst="10.0.0.2")
    with pytest.raises(InvalidFilter):
        filter_sessions([s], ip=bytes([1, 2, 3, 4]))


def test_validacion_nueva_salta_con_lista_vacia():
    for kwargs in ({"protocol": ""}, {"protocol": 6}, {"ip": 123}, {"ip": "fe80::1%eth0"}):
        with pytest.raises(InvalidFilter):
            filter_sessions([], **kwargs)


def test_mensaje_menciona_tipo_o_valor_recibido():
    with pytest.raises(InvalidFilter, match="int"):
        filter_sessions([], ip=123)
    with pytest.raises(InvalidFilter, match="bytes"):
        filter_sessions([], ip=b"1.2.3.4")
    with pytest.raises(InvalidFilter, match="int"):
        filter_sessions([], protocol=6)
    with pytest.raises(InvalidFilter, match="list"):
        filter_sessions([], protocol=["tcp"])
    with pytest.raises(InvalidFilter, match="fe80::1%eth0"):
        filter_sessions([], ip="fe80::1%eth0")
    with pytest.raises(InvalidFilter, match="vac"):
        filter_sessions([], protocol="  ")


def test_sesion_con_ip_invalida_lanza_valueerror_no_invalidfilter():
    # SOSPECHOSO: una Session con IP corrupta rompe con ValueError crudo si se filtra por ip.
    bad = S(src="no-ip", dst="10.0.0.2")
    with pytest.raises(ValueError) as ei:
        filter_sessions([bad], ip="10.0.0.2")
    assert not isinstance(ei.value, InvalidFilter)


def test_protocolo_icmpv6_y_desconocido(sessions):
    extra = [S("ICMPv6", "::1", None, "::2", None), S("IP-47", "1.1.1.1", None, "2.2.2.2", None)]
    assert filter_sessions(extra, protocol="icmpv6") == [extra[0]]
    assert filter_sessions(extra, protocol="ip-47") == [extra[1]]


# ---------- compute_stats ----------

def test_stats_totales_y_por_protocolo(sessions):
    st = compute_stats(sessions)
    assert (st.sessions, st.packets, st.bytes) == (4, 22, 2200)
    assert set(st.by_protocol) == {"TCP", "UDP", "ICMP"}
    tcp = st.by_protocol["TCP"]
    assert (tcp.sessions, tcp.packets, tcp.bytes) == (2, 16, 1600)
    udp = st.by_protocol["UDP"]
    assert (udp.sessions, udp.packets, udp.bytes) == (1, 2, 200)
    icmp = st.by_protocol["ICMP"]
    assert (icmp.sessions, icmp.packets, icmp.bytes) == (1, 4, 400)


def test_suma_por_protocolo_igual_a_totales(sessions):
    st = compute_stats(sessions)
    assert sum(p.sessions for p in st.by_protocol.values()) == st.sessions
    assert sum(p.packets for p in st.by_protocol.values()) == st.packets
    assert sum(p.bytes for p in st.by_protocol.values()) == st.bytes


def test_stats_con_groupingresult_propaga_non_ip_y_malformed(sessions):
    st = compute_stats(GroupingResult(sessions=sessions, non_ip=7, malformed=3))
    assert (st.non_ip, st.malformed, st.sessions) == (7, 3, 4)


def test_stats_con_lista_non_ip_malformed_cero(sessions):
    st = compute_stats(sessions)
    assert (st.non_ip, st.malformed) == (0, 0)


def test_stats_sobre_sesiones_filtradas(sessions):
    st = compute_stats(filter_sessions(sessions, protocol="tcp"))
    assert (st.sessions, st.packets, st.bytes) == (2, 16, 1600)
    assert list(st.by_protocol) == ["TCP"]


def test_stats_lista_vacia():
    st = compute_stats([])
    assert st == Stats()
    assert (st.sessions, st.packets, st.bytes) == (0, 0, 0)
    assert st.by_protocol == {}


def test_stats_groupingresult_vacio_con_contadores():
    st = compute_stats(GroupingResult(non_ip=2, malformed=1))
    assert (st.sessions, st.non_ip, st.malformed, st.by_protocol) == (0, 2, 1, {})


def test_stats_acepta_generador(sessions):
    # compute_stats itera una sola vez, asi que un generador sirve.
    assert compute_stats(s for s in sessions).sessions == 4


def test_stats_no_comparte_estado_entre_llamadas(sessions):
    a = compute_stats(sessions)
    b = compute_stats([])
    assert a.by_protocol is not b.by_protocol and b.by_protocol == {}


# ---------- integración ----------

def _eth(ip_pkt):
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_pkt))


def _tcp(src, dst, sport, dport, payload=b""):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)
    ip = dpkt.ip.IP(src=bytes(map(int, src.split("."))), dst=bytes(map(int, dst.split("."))),
                    p=dpkt.ip.IP_PROTO_TCP, data=t)
    ip.len = len(bytes(ip))
    return _eth(ip)


def _udp(src, dst, sport, dport):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=b"x")
    u.ulen = len(bytes(u))
    ip = dpkt.ip.IP(src=bytes(map(int, src.split("."))), dst=bytes(map(int, dst.split("."))),
                    p=dpkt.ip.IP_PROTO_UDP, data=u)
    ip.len = len(bytes(ip))
    return _eth(ip)


def _arp():
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28))


def test_integracion_paquetes_a_stats():
    raw = [
        _tcp("10.0.0.1", "10.0.0.2", 1000, 21),
        _tcp("10.0.0.2", "10.0.0.1", 21, 1000),
        _tcp("10.0.0.1", "10.0.0.3", 1001, 80),
        _udp("10.0.0.4", "10.0.0.1", 5000, 53),
        _arp(),
        b"\x00\x01",  # truncado -> malformed
    ]
    pkts = [Packet(ts=float(i), data=d, origlen=len(d)) for i, d in enumerate(raw)]
    res = group_packets(pkts)
    assert (len(res.sessions), res.non_ip, res.malformed) == (3, 1, 1)

    full = compute_stats(res)
    assert (full.sessions, full.packets, full.non_ip, full.malformed) == (3, 4, 1, 1)

    tcp_ip = filter_sessions(res.sessions, protocol="tcp", ip="10.0.0.1")
    assert len(tcp_ip) == 2
    assert len(filter_sessions(res.sessions, port=21)) == 1  # ambos sentidos = 1 sesión
    st = compute_stats(tcp_ip)
    assert st.sessions == 2 and st.packets == 3
    assert set(st.by_protocol) == {"TCP"}
    assert (st.non_ip, st.malformed) == (0, 0)
    assert st.bytes == sum(s.bytes for s in tcp_ip)


# ---------- truncated / untracked_packets ----------

def test_stats_defaults():
    st = Stats()
    assert st.truncated is False and st.untracked_packets == 0


def test_compute_stats_propaga_truncado():
    gr = GroupingResult(sessions=[S()], truncated=True, untracked_packets=9)
    st = compute_stats(gr)
    assert st.truncated is True and st.untracked_packets == 9


def test_compute_stats_grouping_no_truncado():
    st = compute_stats(GroupingResult(sessions=[S()]))
    assert st.truncated is False and st.untracked_packets == 0


def test_compute_stats_lista_defaults(sessions):
    st = compute_stats(sessions)
    assert st.truncated is False and st.untracked_packets == 0


def test_compute_stats_filtradas_de_resultado_truncado_son_false(sessions):
    gr = GroupingResult(sessions=sessions, truncated=True, untracked_packets=5)
    st = compute_stats(filter_sessions(gr.sessions, protocol="TCP"))
    assert st.truncated is False and st.untracked_packets == 0
