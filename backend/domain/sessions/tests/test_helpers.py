"""Tests directos de los helpers de backend/domain/sessions (grouper.py y query.py)."""
import ipaddress
import socket
from types import SimpleNamespace

import dpkt
import pytest

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import (
    ETHERNET, GroupingResult, Session, UnsupportedLinktype, _check_group_args,
    _l4_ports, _new_session, _protocol_number, _record_packet, ip_layer,
)
from backend.domain.sessions.query import (
    InvalidFilter, ProtocolStats, Stats, _add_session, _check_port_filter, _matches,
    _normalize_protocol, _parse_ip_filter, _source_parts,
)

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"


def _eth_ip(l4, proto, offset=0, mf=0):
    ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"),
                    p=proto, offset=offset, mf=mf, data=l4)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _tcp_frame():
    return _eth_ip(dpkt.tcp.TCP(sport=1234, dport=80), dpkt.ip.IP_PROTO_TCP)


def _ipv6_frame():
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "::1"),
                       dst=socket.inet_pton(socket.AF_INET6, "::2"),
                       nxt=dpkt.ip.IP_PROTO_UDP, plen=8,
                       data=dpkt.udp.UDP(sport=1, dport=2, ulen=8))
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))


def _arp_frame():
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP,
                                        data=b"\x00" * 28))


# ---------- grouper.ip_layer ----------

def test_ip_layer_ipv4_devuelve_familia_inet():
    """Un frame IPv4 devuelve (IP, AF_INET)."""
    ip, fam = ip_layer(_tcp_frame())
    assert isinstance(ip, dpkt.ip.IP) and fam == socket.AF_INET


def test_ip_layer_ipv6_devuelve_familia_inet6():
    """Un frame IPv6 devuelve (IP6, AF_INET6)."""
    ip, fam = ip_layer(_ipv6_frame())
    assert isinstance(ip, dpkt.ip6.IP6) and fam == socket.AF_INET6


def test_ip_layer_no_ip_devuelve_none():
    """ARP no es IP: devuelve None."""
    assert ip_layer(_arp_frame()) is None


def test_ip_layer_fragmento_no_inicial_lanza_unpackerror():
    """Un fragmento IPv4 con offset > 0 se trata como dañado."""
    frame = _eth_ip(b"\x00" * 8, dpkt.ip.IP_PROTO_UDP, offset=100)
    with pytest.raises(dpkt.UnpackError):
        ip_layer(frame)


def test_ip_layer_fragmento_inicial_es_valido():
    """El primer fragmento (offset 0, MF=1) sí se acepta."""
    frame = _eth_ip(dpkt.udp.UDP(sport=1, dport=2, ulen=8), dpkt.ip.IP_PROTO_UDP, mf=1)
    assert ip_layer(frame)[1] == socket.AF_INET


def test_ip_layer_bytes_daniados_lanza_unpackerror():
    """Un frame Ethernet de pocos bytes lanza UnpackError (NeedData incluido)."""
    with pytest.raises(dpkt.UnpackError):
        ip_layer(b"\x00\x01")


def test_ip_layer_cabecera_ip_truncada_lanza_unpackerror():
    """Ethertype IPv4 con cabecera cortada: dañado, no 'sin IP'."""
    raw = MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00"
    with pytest.raises(dpkt.UnpackError, match="cabecera IP ilegible"):
        ip_layer(raw)


def test_ip_layer_ipv6_truncada_lanza_unpackerror():
    """Ethertype IPv6 con cabecera cortada también es UnpackError."""
    with pytest.raises(dpkt.UnpackError):
        ip_layer(MAC_B + MAC_A + b"\x86\xdd" + b"`\x00\x00")


def test_ip_layer_ethertype_desconocido_es_none():
    """Ethertype desconocido con basura: no es IP, devuelve None."""
    assert ip_layer(MAC_B + MAC_A + b"\x12\x34" + b"\xff" * 30) is None


def _vlan(inner_type, payload):
    return MAC_B + MAC_A + b"\x81\x00" + b"\x00\x01" + inner_type + payload


def test_ip_layer_vlan_con_ip_valida():
    """802.1Q con IP válida sigue funcionando."""
    plain = _tcp_frame()
    frame = _vlan(b"\x08\x00", plain[14:])
    assert ip_layer(frame)[1] == socket.AF_INET


def test_ip_layer_vlan_con_ip_cortada_lanza():
    """802.1Q con IP cortada es dañado (no 'sin IP')."""
    with pytest.raises(dpkt.UnpackError):
        ip_layer(_vlan(b"\x08\x00", b"E\x00\x00"))


def test_ip_layer_vlan_con_ipv6_cortada_lanza():
    """802.1Q con IPv6 cortada también es dañado."""
    with pytest.raises(dpkt.UnpackError):
        ip_layer(_vlan(b"\x86\xdd", b"`\x00\x00"))


def test_ip_layer_qinq_con_ip_cortada_lanza():
    """Doble etiqueta (QinQ) con IP cortada: dañado."""
    raw = MAC_B + MAC_A + b"\x81\x00\x00\x01" + b"\x81\x00\x00\x02" + b"\x08\x00" + b"E\x00\x00"
    with pytest.raises(dpkt.UnpackError):
        ip_layer(raw)


def test_ip_layer_vlan_con_arp_es_none():
    """802.1Q con ARP interno no es IP: None."""
    assert ip_layer(_vlan(b"\x08\x06", b"\x00" * 28)) is None


def test_inner_ethertype_sin_etiqueta_y_con_etiqueta():
    """Sin VLAN devuelve eth.type; con VLAN, el tipo interno."""
    from backend.domain.sessions.grouper import _inner_ethertype
    plain = dpkt.ethernet.Ethernet(_tcp_frame())
    assert _inner_ethertype(plain) == dpkt.ethernet.ETH_TYPE_IP
    tagged = dpkt.ethernet.Ethernet(_vlan(b"\x08\x06", b"\x00" * 28))
    assert _inner_ethertype(tagged) == dpkt.ethernet.ETH_TYPE_ARP


def test_group_packets_vlan_ip_cortada_es_malformed_no_non_ip():
    """VLAN con IP cortada cuenta en malformed, no en non_ip."""
    from backend.domain.sessions.grouper import group_packets
    r = group_packets([Packet(1.0, _vlan(b"\x08\x00", b"E\x00\x00"), None)])
    assert (r.malformed, r.non_ip, len(r.sessions)) == (1, 0, 0)


def test_packet_endpoints_cabecera_cortada_devuelve_none():
    """packet_endpoints no lanza con IP ilegible."""
    from backend.domain.sessions.grouper import packet_endpoints
    assert packet_endpoints(MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00") is None


def test_group_packets_cuenta_cabecera_cortada_como_malformed():
    """IP cortada -> malformed; ARP y ethertype raro -> non_ip."""
    from backend.domain.sessions.grouper import group_packets
    pkts = [
        Packet(1.0, MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00", None),
        Packet(2.0, MAC_B + MAC_A + b"\x86\xdd" + b"`", None),
        Packet(3.0, MAC_B + MAC_A + b"\x08\x06" + b"\x00" * 28, None),
        Packet(4.0, MAC_B + MAC_A + b"\x12\x34" + b"\xff" * 20, None),
    ]
    r = group_packets(pkts)
    assert (r.malformed, r.non_ip, len(r.sessions)) == (2, 2, 0)


def test_evaluate_con_paquetes_ilegibles_no_lanza():
    """Las reglas reales no tumban con cabeceras IP cortadas (_decode -> None)."""
    from pathlib import Path
    from backend.domain.rules.engine import evaluate, load_rules
    rules = load_rules(Path(__file__).resolve().parents[4] / "rules")
    pkts = [
        Packet(1.0, MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00", None),
        Packet(2.0, MAC_B + MAC_A + b"\x86\xdd" + b"`", None),
        Packet(3.0, _vlan(b"\x08\x00", b"E"), None),
    ]
    assert evaluate(rules, pkts) == []


def test_group_packets_fuzz_ethertype_ip_conserva_el_total():
    """Fuzz con semilla fija: nunca lanza y todo paquete queda contabilizado."""
    import random
    from backend.domain.sessions.grouper import group_packets
    rnd = random.Random(1234)
    pkts = []
    for i in range(3000):
        et = rnd.choice([b"\x08\x00", b"\x86\xdd"])
        pl = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 60)))
        pkts.append(Packet(float(i), MAC_B + MAC_A + et + pl, None))
    r = group_packets(pkts)
    en_sesiones = sum(s.packets for s in r.sessions) + r.untracked_packets
    assert r.non_ip + r.malformed + en_sesiones == 3000


# ---------- grouper._protocol_number ----------

def test_protocol_number_ipv4_usa_p():
    """En IPv4 devuelve el campo p."""
    ip, _ = ip_layer(_tcp_frame())
    assert _protocol_number(ip) == 6


def test_protocol_number_ipv6_sin_extension_usa_p():
    """En IPv6 sin extensiones devuelve el protocolo del payload."""
    ip, _ = ip_layer(_ipv6_frame())
    assert _protocol_number(ip) == 17


def test_protocol_number_sin_p_usa_ultima_extension():
    """Sin `p` (ej. ESP) usa la última cabecera de extensión."""
    ip = SimpleNamespace(extension_hdrs={0: object(), 50: object()}, nxt=0)
    assert _protocol_number(ip) == 50


def test_protocol_number_sin_p_ni_extensiones_usa_nxt():
    """Sin `p` ni extensiones cae en nxt."""
    ip = SimpleNamespace(extension_hdrs={}, nxt=59)
    assert _protocol_number(ip) == 59


# ---------- grouper._l4_ports ----------

def test_l4_ports_tcp():
    """TCP devuelve (sport, dport)."""
    ip, _ = ip_layer(_tcp_frame())
    assert _l4_ports(ip, 6) == (1234, 80)


def test_l4_ports_udp():
    """UDP devuelve (sport, dport)."""
    ip, _ = ip_layer(_ipv6_frame())
    assert _l4_ports(ip, 17) == (1, 2)


def test_l4_ports_otro_protocolo_devuelve_none():
    """ICMP no tiene puertos: (None, None), sin tocar la capa 4."""
    assert _l4_ports(SimpleNamespace(data=b""), 1) == (None, None)


def test_l4_ports_capa4_ilegible_lanza_unpackerror():
    """TCP declarado pero con bytes crudos en la capa 4 lanza UnpackError."""
    ip = SimpleNamespace(data=b"\x01\x02")
    with pytest.raises(dpkt.UnpackError):
        _l4_ports(ip, 6)


# ---------- grouper._check_group_args ----------

def test_check_group_args_validos_no_lanza():
    """Ethernet y tope positivo pasan."""
    assert _check_group_args(ETHERNET, 1) is None


def test_check_group_args_linktype_no_ethernet():
    """Un linktype distinto de 1 lanza UnsupportedLinktype."""
    with pytest.raises(UnsupportedLinktype):
        _check_group_args(113, 10)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10", None])
def test_check_group_args_max_sessions_invalido(bad):
    """max_sessions no entero positivo (incluido bool) lanza ValueError."""
    with pytest.raises(ValueError):
        _check_group_args(ETHERNET, bad)


# ---------- grouper._new_session ----------

def test_new_session_campos_y_protocolo_conocido():
    """Crea la sesión con extremos, nombre de protocolo, ts inicial y contadores en 0."""
    key = ("k",)
    s = _new_session(("1.1.1.1", 10, "2.2.2.2", 20, 6), key, 5.0)
    assert (s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port) == ("TCP", "1.1.1.1", 10, "2.2.2.2", 20)
    assert (s.packets, s.bytes, s.first_ts, s.key) == (0, 0, 5.0, key)


def test_new_session_protocolo_desconocido_usa_ip_n():
    """Un protocolo sin nombre se llama IP-<n>, y sin puertos queda None."""
    s = _new_session(("1.1.1.1", None, "2.2.2.2", None, 47), None, 0.0)
    assert s.protocol == "IP-47" and s.src_port is None


# ---------- grouper._record_packet ----------

def test_record_packet_usa_origlen_si_existe():
    """Suma 1 paquete y origlen (no len(data)); actualiza last_ts."""
    s = Session("TCP", "a", 1, "b", 2)
    _record_packet(s, Packet(3.5, b"xx", 100))
    assert (s.packets, s.bytes, s.last_ts) == (1, 100, 3.5)


def test_record_packet_sin_origlen_usa_len_data():
    """Con origlen None usa len(data)."""
    s = Session("TCP", "a", 1, "b", 2)
    _record_packet(s, Packet(1.0, b"abcd", None))
    assert s.bytes == 4


def test_record_packet_acumula():
    """Dos paquetes acumulan contadores y last_ts es el del último."""
    s = Session("TCP", "a", 1, "b", 2)
    _record_packet(s, Packet(1.0, b"a", None))
    _record_packet(s, Packet(2.0, b"bb", 10))
    assert (s.packets, s.bytes, s.last_ts) == (2, 11, 2.0)


def test_record_packet_origlen_cero_no_cae_en_len():
    """origlen=0 es un valor válido (no None): suma 0."""
    s = Session("TCP", "a", 1, "b", 2)
    _record_packet(s, Packet(1.0, b"abc", 0))
    assert s.bytes == 0


# ---------- query._parse_ip_filter ----------

def test_parse_ip_filter_none():
    """None significa sin filtro."""
    assert _parse_ip_filter(None) is None


def test_parse_ip_filter_valida_ipv4_e_ipv6_con_espacios():
    """Devuelve objeto IP y recorta espacios."""
    assert _parse_ip_filter(" 10.0.0.1 ") == ipaddress.ip_address("10.0.0.1")
    assert _parse_ip_filter("::1") == ipaddress.ip_address("0:0:0:0:0:0:0:1")


@pytest.mark.parametrize("bad", [b"\x0a\x00\x00\x01", 167772161, ["10.0.0.1"]])
def test_parse_ip_filter_no_str(bad):
    """Bytes/int/lista (no texto) lanzan InvalidFilter."""
    with pytest.raises(InvalidFilter, match="texto"):
        _parse_ip_filter(bad)


def test_parse_ip_filter_zona_ipv6():
    """Una zona IPv6 con % se rechaza."""
    with pytest.raises(InvalidFilter, match="zona"):
        _parse_ip_filter("fe80::1%eth0")


@pytest.mark.parametrize("bad", ["", "300.1.1.1", "hola"])
def test_parse_ip_filter_invalida(bad):
    """Texto que no es IP lanza InvalidFilter."""
    with pytest.raises(InvalidFilter, match="inválida"):
        _parse_ip_filter(bad)


# ---------- query._check_port_filter ----------

@pytest.mark.parametrize("ok", [None, 0, 80, 65535])
def test_check_port_filter_validos(ok):
    """None y enteros 0..65535 pasan."""
    assert _check_port_filter(ok) is None


@pytest.mark.parametrize("bad", [True, False, -1, 65536, "80", 80.0])
def test_check_port_filter_invalidos(bad):
    """bool, fuera de rango, str y float lanzan InvalidFilter."""
    with pytest.raises(InvalidFilter):
        _check_port_filter(bad)


# ---------- query._normalize_protocol ----------

def test_normalize_protocol_none_y_mayusculas():
    """None queda None; el texto se recorta y pasa a mayúsculas."""
    assert _normalize_protocol(None) is None
    assert _normalize_protocol(" tcp ") == "TCP"


def test_normalize_protocol_no_str():
    """Un valor no texto lanza InvalidFilter."""
    with pytest.raises(InvalidFilter, match="texto"):
        _normalize_protocol(6)


@pytest.mark.parametrize("empty", ["", "   "])
def test_normalize_protocol_vacio(empty):
    """Cadena vacía o de espacios lanza InvalidFilter."""
    with pytest.raises(InvalidFilter, match="vacío"):
        _normalize_protocol(empty)


# ---------- query._matches ----------

def _sess(proto="TCP", src="10.0.0.1", sp=1234, dst="10.0.0.2", dp=80):
    return Session(proto, src, sp, dst, dp)


def test_matches_sin_criterios():
    """Todo None no filtra."""
    assert _matches(_sess(), None, None, None)


def test_matches_protocolo_ip_y_puerto_en_cualquier_extremo():
    """IP y puerto coinciden como origen o destino; un criterio que falla descarta."""
    s = _sess()
    assert _matches(s, "TCP", ipaddress.ip_address("10.0.0.2"), 1234)
    assert not _matches(s, "UDP", None, None)
    assert not _matches(s, None, ipaddress.ip_address("9.9.9.9"), None)
    assert not _matches(s, None, None, 9999)


def test_matches_ipv6_compara_como_objeto():
    """Notación corta y larga de IPv6 coinciden."""
    s = _sess(src="::1", dst="::2")
    assert _matches(s, None, ipaddress.ip_address("0:0:0:0:0:0:0:1"), None)


def test_matches_sesion_sin_puertos():
    """Una sesión ICMP (puertos None) no coincide con el puerto 0 pero sí sin filtro de puerto."""
    s = _sess(proto="ICMP", sp=None, dp=None)
    assert not _matches(s, None, None, 0)
    assert _matches(s, None, None, None)


# ---------- query._source_parts ----------

def test_source_parts_grouping_result():
    """Con GroupingResult extrae sesiones y contadores."""
    sess = [_sess()]
    r = GroupingResult(sessions=sess, non_ip=2, malformed=3, truncated=True, untracked_packets=4)
    assert _source_parts(r) == (sess, 2, 3, True, 4)


def test_source_parts_lista():
    """Con una lista de sesiones los contadores son 0/False."""
    sess = [_sess()]
    assert _source_parts(sess) == (sess, 0, 0, False, 0)


# ---------- query._add_session ----------

def test_add_session_acumula_totales_y_por_protocolo():
    """Suma a totales y al ProtocolStats de su protocolo."""
    st = Stats()
    a = _sess()
    a.packets, a.bytes = 2, 100
    b = _sess(proto="UDP")
    b.packets, b.bytes = 1, 10
    _add_session(st, a)
    _add_session(st, a)
    _add_session(st, b)
    assert (st.sessions, st.packets, st.bytes) == (3, 5, 210)
    assert st.by_protocol["TCP"] == ProtocolStats(2, 4, 200)
    assert st.by_protocol["UDP"] == ProtocolStats(1, 1, 10)


def test_add_session_vacia_crea_entrada_con_ceros():
    """Una sesión sin paquetes igual crea su protocolo y cuenta 1 sesión."""
    st = Stats()
    _add_session(st, _sess())
    assert st.sessions == 1 and st.by_protocol["TCP"] == ProtocolStats(1, 0, 0)
