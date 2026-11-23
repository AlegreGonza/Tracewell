"""Tests de backend/domain/sessions/grouper.py (paquetes armados con dpkt, sin red)."""
import random
import socket

import dpkt
import pytest

from backend.domain.pcap.reader import Packet, capture_info, iter_packets
from backend.domain.sessions.grouper import GroupingResult, UnsupportedLinktype, group_packets

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"


def ip4(s):
    return socket.inet_aton(s)


def ip6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def eth_ip(l4, proto, src="10.0.0.1", dst="10.0.0.2", frag=0, mf=0):
    ip = dpkt.ip.IP(src=ip4(src), dst=ip4(dst), p=proto, mf=mf, offset=frag, data=l4)
    ip.len = len(bytes(ip))
    return dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)


def tcp_eth(src, sport, dst, dport, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, data=payload)
    return eth_ip(tcp, dpkt.ip.IP_PROTO_TCP, src, dst)


def udp_eth(src, sport, dst, dport, payload=b"x"):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(bytes(udp))
    return eth_ip(udp, dpkt.ip.IP_PROTO_UDP, src, dst)


def pkt(eth, ts=1.0, origlen="auto"):
    raw = bytes(eth) if not isinstance(eth, bytes) else eth
    return Packet(ts, raw, len(raw) if origlen == "auto" else origlen)


# ---------- Normal ----------

def test_peticion_y_respuesta_una_sesion():
    req = pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80, b"GET"), ts=1.0)
    resp = pkt(tcp_eth("10.0.0.2", 80, "10.0.0.1", 40000, b"OK!!!"), ts=3.5)
    r = group_packets([req, resp])
    assert isinstance(r, GroupingResult)
    assert len(r.sessions) == 1
    s = r.sessions[0]
    assert (s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port) == \
        ("TCP", "10.0.0.1", 40000, "10.0.0.2", 80)  # src = iniciador
    assert s.packets == 2
    assert s.bytes == len(req.data) + len(resp.data)
    assert s.first_ts == 1.0 and s.last_ts == 3.5
    assert s.duration == pytest.approx(2.5)
    assert (r.non_ip, r.malformed) == (0, 0)


def test_iniciador_es_el_primer_paquete_visto():
    # Si lo primero que se ve es la respuesta del servidor, ese pasa a ser "src".
    first = pkt(tcp_eth("10.0.0.2", 80, "10.0.0.1", 40000), ts=1.0)
    second = pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80), ts=2.0)
    s = group_packets([first, second]).sessions[0]
    assert (s.src_ip, s.src_port, s.dst_ip, s.dst_port) == ("10.0.0.2", 80, "10.0.0.1", 40000)


def test_dos_conexiones_distintas_dos_sesiones():
    pkts = [
        pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80)),
        pkt(tcp_eth("10.0.0.1", 40001, "10.0.0.2", 80)),
    ]
    r = group_packets(pkts)
    assert [s.src_port for s in r.sessions] == [40000, 40001]
    assert all(s.packets == 1 for s in r.sessions)


def test_tcp_y_udp_mismo_host_sesiones_separadas():
    pkts = [
        pkt(tcp_eth("10.0.0.1", 5000, "10.0.0.2", 53)),
        pkt(udp_eth("10.0.0.1", 5000, "10.0.0.2", 53)),
    ]
    r = group_packets(pkts)
    assert [s.protocol for s in r.sessions] == ["TCP", "UDP"]


def test_icmp_puertos_none():
    icmp = dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
    r = group_packets([pkt(eth_ip(icmp, dpkt.ip.IP_PROTO_ICMP))])
    s = r.sessions[0]
    assert s.protocol == "ICMP"
    assert s.src_port is None and s.dst_port is None


def test_icmp_ida_y_vuelta_una_sesion():
    icmp = dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
    a = pkt(eth_ip(icmp, dpkt.ip.IP_PROTO_ICMP, "10.0.0.1", "10.0.0.2"), ts=1)
    b = pkt(eth_ip(icmp, dpkt.ip.IP_PROTO_ICMP, "10.0.0.2", "10.0.0.1"), ts=2)
    r = group_packets([a, b])
    assert len(r.sessions) == 1 and r.sessions[0].packets == 2


def test_ipv6_tcp():
    tcp = dpkt.tcp.TCP(sport=1234, dport=443)
    ip = dpkt.ip6.IP6(src=ip6("2001:db8::1"), dst=ip6("2001:db8::2"), nxt=6, hlim=64, data=tcp)
    ip.plen = len(bytes(tcp))
    eth = dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip)
    r = group_packets([pkt(eth)])
    s = r.sessions[0]
    assert (s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port) == \
        ("TCP", "2001:db8::1", 1234, "2001:db8::2", 443)


def test_orden_de_aparicion():
    pkts = [
        pkt(tcp_eth("10.0.0.9", 1, "10.0.0.2", 80)),
        pkt(tcp_eth("10.0.0.1", 1, "10.0.0.2", 80)),
        pkt(tcp_eth("10.0.0.9", 1, "10.0.0.2", 80)),  # vuelve a la primera
        pkt(tcp_eth("10.0.0.5", 1, "10.0.0.2", 80)),
    ]
    r = group_packets(pkts)
    assert [s.src_ip for s in r.sessions] == ["10.0.0.9", "10.0.0.1", "10.0.0.5"]
    assert r.sessions[0].packets == 2


# ---------- bytes: origlen vs len(data) ----------

def test_bytes_usa_origlen_si_existe():
    e = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2))
    p = Packet(1.0, e, 1500)  # capturado corto (snaplen): en el cable eran 1500
    assert p.snaplen_limited
    assert group_packets([p]).sessions[0].bytes == 1500


def test_bytes_usa_len_data_si_origlen_none():
    e = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"abc"))
    p = Packet(1.0, e, None)
    assert group_packets([p]).sessions[0].bytes == len(e)


# ---------- Bordes ----------

def test_lista_vacia():
    r = group_packets([])
    assert (r.sessions, r.non_ip, r.malformed) == ([], 0, 0)


def test_generador_vacio():
    r = group_packets(p for p in [])
    assert r.sessions == [] and r.non_ip == 0 and r.malformed == 0


def test_acepta_generador():
    gen = (pkt(tcp_eth("10.0.0.1", 1000 + i, "10.0.0.2", 80)) for i in range(3))
    assert len(group_packets(gen).sessions) == 3


def test_arp_es_non_ip():
    arp = dpkt.arp.ARP(sha=MAC_A, spa=ip4("10.0.0.1"), tha=b"\x00" * 6, tpa=ip4("10.0.0.2"))
    eth = dpkt.ethernet.Ethernet(src=MAC_A, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
    r = group_packets([pkt(eth)])
    assert r.non_ip == 1 and r.sessions == [] and r.malformed == 0


def test_menos_de_14_bytes_malformed():
    r = group_packets([Packet(1.0, b"\x00" * 10, 10), Packet(2.0, b"", 0)])
    assert r.malformed == 2 and r.sessions == [] and r.non_ip == 0


def test_tcp_truncado_malformed():
    # IP dice TCP pero el segmento tiene solo 5 bytes (< 20 de cabecera TCP).
    eth = eth_ip(b"\x00\x50\x00\x51\x00", dpkt.ip.IP_PROTO_TCP)
    r = group_packets([pkt(eth)])
    assert r.malformed == 1 and r.sessions == []


def test_udp_truncado_malformed():
    eth = eth_ip(b"\x00\x50\x00", dpkt.ip.IP_PROTO_UDP)
    r = group_packets([pkt(eth)])
    assert r.malformed == 1 and r.sessions == []


def test_fragmento_ipv4_no_inicial_malformed():
    tcp = dpkt.tcp.TCP(sport=1, dport=2)
    r = group_packets([pkt(eth_ip(tcp, dpkt.ip.IP_PROTO_TCP, frag=100))])
    assert r.malformed == 1 and r.sessions == []


def test_primer_fragmento_mf_se_acepta():
    # Primer fragmento (off=0, flag MF): trae cabecera TCP completa.
    tcp = dpkt.tcp.TCP(sport=1, dport=2)
    r = group_packets([pkt(eth_ip(tcp, dpkt.ip.IP_PROTO_TCP, mf=1))])
    assert r.malformed == 0 and len(r.sessions) == 1


@pytest.mark.parametrize("sport,dport", [(0, 0), (65535, 65535), (0, 65535)])
def test_puertos_limite(sport, dport):
    r = group_packets([pkt(tcp_eth("10.0.0.1", sport, "10.0.0.2", dport))])
    s = r.sessions[0]
    assert (s.src_port, s.dst_port) == (sport, dport)


def test_misma_ip_ambos_extremos_puertos_distintos():
    r = group_packets([
        pkt(tcp_eth("10.0.0.1", 1000, "10.0.0.1", 2000), ts=1),
        pkt(tcp_eth("10.0.0.1", 2000, "10.0.0.1", 1000), ts=2),
    ])
    assert len(r.sessions) == 1 and r.sessions[0].packets == 2


def test_misma_ip_y_mismo_puerto_en_ambos_extremos():
    r = group_packets([pkt(tcp_eth("10.0.0.1", 7, "10.0.0.1", 7))])
    assert len(r.sessions) == 1


def test_protocolo_ip_desconocido_gre():
    eth = eth_ip(b"\x00" * 8, 47)
    r = group_packets([pkt(eth)])
    s = r.sessions[0]
    assert s.protocol == "IP-47"
    assert s.src_port is None and s.dst_port is None


# ---------- Errores esperados ----------

@pytest.mark.parametrize("lt", [0, 101, 113, 127])
def test_linktype_no_ethernet(lt):
    with pytest.raises(UnsupportedLinktype):
        group_packets([], linktype=lt)


def test_linktype_invalido_es_valueerror():
    with pytest.raises(ValueError):
        group_packets([], linktype=228)


def test_bytes_aleatorios_no_escapa_excepcion():
    # Caracterizacion
    rng = random.Random(1234)
    total = 0
    for _ in range(2000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randint(14, 200)))
        r = group_packets([Packet(1.0, data, len(data))])
        assert r.non_ip + r.malformed + sum(s.packets for s in r.sessions) == 1
        total += 1
    assert total == 2000


def test_bytes_aleatorios_forzando_ip_no_escapa_excepcion():
    # Cabecera Ethernet valida (IPv4/IPv6) + cuerpo aleatorio
    rng = random.Random(99)
    for ethertype in (b"\x08\x00", b"\x86\xdd"):
        for _ in range(3000):
            body = bytearray(rng.getrandbits(8) for _ in range(rng.randint(0, 80)))
            body = bytes(body)
            data = MAC_B + MAC_A + ethertype + body
            r = group_packets([Packet(1.0, data, len(data))])
            assert r.non_ip + r.malformed + sum(s.packets for s in r.sessions) == 1


def test_ipv6_esp_no_revienta_y_da_ip_50():
    # Regresion: IPv6 con nxt=50 (ESP) hacia que dpkt no seteara ip.p
    hdr = bytes.fromhex("60000000") + (8).to_bytes(2, "big") + bytes([50, 64]) + bytes(32)
    data = MAC_B + MAC_A + bytes.fromhex("86dd") + hdr + bytes(8)
    r = group_packets([Packet(1.0, data, len(data))])
    assert len(r.sessions) == 1
    s = r.sessions[0]
    assert s.protocol == "IP-50"
    assert (s.src_port, s.dst_port) == (None, None)


def test_ipv6_cabecera_extension_hop_by_hop_tcp():
    # IPv6 nxt=0 (hop-by-hop) -> TCP
    tcp = bytes(dpkt.tcp.TCP(sport=4321, dport=80))
    hbh = bytes([6, 0, 1, 4, 0, 0, 0, 0])  # nxt=TCP, len=0 (8 bytes), PadN
    hdr = (bytes.fromhex("60000000") + (len(hbh) + len(tcp)).to_bytes(2, "big")
           + bytes([0, 64]) + ip6("2001:db8::1") + ip6("2001:db8::2"))
    data = MAC_B + MAC_A + bytes.fromhex("86dd") + hdr + hbh + tcp
    r = group_packets([Packet(1.0, data, len(data))])
    assert r.malformed == 0 and len(r.sessions) == 1
    s = r.sessions[0]
    assert (s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port) == \
        ("TCP", "2001:db8::1", 4321, "2001:db8::2", 80)


def test_ip_truncado_no_escapa_excepcion():
    # Todos los prefijos de un paquete IPv4/TCP y otro IPv6/TCP validos.
    v4 = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"hola"))
    tcp = dpkt.tcp.TCP(sport=1, dport=2)
    ip6p = dpkt.ip6.IP6(src=ip6("::1"), dst=ip6("::2"), nxt=6, plen=len(bytes(tcp)), data=tcp)
    v6 = bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6p))
    for full in (v4, v6):
        for cut in range(len(full) + 1):
            d = full[:cut]
            r = group_packets([Packet(1.0, d, len(d))])
            assert r.non_ip + r.malformed + len(r.sessions) >= 1


# ---------- Integracion ----------

def test_integracion_pcap_iter_packets_group(tmp_path):
    path = tmp_path / "t.pcap"
    frames = [
        (1.0, tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80, b"GET")),
        (2.0, tcp_eth("10.0.0.2", 80, "10.0.0.1", 40000, b"200")),
        (3.0, udp_eth("10.0.0.1", 5353, "10.0.0.3", 53)),
    ]
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for ts, eth in frames:
            w.writepkt(bytes(eth), ts=ts)
    info = capture_info(path)
    r = group_packets(iter_packets(path), linktype=info.linktype)
    assert [s.protocol for s in r.sessions] == ["TCP", "UDP"]
    tcp_s = r.sessions[0]
    assert tcp_s.packets == 2
    assert tcp_s.bytes == len(bytes(frames[0][1])) + len(bytes(frames[1][1]))
    assert tcp_s.duration == pytest.approx(1.0)
    assert (r.non_ip, r.malformed) == (0, 0)


def test_integracion_pcap_nanosegundos_duracion_float(tmp_path):
    # Regresion de float(ts): con magic ns la duracion debe poder restarse.
    import struct
    f1, f2 = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2)), bytes(tcp_eth("10.0.0.2", 2, "10.0.0.1", 1))
    out = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    for sec, ns, f in ((5, 100_000_000, f1), (7, 600_000_000, f2)):
        out += struct.pack("<IIII", sec, ns, len(f), len(f)) + f
    p = tmp_path / "ns.pcap"
    p.write_bytes(out)
    r = group_packets(iter_packets(p), linktype=capture_info(p).linktype)
    assert r.sessions[0].duration == pytest.approx(2.5)


# ---------- tope de sesiones (max_sessions) ----------

def _flows(n, per_flow=1, base_ts=1.0):
    """n flujos UDP distintos (puerto origen distinto), per_flow paquetes c/u."""
    return [pkt(udp_eth("10.0.0.1", 1000 + i, "10.0.0.2", 53), ts=base_ts + i + j / 100)
            for i in range(n) for j in range(per_flow)]


def test_tope_exacto_descarta_flujos_nuevos():
    r = group_packets(_flows(8, per_flow=2), max_sessions=5)
    assert len(r.sessions) == 5
    assert r.truncated is True
    assert r.untracked_packets == 3 * 2  # 3 flujos descartados x 2 paquetes
    assert [s.src_port for s in r.sessions] == [1000 + i for i in range(5)]  # los primeros


def test_tope_no_alcanzado():
    r = group_packets(_flows(3), max_sessions=10)
    assert len(r.sessions) == 3 and r.truncated is False and r.untracked_packets == 0


def test_tope_igual_a_cantidad_no_trunca():
    r = group_packets(_flows(5), max_sessions=5)
    assert len(r.sessions) == 5 and r.truncated is False and r.untracked_packets == 0


def test_default_no_trunca_poco_trafico():
    r = group_packets(_flows(3))
    assert r.truncated is False and r.untracked_packets == 0


def test_sesiones_registradas_siguen_actualizandose_tras_el_tope():
    a1 = pkt(tcp_eth("10.0.0.1", 1, "10.0.0.2", 80, b"a"), ts=1.0)
    b1 = pkt(tcp_eth("10.0.0.1", 2, "10.0.0.2", 80, b"b"), ts=2.0)   # descartada
    a2 = pkt(tcp_eth("10.0.0.2", 80, "10.0.0.1", 1, b"cc"), ts=9.0)  # respuesta de A
    b2 = pkt(tcp_eth("10.0.0.1", 2, "10.0.0.2", 80, b"b"), ts=10.0)  # descartada otra vez
    r = group_packets([a1, b1, a2, b2], max_sessions=1)
    assert len(r.sessions) == 1
    s = r.sessions[0]
    assert s.packets == 2 and s.bytes == len(a1.data) + len(a2.data)
    assert s.first_ts == 1.0 and s.last_ts == 9.0
    assert r.truncated is True and r.untracked_packets == 2


def test_max_sessions_uno():
    r = group_packets(_flows(4), max_sessions=1)
    assert len(r.sessions) == 1 and r.truncated is True and r.untracked_packets == 3


@pytest.mark.parametrize("bad", [0, -1, True, False, "5", 2.5, None, float("nan")])
def test_max_sessions_invalido(bad):
    with pytest.raises(ValueError):
        group_packets(_flows(1), max_sessions=bad)


def test_max_sessions_invalido_no_consume_generador():
    gen = (p for p in _flows(2))
    with pytest.raises(ValueError):
        group_packets(gen, max_sessions=0)
    assert len(list(gen)) == 2


def test_non_ip_y_malformed_cuentan_aun_truncado():
    arp = bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP,
                                       data=b"\x00" * 28))
    roto = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2))[:14 + 20 + 5]  # TCP truncado
    pk = _flows(3) + [pkt(arp), pkt(roto)]
    r = group_packets(pk, max_sessions=1)
    assert r.truncated is True and r.untracked_packets == 2
    assert r.non_ip == 1 and r.malformed == 1


def test_tope_con_generador():
    r = group_packets((p for p in _flows(6)), max_sessions=2)
    assert len(r.sessions) == 2 and r.truncated is True and r.untracked_packets == 4
