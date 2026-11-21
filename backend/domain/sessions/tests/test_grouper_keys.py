"""Tests de Session.key, packet_endpoints y packet_session_key."""
import dpkt

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import (
    Session, group_packets, packet_endpoints, packet_session_key,
)
from backend.domain.sessions.tests.test_grouper import MAC_A, MAC_B, eth_ip, pkt, tcp_eth


def _arp():
    return bytes(dpkt.ethernet.Ethernet(
        src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP, data=dpkt.arp.ARP()))


def test_endpoints_none_para_arp():
    assert packet_endpoints(_arp()) is None


def test_endpoints_none_basura_y_corto():
    assert packet_endpoints(b"\xde\xad\xbe\xef" * 20) is None
    assert packet_endpoints(b"\x00\x01") is None
    assert packet_endpoints(b"") is None


def test_endpoints_none_fragmento_no_inicial():
    frag = eth_ip(b"\x00" * 20, dpkt.ip.IP_PROTO_TCP, frag=10)
    assert packet_endpoints(bytes(frag)) is None


def test_endpoints_tcp():
    e = packet_endpoints(bytes(tcp_eth("10.0.0.1", 1234, "10.0.0.2", 80)))
    assert e == ("10.0.0.1", 1234, "10.0.0.2", 80, 6)


def test_key_ida_y_vuelta_igual_y_coincide_con_session():
    a = pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80))
    b = pkt(tcp_eth("10.0.0.2", 80, "10.0.0.1", 40000))
    ka, kb = packet_session_key(a), packet_session_key(b)
    assert ka is not None and ka == kb
    assert group_packets([a, b]).sessions[0].key == ka


def test_key_distinta_otro_puerto():
    a = pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 80))
    c = pkt(tcp_eth("10.0.0.1", 40000, "10.0.0.2", 81))
    assert packet_session_key(a) != packet_session_key(c)


def test_key_none_no_ip():
    assert packet_session_key(Packet(1.0, _arp(), None)) is None


def test_session_key_fuera_de_repr_y_eq():
    s1 = Session("TCP", "a", 1, "b", 2, key=("x",))
    s2 = Session("TCP", "a", 1, "b", 2, key=("y",))
    assert "key" not in repr(s1) and "'x'" not in repr(s1)
    assert s1 == s2


def test_session_sin_key():
    s = Session("TCP", "a", 1, "b", 2)
    assert s.key is None
    assert s.duration == 0.0
