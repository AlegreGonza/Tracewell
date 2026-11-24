"""Tests de parse_ip y SessionGrouper (agrupación paquete a paquete, con la capa IP ya leída)."""
import pytest

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import SessionGrouper, UnsupportedLinktype, group_packets, parse_ip
from backend.domain.sessions.tests.test_grouper import pkt, tcp_eth, udp_eth


def paquetes():
    good = bytes(tcp_eth("10.0.0.1", 1000, "10.0.0.2", 80, b"data"))
    return [
        pkt(tcp_eth("10.0.0.1", 1000, "10.0.0.2", 80, b"GET")),
        pkt(udp_eth("10.0.0.2", 53, "10.0.0.1", 5000)),
        Packet(3.0, b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + bytes(28), 42),  # ARP: no es IP
        Packet(4.0, good[:20], 20),  # Ethernet cortado
        Packet(5.0, good[:40], 40),  # TCP cortado
        pkt(tcp_eth("10.0.0.2", 80, "10.0.0.1", 1000, b"OK")),
    ]


def test_parse_ip_distingue_ip_no_ip_y_danado():
    capa, danado = parse_ip(paquetes()[0].data)
    assert capa is not None and danado is False
    assert parse_ip(paquetes()[2].data) == (None, False)
    assert parse_ip(paquetes()[3].data) == (None, True)


def test_session_grouper_da_lo_mismo_que_group_packets():
    todos = paquetes()
    g = SessionGrouper()
    for p in todos:
        g.add(p, *parse_ip(p.data))
    r, esperado = g.result(), group_packets(todos)
    assert r == esperado and r.sessions == esperado.sessions
    assert r.non_ip == 1 and r.malformed >= 1 and len(r.sessions) == 2


def test_session_grouper_respeta_el_tope_y_valida_argumentos():
    g = SessionGrouper(max_sessions=1)
    for p in paquetes()[:2]:
        g.add(p, *parse_ip(p.data))
    assert g.result().truncated and g.result().untracked_packets == 1
    with pytest.raises(UnsupportedLinktype):
        SessionGrouper(linktype=113)
    with pytest.raises(ValueError):
        SessionGrouper(max_sessions=0)
