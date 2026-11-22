"""Banderas TCP contadas por sesión (SYN puros, RST y reintentos) sin alterar el resto del agrupado."""
import socket

import dpkt

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import group_packets

SYN, ACK, RST, FIN, PSH = 0x02, 0x10, 0x04, 0x01, 0x08


def frame(src, sport, dst, dport, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def run(*frames):
    return group_packets([Packet(float(i), f, None) for i, f in enumerate(frames)]).sessions


def test_un_syn_y_su_respuesta_no_son_reintento():
    [s] = run(frame("10.0.0.1", 5000, "10.0.0.2", 22, SYN), frame("10.0.0.2", 22, "10.0.0.1", 5000, SYN | ACK))
    assert (s.syn_packets, s.syn_retries, s.rst_packets) == (1, 0, 0)  # el SYN+ACK no cuenta como SYN puro


def test_syn_reenviado_cuenta_como_reintento():
    [s] = run(*[frame("10.0.0.1", 5000, "10.0.0.2", 3389, SYN)] * 4)
    assert (s.syn_packets, s.syn_retries) == (4, 3)


def test_rst_se_cuenta_en_ambos_sentidos():
    [s] = run(
        frame("10.0.0.1", 5000, "10.0.0.2", 22, SYN),
        frame("10.0.0.2", 22, "10.0.0.1", 5000, RST | ACK),
        frame("10.0.0.1", 5000, "10.0.0.2", 22, RST),
    )
    assert s.rst_packets == 2 and s.packets == 3


def test_sesion_normal_sin_rst_ni_reintentos():
    [s] = run(
        frame("10.0.0.1", 5000, "10.0.0.2", 22, SYN),
        frame("10.0.0.2", 22, "10.0.0.1", 5000, SYN | ACK),
        frame("10.0.0.1", 5000, "10.0.0.2", 22, ACK),
        frame("10.0.0.1", 5000, "10.0.0.2", 22, PSH | ACK, b"x"),
        frame("10.0.0.1", 5000, "10.0.0.2", 22, FIN | ACK),
    )
    assert (s.syn_packets, s.syn_retries, s.rst_packets) == (1, 0, 0)


def test_udp_no_tiene_banderas():
    udp = dpkt.udp.UDP(sport=1, dport=2, data=b"x")
    udp.ulen = len(bytes(udp))
    ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"), p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(bytes(ip))
    f = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))
    [s] = run(f, f)
    assert (s.syn_packets, s.rst_packets, s.syn_retries) == (0, 0, 0)


def test_las_banderas_no_cambian_paquetes_ni_bytes():
    frames = [frame("10.0.0.1", 5000, "10.0.0.2", 22, SYN), frame("10.0.0.2", 22, "10.0.0.1", 5000, RST)]
    [s] = run(*frames)
    assert s.packets == 2 and s.bytes == sum(len(f) for f in frames)


def test_cada_sesion_lleva_sus_propios_contadores():
    a, b = run(frame("10.0.0.1", 5000, "10.0.0.2", 22, SYN), frame("10.0.0.1", 5001, "10.0.0.2", 23, RST))
    assert (a.syn_packets, a.rst_packets) == (1, 0) and (b.syn_packets, b.rst_packets) == (0, 1)


def test_el_json_exportado_no_lleva_las_banderas():
    from backend.domain.export.json_export import session_to_dict

    [s] = run(frame("10.0.0.1", 5000, "10.0.0.2", 22, RST))
    assert not {"syn_packets", "rst_packets", "syn_retries"} & set(session_to_dict(0, s))
