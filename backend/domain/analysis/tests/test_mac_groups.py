"""MAC por sesión y agrupación de equipos por MAC."""
import socket

import dpkt
import pytest

from backend.domain.analysis.hosts import _host_mac, build_hosts, build_mac_groups
from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import group_packets

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"
MAC_RTR = b"\x00\x50\x56\xc0\x00\x08"


def tcp(src, sport, dst, dport, smac, dmac, flags=0x02):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=seg)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=smac, dst=dmac, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def udp6(src, dst, smac, dmac):
    seg = dpkt.udp.UDP(sport=5000, dport=53, data=b"x")
    seg.ulen = len(bytes(seg))
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src), dst=socket.inet_pton(socket.AF_INET6, dst), nxt=17, data=seg)
    ip.plen = len(bytes(seg))
    return bytes(dpkt.ethernet.Ethernet(src=smac, dst=dmac, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip))


def sessions(*frames):
    return group_packets([Packet(float(i), f, None) for i, f in enumerate(frames)]).sessions


# ----------------------------------------------------------- MAC por sesión

def test_la_sesion_guarda_las_mac_del_primer_paquete():
    [s] = sessions(tcp("10.0.0.5", 5000, "10.0.0.9", 22, MAC_A, MAC_B))
    assert (s.src_mac, s.dst_mac) == ("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff")


def test_la_respuesta_no_cambia_las_mac_de_origen():
    [s] = sessions(tcp("10.0.0.5", 5000, "10.0.0.9", 22, MAC_A, MAC_B), tcp("10.0.0.9", 22, "10.0.0.5", 5000, MAC_B, MAC_A, 0x12))
    assert (s.src_ip, s.src_mac) == ("10.0.0.5", "00:11:22:33:44:55")


def test_origen_invertido_cada_mac_sigue_a_su_ip():
    # el primer paquete visto es la respuesta del servidor
    [s] = sessions(tcp("10.0.0.9", 22, "10.0.0.5", 5000, MAC_B, MAC_A, 0x12))
    assert (s.src_ip, s.src_mac, s.dst_ip, s.dst_mac) == ("10.0.0.9", "aa:bb:cc:dd:ee:ff", "10.0.0.5", "00:11:22:33:44:55")


def test_las_mac_no_van_al_json_exportado():
    from backend.domain.export.json_export import session_to_dict

    [s] = sessions(tcp("10.0.0.5", 5000, "10.0.0.9", 22, MAC_A, MAC_B))
    assert not {"src_mac", "dst_mac"} & set(session_to_dict(0, s))


# ------------------------------------------------------------- MAC por host

def test_host_interno_toma_su_mac():
    hosts = {h.ip: h for h in build_hosts(sessions(tcp("10.0.0.5", 5000, "10.0.0.9", 22, MAC_A, MAC_B)))}
    assert hosts["10.0.0.5"].mac == "00:11:22:33:44:55" and hosts["10.0.0.9"].mac == "aa:bb:cc:dd:ee:ff"


def test_host_remoto_no_toma_la_mac_del_router():
    hosts = {h.ip: h for h in build_hosts(sessions(tcp("10.0.0.5", 5000, "8.8.8.8", 443, MAC_A, MAC_RTR)))}
    assert hosts["10.0.0.5"].mac == "00:11:22:33:44:55" and hosts["8.8.8.8"].mac is None


@pytest.mark.parametrize("mac", ["ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "33:33:00:00:00:fb"])
def test_mac_de_grupo_se_descarta(mac):
    assert _host_mac("10.0.0.5", mac) is None


def test_host_mac_casos_borde():
    assert _host_mac("10.0.0.5", None) is None and _host_mac("10.0.0.5", "") is None
    assert _host_mac("8.8.8.8", "00:11:22:33:44:55") is None
    assert _host_mac("10.0.0.5", "00:11:22:33:44:55") == "00:11:22:33:44:55"


def test_sesion_sin_atributos_de_mac_no_rompe():
    from types import SimpleNamespace

    s = SimpleNamespace(protocol="TCP", src_ip="10.0.0.5", src_port=5000, dst_ip="10.0.0.9", dst_port=22, packets=1, bytes=10)
    assert all(h.mac is None for h in build_hosts([s]))


# ---------------------------------------------------------------- agrupación

def test_dual_stack_agrupa_ipv4_e_ipv6_bajo_la_misma_mac():
    hosts = build_hosts(sessions(
        tcp("192.168.1.10", 5000, "192.168.1.1", 80, MAC_A, MAC_B),
        udp6("fd00::10", "fd00::1", MAC_A, MAC_B),
    ))
    groups = build_mac_groups(hosts)
    shared = groups[0]
    assert shared["mac"] == "00:11:22:33:44:55" and shared["shared"] is True
    assert shared["ips"] == ["192.168.1.10", "fd00::10"] and "IPv4 e IPv6" in shared["hint"]


def test_router_con_varias_ip_se_marca_compartida():
    hosts = build_hosts(sessions(
        tcp("10.0.0.5", 5000, "10.1.0.7", 80, MAC_A, MAC_RTR),
        tcp("10.0.0.5", 5001, "10.1.0.8", 80, MAC_A, MAC_RTR),
    ))
    g = next(g for g in build_mac_groups(hosts) if g["mac"] == "00:50:56:c0:00:08")
    assert g["ips"] == ["10.1.0.7", "10.1.0.8"] and g["shared"] is True and "router" in g["hint"]


def test_grupos_compartidos_primero_y_luego_por_bytes():
    hosts = build_hosts(sessions(
        tcp("10.0.0.5", 5000, "10.1.0.7", 80, MAC_A, MAC_RTR),
        tcp("10.0.0.5", 5001, "10.1.0.8", 80, MAC_A, MAC_RTR),
    ))
    groups = build_mac_groups(hosts)
    assert groups[0]["shared"] is True and groups[-1]["shared"] is False


def test_mac_administrada_localmente_se_avisa():
    local = b"\x02\x11\x22\x33\x44\x55"
    [g] = [g for g in build_mac_groups(build_hosts(sessions(tcp("10.0.0.5", 5000, "8.8.8.8", 443, local, MAC_RTR)))) if g["mac"].startswith("02")]
    assert "administrada localmente" in g["hint"] and g["shared"] is False


def test_suma_sesiones_bytes_y_nombres():
    hosts = build_hosts(sessions(tcp("10.0.0.5", 5000, "10.0.0.9", 22, MAC_A, MAC_B)))
    g = next(g for g in build_mac_groups(hosts) if g["mac"] == "00:11:22:33:44:55")
    assert g["sessions"] == 1 and g["bytes"] > 0 and g["names"] == []


def test_sin_equipos_con_mac_no_hay_grupos():
    assert build_mac_groups([]) == []
    assert build_mac_groups(build_hosts(sessions(tcp("8.8.8.8", 443, "1.1.1.1", 443, MAC_RTR, MAC_RTR)))) == []
