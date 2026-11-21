"""Genera samples/demo.pcap: tráfico SINTÉTICO para el modo demo.

Contiene tráfico normal (DNS, HTTP, ICMP, ARP) y tres comportamientos que
disparan las reglas: escaneo de puertos, login FTP en texto claro y una
consulta DNS con aspecto de túnel. Es determinista: mismo archivo cada vez.

Uso (desde la raíz del proyecto):  python samples/generate_demo.py
"""
import socket
import sys
from pathlib import Path

import dpkt

CLIENT, SERVER, DNS_SRV = "192.168.1.10", "93.184.216.34", "192.168.1.1"
ATTACKER, VICTIM, FTP_CLIENT = "192.168.1.66", "192.168.1.5", "192.168.1.20"
MAC_A, MAC_B = b"\x00\x11\x22\x33\x44\x55", b"\x66\x77\x88\x99\xaa\xbb"


def ip(addr):
    return socket.inet_aton(addr)


def eth(payload, ethertype=dpkt.ethernet.ETH_TYPE_IP, src=MAC_A, dst=MAC_B):
    return bytes(dpkt.ethernet.Ethernet(src=src, dst=dst, type=ethertype, data=payload))


def tcp(src, dst, sport, dport, flags, data=b"", seq=1, ack=0):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, data=data)
    pkt = dpkt.ip.IP(src=ip(src), dst=ip(dst), p=dpkt.ip.IP_PROTO_TCP, data=seg)
    pkt.len = len(bytes(pkt))
    return eth(bytes(pkt))


def udp(src, dst, sport, dport, data):
    seg = dpkt.udp.UDP(sport=sport, dport=dport, data=data)
    seg.ulen = len(bytes(seg))
    pkt = dpkt.ip.IP(src=ip(src), dst=ip(dst), p=dpkt.ip.IP_PROTO_UDP, data=seg)
    pkt.len = len(bytes(pkt))
    return eth(bytes(pkt))


def dns_query(name, txid=0x1234):
    q = dpkt.dns.DNS(id=txid, qr=dpkt.dns.DNS_Q, opcode=dpkt.dns.DNS_QUERY,
                     qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)])
    return bytes(q)


def dns_answer(name, addr, txid=0x1234):
    r = dpkt.dns.DNS(id=txid, qr=dpkt.dns.DNS_R, opcode=dpkt.dns.DNS_QUERY, rcode=dpkt.dns.DNS_RCODE_NOERR,
                     qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)],
                     an=[dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, ttl=60, ip=ip(addr))])
    return bytes(r)


def build():
    SYN, ACK, PSH, FIN = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_FIN
    pk, t = [], 1_700_000_000.0

    def add(frame, dt=0.01):
        nonlocal t
        t += dt
        pk.append((t, frame))

    # ARP (no-IP: aparece en non_ip)
    arp = dpkt.arp.ARP(sha=MAC_A, spa=ip(CLIENT), tha=b"\x00" * 6, tpa=ip(DNS_SRV), op=dpkt.arp.ARP_OP_REQUEST)
    add(eth(bytes(arp), dpkt.ethernet.ETH_TYPE_ARP, dst=b"\xff" * 6))

    # DNS normal
    for i, name in enumerate(["www.example.com", "api.github.com", "cdn.example.org"]):
        add(udp(CLIENT, DNS_SRV, 40000 + i, 53, dns_query(name, 100 + i)), 0.05)
        add(udp(DNS_SRV, CLIENT, 53, 40000 + i, dns_answer(name, SERVER, 100 + i)), 0.02)

    # HTTP normal: handshake + petición + respuesta + cierre
    req = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    add(tcp(CLIENT, SERVER, 51000, 80, SYN))
    add(tcp(SERVER, CLIENT, 80, 51000, SYN | ACK, ack=2))
    add(tcp(CLIENT, SERVER, 51000, 80, ACK, seq=2, ack=2))
    add(tcp(CLIENT, SERVER, 51000, 80, PSH | ACK, req, seq=2, ack=2))
    add(tcp(SERVER, CLIENT, 80, 51000, PSH | ACK, resp, seq=2, ack=2 + len(req)))
    add(tcp(CLIENT, SERVER, 51000, 80, FIN | ACK, seq=2 + len(req), ack=2 + len(resp)))

    # ICMP echo
    echo = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
    icmp = dpkt.ip.IP(src=ip(CLIENT), dst=ip(SERVER), p=dpkt.ip.IP_PROTO_ICMP, data=echo)
    icmp.len = len(bytes(icmp))
    add(eth(bytes(icmp)), 0.1)

    # FTP en texto claro
    add(tcp(FTP_CLIENT, VICTIM, 52000, 21, SYN), 0.2)
    add(tcp(VICTIM, FTP_CLIENT, 21, 52000, SYN | ACK, ack=2))
    add(tcp(VICTIM, FTP_CLIENT, 21, 52000, PSH | ACK, b"220 FTP ready\r\n", seq=2, ack=2))
    add(tcp(FTP_CLIENT, VICTIM, 52000, 21, PSH | ACK, b"USER admin\r\n", seq=2, ack=17))
    add(tcp(VICTIM, FTP_CLIENT, 21, 52000, PSH | ACK, b"331 Password required\r\n", seq=17, ack=14))
    add(tcp(FTP_CLIENT, VICTIM, 52000, 21, PSH | ACK, b"PASS hunter2\r\n", seq=14, ack=40))

    # Escaneo de puertos: SYN a 25 puertos distintos en ~1,25 s
    for port in range(20, 45):
        add(tcp(ATTACKER, VICTIM, 60000, port, SYN), 0.05)

    # DNS con aspecto de túnel (label largo, alta entropía)
    add(udp(FTP_CLIENT, DNS_SRV, 41000, 53,
            dns_query("x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1.evil-c2.example", 777)), 0.3)
    return pk


def main():
    out = Path(__file__).resolve().parent / "demo.pcap"
    with open(out, "wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, frame in build():
            w.writepkt(frame, ts=ts)
    print(f"escrito {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    sys.exit(main())
