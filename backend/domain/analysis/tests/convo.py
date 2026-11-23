"""Constructor de conversaciones TCP (frames Ethernet con dpkt) para probar HTTP, TLS y explicaciones."""
import socket

import dpkt

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.tests.test_grouper import MAC_A, MAC_B

SYN, SYNACK, ACK, PSH, FIN, RST = 0x02, 0x12, 0x10, 0x18, 0x11, 0x04


def frame(src, sport, dst, dport, seq, flags, data=b"", ack=0):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=data)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=t)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def conversation(c_ip="10.0.0.1", cport=40000, s_ip="93.184.216.34", sport=80, turns=(), handshake=True, close="fin",
                 c_isn=1000, s_isn=5000, mss=1200, t0=1.0):
    """turns: [('c'|'s', bytes), ...] en orden."""
    frames = []
    c_seq, s_seq = c_isn, s_isn
    if handshake:
        frames.append(frame(c_ip, cport, s_ip, sport, c_seq, SYN))
        frames.append(frame(s_ip, sport, c_ip, cport, s_seq, SYNACK, ack=c_seq + 1))
        frames.append(frame(c_ip, cport, s_ip, sport, c_seq + 1, ACK, ack=s_seq + 1))
        c_seq += 1
        s_seq += 1
    for who, data in turns:
        for i in range(0, len(data), mss):
            part = data[i:i + mss]
            if who == "c":
                frames.append(frame(c_ip, cport, s_ip, sport, c_seq, PSH, part, ack=s_seq))
                c_seq += len(part)
            else:
                frames.append(frame(s_ip, sport, c_ip, cport, s_seq, PSH, part, ack=c_seq))
                s_seq += len(part)
    if close == "fin":
        frames.append(frame(c_ip, cport, s_ip, sport, c_seq, FIN, ack=s_seq))
        frames.append(frame(s_ip, sport, c_ip, cport, s_seq, FIN, ack=c_seq + 1))
    elif close == "rst":
        frames.append(frame(s_ip, sport, c_ip, cport, s_seq, RST))
    return frames


def as_packets(frames, t0=1.0):
    return [Packet(t0 + i, f, len(f)) for i, f in enumerate(frames)]
