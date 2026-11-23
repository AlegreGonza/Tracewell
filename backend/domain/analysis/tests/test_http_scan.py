"""Tests de backend/domain/analysis/http_scan.py y de stream.raw_directions."""
from types import SimpleNamespace

import pytest

import backend.domain.analysis.http_scan as HS
import backend.domain.analysis.stream as S
from backend.domain.analysis.analyzer import analyze
from backend.domain.analysis.http_scan import HTTP_PORTS, candidate_sessions, scan_http
from backend.domain.analysis.stream import follow_stream, raw_directions
from backend.domain.analysis.tests.convo import as_packets, conversation
from backend.domain.analysis.tests.test_analyzer import DEMO, write_pcap
from backend.domain.analysis.tests.test_http import req, resp
from backend.domain.sessions.grouper import Session

SESS = SimpleNamespace(src_ip="10.0.0.1", src_port=40000, dst_ip="93.184.216.34", dst_port=80)


# ------------------------------------------------------------------ raw_directions

def test_raw_directions_junta_cada_sentido_en_orden():
    r = raw_directions(SESS, as_packets(conversation(turns=[("c", b"AAA"), ("s", b"111"), ("c", b"BBB"), ("s", b"222")])))
    assert (r.origin, r.destination, r.has_gaps, r.truncated) == (b"AAABBB", b"111222", False, False)


def test_raw_directions_sin_datos():
    r = raw_directions(SESS, as_packets(conversation(turns=[])))
    assert (r.origin, r.destination, r.has_gaps, r.truncated) == (b"", b"", False, False)


def test_raw_directions_marca_huecos_y_quita_retransmisiones():
    frames = conversation(turns=[("c", b"AAA")], close=None)
    pk = as_packets(frames + [frames[3]])  # retransmision del dato
    assert raw_directions(SESS, pk).origin == b"AAA"
    gap = conversation(turns=[("c", b"A" * 20)], mss=10, close=None)
    pk = as_packets(gap[:3] + gap[4:])  # falta el primer segmento de datos
    r = raw_directions(SESS, pk)
    assert r.has_gaps is True and r.origin == b"A" * 10


def test_raw_directions_truncado(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 5)
    r = raw_directions(SESS, as_packets(conversation(turns=[("c", b"A" * 10), ("s", b"B" * 10)], mss=6)))
    assert r.truncated is True


def test_raw_directions_no_corta_texto_como_follow_stream(monkeypatch):
    monkeypatch.setattr(S, "TEXT_CHUNK", 5)
    pk = as_packets(conversation(turns=[("c", b"0123456789")]))
    assert follow_stream(SESS, pk).chunks[0]["text"].endswith("…")
    assert raw_directions(SESS, pk).origin == b"0123456789"


def test_raw_directions_un_flujo_tls_no_se_toca():
    tls = b"\x16\x03\x01\x00\x05hello"
    assert raw_directions(SESS, as_packets(conversation(turns=[("c", tls)]))).origin == tls


def test_follow_stream_sigue_igual_que_antes():
    st = follow_stream(SESS, as_packets(conversation(turns=[("c", b"GET /"), ("s", b"HTTP/1.1 200 OK")])))
    assert [(c["from"], c["text"]) for c in st.chunks] == [("origen", "GET /"), ("destino", "HTTP/1.1 200 OK")]


# ------------------------------------------------------------------ candidate_sessions

def an(sessions):
    return SimpleNamespace(result=SimpleNamespace(sessions=sessions))


def sess(proto="TCP", sport=40000, dport=80, key=("k",)):
    return Session(proto, "10.0.0.1", sport, "10.0.0.2", dport, 1, 1, 0.0, 0.0, key=key)


def test_candidatas_solo_tcp_a_puertos_http():
    ss = [sess(), sess(dport=443), sess("UDP", dport=80), sess(dport=8080, key=("a",)), sess(sport=80, dport=50000, key=("b",)), sess(sport=1, dport=2, key=("c",))]
    assert [i for i, _ in candidate_sessions(an(ss))] == [0, 3, 4]


def test_candidatas_ignoran_sesiones_sin_clave():
    assert candidate_sessions(an([sess(key=None), sess(key=("x",))])) == [(1, sess(key=("x",)))] or len(candidate_sessions(an([sess(key=None), sess(key=("x",))]))) == 1


def test_candidatas_tope(monkeypatch):
    monkeypatch.setattr(HS, "MAX_SESSIONS", 3)
    assert len(candidate_sessions(an([sess(key=(i,)) for i in range(10)]))) == 3


@pytest.mark.parametrize("port", HTTP_PORTS)
def test_todos_los_puertos_http_cuentan(port):
    assert len(candidate_sessions(an([sess(dport=port)]))) == 1


# ------------------------------------------------------------------ scan_http

def pcap_with(tmp_path, *convos):
    frames = [f for c in convos for f in c]
    return analyze(write_pcap(tmp_path / "h.pcap", frames), [])


def test_scan_http_una_pasada_items_con_sesion_y_extremos(tmp_path):
    a = pcap_with(
        tmp_path,
        conversation(cport=40000, turns=[("c", req("GET", "/a") + req("GET", "/b")), ("s", resp(200, body=b"AA") + resp(404, "NF", body=b""))]),
        conversation(c_ip="10.0.0.2", cport=40001, turns=[("c", req("POST", "/p", body=b"x=1")), ("s", resp(200, body=b"ok"))], c_isn=77),
    )
    out = scan_http(a)
    assert out["scanned"] == 2 and out["capped"] is False
    assert [(i["session_id"], i["method"], i["target"], i["status"]) for i in out["items"]] == [
        (0, "GET", "/a", 200), (0, "GET", "/b", 404), (1, "POST", "/p", 200)]
    assert out["items"][0]["src"] == "10.0.0.1:40000" and out["items"][0]["dst"] == "93.184.216.34:80"


def test_scan_http_lee_el_archivo_una_sola_vez(tmp_path, monkeypatch):
    a = pcap_with(tmp_path, conversation(turns=[("c", req()), ("s", resp(200, body=b"x"))]), conversation(cport=40001, turns=[("c", req()), ("s", resp(200, body=b"y"))], c_isn=9))
    opened = []
    real = HS.iter_packets
    monkeypatch.setattr(HS, "iter_packets", lambda p: opened.append(p) or real(p))
    scan_http(a)
    assert len(opened) == 1


def test_scan_http_sin_candidatas_o_sin_http(tmp_path):
    a = pcap_with(tmp_path, conversation(sport=443, turns=[("c", b"\x16\x03\x01\x00\x05hello")]))
    assert scan_http(a) == {"scanned": 0, "capped": False, "items": []}
    b = pcap_with(tmp_path, conversation(turns=[("c", b"USER x\r\n"), ("s", b"220 hi\r\n")]))
    assert scan_http(b) == {"scanned": 1, "capped": False, "items": []}


def test_scan_http_https_en_puerto_http_no_da_items(tmp_path):
    a = pcap_with(tmp_path, conversation(turns=[("c", b"\x16\x03\x01\x00\x05hello")]))
    assert scan_http(a)["items"] == []


def test_scan_http_max_exchanges(monkeypatch, tmp_path):
    monkeypatch.setattr(HS, "MAX_EXCHANGES", 2)
    a = pcap_with(tmp_path, conversation(turns=[("c", b"".join(req("GET", f"/{i}") for i in range(5))), ("s", b"".join(resp(200) for _ in range(5)))]))
    out = scan_http(a)
    assert len(out["items"]) == 2 and out["capped"] is True


def test_scan_http_max_bytes_marca_capped(monkeypatch, tmp_path):
    monkeypatch.setattr(HS, "MAX_BYTES", 300)
    a = pcap_with(tmp_path, conversation(turns=[("c", req("GET", "/" + "a" * 500)), ("s", resp(200, body=b"x" * 500))]))
    assert scan_http(a)["capped"] is True


def test_scan_http_demo_no_rompe():
    out = scan_http(analyze(DEMO, []))
    assert out["capped"] is False and any(i["method"] == "GET" and i["host"] == "www.example.com" for i in out["items"])
    assert all(set(i) >= {"session_id", "src", "dst", "method", "status", "file", "sensitive_fields"} for i in out["items"])


# ------------------------------------------------------------------ IPv6 y campos src_ip / dst_ip

def v6_frames(src="2001:db8::1", dst="2001:db8::80", sport=51000, dport=80):
    import socket
    import dpkt
    from backend.domain.sessions.tests.test_grouper import MAC_A, MAC_B

    def f(a, ap, b, bp, seq, flags, data=b""):
        t = dpkt.tcp.TCP(sport=ap, dport=bp, seq=seq, flags=flags, data=data)
        ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, a), dst=socket.inet_pton(socket.AF_INET6, b), nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, data=t)
        ip6.plen = len(bytes(t))
        return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))
    q, r = req("GET", "/v6"), resp(200, body=b"ok")
    return [f(src, sport, dst, dport, 100, 0x02), f(dst, dport, src, sport, 500, 0x12), f(src, sport, dst, dport, 101, 0x10),
            f(src, sport, dst, dport, 101, 0x18, q), f(dst, dport, src, sport, 501, 0x18, r)]


def test_scan_http_items_traen_src_ip_y_dst_ip(tmp_path):
    a = pcap_with(tmp_path, conversation(cport=40000, turns=[("c", req()), ("s", resp(200, body=b"x"))]))
    item = scan_http(a)["items"][0]
    assert (item["src_ip"], item["dst_ip"]) == ("10.0.0.1", "93.184.216.34")
    assert item["src"] == "10.0.0.1:40000" and item["dst"] == "93.184.216.34:80"


def test_scan_http_ipv6_src_ip_es_la_ip_sola(tmp_path):
    a = analyze(write_pcap(tmp_path / "v6.pcap", v6_frames()), [])
    out = scan_http(a)
    assert out["scanned"] == 1 and len(out["items"]) == 1
    item = out["items"][0]
    assert item["src_ip"] == "2001:db8::1" and item["dst_ip"] == "2001:db8::80"
    assert item["src"] == "2001:db8::1:51000"  # ambiguo si se corta en el primer ':'; por eso existe src_ip
    assert item["target"] == "/v6" and item["status"] == 200


def test_scan_http_ipv6_link_local(tmp_path):
    a = analyze(write_pcap(tmp_path / "ll.pcap", v6_frames(src="fe80::1", dst="fe80::2")), [])
    item = scan_http(a)["items"][0]
    assert item["src_ip"] == "fe80::1" and item["src"] == "fe80::1:51000"
