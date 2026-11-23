"""Tests de backend/domain/analysis/stream.py (follow stream) y analyzer.session_stream."""
import socket
from types import SimpleNamespace

import dpkt
import pytest

import backend.domain.analysis.analyzer as analyzer_mod
import backend.domain.analysis.stream as S
from backend.domain.analysis.analyzer import analyze, session_stream
from backend.domain.analysis.stream import Stream, _looks_tls, _printable, follow_stream
from backend.domain.analysis.tests.test_analyzer import DEMO, write_pcap
from backend.domain.pcap.reader import Packet
from backend.domain.sessions.tests.test_grouper import MAC_A, MAC_B, eth_ip, tcp_eth, udp_eth

SYN, SYNACK, ACK, PSH, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
C, SRV = "10.0.0.1", "10.0.0.2"
SESSION = SimpleNamespace(src_ip=C, src_port=40000, dst_ip=SRV, dst_port=80)


def seg(ts, frm, seq, data=b"", flags=ACK, v6=False):
    """Segmento TCP del cliente (frm='c') o del servidor (frm='s')."""
    src, dst, sp, dp = (C, SRV, 40000, 80) if frm == "c" else (SRV, C, 80, 40000)
    t = dpkt.tcp.TCP(sport=sp, dport=dp, seq=seq, flags=flags, data=data)
    raw = bytes(eth_ip(t, dpkt.ip.IP_PROTO_TCP, src, dst))
    return Packet(ts, raw, len(raw))


def follow(*pkts, session=SESSION):
    return follow_stream(session, list(pkts))


def texts(st):
    return [(c.get("from"), c.get("text")) if "from" in c else ("gap", c["gap"]) for c in st.chunks]


# ------------------------------------------------------------------ boceto del coordinador

def test_conversacion_completa_con_retransmision_y_hueco():
    req1, req2 = b"GET / HTTP/1.1\r\n", b"Host: x\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\n\r\n"
    st = follow(
        seg(1, "c", 1000, flags=SYN), seg(2, "s", 5000, flags=SYNACK), seg(3, "c", 1001, flags=ACK),
        seg(4, "c", 1001, req1, PSH),
        seg(5, "c", 1001, req1, PSH),  # retransmision
        seg(6, "c", 1001 + len(req1), req2, PSH),
        seg(7, "s", 5001, resp, PSH),
        seg(8, "s", 5001 + len(resp) + 12, b"tail", PSH),  # faltan 12 bytes
    )
    assert st.chunks == [
        {"from": "origen", "bytes": len(req1 + req2), "text": (req1 + req2).decode()},
        {"from": "destino", "bytes": len(resp), "text": resp.decode()},
        {"gap": 12},
        {"from": "destino", "bytes": 4, "text": "tail"},
    ]
    assert st.origin_bytes == len(req1 + req2) and st.destination_bytes == len(resp) + 4
    assert not st.encrypted and not st.truncated


def test_hueco_en_el_mismo_sentido_queda_entre_dos_bloques():
    st = follow(seg(1, "s", 5000, b"AAAA"), seg(2, "s", 5004 + 12, b"BBBB"))
    assert st.chunks[0]["text"] == "AAAA"
    assert st.chunks[1] == {"gap": 12}
    assert st.chunks[2] == {"from": "destino", "bytes": 4, "text": "BBBB"}


def test_forma_de_los_bloques():
    st = follow(seg(1, "c", 10, b"hi"), seg(2, "s", 99, b"yo"))
    assert all(set(c) == {"from", "bytes", "text"} for c in st.chunks)
    assert [c["from"] for c in st.chunks] == ["origen", "destino"]
    assert isinstance(st, Stream) and (st.origin_bytes, st.destination_bytes) == (2, 2)


def test_vacio():
    st = follow_stream(SESSION, [])
    assert st == Stream() and st.chunks == [] and not st.encrypted and not st.truncated


# ------------------------------------------------------------------ union, retransmision, solape

def test_datos_consecutivos_del_mismo_sentido_se_unen():
    st = follow(seg(1, "c", 1, b"AB"), seg(2, "c", 3, b"CD"), seg(3, "c", 5, b"EF"))
    assert texts(st) == [("origen", "ABCDEF")] and st.chunks[0]["bytes"] == 6


def test_turnos_alternados_dan_un_bloque_por_turno():
    st = follow(seg(1, "c", 1, b"A"), seg(2, "s", 1, b"B"), seg(3, "c", 2, b"C"), seg(4, "s", 2, b"D"))
    assert texts(st) == [("origen", "A"), ("destino", "B"), ("origen", "C"), ("destino", "D")]


def test_retransmision_exacta_se_descarta_y_no_cuenta_bytes():
    st = follow(seg(1, "c", 100, b"hola"), seg(2, "c", 100, b"hola"), seg(3, "c", 100, b"hola"))
    assert texts(st) == [("origen", "hola")] and st.origin_bytes == 4


def test_solape_parcial_se_recorta():
    st = follow(seg(1, "c", 100, b"ABCDEF"), seg(2, "c", 103, b"DEFGHI"))
    assert texts(st) == [("origen", "ABCDEFGHI")] and st.origin_bytes == 9


def test_retransmision_mas_larga_aporta_solo_lo_nuevo():
    st = follow(seg(1, "c", 100, b"AB"), seg(2, "c", 100, b"ABCD"))
    assert texts(st) == [("origen", "ABCD")]


def test_segmento_contenido_dentro_de_lo_ya_visto_se_descarta():
    st = follow(seg(1, "c", 100, b"ABCDEF"), seg(2, "c", 102, b"CD"))
    assert texts(st) == [("origen", "ABCDEF")]


def test_segmento_anterior_a_la_base_se_ignora():
    st = follow(seg(1, "c", 1000, b"AAA"), seg(2, "c", 900, b"old"))
    assert texts(st) == [("origen", "AAA")]


def test_ack_puros_y_segmentos_sin_datos_no_generan_bloques():
    st = follow(seg(1, "c", 1, flags=SYN), seg(2, "s", 1, flags=SYNACK), seg(3, "c", 2), seg(4, "c", 2, flags=FIN))
    assert st.chunks == [] and st.origin_bytes == st.destination_bytes == 0


# ------------------------------------------------------------------ huecos

def test_hueco_se_marca_con_gap_y_el_dato_posterior_sigue():
    st = follow(seg(1, "c", 1000, b"AAA"), seg(2, "c", 1010, b"BBB"))
    assert st.chunks == [
        {"from": "origen", "bytes": 3, "text": "AAA"}, {"gap": 7}, {"from": "origen", "bytes": 3, "text": "BBB"}]
    assert st.origin_bytes == 6  # el hueco no cuenta como dato


def test_dos_huecos_seguidos():
    st = follow(seg(1, "c", 0, b"A"), seg(2, "c", 5, b"B"), seg(3, "c", 10, b"C"))
    assert [c.get("gap") for c in st.chunks] == [None, 4, None, 4, None]


def test_hueco_al_principio_si_la_primera_pieza_no_es_la_base_no_existe():
    """Sin SYN, el primer segmento define la base: nunca hay hueco inicial."""
    st = follow(seg(1, "c", 5000, b"X"))
    assert texts(st) == [("origen", "X")]


def test_llegada_desordenada_tras_un_hueco_se_descarta_sin_romper():
    """Limite documentado: el pedazo que llena un hueco despues de haber pasado de largo no se reubica."""
    st = follow(seg(1, "c", 100, b"AAA"), seg(2, "c", 110, b"BBB"), seg(3, "c", 103, b"CCCCCCC"))
    assert texts(st)[:3] == [("origen", "AAA"), ("gap", 7), ("origen", "BBB")]
    assert st.origin_bytes == 6


# ------------------------------------------------------------------ SYN, base, wraparound

def test_syn_consume_un_numero_de_secuencia():
    st = follow(seg(1, "c", 1000, flags=SYN), seg(2, "c", 1001, b"DATA"))
    assert texts(st) == [("origen", "DATA")]  # sin hueco de 1 byte


def test_primer_segmento_a_mitad_de_conexion_define_la_base():
    st = follow(seg(1, "c", 987654321, b"mid"), seg(2, "c", 987654324, b"dle"))
    assert texts(st) == [("origen", "middle")]


def test_syn_ack_del_servidor_define_su_base_en_seq_mas_uno():
    st = follow(seg(1, "s", 5000, flags=SYNACK), seg(2, "s", 5001, b"220 hi\r\n"))
    assert texts(st) == [("destino", "220 hi\r\n")]


def test_syn_retransmitido_no_rompe():
    st = follow(seg(1, "c", 1000, flags=SYN), seg(2, "c", 1000, flags=SYN), seg(3, "c", 1001, b"x"))
    assert texts(st) == [("origen", "x")]


def test_cada_sentido_tiene_su_propia_base():
    st = follow(seg(1, "c", 1_000_000_000, b"A"), seg(2, "s", 7, b"B"), seg(3, "c", 1_000_000_001, b"C"))
    assert texts(st) == [("origen", "A"), ("destino", "B"), ("origen", "C")]


def test_wraparound_de_secuencia_en_2_32():
    st = follow(seg(1, "c", 0xFFFFFFFE, b"ABCD"), seg(2, "c", 2, b"EFGH"))
    assert texts(st) == [("origen", "ABCDEFGH")]


def test_wraparound_con_syn_cerca_del_final():
    st = follow(seg(1, "c", 0xFFFFFFFF, flags=SYN), seg(2, "c", 0, b"hola"))
    assert texts(st) == [("origen", "hola")]


def test_wraparound_con_retransmision_a_traves_del_limite():
    st = follow(seg(1, "c", 0xFFFFFFFE, b"ABCD"), seg(2, "c", 0xFFFFFFFE, b"ABCD"), seg(3, "c", 0, b"CDEF"))
    assert texts(st) == [("origen", "ABCDEF")]


def test_wraparound_con_hueco():
    st = follow(seg(1, "c", 0xFFFFFFFE, b"AB"), seg(2, "c", 10, b"Z"))
    assert [c.get("gap") for c in st.chunks] == [None, 10, None]


# ------------------------------------------------------------------ MAX_GAP

def test_salto_mayor_que_max_gap_reinicia_el_sentido(monkeypatch):
    monkeypatch.setattr(S, "MAX_GAP", 100)
    st = follow(seg(1, "c", 1000, b"AAA"), seg(2, "c", 1000 + 3 + 101, b"NEW"))
    assert not any("gap" in c for c in st.chunks)  # otra conexion: no es un hueco
    assert st.origin_bytes == 6 and st.chunks[0]["text"] == "AAANEW"


def test_salto_igual_a_max_gap_sigue_siendo_hueco(monkeypatch):
    monkeypatch.setattr(S, "MAX_GAP", 100)
    st = follow(seg(1, "c", 1000, b"AAA"), seg(2, "c", 1000 + 3 + 100, b"NEW"))
    assert {"gap": 100} in st.chunks


def test_tras_el_reinicio_la_retransmision_de_lo_nuevo_se_descarta(monkeypatch):
    monkeypatch.setattr(S, "MAX_GAP", 100)
    st = follow(seg(1, "c", 1000, b"AAA"), seg(2, "c", 5000, b"NEW"), seg(3, "c", 5000, b"NEW"), seg(4, "c", 5003, b"!"))
    assert st.chunks[0]["text"] == "AAANEW!"


def test_max_gap_por_defecto_es_un_millon():
    assert S.MAX_GAP == 1_000_000
    st = follow(seg(1, "c", 0, b"A"), seg(2, "c", 500_000, b"B"))
    assert {"gap": 499_999} in st.chunks


# ------------------------------------------------------------------ paquetes que no son TCP o estan danados

def test_paquetes_no_tcp_o_danados_se_ignoran():
    udp = Packet(1.0, bytes(udp_eth(C, 40000, SRV, 80, b"udp")), None)
    arp = Packet(2.0, MAC_B + MAC_A + b"\x08\x06" + b"\x00" * 28, None)
    cut_ip = Packet(3.0, MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00", None)
    cut_tcp = Packet(4.0, seg(0, "c", 1, b"x").data[:40], None)
    junk = Packet(5.0, b"\x00\x01", None)
    empty = Packet(6.0, b"", None)
    icmp = Packet(7.0, bytes(eth_ip(dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"x")), 1)), None)
    st = follow(udp, arp, cut_ip, cut_tcp, junk, empty, icmp, seg(8, "c", 1, b"ok"))
    assert texts(st) == [("origen", "ok")]


def test_ipv6():
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"), dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
                       nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, data=dpkt.tcp.TCP(sport=5000, dport=80, seq=1, flags=PSH, data=b"v6!"))
    ip6.plen = len(bytes(ip6.data))
    raw = bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP6, data=ip6))
    sess = SimpleNamespace(src_ip="2001:db8::1", src_port=5000, dst_ip="2001:db8::2", dst_port=80)
    assert texts(follow_stream(sess, [Packet(1.0, raw, None)])) == [("origen", "v6!")]


def test_direccion_depende_de_ip_y_puerto():
    """Misma IP que el origen pero otro puerto = el otro extremo."""
    st = follow_stream(SimpleNamespace(src_ip=C, src_port=1111, dst_ip=C, dst_port=2222), [seg(1, "c", 1, b"a")])
    assert texts(st) == [("destino", "a")]  # puerto 40000 no es 1111


# ------------------------------------------------------------------ topes

def test_max_bytes_corta_con_truncated(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 10)
    st = follow(seg(1, "c", 1, b"123456"), seg(2, "c", 7, b"abcdef"), seg(3, "c", 13, b"NO SE LEE"))
    assert st.truncated is True
    assert texts(st) == [("origen", "123456abcdef")] and st.origin_bytes == 12


def test_justo_por_debajo_de_max_bytes_no_trunca(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 10)
    st = follow(seg(1, "c", 1, b"123456789"))
    assert st.truncated is False


def test_exactamente_max_bytes_trunca(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 10)
    assert follow(seg(1, "c", 1, b"1234567890"), seg(2, "c", 11, b"x")).truncated is True


def test_max_bytes_suma_los_dos_sentidos(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 10)
    st = follow(seg(1, "c", 1, b"12345"), seg(2, "s", 1, b"abcde"), seg(3, "c", 6, b"zzz"))
    assert st.truncated and st.origin_bytes == 5 and st.destination_bytes == 5


def test_max_packets_cuenta_todos_los_paquetes_vistos(monkeypatch):
    monkeypatch.setattr(S, "MAX_PACKETS", 3)
    st = follow(seg(1, "c", 1, flags=SYN), seg(2, "c", 2, b"a"), seg(3, "c", 3, b"b"), seg(4, "c", 4, b"c"))
    assert st.truncated is True and st.chunks[0]["text"] == "ab"


def test_max_packets_igual_al_total_marca_truncated(monkeypatch):
    """El tope se evalua tras cada paquete: con exactamente MAX_PACKETS paquetes tambien se marca."""
    monkeypatch.setattr(S, "MAX_PACKETS", 2)
    assert follow(seg(1, "c", 1, b"a"), seg(2, "c", 2, b"b")).truncated is True
    assert follow(seg(1, "c", 1, b"a")).truncated is False


def test_max_packets_no_lee_mas_del_iterador(monkeypatch):
    monkeypatch.setattr(S, "MAX_PACKETS", 2)
    consumed = []

    def gen():
        for i in range(10):
            consumed.append(i)
            yield seg(i, "c", i + 1, b"x")
    follow_stream(SESSION, gen())
    assert consumed == [0, 1]


def test_topes_por_defecto():
    assert (S.MAX_BYTES, S.MAX_PACKETS, S.TEXT_CHUNK) == (1_000_000, 50_000, 20_000)


# ------------------------------------------------------------------ cifrado

TLS = b"\x16\x03\x01\x00\x05hello"


def test_tls_se_marca_cifrado_y_no_devuelve_texto():
    st = follow(seg(1, "c", 1, TLS), seg(2, "s", 1, b"\x16\x03\x03\x00\x02ab"), seg(3, "c", 1 + len(TLS), b"\x17\x03\x03\x00\x01x"))
    assert st.encrypted is True
    assert all(c["text"] == "" for c in st.chunks if "from" in c)
    assert st.origin_bytes == len(TLS) + 6 and st.destination_bytes == 7
    assert [c["bytes"] for c in st.chunks] == [len(TLS), 7, 6]


@pytest.mark.parametrize("first", [0x14, 0x15, 0x16, 0x17])
def test_tls_tipos_de_registro(first):
    assert follow(seg(1, "c", 1, bytes([first, 3, 3, 0, 1, 0]))).encrypted is True


@pytest.mark.parametrize("data", [b"\x16\x03", b"\x16\x03\x09\x00", b"\x18\x03\x03", b"\x16\x02\x03", b"GET /", b"\x00\x03\x03"])
def test_no_es_tls(data):
    assert follow(seg(1, "c", 1, data)).encrypted is False


def test_cifrado_se_decide_por_el_primer_dato_aunque_venga_del_servidor():
    st = follow(seg(1, "s", 1, TLS), seg(2, "c", 1, b"plain"))
    assert st.encrypted and all(c["text"] == "" for c in st.chunks)


def test_primer_dato_en_claro_no_es_cifrado_aunque_despues_haya_tls():
    st = follow(seg(1, "c", 1, b"STARTTLS\r\n"), seg(2, "s", 1, b"220 go\r\n"), seg(3, "c", 11, TLS))
    assert not st.encrypted and any(c.get("text") for c in st.chunks)


def test_cifrado_con_hueco_conserva_el_gap():
    st = follow(seg(1, "c", 1, TLS), seg(2, "c", 100, b"\x17\x03\x03\x00\x01x"))
    assert st.encrypted and any("gap" in c for c in st.chunks)


def test_looks_tls_directo():
    assert _looks_tls(b"\x16\x03\x04") and not _looks_tls(b"") and not _looks_tls(b"\x16\x03\x05")


# ------------------------------------------------------------------ _printable

def test_printable_conserva_imprimibles_y_tab_cr_lf():
    assert _printable(b"Hola\tmundo\r\nok ~") == "Hola\tmundo\r\nok ~"


def test_printable_reemplaza_no_imprimibles():
    assert _printable(bytes([0, 1, 7, 27, 127, 128, 255]) + b"A") == "·······A"


def test_printable_limite_32_y_126():
    assert _printable(bytes([31, 32, 126, 127])) == "· ~·"


def test_printable_trunca_con_puntos_suspensivos(monkeypatch):
    monkeypatch.setattr(S, "TEXT_CHUNK", 5)
    assert _printable(b"abcdefgh") == "abcde…"
    assert _printable(b"abcde") == "abcde"
    assert _printable(b"") == ""


def test_texto_truncado_pero_bytes_completos(monkeypatch):
    monkeypatch.setattr(S, "TEXT_CHUNK", 5)
    st = follow(seg(1, "c", 1, b"0123456789"))
    assert st.chunks == [{"from": "origen", "bytes": 10, "text": "01234…"}]


def test_texto_hostil_es_solo_texto():
    evil = b"<img src=x onerror=alert(1)>\x00<script>"
    st = follow(seg(1, "c", 1, evil))
    assert st.chunks[0]["text"] == "<img src=x onerror=alert(1)>·<script>"
    assert isinstance(st.chunks[0]["text"], str)


def test_utf8_se_muestra_como_puntos():
    assert _printable("café".encode()) == "caf··"


# ------------------------------------------------------------------ analyzer.session_stream

@pytest.fixture(scope="module")
def demo():
    return analyze(DEMO, [])


def tcp_ids(a):
    return [i for i, s in enumerate(a.result.sessions) if s.protocol == "TCP"]


def test_session_stream_demo_ftp(demo):
    sid = next(i for i, s in enumerate(demo.result.sessions) if s.dst_port == 21 and s.packets > 1)
    st = session_stream(demo, sid)
    assert [(c["from"], c["text"]) for c in st.chunks] == [
        ("destino", "220 FTP ready\r\n"), ("origen", "USER admin\r\n"),
        ("destino", "331 Password required\r\n"), ("origen", "PASS hunter2\r\n")]
    assert (st.origin_bytes, st.destination_bytes) == (26, 38)


def test_session_stream_demo_http(demo):
    sid = next(i for i, s in enumerate(demo.result.sessions) if s.dst_port == 80 and s.packets > 1)
    st = session_stream(demo, sid)
    assert st.chunks[0]["text"].startswith("GET / HTTP/1.1") and st.chunks[1]["text"].startswith("HTTP/1.1 200")


def test_session_stream_sesion_tcp_sin_datos(demo):
    sid = next(i for i, s in enumerate(demo.result.sessions) if s.dst_port == 21 and s.packets == 1)
    assert session_stream(demo, sid).chunks == []


@pytest.mark.parametrize("bad", [-1, 9999, True, False, "0", None, 1.0, [0]])
def test_session_stream_id_invalido_es_indexerror(demo, bad):
    with pytest.raises(IndexError, match="no existe"):
        session_stream(demo, bad)


def test_session_stream_no_tcp_es_valueerror(demo):
    sid = next(i for i, s in enumerate(demo.result.sessions) if s.protocol != "TCP")
    with pytest.raises(ValueError, match="TCP"):
        session_stream(demo, sid)


def test_session_stream_lee_solo_los_paquetes_de_esa_sesion(demo, monkeypatch):
    seen = {}

    def spy(session, packets):
        seen["pkts"] = list(packets)
        return Stream()
    monkeypatch.setattr(analyzer_mod, "follow_stream", spy)
    sid = next(i for i, s in enumerate(demo.result.sessions) if s.dst_port == 21 and s.packets > 1)
    session_stream(demo, sid)
    from backend.domain.sessions.grouper import packet_session_key
    assert len(seen["pkts"]) == demo.result.sessions[sid].packets
    assert {packet_session_key(p) for p in seen["pkts"]} == {demo.result.sessions[sid].key}


def test_session_stream_dos_conexiones_distintas_no_se_mezclan(tmp_path):
    frames = [bytes(tcp_eth("10.0.0.1", 1111, "10.0.0.2", 80, b"AAA")), bytes(tcp_eth("10.0.0.1", 2222, "10.0.0.2", 80, b"BBB"))]
    a = analyze(write_pcap(tmp_path / "two.pcap", frames), [])
    texts_ = sorted(session_stream(a, i).chunks[0]["text"] for i in tcp_ids(a))
    assert texts_ == ["AAA", "BBB"]
