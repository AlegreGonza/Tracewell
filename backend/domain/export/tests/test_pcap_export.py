"""Tests de backend/domain/export/pcap_export.py y analyzer.packets_of_sessions."""
import io

import dpkt
import pytest

import backend.domain.analysis.analyzer as analyzer_mod
import backend.domain.export.pcap_export as PE
from backend.domain.analysis.analyzer import analyze, packets_of_sessions
from backend.domain.analysis.tests.test_analyzer import DEMO, write_pcap
from backend.domain.export.pcap_export import PcapFile, build_pcap
from backend.domain.pcap.reader import Packet, iter_packets
from backend.domain.sessions.grouper import Session, packet_session_key
from backend.domain.sessions.tests.test_grouper import tcp_eth, udp_eth


def pk(ts, data):
    return Packet(ts, data, len(data))


def read_back(data):
    r = dpkt.pcap.Reader(io.BytesIO(data))
    return r.datalink(), list(r)


FRAMES = [bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"abc")), bytes(udp_eth("10.0.0.3", 5, "10.0.0.4", 6)), b"\x00" * 20]


# ------------------------------------------------------------------ build_pcap

def test_ida_y_vuelta_con_dpkt():
    pkts = [pk(1700000000.25, FRAMES[0]), pk(1700000001.5, FRAMES[1]), pk(1700000002.0, FRAMES[2])]
    out = build_pcap(pkts, linktype=1)
    assert isinstance(out, PcapFile) and out.packets == 3 and out.truncated is False
    link, got = read_back(out.data)
    assert link == 1
    assert [d for _, d in got] == FRAMES
    assert [ts for ts, _ in got] == pytest.approx([1700000000.25, 1700000001.5, 1700000002.0], abs=1e-6)


def test_vacio_es_un_pcap_valido_con_cero_paquetes():
    out = build_pcap([])
    assert out.packets == 0 and out.truncated is False
    assert out.data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") and len(out.data) == 24
    assert read_back(out.data) == (1, [])


def test_acepta_generadores_y_conserva_el_orden():
    out = build_pcap((pk(float(i), bytes([i]) * 20) for i in (5, 3, 9)))
    assert [d[0] for _, d in read_back(out.data)[1]] == [5, 3, 9]


@pytest.mark.parametrize("linktype", [1, 101, 113, 228])
def test_linktype_se_conserva(linktype):
    assert read_back(build_pcap([pk(1.0, b"x" * 20)], linktype=linktype).data)[0] == linktype


def test_linktype_por_defecto_es_ethernet():
    assert read_back(build_pcap([pk(1.0, b"x" * 20)]).data)[0] == 1


def test_paquete_vacio_y_timestamps_extremos():
    got = read_back(build_pcap([pk(0.0, b""), pk(4_000_000_000.123456, b"zz")]).data)[1]
    assert [d for _, d in got] == [b"", b"zz"]
    assert got[1][0] == pytest.approx(4_000_000_000.123456, abs=1e-3)


def test_paquete_grande_no_se_recorta():
    big = b"\xab" * 70_000
    assert read_back(build_pcap([pk(1.0, big)]).data)[1][0][1] == big


def test_el_largo_original_de_un_recortado_no_se_conserva_pero_los_datos_si():
    p = Packet(1.0, b"x" * 60, 1500)
    assert p.snaplen_limited
    assert read_back(build_pcap([p]).data)[1][0][1] == b"x" * 60


def test_max_packets_trunca(monkeypatch):
    monkeypatch.setattr(PE, "MAX_PACKETS", 3)
    out = build_pcap(pk(float(i), b"x" * 20) for i in range(10))
    assert out.truncated is True and out.packets == 3 and len(read_back(out.data)[1]) == 3


def test_exactamente_max_packets_no_trunca(monkeypatch):
    monkeypatch.setattr(PE, "MAX_PACKETS", 3)
    out = build_pcap(pk(float(i), b"x" * 20) for i in range(3))
    assert out.truncated is False and out.packets == 3


def test_max_packets_no_consume_mas_del_iterador(monkeypatch):
    monkeypatch.setattr(PE, "MAX_PACKETS", 2)
    consumed = []

    def gen():
        for i in range(10):
            consumed.append(i)
            yield pk(float(i), b"x" * 20)
    build_pcap(gen())
    assert consumed == [0, 1, 2]  # lee uno de mas para saber que hay mas


def test_max_bytes_trunca_y_el_archivo_queda_valido(monkeypatch):
    monkeypatch.setattr(PE, "MAX_BYTES", 24 + 3 * (16 + 100))
    out = build_pcap(pk(float(i), b"x" * 100) for i in range(10))
    assert out.truncated is True and 1 <= out.packets < 10
    assert len(out.data) <= 24 + 3 * (16 + 100) + 100
    assert len(read_back(out.data)[1]) == out.packets


def test_max_bytes_un_primer_paquete_demasiado_grande(monkeypatch):
    monkeypatch.setattr(PE, "MAX_BYTES", 50)
    out = build_pcap([pk(1.0, b"x" * 500)])
    assert out.packets == 0 and out.truncated is True
    assert read_back(out.data) == (1, [])


def test_pcapfile_es_inmutable():
    out = build_pcap([])
    with pytest.raises(Exception):
        out.packets = 5


def test_topes_por_defecto():
    assert (PE.MAX_PACKETS, PE.MAX_BYTES) == (500_000, 100_000_000)


# ------------------------------------------------------------------ packets_of_sessions

@pytest.fixture(scope="module")
def demo():
    return analyze(DEMO, [])


def test_una_sesion_da_exactamente_sus_paquetes_en_orden(demo):
    s = demo.result.sessions[5]
    got = list(packets_of_sessions(demo, [s]))
    assert len(got) == s.packets == 6
    assert all(packet_session_key(p) == s.key for p in got)
    assert [p.ts for p in got] == sorted(p.ts for p in got)


def test_varias_sesiones_en_orden_de_captura_y_una_sola_pasada(demo, monkeypatch):
    opened = []
    real = analyzer_mod.iter_packets
    monkeypatch.setattr(analyzer_mod, "iter_packets", lambda p: opened.append(p) or real(p))
    sess = [demo.result.sessions[7], demo.result.sessions[5], demo.result.sessions[5]]  # desordenadas y repetidas
    got = list(packets_of_sessions(demo, sess))
    assert len(opened) == 1
    assert len(got) == demo.result.sessions[5].packets + demo.result.sessions[7].packets
    all_ts = [p.ts for p in iter_packets(DEMO)]
    assert [p.ts for p in got] == [t for t in all_ts if t in {p.ts for p in got}]


def test_sin_sesiones_no_lee_el_archivo(demo, monkeypatch):
    def boom(path):
        raise AssertionError("no debia leer el archivo")
    monkeypatch.setattr(analyzer_mod, "iter_packets", boom)
    assert list(packets_of_sessions(demo, [])) == []


def test_sesiones_sin_clave_se_ignoran(demo, monkeypatch):
    monkeypatch.setattr(analyzer_mod, "iter_packets", lambda p: (_ for _ in ()).throw(AssertionError("no leer")))
    assert list(packets_of_sessions(demo, [Session("TCP", "a", 1, "b", 2)])) == []


def test_clave_valida_mas_sesion_sin_clave(demo):
    s = demo.result.sessions[5]
    assert len(list(packets_of_sessions(demo, [Session("TCP", "a", 1, "b", 2), s]))) == 6


def test_todas_las_sesiones_cubren_los_paquetes_con_sesion(demo):
    got = list(packets_of_sessions(demo, demo.result.sessions))
    assert len(got) == sum(s.packets for s in demo.result.sessions)


def test_es_un_generador_perezoso(demo):
    g = packets_of_sessions(demo, [demo.result.sessions[5]])
    assert iter(g) is g
    assert next(g).ts is not None


def test_pcap_de_una_sesion_del_demo_se_lee_con_dpkt(demo):
    s = demo.result.sessions[5]
    out = build_pcap(packets_of_sessions(demo, [s]), linktype=demo.info.linktype)
    assert out.packets == 6
    link, got = read_back(out.data)
    assert link == 1 and len(got) == 6


def test_captura_propia_dos_conexiones(tmp_path):
    a_frames = [bytes(tcp_eth("10.0.0.1", 1111, "10.0.0.2", 80, b"A")), bytes(tcp_eth("10.0.0.1", 2222, "10.0.0.2", 80, b"B")),
                bytes(tcp_eth("10.0.0.1", 1111, "10.0.0.2", 80, b"C"))]
    a = analyze(write_pcap(tmp_path / "x.pcap", a_frames), [])
    first = next(s for s in a.result.sessions if s.src_port == 1111)
    got = list(packets_of_sessions(a, [first]))
    assert [p.data for p in got] == [a_frames[0], a_frames[2]]
