"""Tests de backend/domain/analysis/analyzer.py."""
import struct
from pathlib import Path

import dpkt
import pytest

from backend.domain.analysis.analyzer import analyze, packet_detail, session_packets
from backend.domain.pcap.hexdump import hexdump
from backend.domain.pcap.reader import PcapError, get_packet
from backend.domain.rules.engine import load_rules
from backend.domain.sessions.grouper import UnsupportedLinktype, packet_session_key
from backend.domain.sessions.tests.test_grouper import MAC_A, MAC_B, tcp_eth

ROOT = Path(__file__).resolve().parents[4]
DEMO = ROOT / "samples" / "demo.pcap"


@pytest.fixture(scope="module")
def demo():
    return analyze(DEMO, load_rules(ROOT / "rules"))


def write_pcap(path, raws, linktype=1):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=linktype)
        for i, r in enumerate(raws):
            w.writepkt(r, ts=1.0 + i)
    return path


def test_demo_alertas_y_conteos(demo):
    assert sorted(a.rule_id for a in demo.alerts) == ["dns_suspicious", "ftp_cleartext", "port_scan"]
    assert len(demo.result.sessions) == 32
    assert demo.result.non_ip == 1


def test_demo_ids_son_posicion(demo):
    for i, s in enumerate(demo.result.sessions):
        assert demo.session_id(s.key) == i
    assert demo.session_id(("nope",)) is None


def test_reglas_vacias():
    a = analyze(DEMO, [])
    assert a.alerts == [] and a.rules == []
    assert len(a.result.sessions) == 32


def test_errores_de_archivo(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(tmp_path / "no.pcap", [])
    (tmp_path / "v.pcap").write_bytes(b"")
    with pytest.raises(PcapError):
        analyze(tmp_path / "v.pcap", [])
    (tmp_path / "i.pcap").write_bytes(b"basura" * 20)
    with pytest.raises(PcapError):
        analyze(tmp_path / "i.pcap", [])


def test_linktype_no_ethernet(tmp_path):
    p = write_pcap(tmp_path / "raw.pcap", [b"\x45" + b"\x00" * 30], linktype=101)
    with pytest.raises(UnsupportedLinktype):
        analyze(p, [])


# ---- session_packets
def test_paginacion_bordes(demo):
    sid = max(range(len(demo.result.sessions)), key=lambda i: demo.result.sessions[i].packets)
    n = demo.result.sessions[sid].packets
    assert n >= 2
    allp, more = session_packets(demo, sid, 0, 1000)
    assert len(allp) == n and more is False
    idx = [p.index for p in allp]
    assert idx == sorted(idx) and len(set(idx)) == n
    assert session_packets(demo, sid, 0, n)[1] is False  # limit == n: no hay mas
    page, more = session_packets(demo, sid, 0, n - 1)
    assert len(page) == n - 1 and more is True
    page, more = session_packets(demo, sid, n - 1, 1)
    assert [p.index for p in page] == [idx[-1]] and more is False
    page, more = session_packets(demo, sid, 0, 1)
    assert [p.index for p in page] == [idx[0]] and more is True


def test_indices_pertenecen_a_la_sesion(demo):
    for sid in (0, 5, 31):
        key = demo.result.sessions[sid].key
        pk, _ = session_packets(demo, sid, 0, 1000)
        assert len(pk) == demo.result.sessions[sid].packets
        for s in pk:
            assert packet_session_key(get_packet(DEMO, s.index)) == key


def test_summary_campos(demo):
    pk, _ = session_packets(demo, 0, 0, 1)
    raw = get_packet(DEMO, pk[0].index)
    assert pk[0].caplen == len(raw.data) and pk[0].origlen == raw.origlen
    assert pk[0].snaplen_limited == raw.snaplen_limited


def test_offset_mas_alla(demo):
    assert session_packets(demo, 0, 10_000, 10) == ([], False)


@pytest.mark.parametrize("sid", [-1, 32, True, "0", None, 1.0])
def test_sesion_inexistente(demo, sid):
    with pytest.raises(IndexError):
        session_packets(demo, sid)


@pytest.mark.parametrize("off,lim", [(-1, 10), (0, 0), (0, 1001), (0, -5)])
def test_params_invalidos(demo, off, lim):
    with pytest.raises(ValueError):
        session_packets(demo, 0, off, lim)


def test_sesion_de_un_paquete(tmp_path):
    p = write_pcap(tmp_path / "u.pcap", [bytes(tcp_eth("1.1.1.1", 1, "2.2.2.2", 2))])
    pk, more = session_packets(analyze(p, []), 0)
    assert len(pk) == 1 and more is False


# ---- packet_detail
def _arp():
    return bytes(dpkt.ethernet.Ethernet(
        src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_ARP, data=dpkt.arp.ARP()))


def test_detail_tcp_y_arp(tmp_path):
    tcp = bytes(tcp_eth("10.0.0.1", 4000, "10.0.0.2", 80, b"hola"))
    a = analyze(write_pcap(tmp_path / "m.pcap", [_arp(), tcp, tcp]), [])
    d = packet_detail(a, 1)
    assert d.index == 1
    assert d.endpoints == {"src_ip": "10.0.0.1", "src_port": 4000, "dst_ip": "10.0.0.2",
                           "dst_port": 80, "protocol": "TCP"}
    assert d.session_id == 0
    assert d.hexdump and d.hexdump == hexdump(tcp)
    assert d.caplen == len(tcp) and d.origlen == len(tcp) and d.snaplen_limited is False
    arp = packet_detail(a, 0)
    assert arp.endpoints is None and arp.session_id is None
    with pytest.raises(IndexError):
        packet_detail(a, 3)


def test_detail_snaplen_limited(tmp_path):
    raw = bytes(tcp_eth("10.0.0.1", 4000, "10.0.0.2", 80, b"x" * 50))[:60]
    p = tmp_path / "s.pcap"
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1, 0, len(raw), 500) + raw)
    d = packet_detail(analyze(p, []), 0)
    assert d.snaplen_limited is True and d.origlen == 500 and d.caplen == 60


def test_detail_demo(demo):
    assert packet_detail(demo, 0).hexdump == hexdump(get_packet(DEMO, 0).data)


def test_analysis_con_sesion_sin_key_no_rompe():
    from backend.domain.analysis.analyzer import Analysis
    from backend.domain.sessions.grouper import GroupingResult, Session
    k = (("a", 1), ("b", 2), 6)
    res = GroupingResult(sessions=[
        Session("TCP", "10.0.0.1", 1, "10.0.0.2", 2),  # sin key
        Session("TCP", "10.0.0.3", 1, "10.0.0.4", 2, key=k),
    ])
    a = Analysis(path=DEMO, info=None, result=res, alerts=[], rules=[])
    assert a.session_id(None) is None  # None nunca resuelve a una sesion
    assert a.session_id(k) == 1  # id = posicion real
    assert a._ids == {k: 1}


# ---- nombres de sitio (DNS + SNI) y capas
def _names_pcap(tmp_path):
    from backend.domain.analysis.tests.test_names import client_hello, dns_response, eth4, tcp, udp
    frames = [
        eth4(udp(53, 40000, dns_response("Shop.Example.com", [("A", "93.184.216.34")])), 17, "8.8.8.8", "10.0.0.5"),
        eth4(tcp(50000, 443, client_hello("secure.test")), 6, "10.0.0.5", "93.184.216.34"),
        eth4(tcp(50001, 443, b"hola"), 6, "10.0.0.5", "93.184.216.34"),
    ]
    return write_pcap(tmp_path / "names.pcap", frames)


def test_analyze_arma_el_libro_de_nombres(tmp_path):
    a = analyze(_names_pcap(tmp_path), [])
    assert a.names.dns == {"93.184.216.34": "shop.example.com"}
    assert list(a.names.sni.values()) == ["secure.test"]
    by_port = {s.src_port: s for s in a.result.sessions if s.protocol == "TCP"}
    assert a.names.best_name(by_port[50000]) == "secure.test"  # SNI gana
    assert a.names.best_name(by_port[50001]) == "shop.example.com"  # sin SNI: DNS de la IP destino


def test_analyze_sin_nombres_libro_vacio(tmp_path):
    from backend.domain.analysis.names import NameBook
    p = write_pcap(tmp_path / "n.pcap", [bytes(tcp_eth("10.0.0.1", 4000, "10.0.0.2", 80, b"x"))])
    a = analyze(p, [])
    assert isinstance(a.names, NameBook) and a.names.dns == {} and a.names.sni == {}


def test_analysis_names_por_defecto_no_se_comparte():
    from backend.domain.analysis.analyzer import Analysis
    from backend.domain.sessions.grouper import GroupingResult
    a1 = Analysis(path=DEMO, info=None, result=GroupingResult(), alerts=[], rules=[])
    a2 = Analysis(path=DEMO, info=None, result=GroupingResult(), alerts=[], rules=[])
    assert a1.names.dns == {} and a1.names is not a2.names


def test_demo_nombres_no_rompen(demo):
    assert isinstance(demo.names.dns, dict) and isinstance(demo.names.sni, dict)


def test_packet_detail_devuelve_capas(tmp_path):
    a = analyze(_names_pcap(tmp_path), [])
    d = packet_detail(a, 1)
    assert [x["name"] for x in d.layers] == ["Ethernet", "IPv4", "TCP", "Datos"]
    assert d.layers[-1]["end"] == d.caplen
    arp = packet_detail(analyze(write_pcap(tmp_path / "a.pcap", [MAC_B + MAC_A + b"\x08\x06" + b"\x00" * 28]), []), 0)
    assert [x["name"] for x in arp.layers] == ["Ethernet", "ARP"]


def test_packet_detail_layers_por_defecto_lista_vacia():
    from backend.domain.analysis.analyzer import PacketDetail
    d = PacketDetail(0, 1.0, 1, 1, False, None, None, "")
    assert d.layers == []
    assert PacketDetail(0, 1.0, 1, 1, False, None, None, "").layers is not d.layers


def test_packet_detail_demo_capas_dentro_del_paquete(demo):
    for i in range(0, 46):
        d = packet_detail(demo, i)
        assert d.layers and all(0 <= x["start"] <= x["end"] <= d.caplen for x in d.layers)
