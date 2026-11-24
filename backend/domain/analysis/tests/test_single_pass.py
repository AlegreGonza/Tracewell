"""Tests de la pasada única de analyze y del escaneo reanudable de sesiones."""
from dataclasses import asdict
from pathlib import Path

import dpkt
import pytest

from backend.domain.analysis import session_scan
from backend.domain.analysis.analyzer import analyze, packet_detail, session_packets
from backend.domain.analysis.names import NameCollector
from backend.domain.pcap import reader
from backend.domain.pcap.reader import capture_info, iter_packets
from backend.domain.rules.engine import evaluate, load_rules
from backend.domain.sessions.grouper import group_packets, ip_layer
from backend.domain.sessions.tests.test_grouper import tcp_eth

ROOT = Path(__file__).resolve().parents[4]
DEMO = ROOT / "samples" / "demo.pcap"


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "rules")


def write_pcap(path, raws):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, r in enumerate(raws):
            w.writepkt(bytes(r), ts=1.0 + i)
    return path


def vista(book):
    """Lo comparable de un NameBook (DnsLog no es dataclass: se compara por sus filas)."""
    return book.dns, book.sni, {k: asdict(e) for k, e in book.dns_log.entries.items()}


def test_analyze_igual_a_las_pasadas_separadas(rules):
    info = capture_info(DEMO)
    a = analyze(DEMO, rules)
    assert a.result == group_packets(iter_packets(DEMO), info.linktype)
    assert a.result.sessions == group_packets(iter_packets(DEMO)).sessions
    assert a.alerts == evaluate(rules, iter_packets(DEMO), info.linktype)
    solo_nombres = NameCollector()
    for pkt in iter_packets(DEMO):
        solo_nombres.add(pkt)
    assert vista(a.names) == vista(solo_nombres.book)


def test_analyze_deja_listo_el_indice_de_get_packet(rules):
    reader._INDEXES.clear()
    analyze(DEMO, rules)
    assert len(reader._INDEXES) == 1
    assert packet_detail(analyze(DEMO, []), 45).index == 45


def test_names_add_layer_igual_a_add():
    capas = NameCollector(), NameCollector()
    for pkt in iter_packets(DEMO):
        capas[0].add(pkt)
        try:
            layer = ip_layer(pkt.data)
        except dpkt.UnpackError:
            layer = None
        capas[1].add_layer(pkt, layer)
    assert vista(capas[0].book) == vista(capas[1].book)
    assert capas[0].book.dns or capas[0].book.sni  # el demo trae nombres: no es una comparación vacía


# ---- session_packets con escaneo reanudable

@pytest.fixture
def flujo(tmp_path):
    """30 paquetes de la sesión A (puerto 1000) mezclados con 30 de otra."""
    raws = []
    for i in range(30):
        raws.append(tcp_eth("10.0.0.1", 1000, "10.0.0.2", 80, bytes([i])))
        raws.append(tcp_eth("10.0.0.3", 2000, "10.0.0.2", 80, bytes([i])))
    return write_pcap(tmp_path / "f.pcap", raws)


def todas(a, sid):
    return session_packets(a, sid, 0, 1000)[0]


def test_paginas_sucesivas_dan_lo_mismo_que_todo_junto(flujo):
    a = analyze(flujo, [])
    completo = todas(analyze(flujo, []), 0)
    assert len(completo) == 30
    paginas, off = [], 0
    while True:
        page, more = session_packets(a, 0, off, 7)
        paginas += page
        off += 7
        if not more:
            break
    assert paginas == completo


def test_las_paginas_siguientes_no_releen_el_archivo(flujo, monkeypatch):
    a = analyze(flujo, [])
    session_packets(a, 0, 0, 5)
    llamadas = []
    real = session_scan.iter_indexed
    monkeypatch.setattr(session_scan, "iter_indexed", lambda *args: llamadas.append(args) or real(*args))
    session_packets(a, 0, 0, 5)  # ya cubierta: sin lectura
    assert llamadas == []
    session_packets(a, 0, 5, 5)  # pide 6 más: reanuda, no empieza de cero
    assert len(llamadas) == 1 and llamadas[0][1] > 0 and llamadas[0][2] is not None


def test_un_archivo_cambiado_descarta_el_escaneo(flujo):
    a = analyze(flujo, [])
    assert len(todas(a, 0)) == 30
    write_pcap(flujo, [tcp_eth("10.0.0.1", 1000, "10.0.0.2", 80)] * 3 + [tcp_eth("10.0.0.3", 2000, "10.0.0.2", 80)])
    assert len(todas(a, 0)) == 3


def test_sesion_enorme_pasa_el_tope_y_relee_sin_cambiar_el_resultado(flujo, monkeypatch):
    esperado = todas(analyze(flujo, []), 0)
    monkeypatch.setattr(session_scan, "MAX_SCAN_PACKETS", 10)
    a = analyze(flujo, [])
    assert todas(a, 0) == esperado
    page, more = session_packets(a, 0, 20, 5)
    assert page == esperado[20:25] and more is True
    assert session_packets(a, 0, 25, 5) == (esperado[25:30], False)


def test_cache_de_escaneos_acotada(tmp_path):
    p = write_pcap(tmp_path / "m.pcap", [tcp_eth("10.0.0.1", 1000 + n, "10.0.0.2", 80) for n in range(8)])
    a = analyze(p, [])
    for sid in range(8):
        assert len(session_packets(a, sid, 0, 3)[0]) == 1
    assert len(a._scans._items) == session_scan.MAX_SCANS
