"""Tests de backend/domain/analysis/timeline.py y de Analysis.timeline."""
import random

import pytest

import backend.domain.analysis.timeline as T
from backend.domain.analysis.analyzer import analyze
from backend.domain.analysis.tests.test_analyzer import DEMO, MAC_A, MAC_B, tcp_eth, write_pcap
from backend.domain.analysis.timeline import MAX_BINS, Timeline, TimelineCollector
from backend.domain.pcap.reader import Packet, iter_packets


def P(ts, size=10, origlen="same"):
    return Packet(ts, b"x" * size, size if origlen == "same" else origlen)


def collect(pkts, **kw):
    c = TimelineCollector()
    for p in pkts:
        c.add(p)
    return c.result(**kw)


# ------------------------------------------------------------------ basico

def test_vacio_es_none():
    assert TimelineCollector().result() is None


def test_un_solo_paquete():
    tl = collect([P(1700000000.5, 60)])
    assert tl == Timeline(start=1700000000.0, bucket_seconds=1.0, packets=[1], bytes=[60])


def test_paquetes_en_el_mismo_segundo_se_suman():
    tl = collect([P(10.1, 5), P(10.5, 7), P(10.99, 8)])
    assert (tl.start, tl.packets, tl.bytes, tl.bucket_seconds) == (10.0, [3], [20], 1.0)


def test_segundos_con_huecos_dejan_barras_en_cero():
    tl = collect([P(10.0, 1), P(13.2, 2)])
    assert tl.start == 10.0 and tl.packets == [1, 0, 0, 1] and tl.bytes == [1, 0, 0, 2]


def test_orden_de_llegada_no_importa():
    a = collect([P(10.0, 1), P(12.0, 2), P(11.0, 3)])
    b = collect([P(12.0, 2), P(11.0, 3), P(10.0, 1)])
    assert a == b and a.packets == [1, 1, 1] and a.bytes == [1, 3, 2]


def test_bytes_usan_origlen_si_existe_y_len_si_no():
    tl = collect([P(1.0, 10, origlen=1500), P(1.2, 10, origlen=None), P(1.4, 10)])
    assert tl.bytes == [1500 + 10 + 10]
    assert collect([P(1.0, 10, origlen=0)]).bytes == [0]  # origlen 0 es un valor valido, no cae en len


def test_paquete_sin_datos():
    assert collect([Packet(1.0, b"", None)]).bytes == [0]


def test_timeline_es_inmutable_y_listas_independientes():
    tl = collect([P(1.0)])
    with pytest.raises(Exception):
        tl.start = 5
    assert tl.packets is not tl.bytes


# ------------------------------------------------------------------ marcas de tiempo raras

def test_timestamps_negativos_usan_piso():
    tl = collect([P(-0.5, 1), P(-1.5, 1), P(0.5, 1)])
    assert tl.start == -2.0 and tl.packets == [1, 1, 1]


def test_timestamps_flotantes_en_el_limite_del_segundo():
    tl = collect([P(9.999999, 1), P(10.0, 1)])
    assert tl.start == 9.0 and tl.packets == [1, 1]


def test_timestamp_cero_y_enorme():
    assert collect([P(0.0, 1)]).start == 0.0
    big = collect([P(4e9 + 0.5, 1)])
    assert big.start == 4e9 and big.packets == [1]


# ------------------------------------------------------------------ MAX_BINS

def test_hasta_120_segundos_una_barra_por_segundo():
    tl = collect([P(float(i)) for i in range(120)])
    assert len(tl.packets) == 120 and tl.bucket_seconds == 1.0


def test_121_segundos_se_agrupa_de_a_dos():
    tl = collect([P(float(i)) for i in range(121)])
    assert tl.bucket_seconds == 2.0 and len(tl.packets) == 61 and sum(tl.packets) == 121


@pytest.mark.parametrize("seconds", [1, 2, 119, 120, 121, 240, 241, 1000, 3600, 86400, 99999])
def test_barras_acotadas_total_conservado_y_fase_correcta(seconds):
    pkts = [P(float(i), 3, origlen=100 + i) for i in range(seconds)]
    tl = collect(pkts)
    assert len(tl.packets) <= MAX_BINS and len(tl.packets) == len(tl.bytes)
    assert sum(tl.packets) == seconds
    assert sum(tl.bytes) == sum(100 + i for i in range(seconds))
    # cada barra cubre bucket_seconds: el ultimo paquete cae dentro de la ultima barra
    assert tl.start + len(tl.packets) * tl.bucket_seconds > seconds - 1
    assert tl.start <= 0


def test_max_bins_pequeno_por_parametro():
    c = TimelineCollector()
    for i in range(100):
        c.add(P(float(i)))
    tl = c.result(max_bins=10)
    assert len(tl.packets) == 10 and tl.bucket_seconds == 10.0 and tl.packets == [10] * 10
    assert len(c.result(max_bins=1).packets) == 1 and c.result(max_bins=1).packets == [100]
    assert c.result(max_bins=1000).bucket_seconds == 1.0


def test_result_no_modifica_el_estado():
    c = TimelineCollector()
    for i in range(300):
        c.add(P(float(i)))
    assert c.result() == c.result()
    c.add(P(300.0))
    assert sum(c.result().packets) == 301


def test_paquetes_dispersos_muy_lejos_entre_si():
    tl = collect([P(0.0, 1), P(1e7, 1)])
    assert len(tl.packets) <= MAX_BINS and sum(tl.packets) == 2
    assert tl.packets[0] == 1 and tl.packets[-1] == 1


# ------------------------------------------------------------------ coarsen

def test_coarsen_con_max_keys_chico_conserva_totales(monkeypatch):
    monkeypatch.setattr(T, "MAX_KEYS", 10)
    c = TimelineCollector()
    n = 1000
    for i in range(n):
        c.add(P(float(i), 5, origlen=7))
    assert len(c._packets) <= 10 + 1 and c._g > 1.0
    tl = c.result()
    assert sum(tl.packets) == n and sum(tl.bytes) == 7 * n
    assert len(tl.packets) <= MAX_BINS
    assert tl.start == 0.0
    # un reagrupado de bins vuelve a conservar el total
    assert sum(c.result(max_bins=3).packets) == n


def test_coarsen_g_es_potencia_de_dos_y_start_alineado(monkeypatch):
    monkeypatch.setattr(T, "MAX_KEYS", 4)
    c = TimelineCollector()
    for i in range(100):
        c.add(P(1000.0 + i))
    assert c._g in (2.0, 4.0, 8.0, 16.0, 32.0, 64.0)
    tl = c.result()
    assert tl.start % c._g == 0 and tl.start <= 1000.0 < tl.start + tl.bucket_seconds


def test_coarsen_equivale_a_agrupar_directo(monkeypatch):
    """floor(ts/2g) == floor(floor(ts/g)/2): el resultado con coarsen es el mismo que sin el."""
    rnd = random.Random(42)
    pkts = [P(rnd.uniform(-500, 500), rnd.randint(1, 1500)) for _ in range(600)]
    plain = collect(pkts, max_bins=1000)
    monkeypatch.setattr(T, "MAX_KEYS", 8)
    c = TimelineCollector()
    for p in pkts:
        c.add(p)
    assert c._g > 1.0
    g = c._g
    # agrupacion directa con el mismo g
    direct = {}
    for p in pkts:
        direct[int(p.ts // g)] = direct.get(int(p.ts // g), 0) + 1
    assert c._packets == direct
    assert sum(plain.packets) == sum(c.result(max_bins=1000).packets) == 600


def test_coarsen_negativos(monkeypatch):
    monkeypatch.setattr(T, "MAX_KEYS", 5)
    c = TimelineCollector()
    for i in range(-50, 50):
        c.add(P(float(i)))
    tl = c.result()
    assert sum(tl.packets) == 100 and tl.start <= -50


def test_tres_dias_un_paquete_cada_7s_da_120_barras_y_mismo_total():
    n = 3 * 86400 // 7
    c = TimelineCollector()
    for i in range(n):
        c.add(P(1_700_000_000.0 + i * 7, 100))
    tl = c.result()
    assert len(tl.packets) == 120
    assert sum(tl.packets) == n and sum(tl.bytes) == 100 * n
    assert len(c._packets) <= T.MAX_KEYS  # memoria acotada
    assert tl.start <= 1_700_000_000.0
    assert tl.start + len(tl.packets) * tl.bucket_seconds > 1_700_000_000.0 + (n - 1) * 7


def test_memoria_acotada_con_paquetes_muy_espaciados():
    c = TimelineCollector()
    for i in range(T.MAX_KEYS * 3):
        c.add(P(i * 10.0))
    assert len(c._packets) <= T.MAX_KEYS
    assert sum(c.result().packets) == T.MAX_KEYS * 3


# ------------------------------------------------------------------ Analysis.timeline

def test_analyze_timeline_suma_todos_los_paquetes_del_archivo():
    a = analyze(DEMO, [])
    total = sum(1 for _ in iter_packets(DEMO))
    assert a.timeline is not None and sum(a.timeline.packets) == total == 46
    assert len(a.timeline.packets) <= MAX_BINS


def test_analyze_timeline_incluye_paquetes_no_ip(tmp_path):
    frames = [bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"x")),
              MAC_B + MAC_A + b"\x08\x06" + b"\x00" * 28,  # ARP
              MAC_B + MAC_A + b"\x08\x00" + b"E\x00\x00",  # IP cortada
              b"\x00" * 5]
    a = analyze(write_pcap(tmp_path / "m.pcap", frames), [])
    assert sum(a.timeline.packets) == 4
    assert a.result.non_ip + a.result.malformed >= 3


def test_analyze_timeline_bytes_son_los_de_la_red(tmp_path):
    raw = bytes(tcp_eth("10.0.0.1", 1, "10.0.0.2", 2, b"x" * 50))
    a = analyze(write_pcap(tmp_path / "b.pcap", [raw, raw]), [])
    assert sum(a.timeline.bytes) == 2 * len(raw)
    assert a.timeline.packets == [1, 1] and a.timeline.start == 1.0 and a.timeline.bucket_seconds == 1.0


def test_analyze_captura_sin_paquetes_timeline_none(tmp_path):
    a = analyze(write_pcap(tmp_path / "e.pcap", []), [])
    assert a.timeline is None
    assert a.names.dns == {}


def test_analysis_timeline_por_defecto_none():
    from backend.domain.analysis.analyzer import Analysis
    from backend.domain.sessions.grouper import GroupingResult
    assert Analysis(path=DEMO, info=None, result=GroupingResult(), alerts=[], rules=[]).timeline is None
