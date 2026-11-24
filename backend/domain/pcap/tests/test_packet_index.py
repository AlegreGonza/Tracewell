"""Tests del índice disperso de posiciones (iter_indexed / get_packet) en reader.py."""
import dpkt
import pytest

from backend.domain.pcap import reader
from backend.domain.pcap.reader import PcapError, get_packet, iter_indexed, iter_packets


@pytest.fixture(autouse=True)
def _indice_chico(monkeypatch):
    """Un punto de reanudación cada 3 paquetes y sin índices de otros tests."""
    monkeypatch.setattr(reader, "INDEX_STEP", 3)
    reader._INDEXES.clear()
    yield
    reader._INDEXES.clear()


def payloads(n, base=0):
    return [bytes([base + i]) * (20 + i) for i in range(n)]


def write(path, items, fmt="pcap"):
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f) if fmt == "pcapng" else dpkt.pcap.Writer(f)
        for i, p in enumerate(items):
            w.writepkt(p, ts=100.0 + i)
    return path


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_get_packet_igual_a_recorrer_el_archivo(tmp_path, fmt):
    p = write(tmp_path / f"a.{fmt}", payloads(20), fmt)
    esperado = list(iter_packets(p))
    for i in (19, 0, 7, 3, 4, 12, 2, 18):  # desordenados: el índice crece a saltos
        assert get_packet(p, i) == esperado[i]
    with pytest.raises(IndexError):
        get_packet(p, 20)


def test_el_indice_guarda_una_posicion_cada_step(tmp_path):
    p = write(tmp_path / "a.pcap", payloads(20))
    get_packet(p, 19)
    (index,) = reader._INDEXES.values()
    assert len(index.positions) == 7  # paquetes 0, 3, 6, 9, 12, 15 y 18


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_iter_indexed_reanuda_donde_se_guardo(tmp_path, fmt):
    p = write(tmp_path / f"a.{fmt}", payloads(10), fmt)
    todo = list(iter_indexed(p))
    assert [i for i, _, _ in todo] == list(range(10))
    i, pos, _ = todo[4]
    resto = list(iter_indexed(p, i + 1, pos))
    assert [(a, b, c) for a, b, c in resto] == todo[5:]


def test_un_archivo_que_cambia_no_reutiliza_el_indice(tmp_path):
    p = tmp_path / "a.pcap"
    write(p, payloads(10))
    assert get_packet(p, 9).data == payloads(10)[9]
    write(p, payloads(12, base=100))  # cambia el tamaño: otra firma
    assert get_packet(p, 11).data == payloads(12, base=100)[11]
    assert get_packet(p, 9).data == payloads(12, base=100)[9]


def test_cache_de_indices_acotada(tmp_path):
    for n in range(reader.MAX_INDEXES + 3):
        get_packet(write(tmp_path / f"{n}.pcap", payloads(5)), 4)
    assert len(reader._INDEXES) == reader.MAX_INDEXES


def test_archivo_truncado_los_primeros_siguen_y_los_ultimos_fallan(tmp_path):
    p = write(tmp_path / "a.pcap", payloads(20))
    p.write_bytes(p.read_bytes()[:-5])  # el último paquete queda cortado
    assert get_packet(p, 2).data == payloads(20)[2]
    assert get_packet(p, 18).data == payloads(20)[18]
    with pytest.raises(PcapError):
        get_packet(p, 19)
    assert get_packet(p, 7).data == payloads(20)[7]  # el índice parcial sigue siendo válido
