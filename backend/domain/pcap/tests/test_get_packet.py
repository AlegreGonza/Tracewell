"""Tests de get_packet en backend/domain/pcap/reader.py."""
import struct

import dpkt
import pytest

from backend.domain.pcap.reader import Packet, PcapError, get_packet


def write_pcap(path, payloads):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, p in enumerate(payloads):
            w.writepkt(p, ts=100.0 + i)
    return path


PAYLOADS = [bytes([i]) * (10 + i) for i in range(5)]


@pytest.fixture
def pcap(tmp_path):
    return write_pcap(tmp_path / "a.pcap", PAYLOADS)


@pytest.mark.parametrize("i", [0, 2, 4])
def test_indices_validos(pcap, i):
    p = get_packet(pcap, i)
    assert isinstance(p, Packet)
    assert p.data == PAYLOADS[i]
    assert p.ts == pytest.approx(100.0 + i)
    assert p.origlen == len(PAYLOADS[i])


def test_indice_igual_a_cantidad(pcap):
    with pytest.raises(IndexError):
        get_packet(pcap, 5)


@pytest.mark.parametrize("bad", [-1, True, "1", 1.5, None])
def test_indice_invalido(pcap, bad):
    with pytest.raises(IndexError):
        get_packet(pcap, bad)


def test_archivo_vacio(tmp_path):
    p = tmp_path / "v.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapError):
        get_packet(p, 0)


def test_archivo_invalido(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"esto no es un pcap, para nada" * 3)
    with pytest.raises(PcapError):
        get_packet(p, 0)


def test_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        get_packet(tmp_path / "no.pcap", 0)


def test_pcapng(tmp_path):
    p = tmp_path / "a.pcapng"
    with open(p, "wb") as f:
        w = dpkt.pcapng.Writer(f)
        w.writepkt(b"\x01" * 20, ts=5.0)
        w.writepkt(b"\x02" * 30, ts=6.0)
    pk = get_packet(p, 1)
    assert pk.data == b"\x02" * 30
    assert pk.origlen is None


def test_origlen_mayor_que_caplen(tmp_path):
    p = tmp_path / "s.pcap"
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1, 0, 10, 1500) + b"\x07" * 10)
    pk = get_packet(p, 0)
    assert (len(pk.data), pk.origlen) == (10, 1500)
    assert pk.snaplen_limited


def test_ultimo_paquete_truncado(tmp_path, pcap):
    t = tmp_path / "t.pcap"
    t.write_bytes(pcap.read_bytes()[:-5])
    assert get_packet(t, 0).data == PAYLOADS[0]
    with pytest.raises(PcapError):
        get_packet(t, 4)
