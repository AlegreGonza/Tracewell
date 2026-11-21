"""pcapng cortado: se detecta; un fin limpio entre bloques no es error."""
import io
import struct

import dpkt
import pytest

from backend.domain.pcap.reader import PcapError, capture_info, count_packets, iter_packets

PKT = bytes(range(60))


def _pad(b):
    return b + b"\x00" * (-len(b) % 4)


def block(btype, body):
    total = 12 + len(_pad(body))
    return struct.pack("<II", btype, total) + _pad(body) + struct.pack("<I", total)


def shb():
    return block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def idb():
    return block(1, struct.pack("<HHI", 1, 0, 0))


def epb(data=PKT, ts=1):
    return block(6, struct.pack("<IIIII", 0, 0, ts, len(data), len(data)) + data)


def nrb():
    return block(4, struct.pack("<HH", 0, 0))  # bloque que no es paquete


def write(tmp_path, data):
    p = tmp_path / "t.pcapng"
    p.write_bytes(data)
    return p


HEAD = shb() + idb()


def test_clean_file(tmp_path):
    assert count_packets(write(tmp_path, HEAD + epb() + epb(ts=2))) == 2


def test_dpkt_writer_clean_and_cut(tmp_path):
    buf = io.BytesIO()
    w = dpkt.pcapng.Writer(buf)
    for i in range(3):
        w.writepkt(PKT, ts=1.0 + i)
    data = buf.getvalue()
    assert count_packets(write(tmp_path, data)) == 3
    with pytest.raises(PcapError):
        count_packets(write(tmp_path, data[:-10]))


def test_header_only_no_packets(tmp_path):
    assert count_packets(write(tmp_path, HEAD)) == 0


def test_only_shb(tmp_path):
    p = write(tmp_path, shb())
    try:
        assert count_packets(p) == 0
    except PcapError:
        pass  # aceptable, pero nunca otra excepción


def test_cut_3_bytes_of_last_block(tmp_path):
    p = write(tmp_path, HEAD + epb() + epb(ts=2)[:3])
    with pytest.raises(PcapError, match="truncad"):
        count_packets(p)


@pytest.mark.parametrize("cut", [1, 2, 4, 20, 40, 60])
def test_cut_mid_packet_body(tmp_path, cut):
    full = HEAD + epb() + epb(ts=2)
    p = write(tmp_path, full[:len(full) - cut])
    with pytest.raises(PcapError, match=r"(último paquete truncado: esperado \d+ bytes, leído \d+|captura truncada: .+)"):
        count_packets(p)


def test_cut_mid_packet_does_not_deliver_corrupt_packet(tmp_path):
    full = HEAD + epb() + epb(ts=2)
    p = write(tmp_path, full[:len(full) - 20])
    got = []
    with pytest.raises(PcapError):
        for pk in iter_packets(p):
            got.append(pk)
    assert len(got) == 1


@pytest.mark.parametrize("extra", [1, 4, 7])
def test_cut_mid_block_header(tmp_path, extra):
    p = write(tmp_path, HEAD + epb() + epb(ts=2)[:extra])
    with pytest.raises(PcapError):
        count_packets(p)


def test_complete_trailing_non_packet_block_ok(tmp_path):
    assert count_packets(write(tmp_path, HEAD + epb() + nrb())) == 1


def test_trailing_non_packet_block_cut_raises(tmp_path):
    with pytest.raises(PcapError):
        count_packets(write(tmp_path, HEAD + epb() + nrb()[:-5]))


def test_capture_info_pcapng(tmp_path):
    info = capture_info(write(tmp_path, HEAD + epb()))
    assert info.format == "pcapng" and info.linktype == 1


def test_pcap_classic_clean_and_cut(tmp_path):
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for i in range(2):
        w.writepkt(PKT, ts=1.0 + i)
    data = buf.getvalue()
    p = tmp_path / "c.pcap"
    p.write_bytes(data)
    assert count_packets(p) == 2
    p.write_bytes(data[:-10])
    with pytest.raises(PcapError, match="truncado"):
        count_packets(p)
    p.write_bytes(data[:24])  # solo cabecera global: sin paquetes, sin error
    assert count_packets(p) == 0
