"""Un largo de paquete falso (~4 GB) no reserva memoria: se lee solo lo que hay."""
import struct
import tracemalloc

import pytest

from backend.domain.pcap.reader import PcapError, iter_packets
from backend.domain.pcap.tests.test_reader_pcapng_truncated import HEAD

FAKE = 0xF0000000  # ~4 GB
LIMIT_MB = 50


def _peak_mb(path):
    tracemalloc.start()
    try:
        with pytest.raises(PcapError):
            list(iter_packets(path))
        return tracemalloc.get_traced_memory()[1] / 1e6
    finally:
        tracemalloc.stop()


def test_pcap_fake_caplen_bounded(tmp_path):
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFFFFFF, 1)
    ph = struct.pack("<IIII", 1, 0, FAKE, FAKE)
    p = tmp_path / "big.pcap"
    p.write_bytes(gh + ph + b"\x00" * 100)
    assert _peak_mb(p) < LIMIT_MB


def test_pcapng_fake_block_length_bounded(tmp_path):
    fake_block = struct.pack("<II", 6, FAKE) + b"\x00" * 100
    p = tmp_path / "big.pcapng"
    p.write_bytes(HEAD + fake_block)
    assert _peak_mb(p) < LIMIT_MB
