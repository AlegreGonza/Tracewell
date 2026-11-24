"""Soporte del fuzz a nivel de archivo: semillas pcap/pcapng, mutaciones y la entrada completa."""
from __future__ import annotations

import itertools
import random
import struct
import tempfile
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from backend.domain.analysis.analyzer import analyze, packet_detail, session_packets, session_stream
from backend.domain.pcap.reader import PcapError
from backend.domain.rules.engine import load_rules
from backend.domain.sessions.grouper import UnsupportedLinktype

ROOT = Path(__file__).resolve().parents[4]

# Lo único que un archivo hostil puede provocar: rechazo limpio (la API lo traduce a 4xx).
EXPECTED = (PcapError, UnsupportedLinktype)

_names = itertools.count()
_RULES = None


def rules():
    global _RULES
    if _RULES is None:
        _RULES = load_rules(ROOT / "rules")
    return _RULES


# ------------------------------------------------------------------ semillas

def _eth_ipv4_tcp(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + tcp
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip


def small_frames() -> List[bytes]:
    """Ocho paquetes: un HTTP, un FTP, un DNS y cinco SYN a puertos distintos."""
    frames = [_eth_ipv4_tcp(40000, 80, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
              _eth_ipv4_tcp(40001, 21, b"USER bob\r\n"),
              _eth_ipv4_tcp(40001, 21, b"PASS secreto\r\n")]
    udp = struct.pack("!HHHH", 5353, 53, 8 + 29, 0) + bytes(29)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 2, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8])) + udp
    frames.append(b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00" + ip)
    frames += [_eth_ipv4_tcp(41000, 1000 + i, b"", flags=0x02) for i in range(4)]
    return frames


def build_pcap(frames: List[bytes], endian: str = "<", magic: bytes = b"\xd4\xc3\xb2\xa1") -> bytes:
    out = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack(endian + "IIII", 1_700_000_000 + i, 0, len(f), len(f)) + f
    return out


def _block(kind: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", kind, total) + body + struct.pack("<I", total)


def build_pcapng(frames: List[bytes]) -> bytes:
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _block(1, struct.pack("<HHI", 1, 0, 65535))
    for i, f in enumerate(frames):
        pad = (-len(f)) % 4
        ts = 1_700_000_000_000_000 + i * 1000
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(f), len(f)) + f + b"\x00" * pad
        out += _block(6, body)
    return out


def big_pcap(count: int = 9000) -> bytes:
    """Más de dos puntos de reanudación del índice (uno cada 4096 paquetes)."""
    frames = small_frames()
    return build_pcap([frames[i % len(frames)] for i in range(count)])


def seeds() -> dict:
    frames = small_frames()
    demo = (ROOT / "samples" / "demo.pcap").read_bytes()
    return {
        "pcap_le": build_pcap(frames),
        "pcap_be": build_pcap(frames, ">", b"\xa1\xb2\xc3\xd4"),
        "pcap_ns": build_pcap(frames, "<", b"\x4d\x3c\xb2\xa1"),
        "pcapng": build_pcapng(frames),
        "demo": demo,
    }


# ----------------------------------------------------------------- mutaciones

def mutate(rng: random.Random, data: bytes) -> bytes:
    """Varias mutaciones al azar: volteos, relleno 0x00/0xFF, cortes, duplicados e inserciones."""
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        if not b:
            break
        op = rng.randrange(6)
        i = rng.randrange(len(b))
        if op == 0:
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            b[i:i + rng.randint(1, 8)] = bytes([rng.choice((0x00, 0xFF, 0x7F, 0x80))]) * rng.randint(1, 8)
        elif op == 2:
            del b[i:i + rng.randint(1, 64)]
        elif op == 3:
            chunk = b[i:i + rng.randint(1, 64)]
            b[i:i] = chunk
        elif op == 4:
            b[i:i] = rng.randbytes(rng.randint(1, 16))
        else:
            del b[i:]
    return bytes(b)


def header_variants(data: bytes, span: int = 24 + 16 * 2) -> Iterator[bytes]:
    """Cada byte de las cabeceras (globales y de los primeros paquetes) con valores extremos."""
    for i in range(min(span, len(data))):
        for v in (0x00, 0xFF, 0x7F, 0x80):
            if data[i] != v:
                yield data[:i] + bytes([v]) + data[i + 1:]


def truncations(data: bytes, rng: random.Random, dense: int = 64, extra: int = 60) -> Iterator[bytes]:
    """Cortes en cada byte de las primeras cabeceras y en posiciones al azar del resto."""
    offsets = set(range(0, min(dense, len(data))))
    offsets.update(rng.randrange(len(data)) for _ in range(extra))
    for n in sorted(offsets):
        yield data[:n]


# ------------------------------------------------------------- entrada completa

def analyze_bytes(data: bytes, workdir: Optional[Path] = None) -> str:
    """Escribe `data` como archivo y corre todo el camino; devuelve 'ok' o el rechazo limpio.

    Un archivo NUEVO por entrada: la caché del lector se indexa por (ruta, tamaño, mtime) y
    reescribir la misma ruta con igual tamaño dentro de un mismo tick del reloj la confundiría.
    """
    base = workdir or Path(tempfile.gettempdir())
    path = base / f"fuzz-{next(_names)}.pcap"
    path.write_bytes(data)
    try:
        return _run_all(path)
    except EXPECTED as exc:
        return type(exc).__name__
    finally:
        path.unlink(missing_ok=True)


def _run_all(path: Path) -> str:
    a = analyze(path, rules())
    _query(lambda: session_packets(a, 0) if a.result.sessions else None)
    _query(lambda: session_stream(a, 0) if a.result.sessions and a.result.sessions[0].protocol == "TCP" else None)
    for index in (0, 3, 7, 4095, 4096, 8500):  # cruzan los puntos de reanudación del índice
        _query(lambda i=index: packet_detail(a, i))
    return "ok"


def _query(fn: Callable[[], object]) -> None:
    """Consultas posteriores al análisis; IndexError es la respuesta correcta a un índice inexistente."""
    try:
        fn()
    except IndexError:
        pass
