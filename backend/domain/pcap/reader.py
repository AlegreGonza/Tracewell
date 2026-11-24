"""Lectura de capturas .pcap / .pcapng en streaming."""
from __future__ import annotations

import struct
import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, NamedTuple, Optional, Tuple, Union

import dpkt

from backend.domain.files import require_regular_file

# Los primeros 4 bytes del archivo identifican el formato ("magic number")
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Magic de pcap clásico -> endianness de las cabeceras
_PCAP_ENDIAN = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xa1\xb2\x3c\x4d": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\x4d\x3c\xb2\xa1": "<",
}
_PKT_HDR_LEN = 16  # ts_sec, ts_usec, caplen, origlen: 4 bytes cada uno


class PcapError(ValueError):
    """Archivo inválido, vacío o truncado."""


class Packet(NamedTuple):
    ts: float
    data: bytes
    # Largo original en el cable
    origlen: Optional[int]

    @property
    def snaplen_limited(self) -> bool:
        """True si la captura guardó MENOS bytes que los que tenía el paquete."""
        return self.origlen is not None and len(self.data) < self.origlen


@dataclass(frozen=True)
class CaptureInfo:
    """Datos de la cabecera GLOBAL (una sola vez por archivo)."""

    format: str  # "pcap" o "pcapng"
    linktype: int  # 1 = Ethernet
    snaplen: Optional[int]  # máx. bytes guardados por paquete


def _file_size(fh) -> int:
    """Tamaño total del archivo (sin mover la posición actual)."""
    pos = fh.tell()
    size = fh.seek(0, 2)
    fh.seek(pos)
    return size


def _bounded_read(fh, size: int, pos: int, n: int) -> bytes:
    """Lee `n` bytes como mucho lo que queda desde `pos`: un largo falso no reserva memoria."""
    if n < 0:
        return fh.read(n)
    return fh.read(min(n, max(size - pos, 0)))


class _TapFile:
    """Envuelve el archivo y "espía" las lecturas que hace dpkt."""

    def __init__(self, fh):
        self._fh = fh
        self._size = _file_size(fh)
        self._state = "global"  # global -> (header -> payload)*
        self._hdr_struct: Optional[struct.Struct] = None
        self.last_origlen: Optional[int] = None
        self.short_read: Optional[tuple[int, int]] = None  # (esperado, leído)
        self.pos = 0  # bytes leídos desde el inicio: dónde empieza lo que sigue

    def jump(self, pos: int) -> None:
        """Salta a la cabecera de un paquete (una posición guardada antes)."""
        self._fh.seek(pos)
        self.pos = pos
        self._state = "header"

    def _on_global(self, data: bytes) -> None:
        """Cabecera global: de su magic sale el endianness de las de paquete."""
        endian = _PCAP_ENDIAN.get(data[:4])
        self._hdr_struct = struct.Struct(endian + "IIII") if endian else None

    def _on_header(self, n: int, data: bytes) -> None:
        """Cabecera de paquete (16 bytes): de ahí sale el origlen que dpkt tira."""
        if self._hdr_struct and n == _PKT_HDR_LEN and len(data) == _PKT_HDR_LEN:
            self.last_origlen = self._hdr_struct.unpack(data)[3]
        else:
            self.last_origlen = None

    def _on_payload(self, n: int, data: bytes) -> None:
        """Payload: si llegaron menos bytes de los pedidos, el archivo se cortó."""
        if 0 <= n and len(data) < n:
            self.short_read = (n, len(data))

    def read(self, n=-1):
        data = _bounded_read(self._fh, self._size, self.pos, n)
        self.pos += len(data)
        if self._state == "global":
            self._on_global(data)
            self._state = "header"
        elif self._state == "header":
            self._on_header(n, data)
            self._state = "payload"
        else:
            self._on_payload(n, data)
            self._state = "header"
        return data

    def __getattr__(self, name):  # seek, fileno, name, close...
        return getattr(self._fh, name)


class _BlockTap:
    """Espía las lecturas de dpkt en un pcapng para detectar un archivo cortado."""

    last_origlen: Optional[int] = None  # pcapng no expone el largo original

    def __init__(self, fh):
        self._fh = fh
        self._size = _file_size(fh)
        self.short_read: Optional[tuple[int, int]] = None  # (esperado, leído)
        self._armed = False
        self._expect_header = True
        self.pos = 0  # bytes leídos desde el inicio: dónde empieza lo que sigue

    def jump(self, pos: int) -> None:
        """Salta al inicio de un bloque (una posición guardada antes)."""
        self._fh.seek(pos)
        self.pos = pos
        self._expect_header = True

    def arm(self) -> None:
        """Empieza a vigilar: las lecturas del constructor de dpkt no siguen el patrón por bloque."""
        self._armed = True
        self._expect_header = True

    def read(self, n=-1):
        data = _bounded_read(self._fh, self._size, self.pos, n)
        self.pos += len(data)
        if self._armed:
            self._check(n, data)
        return data

    def _check(self, n: int, data: bytes) -> None:
        clean_eof = self._expect_header and not data
        if n > 0 and len(data) < n and not clean_eof:
            self.short_read = (n, len(data))
        self._expect_header = not self._expect_header

    def __getattr__(self, name):
        return getattr(self._fh, name)


def _read_magic(fh) -> bytes:
    """Lee el magic number (4 bytes) y rebobina; falla si el archivo es muy corto."""
    magic = fh.read(4)
    if len(magic) < 4:
        raise PcapError("archivo vacío o demasiado corto para ser una captura")
    fh.seek(0)
    return magic


def _make_reader(fh, magic: bytes):
    """(formato, lector dpkt, tap) según el magic; cada formato tiene su propio tap."""
    try:
        if magic == _PCAPNG_MAGIC:
            block_tap = _BlockTap(fh)
            reader = dpkt.pcapng.Reader(block_tap)
            block_tap.arm()
            return "pcapng", reader, block_tap
        tap = _TapFile(fh)
        return "pcap", dpkt.pcap.Reader(tap), tap
    except (ValueError, dpkt.UnpackError) as exc:  # NeedData es una UnpackError
        raise PcapError(f"cabecera inválida: {exc}") from exc


@contextmanager
def _open(path):
    """Abre el archivo, detecta el formato y devuelve (info, reader, tap)."""
    with open(require_regular_file(path), "rb") as fh:  # FileNotFoundError se propaga tal cual
        fmt, reader, tap = _make_reader(fh, _read_magic(fh))
        info = CaptureInfo(
            format=fmt,
            linktype=reader.datalink(),
            snaplen=getattr(reader, "snaplen", None),
        )
        yield info, reader, tap


def capture_info(path) -> CaptureInfo:
    """Lee solo la cabecera global, sin recorrer los paquetes."""
    with _open(path) as (info, _, _tap):
        return info


def _raise_if_truncated(tap: Optional[Union[_TapFile, _BlockTap]]) -> None:
    """Falla si el tap vio un payload cortado (paquete corrupto)."""
    if tap is not None and tap.short_read is not None:
        esperado, leido = tap.short_read
        raise PcapError(f"último paquete truncado: esperado {esperado} bytes, leído {leido}")


def iter_indexed(path, start_index: int = 0, start_pos: Optional[int] = None) -> Iterator[Tuple[int, int, Packet]]:
    """(índice, posición del siguiente paquete, Packet); puede arrancar en una posición guardada."""
    with _open(path) as (_, reader, tap):
        if start_pos is not None:
            tap.jump(start_pos)
        index = start_index
        try:
            for ts, buf in reader:
                # Lo escuchamos ANTES de entregarlo
                _raise_if_truncated(tap)
                origlen = tap.last_origlen if tap is not None else None
                # float(): con magic de nanosegundos dpkt entrega Decimal, y mezclar Decimal
                yield index, tap.pos, Packet(float(ts), buf, origlen)
                index += 1
            # dpkt termina en silencio si el archivo se corta en un bloque que no es paquete.
            _raise_if_truncated(tap)
        except dpkt.NeedData as exc:
            # La cabecera de un paquete quedó cortada: el archivo se truncó.
            raise PcapError(f"captura truncada: {_truncated_detail(exc)}") from exc
        except PcapError:
            raise
        except (ValueError, dpkt.UnpackError, struct.error) as exc:
            # Cabecera de bloque o de paquete con campos imposibles (longitud negativa, etc.)
            raise PcapError(f"captura dañada: {exc}") from exc


def iter_packets(path) -> Iterator[Packet]:
    """Devuelve un Packet por cada paquete del archivo, de a uno."""
    for _, _, pkt in iter_indexed(path):
        yield pkt


def _truncated_detail(exc: Exception) -> str:
    """Motivo legible del truncado."""
    return str(exc).strip() or "el archivo termina antes de lo esperado"


# ------------------------------------------------------- índice de posiciones

INDEX_STEP = 4096  # un punto de reanudación cada tantos paquetes
MAX_INDEXES = 4  # archivos con índice en memoria a la vez


class _PacketIndex:
    """Posición en el archivo de los paquetes 0, STEP, 2·STEP...: saltar sin releer desde el inicio."""

    def __init__(self, first_pos: int):
        self.positions: List[int] = [first_pos]
        self._lock = threading.Lock()

    def note(self, next_index: int, pos: int) -> None:
        """Guarda la posición del paquete `next_index` si es un punto de reanudación nuevo."""
        if next_index % INDEX_STEP:
            return
        with self._lock:
            if next_index // INDEX_STEP == len(self.positions):
                self.positions.append(pos)


_INDEXES: "OrderedDict[Tuple[str, int, int], _PacketIndex]" = OrderedDict()
_INDEXES_LOCK = threading.Lock()


def file_signature(path) -> Tuple[str, int, int]:
    """(ruta, tamaño, mtime en ns): cambia si el archivo cambia, así se descarta lo cacheado."""
    p = require_regular_file(path)
    st = p.stat()
    return str(p.resolve()), st.st_size, st.st_mtime_ns


def packet_index(path) -> _PacketIndex:
    """Índice de posiciones del archivo (cache LRU chica; un archivo cambiado no lo reutiliza)."""
    sig = file_signature(path)
    with _INDEXES_LOCK:
        index = _INDEXES.get(sig)
        if index is None:
            with _open(path) as (_, _, tap):
                index = _INDEXES[sig] = _PacketIndex(tap.pos)
            while len(_INDEXES) > MAX_INDEXES:
                _INDEXES.popitem(last=False)
        _INDEXES.move_to_end(sig)
        return index


def get_packet(path, index: int) -> Packet:
    """Devuelve el paquete número `index` (0 = el primero)."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise IndexError(f"índice de paquete inválido: {index!r}")
    positions = packet_index(path)
    start = min(index // INDEX_STEP, len(positions.positions) - 1)
    for i, pos, pkt in iter_indexed(path, start * INDEX_STEP, positions.positions[start]):
        if i == index:
            return pkt
        positions.note(i + 1, pos)  # el índice crece a medida que se recorre
    raise IndexError(f"el paquete {index} no existe en la captura")


def count_packets(path) -> int:
    """Cuenta paquetes recorriendo el archivo en streaming."""
    return sum(1 for _ in iter_packets(path))
