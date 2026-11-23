"""Lectura de capturas .pcap / .pcapng en streaming."""
from __future__ import annotations

import struct
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, NamedTuple, Optional, Union

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


class _TapFile:
    """Envuelve el archivo y "espía" las lecturas que hace dpkt."""

    def __init__(self, fh):
        self._fh = fh
        self._state = "global"  # global -> (header -> payload)*
        self._hdr_struct: Optional[struct.Struct] = None
        self.last_origlen: Optional[int] = None
        self.short_read: Optional[tuple[int, int]] = None  # (esperado, leído)

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
        data = self._fh.read(n)
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
        self.short_read: Optional[tuple[int, int]] = None  # (esperado, leído)
        self._armed = False
        self._expect_header = True

    def arm(self) -> None:
        """Empieza a vigilar: las lecturas del constructor de dpkt no siguen el patrón por bloque."""
        self._armed = True
        self._expect_header = True

    def read(self, n=-1):
        data = self._fh.read(n)
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


def iter_packets(path) -> Iterator[Packet]:
    """Devuelve un Packet por cada paquete del archivo, de a uno."""
    with _open(path) as (_, reader, tap):
        try:
            for ts, buf in reader:
                # Lo escuchamos ANTES de entregarlo
                _raise_if_truncated(tap)
                origlen = tap.last_origlen if tap is not None else None
                # float(): con magic de nanosegundos dpkt entrega Decimal, y mezclar Decimal
                yield Packet(float(ts), buf, origlen)
            # dpkt termina en silencio si el archivo se corta en un bloque que no es paquete.
            _raise_if_truncated(tap)
        except dpkt.NeedData as exc:
            # La cabecera de un paquete quedó cortada: el archivo se truncó.
            raise PcapError(f"captura truncada: {_truncated_detail(exc)}") from exc


def _truncated_detail(exc: Exception) -> str:
    """Motivo legible del truncado."""
    return str(exc).strip() or "el archivo termina antes de lo esperado"


def get_packet(path, index: int) -> Packet:
    """Devuelve el paquete número `index` (0 = el primero)."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise IndexError(f"índice de paquete inválido: {index!r}")
    for i, pkt in enumerate(iter_packets(path)):
        if i == index:
            return pkt
    raise IndexError(f"el paquete {index} no existe en la captura")


def count_packets(path) -> int:
    """Cuenta paquetes recorriendo el archivo en streaming."""
    return sum(1 for _ in iter_packets(path))
