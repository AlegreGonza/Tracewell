"""Reconstruye lo que se dijo en una sesión TCP ("Follow TCP Stream" de Wireshark).

Junta los datos de cada sentido en orden de número de secuencia, descarta
retransmisiones y marca los huecos (bytes que faltan en la captura). Con protocolos en
claro (FTP, HTTP, Telnet, SMTP) se lee la conversación entera; con TLS el contenido va
cifrado y solo se informa eso.

Límites (conscientes): se leen como máximo `MAX_BYTES` de datos y `MAX_PACKETS` paquetes;
un segmento que llega desordenado después de un hueco se muestra tal como llegó.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

import dpkt

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import ip_layer

MAX_BYTES = 1_000_000  # datos reconstruidos (suma de los dos sentidos)
MAX_PACKETS = 50_000
MAX_GAP = 1_000_000  # un salto de secuencia mayor se toma como una conexión distinta, no como un hueco
TEXT_CHUNK = 20_000  # caracteres máximos por bloque que se devuelven a la interfaz
TCP_SYN = 0x02


@dataclass
class Stream:
    chunks: List[Dict[str, Any]] = field(default_factory=list)
    origin_bytes: int = 0
    destination_bytes: int = 0
    encrypted: bool = False  # el primer dato parece un registro TLS: el contenido no se puede leer
    truncated: bool = False  # se llegó a un tope: lo que falta no está en `chunks`


class _Direction:
    """Estado de un sentido de la conexión: dónde se espera el siguiente byte."""

    def __init__(self) -> None:
        self.base: Optional[int] = None
        self.next = 0


def _tcp_segment(pkt: Packet):
    """(origen ip, puerto, seq, banderas, datos) de un paquete TCP, o None si no lo es o está dañado."""
    try:
        layer = ip_layer(pkt.data)
        if layer is None:
            return None
        ip, family = layer
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            return None
        return socket.inet_ntop(family, ip.src), tcp.sport, tcp.seq, tcp.flags, bytes(tcp.data)
    except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError, AttributeError):
        return None


def _printable(chunk: bytes) -> str:
    """Texto de un bloque: lo imprimible tal cual y el resto como '·' (se muestra siempre como texto)."""
    text = "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "·" for b in chunk[:TEXT_CHUNK])
    return text + ("…" if len(chunk) > TEXT_CHUNK else "")


def _looks_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] in (0x14, 0x15, 0x16, 0x17) and data[1] == 3 and data[2] <= 4


def _emit(stream: Stream, who: str, data: bytes) -> None:
    """Agrega datos: si el bloque anterior es del mismo sentido, se une (una conversación se lee por turnos)."""
    if who == "origen":
        stream.origin_bytes += len(data)
    else:
        stream.destination_bytes += len(data)
    last = stream.chunks[-1] if stream.chunks else None
    if last is not None and last.get("from") == who:
        last["raw"] += data
    else:
        stream.chunks.append({"from": who, "raw": bytes(data)})


def _place(stream: Stream, direction: _Direction, who: str, seq: int, flags: int, data: bytes) -> None:
    """Coloca un segmento: descarta lo ya visto (retransmisión) y marca los huecos."""
    if direction.base is None:
        direction.base = (seq + 1 if flags & TCP_SYN else seq) & 0xFFFFFFFF
    offset = (seq + (1 if flags & TCP_SYN else 0) - direction.base) & 0xFFFFFFFF
    if offset >= 2**31 or not data:  # número anterior a la base (retransmisión vieja) o sin datos
        return
    if offset - direction.next > MAX_GAP:
        direction.base, direction.next, offset = seq & 0xFFFFFFFF, 0, 0  # otra conexión reutilizando el puerto
    if offset > direction.next:
        stream.chunks.append({"gap": offset - direction.next})
        direction.next = offset
    data = data[direction.next - offset:]  # recorta lo ya recibido (retransmisión parcial)
    if data:
        direction.next += len(data)
        _emit(stream, who, data)


def _collect(session, packets: Iterable[Packet]) -> Stream:
    """Reconstruye la sesión dejando los bloques en bytes (`raw`), sin pasarlos a texto todavía."""
    stream = Stream()
    directions = {"origen": _Direction(), "destino": _Direction()}
    seen = 0
    for pkt in packets:
        seen += 1
        parsed = _tcp_segment(pkt)
        if parsed is None:
            continue
        ip, port, seq, flags, data = parsed
        who = "origen" if (ip, port) == (session.src_ip, session.src_port) else "destino"
        _place(stream, directions[who], who, seq, flags, data)
        if stream.origin_bytes + stream.destination_bytes >= MAX_BYTES or seen >= MAX_PACKETS:
            stream.truncated = True
            break
    return stream


def follow_stream(session, packets: Iterable[Packet]) -> Stream:
    """Reconstruye la conversación de `session` (TCP) a partir de SUS paquetes, en orden de captura."""
    return _finish(_collect(session, packets))


@dataclass(frozen=True)
class RawDirections:
    origin: bytes  # todo lo que mandó el extremo de origen, en orden
    destination: bytes
    has_gaps: bool  # faltan bytes en la captura: lo reconstruido puede estar incompleto
    truncated: bool  # se llegó a un tope


def raw_directions(session, packets: Iterable[Packet]) -> RawDirections:
    """Los bytes de cada sentido por separado y sin recortar (los analizadores de protocolo los necesitan
    enteros: una cabecera HTTP o un certificado TLS no se puede leer a pedazos)."""
    stream = _collect(session, packets)
    parts: Dict[str, List[bytes]] = {"origen": [], "destino": []}
    for chunk in stream.chunks:
        if "raw" in chunk:
            parts[chunk["from"]].append(chunk["raw"])
    return RawDirections(
        b"".join(parts["origen"]), b"".join(parts["destino"]),
        any("gap" in c for c in stream.chunks), stream.truncated,
    )


def _finish(stream: Stream) -> Stream:
    """Pasa los bloques de bytes a texto y detecta si la sesión va cifrada."""
    first = next((c["raw"] for c in stream.chunks if "raw" in c), b"")
    stream.encrypted = _looks_tls(first)
    for chunk in stream.chunks:
        if "raw" in chunk:
            raw = chunk.pop("raw")
            chunk["bytes"] = len(raw)
            chunk["text"] = "" if stream.encrypted else _printable(raw)
    return stream
