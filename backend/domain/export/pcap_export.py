"""Guarda un subconjunto de paquetes (una sesión, o lo que coincide con un filtro) como un .pcap nuevo.

Sirve para llevarse SOLO la conversación que importa: abrirla en Wireshark o adjuntarla a un ticket
sin arrastrar toda la captura. Los paquetes se copian tal cual; lo único que no se conserva es el
"largo original" de un paquete recortado por snaplen (el formato que escribe dpkt no lo permite).

Topes: en memoria se arma el archivo entero, así que se limita (`MAX_PACKETS`, `MAX_BYTES`); si se
alcanza un tope el archivo sale COMPLETO HASTA AHÍ y se avisa (`truncated`), nunca en silencio.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Iterable

import dpkt

from backend.domain.pcap.reader import Packet

MAX_PACKETS = 500_000
MAX_BYTES = 100_000_000
ETHERNET = 1
_SNAPLEN = 262_144  # dpkt no recorta con este valor: es solo lo que se declara en la cabecera global


@dataclass(frozen=True)
class PcapFile:
    data: bytes
    packets: int
    truncated: bool  # se alcanzó un tope: faltan paquetes


def build_pcap(packets: Iterable[Packet], linktype: int = ETHERNET) -> PcapFile:
    """Arma un .pcap en memoria con `packets` (en el orden recibido)."""
    buf = io.BytesIO()
    writer = dpkt.pcap.Writer(buf, snaplen=_SNAPLEN, linktype=linktype)
    count, truncated = 0, False
    for pkt in packets:
        if count >= MAX_PACKETS or buf.tell() + len(pkt.data) > MAX_BYTES:
            truncated = True
            break
        writer.writepkt(pkt.data, ts=pkt.ts)
        count += 1
    return PcapFile(buf.getvalue(), count, truncated)
