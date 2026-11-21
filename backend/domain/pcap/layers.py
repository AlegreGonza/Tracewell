"""Decodifica un paquete capa por capa, con el rango de bytes de cada campo.

Sirve para el panel de detalle (como el de Wireshark): cada campo trae su valor
legible, una pista en lenguaje simple y la posición `start:end` dentro del
paquete, para resaltar esos bytes en el hex dump.

Se decodifica a mano con `struct` (y no con dpkt) porque dpkt no informa en qué
byte empieza cada campo. Un paquete cortado o raro NUNCA lanza: se muestra lo que
se pueda leer y se marca la capa como incompleta.
"""
from __future__ import annotations

import ipaddress
import socket
import string
import struct
from typing import Any, Dict, List, Optional, Tuple

Field = Dict[str, Any]
Layer = Dict[str, Any]

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN 802.1Q", 0x88A8: "VLAN 802.1ad"}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
SERVICES = {
    20: "FTP datos", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3389: "RDP", 5353: "mDNS", 8080: "HTTP alterno",
}
TCP_FLAGS = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80))
TCP_FLAG_HINTS = {
    "SYN": "Pide abrir una conexión (1.º paso del saludo de 3 pasos)",
    "SYN+ACK": "Acepta la conexión (2.º paso del saludo de 3 pasos)",
    "ACK": "Confirma datos recibidos (también sirve de latido o keep-alive)",
    "PSH+ACK": "Entrega datos de inmediato y confirma lo recibido",
    "FIN+ACK": "Cierre ordenado de la conexión",
    "FIN+PSH+ACK": "Último dato y cierre ordenado",
    "RST": "Corta la conexión de golpe (puerto cerrado o error)",
    "RST+ACK": "Corta la conexión de golpe",
}
TCP_OPTIONS = {0: "fin de opciones", 1: "relleno (NOP)", 2: "MSS", 3: "escala de ventana", 4: "SACK permitido", 5: "SACK", 8: "marcas de tiempo"}
ICMP_TYPES = {0: "Respuesta de eco (ping)", 3: "Destino inalcanzable", 5: "Redirección", 8: "Solicitud de eco (ping)", 11: "Tiempo excedido (traceroute)"}
ICMP6_TYPES = {1: "Destino inalcanzable", 128: "Solicitud de eco (ping)", 129: "Respuesta de eco (ping)", 133: "Solicitud de router",
               134: "Anuncio de router", 135: "Solicitud de vecino (como ARP)", 136: "Anuncio de vecino (como ARP)"}
CHECKSUM_HINT = "No se verifica: las tarjetas de red suelen calcularlo después de capturar (offload), así que un valor 'malo' es común y normal"
MAX_EXT_HEADERS = 8


# ------------------------------------------------------------------- utilidades

def _field(label: str, value: Any, start: int, end: int, hint: Optional[str] = None) -> Field:
    return {"label": label, "value": str(value), "start": start, "end": end, "hint": hint}


def _u16(d: bytes, i: int) -> int:
    return struct.unpack_from(">H", d, i)[0]


def _u32(d: bytes, i: int) -> int:
    return struct.unpack_from(">I", d, i)[0]


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _layer(name: str, start: int, end: int, fields: List[Field], note: Optional[str] = None) -> Layer:
    return {"name": name, "start": start, "end": end, "fields": fields, "note": note}


def _truncated(name: str, start: int, data: bytes) -> Layer:
    # start nunca pasa del final: el resaltado del hex dump depende de 0 <= start <= end <= largo.
    return _layer(name, min(start, len(data)), len(data), [], "Capa incompleta: el paquete está cortado y no alcanza para leerla")


def _port(label: str, port: int, start: int) -> Field:
    service = SERVICES.get(port)
    return _field(label, f"{port} ({service})" if service else port, start, start + 2,
                  "Puerto bien conocido" if service else None)


def _ttl_hint(ttl: int) -> str:
    if ttl > 128:
        return "Cerca de 255: típico de equipos de red. Orientativo: cada router resta 1"
    if ttl > 64:
        return "Cerca de 128: típico de Windows. Orientativo: cada router resta 1"
    return "Cerca de 64: típico de Linux y macOS. Orientativo: cada router resta 1"


# --------------------------------------------------------------------- Ethernet

def _ethernet(d: bytes, layers: List[Layer]) -> Tuple[Optional[int], int]:
    """Agrega la capa Ethernet. Devuelve (ethertype real, posición del siguiente nivel)."""
    if len(d) < 14:
        layers.append(_truncated("Ethernet", 0, d))
        return None, len(d)
    fields = [_field("MAC de destino", _mac(d[0:6]), 0, 6), _field("MAC de origen", _mac(d[6:12]), 6, 12)]
    pos, etype = 12, _u16(d, 12)
    while etype in (0x8100, 0x88A8) and len(d) >= pos + 6:
        fields.append(_field("VLAN", f"ID {_u16(d, pos + 2) & 0x0FFF}", pos, pos + 4, "Etiqueta de red virtual (802.1Q)"))
        etype = _u16(d, pos + 4)
        pos += 4
    fields.append(_field("Tipo", f"0x{etype:04x} ({ETHERTYPES.get(etype, 'otro')})", pos, pos + 2, "Qué protocolo viene dentro"))
    layers.append(_layer("Ethernet", 0, pos + 2, fields))
    return etype, pos + 2


# --------------------------------------------------------------------------- IP

def _ipv4(d: bytes, p: int, layers: List[Layer]) -> Tuple[Optional[int], int]:
    """Agrega la capa IPv4. Devuelve (protocolo siguiente o None, posición del siguiente nivel)."""
    if len(d) < p + 20:
        layers.append(_truncated("IPv4", p, d))
        return None, len(d)
    ihl = (d[p] & 0x0F) * 4
    flags_frag = _u16(d, p + 6)
    proto, ttl = d[p + 9], d[p + 8]
    flags = ", ".join(n for n, m in (("No fragmentar (DF)", 0x4000), ("Más fragmentos (MF)", 0x2000)) if flags_frag & m) or "ninguna"
    fields = [
        _field("Versión y largo de cabecera", f"4 · cabecera de {ihl} B", p, p + 1),
        _field("Servicios diferenciados", f"0x{d[p + 1]:02x}", p + 1, p + 2, "Prioridad y control de congestión; casi siempre 0"),
        _field("Largo total", f"{_u16(d, p + 2)} B", p + 2, p + 4, "Cabecera IP + datos"),
        _field("Identificación", f"0x{_u16(d, p + 4):04x}", p + 4, p + 6),
        _field("Banderas", flags, p + 6, p + 8, "DF: el paquete no debe partirse en trozos"),
        _field("TTL", ttl, p + 8, p + 9, _ttl_hint(ttl)),
        _field("Protocolo", f"{proto} ({IP_PROTOS.get(proto, 'otro')})", p + 9, p + 10, "Qué protocolo viene dentro"),
        _field("Checksum", f"0x{_u16(d, p + 10):04x}", p + 10, p + 12, CHECKSUM_HINT),
        _field("IP de origen", socket.inet_ntoa(d[p + 12:p + 16]), p + 12, p + 16),
        _field("IP de destino", socket.inet_ntoa(d[p + 16:p + 20]), p + 16, p + 20),
    ]
    end = min(p + max(ihl, 20), len(d))
    if ihl > 20:
        fields.append(_field("Opciones", f"{ihl - 20} B", p + 20, end))
    layers.append(_layer("IPv4", p, end, fields))
    if flags_frag & 0x1FFF:  # fragmento que no es el primero: no trae cabecera de capa 4
        _payload(d, end, layers, "Fragmento IP (sin cabecera de capa 4)")
        return None, end
    return proto, end


def _ipv6_extensions(d: bytes, pos: int, nxt: int, fields: List[Field]) -> Tuple[Optional[int], int]:
    """Salta cabeceras de extensión (salto a salto, enrutamiento, destino). (protocolo final o None, posición)."""
    for _ in range(MAX_EXT_HEADERS):
        if nxt not in (0, 43, 60):
            return nxt, pos
        if len(d) < pos + 2:
            return None, len(d)
        size = (d[pos + 1] + 1) * 8
        fields.append(_field("Cabecera de extensión", f"tipo {nxt}, {size} B", pos, min(pos + size, len(d))))
        nxt, pos = d[pos], pos + size
        if pos > len(d):  # la extensión declara más bytes de los que hay: el paquete está cortado
            return None, len(d)
    return None, pos


def _ipv6(d: bytes, p: int, layers: List[Layer]) -> Tuple[Optional[int], int]:
    if len(d) < p + 40:
        layers.append(_truncated("IPv6", p, d))
        return None, len(d)
    hop, nxt = d[p + 7], d[p + 6]
    fields = [
        _field("Versión", "6", p, p + 1),
        _field("Largo de datos", f"{_u16(d, p + 4)} B", p + 4, p + 6, "Sin contar esta cabecera de 40 B"),
        _field("Siguiente cabecera", f"{nxt} ({IP_PROTOS.get(nxt, 'otro')})", p + 6, p + 7, "Qué viene dentro"),
        _field("Límite de saltos", hop, p + 7, p + 8, _ttl_hint(hop).replace("TTL", "límite")),
        _field("IP de origen", ipaddress.IPv6Address(d[p + 8:p + 24]).compressed, p + 8, p + 24),
        _field("IP de destino", ipaddress.IPv6Address(d[p + 24:p + 40]).compressed, p + 24, p + 40),
    ]
    proto, pos = _ipv6_extensions(d, p + 40, nxt, fields)
    layers.append(_layer("IPv6", p, min(pos, len(d)), fields))
    return proto, pos


def _arp(d: bytes, p: int, layers: List[Layer]) -> None:
    if len(d) < p + 28:
        layers.append(_truncated("ARP", p, d))
        return
    op = _u16(d, p + 6)
    fields = [
        _field("Operación", f"{op} ({ {1: 'solicitud', 2: 'respuesta'}.get(op, 'otra') })", p + 6, p + 8,
               "Solicitud: '¿quién tiene esta IP?'. Respuesta: 'yo, esta es mi MAC'"),
        _field("MAC del emisor", _mac(d[p + 8:p + 14]), p + 8, p + 14),
        _field("IP del emisor", socket.inet_ntoa(d[p + 14:p + 18]), p + 14, p + 18),
        _field("MAC del destino", _mac(d[p + 18:p + 24]), p + 18, p + 24),
        _field("IP del destino", socket.inet_ntoa(d[p + 24:p + 28]), p + 24, p + 28),
    ]
    layers.append(_layer("ARP", p, p + 28, fields))


# ----------------------------------------------------------------------- capa 4

def _tcp_options(d: bytes, start: int, end: int) -> str:
    """Nombres de las opciones TCP presentes (solo se reconocen los tipos comunes)."""
    names, i = [], start
    while i < end:
        kind = d[i]
        names.append(TCP_OPTIONS.get(kind, f"tipo {kind}"))
        if kind in (0, 1):
            i += 1
        else:
            if i + 1 >= end or d[i + 1] < 2:
                break
            i += d[i + 1]
    return ", ".join(n for n in names if n != "relleno (NOP)") or "solo relleno"


def _tcp(d: bytes, p: int, layers: List[Layer]) -> Optional[int]:
    if len(d) < p + 20:
        layers.append(_truncated("TCP", p, d))
        return None
    off, flags = (d[p + 12] >> 4) * 4, d[p + 13]
    names = "+".join(n for n, m in TCP_FLAGS if flags & m) or "ninguna"
    fields = [
        _port("Puerto de origen", _u16(d, p), p),
        _port("Puerto de destino", _u16(d, p + 2), p + 2),
        _field("Nº de secuencia", _u32(d, p + 4), p + 4, p + 8, "Posición del primer byte de datos de este paquete"),
        _field("Nº de confirmación", _u32(d, p + 8), p + 8, p + 12, "Hasta qué byte recibió bien el otro lado (si ACK está activo)"),
        _field("Largo de cabecera", f"{off} B", p + 12, p + 13),
        _field("Banderas", names, p + 13, p + 14, TCP_FLAG_HINTS.get(names)),
        _field("Ventana", _u16(d, p + 14), p + 14, p + 16, "Cuántos bytes más acepta recibir el que envía este paquete"),
        _field("Checksum", f"0x{_u16(d, p + 16):04x}", p + 16, p + 18, CHECKSUM_HINT),
    ]
    end = min(p + max(off, 20), len(d))
    if off > 20:
        fields.append(_field("Opciones", _tcp_options(d, p + 20, end), p + 20, end))
    layers.append(_layer("TCP", p, end, fields))
    return end


def _udp(d: bytes, p: int, layers: List[Layer]) -> Optional[int]:
    if len(d) < p + 8:
        layers.append(_truncated("UDP", p, d))
        return None
    fields = [
        _port("Puerto de origen", _u16(d, p), p),
        _port("Puerto de destino", _u16(d, p + 2), p + 2),
        _field("Largo", f"{_u16(d, p + 4)} B", p + 4, p + 6, "Cabecera UDP (8 B) + datos"),
        _field("Checksum", f"0x{_u16(d, p + 6):04x}", p + 6, p + 8, CHECKSUM_HINT),
    ]
    layers.append(_layer("UDP", p, p + 8, fields))
    return p + 8


def _icmp_like(name: str, types: Dict[int, str]):
    def parse(d: bytes, p: int, layers: List[Layer]) -> Optional[int]:
        if len(d) < p + 4:
            layers.append(_truncated(name, p, d))
            return None
        fields = [
            _field("Tipo", f"{d[p]} ({types.get(d[p], 'otro')})", p, p + 1),
            _field("Código", d[p + 1], p + 1, p + 2, "Detalle del tipo"),
            _field("Checksum", f"0x{_u16(d, p + 2):04x}", p + 2, p + 4, CHECKSUM_HINT),
        ]
        layers.append(_layer(name, p, p + 4, fields))
        return p + 4
    return parse


# ---------------------------------------------------------------------- datos

def _payload_hint(chunk: bytes) -> str:
    """Qué parece el contenido: registro TLS (cifrado), texto legible o binario."""
    if len(chunk) >= 3 and chunk[0] in (0x14, 0x15, 0x16, 0x17) and chunk[1] == 3 and chunk[2] <= 4:
        return "Parece un registro TLS: el contenido va cifrado (se ven solo los metadatos)"
    sample = chunk[:80]
    printable = sum(1 for b in sample if 32 <= b < 127)
    if sample and printable / len(sample) >= 0.85:
        text = "".join(chr(b) if chr(b) in string.printable and b >= 32 else "." for b in chunk[:60])
        return f"Texto legible: {text}"
    return "Datos binarios"


def _payload(d: bytes, pos: int, layers: List[Layer], name: str = "Datos") -> None:
    if pos >= len(d):
        return
    chunk = d[pos:]
    layers.append(_layer(name, pos, len(d), [_field("Largo", f"{len(chunk)} B", pos, len(d), _payload_hint(chunk))]))


# ------------------------------------------------------------------- principal

_L4 = {6: _tcp, 17: _udp, 1: _icmp_like("ICMP", ICMP_TYPES), 58: _icmp_like("ICMPv6", ICMP6_TYPES)}


def dissect(data: bytes) -> List[Layer]:
    """Capas del paquete (Ethernet, IP, TCP/UDP/ICMP/ARP, datos) con el rango de bytes de cada campo.

    Nunca lanza: ante cualquier problema devuelve las capas que pudo leer.
    """
    layers: List[Layer] = []
    try:
        _walk(bytes(data), layers)
    except (struct.error, ValueError, IndexError, OSError):  # defensa: un paquete raro no debe romper el detalle
        layers.append(_layer("Error", len(data), len(data), [], "No se pudo decodificar el resto del paquete"))
    return layers


def _walk(d: bytes, layers: List[Layer]) -> None:
    etype, pos = _ethernet(d, layers)
    if etype == 0x0806:
        _arp(d, pos, layers)
        return
    parsers = {0x0800: _ipv4, 0x86DD: _ipv6}
    if etype not in parsers:
        _payload(d, pos, layers)
        return
    proto, pos = parsers[etype](d, pos, layers)
    if proto is None:
        return
    parse = _L4.get(proto)
    nxt = parse(d, pos, layers) if parse else pos
    if nxt is not None:
        _payload(d, nxt, layers)
