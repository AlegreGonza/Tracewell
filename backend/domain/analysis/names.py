"""Nombre del sitio de cada sesión, sacado de la PROPIA captura (sin consultar a nadie)."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import dpkt

from backend.domain.analysis.dns_log import DnsLog
from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import _PORT_PROTOS, _key, _l4_ports, _protocol_number, ip_layer

MAX_NAMES = 100_000  # tope por tabla: acota la memoria
MAX_NAME_LEN = 253  # largo máximo de un nombre DNS


@dataclass
class NameBook:
    dns: Dict[str, str] = field(default_factory=dict)  # IP -> nombre consultado
    sni: Dict[Tuple, str] = field(default_factory=dict)  # clave de sesión -> nombre del saludo TLS
    dns_log: DnsLog = field(default_factory=DnsLog)  # tabla de consultas y respuestas DNS

    def names_for(self, session) -> List[str]:
        """Nombres conocidos de una sesión (SNI primero), sin repetir."""
        found = [
            self.sni.get(session.key) if session.key is not None else None,
            self.dns.get(_norm(session.dst_ip)),
            self.dns.get(_norm(session.src_ip)),
        ]
        out: List[str] = []
        for name in found:
            if name and name not in out:
                out.append(name)
        return out

    def best_name(self, session) -> Optional[str]:
        names = self.names_for(session)
        return names[0] if names else None


def _norm(ip: str) -> str:
    try:
        return ipaddress.ip_address(str(ip).split("%", 1)[0]).compressed
    except ValueError:
        return str(ip)


def _clean_name(raw) -> Optional[str]:
    """Nombre en minúsculas y sin punto final; None si no parece un nombre razonable."""
    try:
        text = raw.decode("ascii") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except UnicodeDecodeError:
        return None
    text = text.strip().lower().rstrip(".")
    if not text or len(text) > MAX_NAME_LEN or not text.isprintable() or " " in text:
        return None
    return text


# ------------------------------------------------------------------------ DNS

def _answer_ips(dns) -> List[str]:
    """IP (A y AAAA) de las respuestas de un mensaje DNS."""
    ips = (_rr_ip(rr) for rr in dns.an)
    return [ip for ip in ips if ip is not None]


def _rr_ip(rr) -> Optional[str]:
    """IP de un registro A/AAAA; None si es otro tipo o está roto (un registro raro no invalida los demás)."""
    try:
        if rr.type == dpkt.dns.DNS_A:
            return socket.inet_ntop(socket.AF_INET, rr.ip)
        if rr.type == dpkt.dns.DNS_AAAA:
            return socket.inet_ntop(socket.AF_INET6, rr.ip6)
    except (AttributeError, ValueError, OSError):
        pass
    return None


def dns_names(payload: bytes) -> List[Tuple[str, str]]:
    """[(ip, nombre consultado)] de una RESPUESTA DNS; [] si no es una o no se entiende."""
    try:
        dns = dpkt.dns.DNS(payload)
    except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError, UnicodeError):
        return []
    if dns.qr != dpkt.dns.DNS_R or dns.rcode != dpkt.dns.DNS_RCODE_NOERR or not dns.qd:
        return []
    name = _clean_name(dns.qd[0].name)  # el nombre que se PIDIÓ, no el canónico de un CNAME
    return [(_norm(ip), name) for ip in _answer_ips(dns)] if name else []


# ------------------------------------------------------------------------ TLS

def _u16(b: bytes, i: int) -> Optional[int]:
    return int.from_bytes(b[i:i + 2], "big") if i + 2 <= len(b) else None


def _skip_vector(b: bytes, i: int, size: int) -> Optional[int]:
    """Posición tras un vector con prefijo de largo de `size` bytes, o None si no entra."""
    if i + size > len(b):
        return None
    end = i + size + int.from_bytes(b[i:i + size], "big")
    return end if end <= len(b) else None


def _hello_extensions(b: bytes) -> Optional[bytes]:
    """Bloque de extensiones de un ClientHello (tras el registro y el saludo), o None."""
    if len(b) < 6 or b[0] != 0x16 or b[1] != 0x03 or b[5] != 0x01:  # registro handshake TLS + ClientHello
        return None
    i = 5 + 4 + 2 + 32  # cabecera del handshake (4) + versión (2) + random (32)
    for size in (1, 2, 1):  # session_id, cipher_suites, compression_methods
        after = _skip_vector(b, i, size)
        if after is None:
            return None
        i = after
    length = _u16(b, i)
    if length is None:
        return None
    return b[i + 2:i + 2 + length]  # si el paquete se cortó, se analiza lo que haya


def sni_from_client_hello(payload: bytes) -> Optional[str]:
    """Nombre del servidor (extensión server_name) de un ClientHello, o None."""
    ext = _hello_extensions(payload)
    i = 0
    while ext is not None and i + 4 <= len(ext):
        kind, size = _u16(ext, i), _u16(ext, i + 2)
        if kind is None or size is None:
            return None
        body = ext[i + 4:i + 4 + size]
        if kind == 0:  # server_name
            return _first_host_name(body)
        i += 4 + size
    return None


def _first_host_name(body: bytes) -> Optional[str]:
    """Primer nombre de host de la lista server_name (lista: 2 B de largo, luego tipo 0 + 2 B + nombre)."""
    if len(body) < 5 or body[2] != 0:
        return None
    size = _u16(body, 3)
    name = body[5:5 + size] if size else b""
    # Si el paquete se cortó DENTRO del nombre, devolver el pedazo daría un sitio falso
    return _clean_name(name) if size and len(name) == size else None


# ------------------------------------------------------------------ recorrido

def _l4_full(data: bytes):
    """."""
    try:
        layer = ip_layer(data)
        if layer is None:
            return None
        ip, family = layer
        proto = _protocol_number(ip)
        if proto not in _PORT_PROTOS:
            return None
        sport, dport = _l4_ports(ip, proto)  # UnpackError si la capa 4 está cortada
        src, dst = socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst)
        return proto, sport, dport, src, dst, _key(src, sport, dst, dport, proto), bytes(ip.data.data)
    except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError, AttributeError):
        return None


def _l4_payload(data: bytes):
    """(protocolo, puerto origen, clave de sesión, payload) de un paquete TCP/UDP, o None."""
    full = _l4_full(data)
    return None if full is None else (full[0], full[1], full[5], full[6])


def _put(table: dict, key, value) -> None:
    """Primero visto gana; con la tabla llena se ignora lo nuevo."""
    if key not in table and len(table) < MAX_NAMES:
        table[key] = value


class NameCollector:
    """Junta nombres paquete a paquete (así comparte la pasada con otros recolectores)."""

    def __init__(self) -> None:
        self.book = NameBook()

    def add(self, pkt: Packet) -> None:
        parsed = _l4_full(pkt.data)
        if parsed is None or not parsed[6]:
            return
        proto, sport, dport, src, dst, key, payload = parsed
        if proto == 17 and 53 in (sport, dport):
            self.book.dns_log.add(pkt.ts, src, dst, payload)  # tabla de DNS: consultas y respuestas
        if proto == 17 and sport == 53:
            for ip, name in dns_names(payload):
                _put(self.book.dns, ip, name)
        elif proto == 6 and key not in self.book.sni and payload[:2] == b"\x16\x03":
            host = sni_from_client_hello(payload)
            if host:
                _put(self.book.sni, key, host)


def collect_names(packets: Iterable[Packet]) -> NameBook:
    """Una pasada sobre la captura: junta respuestas DNS y SNI de TLS."""
    collector = NameCollector()
    for pkt in packets:
        collector.add(pkt)
    return collector.book
