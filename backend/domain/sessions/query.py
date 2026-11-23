"""Consultas sobre sesiones: filtros y estadísticas."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from backend.domain.sessions.grouper import GroupingResult, Session


class InvalidFilter(ValueError):
    """El valor de un filtro no tiene sentido (IP mal escrita, puerto fuera de rango)."""


def _parse_ip_filter(ip):
    """Valida el filtro de IP y lo devuelve como objeto IP (o None si no hay)."""
    if ip is None:
        return None
    # Solo texto: ipaddress acepta bytes/int como "dirección empaquetada", y un filtro
    if not isinstance(ip, str):
        raise InvalidFilter(f"la IP debe ser texto, no {type(ip).__name__}")
    if "%" in ip:
        # Zona IPv6 (fe80::1%eth0)
        raise InvalidFilter(f"zona IPv6 no soportada en el filtro: {ip!r}")
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError as exc:
        raise InvalidFilter(f"IP inválida: {ip!r}") from exc


def _check_port_filter(port) -> None:
    """Rechaza un puerto que no sea entero de 0 a 65535."""
    if port is None:
        return
    # bool es subclase de int en Python: True no es un puerto válido.
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise InvalidFilter(f"puerto fuera de rango (0-65535): {port!r}")


def _normalize_protocol(protocol):
    """Valida el filtro de protocolo y lo devuelve en mayúsculas (o None)."""
    if protocol is None:
        return None
    if not isinstance(protocol, str):
        raise InvalidFilter(f"el protocolo debe ser texto, no {type(protocol).__name__}")
    wanted = protocol.strip().upper()
    # "" no significa "sin filtro" (eso es None)
    if not wanted:
        raise InvalidFilter("protocolo vacío")
    return wanted


def _matches(s: Session, proto, ip, port) -> bool:
    """True si la sesión cumple los criterios ya validados (None = no filtra)."""
    if proto is not None and s.protocol.upper() != proto:
        return False
    # Comparamos como objetos IP, no como texto
    if ip is not None and ip not in (
        ipaddress.ip_address(s.src_ip),
        ipaddress.ip_address(s.dst_ip),
    ):
        return False
    return port is None or port in (s.src_port, s.dst_port)


def filter_sessions(
    sessions: Iterable[Session],
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    port: Optional[int] = None,
) -> List[Session]:
    """Devuelve las sesiones que cumplen TODOS los criterios dados (AND)."""
    # Validamos ANTES de recorrer
    wanted_ip = _parse_ip_filter(ip)
    _check_port_filter(port)
    wanted_proto = _normalize_protocol(protocol)
    return [s for s in sessions if _matches(s, wanted_proto, wanted_ip, port)]


@dataclass
class ProtocolStats:
    sessions: int = 0
    packets: int = 0
    bytes: int = 0


@dataclass
class Stats:
    sessions: int = 0
    packets: int = 0
    bytes: int = 0
    by_protocol: Dict[str, ProtocolStats] = field(default_factory=dict)
    # Paquetes que no entraron en ninguna sesión
    non_ip: int = 0
    malformed: int = 0
    # Análisis parcial por tope de sesiones (ver group_packets).
    truncated: bool = False
    untracked_packets: int = 0


def _source_parts(source):
    """(sesiones, non_ip, malformed, truncated, untracked) de la fuente."""
    if isinstance(source, GroupingResult):
        return (source.sessions, source.non_ip, source.malformed,
                source.truncated, source.untracked_packets)
    return source, 0, 0, False, 0


def _add_session(stats: Stats, s: Session) -> None:
    """Suma una sesión a los totales y a su protocolo."""
    stats.sessions += 1
    stats.packets += s.packets
    stats.bytes += s.bytes
    p = stats.by_protocol.setdefault(s.protocol, ProtocolStats())
    p.sessions += 1
    p.packets += s.packets
    p.bytes += s.bytes


def compute_stats(source) -> Stats:
    """Totales y distribución por protocolo."""
    sessions, non_ip, malformed, truncated, untracked = _source_parts(source)
    stats = Stats(non_ip=non_ip, malformed=malformed, truncated=truncated, untracked_packets=untracked)
    for s in sessions:
        _add_session(stats, s)
    return stats
