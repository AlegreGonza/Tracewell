"""Acceso remoto: quién se conecta a SSH, Telnet, SMB, RDP, WinRM o VNC, y cómo le fue.

Agrupa por servicio las sesiones TCP cuyo puerto de servicio es uno de la tabla. Es la lista que un analista
revisa primero ante un posible movimiento lateral o fuerza bruta: ¿quién entra a quién, cuántas veces
reintentó y cuántas conexiones se cortaron con RST?

Las señales salen solo de las banderas TCP que cuenta el agrupador (`syn_packets`, `rst_packets`) y son
pistas: un RST puede ser un puerto cerrado, un firewall o un corte normal de la aplicación; varios SYN
seguidos pueden ser un reintento por pérdida de paquetes y no un ataque.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.domain.analysis.direction import session_direction

# puerto -> servicio. WinRM usa dos puertos (HTTP y HTTPS).
REMOTE_PORTS: Dict[int, str] = {
    22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 5900: "VNC",
}
SERVICES: Tuple[str, ...] = ("SSH", "Telnet", "SMB", "RDP", "WinRM", "VNC")  # orden de presentación
MAX_ITEMS = 200  # sesiones que se detallan por servicio (el resumen cuenta todas)
_CLEARTEXT = {"Telnet": "Telnet viaja sin cifrar: usuario y contraseña se ven en la red."}


class UnknownService(ValueError):
    """El servicio pedido no está en la tabla (la API lo traduce a 422)."""


def normalize_service(name: Optional[str]) -> Optional[str]:
    """Nombre canónico del servicio (sin distinguir mayúsculas), None si no se pidió; UnknownService si no existe."""
    if name is None:
        return None
    if isinstance(name, str):
        for known in SERVICES:
            if known.lower() == name.strip().lower():
                return known
    raise UnknownService(f"servicio desconocido; disponibles: {', '.join(SERVICES)}")


def service_of(session: Any) -> Optional[Tuple[str, int]]:
    """(servicio, puerto) si la sesión es TCP a un puerto de acceso remoto, o None. El puerto de servicio es el del
    destino y, si la captura empezó a mitad de la conversación (origen invertido), el del origen."""
    if session.protocol != "TCP":
        return None
    for port in (session.dst_port, session.src_port):
        if port in REMOTE_PORTS:
            return REMOTE_PORTS[port], port
    return None


def _signals(session: Any, service: str) -> List[str]:
    out = []
    if session.rst_packets:
        out.append(f"Con RST ({session.rst_packets}): conexión rechazada o cortada de golpe")
    if session.syn_retries:
        out.append(f"Reintentos de conexión: {session.syn_retries} SYN reenviado(s)")
    if service in _CLEARTEXT:
        out.append(_CLEARTEXT[service])
    return out


def _item(index: int, session: Any, service: str, port: int) -> Dict[str, Any]:
    server_is_dst = session.dst_port == port
    client_ip, server_ip = (session.src_ip, session.dst_ip) if server_is_dst else (session.dst_ip, session.src_ip)
    return {
        "id": index, "service": service, "port": port, "client_ip": client_ip, "server_ip": server_ip,
        "direction": session_direction(session), "packets": session.packets, "bytes": session.bytes,
        "first_ts": session.first_ts, "duration": session.duration,
        "syn_packets": session.syn_packets, "syn_retries": session.syn_retries, "rst_packets": session.rst_packets,
        "signals": _signals(session, service),
    }


def _attention(item: Dict[str, Any]) -> Tuple[int, int, int]:
    """Orden de las filas: primero lo que más llama la atención (RST, reintentos), después lo más pesado."""
    return (-item["rst_packets"], -item["syn_retries"], -item["bytes"])


def _group(service: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    items = sorted(items, key=_attention)
    return {
        "service": service,
        "ports": sorted({i["port"] for i in items}),
        "sessions": len(items),
        "clients": len({i["client_ip"] for i in items}),
        "servers": len({i["server_ip"] for i in items}),
        "with_rst": sum(1 for i in items if i["rst_packets"]),
        "retries": sum(i["syn_retries"] for i in items),
        "bytes": sum(i["bytes"] for i in items),
        "truncated": len(items) > MAX_ITEMS,
        "items": items[:MAX_ITEMS],
    }


def remote_access(sessions: Iterable[Any], service: Optional[str] = None) -> Dict[str, Any]:
    """Sesiones de acceso remoto agrupadas por servicio. El `id` de cada una es su posición en `sessions`
    (el mismo id que usa el resto de la API). `service` limita a un servicio (UnknownService si no existe)."""
    wanted = normalize_service(service)
    by_service: Dict[str, List[Dict[str, Any]]] = {}
    for index, session in enumerate(sessions):
        found = service_of(session)
        if found is None or (wanted and found[0] != wanted):
            continue
        by_service.setdefault(found[0], []).append(_item(index, session, *found))
    groups = [_group(name, by_service[name]) for name in SERVICES if name in by_service]
    return {"total": sum(g["sessions"] for g in groups), "services": groups}
