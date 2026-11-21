"""Puertos abiertos y conexiones del equipo, cada uno con el programa dueño."""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List, Optional

from backend.domain.analysis.hosts import classify
from backend.domain.analysis.owners import owner_of
from backend.domain.pcap.layers import SERVICES
from backend.domain.pcap.processes import normalize_ip

from .common import psutil_or_raise, safe

MAX_ROWS = 1000

EXPOSURE_TEXT = {
    "local": "Solo esta PC",
    "todas": "Toda la red",
    "especifica": "Una dirección concreta",
}


def exposure_of(ip: Optional[str]) -> str:
    """¿Quién puede intentar conectarse a un puerto que escucha en esa dirección?"""
    if ip is None:
        return "especifica"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "especifica"
    if addr.is_loopback:
        return "local"
    return "todas" if addr.is_unspecified else "especifica"


def _names(ps) -> Dict[int, str]:
    names: Dict[int, str] = {}
    for p in safe(lambda: list(ps.process_iter(["pid", "name"])), []) or []:
        names[p.info["pid"]] = p.info.get("name") or f"PID {p.info['pid']}"
    return names


def _inet_connections(ps) -> Optional[list]:
    """Sockets del sistema, o None si el sistema no deja listarlos (p. ej. macOS sin permisos de administrador)."""
    try:
        return list(ps.net_connections(kind="inet"))
    except Exception:  # noqa: BLE001 - AccessDenied u otro fallo de lectura: se informa como "limitado"
        return None


def _addr(ip: Optional[str], port: Any) -> Optional[str]:
    """«ip:puerto», o None si la IP no se pudo leer (nunca el texto «None:443»)."""
    return f"{ip}:{port}" if ip is not None else None


def _proto(c) -> Optional[str]:
    return {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}.get(c.type)


def listening_ports() -> Dict[str, Any]:
    """Puertos que ESCUCHAN (TCP) o están a la espera (UDP), con su programa y qué tan expuestos están."""
    ps = psutil_or_raise()
    names = _names(ps)
    rows: List[Dict[str, Any]] = []
    sockets = _inet_connections(ps)
    if sockets is None:
        return {"total": 0, "items": [], "limited": True}
    for c in sockets:
        proto = _proto(c)
        if proto is None or not c.laddr:
            continue
        if proto == "TCP" and c.status != "LISTEN":
            continue
        if proto == "UDP" and c.raddr:
            continue
        ip = normalize_ip(c.laddr.ip)
        exposure = exposure_of(ip)
        rows.append({
            "proto": proto, "ip": ip, "port": c.laddr.port, "pid": c.pid or None,
            "process": names.get(c.pid) if c.pid else None, "exposure": exposure,
            "exposure_text": EXPOSURE_TEXT[exposure], "service": SERVICES.get(c.laddr.port),
        })
    rows.sort(key=lambda r: (r["port"], r["proto"], r["ip"] or ""))
    return {"total": len(rows), "items": rows[:MAX_ROWS], "limited": bool(rows) and not any(r["pid"] for r in rows)}


def connections() -> Dict[str, Any]:
    """Conexiones TCP con otro equipo (no las que solo escuchan), con el dueño del rango de la IP remota."""
    ps = psutil_or_raise()
    names = _names(ps)
    rows: List[Dict[str, Any]] = []
    sockets = _inet_connections(ps)
    if sockets is None:
        return {"total": 0, "items": [], "limited": True}
    for c in sockets:
        if _proto(c) != "TCP" or not c.raddr or not c.laddr:
            continue
        remote = normalize_ip(c.raddr.ip)
        rows.append({
            "pid": c.pid or None, "process": names.get(c.pid) if c.pid else None,
            "local": _addr(normalize_ip(c.laddr.ip), c.laddr.port), "remote": _addr(remote, c.raddr.port),
            "remote_ip": remote, "status": c.status, "owner": owner_of(remote) if remote else None,
            "scope": classify(remote) if remote else None, "service": SERVICES.get(c.raddr.port),
        })
    rows.sort(key=lambda r: ((r["process"] or "~").lower(), r["remote"] or ""))
    return {"total": len(rows), "items": rows[:MAX_ROWS], "limited": False}
