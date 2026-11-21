"""Configuración de red del equipo: adaptadores, IP, máscara, puerta de enlace, DNS y si la IP es automática (DHCP)."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from backend.domain.system.common import psutil_or_raise, safe

from .common import IS_LINUX, IS_WINDOWS, powershell_json, run

_WIN_SCRIPT = (
    "$r = @(Get-NetIPConfiguration -All | ForEach-Object { [pscustomobject]@{"
    "alias=[string]$_.InterfaceAlias; description=[string]$_.InterfaceDescription;"
    "gateway=(@($_.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop }) -join ',');"
    "dns=(@($_.DNSServer | ForEach-Object { $_.ServerAddresses }) -join ',');"
    "dhcp=[string]$_.NetIPv4Interface.Dhcp } }); ConvertTo-Json -InputObject $r -Compress"
)


def is_apipa(ip: str) -> bool:
    """169.254.x.x: la dirección que Windows se pone sola cuando NO consiguió IP del router (DHCP)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("169.254.0.0/16")
    except ValueError:
        return False


def _extras_windows() -> Dict[str, Dict[str, Any]]:
    data = powershell_json(_WIN_SCRIPT, timeout=25)
    if isinstance(data, dict):
        data = [data]
    out: Dict[str, Dict[str, Any]] = {}
    for item in data or []:
        if isinstance(item, dict) and item.get("alias"):
            out[item["alias"]] = {
                "gateway": [g for g in str(item.get("gateway") or "").split(",") if g],
                "dns": [d for d in str(item.get("dns") or "").split(",") if d],
                "dhcp": {"Enabled": True, "Disabled": False}.get(str(item.get("dhcp"))),
                "description": item.get("description") or None,
            }
    return out


def _linux_gateways() -> Dict[str, str]:
    res = run(["ip", "-j", "route", "show", "default"], timeout=5)
    out: Dict[str, str] = {}
    try:
        for r in json.loads(res.out or "[]"):
            if r.get("dev") and r.get("gateway"):
                out.setdefault(r["dev"], r["gateway"])
    except ValueError:
        pass
    return out


def _linux_dns() -> List[str]:
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            return [ln.split()[1] for ln in f if ln.startswith("nameserver") and len(ln.split()) > 1]
    except OSError:
        return []


_CACHE_SECONDS = 8.0
_cache_lock = threading.Lock()
_cache: Dict[str, Any] = {"at": 0.0, "value": None}


def network_config(fresh: bool = False) -> Dict[str, Any]:
    """Configuración de red, con una caché de unos segundos: leerla llama a PowerShell (varios segundos) y una misma
    pantalla la pide más de una vez. `fresh=True` fuerza una lectura nueva (el botón «Actualizar»)."""
    with _cache_lock:
        if not fresh and _cache["value"] is not None and time.monotonic() - _cache["at"] < _CACHE_SECONDS:
            return _cache["value"]
        value = _read_config()
        _cache["at"], _cache["value"] = time.monotonic(), value
        return value


def _read_config() -> Dict[str, Any]:
    """Adaptadores con su configuración. Los datos de puerta de enlace y DNS salen de PowerShell (Windows) o de
    `ip` y /etc/resolv.conf (Linux); si no se pueden leer, quedan vacíos y el resto igual se muestra."""
    ps = psutil_or_raise()
    stats = safe(ps.net_if_stats, {}) or {}
    extras: Dict[str, Dict[str, Any]] = _extras_windows() if IS_WINDOWS else {}
    gateways = _linux_gateways() if IS_LINUX else {}
    dns = _linux_dns() if IS_LINUX else []
    adapters: List[Dict[str, Any]] = []
    for name, addrs in (safe(ps.net_if_addrs, {}) or {}).items():
        v4 = [{"ip": a.address, "mask": a.netmask} for a in addrs if a.family == socket.AF_INET]
        v6 = [a.address.split("%", 1)[0] for a in addrs if a.family == socket.AF_INET6]
        mac = next((a.address for a in addrs if a.family == ps.AF_LINK), None)
        st = stats.get(name)
        extra = extras.get(name, {})
        gateway = extra.get("gateway") or ([gateways[name]] if name in gateways else [])
        adapters.append({
            "name": name, "description": extra.get("description"), "up": bool(st and st.isup),
            "speed_mbps": st.speed if st and st.speed else None, "mtu": st.mtu if st else None, "mac": mac,
            "ipv4": v4, "ipv6": v6, "gateway": gateway, "dns": extra.get("dns") or dns,
            "dhcp": extra.get("dhcp"), "apipa": any(is_apipa(a["ip"]) for a in v4),
            "loopback": any(a["ip"].startswith("127.") for a in v4),
        })
    adapters.sort(key=lambda a: (not a["up"], a["loopback"], not a["ipv4"], a["name"].lower()))
    return {"adapters": adapters, "hostname": socket.gethostname()}


def default_gateway(config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Primera puerta de enlace IPv4 de un adaptador activo."""
    for a in (config or network_config())["adapters"]:
        if a["up"] and not a["loopback"] and a["gateway"]:
            return str(a["gateway"][0])
    return None


def raw_config() -> Dict[str, Any]:
    """La salida completa de `ipconfig /all` (Windows) o `ip addr` (Linux), tal cual, para quien quiera ver todo."""
    cmd = ["ipconfig", "/all"] if IS_WINDOWS else ["ip", "addr"]
    res = run(cmd, timeout=15)
    if res.missing:
        return {"available": False, "command": " ".join(cmd), "text": "", "reason": f"No se encontró el comando {cmd[0]}."}
    text = re.sub(r"\n{3,}", "\n\n", res.out)
    return {"available": True, "command": " ".join(cmd), "text": text}
