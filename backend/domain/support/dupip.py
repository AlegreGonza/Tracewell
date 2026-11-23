"""IP duplicada."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from .common import IS_WINDOWS, powershell_json
from .devices import fmt_mac, norm_mac
from .netinfo import active_ipv4, network_config

logger = logging.getLogger(__name__)

_EVENTS_SCRIPT = (
    "try { $e = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Tcpip'; Id=4199} -MaxEvents 20 "
    "-ErrorAction Stop | ForEach-Object { [pscustomobject]@{t=$_.TimeCreated.ToString('o'); "
    "m=(([string]$_.Message -split \"`n\")[0]).Trim()} }); ConvertTo-Json -InputObject $e -Compress } "
    "catch { ConvertTo-Json -InputObject @() -Compress }"
)


def _windows_conflicts() -> List[Dict[str, Any]]:
    data = powershell_json(_EVENTS_SCRIPT, timeout=25)
    if isinstance(data, dict):
        data = [data]
    return [{"time": d.get("t"), "message": d.get("m")} for d in (data or []) if isinstance(d, dict)]


def _arp_probe(ip: str, own_mac: str) -> Dict[str, Any]:
    """Pregunta por ARP quién tiene `ip`."""
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]  # import perezoso: es pesado

        # verbose=0 por llamada: no se toca la configuración global de Scapy (conf.verb)
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=1, verbose=0)
        macs = sorted({norm_mac(r.hwsrc) for _s, r in answered})
    except Exception as e:  # noqa: BLE001 - sin Npcap, sin permisos o sin interfaz: la sonda no está disponible
        logger.debug("sonda ARP no disponible para %s", ip, exc_info=True)
        return {"ip": ip, "probed": False, "reason": f"No se pudo hacer la sonda ARP ({type(e).__name__}): hace falta Npcap y abrir Tracewell como administrador."}
    others = [fmt_mac(m) for m in macs if m != norm_mac(own_mac)]
    return {"ip": ip, "probed": True, "other_macs": others, "duplicate": bool(others)}


def check_duplicate_ip(probe: bool = True) -> Dict[str, Any]:
    config = network_config()
    probes = [
        {"adapter": a["name"], **_arp_probe(v4["ip"], a["mac"])}
        for a, v4 in (active_ipv4(config, need_mac=True) if probe else ())
    ]
    conflicts = _windows_conflicts() if IS_WINDOWS else []
    duplicate = any(p.get("duplicate") for p in probes)
    return {
        "summary": _summary(duplicate, conflicts, probes), "duplicate": duplicate, "probes": probes, "conflicts": conflicts,
        "advice": ("Cambiá la IP fija de uno de los dos equipos o reservá IPs distintas en el router (DHCP)." if duplicate else None),
    }


def _summary(duplicate: bool, conflicts: List[Dict[str, Any]], probes: List[Dict[str, Any]]) -> str:
    """Frase de resultado según lo que se encontró."""
    if duplicate:
        return "¡Otro equipo está usando la misma IP que esta PC!"
    if conflicts:
        return "Windows registró conflictos de IP en el pasado (mirá las fechas): puede haber pasado y resolverse."
    if not probes:
        return "Esta PC no tiene una IP válida para revisar."
    if all(p.get("probed") for p in probes):
        return "Nadie más contestó por la IP de esta PC: no se detectó duplicado."
    return "No se pudo hacer la sonda ARP; solo se revisaron los avisos del sistema."
