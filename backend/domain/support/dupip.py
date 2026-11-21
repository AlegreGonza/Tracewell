"""IP duplicada: dos equipos con la misma dirección en la red (provoca cortes intermitentes difíciles de explicar).

Dos pistas, ambas de lectura: los avisos de conflicto que Windows ya registró (evento 4199 de Tcpip) y, si hay Npcap
y permisos, una sonda ARP que pregunta «¿quién tiene mi IP?» y mira si contesta alguien con OTRA dirección física.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .common import IS_WINDOWS, powershell_json
from .devices import fmt_mac, norm_mac
from .netinfo import network_config

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
    """Pregunta por ARP quién tiene `ip`. Si contesta una MAC distinta de la nuestra, hay otro equipo con esa IP."""
    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore[attr-defined]  # import perezoso: es pesado

        conf.verb = 0
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=1)
        macs = sorted({norm_mac(r.hwsrc) for _s, r in answered})
    except Exception as e:  # noqa: BLE001 - sin Npcap, sin permisos o sin interfaz: la sonda no está disponible
        return {"ip": ip, "probed": False, "reason": f"No se pudo hacer la sonda ARP ({type(e).__name__}): hace falta Npcap y abrir Tracewell como administrador."}
    others = [fmt_mac(m) for m in macs if m != norm_mac(own_mac)]
    return {"ip": ip, "probed": True, "other_macs": others, "duplicate": bool(others)}


def check_duplicate_ip(probe: bool = True) -> Dict[str, Any]:
    config = network_config()
    probes: List[Dict[str, Any]] = []
    if probe:
        for a in config["adapters"]:
            if a["up"] and not a["loopback"] and not a["apipa"] and a["mac"]:
                for v4 in a["ipv4"]:
                    probes.append({"adapter": a["name"], **_arp_probe(v4["ip"], a["mac"])})
    conflicts = _windows_conflicts() if IS_WINDOWS else []
    duplicate = any(p.get("duplicate") for p in probes)
    if duplicate:
        summary = "¡Otro equipo está usando la misma IP que esta PC!"
    elif conflicts:
        summary = "Windows registró conflictos de IP en el pasado (mirá las fechas): puede haber pasado y resolverse."
    elif probes and all(p.get("probed") for p in probes):
        summary = "Nadie más contestó por la IP de esta PC: no se detectó duplicado."
    elif probes:
        summary = "No se pudo hacer la sonda ARP; solo se revisaron los avisos del sistema."
    else:
        summary = "Esta PC no tiene una IP válida para revisar."
    return {
        "summary": summary, "duplicate": duplicate, "probes": probes, "conflicts": conflicts,
        "advice": ("Cambiá la IP fija de uno de los dos equipos o reservá IPs distintas en el router (DHCP)." if duplicate else None),
    }
