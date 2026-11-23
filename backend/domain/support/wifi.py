"""Wi-Fi: estado de la conexión actual (señal, canal, velocidad) e historial de conexiones."""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

from .common import IS_LINUX, IS_WINDOWS, powershell_json, run

# Nombre del campo (sin acentos, en minúscula) → clave interna. Español e inglés.
_KEYS = {
    "name": "interface", "nombre": "interface", "state": "state", "estado": "state", "ssid": "ssid", "bssid": "bssid",
    "radio type": "radio", "tipo de radio": "radio", "authentication": "auth", "autenticacion": "auth",
    "channel": "channel", "canal": "channel", "band": "band", "banda": "band", "signal": "signal", "senal": "signal",
    "receive rate (mbps)": "rx", "velocidad de recepcion (mbps)": "rx",
    "transmit rate (mbps)": "tx", "velocidad de transmision (mbps)": "tx",
}
_EVENT_KIND = {8001: "conectado", 8002: "falló la conexión", 8003: "desconectado"}


def _plain(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).strip().lower()


def quality(signal: Optional[int]) -> Optional[str]:
    if signal is None:
        return None
    return "buena" if signal >= 70 else "regular" if signal >= 40 else "débil"


def parse_netsh(text: str) -> Optional[Dict[str, Any]]:
    """Convierte la salida de `netsh wlan show interfaces` en un diccionario."""
    info: Dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        canon = _KEYS.get(_plain(key))
        if canon and canon not in info:
            info[canon] = value.strip()
    if not info:
        return None
    for numeric in ("signal", "channel", "rx", "tx"):
        m = re.search(r"\d+(?:[.,]\d+)?", str(info.get(numeric, "")))
        info[numeric] = (int(float(m.group(0).replace(",", "."))) if m else None)
    return info


def _status_windows() -> Dict[str, Any]:
    res = run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    if res.missing:
        return {"available": False, "reason": "No se encontró `netsh` en este equipo."}
    info = parse_netsh(res.out)
    if info is None:
        return {"available": False, "reason": "No hay un adaptador Wi-Fi activo (o Windows no deja leerlo sin el permiso de ubicación).", "raw": res.out.strip()[:2000]}
    connected = bool(info.get("ssid")) and _plain(str(info.get("state", ""))) in ("connected", "conectado")
    return {"available": True, "connected": connected, "quality": quality(info.get("signal")), **info}


def _split_nmcli(line: str) -> List[str]:
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]


def _status_linux() -> Dict[str, Any]:
    res = run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY", "dev", "wifi"], timeout=10)
    if res.missing:
        return {"available": False, "reason": "No se encontró `nmcli` (NetworkManager); no se puede leer el Wi-Fi."}
    for line in res.out.splitlines():
        parts = _split_nmcli(line)
        if len(parts) >= 7 and parts[0].strip() == "*":
            signal = int(parts[5]) if parts[5].isdigit() else None
            chan = int(parts[3]) if parts[3].isdigit() else None
            rate = re.search(r"\d+", parts[4])
            return {"available": True, "connected": True, "ssid": parts[1], "bssid": parts[2], "channel": chan, "signal": signal,
                    "rx": int(rate.group(0)) if rate else None, "tx": None, "auth": parts[6], "state": "conectado",
                    "quality": quality(signal), "band": None, "radio": None, "interface": None}
    return {"available": True, "connected": False, "reason": "El Wi-Fi no está conectado a ninguna red."}


def wifi_status() -> Dict[str, Any]:
    if IS_WINDOWS:
        return _status_windows()
    if IS_LINUX:
        return _status_linux()
    return {"available": False, "reason": "La lectura de Wi-Fi solo está disponible en Windows y Linux."}


_HISTORY_SCRIPT = (
    "try { $e = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001,8002,8003} "
    "-MaxEvents 300 -ErrorAction Stop | ForEach-Object { [pscustomobject]@{t=$_.TimeCreated.ToString('o'); id=[int]$_.Id; "
    "m=(([string]$_.Message -split \"`n\")[0]).Trim()} }); ConvertTo-Json -InputObject $e -Compress } "
    "catch { ConvertTo-Json -InputObject @{error=$_.Exception.Message} -Compress }"
)


def wifi_history(limit: int = 100) -> Dict[str, Any]:
    """Conexiones y desconexiones de Wi-Fi que Windows anotó (más recientes primero)."""
    if not IS_WINDOWS:
        return {"available": False, "reason": "El historial de Wi-Fi solo se lee en Windows (registro de eventos WLAN-AutoConfig)."}
    data = powershell_json(_HISTORY_SCRIPT, timeout=30)
    if isinstance(data, dict):
        if data.get("error"):
            return {"available": False, "reason": "Windows no dejó leer el historial de Wi-Fi (puede faltar el permiso de administrador o el registro estar desactivado)."}
        data = [data]
    if data is None:
        return {"available": False, "reason": "No se pudo leer el registro de eventos de Windows."}
    events = [{"time": d.get("t"), "kind": _EVENT_KIND.get(int(d.get("id") or 0), "evento"), "message": d.get("m")} for d in data if isinstance(d, dict)]
    events = events[: max(1, min(limit, 300))]
    return {"available": True, "events": events, "disconnections": sum(1 for e in events if e["kind"] == "desconectado")}
