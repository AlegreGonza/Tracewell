"""Dispositivos de la red local: quién está, su MAC, la marca (por la MAC) y su nombre.

Dos fuentes: la tabla ARP del equipo (lo que ya conoce) y, si se pide, un barrido de pings por la subred para que
conteste todo el que esté encendido. Solo MIRA: un ping por equipo, nada más.
"""
from __future__ import annotations

import csv
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Dict, List, Optional

from .common import IS_LINUX, IS_WINDOWS, run
from .netinfo import default_gateway, network_config

OUI_FILE = Path(__file__).resolve().parents[3] / "data" / "oui.csv"
MAX_SWEEP_HOSTS = 1024  # no se barre nada más grande que un /22
_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\S+)")
_oui_cache: Optional[Dict[str, str]] = None


def norm_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", mac.lower())


def fmt_mac(mac: str) -> str:
    h = norm_mac(mac)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_random_mac(mac: str) -> bool:
    """Bit «administrada localmente»: los teléfonos y PC modernos lo usan para una MAC privada que cambia por red."""
    h = norm_mac(mac)
    return len(h) == 12 and bool(int(h[1], 16) & 0b10)


def _load_oui() -> Dict[str, str]:
    """Base de fabricantes (IEEE) desde `data/oui.csv`, si existe. Formato del registro de la IEEE:
    Registry, Assignment (6 hex), Organization Name, Organization Address. Sin el archivo, no hay marcas."""
    global _oui_cache
    if _oui_cache is None:
        table: Dict[str, str] = {}
        try:
            with open(OUI_FILE, encoding="utf-8", errors="replace", newline="") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
                        table[row[1].strip().upper()] = row[2].strip()
        except OSError:
            pass
        _oui_cache = table
    return _oui_cache


def vendor_of(mac: str) -> Optional[str]:
    h = norm_mac(mac)
    return _load_oui().get(h[:6].upper()) if len(h) == 12 else None


def oui_available() -> bool:
    return bool(_load_oui())


def arp_table() -> List[Dict[str, str]]:
    """Pares IP/MAC que el equipo ya conoce (vecinos de la red local), sin multicast ni difusión."""
    entries: List[Dict[str, str]] = []
    if IS_WINDOWS:
        res = run(["arp", "-a"], timeout=10)
        for m in _ARP_LINE.finditer(res.out):
            ip, mac, kind = m.groups()
            mac_n = norm_mac(mac)
            if mac_n == "f" * 12 or mac_n.startswith("01005e") or mac_n.startswith("3333"):
                continue
            entries.append({"ip": ip, "mac": fmt_mac(mac), "kind": "estático" if kind.lower().startswith(("est", "stat")) else "dinámico"})
    elif IS_LINUX:
        res = run(["ip", "neigh"], timeout=10)
        for line in res.out.splitlines():
            parts = line.split()
            if "lladdr" in parts and parts[0].count(".") == 3:
                entries.append({"ip": parts[0], "mac": fmt_mac(parts[parts.index("lladdr") + 1]), "kind": parts[-1].lower()})
    return entries


def local_subnets(only_routed: bool = False) -> List[ipaddress.IPv4Network]:
    """Subredes privadas del equipo. Con `only_routed`, solo las de adaptadores con puerta de enlace: la red real,
    sin las virtuales de WSL, VirtualBox o Docker (que además harían el barrido eterno)."""
    out: List[ipaddress.IPv4Network] = []
    for a in network_config()["adapters"]:
        if not a["up"] or a["loopback"] or a["apipa"] or (only_routed and not a["gateway"]):
            continue
        for v4 in a["ipv4"]:
            try:
                net = ipaddress.IPv4Network(f"{v4['ip']}/{v4['mask']}", strict=False)
            except (ValueError, TypeError):
                continue
            if net.num_addresses > MAX_SWEEP_HOSTS:  # red grande: solo el /24 propio
                net = ipaddress.IPv4Network(f"{v4['ip']}/24", strict=False)
            if net not in out and net.is_private:
                out.append(net)
    return out


def _ping_once(ip: str) -> None:
    cmd = ["ping", "-n", "1", "-w", "400", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    run(cmd, timeout=4)


def sweep(nets: List[ipaddress.IPv4Network]) -> int:
    """Un ping a cada dirección de las subredes para que el sistema aprenda la MAC de quien conteste. Devuelve cuántas."""
    hosts = [str(h) for n in nets for h in n.hosts()][:MAX_SWEEP_HOSTS]
    with ThreadPoolExecutor(max_workers=128) as pool:
        list(pool.map(_ping_once, hosts))
    return len(hosts)


def _hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def _resolve_names(ips: List[str]) -> Dict[str, Optional[str]]:
    """Nombres por DNS inverso en paralelo y con tope de tiempo: un equipo que no contesta no cuelga la pantalla."""
    names: Dict[str, Optional[str]] = {ip: None for ip in ips}
    pool = ThreadPoolExecutor(max_workers=16)
    futures = {ip: pool.submit(_hostname, ip) for ip in ips}
    for ip, fut in futures.items():
        try:
            names[ip] = fut.result(timeout=2.5)
        except (FutureTimeout, OSError):
            names[ip] = None
    pool.shutdown(wait=False, cancel_futures=True)
    return names


def list_devices(scan: bool = False) -> Dict[str, Any]:
    """Dispositivos de la red local. Con `scan` hace primero el barrido de pings (tarda unos segundos)."""
    config = network_config()
    nets = local_subnets()
    swept = sweep(local_subnets(only_routed=True)) if scan and nets else 0
    mine = {v["ip"] for a in config["adapters"] for v in a["ipv4"]}
    own_macs = {norm_mac(a["mac"]): a["name"] for a in config["adapters"] if a["mac"]}
    gateway = default_gateway(config)
    entries = [e for e in arp_table() if any(ipaddress.ip_address(e["ip"]) in n for n in nets)] if nets else arp_table()
    names = _resolve_names([e["ip"] for e in entries])
    devices: List[Dict[str, Any]] = []
    for e in sorted(entries, key=lambda e: ipaddress.ip_address(e["ip"])):
        rnd = is_random_mac(e["mac"])
        devices.append({
            "ip": e["ip"], "mac": e["mac"], "vendor": None if rnd else vendor_of(e["mac"]), "random_mac": rnd,
            "hostname": names.get(e["ip"]), "is_gateway": e["ip"] == gateway, "is_self": e["ip"] in mine or norm_mac(e["mac"]) in own_macs,
        })
    # El propio equipo no aparece en su tabla ARP: se agrega para que la lista esté completa.
    for a in config["adapters"]:
        if a["up"] and not a["loopback"] and a["mac"] and not a["apipa"]:
            for v4 in a["ipv4"]:
                if not any(d["ip"] == v4["ip"] for d in devices) and any(ipaddress.ip_address(v4["ip"]) in n for n in nets):
                    rnd = is_random_mac(a["mac"])
                    devices.append({"ip": v4["ip"], "mac": fmt_mac(a["mac"]), "vendor": None if rnd else vendor_of(a["mac"]), "random_mac": rnd,
                                    "hostname": config["hostname"], "is_gateway": False, "is_self": True})
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return {
        "devices": devices, "scanned": scan, "swept_hosts": swept, "subnets": [str(n) for n in nets],
        "vendor_db": oui_available(),
    }
