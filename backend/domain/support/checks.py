"""Pruebas de conectividad: ¿hay Internet?, latencia, ping, traceroute, puertos, RDP y diferencia de hora.

Todas LEEN o MIDEN: abren conexiones o mandan un ping y cuentan lo que pasó. Ninguna cambia nada en el equipo.
"""
from __future__ import annotations

import re
import socket
import statistics
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from backend.domain.pcap.layers import SERVICES

from .common import IS_WINDOWS, run, valid_host, valid_port
from .netinfo import default_gateway, network_config

TCP_TIMEOUT = 2.0
INTERNET_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 443))
DNS_PROBES = ("www.google.com", "one.one.one.one", "www.microsoft.com")  # alcanza con que UNO resuelva: un solo nombre da falsos positivos
TIME_SERVERS = ("time.windows.com", "pool.ntp.org", "time.cloudflare.com")
MAX_PORTS = 20
PING_COUNT = 3  # pings a la puerta de enlace en «¿hay Internet?»
DNS_SLOW_MS = 1500  # más que esto, el DNS se marca como lento
_TIMES = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


# ------------------------------------------------------------------ piezas básicas

def tcp_connect(host: str, port: int, timeout: float = TCP_TIMEOUT) -> Dict[str, Any]:
    """Abre una conexión TCP y la cierra. `state`: abierto | cerrado (rechazó) | sin_respuesta | error."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except ConnectionRefusedError:
        return {"ok": False, "state": "cerrado", "ms": None, "error": "el equipo rechazó la conexión"}
    except socket.timeout:
        return {"ok": False, "state": "sin_respuesta", "ms": None, "error": "no respondió a tiempo"}
    except OSError as e:
        return {"ok": False, "state": "error", "ms": None, "error": str(e)}
    return {"ok": True, "state": "abierto", "ms": round((time.perf_counter() - t0) * 1000, 1), "error": None}


def resolve(name: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Resuelve un nombre con el DNS del sistema. `getaddrinfo` no tiene tiempo límite: se corre en un hilo aparte."""
    box: Dict[str, Any] = {}

    def work() -> None:
        try:
            box["addrs"] = sorted({r[4][0] for r in socket.getaddrinfo(name, None)})
        except OSError as e:
            box["error"] = str(e)

    t0 = time.perf_counter()
    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    if th.is_alive():
        return {"ok": False, "ms": None, "addresses": [], "error": "el DNS no respondió a tiempo"}
    if "addrs" in box:
        return {"ok": True, "ms": ms, "addresses": box["addrs"][:6], "error": None}
    return {"ok": False, "ms": None, "addresses": [], "error": box.get("error", "no se pudo resolver")}


def _min_max_avg(times: List[float]) -> Dict[str, Optional[float]]:
    """Mínimo, máximo y promedio (1 decimal) de unos tiempos en ms; todo None si no hay ninguno."""
    if not times:
        return {"min": None, "max": None, "avg": None}
    return {"min": min(times), "max": max(times), "avg": round(statistics.fmean(times), 1)}


def ping(host: str, count: int = 4) -> Dict[str, Any]:
    """Ping con el comando del sistema. Las respuestas se cuentan por la línea que trae `TTL=`, que es igual en
    cualquier idioma (el texto «tiempo»/«time» cambia, el TTL no)."""
    host = valid_host(host)
    count = max(1, min(int(count), 20))
    cmd = ["ping", "-n", str(count), "-w", "1500", host] if IS_WINDOWS else ["ping", "-c", str(count), "-W", "2", host]
    res = run(cmd, timeout=count * 3 + 5)
    if res.missing:
        return {"available": False, "host": host, "reason": "No se encontró el comando ping en este equipo."}
    times: List[float] = []
    received = 0
    for line in res.out.splitlines():
        if "ttl=" in line.lower():
            received += 1
            m = _TIMES.search(line)
            if m:
                times.append(float(m.group(1).replace(",", ".")))
            elif "<" in line:
                times.append(0.5)  # «tiempo<1ms»
    return {
        "available": True, "host": host, "sent": count, "received": received,
        "loss_pct": round(100 * (count - received) / count, 1), "times": times, **_min_max_avg(times),
        "timed_out": res.timed_out,
    }


# ------------------------------------------------------------------ ¿hay Internet?

def _adapter_step(config: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Primer paso: ¿hay un adaptador con IP válida? Devuelve el paso y si hay red local (IP que no sea 169.254)."""
    live = [a for a in config["adapters"] if a["up"] and not a["loopback"] and a["ipv4"]]
    apipa = [a for a in live if a["apipa"]]
    good = [a for a in live if not a["apipa"]]
    if good:
        a = good[0]
        return _step("adapter", "Adaptador de red", True, f"{a['name']} con IP {a['ipv4'][0]['ip']}"), True
    if apipa:
        return _step("adapter", "Adaptador de red", False,
                     f"{apipa[0]['name']} tiene una IP 169.254.x.x: no consiguió IP del router (DHCP)."), False
    return _step("adapter", "Adaptador de red", False, "No hay ningún adaptador conectado con IP."), False


def _gateway_step(config: Dict[str, Any], has_network: bool) -> Dict[str, Any]:
    title = "Puerta de enlace (el router)"
    gw = default_gateway(config) if has_network else None
    if not gw:
        return _step("gateway", title, False if has_network else None,
                     "No se encontró una puerta de enlace." if has_network else "Se omite: no hay red local.")
    p = ping(gw, PING_COUNT)
    ok = p.get("received", 0) > 0
    return _step("gateway", title, ok, f"{gw}: respondió ({p['avg']} ms)" if ok else f"{gw}: no respondió al ping", ms=p.get("avg"))


def _internet_step() -> Dict[str, Any]:
    probes = [(h, tcp_connect(h, port)) for h, port in INTERNET_PROBES]
    reachable = [(h, r) for h, r in probes if r["ok"]]
    if reachable:
        host, r = reachable[0]
        return _step("internet", "Internet (por dirección IP)", True, f"{host}: conectó en {r['ms']} ms", ms=r["ms"])
    hosts = " ni a ".join(h for h, _port in INTERNET_PROBES)
    return _step("internet", "Internet (por dirección IP)", False, f"No se pudo conectar a {hosts}.", ms=None)


def _dns_step() -> Dict[str, Any]:
    """Alcanza con que UN nombre resuelva; si ninguno lo hace, se informa el error del último intento."""
    dns: Dict[str, Any] = {"ok": False, "ms": None, "addresses": [], "error": "no se pudo resolver"}
    name = DNS_PROBES[0]
    for name in DNS_PROBES:
        dns = resolve(name)
        if dns["ok"]:
            break
    slow = dns["ok"] and dns["ms"] is not None and dns["ms"] > DNS_SLOW_MS
    return _step("dns", "DNS (traducir nombres)", dns["ok"],
                 (f"{name} → {dns['addresses'][0]}" + (" (responde lento)" if slow else "")) if dns["ok"]
                 else f"No se pudo resolver {', '.join(DNS_PROBES)}: {dns['error']}", ms=dns["ms"])


def internet_check() -> Dict[str, Any]:
    """Revisa capa por capa (adaptador → puerta de enlace → Internet por IP → DNS) y dice dónde se corta.

    Contacta a 1.1.1.1 y 8.8.8.8 (solo abre y cierra una conexión TCP) y le pide a tu DNS la dirección de unos sitios conocidos.
    """
    config = network_config()
    adapter, has_network = _adapter_step(config)
    steps = [adapter, _gateway_step(config, has_network), _internet_step(), _dns_step()]
    return {"steps": steps, **_verdict(steps)}


def _step(code: str, title: str, ok: Optional[bool], detail: str, ms: Optional[float] = None) -> Dict[str, Any]:
    return {"code": code, "title": title, "ok": ok, "detail": detail, "ms": ms}


def _fix(windows: str, linux: str) -> str:
    return windows if IS_WINDOWS else linux


def _verdict(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """El primer paso que falla marca dónde se corta. Los comandos son SOLO texto: Tracewell no los ejecuta."""
    by = {s["code"]: s for s in steps}
    if by["adapter"]["ok"] is False:
        apipa = "169.254" in by["adapter"]["detail"]
        return {
            "ok": False, "layer": "adaptador",
            "summary": ("La PC no consiguió una IP del router (quedó con 169.254.x.x)." if apipa
                        else "La PC no está conectada a ninguna red."),
            "advice": ("Revisá el cable o el Wi-Fi y que el router tenga DHCP activo. Después podés pedir una IP nueva."
                       if apipa else "Revisá el cable de red o conectate al Wi-Fi."),
            "command": _fix("ipconfig /release && ipconfig /renew", "sudo dhclient -r && sudo dhclient") if apipa else None,
        }
    if by["gateway"]["ok"] is False:
        return {"ok": False, "layer": "red local",
                "summary": "La PC tiene IP pero no llega al router.",
                "advice": "El problema está entre tu equipo y el router: cable flojo, señal de Wi-Fi mala o router colgado. Probá reiniciar el router.",
                "command": None}
    if by["internet"]["ok"] is False:
        return {"ok": False, "layer": "internet",
                "summary": "El router responde, pero no hay salida a Internet.",
                "advice": "Lo más probable es una caída del proveedor (ISP) o del módem. Reiniciá el módem y, si sigue igual, llamá al proveedor.",
                "command": None}
    if by["dns"]["ok"] is False:
        return {"ok": False, "layer": "dns",
                "summary": "Hay Internet por IP, pero no se traducen los nombres (DNS).",
                "advice": "Falla el servidor DNS que usa tu PC. Probá limpiar la caché de DNS o usar otro servidor, como 1.1.1.1.",
                "command": _fix("ipconfig /flushdns", "resolvectl flush-caches")}
    return {"ok": True, "layer": None, "summary": "Todo funciona: hay red local, Internet y DNS.", "advice": None, "command": None}


# ------------------------------------------------------------------ latencia

def latency_test(host: str = "1.1.1.1", port: int = 443, samples: int = 8) -> Dict[str, Any]:
    """Latencia medida con el tiempo de abrir conexiones TCP (se parece al ping y funciona aunque el ICMP esté
    bloqueado). Contacta a `host:port`. Además hace un ping corto al router para separar «mi red» de «Internet»."""
    host, port = valid_host(host), valid_port(port)
    samples = max(3, min(int(samples), 30))
    times: List[float] = []
    failed = 0
    for _ in range(samples):
        r = tcp_connect(host, port, 2.0)
        if r["ok"]:
            times.append(r["ms"])
        else:
            failed += 1
        time.sleep(0.15)
    jitter = statistics.fmean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else None
    gw = default_gateway()
    router = ping(gw, 4) if gw else None
    return {
        "host": host, "port": port, "samples": samples, "failed": failed, "times": times, **_min_max_avg(times),
        "jitter": round(jitter, 1) if jitter is not None else None,
        "router": ({"host": gw, "avg": router["avg"], "loss_pct": router["loss_pct"]} if router and router.get("available") else None),
    }


# ------------------------------------------------------------------ traceroute

_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F:]+)")


def traceroute(host: str, max_hops: int = 20) -> Dict[str, Any]:
    """Los saltos hasta un destino (tracert / traceroute). Puede tardar hasta un minuto si hay saltos sin respuesta."""
    host = valid_host(host)
    max_hops = max(1, min(int(max_hops), 30))
    cmd = (["tracert", "-d", "-h", str(max_hops), "-w", "800", host] if IS_WINDOWS
           else ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host])
    res = run(cmd, timeout=90)
    if res.missing:
        return {"available": False, "host": host, "reason": "No se encontró el comando " + cmd[0] + ("" if IS_WINDOWS else " (instalalo con tu gestor de paquetes, por ejemplo `sudo apt install traceroute`).")}
    hops: List[Dict[str, Any]] = []
    for line in res.out.splitlines():
        m = _HOP.match(line)
        if not m:
            continue
        rest = m.group(2)
        hops.append({
            "n": int(m.group(1)), "ips": list(dict.fromkeys(_IP.findall(rest))),
            "times": [float(t.replace(",", ".")) if t != "<1" else 0.5 for t in re.findall(r"(<1|\d+(?:[.,]\d+)?)\s*ms", rest)],
            "timeouts": rest.count("*"),
        })
    return {"available": True, "host": host, "hops": hops, "timed_out": res.timed_out}


# ------------------------------------------------------------------ puertos y RDP

def port_check(host: str, ports: List[int]) -> Dict[str, Any]:
    """Prueba qué puertos TCP de un equipo aceptan conexiones. Máximo 20 a la vez."""
    host = valid_host(host)
    clean = list(dict.fromkeys(valid_port(p) for p in ports))[:MAX_PORTS]
    if not clean:
        raise ValueError("indicá al menos un puerto")
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda p: (p, tcp_connect(host, p, 3.0)), clean))  # Windows tarda ~2 s en admitir que un puerto local está cerrado
    return {"host": host, "results": [
        {"port": p, "service": SERVICES.get(p), "state": r["state"], "ms": r["ms"], "detail": r["error"]} for p, r in results
    ]}


_NEG_FAILURES = {
    1: "El servidor exige TLS (SSL).", 2: "El servidor no admite TLS.", 3: "El servidor no tiene certificado.",
    4: "Banderas inconsistentes.", 5: "El servidor exige autenticación a nivel de red (NLA).",
    6: "TLS con autenticación de usuario requerida.",
}
_NEG_SELECTED = {
    0: "RDP clásico, sin NLA ni TLS (el más débil).", 1: "TLS, sin NLA.", 2: "NLA (CredSSP): pide usuario y contraseña antes de abrir la sesión.",
    8: "NLA con autenticación temprana.",
}


def rdp_check(host: str, port: int = 3389) -> Dict[str, Any]:
    """Comprueba que un equipo ofrezca RDP y qué seguridad pide. Manda UNA solicitud de conexión y se corta: no
    intenta iniciar sesión ni prueba usuarios ni contraseñas."""
    host, port = valid_host(host), valid_port(port)
    # TPKT (3, largo 19) + X.224 «Connection Request» + RDP_NEG_REQ pidiendo TLS, NLA y NLA temprana (0x0b).
    request = bytes.fromhex("03000013") + bytes.fromhex("0ee00000000000") + bytes.fromhex("010008000b000000")
    base = {"host": host, "port": port}
    try:
        with socket.create_connection((host, port), timeout=3.0) as s:
            s.settimeout(3.0)
            s.sendall(request)
            data = s.recv(64)
    except ConnectionRefusedError:
        return {**base, "state": "cerrado", "summary": "El equipo rechazó la conexión: el puerto está cerrado o RDP está desactivado."}
    except socket.timeout:
        return {**base, "state": "sin_respuesta", "summary": "No respondió a tiempo: apagado, otro puerto o un firewall lo bloquea."}
    except OSError as e:
        return {**base, "state": "error", "summary": f"No se pudo conectar: {e}"}
    if len(data) < 11 or data[0] != 3 or data[5] != 0xD0:
        return {**base, "state": "no_rdp", "summary": "Algo contestó en ese puerto, pero no parece RDP."}
    neg = data[11:19]
    if len(neg) >= 8 and neg[0] == 0x02:
        selected = struct.unpack("<I", neg[4:8])[0]
        return {**base, "state": "rdp", "nla": selected in (2, 8), "protocol": selected,
                "summary": "RDP disponible. " + _NEG_SELECTED.get(selected, f"Seguridad elegida: {selected}.")}
    if len(neg) >= 8 and neg[0] == 0x03:
        code = struct.unpack("<I", neg[4:8])[0]
        return {**base, "state": "rdp", "nla": code == 5, "protocol": None,
                "summary": "RDP disponible. " + _NEG_FAILURES.get(code, f"Rechazó la negociación (código {code}).")}
    return {**base, "state": "rdp", "nla": False, "protocol": 0, "summary": "RDP disponible (versión clásica, sin negociación de seguridad)."}


# ------------------------------------------------------------------ diferencia de hora

def time_offset(server: str = "time.windows.com") -> Dict[str, Any]:
    """Cuánto se aleja el reloj de esta PC de uno público (consulta SNTP). SOLO mide: no corrige la hora."""
    if server not in TIME_SERVERS:
        raise ValueError("servidor no permitido (usá " + ", ".join(TIME_SERVERS) + ")")
    packet = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3.0)
            t1 = time.time()
            s.sendto(packet, (server, 123))
            data, _ = s.recvfrom(256)
            t4 = time.time()
    except OSError as e:
        return {"available": False, "server": server, "reason": f"No se pudo consultar la hora: {e}"}
    if len(data) < 48:
        return {"available": False, "server": server, "reason": "Respuesta de hora incompleta."}
    secs, frac = struct.unpack("!II", data[40:48])
    server_time = secs - 2208988800 + frac / 2**32  # de 1900 (NTP) a 1970 (Unix)
    rtt = t4 - t1
    offset = server_time - (t1 + rtt / 2)
    verdict = ("Reloj en hora." if abs(offset) < 1 else
               "El reloj se desvió un poco." if abs(offset) < 5 else
               "El reloj está desfasado: puede causar errores de certificados y de inicio de sesión.")
    return {"available": True, "server": server, "offset_seconds": round(offset, 3), "round_trip_ms": round(rtt * 1000, 1), "summary": verdict,
            "command": None if abs(offset) < 1 else _fix("w32tm /resync", "sudo timedatectl set-ntp true")}
