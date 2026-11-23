"""Detectores adicionales: beaconing, inundación SYN, puertos sospechosos, DNS a un
resolvedor no habitual subidas grandes de datos, fuerza bruta y la regla personalizada por umbral.

Mismas reglas que el resto: la REGLA es un YAML (umbral, severidad, MITRE) y el
DETECTOR es código chico. Cada detector guarda estado acotado (`_LRU`): un atacante
no puede hacer crecer la memoria con millones de pares distintos.

Registro: `engine.py` importa este módulo al final y suma `DETECTORS`; si alguien lo
importa primero, se registra solo al terminar de cargarse (ver el final del archivo).
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import deque
from typing import Deque, Dict, List, Tuple, Type

from backend.domain.rules import engine as _engine
from backend.domain.rules.engine import (
    Decoded, Detector, DnsSuspiciousDetector, _int_range, _LRU, _num_range, _port_list, is_pure_syn,
)

# Puertos de servicios que hablan a intervalos regulares de forma normal (DNS, NTP, mDNS, NetBIOS, SSDP, DHCP).
_REGULAR_PORTS = [53, 123, 5353, 137, 138, 1900, 67, 68]
# Resolvedores públicos conocidos: consultar DNS directamente a ellos no es raro.
_PUBLIC_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
]
_MAX_TRACKED_EVENTS = 200


def _push_recent(seen: _LRU, key, item, maxlen: int) -> Deque:
    """Agrega `item` a la ventana deslizante de `key` (últimos `maxlen`) y refresca su recencia."""
    recent = seen.get(key) or deque(maxlen=maxlen)
    recent.append(item)
    seen[key] = recent
    return recent


def _ports_or_empty(v):
    """Lista de puertos que puede estar vacía (`_port_list` exige al menos uno)."""
    if isinstance(v, list) and not v:
        return []
    return _port_list(v)


def _bool(v):
    if not isinstance(v, bool):
        raise ValueError(f"debe ser true o false, recibí {v!r}")
    return v


def _ip_list(v):
    """Lista (puede ser vacía) de direcciones IP; se normalizan."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de direcciones IP, recibí {v!r}")
    out = []
    for item in v:
        try:
            out.append(ipaddress.ip_address(str(item)).compressed)
        except ValueError:
            raise ValueError(f"no es una dirección IP: {item!r}") from None
    return out


def _is_external(ip_text: str) -> bool:
    """True si la IP es pública (ni privada, ni loopback, ni link-local, ni multicast)."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast  # is_global es verdadero para algunos rangos multicast


# ------------------------------------------------------------------ beaconing

class BeaconingDetector(Detector):
    """Conexiones (o datagramas) hacia un mismo destino a intervalos MUY regulares.

    Un malware que "llama a casa" suele hacerlo cada N segundos con poca variación.
    Se cuentan los intentos de conexión TCP (SYN) y los datagramas UDP; un humano o una
    app normal navegan de forma irregular. Se ignoran intervalos cortos (`min_interval_seconds`):
    un keep-alive de 1 segundo no es un beacon.
    """

    PARAMS = {
        "min_events": (_int_range(4, 1000), 8),
        "min_interval_seconds": (_num_range(0.1), 5.0),
        "max_jitter": (_num_range(0.0, 1.0), 0.15),  # desvío / promedio de los intervalos
        "ignore_ports": (_ports_or_empty, _REGULAR_PORTS),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._times = _LRU()  # (proto, origen, destino, puerto) -> instantes
        self._alerted = _LRU()

    def _is_event(self, d: Decoded) -> bool:
        return (is_pure_syn(d) or d.proto == 17) and d.dport not in self.p["ignore_ports"]

    def _record(self, key, ts: float) -> List[float]:
        times = self._times.get(key) or []
        times.append(ts)
        del times[:-_MAX_TRACKED_EVENTS]
        self._times[key] = times  # refresca la recencia
        return times

    def _regularity(self, times: List[float]) -> Tuple[float, float]:
        """(intervalo promedio, jitter) de los instantes dados."""
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(gaps)
        return mean, (statistics.pstdev(gaps) / mean if mean > 0 else float("inf"))

    def feed(self, d):
        if not self._is_event(d):
            return []
        key = (d.proto, d.src, d.dst, d.dport)
        if key in self._alerted:
            return []
        times = self._record(key, d.ts)
        if len(times) < self.p["min_events"]:
            return []
        mean, jitter = self._regularity(times)
        if mean < self.p["min_interval_seconds"] or jitter > self.p["max_jitter"]:
            return []
        self._alerted[key] = True
        return [self._alert(d, {
            "events": len(times), "mean_interval_seconds": round(mean, 2), "jitter": round(jitter, 3),
            "destination_port": d.dport, "protocol": "TCP" if d.proto == 6 else "UDP",
        }, ts=times[0])]


# ------------------------------------------------------------- inundación SYN

class SynFloodDetector(Detector):
    """Muchísimos SYN hacia un mismo destino y puerto en muy poco tiempo (denegación de servicio)."""

    PARAMS = {
        "min_syns": (_int_range(10, 1_000_000), 200),
        "window_seconds": (_num_range(0.001), 10.0),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._seen = _LRU()  # (destino, puerto) -> últimos SYN (instante, origen)
        self._alerted = _LRU()

    def feed(self, d):
        if not is_pure_syn(d):
            return []
        key = (d.dst, d.dport)
        if key in self._alerted:
            return []
        recent = _push_recent(self._seen, key, (d.ts, d.src), self.p["min_syns"])
        if len(recent) < self.p["min_syns"]:
            return []
        span = recent[-1][0] - recent[0][0]
        if span > self.p["window_seconds"]:
            return []  # los SYN más recientes no caben en la ventana
        self._alerted[key] = True
        return [self._alert(d, {
            "syn_packets": len(recent), "distinct_sources": len({src for _, src in recent}),
            "window_seconds": round(span, 3), "destination_port": d.dport,
        }, ts=recent[0][0])]


# --------------------------------------------------------- puertos sospechosos

class SuspiciousPortsDetector(Detector):
    """Intentos de conexión a puertos que usan herramientas de ataque o puertas traseras conocidas."""

    PARAMS = {"ports": (_port_list, [4444, 31337, 1337, 12345, 54321, 9001])}

    def __init__(self, rule):
        super().__init__(rule)
        self._alerted = _LRU()

    def feed(self, d):
        # Solo el SYN que inicia la conexión: las respuestas del servidor van al puerto efímero del
        # cliente, que podría coincidir por casualidad con uno de la lista.
        if not is_pure_syn(d) or d.dport not in self.p["ports"]:
            return []
        key = (d.src, d.dst, d.dport)
        if key in self._alerted:
            return []
        self._alerted[key] = True
        return [self._alert(d, {"port": d.dport, "source_port": d.sport})]


# ------------------------------------------------------ DNS a resolvedor raro

class DnsUnusualResolverDetector(Detector):
    """Consultas DNS enviadas directo a un servidor público que no está en la lista de conocidos.

    Un malware puede saltarse el resolvedor de la red y consultar su propio servidor. Los
    destinos privados (el router, el DNS de la empresa) se consideran normales.
    """

    PARAMS = {"allowed_resolvers": (_ip_list, _PUBLIC_RESOLVERS)}

    def __init__(self, rule):
        super().__init__(rule)
        self._allowed = frozenset(self.p["allowed_resolvers"])
        self._alerted = _LRU()

    def feed(self, d):
        if d.proto != 17 or d.dport != 53 or not d.payload or not _is_external(d.dst):
            return []
        if ipaddress.ip_address(d.dst).compressed in self._allowed:
            return []
        dns = DnsSuspiciousDetector._parse_query(d.payload)
        key = (d.src, d.dst)
        if dns is None or not dns.qd or key in self._alerted:
            return []
        self._alerted[key] = True
        return [self._alert(d, {"resolver": d.dst, "first_query": dns.qd[0].name.lower(), "qtype": dns.qd[0].type})]


# ------------------------------------------------------------- subidas grandes

class LargeUploadDetector(Detector):
    """Mucho más tráfico saliente que entrante hacia un mismo destino externo (posible exfiltración)."""

    PARAMS = {
        "min_bytes": (_int_range(1_000, 10**12), 10_000_000),
        "min_ratio": (_num_range(1.0), 5.0),
        "external_only": (_bool, True),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._sent = _LRU()  # (origen, destino) -> bytes de datos enviados
        self._alerted = _LRU()

    def feed(self, d):
        size = len(d.payload)
        if not size:
            return []
        key = (d.src, d.dst)
        total = self._sent.get(key, 0) + size
        self._sent[key] = total
        if total < self.p["min_bytes"] or key in self._alerted:
            return []
        if self.p["external_only"] and not _is_external(d.dst):
            return []
        back = self._sent.get((d.dst, d.src), 0)
        if total < self.p["min_ratio"] * max(back, 1):
            return []
        self._alerted[key] = True
        return [self._alert(d, {
            "bytes_sent": total, "bytes_received": back, "ratio": round(total / max(back, 1), 1),
            "destination_port": d.dport,
        })]


# --------------------------------------------------------------- fuerza bruta

class BruteForceDetector(Detector):
    """Muchos intentos de conexión de una misma IP a SSH (22) o RDP (3389) en poco tiempo.

    Cada intento de iniciar sesión abre una conexión nueva: se cuentan los SYN puros de un origen hacia
    un mismo destino y puerto. Un usuario normal abre pocas; un programa que prueba contraseñas, decenas.
    Es una pista: no mira si el inicio de sesión falló (el tráfico va cifrado).
    """

    PARAMS = {
        "min_attempts": (_int_range(3, 100_000), 10),
        "window_seconds": (_num_range(0.001), 60.0),
        "ports": (_port_list, [22, 3389]),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._seen = _LRU()  # (origen, destino, puerto) -> instantes de los últimos intentos
        self._alerted = _LRU()

    def feed(self, d):
        if not is_pure_syn(d) or d.dport not in self.p["ports"]:
            return []
        key = (d.src, d.dst, d.dport)
        if key in self._alerted:
            return []
        recent = _push_recent(self._seen, key, d.ts, self.p["min_attempts"])
        if len(recent) < self.p["min_attempts"]:
            return []
        span = recent[-1] - recent[0]
        if span > self.p["window_seconds"]:
            return []  # los intentos más recientes no caben en la ventana
        self._alerted[key] = True
        return [self._alert(d, {
            "service": "SSH" if d.dport == 22 else "RDP" if d.dport == 3389 else f"puerto {d.dport}",
            "destination_port": d.dport, "attempts": len(recent),
            "window_seconds": round(span, 3), "threshold": self.p["min_attempts"],
        }, ts=recent[0])]


# ------------------------------------------------------ regla personalizada

_PROTOCOLS = {"any": None, "tcp": 6, "udp": 17}


def _protocol(v):
    if not isinstance(v, str) or v.lower() not in _PROTOCOLS:
        raise ValueError(f"debe ser uno de {sorted(_PROTOCOLS)}, recibí {v!r}")
    return v.lower()


def _ip_or_network(v):
    """IP o red CIDR (texto); vacío = cualquiera. Se devuelve normalizado."""
    if v in (None, ""):
        return ""
    try:
        return str(ipaddress.ip_network(str(v).strip(), strict=False))
    except ValueError:
        raise ValueError(f"no es una IP ni una red CIDR: {v!r}") from None


def _port_or_zero(v):
    """Puerto de destino 1..65535; 0 = cualquiera."""
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 65535:
        raise ValueError(f"debe ser un entero entre 0 y 65535 (0 = cualquiera), recibí {v!r}")
    return v


def _in_network(ip_text: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text) in ipaddress.ip_network(network)
    except ValueError:  # versión de IP distinta o texto raro
        return False


class ThresholdDetector(Detector):
    """Regla creada por el analista: N eventos que cumplen un filtro en una ventana de tiempo.

    Filtro: protocolo, red/IP de origen, red/IP de destino y puerto de destino (todo opcional).
    En TCP se cuentan los intentos de conexión (SYN puros); en UDP y `any`, cada paquete.
    Se cuenta por par origen -> destino y se alerta una vez por par.
    """

    PARAMS = {
        "protocol": (_protocol, "any"),
        "src_ip": (_ip_or_network, ""),
        "dst_ip": (_ip_or_network, ""),
        "port": (_port_or_zero, 0),
        "min_events": (_int_range(2, 1_000_000), 20),
        "window_seconds": (_num_range(0.001), 60.0),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._seen = _LRU()
        self._alerted = _LRU()

    def _matches(self, d: Decoded) -> bool:
        p = self.p
        wanted = _PROTOCOLS[p["protocol"]]
        if wanted is not None and d.proto != wanted:
            return False
        if d.proto == 6 and not is_pure_syn(d):
            return False
        if p["port"] and d.dport != p["port"]:
            return False
        if p["src_ip"] and not _in_network(d.src, p["src_ip"]):
            return False
        return not (p["dst_ip"] and not _in_network(d.dst, p["dst_ip"]))

    def feed(self, d):
        if not self._matches(d):
            return []
        key = (d.src, d.dst)
        if key in self._alerted:
            return []
        recent = _push_recent(self._seen, key, d.ts, self.p["min_events"])
        if len(recent) < self.p["min_events"]:
            return []
        span = recent[-1] - recent[0]
        if span > self.p["window_seconds"]:
            return []
        self._alerted[key] = True
        return [self._alert(d, {
            "events": len(recent), "window_seconds": round(span, 3), "threshold": self.p["min_events"],
            "protocol": self.p["protocol"], "destination_port": d.dport,
        }, ts=recent[0])]


DETECTORS: Dict[str, Type[Detector]] = {
    "beaconing": BeaconingDetector,
    "syn_flood": SynFloodDetector,
    "suspicious_ports": SuspiciousPortsDetector,
    "dns_unusual_resolver": DnsUnusualResolverDetector,
    "large_upload": LargeUploadDetector,
    "brute_force": BruteForceDetector,
    "threshold": ThresholdDetector,
}

# Si este módulo se importó ANTES que engine, engine ya terminó de cargarse y no vio DETECTORS:
# se registran aquí. (Si engine se importó primero, ya lo hizo él y esto es inocuo.)
_engine.DETECTORS.update(DETECTORS)
