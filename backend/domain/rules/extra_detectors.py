"""Detectores adicionales: beaconing, inundación SYN, puertos sospechosos, DNS a un
resolvedor no habitual y subidas grandes de datos.

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
from typing import Any, Deque, Dict, List, Tuple, Type

from backend.domain.rules import engine as _engine
from backend.domain.rules.engine import (
    TCP_ACK, TCP_SYN, Alert, Decoded, Detector, DnsSuspiciousDetector, _int_range, _LRU, _num_range, _port_list,
)

# Puertos de servicios que hablan a intervalos regulares de forma normal (DNS, NTP, mDNS, NetBIOS, SSDP, DHCP).
_REGULAR_PORTS = [53, 123, 5353, 137, 138, 1900, 67, 68]
# Resolvedores públicos conocidos: consultar DNS directamente a ellos no es raro.
_PUBLIC_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
]
_MAX_TRACKED_EVENTS = 200


def _is_pure_syn(d: Decoded) -> bool:
    """SYN sin ACK: intento de abrir una conexión."""
    return d.proto == 6 and bool(d.flags & TCP_SYN) and not d.flags & TCP_ACK


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
        return (_is_pure_syn(d) or d.proto == 17) and d.dport not in self.p["ignore_ports"]

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
        if not _is_pure_syn(d):
            return []
        key = (d.dst, d.dport)
        if key in self._alerted:
            return []
        recent: Deque[Tuple[float, str]] = self._seen.get(key) or deque(maxlen=self.p["min_syns"])
        recent.append((d.ts, d.src))
        self._seen[key] = recent
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
        if not _is_pure_syn(d) or d.dport not in self.p["ports"]:
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


DETECTORS: Dict[str, Type[Detector]] = {
    "beaconing": BeaconingDetector,
    "syn_flood": SynFloodDetector,
    "suspicious_ports": SuspiciousPortsDetector,
    "dns_unusual_resolver": DnsUnusualResolverDetector,
    "large_upload": LargeUploadDetector,
}

# Si este módulo se importó ANTES que engine, engine ya terminó de cargarse y no vio DETECTORS:
# se registran aquí. (Si engine se importó primero, ya lo hizo él y esto es inocuo.)
_engine.DETECTORS.update(DETECTORS)
