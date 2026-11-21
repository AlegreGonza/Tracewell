"""Tabla de DNS: qué nombres se consultaron, cuántas veces, qué respondieron y qué salió mal.

Es el equivalente simple del `dns.log` de Zeek (o de filtrar `dns` en Wireshark): una fila por nombre y
tipo de consulta (A, AAAA, MX...). Sirve para ver de un vistazo a qué se conectó un equipo, qué nombres
NO existen (NXDOMAIN) y qué nombres parecen generados al azar.

Límites (conscientes): una fila por (nombre, tipo) con topes (`MAX_ENTRIES`, listas cortas) para acotar la
memoria; solo DNS sobre UDP (el DNS sobre TCP, DoH y DoT no se ven aquí).
"""
from __future__ import annotations

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dpkt

MAX_ENTRIES = 20_000
MAX_LIST = 8  # respuestas y clientes que se recuerdan por fila
RANDOM_ENTROPY = 3.5  # bits por carácter del primer label a partir de los cuales "parece aleatorio"
RANDOM_MIN_LABEL = 20

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class DnsEntry:
    name: str
    qtype: str
    queries: int = 0
    responses: int = 0
    rcodes: Counter = field(default_factory=Counter)
    answers: List[str] = field(default_factory=list)
    clients: List[str] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0
    min_ttl: Optional[int] = None


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _add_unique(items: List[str], value: str) -> None:
    if value and value not in items and len(items) < MAX_LIST:
        items.append(value)


class DnsLog:
    def __init__(self) -> None:
        self.entries: Dict[Tuple[str, str], DnsEntry] = {}
        self.dropped = 0  # filas que no entraron por el tope

    def add(self, ts: float, src_ip: str, dst_ip: str, payload: bytes) -> None:
        """Anota una consulta o una respuesta DNS (cualquier otra cosa se ignora)."""
        try:
            dns = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError, UnicodeError):
            return
        if not dns.qd:
            return
        name = str(dns.qd[0].name).strip().lower().rstrip(".")
        if not name or len(name) > 253 or not name.isprintable():
            return
        entry = self._entry(name, QTYPES.get(dns.qd[0].type, str(dns.qd[0].type)))
        if entry is None:
            return
        entry.first_ts = ts if entry.queries + entry.responses == 0 else min(entry.first_ts, ts)
        entry.last_ts = max(entry.last_ts, ts)
        if dns.qr == dpkt.dns.DNS_Q:
            entry.queries += 1
            _add_unique(entry.clients, src_ip)
        else:
            self._add_response(entry, dns, dst_ip)

    def _entry(self, name: str, qtype: str) -> Optional[DnsEntry]:
        key = (name, qtype)
        if key not in self.entries:
            if len(self.entries) >= MAX_ENTRIES:
                self.dropped += 1
                return None
            self.entries[key] = DnsEntry(name, qtype)
        return self.entries[key]

    @staticmethod
    def _add_response(entry: DnsEntry, dns, client_ip: str) -> None:
        entry.responses += 1
        entry.rcodes[RCODES.get(dns.rcode, str(dns.rcode))] += 1
        _add_unique(entry.clients, client_ip)
        for rr in dns.an:
            ttl = getattr(rr, "ttl", None)
            if isinstance(ttl, int):
                entry.min_ttl = ttl if entry.min_ttl is None else min(entry.min_ttl, ttl)
            for attr in ("ip", "ip6"):
                raw = getattr(rr, attr, None)
                if isinstance(raw, bytes):
                    try:
                        _add_unique(entry.answers, ipaddress.ip_address(raw).compressed)
                    except ValueError:
                        continue  # un registro con una dirección de largo inválido (paquete raro o hostil) se ignora
            if getattr(rr, "cname", None):
                _add_unique(entry.answers, str(rr.cname).lower().rstrip("."))

    # ------------------------------------------------------------ consulta

    @staticmethod
    def hints(entry: DnsEntry) -> List[str]:
        """Pistas en lenguaje simple (orientativas): por qué esta fila merece una mirada."""
        hints = []
        if entry.rcodes.get("NXDOMAIN"):
            hints.append("El nombre no existe (NXDOMAIN). Muchos seguidos pueden ser malware probando dominios al azar.")
        label = entry.name.split(".")[0]
        if len(label) >= RANDOM_MIN_LABEL and _entropy(label) >= RANDOM_ENTROPY:
            hints.append("El nombre parece generado al azar (posible DGA o túnel DNS).")
        if entry.min_ttl is not None and entry.min_ttl <= 30:
            hints.append("TTL muy bajo: la respuesta cambia seguido (típico de CDN, pero también de infraestructura maliciosa).")
        return hints

    def rows(self, query: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Filas serializables, de más a menos actividad. `query` filtra por texto en el nombre."""
        q = (query or "").strip().lower()
        chosen = [e for e in self.entries.values() if not q or q in e.name]
        chosen.sort(key=lambda e: (-(e.queries + e.responses), e.name))
        return [
            {
                "name": e.name, "qtype": e.qtype, "queries": e.queries, "responses": e.responses,
                "rcodes": dict(e.rcodes), "answers": e.answers, "clients": e.clients,
                "first_ts": e.first_ts, "last_ts": e.last_ts, "min_ttl": e.min_ttl, "hints": self.hints(e),
            }
            for e in chosen[:limit]
        ]

    def summary(self) -> Dict[str, Any]:
        entries = self.entries.values()
        return {
            "names": len({e.name for e in entries}),
            "queries": sum(e.queries for e in entries),
            "responses": sum(e.responses for e in entries),
            "nxdomain": sum(e.rcodes.get("NXDOMAIN", 0) for e in entries),
            "flagged": sum(1 for e in entries if self.hints(e)),
            "dropped": self.dropped,
        }
