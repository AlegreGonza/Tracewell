"""Lista de indicadores de compromiso (IOC) cargada desde un archivo local.

Un IOC es una IP, una red (CIDR) o un dominio que ya se sabe malicioso. El
analista carga su lista (una por línea, `#` para comentarios) y Tracewell marca
las sesiones que coinciden. Todo es local: no se consulta ningún servicio externo
(mandar IP de tu red a un tercero filtraría datos).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

MAX_FILE_BYTES = 5_000_000
MAX_ENTRIES = 100_000
MAX_NETWORKS = 5_000  # cada sesión se compara contra todas las redes: se acota el costo

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")


class IocError(ValueError):
    """El archivo de IOC no se puede usar (formato, tamaño o contenido inválido)."""


@dataclass(frozen=True)
class IocSet:
    ips: frozenset = field(default_factory=frozenset)
    networks: Tuple = ()
    domains: frozenset = field(default_factory=frozenset)

    def __len__(self) -> int:
        return len(self.ips) + len(self.networks) + len(self.domains)

    def match_ip(self, ip: str) -> Optional[str]:
        """Texto del indicador que coincide con la IP, o None."""
        try:
            addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
        except ValueError:
            return None
        if addr.compressed in self.ips:
            return f"ip:{addr.compressed}"
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return f"red:{net}"
        return None

    def match_domain(self, name: str) -> Optional[str]:
        """Coincide si el nombre ES un dominio de la lista o cuelga de uno (con límite de label)."""
        host = str(name).lower().rstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):  # evita comparar contra un TLD suelto
            candidate = ".".join(parts[i:])
            if candidate in self.domains:
                return f"dominio:{candidate}"
        return None

    def match_session(self, session, names: Iterable[str] = ()) -> List[str]:
        """Indicadores que coinciden con los extremos de la sesión (y sus nombres, si se conocen)."""
        found = [self.match_ip(session.src_ip), self.match_ip(session.dst_ip)]
        found += [self.match_domain(n) for n in names]
        return sorted({f for f in found if f})


def _parse_entry(text: str, number: int):
    """('ip'|'red'|'dominio', valor) de una línea ya limpia; IocError con el número de línea."""
    try:
        return "ip", ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise IocError(f"línea {number}: red inválida: {text[:60]!r}") from None
        if net.prefixlen == 0:
            raise IocError(f"línea {number}: una red /0 coincidiría con todo el tráfico")
        return "red", net
    domain = text.lower().lstrip("*.").rstrip(".")
    if domain.rsplit(".", 1)[-1].isdigit():  # ningún dominio real termina en un número: es una IP mal escrita
        raise IocError(f"línea {number}: parece una IP mal escrita: {text[:60]!r}")
    if len(domain) <= 253 and _DOMAIN.match(domain):
        return "dominio", domain
    raise IocError(f"línea {number}: no es una IP, una red ni un dominio: {text[:60]!r}")


def parse_iocs(text: str) -> IocSet:
    ips, networks, domains = set(), [], set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        kind, value = _parse_entry(line, number)
        if kind == "ip":
            ips.add(value)
        elif kind == "red":
            networks.append(value)
        else:
            domains.add(value)
        if len(ips) + len(networks) + len(domains) > MAX_ENTRIES:
            raise IocError(f"demasiados indicadores (máximo {MAX_ENTRIES})")
    if len(networks) > MAX_NETWORKS:
        raise IocError(f"demasiadas redes (máximo {MAX_NETWORKS}); usá IP sueltas o redes más grandes")
    return IocSet(frozenset(ips), tuple(networks), frozenset(domains))


def load_iocs(path) -> IocSet:
    """Lee y valida un archivo de IOC. FileNotFoundError si no existe (la API lo traduce a 404)."""
    p = Path(path).expanduser()
    if p.stat().st_size > MAX_FILE_BYTES:
        raise IocError(f"el archivo es demasiado grande (máximo {MAX_FILE_BYTES // 1_000_000} MB)")
    try:
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise IocError("el archivo no es texto UTF-8") from None
    ioc = parse_iocs(text)
    if len(ioc) == 0:
        raise IocError("el archivo no contiene ningún indicador")
    return ioc
