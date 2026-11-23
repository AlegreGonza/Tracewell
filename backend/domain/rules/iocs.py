"""Lista de indicadores de compromiso (IOC) cargada desde un archivo local.

Un IOC es una IP, una red (CIDR) o un dominio que ya se sabe malicioso. El
analista carga su lista y Tracewell marca las sesiones que coinciden. Todo es
local: no se consulta ningún servicio externo (mandar IP de tu red a un tercero
filtraría datos).

Formatos (se detectan por la extensión y, si no alcanza, por el contenido):
- texto: un indicador por línea, `#` para comentarios (el formato original);
- CSV/TSV: con una columna de valor (`value`, `valor`, `indicator`, `ioc`, `ip`, `domain`...);
- STIX 2.1 (JSON): indicadores con patrón `ipv4-addr`, `ipv6-addr`, `domain-name` o `network-traffic`.
Las mismas validaciones valen para los tres (red /0 rechazada, IP mal escrita, límites de tamaño).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
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
    # Índice por (versión, prefijo) -> {dirección de red: (orden, red)}; se arma una vez en __post_init__.
    _index: dict = field(init=False, repr=False, compare=False, default_factory=dict)

    def __post_init__(self) -> None:
        index: dict = {}
        for order, net in enumerate(self.networks):
            slot = index.setdefault((net.version, net.prefixlen), {})
            slot.setdefault(int(net.network_address), (order, net))  # ante solapes gana la primera de la lista
        object.__setattr__(self, "_index", index)

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
        # Una consulta por prefijo distinto (<=129) en vez de recorrer miles de redes.
        value, bits, best = int(addr), addr.max_prefixlen, None
        for (version, prefixlen), nets in self._index.items():
            if version != addr.version:
                continue
            shift = bits - prefixlen
            hit = nets.get((value >> shift) << shift)
            if hit and (best is None or hit[0] < best[0]):
                best = hit
        return f"red:{best[1]}" if best else None

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


def _parse_entry(text: str, number: int, where: Optional[str] = None):
    """('ip'|'red'|'dominio', valor) de un valor ya limpio; IocError indicando DÓNDE falló (por defecto, «línea N»)."""
    where = where or f"línea {number}"
    try:
        return "ip", ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise IocError(f"{where}: red inválida: {text[:60]!r}") from None
        if net.prefixlen == 0:
            raise IocError(f"{where}: una red /0 coincidiría con todo el tráfico")
        return "red", net
    domain = text.lower().lstrip("*.").rstrip(".")
    if domain.rsplit(".", 1)[-1].isdigit():  # ningún dominio real termina en un número: es una IP mal escrita
        raise IocError(f"{where}: parece una IP mal escrita: {text[:60]!r}")
    if len(domain) <= 253 and _DOMAIN.match(domain):
        return "dominio", domain
    raise IocError(f"{where}: no es una IP, una red ni un dominio: {text[:60]!r}")


class _Collector:
    """Junta indicadores validados y aplica los topes, sea cual sea el formato de origen."""

    def __init__(self) -> None:
        self.ips: set = set()
        self.networks: list = []
        self.domains: set = set()

    def add(self, text: str, number: int, where: Optional[str] = None) -> None:
        kind, value = _parse_entry(text, number, where)
        if kind == "ip":
            self.ips.add(value)
        elif kind == "red":
            self.networks.append(value)
        else:
            self.domains.add(value)
        if len(self.ips) + len(self.networks) + len(self.domains) > MAX_ENTRIES:
            raise IocError(f"demasiados indicadores (máximo {MAX_ENTRIES})")

    def build(self) -> IocSet:
        if len(self.networks) > MAX_NETWORKS:
            raise IocError(f"demasiadas redes (máximo {MAX_NETWORKS}); usá IP sueltas o redes más grandes")
        return IocSet(frozenset(self.ips), tuple(self.networks), frozenset(self.domains))


# ------------------------------------------------------------------ texto plano

def parse_iocs(text: str) -> IocSet:
    """Formato original: un indicador por línea, `#` para comentarios."""
    acc = _Collector()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if line:
            acc.add(line, number)
    return acc.build()


# ------------------------------------------------------------------------- CSV

_VALUE_COLUMNS = (
    "value", "valor", "indicator", "indicador", "ioc", "observable",
    "ip", "ipv4", "ipv6", "domain", "dominio", "host", "network", "red",
)


def _first_data_line(text: str) -> str:
    return next((ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")), "")


def _delimiter(text: str) -> str:
    """Delimitador del CSV: coma, punto y coma o tabulador (el más frecuente en la primera línea de datos)."""
    first = _first_data_line(text)
    best = max(",;\t", key=first.count)
    return best if first.count(best) else ","


def _value_column(header: list) -> Optional[int]:
    names = [h.strip().lstrip("﻿").lower() for h in header]
    for wanted in _VALUE_COLUMNS:  # el orden de _VALUE_COLUMNS decide si hay varias candidatas
        if wanted in names:
            return names.index(wanted)
    return None


def _csv_rows(text: str) -> list:
    """(número de línea, fila) de las filas con contenido, sin comentarios."""
    reader = csv.reader(io.StringIO(text), delimiter=_delimiter(text))
    return [(n, r) for n, r in enumerate(reader, start=1) if any(c.strip() for c in r) and not r[0].lstrip().startswith("#")]


def parse_csv_iocs(text: str) -> IocSet:
    """CSV/TSV con una columna de valor. Con una sola columna se admite sin encabezado.

    Los errores indican la fila (`línea N`, contando también el encabezado y los comentarios).
    """
    rows = _csv_rows(text)
    if not rows:
        return IocSet()
    column = _value_column(rows[0][1])
    if column is not None:
        rows = rows[1:]
    elif len(rows[0][1]) == 1:
        column = 0
    else:
        raise IocError(f"CSV sin columna de valor: el encabezado debe incluir una de {', '.join(_VALUE_COLUMNS[:6])}...")
    acc = _Collector()
    for number, row in rows:
        value = row[column].strip() if column < len(row) else ""
        if value:
            acc.add(value, number)
    return acc.build()


# ------------------------------------------------------------------- STIX 2.1

_STIX_VALUE_TYPES = ("ipv4-addr", "ipv6-addr", "domain-name")
_STIX_COMPARE = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_.\[\]*-]+)\s*(=|LIKE)\s*'((?:[^'\\]|\\.)*)'")
_STIX_IN = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_.\[\]*-]+)\s+IN\s*\(([^)]*)\)")
_STIX_LITERAL = re.compile(r"'((?:[^'\\]|\\.)*)'")


def _stix_path_ok(obj_type: str, path: str) -> bool:
    """¿La propiedad comparada es el valor de una IP/dominio o el extremo de un tráfico de red?"""
    if obj_type in _STIX_VALUE_TYPES:
        return path == "value"
    return obj_type == "network-traffic" and path in ("src_ref.value", "dst_ref.value")


def _unescape(literal: str) -> str:
    return re.sub(r"\\(.)", r"\1", literal)


def _pattern_values(pattern: str) -> List[str]:
    """Valores de IP/dominio comparados con `=` (o con `IN`) en un patrón STIX. Un `NOT` lo descarta: sería lo contrario."""
    if re.search(r"\bNOT\b", pattern):
        return []
    found = [m.group(4) for m in _STIX_COMPARE.finditer(pattern) if m.group(3) == "=" and _stix_path_ok(m.group(1), m.group(2))]
    for m in _STIX_IN.finditer(pattern):
        if _stix_path_ok(m.group(1), m.group(2)):
            found += _STIX_LITERAL.findall(m.group(3))
    return [_unescape(v) for v in found]


def _stix_objects(data):
    """Lista de objetos de un bundle, de una lista suelta o de un objeto único; IocError si no parece STIX."""
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        return data["objects"]
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("type"), str):
        return [data]
    raise IocError("JSON sin forma de STIX: se esperaba un bundle con 'objects', una lista o un objeto STIX")


def _object_values(obj: dict) -> List[str]:
    """Valores de un objeto STIX: el patrón de un indicador vigente o el `value` de una IP/dominio suelta."""
    kind = obj.get("type")
    if kind == "indicator":
        pattern = obj.get("pattern")
        if not isinstance(pattern, str) or obj.get("pattern_type", "stix") != "stix" or obj.get("revoked") is True:
            return []
        return _pattern_values(pattern)
    if kind in _STIX_VALUE_TYPES and isinstance(obj.get("value"), str):
        return [obj["value"]]
    return []


def parse_stix_iocs(text: str) -> IocSet:
    """STIX 2.1 en JSON. Solo se leen indicadores de IP/dominio/tráfico de red; hashes, URL y demás se ignoran."""
    try:
        data = json.loads(text)
    except ValueError:
        raise IocError("el archivo no es un JSON válido") from None
    acc = _Collector()
    for number, obj in enumerate(_stix_objects(data), start=1):
        if not isinstance(obj, dict):
            raise IocError(f"objeto {number}: se esperaba un objeto STIX, no {type(obj).__name__}")
        for value in _object_values(obj):
            acc.add(value.strip(), number, where=f"objeto {number}")
    return acc.build()


# --------------------------------------------------------------- detección y carga

def detect_format(text: str, name: str = "") -> str:
    """'stix', 'csv' o 'texto': por la extensión (.json/.stix, .csv/.tsv, .txt) y, si no dice nada, por el contenido."""
    ext = Path(name).suffix.lower()
    if ext in (".json", ".stix"):
        return "stix"
    if ext in (".csv", ".tsv"):
        return "csv"
    if ext == ".txt":
        return "texto"
    if text.lstrip("﻿ \t\r\n")[:1] in ("{", "["):
        return "stix"
    data = _first_data_line(text).split("#", 1)[0]
    return "csv" if any(c in data for c in ",;\t") else "texto"


def parse_ioc_text(text: str, name: str = "") -> IocSet:
    """Interpreta el contenido de un archivo de IOC en el formato que corresponda."""
    parsers = {"stix": parse_stix_iocs, "csv": parse_csv_iocs, "texto": parse_iocs}
    return parsers[detect_format(text, name)](text)


def load_iocs(path) -> IocSet:
    """Lee y valida un archivo de IOC (texto, CSV o STIX). FileNotFoundError si no existe (la API lo traduce a 404)."""
    p = Path(path).expanduser()
    if p.stat().st_size > MAX_FILE_BYTES:
        raise IocError(f"el archivo es demasiado grande (máximo {MAX_FILE_BYTES // 1_000_000} MB)")
    try:
        text = p.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise IocError("el archivo no es texto UTF-8") from None
    ioc = parse_ioc_text(text, p.name)
    if len(ioc) == 0:
        raise IocError("el archivo no contiene ningún indicador")
    return ioc
