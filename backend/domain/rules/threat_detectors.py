"""Detectores de amenazas: DGA, huellas JA4, certificados TLS, User-Agent, SMB/RPC e ICMP."""
from __future__ import annotations

import ipaddress
import logging
import re
import struct
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Tuple, Type

import dpkt

from backend.domain.analysis.tls import (
    ja4, parse_certificate, parse_certificates, parse_client_hello, parse_server_hello, sni_of,
)
from backend.domain.rules import engine as _engine
from backend.domain.rules.engine import (
    Decoded, Detector, _entropy, _int_range, _LRU, _num_range, _port_list, _suffix_list,
    is_pure_syn, split_registrable,
)
from backend.domain.rules.extra_detectors import _bool, _is_external, _ports_or_empty

logger = logging.getLogger("tracewell")

NXDOMAIN = 3
TLS_HANDSHAKE, HELLO_CLIENT, HELLO_SERVER = 0x16, 1, 2
TLS13 = 0x0304
_MAX_FLOW_BYTES = 65_536  # bytes de un flujo que se guardan buscando el saludo o el certificado
_MAX_FLOW_PACKETS = 12


def _toward_client(d: Decoded) -> Decoded:
    """El mismo paquete visto del lado del cliente: la alerta lee «cliente -> servidor»."""
    return replace(d, src=d.dst, dst=d.src, sport=d.dport, dport=d.sport)


def _is_internal(ip_text: str) -> bool:
    """True si la IP es privada o de red local (ni pública, ni loopback, ni multicast)."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return ip.is_private and not (ip.is_loopback or ip.is_multicast or ip.is_unspecified)


# ------------------------------------------------------------------ DGA / NXDOMAIN

_VOWELS = frozenset("aeiou")


class DgaNxdomainDetector(Detector):
    """Un cliente recibe muchas respuestas NXDOMAIN, y la mayoría con nombres que parecen aleatorios."""

    PARAMS = {
        "min_nxdomain": (_int_range(2, 100_000), 20),
        "window_seconds": (_num_range(0.001), 60.0),
        # Proporción mínima de nombres de aspecto aleatorio (0 = basta con el volumen).
        "min_random_ratio": (_num_range(0.0, 1.0), 0.5),
        "min_label_length": (_int_range(3, 63), 8),
        "min_entropy": (_num_range(0.0, 8.0), 2.5),
        "max_vowel_ratio": (_num_range(0.0, 1.0), 0.3),
        "ignore_suffixes": (_suffix_list, ["arpa", "local"]),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._seen = _LRU()  # cliente -> {nombre: (instante, ¿aleatorio?)}
        self._alerted = _LRU()

    def _is_ignored(self, name: str) -> bool:
        return any(name == s or name.endswith("." + s) for s in self.p["ignore_suffixes"])

    def looks_random(self, name: str) -> bool:
        """El dominio registrable parece generado: largo, entropía alta y pocas vocales (o con dígitos)."""
        label = split_registrable(name)[1].split(".")[0]
        if len(label) < self.p["min_label_length"] or _entropy(label) < self.p["min_entropy"]:
            return False
        letters = [c for c in label if c.isalpha()]
        if len(letters) < len(label):
            return True  # mezcla letras y dígitos o guiones: típico de un hash
        return sum(c in _VOWELS for c in letters) / len(letters) <= self.p["max_vowel_ratio"]

    @staticmethod
    def _parse_nxdomain(payload: bytes) -> Optional[str]:
        """Nombre consultado si el mensaje es una respuesta NXDOMAIN legible; si no, None."""
        try:
            dns = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, ValueError, IndexError, struct.error, UnicodeError):
            return None
        if dns.qr != 1 or dns.rcode != NXDOMAIN or not dns.qd:
            return None
        return dns.qd[0].name.lower().rstrip(".") or None

    def _record(self, client: str, name: str, ts: float) -> Dict[str, Tuple[float, bool]]:
        """Anota el nombre del cliente (los más viejos salen: la memoria queda acotada)."""
        names = self._seen.get(client) or {}
        names.pop(name, None)
        names[name] = (ts, self.looks_random(name))
        window = self.p["window_seconds"]
        for old in [n for n, (t, _) in names.items() if ts - t > window]:
            del names[old]
        while len(names) > max(4 * self.p["min_nxdomain"], 100):
            del names[next(iter(names))]
        self._seen[client] = names
        return names

    def feed(self, d):
        if d.proto != 17 or d.sport != 53 or not d.payload or d.dst in self._alerted:
            return []
        name = self._parse_nxdomain(d.payload)
        if name is None or self._is_ignored(name):
            return []
        names = self._record(d.dst, name, d.ts)
        total = len(names)
        random_names = [n for n, (_, rnd) in names.items() if rnd]
        if total < self.p["min_nxdomain"] or len(random_names) < self.p["min_random_ratio"] * total:
            return []
        self._alerted[d.dst] = True
        return [self._alert(_toward_client(d), {
            "nxdomain_count": total, "random_looking": len(random_names),
            "random_ratio": round(len(random_names) / total, 2), "window_seconds": self.p["window_seconds"],
            "sample_domains": (random_names or list(names))[:10], "resolver": d.src,
        }, ts=min(t for t, _ in names.values()))]


# ----------------------------------------------------------------- huellas JA4

_JA4_RE = re.compile(r"^[tqd][0-9a-z]{9}_[0-9a-f]{12}_[0-9a-f]{12}$")
MAX_FINGERPRINT_FILE = 1_000_000
MAX_FINGERPRINTS = 50_000


def _ja4_list(v):
    """Lista (puede ser vacía) de huellas JA4 en minúsculas."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de huellas JA4, recibí {v!r}")
    out = []
    for item in v:
        text = str(item).strip().lower()
        if not _JA4_RE.match(text):
            raise ValueError(f"no es una huella JA4 válida: {item!r}")
        out.append(text)
    return out


def _relative_path(v):
    """Ruta relativa a la carpeta de la regla ('' = ninguna); sin rutas absolutas ni '..'."""
    if not isinstance(v, str):
        raise ValueError(f"debe ser texto, recibí {v!r}")
    text = v.strip()
    parts = re.split(r"[\\/]", text)
    if text.startswith(("/", "\\")) or PureWindowsPath(text).drive or ".." in parts:
        raise ValueError(f"debe ser una ruta relativa a la carpeta de la regla, sin '..': {v!r}")
    return text


def load_fingerprints(path: Path) -> Dict[str, Tuple[str, str]]:
    """Lee un CSV `ja4,etiqueta,referencia` ('#' comenta); {huella: (etiqueta, referencia)}."""
    if path.stat().st_size > MAX_FINGERPRINT_FILE:
        raise ValueError(f"{path.name} supera {MAX_FINGERPRINT_FILE} bytes")
    table: Dict[str, Tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(",", 2)] + ["", ""]
        fingerprint = fields[0].lower()
        if not _JA4_RE.match(fingerprint):
            logger.warning("huella JA4 inválida ignorada en %s: %r", path.name, fields[0][:60])
        elif len(table) < MAX_FINGERPRINTS:
            table[fingerprint] = (fields[1][:80], fields[2][:200])
    return table


class Ja4BlocklistDetector(Detector):
    """ClientHello TLS cuya huella JA4 está en una lista de huellas asociadas a malware."""

    PARAMS = {
        "fingerprints": (_ja4_list, []),
        # CSV editable (ver el README de `rules/`), relativo a la carpeta de la regla.
        "fingerprints_file": (_relative_path, ""),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._table = {fp: ("", "") for fp in self.p["fingerprints"]}
        self._table.update(self._from_file(rule))
        self._pending = _LRU()  # flujo -> (bytes del saludo incompleto, paquetes)
        self._alerted = _LRU()

    def _from_file(self, rule) -> Dict[str, Tuple[str, str]]:
        """Huellas del archivo de datos; un archivo ilegible avisa y no tumba el análisis."""
        name = self.p["fingerprints_file"]
        if not name or not rule.directory:
            return {}
        base = Path(rule.directory).resolve()
        path = (base / name).resolve()
        try:
            if base not in path.parents:
                raise ValueError("fuera de la carpeta de la regla")
            return load_fingerprints(path)
        except (OSError, ValueError, UnicodeError) as exc:
            logger.warning("regla %s: no se pudo leer %s: %s", rule.id, name, exc)
            return {}

    @staticmethod
    def _starts_client_hello(payload: bytes) -> bool:
        return len(payload) > 5 and payload[0] == TLS_HANDSHAKE and payload[1] == 3 and payload[5] == HELLO_CLIENT

    def _hello_bytes(self, d: Decoded) -> Optional[Tuple[bytes, int]]:
        """(bytes del saludo, segmentos), uniendo unos pocos si no cabe en uno; None si no hay."""
        flow = (d.src, d.dst, d.sport, d.dport)
        pending = self._pending.pop(flow, None)
        if pending is None:
            return (d.payload, 1) if self._starts_client_hello(d.payload) else None
        data, count = pending
        if count >= _MAX_FLOW_PACKETS or len(data) >= _MAX_FLOW_BYTES:
            return None
        return data + d.payload, count + 1

    def feed(self, d):
        if d.proto != 6 or not d.payload or not self._table:
            return []
        found = self._hello_bytes(d)
        if found is None:
            return []
        hello = parse_client_hello(found[0])
        if hello is None or not hello.complete:
            self._pending[(d.src, d.dst, d.sport, d.dport)] = found  # falta el resto del saludo
            return []
        fingerprint = ja4(hello)
        entry = self._table.get(fingerprint)
        key = (d.src, d.dst, fingerprint)
        if entry is None or key in self._alerted:
            return []
        self._alerted[key] = True
        return [self._alert(d, {
            "ja4": fingerprint, "label": entry[0], "reference": entry[1],
            "sni": sni_of(hello), "destination_port": d.dport,
        })]


# ------------------------------------------------------------ certificados TLS

class TlsCertificateDetector(Detector):
    """Servidor TLS (≤ 1.2) que presenta un certificado autofirmado o vencido."""

    PARAMS = {
        "flag_self_signed": (_bool, True),
        "flag_expired": (_bool, True),
        # Solo servidores públicos: los equipos internos suelen usar certificados propios.
        "external_only": (_bool, True),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._flows = _LRU()  # (servidor, puerto, cliente, puerto) -> [bytes, paquetes]
        self._alerted = _LRU()

    @staticmethod
    def _starts_server_hello(payload: bytes) -> bool:
        return len(payload) > 5 and payload[0] == TLS_HANDSHAKE and payload[1] == 3 and payload[5] == HELLO_SERVER

    def _collect(self, d: Decoded) -> Optional[bytes]:
        """Bytes del flujo del servidor acumulados (None si no es un saludo ni seguimiento de uno)."""
        key = (d.src, d.sport, d.dst, d.dport)
        entry = self._flows.get(key)
        if entry is None:
            if not self._starts_server_hello(d.payload):
                return None
            hello = parse_server_hello(d.payload)
            if hello is not None and hello.version == TLS13:
                return None  # TLS 1.3: el certificado va cifrado
            entry = [b"", 0]
        entry[0] += d.payload
        entry[1] += 1
        if len(entry[0]) > _MAX_FLOW_BYTES or entry[1] > _MAX_FLOW_PACKETS:
            self._flows.pop(key, None)
            return None
        self._flows[key] = entry
        return entry[0]

    def _reasons(self, cert: Dict[str, Any], ts: float) -> List[str]:
        """Motivos por los que el certificado llama la atención en el instante `ts`."""
        reasons = []
        if self.p["flag_self_signed"] and cert.get("self_signed"):
            reasons.append("certificado autofirmado")
        not_after = cert.get("not_after")
        if self.p["flag_expired"] and not_after:
            try:
                now = datetime.fromtimestamp(ts, timezone.utc)
                expired = now > datetime.fromisoformat(not_after)
            except (OverflowError, OSError, ValueError):
                expired = False
            if expired:
                reasons.append(f"certificado vencido el {not_after[:10]}")
        return reasons

    def feed(self, d):
        if d.proto != 6 or not d.payload:
            return []
        data = self._collect(d)
        if data is None:
            return []
        certs = parse_certificates(data)
        cert = parse_certificate(certs[0]) if certs else None
        if cert is None:
            return []
        self._flows.pop((d.src, d.sport, d.dst, d.dport), None)
        key = (d.src, cert["sha256"])
        if key in self._alerted or (self.p["external_only"] and not _is_external(d.src)):
            return []
        reasons = self._reasons(cert, d.ts)
        if not reasons:
            return []
        self._alerted[key] = True
        return [self._alert(_toward_client(d), {
            "reasons": reasons, "subject": cert["subject"], "issuer": cert["issuer"],
            "not_before": cert["not_before"], "not_after": cert["not_after"],
            "self_signed": cert["self_signed"], "sha256": cert["sha256"], "server_port": d.sport,
        })]


# ------------------------------------------------------------------ User-Agent

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
_MAX_HEAD = 4096
_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def _pattern_list(v):
    """Lista (puede ser vacía) de fragmentos en minúsculas que delatan una herramienta."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de textos, recibí {v!r}")
    out = []
    for item in v:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"fragmento inválido: {item!r}")
        out.append(item.strip().lower())
    return out


def _printable(raw: bytes) -> str:
    """Texto con todo lo no imprimible reemplazado por '?'."""
    return _PRINTABLE.sub("?", raw.decode("latin-1"))


def parse_http_request(payload: bytes) -> Optional[Dict[str, Any]]:
    """Método, ruta, Host y User-Agent de una petición HTTP/1.x; None si no lo parece."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    head, sep, _ = payload[:_MAX_HEAD].partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
        return None
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers.setdefault(name.strip().lower(), value.strip())
    return {
        "method": parts[0].decode("ascii", "replace"), "path": _printable(parts[1].split(b"?")[0])[:100],
        "host": _printable(headers.get(b"host", b""))[:100], "complete": bool(sep),
        "user_agent": _printable(headers[b"user-agent"])[:200] if b"user-agent" in headers else None,
    }


class UserAgentDetector(Detector):
    """Peticiones HTTP con un User-Agent propio de herramientas, vacío o anormalmente corto."""

    PARAMS = {
        "patterns": (_pattern_list, []),
        "flag_empty": (_bool, False),  # cabecera User-Agent presente pero vacía
        "flag_missing": (_bool, False),  # petición completa sin cabecera User-Agent
        "min_length": (_int_range(0, 200), 0),  # 0 = apagado
        "ports": (_ports_or_empty, []),  # [] = cualquier puerto
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._alerted = _LRU()

    def _reasons(self, req: Dict[str, Any]) -> List[str]:
        agent = req["user_agent"]
        if agent is None:
            return ["sin User-Agent"] if self.p["flag_missing"] and req["complete"] else []
        if not agent:
            return ["User-Agent vacío"] if self.p["flag_empty"] else []
        lowered = agent.lower()
        reasons = [f"contiene '{p}'" for p in self.p["patterns"] if p in lowered]
        if len(agent) < self.p["min_length"]:
            reasons.append(f"muy corto ({len(agent)} caracteres)")
        return reasons

    def feed(self, d):
        if d.proto != 6 or (self.p["ports"] and d.dport not in self.p["ports"]):
            return []
        req = parse_http_request(d.payload)
        if req is None:
            return []
        reasons = self._reasons(req)
        key = (d.src, d.dst, req["user_agent"])
        if not reasons or key in self._alerted:
            return []
        self._alerted[key] = True
        return [self._alert(d, {
            "user_agent": req["user_agent"] or "", "reasons": reasons, "method": req["method"],
            "host": req["host"], "path": req["path"], "destination_port": d.dport,
        })]


# --------------------------------------------------------------- SMB / RPC lateral

class SmbRpcLateralDetector(Detector):
    """Un equipo interno abre conexiones SMB o RPC hacia muchos equipos internos distintos."""

    PARAMS = {
        "ports": (_port_list, [445, 135]),
        "min_hosts": (_int_range(2, 10_000), 8),
        "window_seconds": (_num_range(0.001), 300.0),
        "internal_only": (_bool, True),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._seen = _LRU()  # origen -> {destino: (instante, puerto)}
        self._alerted = _LRU()

    def _record(self, d: Decoded) -> Dict[str, Tuple[float, int]]:
        """Anota el destino; el diccionario nunca pasa de `min_hosts` entradas por origen."""
        hosts = self._seen.get(d.src) or {}
        hosts[d.dst] = (d.ts, d.dport)
        if len(hosts) >= self.p["min_hosts"]:
            for old in [h for h, (t, _) in hosts.items() if d.ts - t > self.p["window_seconds"]]:
                del hosts[old]
        self._seen[d.src] = hosts
        return hosts

    def feed(self, d):
        if not is_pure_syn(d) or d.dport not in self.p["ports"] or d.src in self._alerted or d.src == d.dst:
            return []
        if self.p["internal_only"] and not (_is_internal(d.src) and _is_internal(d.dst)):
            return []
        hosts = self._record(d)
        if len(hosts) < self.p["min_hosts"]:
            return []
        self._alerted[d.src] = True
        self._seen.pop(d.src, None)
        return [self._alert(d, {
            "distinct_hosts": len(hosts), "sample_hosts": sorted(hosts)[:20],
            "ports": sorted({p for _, p in hosts.values()}), "window_seconds": self.p["window_seconds"],
            "threshold": self.p["min_hosts"],
        }, ts=min(t for t, _ in hosts.values()))]


# ------------------------------------------------------------------ ICMP tunnel

_ECHO_TYPES = {1: (8, 0), 58: (128, 129)}  # protocolo -> (petición, respuesta)


class IcmpTunnelDetector(Detector):
    """Ecos ICMP con carga útil grande o en volumen alto: posible túnel (ptunnel, icmpsh)."""

    PARAMS = {
        "min_payload_bytes": (_int_range(1, 65_535), 256),
        "min_large_packets": (_int_range(1, 1_000_000), 10),
        "min_packets": (_int_range(0, 100_000_000), 600),  # 0 = apagado
        "min_bytes": (_int_range(0, 10**12), 2_000_000),  # 0 = apagado
        "window_seconds": (_num_range(0.001), 60.0),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._windows = _LRU()  # (origen, destino) -> [inicio, paquetes, bytes, grandes, máximo]
        self._alerted = _LRU()

    def _update(self, d: Decoded) -> List[float]:
        """Contadores del par en la ventana actual (ventanas fijas: memoria constante)."""
        key = (d.src, d.dst)
        win = self._windows.get(key)
        if win is None or d.ts - win[0] > self.p["window_seconds"]:
            win = [d.ts, 0, 0, 0, 0]
        size = len(d.payload)
        win[1] += 1
        win[2] += size
        win[3] += size >= self.p["min_payload_bytes"]
        win[4] = max(win[4], size)
        self._windows[key] = win
        return win

    def _reasons(self, win: List[float]) -> List[str]:
        p, reasons = self.p, []
        if win[3] >= p["min_large_packets"]:
            reasons.append(f"{win[3]} ecos con carga >= {p['min_payload_bytes']} bytes")
        if p["min_packets"] and win[1] >= p["min_packets"]:
            reasons.append(f"{win[1]} ecos en {p['window_seconds']:g} s")
        if p["min_bytes"] and win[2] >= p["min_bytes"]:
            reasons.append(f"{win[2]} bytes de carga en {p['window_seconds']:g} s")
        return reasons

    def feed(self, d):
        if d.proto not in _ECHO_TYPES or d.flags not in _ECHO_TYPES[d.proto]:
            return []
        if (d.src, d.dst) in self._alerted:
            return []
        win = self._update(d)
        reasons = self._reasons(win)
        if not reasons:
            return []
        self._alerted[(d.src, d.dst)] = True
        return [self._alert(d, {
            "reasons": reasons, "echo_packets": win[1], "payload_bytes": win[2],
            "large_packets": win[3], "max_payload_bytes": win[4], "window_seconds": self.p["window_seconds"],
        }, ts=win[0])]


DETECTORS: Dict[str, Type[Detector]] = {
    "dga_nxdomain": DgaNxdomainDetector,
    "ja4_blocklist": Ja4BlocklistDetector,
    "tls_certificate": TlsCertificateDetector,
    "user_agent": UserAgentDetector,
    "smb_rpc_lateral": SmbRpcLateralDetector,
    "icmp_tunnel": IcmpTunnelDetector,
}

# Si este módulo se importó ANTES que extra_detectors, se registra aquí (si no, ya lo hizo él)
_engine.DETECTORS.update(DETECTORS)
