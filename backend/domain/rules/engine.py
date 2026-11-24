"""Motor de reglas: carga reglas YAML y las evalúa sobre el tráfico."""
from __future__ import annotations

import ipaddress
import logging
import math
import re
import socket
import struct
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NoReturn, Optional, Tuple, Type

import dpkt
import yaml

from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import ETHERNET, UnsupportedLinktype, ip_layer

logger = logging.getLogger("tracewell")

SEVERITIES = ("low", "medium", "high", "critical")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Tácticas MITRE ATT&CK admitidas: nombres canónicos, en orden de la cadena de ataque.
MITRE_TACTICS = (
    "Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)

TCP_SYN, TCP_ACK = 0x02, 0x10


class RuleError(ValueError):
    """Regla mal formada. Falla ruidosamente al cargar, no en medio del análisis."""


# ---------------------------------------------------------------- modelos

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str
    detector: str
    mitre_technique: str
    mitre_name: str
    mitre_tactic: str
    params: Dict[str, Any]
    source: str = ""  # archivo del que salió, para mensajes de error
    # Campos explicativos OPCIONALES del YAML: ayudan al analista a decidir
    false_positives: Tuple[str, ...] = ()
    investigation_steps: Tuple[str, ...] = ()
    wireshark_filter: str = ""
    directory: str = ""  # carpeta del YAML: ahí se resuelven los archivos de datos de la regla


@dataclass
class Alert:
    rule_id: str
    name: str
    severity: str
    mitre_technique: str
    mitre_name: str
    mitre_tactic: str
    description: str
    src_ip: str
    dst_ip: str
    first_ts: float
    # Evidencia: por qué saltó la alerta, con datos concretos
    evidence: Dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------- validación de params
# Cada parámetro: nombre -> (validador, valor por defecto). El validador
# devuelve el valor normalizado o lanza ValueError.

def _is_int(v) -> bool:
    """Entero de verdad: bool es subclase de int pero no vale como número."""
    return isinstance(v, int) and not isinstance(v, bool)


def _int_range(lo: int, hi: int = 10**9) -> Callable[[Any], int]:
    def check(v):
        if not _is_int(v) or not lo <= v <= hi:
            raise ValueError(f"debe ser un entero entre {lo} y {hi}, recibí {v!r}")
        return v
    return check


def _num_range(lo: float, hi: float = 1e9) -> Callable[[Any], float]:
    def check(v):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise ValueError(f"debe ser un número entre {lo} y {hi}, recibí {v!r}")
        return float(v)
    return check


def _check_port(p) -> None:
    """Falla si `p` no es un puerto entero de 0 a 65535."""
    if not _is_int(p) or not 0 <= p <= 65535:
        raise ValueError(f"puerto fuera de rango (0-65535): {p!r}")


def _port_list(v):
    if not isinstance(v, list) or not v:
        raise ValueError(f"debe ser una lista no vacía de puertos, recibí {v!r}")
    for p in v:
        _check_port(p)
    return list(v)


def _suffix_list(v):
    """Lista (puede ser vacía) de sufijos de dominio."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de dominios, recibí {v!r}")
    out = []
    for s in v:
        if not isinstance(s, str) or not s.strip(".").strip() or any(c.isspace() for c in s):
            raise ValueError(f"dominio inválido en la lista: {s!r}")
        out.append(s.strip(".").lower())
    return out


# Nombres de servicio admitidos en `allow_services` (además de números de puerto).
_SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "dns": 53, "http": 80, "kerberos": 88, "ntp": 123,
    "rpc": 135, "ldap": 389, "https": 443, "smb": 445, "rdp": 3389, "winrm": 5985,
}


def _host_list(v):
    """Lista (puede ser vacía) de IP o redes CIDR; se normalizan."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de IP o redes CIDR, recibí {v!r}")
    out = []
    for item in v:
        try:
            out.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
        except ValueError:
            raise ValueError(f"no es una IP ni una red CIDR: {item!r}") from None
    return out


def _service_list(v):
    """Lista (puede ser vacía) de puertos o nombres de servicio (ssh, smb...); sale como puertos."""
    if not isinstance(v, list):
        raise ValueError(f"debe ser una lista de puertos o servicios, recibí {v!r}")
    ports = set()
    for item in v:
        if isinstance(item, str) and item.strip().lower() in _SERVICE_PORTS:
            ports.add(_SERVICE_PORTS[item.strip().lower()])
            continue
        _check_port(item)
        ports.add(item)
    return sorted(ports)


# Parámetros opcionales que acepta CUALQUIER regla: excepciones contra falsos positivos.
COMMON_PARAMS: Dict[str, Tuple[Callable[[Any], Any], Any]] = {
    "allow_hosts": (_host_list, []),
    "allow_services": (_service_list, []),
}


class Allowlist:
    """Hosts (IP/CIDR) y puertos que una regla nunca debe evaluar ni alertar."""

    def __init__(self, params: Dict[str, Any]):
        self.nets = tuple(ipaddress.ip_network(h) for h in params.get("allow_hosts", ()))
        self.ports = frozenset(params.get("allow_services", ()))
        self._memo: Dict[str, bool] = {}

    def _host_allowed(self, ip: str) -> bool:
        """True si la IP cae en alguna red permitida (con memoria acotada)."""
        hit = self._memo.get(ip)
        if hit is None:
            try:
                addr = ipaddress.ip_address(ip)
                hit = any(addr in net for net in self.nets)
            except ValueError:
                hit = False
            if len(self._memo) < MAX_TRACKED:
                self._memo[ip] = hit
        return hit

    def allows(self, d: "Decoded") -> bool:
        """True si el paquete involucra un host o un servicio permitido (en cualquier sentido)."""
        if self.ports and d.proto in (6, 17) and (d.dport in self.ports or d.sport in self.ports):
            return True
        return bool(self.nets) and (self._host_allowed(d.src) or self._host_allowed(d.dst))


# ------------------------------------------------------------- decodificado

@dataclass(frozen=True)
class Decoded:
    """Lo mínimo que los detectores necesitan de un paquete TCP/UDP."""

    ts: float
    src: str
    dst: str
    proto: int  # 6 = TCP, 17 = UDP, 1 = ICMP, 58 = ICMPv6
    sport: int  # 0 en ICMP
    dport: int  # 0 en ICMP
    flags: int  # flags TCP; tipo en ICMP; 0 en UDP
    payload: bytes  # en un eco ICMP, solo la carga útil (sin identificador ni secuencia)


def _l4_info(l4):
    """(proto, flags) de un segmento TCP/UDP, o None si es otra cosa."""
    if isinstance(l4, dpkt.tcp.TCP):
        return 6, l4.flags
    if isinstance(l4, dpkt.udp.UDP):
        return 17, 0
    return None


def _icmp_info(l4):
    """(proto, tipo) de un mensaje ICMP/ICMPv6, o None si es otra cosa."""
    if isinstance(l4, dpkt.icmp.ICMP):
        return 1, l4.type
    if isinstance(l4, dpkt.icmp6.ICMP6):
        return 58, l4.type
    return None


def _l4_fields(l4):
    """(proto, flags, sport, dport, payload) de TCP/UDP/ICMP, o None si es otra cosa."""
    info = _l4_info(l4)
    if info is not None:
        return info[0], info[1], l4.sport, l4.dport, bytes(l4.data)
    info = _icmp_info(l4)
    if info is None:
        return None
    inner = getattr(l4.data, "data", l4.data)  # eco: la carga útil va dentro del eco
    return info[0], info[1], 0, 0, bytes(inner)


def decode_layer(pkt: Packet, layer) -> Optional[Decoded]:
    """TCP/UDP/ICMP de una capa IP ya leída (`ip_layer`), o None si no aplica o está dañado."""
    if layer is None:
        return None
    ip, family = layer
    try:
        fields = _l4_fields(ip.data)
        if fields is None:
            return None
        proto, flags, sport, dport, payload = fields
        return Decoded(
            pkt.ts, socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst),
            proto, sport, dport, flags, payload,
        )
    except (dpkt.UnpackError, ValueError, IndexError, struct.error):
        return None


def _decode(pkt: Packet) -> Optional[Decoded]:
    """Ethernet -> IP -> TCP/UDP, o None si no aplica o está dañado."""
    try:
        return decode_layer(pkt, ip_layer(pkt.data))  # fragmento sin capa 4 => UnpackError => None
    except (dpkt.UnpackError, ValueError, IndexError, struct.error):
        return None


# ---------------------------------------------------------------- detectores

# Tope de entradas por estructura de estado de un detector
MAX_TRACKED = 100_000
# Tope de puertos con respuesta recordados por par (escaneo lento)
_MAX_ANSWERED_PORTS = 1024


class _LRU(OrderedDict):
    """Diccionario acotado: al superar `maxsize` descarta el menos reciente."""

    def __init__(self, maxsize: int = MAX_TRACKED):
        super().__init__()
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.move_to_end(key)
        if len(self) > self.maxsize:
            self.popitem(last=False)


def is_pure_syn(d: Decoded) -> bool:
    """SYN sin ACK: intento de abrir una conexión TCP."""
    return d.proto == 6 and bool(d.flags & TCP_SYN) and not d.flags & TCP_ACK


class Detector:
    PARAMS: Dict[str, Tuple[Callable[[Any], Any], Any]] = {}

    def __init__(self, rule: Rule):
        self.rule = rule
        self.p = rule.params
        self.allow = Allowlist(rule.params)  # `RuleRunner` omite lo que permite

    def feed(self, d: Decoded) -> List[Alert]:  # pragma: no cover - interfaz
        raise NotImplementedError

    def _alert(self, d: Decoded, evidence: Dict[str, Any], ts: Optional[float] = None) -> Alert:
        r = self.rule
        return Alert(
            rule_id=r.id, name=r.name, severity=r.severity,
            mitre_technique=r.mitre_technique, mitre_name=r.mitre_name,
            mitre_tactic=r.mitre_tactic, description=r.description,
            src_ip=d.src, dst_ip=d.dst,
            first_ts=d.ts if ts is None else ts, evidence=evidence,
        )


class PortScanDetector(Detector):
    """Una IP origen envía SYN a muchos puertos distintos de un mismo destino en poco tiempo."""

    PARAMS = {
        "min_ports": (_int_range(2, 65535), 15),
        "window_seconds": (_num_range(0.001), 60.0),
        # Segunda ventana, larga y con umbral propio, para escaneos lentos (0 = apagada).
        "long_window_seconds": (_num_range(0.0), 0.0),
        "long_threshold": (_int_range(2, 65535), 20),
    }

    def __init__(self, rule):
        super().__init__(rule)
        # (origen, destino) -> {puerto: último instante visto}
        self._seen = _LRU()
        self._seen_long = _LRU()  # ventana larga: solo puertos que no respondieron
        self._answered = _LRU()  # (origen, destino) -> puertos que respondieron SYN+ACK
        self._alerted = _LRU()

    _is_pure_syn = staticmethod(is_pure_syn)  # alias: los tests lo usan desde la clase

    def _record_port(self, key, d: Decoded, seen=None) -> Dict[int, float]:
        """Anota el puerto visto para el par y refresca su recencia."""
        seen = self._seen if seen is None else seen
        ports = seen.get(key)
        if ports is None:
            ports = {}
        ports[d.dport] = d.ts
        seen[key] = ports  # refresca la recencia del par
        return ports

    @staticmethod
    def _prune_old(ports: Dict[int, float], now: float, window: float) -> None:
        """Descarta los puertos fuera de la ventana de tiempo."""
        for port in [p for p, t in ports.items() if now - t > window]:
            del ports[port]

    def _build_alert(self, d: Decoded, ports: Dict[int, float], window, minimum) -> Alert:
        """Alerta de escaneo con la evidencia de los puertos tocados."""
        return self._alert(d, {
            "distinct_ports": len(ports),
            "sample_ports": sorted(ports)[:20],
            "window_seconds": window,
            "threshold": minimum,
        }, ts=min(ports.values()))

    def _note_answer(self, d: Decoded) -> None:
        """Un SYN+ACK del servidor marca ese puerto como servicio real, no sondeo."""
        if not self.p.get("long_window_seconds", 0) or d.proto != 6:
            return
        if d.flags & (TCP_SYN | TCP_ACK) != TCP_SYN | TCP_ACK:
            return
        key = (d.dst, d.src)  # el SYN+ACK va en sentido inverso al SYN
        answered = self._answered.get(key)
        if answered is None:
            answered = set()
        if len(answered) < _MAX_ANSWERED_PORTS:
            answered.add(d.sport)
        self._answered[key] = answered
        long_ports = self._seen_long.get(key)
        if long_ports:
            long_ports.pop(d.sport, None)

    def _feed_short(self, key, d: Decoded) -> List[Alert]:
        """Ventana corta: muchos puertos en pocos segundos."""
        ports = self._record_port(key, d)
        minimum = self.p["min_ports"]
        if len(ports) < minimum:
            return []  # así el dict nunca pasa de `min_ports` entradas por par
        # Llegamos al umbral
        window = self.p["window_seconds"]
        self._prune_old(ports, d.ts, window)
        if len(ports) < minimum:
            return []
        return [self._build_alert(d, ports, window, minimum)]

    def _feed_long(self, key, d: Decoded) -> List[Alert]:
        """Ventana larga: pocos puertos por minuto pero muchos en total (evasión por lentitud)."""
        window = self.p.get("long_window_seconds", 0)
        if not window or d.dport in self._answered.get(key, ()):
            return []
        ports = self._record_port(key, d, self._seen_long)
        minimum = self.p.get("long_threshold", 20)
        if len(ports) < minimum:
            return []
        self._prune_old(ports, d.ts, window)
        if len(ports) < minimum:
            return []
        return [self._build_alert(d, ports, window, minimum)]

    def feed(self, d):
        if not self._is_pure_syn(d):
            self._note_answer(d)
            return []
        key = (d.src, d.dst)
        if key in self._alerted:  # una alerta por par; no inundar al analista
            return []
        alerts = self._feed_short(key, d) or self._feed_long(key, d)
        if alerts:
            self._alerted[key] = True
            self._seen.pop(key, None)  # liberar memoria
            self._seen_long.pop(key, None)
            self._answered.pop(key, None)
        return alerts


class FtpCleartextDetector(Detector):
    """Credenciales USER/PASS (FTP, POP3) viajando sin cifrar, en cualquier puerto TCP."""

    # `ports`: puertos de confianza; ahí un PASS suelto alerta. Fuera, exige USER antes.
    PARAMS = {"ports": (_port_list, [21])}

    def __init__(self, rule):
        super().__init__(rule)
        self._users = _LRU()  # (origen, destino, puerto origen, puerto destino) -> usuario
        self._banners = _LRU()  # mismo flujo (lado cliente) -> protocolo según el banner
        self._alerted = _LRU()

    @staticmethod
    def _split_command(payload: bytes):
        """(comando de 5 bytes en mayúsculas, argumento) de la primera línea."""
        line = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        return line[:5].upper(), line[5:]

    def _note_banner(self, d: Decoded) -> None:
        """Recuerda si el servidor se presentó como POP3 (+OK) o FTP (220)."""
        if d.payload.startswith(b"+OK"):
            self._banners[(d.dst, d.src, d.dport, d.sport)] = "POP3"
        elif d.payload.startswith(b"220"):
            self._banners[(d.dst, d.src, d.dport, d.sport)] = "FTP"

    def _protocol(self, d: Decoded) -> str:
        """FTP o POP3 según el banner; sin banner, por el puerto o 'USER/PASS'."""
        known = self._banners.get((d.src, d.dst, d.sport, d.dport))
        if known:
            return known
        return "FTP" if d.dport == 21 else "USER/PASS"

    def _password_alert(self, d: Decoded, value: bytes, user: str) -> List[Alert]:
        """Alerta (una por origen/destino/usuario) sin guardar la contraseña."""
        if (d.src, d.dst, user) in self._alerted:
            return []
        self._alerted[(d.src, d.dst, user)] = True
        return [self._alert(d, {
            "username": user,
            "password": "<oculta>",
            "password_length": len(value.strip()),
            "port": d.dport,
            "protocol": self._protocol(d),
        })]

    @staticmethod
    def _valid_user(value: bytes) -> bool:
        """USER de FTP/POP3: un solo argumento imprimible (el USER de IRC lleva varios)."""
        text = value.strip()
        return bool(text) and all(32 < c < 127 for c in text)

    def feed(self, d):
        if d.proto != 6 or not d.payload:
            return []
        cmd, value = self._split_command(d.payload)
        flow = (d.src, d.dst, d.sport, d.dport)
        if cmd == b"USER ":
            if self._valid_user(value):
                self._users[flow] = value.decode("latin-1").strip()[:64]
            return []
        if cmd != b"PASS ":
            self._note_banner(d)
            return []
        user = self._users.get(flow)
        if user is None and d.dport not in self.p["ports"]:
            return []  # en un puerto desconocido, PASS sin USER previo no basta
        return self._password_alert(d, value, user or "<no visto>")


def _entropy(s: str) -> float:
    """Entropía de Shannon (bits/carácter): qué tan "aleatorio" es el texto."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}  # co.uk, com.ar...


def split_registrable(name: str) -> Tuple[str, str]:
    """(subdominios, dominio registrable aproximado) de un nombre; sin lista pública de sufijos."""
    labels = name.rstrip(".").split(".")
    keep = 2
    if len(labels) > 2 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        keep = 3
    return ".".join(labels[:-keep]), ".".join(labels[-keep:])


class DnsSuspiciousDetector(Detector):
    """Consultas DNS con nombres que parecen datos y no nombres humanos."""

    PARAMS = {
        "max_label_length": (_int_range(1, 63), 40),
        "min_entropy": (_num_range(0.0, 8.0), 3.5),
        "entropy_min_label": (_int_range(1, 63), 20),
        # Dominios de confianza: nombres largos pero legítimos (p. ej. balanceadores de nube).
        "ignore_suffixes": (_suffix_list, []),
        # Medida agregada: subdominios (sin el dominio registrable) largos y de alta entropía.
        "min_total_length": (_int_range(0, 253), 50),  # 0 = apagada
        # Volumen: subdominios únicos hacia un mismo dominio padre en la ventana (0 = apagado).
        "min_unique_subdomains": (_int_range(0, 100_000), 0),
        "volume_window_seconds": (_num_range(0.001), 60.0),
    }

    def __init__(self, rule):
        super().__init__(rule)
        self._alerted = _LRU()
        self._volume = _LRU()  # (origen, dominio padre) -> {subdominio: instante}

    def _is_ignored(self, name: str) -> bool:
        """True si el nombre es un dominio ignorado o cuelga de uno (con límite de label)."""
        host = name.rstrip(".")
        return any(host == s or host.endswith("." + s) for s in self.p.get("ignore_suffixes", ()))

    @staticmethod
    def _parse_query(payload: bytes):
        """Mensaje DNS si es una consulta legible; None si es respuesta o basura."""
        try:
            dns = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, ValueError, IndexError, struct.error, UnicodeError):
            return None
        return dns if dns.qr == 0 else None  # solo consultas, no respuestas

    def _reasons(self, label: str, entropy: float) -> List[str]:
        """Motivos por los que el label parece datos y no un nombre humano."""
        reasons = []
        if len(label) > self.p["max_label_length"]:
            reasons.append(f"label de {len(label)} caracteres (máx. {self.p['max_label_length']})")
        if len(label) >= self.p["entropy_min_label"] and entropy >= self.p["min_entropy"]:
            reasons.append(f"entropía {entropy} >= {self.p['min_entropy']}")
        return reasons

    def _aggregate_reason(self, sub: str) -> Optional[str]:
        """Motivo si el conjunto de subdominios (varias etiquetas cortas) parece datos."""
        minimum = self.p.get("min_total_length", 0)
        joined = sub.replace(".", "")
        if not minimum or "." not in sub or len(joined) < minimum:
            return None  # una sola etiqueta ya la cubre el análisis por etiqueta
        entropy = round(_entropy(joined), 2)
        if entropy < self.p["min_entropy"]:
            return None
        return f"{len(joined)} caracteres en {sub.count('.') + 1} etiquetas, entropía {entropy}"

    def _volume_reason(self, d: Decoded, sub: str, parent: str) -> Optional[str]:
        """Motivo si el origen consultó muchos subdominios únicos del mismo dominio padre."""
        minimum = self.p.get("min_unique_subdomains", 0)
        vkey = ("volumen", d.src, parent)
        if not minimum or not sub or vkey in self._alerted:
            return None
        window = self.p.get("volume_window_seconds", 60.0)
        seen = self._volume.get((d.src, parent)) or {}
        seen[sub] = d.ts
        for old in [k for k, t in seen.items() if d.ts - t > window]:
            del seen[old]
        self._volume[(d.src, parent)] = seen
        if len(seen) < minimum:
            return None
        self._alerted[vkey] = True
        self._volume.pop((d.src, parent), None)
        return f"{len(seen)} subdominios únicos de {parent} en {window:g} s"

    def _query_alert(self, d: Decoded, q) -> Optional[Alert]:
        """Alerta para una consulta sospechosa aún no avisada, o None."""
        name = q.name.lower()
        if self._is_ignored(name):
            return None
        sub, parent = split_registrable(name)
        label = name.split(".")[0]
        entropy = round(_entropy(label), 2)
        reasons = self._reasons(label, entropy)
        aggregate = self._aggregate_reason(sub)
        if aggregate:
            reasons.append(aggregate)
        volume = self._volume_reason(d, sub, parent)
        if volume:
            reasons.append(volume)
        key = (d.src, name)
        if not reasons or key in self._alerted:
            return None
        self._alerted[key] = True
        return self._alert(d, {
            "query": name, "qtype": q.type, "reasons": reasons,
            "label_entropy": entropy,
        })

    @staticmethod
    def _is_dns_payload(d: Decoded) -> bool:
        """UDP al puerto 53 con datos."""
        return d.proto == 17 and d.dport == 53 and bool(d.payload)

    def feed(self, d):
        if not self._is_dns_payload(d):
            return []
        dns = self._parse_query(d.payload)
        if dns is None:
            return []
        alerts = (self._query_alert(d, q) for q in dns.qd)
        return [a for a in alerts if a is not None]


DETECTORS: Dict[str, Type[Detector]] = {
    "port_scan": PortScanDetector,
    "ftp_cleartext": FtpCleartextDetector,
    "dns_suspicious": DnsSuspiciousDetector,
}


# ------------------------------------------------------------------- carga

_OPTIONAL_KEYS = {"false_positives", "investigation_steps", "wireshark_filter"}
_TOP_KEYS = {"id", "name", "description", "severity", "detector", "mitre", "params"} | _OPTIONAL_KEYS
_REQUIRED = {"id", "name", "severity", "detector", "mitre"}


def _fail(source: str, msg) -> NoReturn:  # NoReturn: tras llamarla el código no continúa
    """Lanza RuleError prefijando el archivo de origen."""
    raise RuleError(f"{source}: {msg}")


def _is_text(v) -> bool:
    """Texto con algo más que espacios."""
    return isinstance(v, str) and bool(v.strip())


def _check_keys(data: Any, source: str) -> None:
    """Valida que sea un mapa con los campos obligatorios y ninguno de más."""
    if not isinstance(data, dict):
        _fail(source, "la regla debe ser un mapa YAML")
    missing = _REQUIRED - data.keys()
    if missing:
        _fail(source, f"faltan campos: {sorted(missing)}")
    unknown = data.keys() - _TOP_KEYS
    if unknown:  # un typo ("severty") no debe ignorarse en silencio
        _fail(source, f"campos desconocidos: {sorted(unknown)}")


def _check_text_fields(data: dict, source: str) -> None:
    """Valida id/name/severity/detector como texto no vacío y el formato del id."""
    for key in ("id", "name", "severity", "detector"):
        if not _is_text(data[key]):
            _fail(source, f"'{key}' debe ser texto no vacío")
    if not re.fullmatch(r"[a-z0-9_]+", data["id"]):
        _fail(source, "'id' solo admite minúsculas, números y _")


def _check_severity(data: dict, source: str) -> None:
    """Valida que la severidad sea una de SEVERITIES."""
    if data["severity"] not in SEVERITIES:
        _fail(source, f"severity debe ser una de {SEVERITIES}, recibí {data['severity']!r}")


def _resolve_detector(data: dict, source: str) -> Type[Detector]:
    """Clase de detector nombrada por la regla, o falla si no existe."""
    detector_cls = DETECTORS.get(data["detector"])
    if detector_cls is None:
        _fail(source, f"detector desconocido {data['detector']!r}; disponibles: {sorted(DETECTORS)}")
    return detector_cls


def _check_mitre(mitre: Any, source: str) -> None:
    """Valida técnica (T1234[.001]), nombre y táctica MITRE."""
    if not isinstance(mitre, dict) or not isinstance(mitre.get("technique"), str) \
            or not _TECHNIQUE_RE.match(mitre["technique"]):
        _fail(source, "mitre.technique debe tener formato T1234 o T1234.001")
    for k in ("name", "tactic"):
        if not _is_text(mitre.get(k)):
            _fail(source, f"mitre.{k} debe ser texto no vacío")
    if mitre["tactic"] not in MITRE_TACTICS:
        _fail(source, f"mitre.tactic debe ser una de {list(MITRE_TACTICS)}, recibí {mitre['tactic']!r}")


def _build_params(data: dict, detector_cls: Type[Detector], source: str) -> Dict[str, Any]:
    """Params de la regla validados, con los defaults del detector."""
    raw = data.get("params") or {}
    if not isinstance(raw, dict):
        _fail(source, "'params' debe ser un mapa")
    known = {**COMMON_PARAMS, **detector_cls.PARAMS}
    bad = raw.keys() - known.keys()
    if bad:
        _fail(source, f"params desconocidos para {data['detector']}: {sorted(bad)}")
    params = {}
    for name, (check, default) in known.items():
        if name in COMMON_PARAMS and name not in raw:
            continue  # las excepciones solo constan si la regla las declara
        try:
            params[name] = check(raw[name]) if name in raw else default
        except ValueError as exc:
            _fail(source, f"param '{name}': {exc}")
    return params


def _text_list(data: dict, key: str, source: str) -> Tuple[str, ...]:
    """Lista de textos no vacíos de un campo opcional (ausente = vacía)."""
    value = data.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(_is_text(v) for v in value):
        _fail(source, f"'{key}' debe ser una lista de textos no vacíos")
    return tuple(v.strip() for v in value)


def _optional_fields(data: dict, source: str) -> Dict[str, Any]:
    """Campos explicativos opcionales ya validados, listos para construir la `Rule`."""
    wireshark = data.get("wireshark_filter")
    if wireshark is not None and not _is_text(wireshark):
        _fail(source, "'wireshark_filter' debe ser texto no vacío")
    return {
        "false_positives": _text_list(data, "false_positives", source),
        "investigation_steps": _text_list(data, "investigation_steps", source),
        "wireshark_filter": wireshark.strip() if wireshark else "",
    }


def _parse_rule(data: Any, source: str, directory: str = "") -> Rule:
    _check_keys(data, source)
    _check_text_fields(data, source)
    _check_severity(data, source)
    detector_cls = _resolve_detector(data, source)
    mitre = data["mitre"]
    _check_mitre(mitre, source)
    params = _build_params(data, detector_cls, source)
    return Rule(
        id=data["id"], name=data["name"], description=str(data.get("description", "")).strip(),
        severity=data["severity"], detector=data["detector"],
        mitre_technique=mitre["technique"], mitre_name=mitre["name"], mitre_tactic=mitre["tactic"],
        params=params, source=source, directory=directory, **_optional_fields(data, source),
    )


def _rule_files(p: Path) -> List[Path]:
    """Archivos de reglas: el propio archivo o los .yaml/.yml de la carpeta (ordenados)."""
    if p.is_dir():
        return sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml")))
    if p.is_file():
        return [p]
    raise FileNotFoundError(f"no existe: {p}")


def _read_yaml(f: Path) -> Any:
    """Lee un YAML; safe_load nunca ejecuta código."""
    try:
        return yaml.safe_load(f.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:  # un archivo no UTF-8 también es una regla mala
        raise RuleError(f"{f.name}: YAML inválido: {exc}") from exc


def load_rules(path) -> List[Rule]:
    """Carga un archivo .yaml o todos los .yaml de una carpeta (ordenados)."""
    rules: List[Rule] = []
    seen: Dict[str, str] = {}
    for f in _rule_files(Path(path)):
        rule = _parse_rule(_read_yaml(f), f.name, str(f.parent))
        if rule.id in seen:
            raise RuleError(f"{f.name}: id duplicado {rule.id!r} (ya definido en {seen[rule.id]})")
        seen[rule.id] = f.name
        rules.append(rule)
    return rules


def load_all_rules(bundled_dir, user_dir=None) -> List[Rule]:
    """Reglas incluidas (estrictas) más las del usuario; ver el README de `rules/` por el criterio."""
    rules = load_rules(bundled_dir)
    if user_dir is None or not Path(user_dir).is_dir():
        return rules
    seen = {r.id: "las incluidas" for r in rules}
    for f in _rule_files(Path(user_dir)):
        try:
            rule = _parse_rule(_read_yaml(f), f.name, str(f.parent))
        except RuleError as exc:  # un archivo del usuario roto no impide arrancar
            logger.warning("regla de usuario ignorada: %s", exc)
            continue
        if rule.id in seen:
            logger.warning("regla de usuario %s ignorada: el id %r ya existe en %s", f.name, rule.id, seen[rule.id])
            continue
        seen[rule.id] = f.name
        rules.append(rule)
    return rules


# ---------------------------------------------------------------- evaluación

class RuleRunner:
    """Pasa paquetes ya decodificados por los detectores (así comparte la pasada con otros)."""

    def __init__(self, rules: Iterable[Rule], linktype: int = ETHERNET):
        if linktype != ETHERNET:
            raise UnsupportedLinktype(f"linktype {linktype} no soportado (solo Ethernet = 1)")
        self._detectors = [DETECTORS[r.detector](r) for r in rules]
        self._alerts: List[Alert] = []

    def feed(self, d: Optional[Decoded]) -> None:
        """Alimenta los detectores con un paquete decodificado (None = no aplica)."""
        if d is None:
            return
        for det in self._detectors:
            if not det.allow.allows(d):
                self._alerts.extend(det.feed(d))

    def alerts(self) -> List[Alert]:
        """Las alertas ordenadas por tiempo."""
        return sorted(self._alerts, key=lambda a: a.first_ts)


def evaluate(rules: Iterable[Rule], packets: Iterable[Packet], linktype: int = ETHERNET) -> List[Alert]:
    """Pasa cada paquete por todos los detectores y devuelve las alertas ordenadas por tiempo."""
    runner = RuleRunner(rules, linktype)
    for pkt in packets:
        runner.feed(_decode(pkt))
    return runner.alerts()


# Detectores adicionales
from backend.domain.rules import extra_detectors as _extra  # noqa: E402

# getattr: si alguien importó extra_detectors ANTES que este módulo
DETECTORS.update(getattr(_extra, "DETECTORS", {}))
