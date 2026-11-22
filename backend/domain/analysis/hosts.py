"""Vista por EQUIPO (IP) de una captura: quién es cada uno, con quién habla y cuánto.

Es la mirada que usan NetworkMiner o la pestaña "Conversaciones → IPv4" de Wireshark, pero resumida:
una fila por IP y un grafo "quién habla con quién". Todo sale de las sesiones ya calculadas, sin
volver a leer la captura.

Límites: se resume por SESIÓN (no por paquete); los bytes de una sesión cuentan para sus DOS extremos;
`MAX_PEERS` acota la memoria por equipo (un escaneo a miles de destinos no la hace crecer sin límite).
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from backend.domain.analysis.owners import describe_ip

MAX_PEERS = 5_000  # destinos distintos que se recuerdan por equipo (después solo se cuenta)
MAX_EDGES = 300
TOP_PORTS = 5
WEB_PORTS = frozenset({80, 443, 8080, 8443})
TOP_TALKERS = 3  # cuántos equipos, como máximo, se marcan como «top talker»
TALKER_MIN_SHARE = 0.10  # ...y solo si movieron al menos esta parte de los bytes de la captura

ROLE_DNS_CLIENT = "Cliente DNS"
ROLE_WEB_SERVER = "Servidor web"
ROLE_SCANNER = "Emisor de escaneos"
ROLE_TOP_TALKER = "Top talker"


def classify(ip: str) -> str:
    """'interna' (red local), 'multicast' o 'publica'. Una IP ilegible cuenta como pública."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return "publica"
    if addr.is_multicast:
        return "multicast"
    return "interna" if addr.is_private else "publica"


@dataclass
class Host:
    ip: str
    kind: str
    sessions: int = 0
    packets: int = 0
    bytes: int = 0
    initiated: int = 0  # sesiones que este equipo abrió (era el origen)
    received: int = 0  # sesiones en las que fue el destino
    peers: int = 0
    protocols: List[str] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)  # puertos más usados COMO destino
    name: Optional[str] = None
    alerts: int = 0
    alert_rules: List[str] = field(default_factory=list)
    ioc: List[str] = field(default_factory=list)
    role: str = "publica"  # red_local | ipv6_local | multicast | publica
    role_label: str = ""
    owner: Optional[str] = None  # dueño conocido del rango (tabla local, solo pista)
    note: Optional[str] = None  # qué es una dirección especial (p. ej. mDNS)
    # Perfil: roles INFERIDOS de lo observado en esta captura (cliente DNS, servidor web, emisor de
    # escaneos, top talker). Son pistas, no una auditoría: un equipo que no aparece no «no es» eso.
    roles: List[str] = field(default_factory=list)
    # MAC más vista de este equipo (solo equipos de la red local: la MAC de un extremo remoto es la del router).
    mac: Optional[str] = None


class _Acc:
    """Acumulador por IP mientras se recorren las sesiones."""

    def __init__(self) -> None:
        self.sessions = self.packets = self.bytes = self.initiated = self.received = 0
        self.peers: Set[str] = set()
        self.peer_overflow = 0
        self.protocols: Set[str] = set()
        self.ports: Counter = Counter()
        self.macs: Counter = Counter()  # MAC -> veces vista (solo equipos de la red local)
        self.client_services: Counter = Counter()  # (protocolo, puerto) de los servicios a los que este equipo SE CONECTÓ
        self.names: Counter = Counter()

    def add(self, s, other_ip: str, as_origin: bool, service_port: Optional[int], name: Optional[str],
            client_service: Optional[Tuple[str, int]] = None, mac: Optional[str] = None) -> None:
        """`service_port` y `name` solo llegan si este equipo es el SERVIDOR de la sesión; `client_service`, si es el CLIENTE."""
        self.sessions += 1
        self.packets += s.packets
        self.bytes += s.bytes
        self.protocols.add(s.protocol)
        if as_origin:
            self.initiated += 1
        else:
            self.received += 1
        if service_port is not None:
            self.ports[(s.protocol, service_port)] += 1
        if name:
            self.names[name] += 1
        if mac:
            self.macs[mac] += 1
        if client_service is not None and client_service[1] is not None:
            self.client_services[client_service] += 1
        if other_ip in self.peers:
            return
        if len(self.peers) < MAX_PEERS:
            self.peers.add(other_ip)
        else:
            self.peer_overflow += 1


def _server_is_src(s) -> bool:
    """¿El servidor es el extremo de ORIGEN? El "origen" es quien mandó el primer paquete VISTO: si la captura
    empezó a mitad de la conversación está al revés. Se decide por el puerto (uno bajo, como 443, es un servicio),
    y si no alcanza, por la red: el que está afuera de la red local es el servidor."""
    if s.src_port is not None and s.dst_port is not None:
        if s.src_port < 1024 <= s.dst_port:
            return True
        if s.dst_port < 1024 <= s.src_port:
            return False
    src_kind, dst_kind = classify(s.src_ip), classify(s.dst_ip)
    return src_kind != "interna" and dst_kind == "interna"


def _host_mac(ip: str, mac: Optional[str]) -> Optional[str]:
    """La MAC solo identifica al equipo si es de la red local y de UN equipo: se descartan las de grupo
    (multicast y broadcast, bit 0 del primer byte) y las de equipos remotos (serían la del router)."""
    if not mac or classify(ip) != "interna":
        return None
    return None if int(mac[:2], 16) & 1 else mac


def _accumulate(sessions: Iterable, names) -> Dict[str, _Acc]:
    accs: Dict[str, _Acc] = {}
    for s in sessions:
        name = names.best_name(s) if names is not None else None
        src_is_server = _server_is_src(s)
        service = s.src_port if src_is_server else s.dst_port
        accs.setdefault(s.src_ip, _Acc()).add(
            s, s.dst_ip, True, s.src_port if src_is_server else None, name if src_is_server else None,
            None if src_is_server else (s.protocol, service), _host_mac(s.src_ip, getattr(s, "src_mac", None)))
        accs.setdefault(s.dst_ip, _Acc()).add(
            s, s.src_ip, False, None if src_is_server else s.dst_port, None if src_is_server else name,
            (s.protocol, service) if src_is_server else None, _host_mac(s.dst_ip, getattr(s, "dst_mac", None)))
    return accs


def _alert_index(alerts: Iterable) -> Dict[str, Set[str]]:
    """IP -> reglas que la involucran (como origen o destino de una alerta)."""
    index: Dict[str, Set[str]] = {}
    for a in alerts:
        for ip in (a.src_ip, a.dst_ip):
            index.setdefault(ip, set()).add(a.rule_id)
    return index


def _scan_sources(alerts: Iterable) -> Set[str]:
    """IP que dispararon la regla de escaneo de puertos (como ORIGEN de la alerta)."""
    return {a.src_ip for a in alerts if a.rule_id == "port_scan"}


def _roles(acc: _Acc, scanner: bool) -> List[str]:
    """Roles que se desprenden SOLO de lo observado en las sesiones y las alertas de esta captura."""
    roles = []
    if any(port == 53 for (_proto, port) in acc.client_services):
        roles.append(ROLE_DNS_CLIENT)
    if any(proto == "TCP" and port in WEB_PORTS for (proto, port) in acc.ports):
        roles.append(ROLE_WEB_SERVER)
    if scanner:
        roles.append(ROLE_SCANNER)
    return roles


def _mark_top_talkers(hosts: List[Host], total_bytes: int) -> None:
    """Marca como «Top talker» a los que más bytes movieron (ya ordenados), si pesan lo suficiente."""
    if total_bytes <= 0:
        return
    for h in hosts[:TOP_TALKERS]:
        if h.bytes / total_bytes >= TALKER_MIN_SHARE:
            h.roles.append(ROLE_TOP_TALKER)


def _to_host(ip: str, acc: _Acc, names, rules: Set[str], alert_count: int, ioc, scanner: bool = False) -> Host:
    kind = classify(ip)
    # Un equipo de TU red no se llama como el sitio al que se conecta: el nombre es del servidor.
    name = acc.names.most_common(1)[0][0] if acc.names else (names.dns.get(ip) if names is not None else None)
    info = describe_ip(ip, kind)
    return Host(
        role=info["role"] or "publica", role_label=info["role_label"] or "", owner=info["owner"], note=info["note"],
        ip=ip, kind=kind, sessions=acc.sessions, packets=acc.packets, bytes=acc.bytes,
        initiated=acc.initiated, received=acc.received, peers=len(acc.peers) + acc.peer_overflow,
        protocols=sorted(acc.protocols),
        services=[{"protocol": p, "port": port, "sessions": n} for (p, port), n in acc.ports.most_common(TOP_PORTS)],
        name=name, alerts=alert_count, alert_rules=sorted(rules),
        ioc=[m] if ioc is not None and (m := ioc.match_ip(ip)) else [],
        roles=_roles(acc, scanner), mac=acc.macs.most_common(1)[0][0] if acc.macs else None,
    )


def build_hosts(sessions, names=None, alerts: Iterable = (), ioc=None) -> List[Host]:
    """Un Host por IP, ordenado de más a menos tráfico."""
    alerts, sessions = list(alerts), list(sessions)
    index = _alert_index(alerts)
    scanners = _scan_sources(alerts)
    counts: Counter = Counter()
    for a in alerts:
        for ip in {a.src_ip, a.dst_ip}:
            counts[ip] += 1
    hosts = [
        _to_host(ip, acc, names, index.get(ip, set()), counts[ip], ioc, ip in scanners)
        for ip, acc in _accumulate(sessions, names).items()
    ]
    hosts.sort(key=lambda h: (-h.bytes, -h.sessions, h.ip))
    _mark_top_talkers(hosts, sum(s.bytes for s in sessions))
    return hosts


def build_graph(sessions, hosts: List[Host], limit: int = 24) -> Dict[str, Any]:
    """Grafo de los `limit` equipos con más tráfico: nodos y aristas (pares de equipos que hablaron)."""
    top = hosts[:limit]
    chosen = {h.ip for h in top}
    edges: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for s in sessions:
        if s.src_ip not in chosen or s.dst_ip not in chosen or s.src_ip == s.dst_ip:
            continue
        key = tuple(sorted((s.src_ip, s.dst_ip)))
        e = edges.setdefault(key, {"a": key[0], "b": key[1], "bytes": 0, "sessions": 0, "protocols": set()})
        e["bytes"] += s.bytes
        e["sessions"] += 1
        e["protocols"].add(s.protocol)
    ordered = sorted(edges.values(), key=lambda e: -e["bytes"])[:MAX_EDGES]
    for e in ordered:
        e["protocols"] = sorted(e["protocols"])
    return {
        "nodes": [
            {"ip": h.ip, "kind": h.kind, "label": h.name or h.ip, "bytes": h.bytes, "sessions": h.sessions,
             "alerts": h.alerts, "ioc": bool(h.ioc), "name": h.name, "role": h.role, "role_label": h.role_label,
             "owner": h.owner, "note": h.note}
            for h in top
        ],
        "edges": ordered,
        "truncated": len(hosts) > limit or len(edges) > MAX_EDGES,
    }


def _mac_hint(mac: str, shared: bool) -> str:
    """Pista de lectura de un grupo de MAC (orientativa, no una prueba)."""
    parts = []
    if int(mac[:2], 16) & 2:
        parts.append("MAC administrada localmente (privada o aleatoria): suele ser un teléfono o equipo que la rota, o una máquina virtual.")
    if shared:
        parts.append(
            "Varias IP con la misma MAC: puede ser el mismo equipo con IPv4 e IPv6 o con varias direcciones, "
            "pero también un router, NAT o puente que reenvía tráfico de otras redes."
        )
    return " ".join(parts)


def build_mac_groups(hosts: Iterable[Host]) -> List[Dict[str, Any]]:
    """Agrupa los equipos por MAC: una fila por MAC con sus IP. Los grupos con varias IP van primero.

    Solo entran equipos de la red local con una MAC conocida; los demás no tienen MAC propia en la captura.
    """
    groups: Dict[str, List[Host]] = {}
    for h in hosts:
        if h.mac:
            groups.setdefault(h.mac, []).append(h)
    rows = [
        {
            "mac": mac, "ips": sorted(h.ip for h in members), "names": sorted({h.name for h in members if h.name}),
            "sessions": sum(h.sessions for h in members), "bytes": sum(h.bytes for h in members),
            "shared": len(members) > 1, "hint": _mac_hint(mac, len(members) > 1),
        }
        for mac, members in groups.items()
    ]
    rows.sort(key=lambda r: (-len(r["ips"]), -r["bytes"], r["mac"]))
    return rows
