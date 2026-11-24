"""Agrupa paquetes en sesiones (flujos de red)."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import dpkt

from backend.domain.pcap.reader import Packet

ETHERNET = 1  # linktype soportado por ahora

# Tope de sesiones en memoria (~640 B c/u => ~320 MB en el peor caso).
DEFAULT_MAX_SESSIONS = 500_000

_IP_ETHERTYPES = (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6)
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_PORT_PROTOS = (6, 17)  # solo TCP y UDP tienen puertos
_TCP = 6
_TCP_SYN, _TCP_RST, _TCP_ACK = 0x02, 0x04, 0x10


class UnsupportedLinktype(ValueError):
    """La captura no es Ethernet; todavía no sabemos interpretarla."""


@dataclass
class Session:
    protocol: str
    # Extremo "origen" = quien envió el PRIMER paquete que vimos (el iniciador).
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    # Clave bidireccional de la sesión
    key: Optional[Tuple] = field(default=None, repr=False, compare=False)
    # Banderas TCP contadas por sesión (0 en UDP/ICMP)
    syn_packets: int = 0  # SYN puros (intentos de abrir conexión)
    rst_packets: int = 0  # paquetes con RST (corte o rechazo)
    # MAC de cada extremo, leídas del PRIMER paquete de la sesión (Ethernet)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def syn_retries(self) -> int:
        """SYN reenviados: más de un SYN puro en la misma sesión es un reintento de conexión."""
        return max(self.syn_packets - 1, 0)


@dataclass
class GroupingResult:
    sessions: List[Session] = field(default_factory=list)
    non_ip: int = 0  # ARP, STP, etc.: no tienen IP, no pertenecen a una sesión
    malformed: int = 0  # IP/TCP/UDP ilegible (truncado o fragmento sin puertos)
    # Análisis parcial
    truncated: bool = False
    untracked_packets: int = 0  # paquetes de sesiones que no se registraron por el tope


def _inner_ethertype(eth) -> int:
    """Ethertype real del contenido."""
    tags = getattr(eth, "vlan_tags", None)
    return tags[-1].type if tags else eth.type


def ip_layer(data: bytes):
    """Ethernet -> capa IP: devuelve (ip, familia) o None si el paquete no es IP."""
    eth = dpkt.ethernet.Ethernet(data)
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        # Un fragmento que NO es el primero no trae cabecera TCP/UDP: sus "puertos" serían basura
        if ip.offset:
            raise dpkt.UnpackError("fragmento IP sin cabecera de capa 4")
        return ip, socket.AF_INET
    if isinstance(ip, dpkt.ip6.IP6):
        return ip, socket.AF_INET6
    # El Ethernet DICE llevar IP pero dpkt no pudo leerla (cabecera cortada) y dejó bytes crudos
    if _inner_ethertype(eth) in _IP_ETHERTYPES:
        raise dpkt.UnpackError("cabecera IP ilegible")
    return None


def _protocol_number(ip) -> int:
    """Protocolo del payload IP, aun en IPv6 con cabeceras de extensión."""
    # En IPv6 dpkt solo setea `p` (protocolo del payload tras las cabeceras de extensión)
    proto = getattr(ip, "p", None)
    if proto is None:
        ext = list(ip.extension_hdrs)
        proto = ext[-1] if ext else ip.nxt
    return proto


def _l4_ports(ip, proto):
    """(sport, dport) de TCP/UDP; (None, None) para otros protocolos."""
    if proto not in _PORT_PROTOS:
        return None, None
    l4 = ip.data
    # Si dpkt no pudo interpretar la capa 4 deja bytes crudos: está truncada.
    if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        raise dpkt.UnpackError("cabecera de capa 4 ilegible")
    return l4.sport, l4.dport


def parse_ip(data: bytes):
    """(capa IP, dañado): `ip_layer` sin lanzar; dañado=True si dpkt no pudo leer el paquete."""
    try:
        return ip_layer(data), False
    except dpkt.UnpackError:  # incluye NeedData
        return None, True


def _layer_endpoints_flags(layer):
    """((ip_src, sport, ip_dst, dport, proto), flags TCP) de una capa IP (flags = 0 si no es TCP)."""
    ip, family = layer
    proto = _protocol_number(ip)
    sport, dport = _l4_ports(ip, proto)
    ends = (socket.inet_ntop(family, ip.src), sport, socket.inet_ntop(family, ip.dst), dport, proto)
    return ends, (ip.data.flags if proto == _TCP else 0)


def _endpoints_flags(data: bytes):
    """Como `_layer_endpoints_flags` pero desde los bytes; None si no es IP."""
    layer = ip_layer(data)
    return None if layer is None else _layer_endpoints_flags(layer)


def _key(src, sport, dst, dport, proto) -> Tuple:
    """Clave BIDIRECCIONAL: A->B y B->A caen en la misma sesión."""
    a = (src, -1 if sport is None else sport)
    b = (dst, -1 if dport is None else dport)
    return (min(a, b), max(a, b), proto)


def packet_endpoints(data: bytes):
    """(ip_src, sport, ip_dst, dport, proto) de un paquete, o None si no es IP o está dañado."""
    try:
        found = _endpoints_flags(data)
    except dpkt.UnpackError:
        return None
    return None if found is None else found[0]


def packet_session_key(pkt: Packet) -> Optional[Tuple]:
    """Clave de sesión de un paquete, o None si no pertenece a ninguna."""
    ends = packet_endpoints(pkt.data)
    return None if ends is None else _key(*ends)


def _check_group_args(linktype: int, max_sessions) -> None:
    """Valida linktype y tope antes de recorrer ningún paquete."""
    if linktype != ETHERNET:
        raise UnsupportedLinktype(f"linktype {linktype} no soportado (solo Ethernet = 1)")
    if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions < 1:
        raise ValueError(f"max_sessions debe ser un entero positivo, recibí {max_sessions!r}")


def _mac(raw: bytes) -> Optional[str]:
    """MAC legible (aa:bb:cc:dd:ee:ff) de 6 bytes, o None si el paquete es demasiado corto."""
    return ":".join(f"{b:02x}" for b in raw) if len(raw) == 6 else None


def _new_session(ends, key, ts: float, frame: bytes = b"") -> Session:
    """Crea la sesión con el primer paquete: su emisor queda como origen (y su MAC, la de origen)."""
    src, sport, dst, dport, proto = ends
    return Session(
        protocol=_PROTO_NAMES.get(proto, f"IP-{proto}"),
        src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
        first_ts=ts, key=key, dst_mac=_mac(frame[0:6]), src_mac=_mac(frame[6:12]),
    )


def _record_packet(sess: Session, pkt: Packet, flags: int = 0) -> None:
    """Suma el paquete a los contadores de su sesión (y las banderas TCP que importan)."""
    sess.packets += 1
    if flags & _TCP_SYN and not flags & _TCP_ACK:
        sess.syn_packets += 1
    if flags & _TCP_RST:
        sess.rst_packets += 1
    # origlen = bytes reales en el cable; len(data) puede ser menos si hubo snaplen
    sess.bytes += pkt.origlen if pkt.origlen is not None else len(pkt.data)
    sess.last_ts = pkt.ts


class SessionGrouper:
    """Arma las sesiones paquete a paquete (así comparte la pasada con otros recolectores)."""

    def __init__(self, linktype: int = ETHERNET, max_sessions: int = DEFAULT_MAX_SESSIONS):
        _check_group_args(linktype, max_sessions)
        self._max = max_sessions
        self._sessions: Dict[Tuple, Session] = {}
        self._result = GroupingResult()

    def _classify(self, layer, malformed: bool):
        """(ends, key, flags TCP) del paquete; si no es una sesión cuenta el descarte y da None."""
        if not malformed and layer is not None:
            try:
                ends, flags = _layer_endpoints_flags(layer)
            except dpkt.UnpackError:  # capa 4 cortada
                malformed = True
            else:
                return ends, _key(*ends), flags
        if malformed:
            self._result.malformed += 1
        else:
            self._result.non_ip += 1
        return None

    def add(self, pkt: Packet, layer, malformed: bool = False) -> None:
        """Suma un paquete ya decodificado con `parse_ip` (capa IP o dañado)."""
        classified = self._classify(layer, malformed)
        if classified is None:
            return
        ends, key, flags = classified
        sess = self._sessions.get(key)
        if sess is None and len(self._sessions) >= self._max:
            self._result.truncated = True
            self._result.untracked_packets += 1
            return
        if sess is None:
            sess = self._sessions[key] = _new_session(ends, key, pkt.ts, pkt.data)
        _record_packet(sess, pkt, flags)

    def result(self) -> GroupingResult:
        """Resultado con las sesiones en orden de aparición."""
        self._result.sessions = list(self._sessions.values())
        return self._result


def group_packets(
    packets: Iterable[Packet],
    linktype: int = ETHERNET,
    max_sessions: int = DEFAULT_MAX_SESSIONS,
) -> GroupingResult:
    """Recorre los paquetes (en streaming) y arma las sesiones."""
    grouper = SessionGrouper(linktype, max_sessions)
    for pkt in packets:
        grouper.add(pkt, *parse_ip(pkt.data))
    return grouper.result()
