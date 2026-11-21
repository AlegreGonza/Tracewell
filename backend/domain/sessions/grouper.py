"""Agrupa paquetes en sesiones (flujos de red).

Una sesión es una conversación entre dos extremos: se identifica por la
"5-tupla" (IP origen, puerto origen, IP destino, puerto destino, protocolo).

Por qué agrupar: un analista no mira 2 millones de paquetes sueltos; mira
"esta IP habló 40.000 veces con aquella en el puerto 21". La sesión es la
unidad con la que razonan las reglas (escaneo de puertos = una IP, muchas
sesiones a puertos distintos).
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import dpkt

from backend.domain.pcap.reader import Packet

ETHERNET = 1  # linktype soportado por ahora (el 99% de las capturas de escritorio)

# Tope de sesiones en memoria (~640 B c/u => ~320 MB en el peor caso).
DEFAULT_MAX_SESSIONS = 500_000

_IP_ETHERTYPES = (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6)
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_PORT_PROTOS = (6, 17)  # solo TCP y UDP tienen puertos


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
    # Clave bidireccional de la sesión. Sirve para volver a encontrar sus
    # paquetes más tarde sin guardarlos en memoria. Interna: no se exporta.
    key: Optional[Tuple] = field(default=None, repr=False, compare=False)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


@dataclass
class GroupingResult:
    sessions: List[Session] = field(default_factory=list)
    non_ip: int = 0  # ARP, STP, etc.: no tienen IP, no pertenecen a una sesión
    malformed: int = 0  # IP/TCP/UDP ilegible (truncado o fragmento sin puertos)
    # Análisis parcial: se alcanzó el tope de sesiones y las sesiones NUEVAS ya
    # no se registraron. Se informa para que el analista no crea que vio todo.
    truncated: bool = False
    untracked_packets: int = 0  # paquetes de sesiones que no se registraron por el tope


def _inner_ethertype(eth) -> int:
    """Ethertype real del contenido: con una etiqueta VLAN 802.1Q, dpkt deja
    `eth.type` en 0x8100 y guarda el tipo interno en la última de `vlan_tags`."""
    tags = getattr(eth, "vlan_tags", None)
    return tags[-1].type if tags else eth.type


def ip_layer(data: bytes):
    """Ethernet -> capa IP: devuelve (ip, familia) o None si el paquete no es IP.

    Lanza dpkt.UnpackError si está dañado o es un fragmento sin capa 4.
    """
    eth = dpkt.ethernet.Ethernet(data)
    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        # Un fragmento que NO es el primero no trae cabecera TCP/UDP: sus
        # "puertos" serían basura. Lo tratamos como dañado en vez de inventar.
        if ip.offset:
            raise dpkt.UnpackError("fragmento IP sin cabecera de capa 4")
        return ip, socket.AF_INET
    if isinstance(ip, dpkt.ip6.IP6):
        return ip, socket.AF_INET6
    # El Ethernet DICE llevar IP pero dpkt no pudo leerla (cabecera cortada) y
    # dejó bytes crudos: es un paquete dañado, no uno "sin IP" como un ARP.
    # Sin esto se contaba en `non_ip` y el analista no veía que había daño.
    if _inner_ethertype(eth) in _IP_ETHERTYPES:
        raise dpkt.UnpackError("cabecera IP ilegible")
    return None


def _protocol_number(ip) -> int:
    """Protocolo del payload IP, aun en IPv6 con cabeceras de extensión."""
    # En IPv6 dpkt solo setea `p` (protocolo del payload tras las cabeceras de
    # extensión) si pudo seguir la cadena; con ESP (cifrado) no hay "siguiente"
    # visible y `p` no existe. En ese caso la última cabecera de la cadena es
    # lo más honesto que podemos reportar.
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


def _endpoints(data: bytes):
    """Extrae (ip_src, sport, ip_dst, dport, proto) o None si no es IP.

    Lanza dpkt.UnpackError si el paquete está dañado.
    """
    layer = ip_layer(data)
    if layer is None:
        return None
    ip, family = layer
    proto = _protocol_number(ip)
    sport, dport = _l4_ports(ip, proto)
    return (
        socket.inet_ntop(family, ip.src), sport,
        socket.inet_ntop(family, ip.dst), dport,
        proto,
    )


def _key(src, sport, dst, dport, proto) -> Tuple:
    """Clave BIDIRECCIONAL: A->B y B->A caen en la misma sesión.

    Ordenamos los dos extremos para que no importe quién habla. Sin esto, la
    respuesta del servidor abriría una "sesión" aparte de la petición.
    """
    a = (src, -1 if sport is None else sport)
    b = (dst, -1 if dport is None else dport)
    return (min(a, b), max(a, b), proto)


def packet_endpoints(data: bytes):
    """(ip_src, sport, ip_dst, dport, proto) de un paquete, o None si no es IP
    o está dañado. Versión que nunca lanza, para consultas sueltas."""
    try:
        return _endpoints(data)
    except dpkt.UnpackError:
        return None


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


def _new_session(ends, key, ts: float) -> Session:
    """Crea la sesión con el primer paquete: su emisor queda como origen."""
    src, sport, dst, dport, proto = ends
    return Session(
        protocol=_PROTO_NAMES.get(proto, f"IP-{proto}"),
        src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
        first_ts=ts, key=key,
    )


def _record_packet(sess: Session, pkt: Packet) -> None:
    """Suma el paquete a los contadores de su sesión."""
    sess.packets += 1
    # origlen = bytes reales en el cable; len(data) puede ser menos si hubo
    # snaplen. Para "cuánto tráfico fue" importa lo que viajó, no lo guardado.
    sess.bytes += pkt.origlen if pkt.origlen is not None else len(pkt.data)
    sess.last_ts = pkt.ts


def _classify(pkt: Packet, result: GroupingResult):
    """(ends, key) del paquete; si no es una sesión cuenta el descarte y da None."""
    try:
        ends = _endpoints(pkt.data)
    except dpkt.UnpackError:  # incluye NeedData
        result.malformed += 1
        return None
    if ends is None:
        result.non_ip += 1
        return None
    return ends, _key(*ends)


def group_packets(
    packets: Iterable[Packet],
    linktype: int = ETHERNET,
    max_sessions: int = DEFAULT_MAX_SESSIONS,
) -> GroupingResult:
    """Recorre los paquetes (en streaming) y arma las sesiones.

    En memoria guardamos un resumen por sesión, no los paquetes: el costo
    crece con la cantidad de sesiones (~640 B cada una), no con el tamaño del
    archivo. Pero un escaneo o un DDoS puede generar millones de sesiones, así
    que hay un TOPE: al alcanzarlo, las sesiones nuevas se descartan (las
    existentes siguen actualizándose) y el resultado queda marcado `truncated`.
    """
    _check_group_args(linktype, max_sessions)
    sessions: Dict[Tuple, Session] = {}
    result = GroupingResult()
    for pkt in packets:
        classified = _classify(pkt, result)
        if classified is None:
            continue
        ends, key = classified
        sess = sessions.get(key)
        if sess is None and len(sessions) >= max_sessions:
            result.truncated = True
            result.untracked_packets += 1
            continue
        if sess is None:
            sess = sessions[key] = _new_session(ends, key, pkt.ts)
        _record_packet(sess, pkt)
    result.sessions = list(sessions.values())  # orden de aparición
    return result
