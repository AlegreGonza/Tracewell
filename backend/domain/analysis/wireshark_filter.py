"""Filtros de visualización de Wireshark para una sesión, una IP o una alerta.

Es la «llave» para pasar de Tracewell a Wireshark: el analista copia el filtro, abre el `.pcap` y ve los
mismos paquetes. Funciones puras (sin I/O): reciben datos simples y devuelven texto.

Todo lo que viene del tráfico (nombres DNS, por ejemplo) se escapa antes de ir entre comillas: un nombre
hostil no puede cerrar la cadena y agregar condiciones al filtro.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Optional

_PORT_PROTOCOLS = {"TCP": "tcp", "UDP": "udp"}
_NAMED_PROTOCOLS = {"ICMP": "icmp", "ICMPv6": "icmpv6"}
_SYN_ONLY = "tcp.flags.syn==1 && tcp.flags.ack==0"
MAX_PORTS = 20  # puertos de muestra que caben en un filtro legible


def _parse_ip(ip: Any) -> ipaddress._BaseAddress:
    """IP como objeto; ValueError con mensaje claro si no es una dirección (se ignora la zona IPv6)."""
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError(f"IP inválida: {ip!r}")
    try:
        return ipaddress.ip_address(ip.strip().split("%", 1)[0])
    except ValueError:
        raise ValueError(f"IP inválida: {ip[:60]!r}") from None


def _field(addr, suffix: str) -> str:
    """Nombre del campo de Wireshark: ip.addr / ip.src / ip.dst o ipv6.addr / ipv6.src / ipv6.dst."""
    return f"{'ipv6' if addr.version == 6 else 'ip'}.{suffix}"


def _quote(text: str) -> str:
    """Cadena entre comillas para Wireshark: se escapan la barra y la comilla, y se descartan los controles."""
    clean = "".join(c for c in text if c.isprintable())
    return '"' + clean.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _valid_port(p: Any) -> bool:
    return isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535


def ip_filter(ip: str) -> str:
    """Todo el tráfico de una IP: `ip.addr==X` (o `ipv6.addr==X`)."""
    addr = _parse_ip(ip)
    return f"{_field(addr, 'addr')}=={addr.compressed}"


def _ends_filter(src_ip: str, dst_ip: str) -> str:
    """Los dos extremos, en cualquier sentido (una sesión es bidireccional)."""
    a, b = _parse_ip(src_ip), _parse_ip(dst_ip)
    first = f"{_field(a, 'addr')}=={a.compressed}"
    if a == b:
        return first
    return f"{first} && {_field(b, 'addr')}=={b.compressed}"


def _protocol_part(protocol: str, addr, src_port, dst_port) -> Optional[str]:
    """Parte del filtro que fija el protocolo (y los puertos, si los tiene)."""
    if protocol in _PORT_PROTOCOLS:
        name = _PORT_PROTOCOLS[protocol]
        ports = [p for p in (src_port, dst_port) if _valid_port(p)]
        if not ports:
            return name
        return " && ".join(f"{name}.port=={p}" for p in dict.fromkeys(ports))
    if protocol in _NAMED_PROTOCOLS:
        return _NAMED_PROTOCOLS[protocol]
    if isinstance(protocol, str) and protocol.startswith("IP-") and protocol[3:].isdigit():
        return f"{'ipv6.nxt' if addr.version == 6 else 'ip.proto'}=={int(protocol[3:])}"
    return None


def session_filter(protocol: str, src_ip: str, src_port: Optional[int], dst_ip: str, dst_port: Optional[int]) -> str:
    """Filtro de UNA sesión: los dos extremos, el protocolo y los puertos (TCP/UDP), en ambos sentidos."""
    parts = [_ends_filter(src_ip, dst_ip)]
    proto = _protocol_part(protocol, _parse_ip(src_ip), src_port, dst_port)
    if proto:
        parts.append(proto)
    return " && ".join(parts)


def _evidence_port(evidence: Mapping[str, Any]) -> Optional[int]:
    for key in ("destination_port", "port"):
        if _valid_port(evidence.get(key)):
            return evidence[key]
    return None


def _evidence_protocol(evidence: Mapping[str, Any]) -> str:
    return "udp" if str(evidence.get("protocol", "")).upper() == "UDP" else "tcp"


def _dns_name(evidence: Mapping[str, Any]) -> Optional[str]:
    for key in ("query", "first_query"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _scan_ports(evidence: Mapping[str, Any]) -> list:
    ports = evidence.get("sample_ports")
    if not isinstance(ports, list):
        return []
    return sorted({p for p in ports if _valid_port(p)})[:MAX_PORTS]


def _flood_filter(dst_ip: str, port: Optional[int]) -> str:
    """Inundación SYN: muchos orígenes distintos, así que se filtra por la VÍCTIMA y no por un origen."""
    dst = _parse_ip(dst_ip)
    parts = [f"{_field(dst, 'dst')}=={dst.compressed}", _SYN_ONLY]
    if port is not None:
        parts.insert(1, f"tcp.dstport=={port}")
    return " && ".join(parts)


def _scan_filter(src_ip: str, dst_ip: str, ports: list) -> str:
    """Escaneo: los SYN puros del atacante hacia la víctima, solo a los puertos tocados."""
    src, dst = _parse_ip(src_ip), _parse_ip(dst_ip)
    parts = [f"{_field(src, 'src')}=={src.compressed}", f"{_field(dst, 'dst')}=={dst.compressed}", _SYN_ONLY]
    if ports:
        parts.append("tcp.dstport in {" + " ".join(str(p) for p in ports) + "}")
    return " && ".join(parts)


def alert_filter(src_ip: str, dst_ip: str, evidence: Optional[Mapping[str, Any]] = None) -> str:
    """Filtro de una alerta, derivado de su evidencia.

    Sin evidencia útil devuelve los dos extremos; con ella lo afina: nombre DNS (`dns.qry.name`), puertos
    de un escaneo, puerto de destino o la víctima de una inundación. Es una pista para llegar a los paquetes:
    el analista puede ampliarlo o recortarlo en Wireshark.
    """
    ev = evidence if isinstance(evidence, Mapping) else {}
    if _is_flood(ev):
        return _flood_filter(dst_ip, _evidence_port(ev))
    ports = _scan_ports(ev)
    if ports:
        return _scan_filter(src_ip, dst_ip, ports)
    parts = [_ends_filter(src_ip, dst_ip)]
    name = _dns_name(ev)
    if name:
        parts.append(f"dns.qry.name=={_quote(name)}")
    else:
        port = _evidence_port(ev)
        if port is not None:
            parts.append(f"{_evidence_protocol(ev)}.port=={port}")
    return " && ".join(parts)


def _is_flood(evidence: Mapping[str, Any]) -> bool:
    sources = evidence.get("distinct_sources")
    return isinstance(sources, int) and not isinstance(sources, bool) and sources > 1 and "syn_packets" in evidence
