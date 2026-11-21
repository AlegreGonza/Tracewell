"""Quién es una IP, SIN salir a internet: un rol (tu red, multicast, servidor público…) y, para unos pocos
proveedores grandes, el dueño del rango.

La tabla de dueños es CHICA y a propósito conservadora: solo rangos que pertenecen a una empresa conocida.
Es una pista, no una prueba: una IP de Amazon o de Microsoft puede estar alquilada a cualquiera (la nube se
alquila), y los rangos cambian con el tiempo. Por eso la pantalla lo muestra como «rango de …», nunca como
un hecho, y un nombre sacado de la propia captura (DNS o TLS) siempre le gana.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

# (dueño, rangos). Solo se listan rangos de los que hay certeza razonable.
_OWNER_RANGES: List[Tuple[str, Tuple[str, ...]]] = [
    ("Google", ("8.8.8.0/24", "8.8.4.0/24", "64.233.160.0/19", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15",
                "172.217.0.0/16", "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19", "2607:f8b0::/32", "2a00:1450::/32")),
    ("Cloudflare", ("1.0.0.0/24", "1.1.1.0/24", "104.16.0.0/13", "162.158.0.0/15", "172.64.0.0/13", "188.114.96.0/20",
                    "2606:4700::/32")),
    ("Anthropic", ("160.79.104.0/23",)),
    ("Microsoft", ("13.64.0.0/11", "20.0.0.0/11", "40.64.0.0/10", "52.96.0.0/12", "150.171.0.0/16", "204.79.197.0/24")),
    ("Amazon AWS", ("18.32.0.0/11", "18.64.0.0/10", "52.0.0.0/10")),
    ("Fastly", ("151.101.0.0/16", "199.232.0.0/16")),
    ("Akamai", ("23.32.0.0/11", "104.64.0.0/10")),
    ("Meta (Facebook / WhatsApp)", ("31.13.24.0/21", "157.240.0.0/16", "2a03:2880::/32")),
    ("Apple", ("17.0.0.0/8",)),
    ("GitHub", ("140.82.112.0/20",)),
    ("Quad9 (DNS)", ("9.9.9.0/24",)),
    ("OpenDNS (DNS)", ("208.67.220.0/24", "208.67.222.0/24")),
]

_NETS: List[Tuple[str, "ipaddress._BaseNetwork"]] = [
    (owner, ipaddress.ip_network(cidr)) for owner, cidrs in _OWNER_RANGES for cidr in cidrs
]

# Direcciones especiales muy comunes que conviene nombrar: qué hacen en una red.
_SPECIAL: Dict[str, str] = {
    "224.0.0.1": "Todos los equipos de la red",
    "224.0.0.2": "Todos los routers de la red",
    "224.0.0.22": "Grupo IGMP (equipos que se anotan a multicast)",
    "224.0.0.251": "mDNS (descubrir equipos por nombre)",
    "224.0.0.252": "LLMNR (resolver nombres en Windows)",
    "239.255.255.250": "SSDP / UPnP (descubrir dispositivos)",
    "255.255.255.255": "Difusión (broadcast) a toda la red",
    "ff02::1": "Todos los equipos del enlace",
    "ff02::2": "Todos los routers del enlace",
    "ff02::16": "Grupo MLD (equipos que se anotan a multicast IPv6)",
    "ff02::fb": "mDNS (descubrir equipos por nombre)",
    "ff02::1:2": "Servidores DHCPv6",
    "ff02::1:3": "LLMNR (resolver nombres en Windows)",
}

ROLE_LABELS = {
    "red_local": "Equipo de tu red",
    "ipv6_local": "IPv6 del enlace local",
    "multicast": "Multicast / difusión",
    "publica": "Servidor en internet",
}


def owner_of(ip: str) -> Optional[str]:
    """Dueño conocido del rango de una IP pública, o None."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return None
    for owner, net in _NETS:
        if addr.version == net.version and addr in net:
            return owner
    return None


def describe_ip(ip: str, kind: str) -> Dict[str, Optional[str]]:
    """{'role', 'role_label', 'owner', 'note'} de una IP; `kind` es el de `hosts.classify`."""
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return {"role": "publica", "role_label": ROLE_LABELS["publica"], "owner": None, "note": None}
    canon = addr.compressed
    note = _SPECIAL.get(canon)
    if kind == "multicast" or canon == "255.255.255.255":
        role = "multicast"
    elif addr.version == 6 and (addr.is_link_local or addr.is_private) and kind == "interna":
        role = "ipv6_local"
    elif kind == "interna":
        role = "red_local"
    else:
        role = "publica"
    return {
        "role": role,
        "role_label": ROLE_LABELS[role],
        "owner": owner_of(ip) if role == "publica" else None,
        "note": note,
    }
