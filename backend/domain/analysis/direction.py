"""Dirección de una sesión respecto de TU red: ¿quién habló con quién, adentro o afuera?

Etiquetas: «Interno→Externo» (salida a internet), «Externo→Interno» (algo de afuera le habló a un equipo tuyo),
«Interno→Interno (lateral)» (entre equipos de la red local, donde se mueve un atacante ya adentro) y
«Externo→Externo» (ninguno de los dos extremos es de la red local: tráfico que pasó por la captura, un tránsito).
Si un extremo es multicast se etiqueta aparte («Multicast»): no es ni adentro ni afuera.

La flecha va del CLIENTE al SERVIDOR, no del primer paquete visto: si la captura empezó a mitad de la
conversación el «origen» de la sesión puede estar invertido, y se corrige con la misma regla que usa la vista
de equipos (puerto de servicio y, si no alcanza, estar afuera de la red). Es una pista, no una prueba: «interno»
significa dirección privada (RFC 1918, ULA, link-local, loopback); no se conoce la topología real.
"""
from __future__ import annotations

from typing import Any

from backend.domain.analysis.hosts import _server_is_src, classify

INTERNAL_TO_EXTERNAL = "Interno→Externo"
EXTERNAL_TO_INTERNAL = "Externo→Interno"
LATERAL = "Interno→Interno (lateral)"
EXTERNAL_TO_EXTERNAL = "Externo→Externo"
MULTICAST = "Multicast"

_BY_KINDS = {
    ("interna", "publica"): INTERNAL_TO_EXTERNAL,
    ("publica", "interna"): EXTERNAL_TO_INTERNAL,
    ("interna", "interna"): LATERAL,
    ("publica", "publica"): EXTERNAL_TO_EXTERNAL,
}


def direction_of_ips(client_ip: str, server_ip: str) -> str:
    """Etiqueta de dirección para un cliente y un servidor dados."""
    kinds = (classify(client_ip), classify(server_ip))
    if "multicast" in kinds:
        return MULTICAST
    return _BY_KINDS[kinds]


def session_direction(session: Any) -> str:
    """Etiqueta de dirección de una sesión (cliente → servidor, corrigiendo el origen invertido)."""
    if _server_is_src(session):
        return direction_of_ips(session.dst_ip, session.src_ip)
    return direction_of_ips(session.src_ip, session.dst_ip)
