from types import SimpleNamespace

import pytest

from backend.domain.analysis.direction import (
    EXTERNAL_TO_EXTERNAL, EXTERNAL_TO_INTERNAL, INTERNAL_TO_EXTERNAL, LATERAL, MULTICAST,
    direction_of_ips, session_direction,
)


def sess(src, sport, dst, dport, proto="TCP"):
    return SimpleNamespace(protocol=proto, src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport)


def test_interno_a_externo():
    assert session_direction(sess("192.168.1.10", 50000, "93.184.216.34", 443)) == INTERNAL_TO_EXTERNAL


def test_externo_a_interno():
    assert session_direction(sess("8.8.4.4", 40000, "10.0.0.5", 22)) == EXTERNAL_TO_INTERNAL


def test_lateral_entre_equipos_internos():
    assert session_direction(sess("10.0.0.5", 51000, "10.0.0.9", 445)) == LATERAL


def test_los_rangos_de_documentacion_cuentan_como_privados():
    # Python trata 203.0.113.0/24 (TEST-NET) como no enrutable: la vista de equipos hace lo mismo
    assert session_direction(sess("203.0.113.9", 40000, "10.0.0.5", 22)) == LATERAL


def test_externo_a_externo():
    assert session_direction(sess("1.1.1.1", 40000, "8.8.8.8", 443)) == EXTERNAL_TO_EXTERNAL


def test_ipv6_interno_y_publico():
    assert session_direction(sess("fd00::5", 50000, "2606:4700::1111", 443)) == INTERNAL_TO_EXTERNAL
    assert session_direction(sess("fe80::1", 50000, "fe80::2", 22)) == LATERAL


def test_multicast_se_etiqueta_aparte():
    assert session_direction(sess("192.168.1.10", 5353, "224.0.0.251", 5353, "UDP")) == MULTICAST
    assert session_direction(sess("fe80::1", 546, "ff02::1:2", 547, "UDP")) == MULTICAST


def test_origen_invertido_por_captura_a_mitad_de_conversacion():
    # el primer paquete visto es la RESPUESTA del servidor: la dirección sigue siendo cliente -> servidor
    assert session_direction(sess("93.184.216.34", 443, "192.168.1.10", 50000)) == INTERNAL_TO_EXTERNAL
    assert session_direction(sess("10.0.0.5", 22, "8.8.4.4", 40000)) == EXTERNAL_TO_INTERNAL


def test_sin_puertos_usa_la_red_para_decidir():
    # ICMP: el de afuera se toma como servidor; el que escribió primero es el interno
    assert session_direction(sess("192.168.1.10", None, "8.8.8.8", None, "ICMP")) == INTERNAL_TO_EXTERNAL
    assert session_direction(sess("8.8.8.8", None, "192.168.1.10", None, "ICMP")) == INTERNAL_TO_EXTERNAL


def test_ip_ilegible_cuenta_como_publica():
    assert direction_of_ips("10.0.0.1", "no-es-ip") == INTERNAL_TO_EXTERNAL


def test_loopback_y_link_local_son_internos():
    assert session_direction(sess("127.0.0.1", 50000, "127.0.0.1", 8000)) == LATERAL
    assert session_direction(sess("169.254.1.1", 50000, "10.0.0.1", 80)) == LATERAL


@pytest.mark.parametrize("c,s_,expected", [
    ("10.0.0.1", "8.8.8.8", INTERNAL_TO_EXTERNAL),
    ("8.8.8.8", "10.0.0.1", EXTERNAL_TO_INTERNAL),
    ("10.0.0.1", "10.0.0.2", LATERAL),
    ("8.8.8.8", "1.1.1.1", EXTERNAL_TO_EXTERNAL),
    ("10.0.0.1", "239.255.255.250", MULTICAST),
])
def test_direction_of_ips(c, s_, expected):
    assert direction_of_ips(c, s_) == expected
