"""Perfil de host: roles inferidos solo de lo observado (cliente DNS, servidor web, emisor de escaneos, top talker)."""
import pytest

from backend.domain.analysis.hosts import (
    ROLE_DNS_CLIENT, ROLE_SCANNER, ROLE_TOP_TALKER, ROLE_WEB_SERVER, TOP_TALKERS, build_hosts,
)
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import Session


def S(src, sport, dst, dport, proto="TCP", nbytes=100):
    return Session(proto, src, sport, dst, dport, 1, nbytes, 1.0, 2.0)


def scan_alert(src, dst):
    return Alert("port_scan", "Escaneo", "high", "T1046", "n", "t", "d", src, dst, 1.0)


def roles(hosts, ip):
    return next(h for h in hosts if h.ip == ip).roles


def test_cliente_dns_por_udp_y_por_tcp():
    hosts = build_hosts([S("10.0.0.5", 50000, "8.8.8.8", 53, "UDP"), S("10.0.0.6", 50001, "8.8.8.8", 53, "TCP")])
    assert ROLE_DNS_CLIENT in roles(hosts, "10.0.0.5") and ROLE_DNS_CLIENT in roles(hosts, "10.0.0.6")


def test_el_servidor_dns_no_es_cliente_dns():
    hosts = build_hosts([S("10.0.0.5", 50000, "8.8.8.8", 53, "UDP")])
    assert ROLE_DNS_CLIENT not in roles(hosts, "8.8.8.8")


def test_cliente_dns_con_origen_invertido_por_captura_a_mitad():
    # el primer paquete visto es la respuesta del servidor (origen = 8.8.8.8:53)
    hosts = build_hosts([S("8.8.8.8", 53, "10.0.0.5", 50000, "UDP")])
    assert ROLE_DNS_CLIENT in roles(hosts, "10.0.0.5") and ROLE_DNS_CLIENT not in roles(hosts, "8.8.8.8")


@pytest.mark.parametrize("port", [80, 443, 8080, 8443])
def test_servidor_web_por_puertos_habituales(port):
    hosts = build_hosts([S("10.0.0.5", 50000, "10.0.0.9", port)])
    assert ROLE_WEB_SERVER in roles(hosts, "10.0.0.9") and ROLE_WEB_SERVER not in roles(hosts, "10.0.0.5")


def test_puerto_web_por_udp_no_cuenta_como_servidor_web():
    hosts = build_hosts([S("10.0.0.5", 50000, "10.0.0.9", 443, "UDP")])  # p. ej. QUIC: no se afirma
    assert ROLE_WEB_SERVER not in roles(hosts, "10.0.0.9")


def test_servidor_en_otro_puerto_no_es_web():
    assert ROLE_WEB_SERVER not in roles(build_hosts([S("10.0.0.5", 50000, "10.0.0.9", 22)]), "10.0.0.9")


def test_emisor_de_escaneos_sale_de_la_alerta_port_scan():
    sessions = [S("10.0.0.66", 40000, "10.0.0.1", 22)]
    hosts = build_hosts(sessions, alerts=[scan_alert("10.0.0.66", "10.0.0.1")])
    assert ROLE_SCANNER in roles(hosts, "10.0.0.66") and ROLE_SCANNER not in roles(hosts, "10.0.0.1")


def test_otra_alerta_no_hace_emisor_de_escaneos():
    a = Alert("beaconing", "B", "high", "T1", "n", "t", "d", "10.0.0.66", "10.0.0.1", 1.0)
    assert ROLE_SCANNER not in roles(build_hosts([S("10.0.0.66", 40000, "10.0.0.1", 22)], alerts=[a]), "10.0.0.66")


def test_top_talker_los_que_mas_bytes_mueven():
    sessions = [S("10.0.0.1", 50000, "8.8.8.8", 443, nbytes=9000), S("10.0.0.2", 50000, "1.1.1.1", 443, nbytes=1000)]
    hosts = build_hosts(sessions)
    assert ROLE_TOP_TALKER in roles(hosts, "10.0.0.1") and ROLE_TOP_TALKER in roles(hosts, "8.8.8.8")


def test_top_talker_se_limita_a_la_cantidad_de_tope():
    sessions = [S(f"10.0.0.{i}", 50000, f"8.8.8.{i}", 443, nbytes=1000) for i in range(1, 11)]
    marked = [h for h in build_hosts(sessions) if ROLE_TOP_TALKER in h.roles]
    assert len(marked) == TOP_TALKERS


def test_top_talker_exige_un_peso_minimo():
    # 30 pares iguales: ninguno llega al 10 % de los bytes
    sessions = [S(f"10.0.{i}.1", 50000, f"8.8.{i}.8", 443, nbytes=1000) for i in range(30)]
    assert all(ROLE_TOP_TALKER not in h.roles for h in build_hosts(sessions))


def test_sin_bytes_no_hay_top_talker_ni_division_por_cero():
    assert all(h.roles == [] or ROLE_TOP_TALKER not in h.roles for h in build_hosts([S("10.0.0.1", 1, "8.8.8.8", 443, nbytes=0)]))


def test_sin_sesiones():
    assert build_hosts([]) == []


def test_un_equipo_puede_tener_varios_roles():
    sessions = [
        S("10.0.0.5", 50000, "8.8.8.8", 53, "UDP", nbytes=10), S("10.0.0.5", 50001, "10.0.0.9", 80, nbytes=10),
        S("10.0.0.7", 51000, "10.0.0.5", 443, nbytes=90_000),
    ]
    r = roles(build_hosts(sessions, alerts=[scan_alert("10.0.0.5", "10.0.0.9")]), "10.0.0.5")
    assert {ROLE_DNS_CLIENT, ROLE_SCANNER, ROLE_WEB_SERVER, ROLE_TOP_TALKER} == set(r)


def test_acepta_sesiones_como_generador():
    hosts = build_hosts((s for s in [S("10.0.0.5", 50000, "8.8.8.8", 53, "UDP")]))
    assert ROLE_DNS_CLIENT in roles(hosts, "10.0.0.5")
