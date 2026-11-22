"""Acceso remoto: mapa de puertos, agrupado por servicio, filtro, señales (RST y reintentos) y orden."""
import pytest

from backend.domain.analysis.remote_access import (
    MAX_ITEMS, REMOTE_PORTS, SERVICES, UnknownService, normalize_service, remote_access, service_of,
)
from backend.domain.sessions.grouper import Session


def S(dport, src="10.0.0.5", dst="10.0.0.9", sport=50000, proto="TCP", nbytes=500, syn=1, rst=0):
    return Session(proto, src, sport, dst, dport, 4, nbytes, 1.0, 3.0, syn_packets=syn, rst_packets=rst)


PORTS = [(22, "SSH"), (23, "Telnet"), (445, "SMB"), (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM"), (5900, "VNC")]


def test_mapa_de_puertos_exacto():
    assert REMOTE_PORTS == {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 5900: "VNC"}


@pytest.mark.parametrize("port,name", PORTS)
def test_cada_puerto_se_reconoce(port, name):
    r = remote_access([S(port)])
    assert r["total"] == 1 and r["services"][0]["service"] == name and r["services"][0]["items"][0]["port"] == port


def test_los_siete_puertos_juntos_se_agrupan_en_seis_servicios_en_orden():
    r = remote_access([S(p) for p, _ in reversed(PORTS)])
    assert [g["service"] for g in r["services"]] == list(SERVICES)
    assert r["total"] == 7
    winrm = next(g for g in r["services"] if g["service"] == "WinRM")
    assert winrm["ports"] == [5985, 5986] and winrm["sessions"] == 2


def test_sesion_con_rst_se_senala():
    r = remote_access([S(22, rst=2)])
    item = r["services"][0]["items"][0]
    assert item["rst_packets"] == 2 and any("RST" in t for t in item["signals"])
    assert r["services"][0]["with_rst"] == 1


def test_reintentos_se_senalan_y_se_suman():
    r = remote_access([S(3389, syn=4), S(3389, sport=50001, syn=2)])
    g = r["services"][0]
    assert g["retries"] == 4 and g["items"][0]["syn_retries"] == 3
    assert any("Reintentos" in t for t in g["items"][0]["signals"])


def test_sesion_normal_sin_senales():
    assert remote_access([S(22)])["services"][0]["items"][0]["signals"] == []


def test_telnet_avisa_que_va_sin_cifrar():
    assert any("sin cifrar" in t for t in remote_access([S(23)])["services"][0]["items"][0]["signals"])


def test_origen_invertido_cliente_y_servidor():
    # primer paquete visto: la respuesta del servidor (origen = puerto 22)
    r = remote_access([S(50000, src="10.0.0.9", dst="10.0.0.5", sport=22)])
    item = r["services"][0]["items"][0]
    assert (item["client_ip"], item["server_ip"], item["port"]) == ("10.0.0.5", "10.0.0.9", 22)


def test_solo_tcp_cuenta():
    assert remote_access([S(22, proto="UDP"), S(3389, proto="ICMP")]) == {"total": 0, "services": []}


def test_otros_puertos_no_cuentan():
    assert remote_access([S(80), S(443), S(None)])["total"] == 0


def test_filtro_por_servicio_sin_distinguir_mayusculas():
    r = remote_access([S(22), S(3389), S(445)], "rdp")
    assert [g["service"] for g in r["services"]] == ["RDP"] and r["total"] == 1


def test_filtro_por_servicio_sin_sesiones_da_vacio():
    assert remote_access([S(22)], "VNC") == {"total": 0, "services": []}


@pytest.mark.parametrize("bad", ["ftp", "", "  ", 5, ["SSH"]])
def test_servicio_desconocido_falla(bad):
    with pytest.raises(UnknownService, match="disponibles"):
        remote_access([S(22)], bad)


def test_normalize_service():
    assert normalize_service(None) is None and normalize_service(" winrm ") == "WinRM"


def test_el_id_es_la_posicion_en_la_lista():
    r = remote_access([S(80), S(22), S(23)])
    assert {i["id"] for g in r["services"] for i in g["items"]} == {1, 2}


def test_orden_primero_rst_luego_reintentos_luego_bytes():
    sessions = [S(22, nbytes=9000), S(22, sport=1, syn=5), S(22, sport=2, rst=1, nbytes=1), S(22, sport=3, nbytes=100)]
    ids = [i["id"] for i in remote_access(sessions)["services"][0]["items"]]
    assert ids == [2, 1, 0, 3]


def test_resumen_cuenta_clientes_servidores_y_bytes():
    r = remote_access([S(22, src="10.0.0.5", dst="10.0.0.9"), S(22, src="10.0.0.6", dst="10.0.0.9", nbytes=100)])
    g = r["services"][0]
    assert (g["clients"], g["servers"], g["bytes"]) == (2, 1, 600)


def test_detalle_acotado_pero_resumen_completo():
    r = remote_access([S(22, sport=1000 + i) for i in range(MAX_ITEMS + 5)])
    g = r["services"][0]
    assert g["sessions"] == MAX_ITEMS + 5 and len(g["items"]) == MAX_ITEMS and g["truncated"] is True


def test_incluye_la_direccion_del_flujo():
    assert remote_access([S(22, src="10.0.0.5", dst="8.8.8.8")])["services"][0]["items"][0]["direction"] == "Interno→Externo"


def test_service_of_sesion_sin_puertos():
    assert service_of(S(None)) is None


def test_sin_sesiones():
    assert remote_access([]) == {"total": 0, "services": []}
