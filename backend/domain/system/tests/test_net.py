"""Tests de backend/domain/system/net.py (puertos que escuchan y conexiones) con psutil falso."""
import json
import socket

import pytest

import backend.domain.system.net as N
from backend.domain.system.net import connections, exposure_of, listening_ports
from backend.domain.system.tests.fakes import FakeProcess, FakePsutil, addr, conn, patch_psutil

TCP, UDP = socket.SOCK_STREAM, socket.SOCK_DGRAM


def setup(monkeypatch, conns=(), procs=(), **kw):
    patch_psutil(monkeypatch, FakePsutil(procs=procs, connections=conns, **kw))


# ------------------------------------------------------------------ exposure_of

@pytest.mark.parametrize("ip,expected", [
    ("127.0.0.1", "local"), ("127.1.2.3", "local"), ("::1", "local"),
    ("0.0.0.0", "todas"), ("::", "todas"),
    ("192.168.1.5", "especifica"), ("10.0.0.1", "especifica"), ("8.8.8.8", "especifica"), ("fe80::1", "especifica"), ("2001:db8::1", "especifica"),
    (None, "especifica"), ("", "especifica"), ("no-es-ip", "especifica"), ("999.1.1.1", "especifica"), ("fe80::1%eth0", "especifica"), (42, "especifica"),
])
def test_exposure_of(ip, expected):
    assert exposure_of(ip) == expected


def test_los_textos_de_exposicion_cubren_todas_las_categorias():
    assert set(N.EXPOSURE_TEXT) == {"local", "todas", "especifica"}
    assert N.EXPOSURE_TEXT["local"] == "Solo esta PC" and N.EXPOSURE_TEXT["todas"] == "Toda la red"


# ------------------------------------------------------------------ listening_ports

def test_tcp_solo_en_listen_y_udp_solo_sin_remoto(monkeypatch):
    conns = [
        conn(addr("0.0.0.0", 80), None, "LISTEN", pid=1),
        conn(addr("10.0.0.5", 50000), addr("8.8.8.8", 443), "ESTABLISHED", pid=2),
        conn(addr("10.0.0.5", 50001), None, "TIME_WAIT", pid=2),
        conn(addr("0.0.0.0", 53), None, "NONE", pid=3, type=UDP),
        conn(addr("10.0.0.5", 5000), addr("1.1.1.1", 53), "NONE", pid=3, type=UDP),  # UDP "conectado": no es de escucha
    ]
    setup(monkeypatch, conns, [FakeProcess(1, name="web"), FakeProcess(2, name="cli"), FakeProcess(3, name="dns")])
    rows = listening_ports()["items"]
    assert [(r["proto"], r["port"], r["process"]) for r in rows] == [("UDP", 53, "dns"), ("TCP", 80, "web")]


def test_forma_de_cada_fila(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 443), None, "LISTEN", pid=9)], [FakeProcess(9, name="nginx")])
    assert listening_ports()["items"][0] == {
        "proto": "TCP", "ip": "0.0.0.0", "port": 443, "pid": 9, "process": "nginx", "exposure": "todas", "exposure_text": "Toda la red", "service": "HTTPS"}


def test_exposicion_por_direccion(monkeypatch):
    conns = [conn(addr(ip, 1000 + i), None, "LISTEN", pid=1) for i, ip in enumerate(["127.0.0.1", "::1", "0.0.0.0", "::", "192.168.1.5", "::ffff:0.0.0.0", "::ffff:127.0.0.1"])]
    setup(monkeypatch, conns, [FakeProcess(1)])
    assert [r["exposure"] for r in listening_ports()["items"]] == ["local", "local", "todas", "todas", "especifica", "todas", "local"]


def test_ipv4_mapeada_se_normaliza(monkeypatch):
    setup(monkeypatch, [conn(addr("::ffff:192.168.1.5", 22), None, "LISTEN", pid=1)], [FakeProcess(1)])
    assert listening_ports()["items"][0]["ip"] == "192.168.1.5"


def test_ip_ilegible_queda_en_none_y_especifica(monkeypatch):
    setup(monkeypatch, [conn(addr("basura", 8080), None, "LISTEN", pid=1)], [FakeProcess(1)])
    row = listening_ports()["items"][0]
    assert row["ip"] is None and row["exposure"] == "especifica"


def test_se_omiten_sockets_sin_direccion_local_o_de_otro_tipo(monkeypatch):
    conns = [conn(None, None, "LISTEN", pid=1), conn(addr("0.0.0.0", 99), None, "LISTEN", pid=1, type=socket.SOCK_RAW), conn(addr("0.0.0.0", 100), None, "LISTEN", pid=1)]
    setup(monkeypatch, conns, [FakeProcess(1)])
    assert [r["port"] for r in listening_ports()["items"]] == [100]


def test_proceso_desconocido_o_sin_pid(monkeypatch):
    conns = [conn(addr("0.0.0.0", 1), None, "LISTEN", pid=None), conn(addr("0.0.0.0", 2), None, "LISTEN", pid=0), conn(addr("0.0.0.0", 3), None, "LISTEN", pid=777)]
    setup(monkeypatch, conns, [FakeProcess(1)])
    rows = {r["port"]: r for r in listening_ports()["items"]}
    assert rows[1]["pid"] is None and rows[1]["process"] is None
    assert rows[2]["pid"] is None and rows[2]["process"] is None
    assert rows[3]["pid"] == 777 and rows[3]["process"] is None  # el proceso no se pudo nombrar


def test_proceso_sin_nombre_usa_pid(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 1), None, "LISTEN", pid=5)], [FakeProcess(5, no_name=True)])
    assert listening_ports()["items"][0]["process"] == "PID 5"


def test_servicio_conocido_o_none(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 22), None, "LISTEN", pid=1), conn(addr("0.0.0.0", 54321), None, "LISTEN", pid=1)], [FakeProcess(1)])
    rows = {r["port"]: r for r in listening_ports()["items"]}
    assert rows[22]["service"] == "SSH" and rows[54321]["service"] is None


def test_orden_por_puerto_protocolo_e_ip(monkeypatch):
    conns = [
        conn(addr("10.0.0.2", 80), None, "LISTEN", pid=1), conn(addr("10.0.0.1", 80), None, "LISTEN", pid=1), conn(addr("0.0.0.0", 80), None, "NONE", pid=1, type=UDP),
        conn(addr("0.0.0.0", 22), None, "LISTEN", pid=1),
    ]
    setup(monkeypatch, conns, [FakeProcess(1)])
    assert [(r["port"], r["proto"], r["ip"]) for r in listening_ports()["items"]] == [(22, "TCP", "0.0.0.0"), (80, "TCP", "10.0.0.1"), (80, "TCP", "10.0.0.2"), (80, "UDP", "0.0.0.0")]


def test_limited_cuando_ninguna_fila_trae_pid(monkeypatch):
    conns = [conn(addr("0.0.0.0", 80), None, "LISTEN", pid=None), conn(addr("0.0.0.0", 81), None, "LISTEN", pid=0)]
    setup(monkeypatch, conns, [])
    assert listening_ports()["limited"] is True


def test_no_limited_si_alguna_fila_trae_pid_o_si_no_hay_filas(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 80), None, "LISTEN", pid=None), conn(addr("0.0.0.0", 81), None, "LISTEN", pid=4)], [FakeProcess(4)])
    assert listening_ports()["limited"] is False
    setup(monkeypatch, [], [])
    assert listening_ports() == {"total": 0, "items": [], "limited": False}


def test_tope_de_filas_pero_total_real(monkeypatch):
    monkeypatch.setattr(N, "MAX_ROWS", 5)
    setup(monkeypatch, [conn(addr("0.0.0.0", 1000 + i), None, "LISTEN", pid=1) for i in range(20)], [FakeProcess(1)])
    out = listening_ports()
    assert out["total"] == 20 and len(out["items"]) == 5 and [r["port"] for r in out["items"]] == [1000, 1001, 1002, 1003, 1004]


def test_muchos_sockets(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", i), None, "LISTEN", pid=1) for i in range(1, 5001)], [FakeProcess(1)])
    out = listening_ports()
    assert out["total"] == 5000 and len(out["items"]) == 1000


def test_sin_poder_nombrar_procesos_igual_lista(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 80), None, "LISTEN", pid=1)], [FakeProcess(1)], deny=["process_iter"])
    row = listening_ports()["items"][0]
    assert row["pid"] == 1 and row["process"] is None


def test_accessdenied_al_listar_sockets_no_rompe_los_puertos(monkeypatch):
    setup(monkeypatch, [], [], conn_error=True)
    assert listening_ports() == {"total": 0, "items": [], "limited": True}


def test_accessdenied_al_listar_sockets_no_rompe_las_conexiones(monkeypatch):
    setup(monkeypatch, [], [], conn_error=True)
    assert connections() == {"total": 0, "items": [], "limited": True}


@pytest.mark.parametrize("exc", [PermissionError("x"), OSError("x"), RuntimeError("x"), ValueError("x")])
def test_cualquier_fallo_al_listar_sockets_se_informa_como_limitado(monkeypatch, exc):
    fake = FakePsutil()

    def boom(kind="inet"):
        raise exc
    fake.net_connections = boom
    patch_psutil(monkeypatch, fake)
    assert listening_ports()["limited"] is True and connections()["limited"] is True


def test_connections_trae_limited_false_en_el_caso_normal(monkeypatch):
    setup(monkeypatch, [conn(addr("10.0.0.5", 1), addr("8.8.8.8", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    out = connections()
    assert out["limited"] is False and out["total"] == 1


def test_connections_vacia_pero_legible_no_es_limitada(monkeypatch):
    setup(monkeypatch, [], [])
    assert connections() == {"total": 0, "items": [], "limited": False}


def test_inet_connections_devuelve_none_si_falla_y_lista_si_no(monkeypatch):
    assert N._inet_connections(FakePsutil(conn_error=True)) is None
    assert N._inet_connections(FakePsutil(connections=[conn(addr("1.1.1.1", 1), None)])) != None  # noqa: E711


def test_puertos_serializable(monkeypatch):
    setup(monkeypatch, [conn(addr("0.0.0.0", 80), None, "LISTEN", pid=1)], [FakeProcess(1)])
    json.dumps(listening_ports())


# ------------------------------------------------------------------ connections

def test_solo_tcp_con_remoto_y_local(monkeypatch):
    conns = [
        conn(addr("10.0.0.5", 50000), addr("8.8.8.8", 443), "ESTABLISHED", pid=1),
        conn(addr("0.0.0.0", 80), None, "LISTEN", pid=1),
        conn(addr("10.0.0.5", 5000), addr("1.1.1.1", 53), "NONE", pid=1, type=UDP),
        conn(None, addr("1.1.1.1", 53), "ESTABLISHED", pid=1),
    ]
    setup(monkeypatch, conns, [FakeProcess(1, name="chrome")])
    out = connections()
    assert out["total"] == 1 and out["items"][0]["remote"] == "8.8.8.8:443"


def test_forma_dueno_y_alcance(monkeypatch):
    setup(monkeypatch, [conn(addr("192.168.1.5", 50000), addr("160.79.104.10", 443), "ESTABLISHED", pid=3)], [FakeProcess(3, name="claude")])
    assert connections()["items"][0] == {
        "pid": 3, "process": "claude", "local": "192.168.1.5:50000", "remote": "160.79.104.10:443", "remote_ip": "160.79.104.10", "status": "ESTABLISHED",
        "owner": "Anthropic", "scope": "publica", "service": "HTTPS"}


@pytest.mark.parametrize("remote,scope,owner", [
    ("142.250.1.1", "publica", "Google"), ("93.184.216.34", "publica", None), ("192.168.1.9", "interna", None), ("127.0.0.1", "interna", None),
    ("224.0.0.251", "multicast", None), ("::1", "interna", None), ("2a00:1450:4001::1", "publica", "Google"), ("fe80::2", "interna", None),
])
def test_alcance_y_dueno(monkeypatch, remote, scope, owner):
    setup(monkeypatch, [conn(addr("10.0.0.5", 1000), addr(remote, 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    row = connections()["items"][0]
    assert (row["scope"], row["owner"]) == (scope, owner)


def test_ipv4_mapeada_en_conexiones(monkeypatch):
    setup(monkeypatch, [conn(addr("::ffff:10.0.0.5", 1000), addr("::ffff:8.8.8.8", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    row = connections()["items"][0]
    assert row["local"] == "10.0.0.5:1000" and row["remote"] == "8.8.8.8:443" and row["remote_ip"] == "8.8.8.8" and row["owner"] == "Google"


def test_ip_remota_ilegible_no_rompe_y_no_inventa_dueno(monkeypatch):
    setup(monkeypatch, [conn(addr("10.0.0.5", 1000), addr("basura", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    row = connections()["items"][0]
    assert row["remote_ip"] is None and row["owner"] is None and row["scope"] is None


def test_ip_local_ilegible_no_rompe(monkeypatch):
    setup(monkeypatch, [conn(addr("basura", 1000), addr("8.8.8.8", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    assert connections()["total"] == 1


def test_conexion_sin_proceso(monkeypatch):
    setup(monkeypatch, [conn(addr("10.0.0.5", 1), addr("8.8.8.8", 443), "ESTABLISHED", pid=None)], [])
    row = connections()["items"][0]
    assert row["pid"] is None and row["process"] is None


def test_orden_por_proceso_sin_mayusculas_y_sin_proceso_al_final(monkeypatch):
    conns = [
        conn(addr("10.0.0.5", 1), addr("8.8.8.8", 443), "ESTABLISHED", pid=None),
        conn(addr("10.0.0.5", 2), addr("8.8.8.9", 443), "ESTABLISHED", pid=2),
        conn(addr("10.0.0.5", 3), addr("8.8.8.7", 443), "ESTABLISHED", pid=1),
        conn(addr("10.0.0.5", 4), addr("8.8.8.1", 443), "ESTABLISHED", pid=2),
    ]
    setup(monkeypatch, conns, [FakeProcess(1, name="zeta"), FakeProcess(2, name="Alfa")])
    assert [(r["process"], r["remote"]) for r in connections()["items"]] == [("Alfa", "8.8.8.1:443"), ("Alfa", "8.8.8.9:443"), ("zeta", "8.8.8.7:443"), (None, "8.8.8.8:443")]


def test_tope_de_conexiones(monkeypatch):
    monkeypatch.setattr(N, "MAX_ROWS", 3)
    setup(monkeypatch, [conn(addr("10.0.0.5", 1000 + i), addr("8.8.8.8", 443), "ESTABLISHED", pid=1) for i in range(10)], [FakeProcess(1)])
    out = connections()
    assert out["total"] == 10 and len(out["items"]) == 3


def test_estados_de_la_conexion_se_conservan(monkeypatch):
    conns = [conn(addr("10.0.0.5", 1000 + i), addr("8.8.8.8", 443), st, pid=1) for i, st in enumerate(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"])]
    setup(monkeypatch, conns, [FakeProcess(1)])
    assert sorted(r["status"] for r in connections()["items"]) == ["CLOSE_WAIT", "ESTABLISHED", "SYN_SENT", "TIME_WAIT"]


def test_conexiones_serializable(monkeypatch):
    setup(monkeypatch, [conn(addr("10.0.0.5", 1), addr("8.8.8.8", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    json.dumps(connections())


def test_ip_ilegible_no_se_muestra_como_la_palabra_None(monkeypatch):
    setup(monkeypatch, [conn(addr("basura", 1000), addr("basura2", 443), "ESTABLISHED", pid=1)], [FakeProcess(1)])
    row = connections()["items"][0]
    assert row["local"] is None and row["remote"] is None and row["remote_ip"] is None


def test_addr_directo():
    assert N._addr("10.0.0.1", 80) == "10.0.0.1:80" and N._addr(None, 80) is None


def test_el_orden_tolera_conexiones_con_remoto_ilegible(monkeypatch):
    conns = [conn(addr("10.0.0.5", 1), addr("basura", 443), "ESTABLISHED", pid=1), conn(addr("10.0.0.5", 2), addr("8.8.8.8", 443), "ESTABLISHED", pid=1),
             conn(addr("10.0.0.5", 3), addr("basura2", 80), "ESTABLISHED", pid=None)]
    setup(monkeypatch, conns, [FakeProcess(1)])
    out = connections()
    assert out["total"] == 3 and len(out["items"]) == 3
