"""GET /api/remote-access con una captura sintética: un SYN por servicio y uno rechazado con RST."""
import socket

import dpkt
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.api.tests.test_insights_api import load

SYN, ACK, RST = 0x02, 0x10, 0x04


def frame(src, sport, dst, dport, flags):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


FRAMES = (
    [frame("10.0.0.5", 40000 + i, "10.0.0.9", p, SYN) for i, p in enumerate([22, 23, 445, 3389, 5985, 5986, 5900])]
    + [frame("10.0.0.9", 22, "10.0.0.5", 40000, SYN | ACK)]
    + [
        frame("10.0.0.5", 41000, "10.0.0.9", 3389, SYN),
        frame("10.0.0.5", 41000, "10.0.0.9", 3389, SYN),
        frame("10.0.0.9", 3389, "10.0.0.5", 41000, RST | ACK),
    ]
    + [frame("10.0.0.5", 42000, "10.0.0.9", 80, SYN)]
)


@pytest.fixture
def client(tmp_path):
    return load(TestClient(create_app(sampler_factory=None)), tmp_path, FRAMES)


def test_sin_analisis_409():
    assert TestClient(create_app(sampler_factory=None)).get("/api/remote-access").status_code == 409


def test_agrupa_por_servicio_y_ignora_http(client):
    j = client.get("/api/remote-access").json()
    assert [g["service"] for g in j["services"]] == ["SSH", "Telnet", "SMB", "RDP", "WinRM", "VNC"]
    assert j["total"] == 8  # 7 servicios + la segunda sesión RDP; el puerto 80 no cuenta


def test_la_sesion_rechazada_trae_rst_y_reintento(client):
    rdp = next(g for g in client.get("/api/remote-access").json()["services"] if g["service"] == "RDP")
    assert rdp["with_rst"] == 1 and rdp["retries"] == 1
    worst = rdp["items"][0]
    assert worst["rst_packets"] == 1 and worst["syn_retries"] == 1 and worst["signals"]


def test_filtro_por_servicio(client):
    j = client.get("/api/remote-access", params={"service": "ssh"}).json()
    assert [g["service"] for g in j["services"]] == ["SSH"] and j["total"] == 1


def test_servicio_desconocido_422(client):
    r = client.get("/api/remote-access", params={"service": "ftp"})
    assert r.status_code == 422 and "disponibles" in r.json()["detail"]


def test_ids_coinciden_con_los_de_sessions(client):
    item = client.get("/api/remote-access?service=SMB").json()["services"][0]["items"][0]
    s = client.get("/api/sessions?limit=1000").json()["items"][item["id"]]
    assert s["dst_port"] == 445


def test_el_json_exportado_no_cambia(client):
    j = client.get("/api/export").json()
    assert j["schema_version"] == 1
    assert all(not {"syn_packets", "rst_packets", "syn_retries"} & set(s) for s in j["sessions"])
