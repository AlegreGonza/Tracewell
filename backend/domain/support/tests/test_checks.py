"""checks: ping, internet_check por capa, RDP, hora, traceroute y puertos, todo con falsos (sin red real)."""
import socket
import struct

import pytest

from backend.domain.support import checks as K
from backend.domain.support.common import RunResult


def fake_run(out, **kw):
    return lambda cmd, timeout=15.0, env_extra=None: RunResult(kw.get("ok", True), 0, out, "", missing=kw.get("missing", False))


@pytest.mark.parametrize("out,first", [
    ("Respuesta desde 1.1.1.1: bytes=32 time=12ms TTL=57\nRespuesta desde 1.1.1.1: bytes=32 time<1ms TTL=57", 12.0),
    ("Respuesta desde 1.1.1.1: bytes=32 tiempo=12ms TTL=57\nRespuesta desde 1.1.1.1: bytes=32 tiempo<1ms TTL=57", 12.0),
    ("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=12.3 ms", 12.3),
])
def test_ping_parsea(monkeypatch, out, first):
    monkeypatch.setattr(K, "run", fake_run(out))
    r = K.ping("1.1.1.1", 2)
    assert r["received"] == 2 and r["times"][0] == first and r["loss_pct"] == 0.0 and r["avg"] is not None


def test_ping_menor_que_1ms(monkeypatch):
    monkeypatch.setattr(K, "run", fake_run("Respuesta desde 1.1.1.1: bytes=32 tiempo<1ms TTL=57"))
    assert K.ping("1.1.1.1", 1)["times"][0] <= 1.0  # el regex lo toma como 1.0 (la rama 0.5 es inalcanzable)


def test_ping_inalcanzable_sin_ttl_es_cero(monkeypatch):
    monkeypatch.setattr(K, "run", fake_run("Respuesta desde 192.168.1.5: Host de destino inaccesible.\nDestination host unreachable"))
    r = K.ping("192.168.1.5", 4)
    assert r["received"] == 0 and r["loss_pct"] == 100.0 and r["avg"] is None


def test_ping_faltante_y_host_invalido(monkeypatch):
    monkeypatch.setattr(K, "run", fake_run("", missing=True, ok=False))
    assert K.ping("1.1.1.1")["available"] is False
    with pytest.raises(ValueError):
        K.ping("a;b")


# ------------------------------------------------------------------ internet_check
def adapter(name="Ethernet", ip="192.168.1.10", up=True, loopback=False):
    return {"name": name, "up": up, "loopback": loopback, "ipv4": [{"ip": ip, "mask": "255.255.255.0"}] if ip else [],
            "apipa": bool(ip and ip.startswith("169.254")), "gateway": []}


@pytest.fixture
def net(monkeypatch):
    """Todo bien por defecto; cada test rompe una capa. `run` explota: internet_check no ejecuta comandos."""
    st = {"adapters": [adapter()], "gw": "192.168.1.1", "ping_ok": True, "tcp_ok": True,
          "dns_ok": {"www.google.com", "one.one.one.one", "www.microsoft.com"}, "resolved": []}
    monkeypatch.setattr(K, "network_config", lambda: {"adapters": st["adapters"]})
    monkeypatch.setattr(K, "default_gateway", lambda cfg=None: st["gw"])
    monkeypatch.setattr(K, "ping", lambda h, c=4: {"received": 3 if st["ping_ok"] else 0, "avg": 1.0})
    monkeypatch.setattr(K, "tcp_connect", lambda h, p, t=2.0: {"ok": st["tcp_ok"], "state": "abierto", "ms": 9.0, "error": None})

    def res(name, timeout=3.0):
        st["resolved"].append(name)
        ok = name in st["dns_ok"]
        return {"ok": ok, "ms": 5.0 if ok else None, "addresses": ["1.2.3.4"] if ok else [], "error": None if ok else "nxdomain"}

    monkeypatch.setattr(K, "resolve", res)

    def no_run(*a, **k):
        raise AssertionError("internet_check no debe ejecutar comandos")

    monkeypatch.setattr(K, "run", no_run)
    return st


def test_todo_ok(net):
    r = K.internet_check()
    assert r["ok"] and r["layer"] is None and [s["ok"] for s in r["steps"]] == [True] * 4 and r["command"] is None


def test_sin_adaptador(net):
    net["adapters"] = [adapter(ip=None)]
    r = K.internet_check()
    assert not r["ok"] and r["layer"] == "adaptador" and r["command"] is None
    assert r["steps"][1]["ok"] is None  # gateway omitido


def test_apipa_sugiere_comando_solo_como_texto(net):
    net["adapters"] = [adapter(ip="169.254.3.4")]
    r = K.internet_check()
    assert r["layer"] == "adaptador" and r["command"] and ("ipconfig" in r["command"] or "dhclient" in r["command"])


def test_router_caido(net):
    net["ping_ok"] = False
    r = K.internet_check()
    assert r["layer"] == "red local" and not r["ok"]


def test_internet_caido(net):
    net["tcp_ok"] = False
    assert K.internet_check()["layer"] == "internet"


def test_dns_caido_prueba_todos(net):
    net["dns_ok"] = set()
    r = K.internet_check()
    assert r["layer"] == "dns" and net["resolved"] == list(K.DNS_PROBES) and r["command"]


def test_dns_basta_uno(net):
    net["dns_ok"] = {"www.microsoft.com"}
    r = K.internet_check()
    assert r["ok"] and len(net["resolved"]) == 3


# ------------------------------------------------------------------ rdp
REQ = bytes.fromhex("03000013" + "0ee00000000000" + "010008000b000000")


class FakeSock:
    def __init__(self, reply=b""):
        self.reply, self.sent = reply, b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, t):
        pass

    def sendall(self, b):
        self.sent += b

    def recv(self, n):
        return self.reply


def rdp_reply(kind, value):
    return bytes([3, 0, 0, 19, 14, 0xD0, 0, 0, 0, 0, 0]) + bytes([kind, 0, 8, 0]) + struct.pack("<I", value)


def patch_conn(monkeypatch, sock=None, exc=None):
    def cc(addr, timeout=None):
        if exc:
            raise exc
        return sock

    monkeypatch.setattr(K.socket, "create_connection", cc)


@pytest.mark.parametrize("sel,nla", [(0, False), (1, False), (2, True), (8, True)])
def test_rdp_neg_rsp(monkeypatch, sel, nla):
    s = FakeSock(rdp_reply(2, sel))
    patch_conn(monkeypatch, s)
    r = K.rdp_check("10.0.0.5")
    assert r["state"] == "rdp" and r["nla"] is nla and r["protocol"] == sel
    assert s.sent == REQ


def test_rdp_neg_failure_5(monkeypatch):
    patch_conn(monkeypatch, FakeSock(rdp_reply(3, 5)))
    r = K.rdp_check("10.0.0.5")
    assert r["state"] == "rdp" and r["nla"] is True and "NLA" in r["summary"]


def test_rdp_no_rdp_refused_timeout(monkeypatch):
    patch_conn(monkeypatch, FakeSock(b"HTTP/1.1 400 Bad Request\r\n"))
    assert K.rdp_check("10.0.0.5")["state"] == "no_rdp"
    patch_conn(monkeypatch, exc=ConnectionRefusedError())
    assert K.rdp_check("10.0.0.5")["state"] == "cerrado"
    patch_conn(monkeypatch, exc=socket.timeout())
    assert K.rdp_check("10.0.0.5")["state"] == "sin_respuesta"
    patch_conn(monkeypatch, exc=OSError("x"))
    assert K.rdp_check("10.0.0.5")["state"] == "error"


# ------------------------------------------------------------------ time_offset
class FakeUdp:
    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.sent = reply, exc, None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, t):
        pass

    def sendto(self, data, addr):
        self.sent = (data, addr)

    def recvfrom(self, n):
        if self.exc:
            raise self.exc
        return self.reply, ("x", 123)


def test_time_offset(monkeypatch):
    now = 1_700_000_000.0
    monkeypatch.setattr(K.time, "time", lambda: now)
    reply = bytearray(48)
    reply[40:48] = struct.pack("!II", int(now + 2208988800 + 10), 0)  # servidor 10 s adelantado
    u = FakeUdp(bytes(reply))
    monkeypatch.setattr(K.socket, "socket", lambda *a, **k: u)
    r = K.time_offset("pool.ntp.org")
    assert r["available"] and abs(r["offset_seconds"] - 10) < 0.01
    assert len(u.sent[0]) == 48 and u.sent[1] == ("pool.ntp.org", 123)


def test_time_offset_errores(monkeypatch):
    with pytest.raises(ValueError):
        K.time_offset("evil.example.com")
    monkeypatch.setattr(K.socket, "socket", lambda *a, **k: FakeUdp(exc=OSError("sin red")))
    assert K.time_offset()["available"] is False
    monkeypatch.setattr(K.socket, "socket", lambda *a, **k: FakeUdp(b"\0" * 10))
    assert K.time_offset()["available"] is False


# ------------------------------------------------------------------ traceroute y puertos
def test_traceroute_parsea(monkeypatch):
    out = ("Traza a 8.8.8.8 sobre un máximo de 20 saltos\n\n"
           "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
           "  2     *        *        *     Tiempo de espera agotado para esta solicitud.\n"
           "  3    12 ms    13 ms    11 ms  8.8.8.8\n\nTraza completa.")
    monkeypatch.setattr(K, "run", fake_run(out))
    r = K.traceroute("8.8.8.8")
    assert [h["n"] for h in r["hops"]] == [1, 2, 3]
    assert r["hops"][0]["times"] == [0.5, 0.5, 0.5] and r["hops"][0]["ips"] == ["192.168.1.1"]
    assert r["hops"][1]["timeouts"] >= 3 and r["hops"][1]["times"] == []
    assert r["hops"][2]["times"] == [12.0, 13.0, 11.0]


def test_port_check(monkeypatch):
    states = {80: "abierto", 81: "cerrado", 82: "sin_respuesta"}

    def tc(h, p, t=2.0):
        return {"ok": states.get(p) == "abierto", "state": states.get(p, "abierto"), "ms": None, "error": None}

    monkeypatch.setattr(K, "tcp_connect", tc)
    r = K.port_check("10.0.0.1", [80, 80, 81, 82])
    assert [x["port"] for x in r["results"]] == [80, 81, 82] and [x["state"] for x in r["results"]] == ["abierto", "cerrado", "sin_respuesta"]
    assert len(K.port_check("10.0.0.1", list(range(1, 40)))["results"]) == 20
    with pytest.raises(ValueError):
        K.port_check("10.0.0.1", [])
