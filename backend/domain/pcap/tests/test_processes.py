"""Tests de backend/domain/pcap/processes.py."""
import logging
import socket
import threading
from collections import namedtuple

import pytest

from backend.domain.pcap import processes as P
from backend.domain.pcap.processes import (
    Conn, ProcessInfo, ProcessSampler, ProcessTable, PsutilProvider, make_default_sampler, normalize_ip,
)

A = ProcessInfo(1, "a.exe")
B = ProcessInfo(2, "b.exe")


# ------------------------------------------------------------- normalize_ip
@pytest.mark.parametrize("raw,expected", [
    ("1.2.3.4", "1.2.3.4"),
    ("::ffff:1.2.3.4", "1.2.3.4"),
    ("::FFFF:1.2.3.4", "1.2.3.4"),
    ("fe80::1%12", "fe80::1"),
    ("fe80::1%eth0", "fe80::1"),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("2001:DB8::1", "2001:db8::1"),
    ("::1", "::1"),
    ("::", "::"),
    ("1.2.3.4%1", "1.2.3.4"),
])
def test_normalize_ip_validas(raw, expected):
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["", "garbage", "999.1.1.1", "1.2.3", "%12", " 1.2.3.4", None, 5, b"1.2.3.4", ["1.2.3.4"], "1.2.3.4/24"])
def test_normalize_ip_invalidas(raw):
    assert normalize_ip(raw) is None


# --------------------------------------------------------------- ProcessTable
def conn(proto="TCP", lip="10.0.0.1", lport=1000, rip="8.8.8.8", rport=443, proc=A):
    return Conn(proto, lip, lport, rip, rport, proc)


def test_tabla_vacia():
    t = ProcessTable()
    assert len(t) == 0 and t.full is False
    assert t.lookup("TCP", "1.1.1.1", 1, "2.2.2.2", 2) is None


def test_lookup_exacto_en_ambas_orientaciones():
    t = ProcessTable()
    t.add(conn())
    assert t.lookup("TCP", "10.0.0.1", 1000, "8.8.8.8", 443) == A
    assert t.lookup("TCP", "8.8.8.8", 443, "10.0.0.1", 1000) == A


def test_exacto_no_coincide_con_otro_puerto_o_proto():
    t = ProcessTable()
    t.add(conn())
    assert t.lookup("TCP", "10.0.0.1", 1001, "8.8.8.8", 443) is None
    assert t.lookup("UDP", "10.0.0.1", 1000, "8.8.8.8", 443) is None
    assert t.lookup("TCP", "10.0.0.1", 1000, "8.8.4.4", 443) is None


def test_lookup_normaliza_la_ip_consultada():
    t = ProcessTable()
    t.add(conn(lip="fe80::1", rip="2001:db8::1"))
    assert t.lookup("TCP", "FE80::1%3", 1000, "2001:0db8::1", 443) == A
    t2 = ProcessTable()
    t2.add(conn())
    assert t2.lookup("TCP", "::ffff:10.0.0.1", 1000, "8.8.8.8", 443) == A


def test_lookup_ip_invalida_devuelve_none():
    t = ProcessTable()
    t.add(conn())
    assert t.lookup("TCP", "basura", 1000, "8.8.8.8", 443) is None
    assert t.lookup("TCP", "10.0.0.1", 1000, None, 443) is None


def test_primera_vista_gana_exacto():
    t = ProcessTable()
    t.add(conn(proc=A))
    t.add(conn(proc=B))
    assert t.lookup("TCP", "10.0.0.1", 1000, "8.8.8.8", 443) == A
    assert len(t) == 1


def test_primera_vista_gana_por_puerto():
    t = ProcessTable()
    t.set_local_ips(["10.0.0.1"])
    t.add(conn("UDP", rip=None, rport=None, proc=A))
    t.add(conn("UDP", rip=None, rport=None, proc=B))
    assert t.lookup("UDP", "10.0.0.1", 1000, "9.9.9.9", 53) == A


def test_respaldo_por_puerto_solo_con_ip_local():
    t = ProcessTable()
    t.add(conn("UDP", lip="0.0.0.0", rip=None, rport=None, lport=5353))
    # sin local_ips no se usa el respaldo
    assert t.lookup("UDP", "10.0.0.1", 5353, "9.9.9.9", 5000) is None
    t.set_local_ips(["10.0.0.1"])
    assert t.lookup("UDP", "10.0.0.1", 5353, "9.9.9.9", 5000) == A
    # orientación inversa: el extremo local es el destino
    assert t.lookup("UDP", "9.9.9.9", 5000, "10.0.0.1", 5353) == A
    # IP remota con el mismo puerto NO cuenta
    assert t.lookup("UDP", "9.9.9.9", 5353, "8.8.8.8", 1) is None
    # puerto local distinto
    assert t.lookup("UDP", "10.0.0.1", 5354, "9.9.9.9", 5000) is None


def test_respaldo_por_puerto_separa_protocolos():
    t = ProcessTable()
    t.set_local_ips(["10.0.0.1"])
    t.add(conn("UDP", rip=None, rport=None, lport=53, proc=A))
    t.add(conn("TCP", rip=None, rport=None, lport=53, proc=B))
    assert t.lookup("UDP", "10.0.0.1", 53, "1.1.1.1", 9) == A
    assert t.lookup("TCP", "10.0.0.1", 53, "1.1.1.1", 9) == B


def test_set_local_ips_normaliza_filtra_y_reemplaza():
    t = ProcessTable()
    t.add(conn("UDP", rip=None, rport=None, lport=7, proc=A))
    t.set_local_ips(["::ffff:10.0.0.1", "basura", None, "fe80::1%2"])
    assert t.lookup("UDP", "10.0.0.1", 7, "9.9.9.9", 1) == A
    assert t.lookup("UDP", "fe80::1", 7, "9.9.9.9", 1) == A
    t.set_local_ips([])
    assert t.lookup("UDP", "10.0.0.1", 7, "9.9.9.9", 1) is None


def test_conn_con_remoto_incompleto_va_por_puerto():
    t = ProcessTable()
    t.set_local_ips(["10.0.0.1"])
    t.add(conn(rip="8.8.8.8", rport=None, lport=77))
    t.add(conn(rip=None, rport=80, lport=78, proc=B))
    assert t.lookup("TCP", "10.0.0.1", 77, "1.1.1.1", 1) == A
    assert t.lookup("TCP", "10.0.0.1", 78, "1.1.1.1", 1) == B


def test_ipv6():
    t = ProcessTable()
    t.set_local_ips(["2001:db8::1"])
    t.add(Conn("TCP", "2001:db8::1", 5000, "2001:db8::2", 443, A))
    t.add(Conn("UDP", "::", 546, None, None, B))
    assert t.lookup("TCP", "2001:db8::2", 443, "2001:db8::1", 5000) == A
    assert t.lookup("UDP", "2001:db8::1", 546, "2001:db8::ff", 547) == B


@pytest.mark.parametrize("proto", ["ICMP", "ICMPv6", "SCTP", "", "tcp"])
def test_protocolo_desconocido_o_icmp_es_none(proto):
    t = ProcessTable()
    t.set_local_ips(["10.0.0.1"])
    t.add(conn())
    t.add(conn("UDP", rip=None, rport=None, lport=0))
    assert t.lookup(proto, "10.0.0.1", 1000, "8.8.8.8", 443) is None
    assert t.lookup(proto, "10.0.0.1", 0, "8.8.8.8", 0) is None


def test_tcp_y_udp_exactos_no_se_mezclan():
    t = ProcessTable()
    t.add(conn("TCP", proc=A))
    t.add(conn("UDP", proc=B))
    assert t.lookup("TCP", "10.0.0.1", 1000, "8.8.8.8", 443) == A
    assert t.lookup("UDP", "10.0.0.1", 1000, "8.8.8.8", 443) == B
    assert len(t) == 2


def test_tope_por_almacen():
    t = ProcessTable(max_entries=2)
    t.add(conn(lport=1))
    t.add(conn(lport=2))
    assert not t.full
    t.add(conn(lport=3))  # excede: se ignora
    assert t.full and len(t) == 2
    assert t.lookup("TCP", "10.0.0.1", 3, "8.8.8.8", 443) is None
    assert t.lookup("TCP", "10.0.0.1", 1, "8.8.8.8", 443) == A


def test_tope_es_por_almacen_no_global():
    t = ProcessTable(max_entries=1)
    t.add(conn(lport=1))
    t.add(conn("UDP", rip=None, rport=None, lport=9, proc=B))  # otro almacén: aún cabe
    assert len(t) == 2 and not t.full
    t.add(conn("UDP", rip=None, rport=None, lport=10))
    assert t.full


def test_duplicado_con_tabla_llena_no_marca_full():
    t = ProcessTable(max_entries=1)
    t.add(conn(lport=1))
    t.add(conn(lport=1, proc=B))  # clave existente: no es exceso
    assert not t.full


def test_tabla_concurrente():
    t = ProcessTable()

    def work(base):
        for i in range(200):
            t.add(conn(lport=base + i))
            t.lookup("TCP", "10.0.0.1", base + i, "8.8.8.8", 443)

    threads = [threading.Thread(target=work, args=(k * 1000,)) for k in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(t) == 800


# ------------------------------------------------------------ PsutilProvider
Addr = namedtuple("Addr", "ip port")
SConn = namedtuple("SConn", "fd family type laddr raddr status pid")
IfAddr = namedtuple("IfAddr", "family address netmask broadcast ptp")


def sc(type_=socket.SOCK_STREAM, laddr=Addr("10.0.0.1", 1000), raddr=Addr("8.8.8.8", 443), pid=10):
    return SConn(-1, socket.AF_INET, type_, laddr, raddr, "ESTABLISHED", pid)


class NoSuchProcess(Exception):
    pass


class AccessDenied(Exception):
    pass


class FakeProc:
    def __init__(self, value):
        self.value = value

    def name(self):
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class FakePsutil:
    def __init__(self, conns=(), addrs=None, names=None):
        self.conns = list(conns)
        self.addrs = addrs or {}
        self.names = names or {}
        self.process_calls = []
        self.kinds = []

    def net_connections(self, kind="inet"):
        self.kinds.append(kind)
        return self.conns

    def net_if_addrs(self):
        return self.addrs

    def Process(self, pid):
        self.process_calls.append(pid)
        return FakeProc(self.names[pid])


def test_provider_local_ips_solo_ip():
    ps = FakePsutil(addrs={
        "eth0": [IfAddr(socket.AF_INET, "10.0.0.1", None, None, None),
                 IfAddr(socket.AF_INET6, "fe80::1%12", None, None, None)],
        "mac": [IfAddr(-1000, "aa:bb:cc:dd:ee:ff", None, None, None)],
    })
    assert PsutilProvider(ps).local_ips() == ["10.0.0.1", "fe80::1%12"]
    assert PsutilProvider(FakePsutil()).local_ips() == []


def test_provider_mapea_tcp_udp_y_normaliza():
    ps = FakePsutil(
        conns=[sc(), sc(socket.SOCK_DGRAM, Addr("::ffff:10.0.0.1", 5000), ()),
               sc(socket.SOCK_DGRAM, Addr("fe80::1%3", 6000), Addr("fe80::2", 7000))],
        names={10: "app.exe"},
    )
    got = PsutilProvider(ps).connections()
    assert ps.kinds == ["inet"]
    assert got == [
        Conn("TCP", "10.0.0.1", 1000, "8.8.8.8", 443, ProcessInfo(10, "app.exe")),
        Conn("UDP", "10.0.0.1", 5000, None, None, ProcessInfo(10, "app.exe")),
        Conn("UDP", "fe80::1", 6000, "fe80::2", 7000, ProcessInfo(10, "app.exe")),
    ]


def test_provider_omite_tipos_otros_pid_none_y_laddr_vacia():
    ps = FakePsutil(
        conns=[sc(type_=socket.SOCK_RAW), sc(pid=None), sc(laddr=()), sc(laddr=None),
               sc(laddr=Addr("basura", 1)), sc(pid=5)],
        names={5: "ok"},
    )
    got = PsutilProvider(ps).connections()
    assert [c.process.pid for c in got] == [5]


def test_provider_raddr_con_ip_invalida_queda_sin_remoto():
    ps = FakePsutil(conns=[sc(raddr=Addr("basura", 9))], names={10: "n"})
    (c,) = PsutilProvider(ps).connections()
    assert c.remote_ip is None and c.remote_port is None


def test_provider_nombre_falla_da_pid_n():
    ps = FakePsutil(
        conns=[sc(pid=1), sc(pid=2), sc(pid=3)],
        names={1: NoSuchProcess(), 2: AccessDenied(), 3: RuntimeError("x")},
    )
    names = [c.process.name for c in PsutilProvider(ps).connections()]
    assert names == ["PID 1", "PID 2", "PID 3"]


def test_provider_cachea_nombres_solo_dentro_de_una_llamada():
    ps = FakePsutil(conns=[sc(laddr=Addr("10.0.0.1", 1)), sc(laddr=Addr("10.0.0.1", 2))], names={10: "p"})
    prov = PsutilProvider(ps)
    prov.connections()
    assert ps.process_calls == [10]  # dos conexiones, un solo lookup
    ps.names[10] = "reusado"  # el PID se reutilizó para otro programa
    got = prov.connections()
    assert ps.process_calls == [10, 10]
    assert got[0].process.name == "reusado"


def test_provider_propaga_errores_de_psutil():
    class Boom(FakePsutil):
        def net_connections(self, kind="inet"):
            raise PermissionError("sin permiso")

    with pytest.raises(PermissionError):
        PsutilProvider(Boom()).connections()


# ------------------------------------------------------------ ProcessSampler
class FakeProvider:
    def __init__(self, conns=(), fail=0, ips=("10.0.0.1",)):
        self.conns = list(conns)
        self.fail = fail  # cuántas llamadas fallan al principio
        self.ips = list(ips)
        self.calls = 0
        self.first = threading.Event()

    def local_ips(self):
        return self.ips

    def connections(self):
        self.calls += 1
        self.first.set()
        if self.calls <= self.fail:
            raise PermissionError("denegado")
        return self.conns


def test_sampler_muestrea_de_inmediato_y_una_final_al_parar():
    prov = FakeProvider([conn()])
    s = ProcessSampler(prov, interval=3600)  # nunca vence solo: determinista
    s.start()
    assert prov.first.wait(5)
    s.stop()
    assert prov.calls == 2 and s.samples == 2 and s.errors == 0
    assert s.table.lookup("TCP", "10.0.0.1", 1000, "8.8.8.8", 443) == A
    assert not s._thread.is_alive()


def test_sampler_hilo_daemon():
    s = ProcessSampler(FakeProvider(), interval=3600)
    s.start()
    try:
        assert s._thread.daemon is True
    finally:
        s.stop()


def test_sampler_start_idempotente():
    prov = FakeProvider()
    s = ProcessSampler(prov, interval=3600)
    s.start()
    t = s._thread
    s.start()
    assert s._thread is t
    s.stop()
    assert prov.calls == 2


def test_sampler_stop_idempotente():
    prov = FakeProvider()
    s = ProcessSampler(prov, interval=3600)
    s.start()
    s.stop()
    n = prov.calls
    s.stop()
    s.stop()
    assert prov.calls == n


def test_sampler_stop_sin_start_es_seguro_y_no_muestrea():
    prov = FakeProvider()
    s = ProcessSampler(prov)
    s.stop()
    assert prov.calls == 0 and s.samples == 0


def test_sampler_excepcion_no_se_propaga_y_se_loguea_una_vez(caplog):
    prov = FakeProvider([conn()], fail=2)
    s = ProcessSampler(prov, interval=3600)
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        s.start()
        assert prov.first.wait(5)
        s.stop()  # la muestra final también falla
    assert s.errors == 2 and s.samples == 0
    assert len([r for r in caplog.records if r.name == "tracewell"]) == 1
    assert len(s.table) == 0


def test_sampler_primera_falla_luego_ok_cuenta_solo_las_buenas():
    prov = FakeProvider([conn()], fail=1)
    s = ProcessSampler(prov, interval=3600)
    s.start()
    assert prov.first.wait(5)
    s.stop()
    assert s.errors == 1 and s.samples == 1
    assert len(s.table) == 1


def test_sampler_falla_en_local_ips_cuenta_como_error():
    class BadIps(FakeProvider):
        def local_ips(self):
            raise OSError("x")

    s = ProcessSampler(BadIps(), interval=3600)
    s._sample_safely()
    assert s.errors == 1 and s.samples == 0


def test_sampler_usa_tabla_inyectada_y_setea_ips_locales():
    table = ProcessTable()
    prov = FakeProvider([Conn("UDP", "0.0.0.0", 53, None, None, A)], ips=["10.0.0.1"])
    s = ProcessSampler(prov, interval=3600, table=table)
    assert s.table is table
    s._sample_safely()
    assert table.lookup("UDP", "10.0.0.1", 53, "9.9.9.9", 1) == A


def test_sampler_muestrea_periodicamente():
    prov = FakeProvider()
    done = threading.Event()
    orig = prov.connections

    def counting():
        r = orig()
        if prov.calls >= 3:
            done.set()
        return r

    prov.connections = counting
    s = ProcessSampler(prov, interval=0.01)
    s.start()
    assert done.wait(5)
    s.stop()
    assert s.samples >= 3


# -------------------------------------------------------- make_default_sampler
def test_make_default_sampler_none_sin_psutil(monkeypatch):
    monkeypatch.setattr(P, "_import_psutil", lambda: None)
    assert make_default_sampler() is None


def test_make_default_sampler_con_psutil_falso(monkeypatch):
    fake = FakePsutil()
    monkeypatch.setattr(P, "_import_psutil", lambda: fake)
    s = make_default_sampler(interval=7)
    assert isinstance(s, ProcessSampler) and s._interval == 7
    assert isinstance(s._provider, PsutilProvider) and s._provider._ps is fake
    assert s._thread is None  # no arranca solo


def test_import_psutil_sin_modulo(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "psutil":
            raise ImportError
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert P._import_psutil() is None


def test_import_psutil_con_modulo_falso(monkeypatch):
    import sys
    import types
    fake = types.ModuleType("psutil")
    monkeypatch.setitem(sys.modules, "psutil", fake)
    assert P._import_psutil() is fake


@pytest.mark.parametrize("type_", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_provider_omite_pid_0_en_tcp_y_udp(type_):
    ps = FakePsutil(conns=[sc(type_=type_, pid=0)], names={0: "System Idle Process"})
    assert PsutilProvider(ps).connections() == []
    assert ps.process_calls == []  # ni siquiera se consulta el nombre


def test_provider_pid_none_sigue_omitido_y_pids_chicos_se_incluyen():
    ps = FakePsutil(
        conns=[sc(pid=None), sc(pid=4, laddr=Addr("10.0.0.1", 1)), sc(pid=1, laddr=Addr("10.0.0.1", 2))],
        names={4: "System", 1: "init"},
    )
    got = PsutilProvider(ps).connections()
    assert [(c.process.pid, c.process.name) for c in got] == [(4, "System"), (1, "init")]


def test_provider_lista_mixta_pid_0_desaparece():
    ps = FakePsutil(
        conns=[sc(pid=0, laddr=Addr("10.0.0.1", 1)), sc(pid=10, laddr=Addr("10.0.0.1", 2)),
               sc(socket.SOCK_DGRAM, pid=0, laddr=Addr("10.0.0.1", 3), raddr=()),
               sc(pid=4, laddr=Addr("10.0.0.1", 4)), sc(pid=None, laddr=Addr("10.0.0.1", 5))],
        names={10: "app", 4: "System"},
    )
    got = PsutilProvider(ps).connections()
    assert [c.local_port for c in got] == [2, 4]
