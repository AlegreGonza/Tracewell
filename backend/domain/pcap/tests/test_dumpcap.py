"""Tests de dumpcap.py con un dumpcap simulado (sin procesos ni permisos reales)."""
import io
import struct

import pytest

from backend.domain.pcap import dumpcap
from backend.domain.pcap.dumpcap import DUMPCAP_HELP, DumpcapSource, make_source, parse_global_header
from backend.domain.pcap.live import CaptureError, PermissionDenied, ScapySource


def header(linktype=1, magic=0xA1B2C3D4, order="<"):
    return struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)


def record(data, sec=10, frac=500_000, order="<"):
    return struct.pack(order + "IIII", sec, frac, len(data), len(data)) + data


class FakeProc:
    def __init__(self, stdout=b"", stderr=b"", exit_code=None):
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.code, self.terminated = exit_code, False

    def poll(self):
        return self.code

    def send_signal(self, sig):
        self.terminated, self.code = True, 0

    def kill(self):
        self.code = -9

    def wait(self, timeout=None):
        return self.code


@pytest.fixture
def popen(monkeypatch):
    calls = {}

    def install(proc):
        def fake(cmd, **kw):
            calls["cmd"] = cmd
            return proc
        monkeypatch.setattr(dumpcap.subprocess, "Popen", fake)
        return calls
    monkeypatch.setattr(dumpcap, "EARLY_EXIT_WAIT", 0.1)
    return install


def test_entrega_los_paquetes_con_su_tiempo(popen):
    calls = popen(FakeProc(header() + record(b"abc") + record(b"de", sec=11, frac=0)))
    got = []
    src = DumpcapSource("eth0", "tcp", dumpcap="/x/dumpcap")
    src.start(lambda ts, data: got.append((ts, data)))
    src._thread.join(2)
    assert got == [(10.5, b"abc"), (11.0, b"de")]
    assert calls["cmd"] == ["/x/dumpcap", "-i", "eth0", "-P", "-q", "-w", "-", "-f", "tcp"]
    src.stop()


def test_nanosegundos_y_big_endian():
    assert parse_global_header(header(magic=0xA1B23C4D)) == ("<", 1e9)
    assert parse_global_header(header(order=">")) == (">", 1e6)


@pytest.mark.parametrize("head", [b"\x00" * 24, header(linktype=101)])
def test_cabecera_invalida_o_no_ethernet(head):
    with pytest.raises(CaptureError):
        parse_global_header(head)


@pytest.mark.parametrize("msg", [
    b"dumpcap: You don't have permission to capture on that device (socket: Operation not permitted)",
    b"socket: Operation not permitted",
])
def test_salida_inmediata_por_permiso_es_permission_denied(popen, msg):
    popen(FakeProc(stderr=msg, exit_code=1))
    with pytest.raises(PermissionDenied) as ei:
        DumpcapSource("eth0").start(lambda *a: None)
    assert str(ei.value) == DUMPCAP_HELP


def test_salida_con_error_antes_de_la_cabecera_se_informa_en_stop(popen):
    proc = FakeProc(stderr=b"dumpcap: algo fallo")
    proc.wait = lambda timeout=None: setattr(proc, "code", 1)
    popen(proc)
    src = DumpcapSource("eth0")
    src.start(lambda *a: None)
    src._thread.join(2)
    with pytest.raises(CaptureError, match="algo fallo"):
        src.stop()


def test_salida_inmediata_otro_error_muestra_el_mensaje(popen):
    popen(FakeProc(stderr=b"dumpcap: There is no device named nope", exit_code=1))
    with pytest.raises(CaptureError, match="no device named nope"):
        DumpcapSource("nope").start(lambda *a: None)


def test_flujo_corrupto_se_informa_en_stop(popen):
    popen(FakeProc(header() + struct.pack("<IIII", 1, 0, 10_000_000, 10_000_000)))
    src = DumpcapSource("eth0")
    src.start(lambda *a: None)
    src._thread.join(2)
    with pytest.raises(CaptureError, match="corrupto"):
        src.stop()


@pytest.mark.parametrize("name", ["", "  ", "-w", "-", "1", "/tmp/fifo", "rpcap://h:1/eth0", "TCP@h:1", "a b", "x" * 40, None])
def test_interfaz_invalida_no_llega_a_la_linea_de_comandos(name):
    with pytest.raises(CaptureError):
        DumpcapSource(name)


def test_make_source_elige_segun_plataforma_y_variable(monkeypatch):
    monkeypatch.setattr(dumpcap.sys, "platform", "linux")
    monkeypatch.setattr(dumpcap.shutil, "which", lambda n: "/usr/bin/dumpcap")
    monkeypatch.delenv(dumpcap.ENV_BACKEND, raising=False)
    assert isinstance(make_source("eth0"), DumpcapSource)
    monkeypatch.setenv(dumpcap.ENV_BACKEND, "scapy")
    assert isinstance(make_source("eth0"), ScapySource)
    monkeypatch.delenv(dumpcap.ENV_BACKEND)
    monkeypatch.setattr(dumpcap.sys, "platform", "win32")
    assert isinstance(make_source("eth0"), ScapySource)
    monkeypatch.setattr(dumpcap.sys, "platform", "linux")
    monkeypatch.setattr(dumpcap.shutil, "which", lambda n: None)
    assert isinstance(make_source("eth0"), ScapySource)
