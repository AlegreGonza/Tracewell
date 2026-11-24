"""Tests de dumpcap.py con un dumpcap simulado (sin procesos ni permisos reales)."""
import io
import os
import struct

import pytest

from backend.domain.pcap import dumpcap
from backend.domain.pcap.dumpcap import DUMPCAP_HELP, DumpcapSource, check_filter, find_dumpcap, make_source, parse_global_header
from backend.domain.pcap.live import CaptureError, PermissionDenied, ScapySource

# Ruta absoluta en cualquier SO (en Windows '/x' no lo es)
EXE = os.path.abspath("/x/dumpcap")


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
    src = DumpcapSource("eth0", "tcp", dumpcap=EXE)
    src.start(lambda ts, data: got.append((ts, data)))
    src._thread.join(2)
    assert got == [(10.5, b"abc"), (11.0, b"de")]
    assert calls["cmd"] == [EXE, "-i", "eth0", "-P", "-q", "-w", "-", "-f", "tcp"]
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
        DumpcapSource("eth0", dumpcap=EXE).start(lambda *a: None)
    assert str(ei.value) == DUMPCAP_HELP


def test_salida_con_error_antes_de_la_cabecera_se_informa_en_stop(popen):
    proc = FakeProc(stderr=b"dumpcap: algo fallo")
    proc.wait = lambda timeout=None: setattr(proc, "code", 1)
    popen(proc)
    src = DumpcapSource("eth0", dumpcap=EXE)
    src.start(lambda *a: None)
    src._thread.join(2)
    with pytest.raises(CaptureError, match="algo fallo"):
        src.stop()


def test_salida_inmediata_otro_error_muestra_el_mensaje(popen):
    popen(FakeProc(stderr=b"dumpcap: There is no device named nope", exit_code=1))
    with pytest.raises(CaptureError, match="no device named nope"):
        DumpcapSource("nope", dumpcap=EXE).start(lambda *a: None)


def test_flujo_corrupto_se_informa_en_stop(popen):
    popen(FakeProc(header() + struct.pack("<IIII", 1, 0, 10_000_000, 10_000_000)))
    src = DumpcapSource("eth0", dumpcap=EXE)
    src.start(lambda *a: None)
    src._thread.join(2)
    with pytest.raises(CaptureError, match="corrupto"):
        src.stop()


@pytest.mark.parametrize("name", ["", "  ", "-w", "-", "1", "/tmp/fifo", "rpcap://h:1/eth0", "TCP@h:1", "a b", "x" * 40, None])
def test_interfaz_invalida_no_llega_a_la_linea_de_comandos(name):
    with pytest.raises(CaptureError):
        DumpcapSource(name)


def test_make_source_elige_segun_find_dumpcap(monkeypatch):
    monkeypatch.setattr(dumpcap, "find_dumpcap", lambda: EXE)
    assert isinstance(make_source("eth0"), DumpcapSource)
    monkeypatch.setattr(dumpcap, "find_dumpcap", lambda: None)
    assert isinstance(make_source("eth0"), ScapySource)


def test_la_guia_limita_el_permiso_a_un_grupo():
    assert "chgrp packetcapture" in DUMPCAP_HELP and "chmod 750" in DUMPCAP_HELP
    assert DUMPCAP_HELP.index("chmod 750") < DUMPCAP_HELP.index("sudo setcap")  # setcap al final


@pytest.mark.parametrize("bad", ["", "  ", "tcp\nand udp", "tcp\x00", "a" * 2000, 5])
def test_filtro_bpf_invalido_se_rechaza(bad):
    with pytest.raises(CaptureError):
        check_filter(bad)
    with pytest.raises(CaptureError):
        DumpcapSource("eth0", bad)


def test_filtro_bpf_valido_pasa_recortado():
    assert check_filter(" tcp port 80 ") == "tcp port 80" and check_filter(None) is None


def test_dumpcap_exige_ruta_absoluta():
    with pytest.raises(CaptureError):
        DumpcapSource("eth0", dumpcap="dumpcap")


def _fake_fs(monkeypatch, tmp_path, *, uid=0, mode=0o755):
    exe = tmp_path / "dumpcap"
    exe.write_text("x")
    exe.chmod(mode)
    monkeypatch.setattr(dumpcap, "_SYSTEM_DIRS", (str(tmp_path),))
    monkeypatch.setattr(dumpcap.sys, "platform", "linux")
    monkeypatch.delenv(dumpcap.ENV_BACKEND, raising=False)
    real = dumpcap.os.stat
    target = str(exe.resolve())
    monkeypatch.setattr(dumpcap.os, "stat", lambda p, **kw: _with_uid(real(p, **kw), uid) if str(p) == target else real(p, **kw))
    return exe


def _with_uid(st, uid):
    return type("St", (), {"st_mode": st.st_mode, "st_uid": uid})()


@pytest.mark.skipif(dumpcap.sys.platform == "win32", reason="modos POSIX")
def test_busca_solo_en_carpetas_del_sistema_y_exige_dueno_root(monkeypatch, tmp_path):
    exe = _fake_fs(monkeypatch, tmp_path)
    assert find_dumpcap() == str(exe.resolve())
    monkeypatch.setattr(dumpcap.os, "access", lambda p, m: True)
    exe.chmod(0o775)  # escribible por el grupo
    assert find_dumpcap() is None


@pytest.mark.skipif(dumpcap.sys.platform == "win32", reason="modos POSIX")
def test_no_se_confia_en_un_dumpcap_de_otro_usuario(monkeypatch, tmp_path):
    _fake_fs(monkeypatch, tmp_path, uid=1000)
    assert find_dumpcap() is None


def test_no_busca_en_el_path(monkeypatch):
    monkeypatch.setattr(dumpcap.sys, "platform", "linux")
    monkeypatch.setattr(dumpcap, "_SYSTEM_DIRS", ())
    monkeypatch.setenv("PATH", "/tmp/evil")
    assert find_dumpcap() is None


@pytest.mark.skipif(dumpcap.sys.platform == "win32", reason="modos POSIX")
def test_find_dumpcap_respeta_plataforma_y_variable(monkeypatch, tmp_path):
    exe = _fake_fs(monkeypatch, tmp_path)
    assert find_dumpcap() == str(exe.resolve())
    monkeypatch.setenv(dumpcap.ENV_BACKEND, "scapy")
    assert find_dumpcap() is None
    monkeypatch.delenv(dumpcap.ENV_BACKEND)
    monkeypatch.setattr(dumpcap.sys, "platform", "win32")
    assert find_dumpcap() is None
