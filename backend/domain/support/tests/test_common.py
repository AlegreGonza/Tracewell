"""common: validación de host/puerto y ejecución de comandos sin shell (subprocess falso)."""
import subprocess

import pytest

from backend.domain.support import common as C


@pytest.mark.parametrize("h", ["8.8.8.8", "::1", "www.google.com", "mi-pc", "host.local.", "a" * 63 + ".com"])
def test_valid_host_acepta(h):
    assert C.valid_host(h)


@pytest.mark.parametrize("h", ["", "   ", "a" * 254, "a b", "a;b", "a|b", "a&b", "a$b", "a`b", 'a"b', "a'b", "-n", "-w 1", "a\nb", "a\r\nb", "a..b", "a_b", None])
def test_valid_host_rechaza(h):
    with pytest.raises(ValueError):
        C.valid_host(h)


def test_valid_port():
    assert C.valid_port("443") == 443 and C.valid_port(1) == 1 and C.valid_port(65535) == 65535
    for bad in (0, 65536, "abc", None, -1):
        with pytest.raises(ValueError):
            C.valid_port(bad)


class _Res:
    returncode, stdout, stderr = 0, "ñ".encode(), b""


def test_run_exito_sin_shell(monkeypatch):
    seen = {}

    def fake(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        return _Res()

    monkeypatch.setattr(C.subprocess, "run", fake)
    r = C.run(["x", "a b"], timeout=3)
    assert r.ok and r.out == "ñ" and seen["cmd"] == ["x", "a b"] and "shell" not in seen


@pytest.mark.parametrize("exc,attr", [(FileNotFoundError(), "missing"), (subprocess.TimeoutExpired("x", 1), "timed_out")])
def test_run_errores(monkeypatch, exc, attr):
    def boom(*a, **k):
        raise exc

    monkeypatch.setattr(C.subprocess, "run", boom)
    r = C.run(["x"])
    assert not r.ok and getattr(r, attr) is True


def test_run_oserror(monkeypatch):
    def boom(*a, **k):
        raise OSError("sin permiso")

    monkeypatch.setattr(C.subprocess, "run", boom)
    r = C.run(["x"])
    assert not r.ok and r.err == "sin permiso" and not r.missing


def test_decode(monkeypatch):
    assert C._decode("Señal".encode("utf-8")) == "Señal"
    monkeypatch.setattr(C, "IS_WINDOWS", True)
    assert C._decode("ó".encode("cp850")) == "ó"  # 0xA2 no es UTF-8 válido: cae a la página del sistema (oem)
