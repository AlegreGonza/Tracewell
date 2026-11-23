"""Tests de backend/domain/system/common.py."""
import sys

import pytest

import backend.domain.system.common as C
from backend.domain.system.common import SystemUnavailable, path_hints, psutil_or_raise, safe
from backend.domain.system.tests.fakes import AccessDenied, NoSuchProcess


# ------------------------------------------------------------------ psutil_or_raise

def test_psutil_or_raise_devuelve_el_modulo(monkeypatch):
    fake = object()
    monkeypatch.setitem(sys.modules, "psutil", fake)
    assert psutil_or_raise() is fake


def test_psutil_or_raise_sin_psutil_lanza_systemunavailable_con_texto(monkeypatch):
    monkeypatch.setitem(sys.modules, "psutil", None)  # import psutil -> ImportError
    with pytest.raises(SystemUnavailable) as exc:
        psutil_or_raise()
    assert "psutil" in str(exc.value) and "pip install" in str(exc.value)
    assert isinstance(exc.value.__cause__, ImportError)


def test_systemunavailable_es_runtimeerror():
    assert issubclass(SystemUnavailable, RuntimeError)


# ------------------------------------------------------------------ safe

def test_safe_devuelve_el_valor():
    assert safe(lambda: 42) == 42
    assert safe(lambda: 0, default=7) == 0 and safe(lambda: "", default="x") == ""


@pytest.mark.parametrize("exc", [AccessDenied, NoSuchProcess, OSError, PermissionError, ValueError, KeyError, ZeroDivisionError, RuntimeError])
def test_safe_traga_los_fallos_de_lectura(exc):
    def boom():
        raise exc("x")
    assert safe(boom) is None
    assert safe(boom, default=[]) == []
    assert safe(boom, "d") == "d"


def test_safe_no_traga_las_interrupciones():
    def stop():
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        safe(stop)


def test_safe_llama_a_la_funcion_una_sola_vez():
    calls = []
    safe(lambda: calls.append(1))
    assert calls == [1]


# ------------------------------------------------------------------ path_hints

def codes(name, exe):
    return [h["code"] for h in path_hints(name, exe)]


def test_sin_exe_no_hay_pistas():
    assert path_hints("svchost.exe", None) == [] and path_hints("x", "") == []


def test_cada_pista_trae_codigo_y_texto():
    hints = path_hints("x", "C:\\Users\\a\\AppData\\Local\\Temp\\x.exe (deleted)")
    assert hints and all(set(h) == {"code", "text"} and h["text"].strip() for h in hints)


@pytest.mark.parametrize("exe", [
    "C:\\Users\\ana\\AppData\\Local\\Temp\\setup.exe", "c:\\windows\\temp\\x.exe", "C:\\Users\\ana\\Downloads\\x.exe", "C:\\Users\\Public\\x.exe",
    "/tmp/evil", "/var/tmp/evil", "/dev/shm/evil", "/home/ana/Downloads/x", "C:/Users/ana/AppData/Local/Temp/x.exe",
])
def test_carpeta_temporal(exe):
    assert "carpeta_temporal" in codes("x", exe)


@pytest.mark.parametrize("exe", [
    "C:\\Program Files\\App\\app.exe", "/usr/bin/python3", "/opt/app/bin/app", "C:\\Windows\\System32\\notepad.exe", "/home/ana/tmpfile/x",
    "C:\\Users\\ana\\AppData\\Local\\Programs\\App\\app.exe",
])
def test_rutas_normales_sin_carpeta_temporal(exe):
    assert "carpeta_temporal" not in codes("x", exe)


def test_borrado():
    assert codes("x", "/usr/bin/prog (deleted)") == ["borrado"]
    assert "borrado" not in codes("x", "/usr/bin/prog")
    assert "borrado" not in codes("x", "/usr/bin/(deleted)/prog")


def test_borrado_en_carpeta_temporal_da_las_dos_pistas():
    assert codes("x", "/tmp/evil (deleted)") == ["borrado", "carpeta_temporal"]


class TestNombreDeWindows:
    @pytest.fixture(autouse=True)
    def windows(self, monkeypatch):
        monkeypatch.setattr(C, "IS_WINDOWS", True)

    @pytest.mark.parametrize("name", ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "taskhostw.exe"])
    def test_en_system32_no_hay_pista(self, name):
        assert "nombre_de_windows" not in codes(name, f"C:\\Windows\\System32\\{name}")
        assert "nombre_de_windows" not in codes(name, f"c:\\WINDOWS\\system32\\{name}")  # mayúsculas y minúsculas

    @pytest.mark.parametrize("name", ["svchost.exe", "lsass.exe", "csrss.exe", "services.exe"])
    def test_en_otra_carpeta_si(self, name):
        assert "nombre_de_windows" in codes(name, f"C:\\Users\\ana\\{name}")
        assert "nombre_de_windows" in codes(name, f"C:\\ProgramData\\x\\{name}")

    def test_el_texto_nombra_el_proceso_y_su_carpeta(self):
        h = next(h for h in path_hints("svchost.exe", "C:\\Users\\a\\svchost.exe") if h["code"] == "nombre_de_windows")
        assert "svchost.exe" in h["text"] and "c:\\windows\\system32" in h["text"]

    def test_explorer_vive_en_windows_no_en_system32(self):
        assert "nombre_de_windows" not in codes("explorer.exe", "C:\\Windows\\explorer.exe")
        assert "nombre_de_windows" not in codes("explorer.exe", "C:\\Windows\\System32\\explorer.exe")  # también empieza con c:\windows\
        assert "nombre_de_windows" in codes("explorer.exe", "C:\\Users\\a\\explorer.exe")

    def test_nombre_en_mayusculas(self):
        assert "nombre_de_windows" in codes("SVCHOST.EXE", "C:\\Users\\a\\svchost.exe")

    def test_una_carpeta_parecida_no_engana(self):
        assert "nombre_de_windows" in codes("explorer.exe", "C:\\WindowsFake\\explorer.exe")
        assert "nombre_de_windows" in codes("svchost.exe", "C:\\Windows\\System32Fake\\svchost.exe")

    def test_nombres_desconocidos_o_ausentes_no_generan_pista(self):
        assert "nombre_de_windows" not in codes("chrome.exe", "C:\\Users\\a\\chrome.exe")
        assert "nombre_de_windows" not in codes(None, "C:\\Users\\a\\svchost.exe")

    def test_ruta_con_barras_normales(self):
        assert "nombre_de_windows" not in codes("svchost.exe", "C:/Windows/System32/svchost.exe")
        assert "nombre_de_windows" in codes("svchost.exe", "C:/Users/a/svchost.exe")


def test_nombre_de_windows_solo_en_windows(monkeypatch):
    monkeypatch.setattr(C, "IS_WINDOWS", False)
    assert "nombre_de_windows" not in codes("svchost.exe", "/home/a/svchost.exe")
    assert "nombre_de_windows" not in codes("svchost.exe", "C:\\Users\\a\\svchost.exe")


def test_las_pistas_son_orientativas_nunca_dicen_que_es_malware():
    for exe in ("/tmp/x (deleted)", "C:\\Users\\a\\Downloads\\x.exe"):
        for h in path_hints("x", exe):
            assert "es un virus" not in h["text"].lower() and "es malware" not in h["text"].lower()


def test_exe_con_caracteres_raros_no_rompe():
    for exe in ("\x00", "<script>alert(1)</script>", "ñ" * 500, "C:\\" + "a\\" * 300 + "x.exe"):
        assert isinstance(path_hints("x", exe), list)
