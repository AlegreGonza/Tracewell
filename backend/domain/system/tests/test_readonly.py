"""Garantía de SOLO LECTURA: ningún módulo de backend/domain/system (ni sus rutas) puede modificar el sistema."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
FILES = sorted((ROOT / "backend" / "domain" / "system").glob("*.py")) + [ROOT / "backend" / "api" / "routes" / "system.py"]

FORBIDDEN_CALLS = [
    r"\.kill\(", r"\.terminate\(", r"\.suspend\(", r"\.resume\(", r"\.nice\(", r"\.ionice\(", r"\.cpu_affinity\(", r"\.send_signal\(", r"\.rlimit\(",
    r"os\.kill\(", r"os\.killpg\(", r"os\.system\(", r"os\.popen\(", r"os\.remove\(", r"os\.unlink\(", r"os\.rmdir\(", r"os\.rename\(", r"os\.chmod\(", r"os\.setuid\(",
    r"shutil\.(rmtree|move|copy|copyfile)\(", r"\.write_text\(", r"\.write_bytes\(", r"\.unlink\(", r"\.rmdir\(", r"\.mkdir\(", r"\.touch\(",
    r"SetValue", r"SetValueEx", r"CreateKey", r"DeleteKey", r"DeleteValue", r"SaveKey", r"LoadKey", r"RegSetValue",
    r"win_service_install", r"\.start\(\)", r"\.stop\(\)", r"\.restart\(", r"shell\s*=\s*True", r"\beval\(", r"\bexec\(", r"__import__\(",
]
WRITE_OPEN = re.compile(r"open\([^)]*['\"][wa+x]b?['\"]")


def code_of(path: Path) -> str:
    """Código sin comentarios ni cadenas de documentación (para no confundir texto explicativo con llamadas)."""
    src = path.read_text(encoding="utf-8")
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    return "\n".join(line.split("#", 1)[0] for line in src.splitlines())


def test_hay_modulos_que_revisar():
    names = {f.name for f in FILES}
    assert {"common.py", "overview.py", "procs.py", "net.py", "autostart.py", "system.py"} <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("pattern", FORBIDDEN_CALLS)
def test_ningun_modulo_llama_a_funciones_que_modifican(path, pattern):
    assert not re.search(pattern, code_of(path)), f"{path.name} contiene {pattern}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_ningun_modulo_abre_archivos_para_escribir(path):
    assert not WRITE_OPEN.search(code_of(path))


def test_winreg_solo_se_usa_para_leer():
    code = code_of(ROOT / "backend" / "domain" / "system" / "autostart.py")
    used = set(re.findall(r"winreg\.(\w+)", code))
    assert used <= {"HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "OpenKey", "EnumValue"}, used


def test_los_comandos_externos_son_solo_los_de_consulta():
    code = code_of(ROOT / "backend" / "domain" / "system" / "procs.py") + code_of(ROOT / "backend" / "domain" / "system" / "autostart.py")
    calls = re.findall(r"subprocess\.(\w+)\(", code)
    assert set(calls) <= {"run"}
    assert "powershell" in code and "systemctl" in code
    for verb in ("Remove-", "Set-", "Stop-", "Start-Process", "Restart-", "Invoke-", "Disable-", "Enable-", "New-", "sc.exe", "taskkill", "reg add", "reg delete"):
        assert verb not in code, verb


def test_solo_hay_rutas_get():
    code = code_of(ROOT / "backend" / "api" / "routes" / "system.py")
    assert re.findall(r"@router\.(\w+)\(", code) and set(re.findall(r"@router\.(\w+)\(", code)) == {"get"}
    for verb in ("post", "put", "delete", "patch"):
        assert f"@router.{verb}" not in code


def test_no_hay_funciones_publicas_con_nombre_de_accion_destructiva():
    from backend.domain.system import autostart, net, overview, procs
    for mod in (autostart, net, overview, procs):
        for name in dir(mod):
            if name.startswith("_"):
                continue
            assert not re.match(r"(kill|terminate|stop|suspend|disable|enable|delete|remove|uninstall|set_|write|create|install|restart|start_)", name), f"{mod.__name__}.{name}"


def test_corriendo_todo_con_un_psutil_que_explota_si_se_modifica(monkeypatch):
    """Recorre TODAS las lecturas con fakes que lanzan AssertionError ante cualquier llamada que modifique."""
    from backend.domain.system import autostart, net, overview, procs
    from backend.domain.system.tests.fakes import FakeProcess, FakePsutil, FakeService, addr, conn, patch_psutil
    p = FakeProcess(5, children=[FakeProcess(6)], open_files=["/a"], maps=["/b"], conns=[conn(addr("10.0.0.1", 1), addr("8.8.8.8", 2), "ESTABLISHED")])
    fake = FakePsutil(procs=[p, FakeProcess(6)], connections=[conn(addr("0.0.0.0", 80), None, "LISTEN", pid=5)],
                      services=[FakeService(name="s", display_name="d", status="running", start_type="auto", pid=1, username="u", binpath="x")])
    patch_psutil(monkeypatch, fake)
    monkeypatch.setattr(procs.time, "sleep", lambda s: None)
    monkeypatch.setattr(autostart, "IS_WINDOWS", True)
    overview.overview()
    procs.list_processes()
    procs.process_detail(5)
    procs.file_info(5)
    net.listening_ports()
    net.connections()
    autostart.services()
    # (si alguno hubiera llamado a kill/terminate/etc., FakeProcess/FakePsutil habrían lanzado AssertionError)
    assert not {"kill", "terminate", "suspend", "resume", "nice"} & set(p.calls)
