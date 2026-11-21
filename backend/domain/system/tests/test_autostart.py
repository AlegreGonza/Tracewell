"""Tests de backend/domain/system/autostart.py (servicios y programas de inicio): todo con fakes, nada del sistema real."""
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

import backend.domain.system.autostart as A
from backend.domain.system.autostart import _item, services, startup_items
from backend.domain.system.tests.fakes import FakePsutil, FakeService, patch_psutil


# ------------------------------------------------------------------ _item

@pytest.mark.parametrize("command,exe", [
    ('"C:\\Program Files\\App\\app.exe" --silent', "C:\\Program Files\\App\\app.exe"),
    ("C:\\Tools\\tool.exe /x /y", "C:\\Tools\\tool.exe"),
    ("/usr/bin/app --flag", "/usr/bin/app"), ("solo.exe", "solo.exe"), ("  /usr/bin/app  ", "/usr/bin/app"),
    ('"C:\\a b\\x.exe"', "C:\\a b\\x.exe"),
])
def test_item_extrae_el_exe(command, exe, monkeypatch):
    seen = []
    monkeypatch.setattr(A, "path_hints", lambda name, e: seen.append(e) or [])
    _item("donde", "nombre", command)
    assert seen == [exe]


def test_item_forma_y_pistas():
    it = _item("Inicio de tu usuario", "Updater", "C:\\Users\\a\\AppData\\Local\\Temp\\upd.exe --x")
    assert set(it) == {"where", "name", "command", "hints"} and it["where"] == "Inicio de tu usuario" and it["name"] == "Updater"
    assert [h["code"] for h in it["hints"]] == ["carpeta_temporal"]


def test_item_comando_largo_se_corta_a_400():
    assert len(_item("w", "n", "x" * 5000)["command"]) == 400


@pytest.mark.parametrize("command", ["", "   ", '"', '"sin cerrar', '""', "\x00", "<script>alert(1)</script>"])
def test_item_comandos_raros_no_rompen(command):
    assert isinstance(_item("w", "n", command), dict)


def test_item_comillas_desbalanceadas_cae_al_primer_espacio(monkeypatch):
    seen = []
    monkeypatch.setattr(A, "path_hints", lambda name, e: seen.append(e) or [])
    _item("w", "n", '"sin cerrar x')
    assert seen == ['"sin']


# ------------------------------------------------------------------ services

def test_services_plataforma_no_soportada(monkeypatch):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", False)
    out = services()
    assert out["supported"] is False and out["total"] == 0 and out["items"] == [] and "Windows" in out["reason"]


def test_services_linux_sin_systemd_no_soportado(monkeypatch):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", True)
    monkeypatch.setattr(A.shutil, "which", lambda name: None)
    assert services()["supported"] is False


# --- Windows
@pytest.fixture
def win(monkeypatch):
    monkeypatch.setattr(A, "IS_WINDOWS", True)
    monkeypatch.setattr(A, "IS_LINUX", False)


def svc(name, display=None, status="running", start="automatic", pid=None, user="LocalSystem", binpath=None, **kw):
    return FakeService(name=name, display_name=display, status=status, start_type=start, pid=pid, username=user, binpath=binpath, **kw)


def test_servicios_windows_forma_y_traduccion_del_inicio(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("Spooler", "Cola de impresión", "running", "automatic", 44, binpath='"C:\\Windows\\System32\\spoolsv.exe"')]))
    out = services()
    assert out["supported"] is True and out["total"] == 1
    assert out["items"][0] == {"name": "Spooler", "display": "Cola de impresión", "status": "running", "start": "Automático", "pid": 44,
                               "user": "LocalSystem", "path": '"C:\\Windows\\System32\\spoolsv.exe"', "hints": []}


@pytest.mark.parametrize("start,text", [("automatic", "Automático"), ("manual", "Manual"), ("disabled", "Desactivado"), ("raro", "raro"), (None, None)])
def test_servicios_windows_tipos_de_inicio(win, monkeypatch, start, text):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("S", start=start)]))
    assert services()["items"][0]["start"] == text


def test_servicios_windows_en_marcha_primero_y_luego_por_nombre(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[
        svc("a", "Zeta", "stopped"), svc("b", "beta", "running"), svc("c", "Alfa", "stopped"), svc("d", "Gamma", "running")]))
    assert [r["name"] for r in services()["items"]] == ["b", "d", "c", "a"]


def test_servicios_windows_pistas_de_la_ruta(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("Evil", binpath='"C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe" -k x'), svc("Ok", binpath="C:\\Windows\\ok.exe")]))
    rows = {r["name"]: r for r in services()["items"]}
    assert [h["code"] for h in rows["Evil"]["hints"]] == ["carpeta_temporal"]
    assert rows["Ok"]["hints"] == []


def test_servicios_windows_pid_cero_es_none(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("S", pid=0)]))
    assert services()["items"][0]["pid"] is None


def test_servicios_windows_un_servicio_ilegible_no_rompe(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("ok"), svc("roto", _fail=True)]))
    out = services()
    assert out["total"] == 2
    broken = next(r for r in out["items"] if r["name"] is None)
    assert broken["display"] is None and broken["hints"] == []


def test_servicios_windows_listado_imposible_da_lista_vacia(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(deny=["win_service_iter"]))
    assert services() == {"supported": True, "total": 0, "items": []}


def test_servicios_windows_tope(win, monkeypatch):
    monkeypatch.setattr(A, "MAX_ROWS", 4)
    patch_psutil(monkeypatch, FakePsutil(services=[svc(f"s{i}") for i in range(20)]))
    out = services()
    assert out["total"] == 20 and len(out["items"]) == 4


def test_servicios_windows_nombres_hostiles_son_solo_datos(win, monkeypatch):
    patch_psutil(monkeypatch, FakePsutil(services=[svc("<script>", "<img src=x onerror=alert(1)>")]))
    json.dumps(services())


# --- Linux
class RunFake:
    def __init__(self, stdout="", exc=None):
        self.stdout, self.exc, self.calls = stdout, exc, []

    def __call__(self, args, **kw):
        self.calls.append((args, kw))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(args, 0, stdout=self.stdout, stderr="")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", True)
    monkeypatch.setattr(A.shutil, "which", lambda name: "/usr/bin/systemctl")


SYSTEMCTL = """\
ssh.service loaded active running OpenBSD Secure Shell server
cron.service loaded active running Regular background program processing daemon
apt-daily.service loaded inactive dead Daily apt download activities
broken.service loaded failed failed
linea corta
"""


def test_servicios_linux_se_leen_y_ordenan(linux, monkeypatch):
    run = RunFake(SYSTEMCTL)
    monkeypatch.setattr(A.subprocess, "run", run)
    out = services()
    assert out["supported"] is True
    assert [(r["name"], r["status"]) for r in out["items"]] == [("cron.service", "running"), ("ssh.service", "running"), ("apt-daily.service", "dead"), ("broken.service", "failed")]
    assert out["items"][1]["display"] == "OpenBSD Secure Shell server" and out["items"][3]["display"] is None
    assert all(r["start"] is None and r["pid"] is None and r["hints"] == [] for r in out["items"])


def test_servicios_linux_comando_de_solo_lectura(linux, monkeypatch):
    run = RunFake(SYSTEMCTL)
    monkeypatch.setattr(A.subprocess, "run", run)
    services()
    args, kw = run.calls[0]
    assert args[:2] == ["systemctl", "list-units"] and "--type=service" in args
    for verb in ("start", "stop", "restart", "enable", "disable", "mask", "kill", "daemon-reload"):
        assert verb not in args
    assert kw["timeout"] == 15 and kw.get("shell") is not True


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("systemctl", 15), subprocess.SubprocessError("x"), FileNotFoundError("systemctl"), OSError("x")])
def test_servicios_linux_fallo_del_comando(linux, monkeypatch, exc):
    monkeypatch.setattr(A.subprocess, "run", RunFake(exc=exc))
    out = services()
    assert out["supported"] is False and "systemd" in out["reason"] and out["items"] == []


def test_servicios_linux_salida_vacia(linux, monkeypatch):
    monkeypatch.setattr(A.subprocess, "run", RunFake(""))
    assert services() == {"supported": True, "total": 0, "items": []}


def test_servicios_linux_tope(linux, monkeypatch):
    monkeypatch.setattr(A, "MAX_ROWS", 2)
    monkeypatch.setattr(A.subprocess, "run", RunFake("\n".join(f"s{i}.service loaded active running d{i}" for i in range(9))))
    out = services()
    assert out["total"] == 9 and len(out["items"]) == 2


# ------------------------------------------------------------------ startup_items

def test_startup_plataforma_no_soportada(monkeypatch):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", False)
    out = startup_items()
    assert out["supported"] is False and out["items"] == [] and "Windows" in out["reason"]


class PathDouble:
    """Reemplaza a Path para que home() y /etc/xdg/autostart apunten a carpetas temporales."""

    def __init__(self, home, etc):
        self._home, self._etc = home, etc

    def home(self):
        return self._home

    def __call__(self, *a):
        if a and str(a[0]) == "/etc/xdg/autostart":
            return self._etc
        return Path(*a)


@pytest.fixture
def linux_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", True)
    home, etc = tmp_path / "home", tmp_path / "etc"
    (home / ".config" / "autostart").mkdir(parents=True)
    etc.mkdir()
    monkeypatch.setattr(A, "Path", PathDouble(home, etc))
    return home / ".config" / "autostart", etc


def test_inicio_linux_lee_desktop_de_usuario_y_de_sistema(linux_dirs):
    user, etc = linux_dirs
    (user / "a.desktop").write_text("[Desktop Entry]\nName=Mi app\nExec=/opt/app/run --x\n", encoding="utf-8")
    (etc / "b.desktop").write_text("[Desktop Entry]\nName=Sistema\nExec=/usr/bin/sys\n", encoding="utf-8")
    (user / "ignorame.txt").write_text("x")
    out = startup_items()
    assert out["supported"] is True and out["total"] == 2
    by = {i["name"]: i for i in out["items"]}
    assert by["Mi app"]["where"] == "Inicio de tu usuario" and by["Mi app"]["command"] == "/opt/app/run --x"
    assert by["Sistema"]["where"] == "Inicio de todos los usuarios"


def test_inicio_linux_sin_name_o_exec_usa_valores_de_respaldo(linux_dirs):
    user, _ = linux_dirs
    f = user / "sinnombre.desktop"
    f.write_text("[Desktop Entry]\nType=Application\n", encoding="utf-8")
    item = startup_items()["items"][0]
    assert item["name"] == "sinnombre" and item["command"] == str(f)


def test_inicio_linux_pistas_de_ruta(linux_dirs):
    user, _ = linux_dirs
    (user / "t.desktop").write_text("Name=Tmp\nExec=/tmp/evil --x\n", encoding="utf-8")
    assert [h["code"] for h in startup_items()["items"][0]["hints"]] == ["carpeta_temporal"]


def test_inicio_linux_carpetas_inexistentes(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "IS_WINDOWS", False)
    monkeypatch.setattr(A, "IS_LINUX", True)
    monkeypatch.setattr(A, "Path", PathDouble(tmp_path / "nohome", tmp_path / "noetc"))
    assert startup_items() == {"supported": True, "total": 0, "items": []}


def test_inicio_linux_archivo_con_bytes_raros_no_rompe(linux_dirs):
    user, _ = linux_dirs
    (user / "raro.desktop").write_bytes(b"Name=\xff\xfe\x00caf\xc3\xa9\nExec=\x80\x81 x\n")
    assert startup_items()["total"] == 1


def test_inicio_linux_tope(monkeypatch, linux_dirs):
    user, _ = linux_dirs
    monkeypatch.setattr(A, "MAX_ROWS", 3)
    for i in range(10):
        (user / f"{i}.desktop").write_text(f"Name=n{i}\nExec=/bin/x{i}\n", encoding="utf-8")
    out = startup_items()
    assert out["total"] == 10 and len(out["items"]) == 3


# --- Windows (con un winreg FALSO de solo lectura)
class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_winreg(tree):
    """tree: {(root, subkey): [(name, value), ...]}. Cualquier función de escritura hace fallar el test."""
    calls = []

    def open_key(root, sub, *a, **kw):
        calls.append(("OpenKey", root, sub, a, kw))
        if (root, sub) not in tree:
            raise OSError("no existe")
        return FakeKey(tree[(root, sub)])

    def enum_value(key, i):
        if i >= len(key.values):
            raise OSError("fin")
        n, v = key.values[i]
        return n, v, 1

    mod = types.SimpleNamespace(HKEY_CURRENT_USER="HKCU", HKEY_LOCAL_MACHINE="HKLM", OpenKey=open_key, EnumValue=enum_value, calls=calls)

    def forbidden(name):
        def f(*a, **kw):
            raise AssertionError(f"winreg.{name} modificaría el registro")
        return f

    for name in ("SetValue", "SetValueEx", "CreateKey", "CreateKeyEx", "DeleteKey", "DeleteKeyEx", "DeleteValue", "SaveKey", "LoadKey"):
        setattr(mod, name, forbidden(name))
    return mod


RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
RUN32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"


@pytest.fixture
def win_start(monkeypatch, tmp_path):
    monkeypatch.setattr(A, "IS_WINDOWS", True)
    monkeypatch.setattr(A, "IS_LINUX", False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "progdata"))

    def install(tree):
        mod = fake_winreg(tree)
        monkeypatch.setitem(sys.modules, "winreg", mod)
        return mod
    return install


def test_inicio_windows_claves_run(win_start):
    mod = win_start({
        ("HKCU", RUN): [("Spotify", '"C:\\Users\\a\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart'), ("Evil", "C:\\Users\\a\\AppData\\Local\\Temp\\e.exe")],
        ("HKLM", RUN): [("Defender", "C:\\Program Files\\Defender\\d.exe")],
        ("HKCU", RUNONCE): [("Una vez", "cmd /c echo hola")],
        ("HKLM", RUN32): [("Viejo", "C:\\Old\\old.exe")],
    })
    out = startup_items()
    assert out["supported"] is True and out["total"] == 5
    by = {i["name"]: i for i in out["items"]}
    assert by["Spotify"]["where"] == "Inicio de tu usuario" and by["Defender"]["where"] == "Inicio de todos los usuarios"
    assert by["Una vez"]["where"] == "Inicio de tu usuario (una vez)" and by["Viejo"]["where"] == "Inicio de todos (programas de 32 bits)"
    assert [h["code"] for h in by["Evil"]["hints"]] == ["carpeta_temporal"] and by["Spotify"]["hints"] == []
    assert all(c[0] == "OpenKey" for c in mod.calls) and len(mod.calls) == 5  # solo se abrieron las 5 claves, para leer


def test_inicio_windows_claves_inexistentes_se_saltan(win_start):
    win_start({("HKCU", RUN): [("Solo", "C:\\x.exe")]})
    assert [i["name"] for i in startup_items()["items"]] == ["Solo"]


def test_inicio_windows_valores_no_texto(win_start):
    win_start({("HKCU", RUN): [("Bin", b"\x01\x02"), ("Num", 42)]})
    assert startup_items()["total"] == 2


def test_inicio_windows_carpetas_inicio(win_start, tmp_path):
    win_start({})
    user = tmp_path / "appdata" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    allu = tmp_path / "progdata" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
    user.mkdir(parents=True)
    allu.mkdir(parents=True)
    (user / "acceso.lnk").write_text("x")
    (user / "desktop.ini").write_text("x")
    (user / "DESKTOP.INI").write_text("x")
    (allu / "otro.bat").write_text("x")
    out = startup_items()
    names = {(i["where"], i["name"]) for i in out["items"]}
    assert names == {("Carpeta Inicio de tu usuario", "acceso"), ("Carpeta Inicio de todos los usuarios", "otro")}


def test_inicio_windows_nunca_escribe_en_el_registro(win_start):
    mod = win_start({("HKCU", RUN): [("a", "x.exe")], ("HKLM", RUN): [("b", "y.exe")]})
    startup_items()  # si llamara a SetValue/CreateKey/Delete* el fake lanza AssertionError
    assert {c[0] for c in mod.calls} == {"OpenKey"}
    for c in mod.calls:  # y la apertura es la de lectura por defecto (sin pedir KEY_WRITE / KEY_SET_VALUE)
        assert c[3] == () and c[4] == {}


def test_inicio_windows_tope(win_start, monkeypatch):
    monkeypatch.setattr(A, "MAX_ROWS", 2)
    win_start({("HKCU", RUN): [(f"n{i}", f"c{i}.exe") for i in range(7)]})
    out = startup_items()
    assert out["total"] == 7 and len(out["items"]) == 2
