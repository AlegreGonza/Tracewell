"""Servicios y programas que arrancan solos. SOLO lee: no activa, desactiva ni borra nada."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from functools import partial
from typing import Any, Dict, List

from .common import IS_LINUX, IS_WINDOWS, path_hints, psutil_or_raise, safe

MAX_ROWS = 500

_RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Inicio de tu usuario"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Inicio de tu usuario (una vez)"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "Inicio de todos los usuarios"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Inicio de todos los usuarios (una vez)"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Inicio de todos (programas de 32 bits)"),
)
_START_TEXT = {"automatic": "Automático", "manual": "Manual", "disabled": "Desactivado"}


def services() -> Dict[str, Any]:
    if IS_WINDOWS:
        return _windows_services()
    if IS_LINUX and shutil.which("systemctl"):
        return _linux_services()
    return {"supported": False, "reason": "Los servicios solo se listan en Windows y en Linux con systemd.", "total": 0, "items": []}


def _windows_services() -> Dict[str, Any]:
    ps = psutil_or_raise()
    rows: List[Dict[str, Any]] = []
    for s in safe(lambda: list(ps.win_service_iter()), []) or []:
        info = safe(s.as_dict, {}) or {}
        binpath = info.get("binpath") or None
        rows.append({
            "name": info.get("name"), "display": info.get("display_name"), "status": info.get("status"),
            "start": _START_TEXT.get(str(info.get("start_type")), info.get("start_type")),
            "pid": info.get("pid") or None, "user": info.get("username"), "path": binpath,
            "hints": path_hints(None, binpath.strip('"') if binpath else None),
        })
    rows.sort(key=lambda r: ((r["status"] != "running"), (r["display"] or r["name"] or "").lower()))
    return {"supported": True, "total": len(rows), "items": rows[:MAX_ROWS]}


def _linux_services() -> Dict[str, Any]:
    try:
        res = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return {"supported": False, "reason": "No se pudo consultar systemd.", "total": 0, "items": []}
    rows: List[Dict[str, Any]] = []
    for line in res.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            rows.append({
                "name": parts[0], "display": parts[4] if len(parts) > 4 else None, "status": parts[3],
                "start": None, "pid": None, "user": None, "path": None, "hints": [],
            })
    rows.sort(key=lambda r: ((r["status"] != "running"), r["name"].lower()))
    return {"supported": True, "total": len(rows), "items": rows[:MAX_ROWS]}


def startup_items() -> Dict[str, Any]:
    if IS_WINDOWS:
        items = _windows_startup()
    elif IS_LINUX:
        items = _linux_startup()
    else:
        return {"supported": False, "reason": "Los programas de inicio solo se listan en Windows y Linux.", "total": 0, "items": []}
    return {"supported": True, "total": len(items), "items": items[:MAX_ROWS]}


def _windows_startup() -> List[Dict[str, Any]]:
    import winreg  # solo existe en Windows

    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    items: List[Dict[str, Any]] = []
    for root, sub, where in _RUN_KEYS:
        items += [_item(where, n, v) for n, v in _registry_values(winreg, roots[root], sub)]
    for where, folder in (
        ("Carpeta Inicio de tu usuario", Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"),
        ("Carpeta Inicio de todos los usuarios", Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/StartUp"),
    ):
        for f in safe(partial(_sorted_dir, folder), []) or []:
            if f.name.lower() != "desktop.ini":
                items.append(_item(where, f.stem, str(f)))
    return items


def _registry_values(winreg, root, sub: str) -> List[tuple]:
    """(nombre, valor) de una clave del registro; lista vacía si no existe o no se puede leer."""
    values: List[tuple] = []
    try:
        with winreg.OpenKey(root, sub) as key:
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, len(values))
                except OSError:
                    break
                values.append((name, str(value)))
    except OSError:
        pass
    return values


def _linux_startup() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for where, folder in (
        ("Inicio de tu usuario", Path.home() / ".config/autostart"),
        ("Inicio de todos los usuarios", Path("/etc/xdg/autostart")),
    ):
        for f in safe(partial(_sorted_desktop, folder), []) or []:
            text = safe(partial(_read_text, f), "") or ""
            fields = {k.strip(): v.strip() for k, _, v in (ln.partition("=") for ln in text.splitlines()) if k.strip() in ("Name", "Exec")}
            items.append(_item(where, fields.get("Name", f.stem), fields.get("Exec", str(f))))
    return items


def _sorted_dir(folder: Path) -> List[Path]:
    return sorted(folder.iterdir())


def _sorted_desktop(folder: Path) -> List[Path]:
    return sorted(folder.glob("*.desktop"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _item(where: str, name: str, command: str) -> Dict[str, Any]:
    cmd = command.strip()
    exe = cmd.split('"')[1] if cmd.startswith('"') and cmd.count('"') >= 2 else cmd.split(" ")[0]
    return {"where": where, "name": name, "command": command[:400], "hints": path_hints(None, exe)}
