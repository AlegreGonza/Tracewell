"""Utilidades compartidas del paquete: acceso perezoso a psutil, lecturas tolerantes y pistas sobre rutas."""
from __future__ import annotations

import sys
from typing import Any, Callable, Dict, List, Optional

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


class SystemUnavailable(RuntimeError):
    """No se puede leer el sistema (falta psutil o la plataforma no está soportada)."""


def psutil_or_raise():
    try:
        import psutil
    except ImportError as e:
        raise SystemUnavailable("Falta la librería psutil (pip install psutil) para ver el sistema.") from e
    return psutil


def safe(fn: Callable[[], Any], default: Any = None) -> Any:
    """Ejecuta una lectura que puede fallar por permisos o porque el proceso ya terminó (AccessDenied,
    NoSuchProcess, OSError…): devuelve `default` en vez de romper. Un dato que falta es normal, no un error."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - cualquier fallo de lectura del sistema es "dato no disponible"
        return default


# Carpetas desde donde un programa legítimo casi nunca debería correr de forma permanente.
_TEMP_MARKERS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\",
    "/tmp/", "/var/tmp/", "/dev/shm/",
)
# Procesos propios de Windows y la carpeta donde viven de verdad: el mismo nombre en otro lado es la forma
# más común de disfrazar un programa ajeno.
_WINDOWS_PROCESSES = {
    "svchost.exe": "c:\\windows\\system32\\", "lsass.exe": "c:\\windows\\system32\\",
    "csrss.exe": "c:\\windows\\system32\\", "winlogon.exe": "c:\\windows\\system32\\",
    "services.exe": "c:\\windows\\system32\\", "smss.exe": "c:\\windows\\system32\\",
    "wininit.exe": "c:\\windows\\system32\\", "taskhostw.exe": "c:\\windows\\system32\\",
    "explorer.exe": "c:\\windows\\",
}


def path_hints(name: Optional[str], exe: Optional[str]) -> List[Dict[str, str]]:
    """Pistas (no veredictos) sobre dónde vive un programa. Cada una trae un texto que dice por qué mirarla."""
    hints: List[Dict[str, str]] = []
    if not exe:
        return hints
    low = exe.lower().replace("/", "\\")
    if exe.endswith(" (deleted)"):
        hints.append({"code": "borrado", "text": "El archivo del programa ya no está en el disco pero sigue corriendo. Algunos programas maliciosos hacen esto para esconderse."})
    if any(m in low or m in exe.lower() for m in _TEMP_MARKERS):
        hints.append({"code": "carpeta_temporal", "text": "Corre desde una carpeta temporal o de descargas. Los programas instalados suelen vivir en otra parte."})
    expected = _WINDOWS_PROCESSES.get((name or "").lower())
    if expected and IS_WINDOWS and not low.startswith(expected):
        folder = expected.rstrip("\\")
        hints.append({"code": "nombre_de_windows", "text": f"Se llama como un proceso de Windows ({name}) pero no está en su carpeta habitual ({folder}). Un programa ajeno puede usar ese nombre para pasar desapercibido."})
    return hints
