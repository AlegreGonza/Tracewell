"""Comprobación común de las rutas de archivo que escribe el usuario."""
from __future__ import annotations

from pathlib import Path


class NotRegularFile(Exception):
    """La ruta existe pero no es un archivo regular (dispositivo, tubería, carpeta)."""


def require_regular_file(path, kind: str = "archivo") -> Path:
    """Ruta expandida de un archivo regular; falla antes de abrir (con, aux, nul no se abren)."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError("el archivo no existe")
    if p.is_dir():
        raise IsADirectoryError(f"la ruta es una carpeta, no un {kind}")
    if not p.is_file():
        raise NotRegularFile(f"la ruta no es un archivo normal (¿un dispositivo?), no un {kind}")
    return p
