"""Comprobación común de las rutas de archivo que escribe el usuario."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional, Sequence

ENV_ALLOWED_DIRS = "TRACEWELL_ALLOWED_DIRS"  # carpetas separadas con os.pathsep
ANALYZE_EXTENSIONS = (".pcap", ".pcapng", ".cap")


class NotRegularFile(Exception):
    """La ruta existe pero no es un archivo regular (dispositivo, tubería, carpeta)."""


class OutsideAllowedDirs(PermissionError):
    """La ruta (ya resuelta) cae fuera de las carpetas permitidas."""


class BadExtension(Exception):
    """La extensión del archivo no es una de las admitidas."""


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


def _user_folders() -> list[Path]:
    """Descargas, Documentos y Escritorio del usuario (también los de OneDrive)."""
    homes = [Path.home()]
    onedrive = os.environ.get("OneDrive")
    if onedrive:
        homes.append(Path(onedrive))
    return [h / name for h in homes for name in ("Downloads", "Documents", "Desktop")]


def default_allowed_dirs() -> list[Path]:
    """Carpetas por defecto: Descargas, Documentos y Escritorio (sin carpeta temporal fija)."""
    return _user_folders()


def resolve_allowed_dirs(
    explicit: Optional[Iterable] = None, extra: Sequence[Optional[Path]] = ()
) -> tuple[Path, ...]:
    """Lista final y resuelta: parámetro, si no la variable de entorno, si no los valores por defecto."""
    env = os.environ.get(ENV_ALLOWED_DIRS)
    if explicit is not None:
        base = [Path(d) for d in explicit]
    elif env:
        base = [Path(d) for d in env.split(os.pathsep) if d.strip()]
    else:
        base = default_allowed_dirs()
    chosen = base + [p for p in extra if p is not None]
    return tuple(Path(d).expanduser().resolve() for d in chosen)


def require_allowed_file(
    path, allowed: Sequence[Path], kind: str = "archivo", extensions: Optional[Sequence[str]] = None
) -> Path:
    """Como `require_regular_file`, pero exige que la ruta resuelta esté en una carpeta permitida."""
    real = Path(path).expanduser().resolve()  # resuelve `..` y enlaces simbólicos
    if not any(real.is_relative_to(d) for d in allowed):
        raise OutsideAllowedDirs(
            "la ruta está fuera de las carpetas permitidas (Descargas, Documentos, Escritorio, samples). "
            f"Para usar otra carpeta o disco, definí {ENV_ALLOWED_DIRS} antes de iniciar Tracewell"
        )
    if extensions and real.suffix.lower() not in extensions:
        raise BadExtension(f"extensión no admitida: se esperan {', '.join(extensions)}")
    return require_regular_file(real, kind)
