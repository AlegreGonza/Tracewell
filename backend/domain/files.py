"""Comprobación común de las rutas de archivo que escribe el usuario."""
from __future__ import annotations

import os
import threading
from collections import deque
from pathlib import Path
from typing import Iterable, Optional, Sequence

ENV_ALLOWED_DIRS = "TRACEWELL_ALLOWED_DIRS"  # carpetas separadas con os.pathsep
ANALYZE_EXTENSIONS = (".pcap", ".pcapng", ".cap")
# Listas de IOC: sin esto, la API leería cualquier archivo de texto de una carpeta permitida (.env, claves...)
IOC_EXTENSIONS = (".txt", ".csv", ".json", ".stix", ".ioc")


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
    """Descargas del usuario (también la de OneDrive): ahí suelen caer las capturas."""
    homes = [Path.home()]
    onedrive = os.environ.get("OneDrive")
    if onedrive:
        homes.append(Path(onedrive))
    return [h / "Downloads" for h in homes]


def default_allowed_dirs() -> list[Path]:
    """Mínimo privilegio: solo Descargas. Documentos y Escritorio enteros ya no se abren por defecto."""
    return _user_folders()


class FileGrants:
    """Archivos que el usuario eligió en el diálogo nativo: se autoriza ESE archivo, no su carpeta."""

    MAX = 64  # los más recientes; así la lista no crece sin límite

    def __init__(self) -> None:
        self._items: deque[Path] = deque(maxlen=self.MAX)
        self._lock = threading.Lock()

    def grant(self, path) -> Path:
        """Autoriza la ruta resuelta (sigue enlaces: si luego apunta a otro archivo, ya no vale)."""
        real = Path(path).expanduser().resolve()
        with self._lock:
            if real not in self._items:
                self._items.append(real)
        return real

    def allows(self, real: Path) -> bool:
        with self._lock:
            return real in self._items


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
    path, allowed: Sequence[Path], kind: str = "archivo", extensions: Optional[Sequence[str]] = None,
    grants: Optional[FileGrants] = None,
) -> Path:
    """Como `require_regular_file`, pero exige carpeta permitida o archivo elegido en el diálogo nativo."""
    real = Path(path).expanduser().resolve()  # resuelve `..` y enlaces simbólicos
    granted = grants is not None and grants.allows(real)
    if not granted and not any(real.is_relative_to(d) for d in allowed):
        raise OutsideAllowedDirs(
            "la ruta está fuera de las carpetas permitidas (Descargas, samples). Elegí el archivo con "
            "«Abrir captura» (autoriza solo ese archivo) o definí "
            f"{ENV_ALLOWED_DIRS} antes de iniciar Tracewell"
        )
    if real.is_dir():
        return require_regular_file(real, kind)  # "la ruta es una carpeta", más útil que la extensión
    if extensions and real.suffix.lower() not in extensions:
        raise BadExtension(f"extensión no admitida: se esperan {', '.join(extensions)}")
    return require_regular_file(real, kind)
