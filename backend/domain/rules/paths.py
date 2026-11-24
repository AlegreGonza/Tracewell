"""Carpeta de reglas del usuario: escribible y fuera de la instalación."""
from __future__ import annotations

import os
from pathlib import Path

ENV_USER_RULES_DIR = "TRACEWELL_USER_RULES_DIR"


def _is_windows() -> bool:
    """Separado para poder probar las dos ramas."""
    return os.name == "nt"


def default_user_rules_dir() -> Path:
    """Variable de entorno; APPDATA en Windows (Tracewell/rules); XDG o ~/.config en el resto."""
    override = os.environ.get(ENV_USER_RULES_DIR)
    if override:
        return Path(override).expanduser()
    if _is_windows():
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "Tracewell" / "rules"
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "tracewell" / "rules"
