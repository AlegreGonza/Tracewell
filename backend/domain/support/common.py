"""Base de las herramientas de soporte."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, List, Optional

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
_NO_WINDOW = 0x08000000  # en Windows: no abre una consola negra por cada comando

MAX_OUTPUT = 200_000  # tope de texto que se guarda de un comando


@dataclass
class RunResult:
    ok: bool  # terminó con código 0
    code: Optional[int]
    out: str
    err: str
    missing: bool = False  # el programa no existe en este equipo
    timed_out: bool = False


def run(cmd: List[str], timeout: float = 15.0, env_extra: Optional[dict] = None) -> RunResult:
    """Ejecuta un comando SIN shell (los argumentos van como lista: nada se interpreta ni se concatena)."""
    env = {**os.environ, **env_extra} if env_extra else None
    kwargs: dict = {"creationflags": _NO_WINDOW} if IS_WINDOWS else {}
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, env=env, **kwargs)
    except FileNotFoundError:
        return RunResult(False, None, "", "", missing=True)
    except subprocess.TimeoutExpired:
        return RunResult(False, None, "", "", timed_out=True)
    except OSError as e:
        return RunResult(False, None, "", str(e))
    return RunResult(res.returncode == 0, res.returncode, _decode(res.stdout)[:MAX_OUTPUT], _decode(res.stderr)[:MAX_OUTPUT])


def _decode(raw: bytes) -> str:
    """Texto de un comando."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("oem" if IS_WINDOWS else "utf-8", errors="replace")


def powershell_json(script: str, timeout: float = 20.0) -> Any:
    """Ejecuta un guion de PowerShell que imprime JSON y lo devuelve ya convertido, o None si falló."""
    res = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    if not res.out.strip():
        return None
    try:
        return json.loads(res.out.strip())
    except ValueError:
        return None


_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def valid_host(text: str) -> str:
    """Nombre de equipo o IP escritos por el usuario, ya validados."""
    host = (text or "").strip()
    if not host:
        raise ValueError("escribí un nombre de equipo o una IP")
    if len(host) > 253:
        raise ValueError("el nombre es demasiado largo (máximo 253 caracteres)")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    if all(_LABEL.match(label) for label in labels):
        return host.rstrip(".")
    raise ValueError("el nombre o la IP no es válido (usá letras, números, puntos y guiones)")


def valid_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError("el puerto debe ser un número") from e
    if not 1 <= port <= 65535:
        raise ValueError("el puerto debe estar entre 1 y 65535")
    return port
