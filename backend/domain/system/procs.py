"""Procesos: lista con memoria y procesador, detalle de uno, y la huella y firma de su archivo.

Cada lectura se hace con tolerancia a fallos: sin permisos de administrador algunos procesos (del sistema o de otros
usuarios) no dejan ver todo, y eso se muestra como «—», no como un error. NUNCA se modifica ni se termina un proceso.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from functools import partial
from typing import Any, Dict, List, Optional

from backend.domain.analysis.owners import owner_of
from backend.domain.pcap.processes import normalize_ip

from .common import IS_WINDOWS, path_hints, psutil_or_raise, safe

logger = logging.getLogger(__name__)

CPU_SAMPLE_SECONDS = 0.4
MAX_CMDLINE = 400
MAX_HASH_BYTES = 300 * 1024 * 1024
SORTS = ("ram", "cpu", "name", "pid")
_NO_WINDOW = 0x08000000  # no abre una consola negra al consultar la firma en Windows


def _conn_counts(ps) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for c in safe(lambda: ps.net_connections(kind="inet"), []) or []:
        if c.pid:
            counts[c.pid] = counts.get(c.pid, 0) + 1
    return counts


def list_processes(sort: str = "ram", limit: int = 300) -> Dict[str, Any]:
    """Procesos en marcha. El PID 0 (tiempo libre del procesador en Windows) no es un programa y se omite."""
    ps = psutil_or_raise()
    procs = []
    for p in ps.process_iter():
        if p.pid == 0:
            continue
        safe(partial(p.cpu_percent, None))  # primera lectura: arranca el contador
        procs.append(p)
    time.sleep(CPU_SAMPLE_SECONDS)
    ncpu = ps.cpu_count(logical=True) or 1
    conns = _conn_counts(ps)
    rows: List[Dict[str, Any]] = []
    for p in procs:
        row = safe(partial(_row, p, ncpu, conns))
        if row is not None:
            rows.append(row)
    key = {
        "ram": lambda r: -(r["rss"] or 0), "cpu": lambda r: -(r["cpu"] or 0),
        "name": lambda r: (r["name"] or "").lower(), "pid": lambda r: r["pid"],
    }[sort if sort in SORTS else "ram"]
    rows.sort(key=key)
    return {"total": len(rows), "ncpu": ncpu, "items": rows[: max(1, limit)]}


def _row(p, ncpu: int, conns: Dict[int, int]) -> Dict[str, Any]:
    with p.oneshot():
        name = safe(p.name)
        exe = safe(p.exe) or None
        cmd = safe(p.cmdline) or []
        mem = safe(p.memory_info)
        cpu = safe(lambda: p.cpu_percent(None))
        return {
            "pid": p.pid, "ppid": safe(p.ppid), "name": name, "user": safe(p.username),
            "cpu": round(cpu / ncpu, 1) if cpu is not None else None,
            "rss": mem.rss if mem else None,
            "threads": safe(p.num_threads), "status": safe(p.status), "started": safe(p.create_time),
            "exe": exe, "cmdline": " ".join(cmd)[:MAX_CMDLINE] or None,
            "connections": conns.get(p.pid, 0), "hints": path_hints(name, exe),
        }


def process_detail(pid: int) -> Dict[str, Any]:
    """Todo lo legible de UN proceso. Diccionario vacío si no existe. Lo que el sistema no deja ver va en null."""
    ps = psutil_or_raise()
    try:
        p = ps.Process(pid)
        p.name()
    except Exception:  # noqa: BLE001 - no existe, o ya terminó
        logger.debug("el proceso %s no existe o no se puede leer", pid, exc_info=True)
        return {}
    with p.oneshot():
        name = safe(p.name)
        exe = safe(p.exe) or None
        parent = safe(p.parent)
        mem = safe(p.memory_info)
        io = safe(p.io_counters)
        detail: Dict[str, Any] = {
            "pid": pid, "name": name, "exe": exe, "user": safe(p.username), "status": safe(p.status),
            "cmdline": " ".join(safe(p.cmdline) or [])[:2000] or None, "cwd": safe(p.cwd) or None,
            "started": safe(p.create_time), "threads": safe(p.num_threads),
            "rss": mem.rss if mem else None, "vms": mem.vms if mem else None,
            "parent": {"pid": parent.pid, "name": safe(parent.name)} if parent else None,
            "children": [{"pid": c.pid, "name": safe(c.name)} for c in (safe(p.children, []) or [])[:50]],
            "io": {"read": io.read_bytes, "written": io.write_bytes} if io else None,
            "hints": path_hints(name, exe),
        }
    detail["open_files"] = [f.path for f in (safe(p.open_files, []) or [])[:40]]
    detail["modules"] = _modules(p)
    detail["connections"] = [
        _conn_row(c) for c in (safe(lambda: p.net_connections(kind="inet"), []) or [])[:100]
    ]
    return detail


def _modules(p) -> List[str]:
    """Archivos mapeados en memoria (DLL o bibliotecas), sin repetir y con tope."""
    seen: List[str] = []
    for m in safe(p.memory_maps, []) or []:
        path = getattr(m, "path", None)
        if path and path not in seen:
            seen.append(path)
        if len(seen) >= 80:
            break
    return seen


def _conn_row(c) -> Dict[str, Any]:
    remote = normalize_ip(c.raddr.ip) if c.raddr else None
    return {
        "local": f"{normalize_ip(c.laddr.ip)}:{c.laddr.port}" if c.laddr else None,
        "remote": f"{remote}:{c.raddr.port}" if remote else None,
        "status": c.status, "owner": owner_of(remote) if remote else None,
    }


# ------------------------------------------------------------ huella y firma del archivo

def file_info(pid: int) -> Dict[str, Any]:
    """SHA-256 y firma digital del programa de un proceso. La ruta sale del PROPIO sistema, nunca del usuario."""
    ps = psutil_or_raise()
    exe = safe(lambda: ps.Process(pid).exe())
    if not exe:
        return {"available": False, "reason": "No se pudo leer la ruta del programa (puede faltar permiso de administrador)."}
    path = exe[: -len(" (deleted)")] if exe.endswith(" (deleted)") else exe
    out: Dict[str, Any] = {"available": True, "path": exe, "sha256": None, "size": None, "signature": None}
    size = safe(lambda: os.path.getsize(path))
    out["size"] = size
    if size is None:
        out["hash_note"] = "El archivo no se puede leer (borrado o sin permiso)."
    elif size > MAX_HASH_BYTES:
        out["hash_note"] = "El archivo es demasiado grande para calcular la huella acá."
    else:
        out["sha256"] = safe(lambda: sha256_of(path))
    out["signature"] = file_signature(path)
    return out


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_SIGNATURE_TEXT = {
    "Valid": "Firma válida: el programa lo firmó su autor y no fue modificado.",
    "NotSigned": "Sin firma. No es raro en programas chicos, pero un programa sin firma pide más cuidado.",
    "HashMismatch": "La firma NO coincide con el archivo: fue modificado después de firmarse.",
    "NotTrusted": "Tiene firma, pero de un emisor en el que Windows no confía.",
    "UnknownError": "No se pudo verificar la firma.",
}


def file_signature(path: str) -> Optional[Dict[str, Any]]:
    """Firma digital (solo Windows). Consulta con un único comando de lectura; la ruta viaja en una variable de
    entorno, no dentro del texto del comando, así un nombre de archivo raro no puede inyectar nada."""
    if not IS_WINDOWS:
        return {"status": None, "text": "La verificación de firma digital solo está disponible en Windows.", "subject": None}
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:TW_FILE; "
        "[pscustomobject]@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            env={**os.environ, "TW_FILE": path}, capture_output=True, text=True, timeout=20,
            creationflags=_NO_WINDOW, check=False,
        )
        data = json.loads(res.stdout.strip() or "{}")
    except (subprocess.SubprocessError, OSError, ValueError):
        return {"status": "UnknownError", "text": _SIGNATURE_TEXT["UnknownError"], "subject": None}
    status = data.get("status") or "UnknownError"
    return {"status": status, "text": _SIGNATURE_TEXT.get(status, f"Estado de la firma: {status}."), "subject": data.get("subject") or None}
