"""Estado compartido de la API y contexto que reciben las rutas.

Una app de escritorio tiene un solo usuario y una captura abierta a la vez,
así que guardamos UN análisis actual en memoria (`_State`). Las rutas lo
alcanzan por inyección de dependencias (`Ctx`), no por globales: cada
`create_app` tiene el suyo y los tests no se pisan entre sí.
"""
from __future__ import annotations

import shutil
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Callable, Dict, Optional

from fastapi import Depends, HTTPException, Request

from backend.domain.analysis.analyzer import Analysis
from backend.domain.rules.iocs import IocSet
from backend.domain.pcap.live import LiveCapture, PacketSource
from backend.domain.pcap.processes import ProcessSampler, ProcessTable
from backend.domain.rules.engine import Rule
from backend.domain.sessions.query import compute_stats


VERSION = "0.2.0"


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop_lock = threading.Lock()  # serializa "detener + analizar" de la captura en vivo
        self.analysis: Optional[Analysis] = None
        self.live: Optional[LiveCapture] = None
        self.live_result: Optional[dict] = None  # resultado de /live/stop, para repetirlo sin reanalizar
        self.owned_dir: Optional[Path] = None  # carpeta temporal de la que depende el análisis actual
        self.sampler: Optional[ProcessSampler] = None  # muestreador de procesos de la captura en vivo en curso
        self.processes: Optional[ProcessTable] = None  # procesos observados del análisis actual (solo captura en vivo)
        self.notes: Dict[int, dict] = {}  # notas del analista por id de sesión; valen para el análisis actual
        self.iocs: Optional[IocSet] = None  # lista de IOC cargada; NO se reemplaza al cambiar de análisis
        self.iocs_name: Optional[str] = None  # solo el nombre del archivo de IOC


@dataclass
class Ctx:
    """Todo lo que las rutas necesitan: estado + dependencias externas inyectadas."""
    state: _State
    rules: list[Rule]
    samples_dir: Path
    live_dir: Optional[Path]
    make_source: Callable[[str], PacketSource]
    interface_lister: Optional[Callable]
    analyze: Callable[[Path, list[Rule]], Analysis]
    make_sampler: Optional[Callable[[], Optional[ProcessSampler]]] = None  # None: sin columna Proceso
    rules_dir: Optional[Path] = None  # carpeta donde el panel de reglas guarda las reglas nuevas


def get_ctx(request: Request) -> Ctx:
    """Dependencia de FastAPI: el contexto guardado en `app.state` al crear la app."""
    return request.app.state.ctx


CtxDep = Annotated[Ctx, Depends(get_ctx)]


def _session_id(a: Analysis, s) -> int:
    """Id de una sesión del análisis. Toda sesión que sale de `group_packets`
    tiene clave, así que un None acá es un bug de core: mejor un error claro
    que un id `null` en la respuesta."""
    sid = a.session_id(s.key)
    if sid is None:
        raise RuntimeError("sesión sin id en el análisis actual")
    return sid


def _rmtree(path: Optional[Path]) -> None:
    """Borra una carpeta temporal si existe, sin quejarse si ya no está."""
    if path is not None:
        shutil.rmtree(path, ignore_errors=True)


def current(ctx: Ctx) -> Analysis:
    """Análisis actual, o 409 si todavía no se analizó nada."""
    a = ctx.state.analysis
    if a is None:
        raise HTTPException(409, "no hay una captura analizada: usá /api/analyze, /api/demo o la captura en vivo")
    return a


def summary(a: Analysis, has_processes: bool = False) -> dict:
    """Resumen de un análisis para las respuestas de analyze/demo/capture.
    `processes`: si hay datos de procesos (solo captura en vivo): la interfaz muestra la columna."""
    return {
        "source": a.path.name,
        "format": a.info.format,
        "linktype": a.info.linktype,
        "snaplen": a.info.snaplen,
        "stats": asdict(compute_stats(a.result)),
        "alerts": len(a.alerts),
        "rules": [{"id": r.id, "name": r.name, "severity": r.severity} for r in a.rules],
        "processes": has_processes,
    }


def clear_analysis(ctx: Ctx) -> None:
    """Vuelve al estado inicial (sin captura cargada). Si el análisis era de una captura en vivo,
    borra su carpeta temporal. Las notas, los procesos y la selección dependían de ese análisis; la
    lista de IOC no: sobrevive, igual que al cambiar de captura."""
    state = ctx.state
    with state.lock:
        previous = state.owned_dir
        state.analysis, state.owned_dir, state.processes, state.notes = None, None, None, {}
    _rmtree(previous)


def set_analysis(
    ctx: Ctx, a: Analysis, owned_dir: Optional[Path] = None, processes: Optional[ProcessTable] = None
) -> dict:
    """Reemplaza el análisis actual. `owned_dir` es una carpeta temporal que
    creamos nosotros y de la que depende el análisis (el pcap de una captura
    en vivo); se borra cuando el análisis se reemplaza, no antes: el detalle
    de paquetes relee ese archivo. `processes` (solo captura en vivo) se
    reemplaza junto con el análisis: los de un archivo nunca los tienen."""
    state = ctx.state
    with state.lock:
        previous = state.owned_dir
        state.analysis = a
        state.owned_dir = owned_dir
        state.processes = processes
        state.notes = {}  # los ids de sesión cambian con cada análisis: las notas viejas apuntarían a otra cosa
    if previous is not None and previous != owned_dir:
        _rmtree(previous)
    return summary(a, has_processes=processes is not None)
