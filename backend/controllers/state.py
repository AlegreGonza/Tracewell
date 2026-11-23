"""Estado compartido de la API y contexto que reciben las rutas."""
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
        self.processes: Optional[ProcessTable] = None  # procesos observados del análisis actual
        self.notes: Dict[int, dict] = {}  # notas del analista por id de sesión
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
    """Id de una sesión del análisis."""
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
    """Resumen de un análisis para las respuestas de analyze/demo/capture."""
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
    """Vuelve al estado inicial (sin captura cargada)."""
    state = ctx.state
    with state.lock:
        previous = state.owned_dir
        state.analysis, state.owned_dir, state.processes, state.notes = None, None, None, {}
    _rmtree(previous)


def set_analysis(
    ctx: Ctx, a: Analysis, owned_dir: Optional[Path] = None, processes: Optional[ProcessTable] = None
) -> dict:
    """Reemplaza el análisis actual."""
    state = ctx.state
    with state.lock:
        previous = state.owned_dir
        state.analysis = a
        state.owned_dir = owned_dir
        state.processes = processes
        state.notes = {}  # los ids de sesión cambian con cada análisis
    if previous is not None and previous != owned_dir:
        _rmtree(previous)
    return summary(a, has_processes=processes is not None)
