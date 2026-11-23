"""API HTTP de Tracewell."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional, Sequence

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.domain.analysis.analyzer import analyze
from backend.domain.pcap.live import CaptureError, PacketSource, ScapySource
from backend.domain.pcap.processes import ProcessSampler, make_default_sampler
from backend.domain.rules.engine import load_rules
from backend.domain.support.monitor import monitor

from .routes import analysis as routes_analysis
from .routes import insights as routes_insights
from .routes import live as routes_live
from .routes import rules as routes_rules
from .routes import support as routes_support
from .routes import system as routes_system
from .routes import triage as routes_triage
from .errors import register_error_handlers
from .security import LOCAL_HOSTS, install_local_only, install_security_headers
from backend.controllers.state import VERSION, Ctx, _rmtree, _State

logger = logging.getLogger("tracewell")

ROOT = Path(__file__).resolve().parents[2]  # raíz del proyecto (backend/api/app.py)

__all__ = ["ROOT", "VERSION", "LOCAL_HOSTS", "create_app", "analyze"]


def _shutdown(state: _State) -> None:
    """Al cerrar: detiene una captura en curso (y su muestreo de procesos) y borra lo temporal que creamos."""
    try:
        _stop_live(state.live)
    finally:
        monitor.stop()  # el monitoreo de cortes es un hilo de fondo
        if state.sampler is not None:
            state.sampler.stop()
        _rmtree(state.owned_dir)  # se borra aunque detener la captura falle


def _stop_live(cap) -> None:
    """Detiene y limpia la captura en vivo; un error al cerrar se registra, no tumba el cierre."""
    if cap is None:
        return
    try:
        if cap.running:
            cap.stop()
        cap.cleanup()
    except CaptureError:
        logger.warning("no se pudo cerrar limpiamente la captura en vivo", exc_info=True)


def _make_lifespan(state: _State):
    """Lifespan de la app: sin trabajo al arrancar, limpieza al cerrar."""
    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            _shutdown(state)
    return lifespan


def _mount_frontend(app: FastAPI, frontend_dir) -> None:
    """Sirve el frontend compilado."""
    if Path(frontend_dir).is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")


def create_app(
    rules_dir=ROOT / "rules",
    samples_dir=ROOT / "samples",
    frontend_dir=ROOT / "frontend" / "dist",
    source_factory: Optional[Callable[[str], PacketSource]] = None,
    interface_lister: Optional[Callable] = None,
    live_dir=None,
    allowed_hosts: Sequence[str] = LOCAL_HOSTS,
    sampler_factory: Optional[Callable[[], Optional[ProcessSampler]]] = make_default_sampler,
) -> FastAPI:
    """Fábrica de la app."""
    rules = load_rules(rules_dir)  # falla al arrancar si una regla está mal, no a mitad de uso
    state = _State()
    app = FastAPI(title="Tracewell", version=VERSION, lifespan=_make_lifespan(state))
    app.state.ctx = Ctx(
        state=state,
        rules=rules,
        samples_dir=Path(samples_dir),
        live_dir=Path(live_dir) if live_dir else None,
        make_source=source_factory or (lambda iface: ScapySource(iface)),
        interface_lister=interface_lister,
        # Se resuelve al llamar (no al crear)
        analyze=lambda path, rls: analyze(path, rls),
        make_sampler=sampler_factory,
        rules_dir=Path(rules_dir),
    )
    install_local_only(app, allowed_hosts)
    install_security_headers(app)  # al final: envuelve también los rechazos de Host/Origin
    register_error_handlers(app)
    app.include_router(routes_analysis.router)
    app.include_router(routes_live.router)
    app.include_router(routes_triage.router)
    app.include_router(routes_insights.router)
    app.include_router(routes_rules.router)
    app.include_router(routes_system.router)
    app.include_router(routes_support.router)
    _mount_frontend(app, frontend_dir)
    return app
