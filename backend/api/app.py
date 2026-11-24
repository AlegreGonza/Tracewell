"""API HTTP de Tracewell."""
from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional, Sequence

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.types import Scope

from backend.domain.analysis.analyzer import analyze
from backend.domain.pcap.dumpcap import make_source
from backend.domain.pcap.live import CaptureError, PacketSource
from backend.domain.pcap.processes import ProcessSampler, make_default_sampler
from backend.domain.files import FileGrants, resolve_allowed_dirs
from backend.domain.rules.engine import load_all_rules
from backend.domain.rules.paths import default_user_rules_dir
from backend.domain.support.monitor import monitor

from .routes import analysis as routes_analysis
from .routes import downloads as routes_downloads
from .routes import insights as routes_insights
from .routes import live as routes_live
from .routes import rules as routes_rules
from .routes import support as routes_support
from .routes import system as routes_system
from .routes import triage as routes_triage
from .errors import register_error_handlers
from .security import LOCAL_HOSTS, TicketStore, install_local_only, install_security_headers, make_token_check
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


def _is_spa_route(path: str) -> bool:
    """True si la ruta pide una pantalla del frontend: fuera de /api y sin extensión de archivo."""
    parts = path.replace("\\", "/").strip("/").split("/")  # en Windows llega con "\\"
    return parts[0] != "api" and "." not in parts[-1]


class SPAStaticFiles(StaticFiles):
    """StaticFiles que devuelve index.html para las rutas del lado del cliente (recarga)."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        """Sirve el archivo; si no existe y es una ruta de pantalla, sirve index.html."""
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or not _is_spa_route(path):
                raise
            return await super().get_response("index.html", scope)
        if response.status_code == 404 and _is_spa_route(path):
            return await super().get_response("index.html", scope)
        return response


def _mount_frontend(app: FastAPI, frontend_dir) -> None:
    """Sirve el frontend compilado (con fallback a index.html para rutas de la SPA)."""
    if Path(frontend_dir).is_dir():
        app.mount("/", SPAStaticFiles(directory=str(frontend_dir), html=True), name="frontend")


def create_app(
    rules_dir=ROOT / "rules",
    samples_dir=ROOT / "samples",
    frontend_dir=ROOT / "frontend" / "dist",
    source_factory: Optional[Callable[[str], PacketSource]] = None,
    interface_lister: Optional[Callable] = None,
    live_dir=None,
    allowed_hosts: Sequence[str] = LOCAL_HOSTS,
    sampler_factory: Optional[Callable[[], Optional[ProcessSampler]]] = make_default_sampler,
    api_token: Optional[str] = None,
    allowed_dirs: Optional[Sequence] = None,
    user_rules_dir=None,
    grants: Optional[FileGrants] = None,
) -> FastAPI:
    """Fábrica de la app; toda ruta de la API exige token (si no se pasa, se genera uno al azar)."""
    # Falla al arrancar si una regla está mal, no a mitad de uso.
    user_dir = Path(user_rules_dir) if user_rules_dir is not None else default_user_rules_dir()
    rules = load_all_rules(rules_dir, user_dir)
    state = _State()
    token = api_token if api_token is not None else secrets.token_urlsafe(32)
    check = make_token_check(token)
    # No se publica el mapa de la API (/docs, /redoc, /openapi.json).
    docs = {"docs_url": None, "redoc_url": None, "openapi_url": None}
    app = FastAPI(
        title="Tracewell", version=VERSION, lifespan=_make_lifespan(state),
        dependencies=[Depends(check)], **docs,
    )
    app.state.api_token = token
    app.state.token_generated = api_token is None
    app.state.tickets = TicketStore()
    app.state.ctx = Ctx(
        state=state,
        rules=rules,
        samples_dir=Path(samples_dir),
        live_dir=Path(live_dir) if live_dir else None,
        make_source=source_factory or make_source,
        interface_lister=interface_lister,
        # Se resuelve al llamar (no al crear)
        analyze=lambda path, rls: analyze(path, rls),
        make_sampler=sampler_factory,
        rules_dir=user_dir,
        allowed_dirs=resolve_allowed_dirs(
            allowed_dirs, extra=(Path(samples_dir), Path(live_dir) if live_dir else None)),
        grants=grants if grants is not None else FileGrants(),
    )
    install_local_only(app, allowed_hosts)
    install_security_headers(app)  # al final: envuelve también los rechazos de Host/Origin
    register_error_handlers(app)
    app.include_router(routes_analysis.router)
    app.include_router(routes_downloads.router)
    app.include_router(routes_live.router)
    app.include_router(routes_triage.router)
    app.include_router(routes_insights.router)
    app.include_router(routes_rules.router)
    app.include_router(routes_system.router)
    app.include_router(routes_support.router)
    _mount_frontend(app, frontend_dir)
    return app
