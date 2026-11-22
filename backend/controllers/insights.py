"""Controlador de «insights»: la lógica que las rutas HTTP de `api/routes/insights.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones."""
from __future__ import annotations

from backend.controllers.state import Ctx, CtxDep, current
from backend.controllers.triage import _ioc_by_session
from backend.domain.analysis.case_timeline import build_case_timeline
from backend.domain.analysis.hosts import build_graph, build_hosts, build_mac_groups
from backend.domain.analysis.remote_access import UnknownService, remote_access
from backend.domain.analysis.wireshark_filter import session_filter
from fastapi import APIRouter, HTTPException, Query


def _hosts(ctx: Ctx):
    a = current(ctx)
    return a, build_hosts(a.result.sessions, a.names, a.alerts, ctx.state.iocs)


def _session(ctx: Ctx, session_id: int, tcp_only: bool = False):
    """(análisis, sesión) o 404; con `tcp_only`, 422 si no es TCP."""
    a = current(ctx)
    if not 0 <= session_id < len(a.result.sessions):
        raise HTTPException(404, "la sesión no existe")
    s = a.result.sessions[session_id]
    if tcp_only and s.protocol != "TCP":
        raise HTTPException(422, "solo las sesiones TCP tienen este análisis")
    return a, s


def _session_filter(s) -> str:
    """Filtro de Wireshark de una sesión (se arma con sus extremos y su protocolo)."""
    return session_filter(s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port)


def _remote_access(ctx: Ctx, service):
    """Acceso remoto del análisis actual, agrupado por servicio; 422 si el servicio pedido no existe."""
    a = current(ctx)
    try:
        return remote_access(a.result.sessions, service)
    except UnknownService as exc:
        raise HTTPException(422, str(exc)) from None


def _case_timeline(ctx: Ctx, host, limit: int):
    """Cronología unificada (alertas, DNS sospechoso, sesiones marcadas e IOC); 422 si `host` no es una IP."""
    a = current(ctx)
    try:
        return build_case_timeline(
            a.alerts, a.names.dns_log.rows(None, 1000), a.result.sessions,
            dict(ctx.state.notes), _ioc_by_session(ctx, a), host, limit,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


def _mac_groups(ctx: Ctx):
    """Equipos del análisis actual agrupados por MAC."""
    _a, found = _hosts(ctx)
    return build_mac_groups(found)
