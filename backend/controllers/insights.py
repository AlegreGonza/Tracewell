"""Controlador de «insights»: la lógica que las rutas HTTP de `api/routes/insights.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones."""
from __future__ import annotations

from backend.controllers.state import Ctx, CtxDep, current
from backend.domain.analysis.hosts import build_graph, build_hosts
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
