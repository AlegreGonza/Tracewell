"""Rutas de "entender la captura": equipos y grafo, tabla de DNS, explicación de una sesión, HTTP y archivos.

Son vistas de LECTURA sobre el análisis actual; el cálculo vive en `core`.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.domain.analysis.analyzer import packets_of_sessions
from backend.domain.analysis.explain import explain_session
from backend.domain.analysis.hosts import build_graph
from backend.domain.analysis.http import http_body, http_exchanges
from backend.domain.analysis.http_scan import scan_http
from backend.domain.analysis.stream import raw_directions
from backend.domain.analysis.tls import analyze_tls, parse_client_hello
from backend.domain.analysis.wireshark_filter import ip_filter

from backend.controllers.analysis import _process_of
from backend.controllers.state import CtxDep, current
from backend.controllers.insights import (  # noqa: F401  (los tests parchean estos nombres desde la ruta)
    _case_timeline,
    _hosts,
    _remote_access,
    _session,
    _session_filter,
)

router = APIRouter(prefix="/api")


# ------------------------------------------------------------- equipos y grafo

@router.get("/hosts")
def hosts(ctx: CtxDep, limit: int = Query(50, ge=1, le=500)):
    _a, found = _hosts(ctx)
    return {"total": len(found), "items": [asdict(h) for h in found[:limit]]}


@router.get("/graph")
def graph(ctx: CtxDep, limit: int = Query(24, ge=2, le=60)):
    a, found = _hosts(ctx)
    return build_graph(a.result.sessions, found, limit)


# ------------------------------------------------------------- acceso remoto

@router.get("/remote-access")
def remote_access_overview(ctx: CtxDep, service: Optional[str] = Query(None, max_length=20)):
    """Sesiones de SSH, Telnet, SMB, RDP, WinRM y VNC agrupadas por servicio (filtro opcional `service`)."""
    return _remote_access(ctx, service)


# --------------------------------------------------------- cronología del caso

@router.get("/case-timeline")
def case_timeline(
    ctx: CtxDep,
    host: Optional[str] = Query(None, max_length=64),
    limit: int = Query(500, ge=1, le=2000),
):
    """Alertas, DNS sospechoso, sesiones marcadas e IOC en orden cronológico (opcional: solo los de una IP).
    Es una vista NUEVA: no reemplaza a `/api/timeline` (paquetes por intervalo)."""
    return _case_timeline(ctx, host, limit)


# ------------------------------------------------------------------------ DNS

@router.get("/dns")
def dns(ctx: CtxDep, q: Optional[str] = Query(None, max_length=253), limit: int = Query(100, ge=1, le=1000)):
    """Tabla de consultas y respuestas DNS (filtrable por texto en el nombre)."""
    log = current(ctx).names.dns_log
    return {"summary": log.summary(), "items": log.rows(q, limit)}


# --------------------------------------------------------- explicación didáctica

@router.get("/sessions/{session_id}/explain")
def explain(session_id: int, ctx: CtxDep):
    """La sesión contada en palabras simples, más los pasos de la conexión (como un Flow Graph)."""
    a, s = _session(ctx, session_id)
    process = _process_of(ctx, s) if ctx.state.processes is not None else None
    result = explain_session(s, packets_of_sessions(a, [s]), a.names, process)
    result["wireshark_filter"] = _session_filter(s)
    return result


@router.get("/wireshark-filter")
def wireshark_filter_of_ip(ip: str = Query(..., min_length=1, max_length=64)):
    """Filtro de visualización de Wireshark para una IP (`ip.addr==X`). No necesita una captura cargada."""
    try:
        return {"ip": ip, "wireshark_filter": ip_filter(ip)}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


# ------------------------------------------------------------------ HTTP y archivos

@router.get("/sessions/{session_id}/http")
def http_of_session(session_id: int, ctx: CtxDep):
    """Peticiones y respuestas HTTP (sin cifrar) de una sesión TCP. Vacío si no es HTTP en claro."""
    a, s = _session(ctx, session_id, tcp_only=True)
    raw = raw_directions(s, packets_of_sessions(a, [s]))
    return {"exchanges": http_exchanges(raw.origin, raw.destination), "incomplete": raw.has_gaps or raw.truncated}


@router.get("/sessions/{session_id}/http/{index}/body")
def http_file(session_id: int, index: int, ctx: CtxDep):
    """Descarga el cuerpo (archivo) de un intercambio HTTP como `.bin`. Son datos de la red: pueden ser malware."""
    a, s = _session(ctx, session_id, tcp_only=True)
    raw = raw_directions(s, packets_of_sessions(a, [s]))
    found = http_body(raw.origin, raw.destination, index)
    if found is None:
        raise HTTPException(404, "ese intercambio no tiene un archivo")
    body, name = found
    return Response(
        content=body, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}.bin"', "X-Content-Type-Options": "nosniff"},
    )


@router.get("/sessions/{session_id}/tls")
def tls_of_session(session_id: int, ctx: CtxDep):
    """Lo que se sabe de una sesión TLS sin descifrarla: huella JA4, versión y certificado (si va en claro)."""
    a, s = _session(ctx, session_id, tcp_only=True)
    raw = raw_directions(s, packets_of_sessions(a, [s]))
    client, server = raw.origin, raw.destination
    # El «origen» puede estar invertido (captura iniciada a mitad): el cliente es quien manda el ClientHello.
    if parse_client_hello(server) is not None and parse_client_hello(client) is None:
        client, server = server, client
    result = analyze_tls(client, server, when=s.first_ts)
    result["incomplete"] = raw.has_gaps or raw.truncated
    return result


@router.get("/http")
def http_overview(ctx: CtxDep):
    """Todas las peticiones HTTP de la captura (sesiones TCP a los puertos habituales de HTTP)."""
    return scan_http(current(ctx))
