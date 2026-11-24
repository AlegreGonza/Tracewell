"""Rutas de análisis: cargar una captura y consultarla (sesiones, alertas, paquetes, export)."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.domain.analysis.analyzer import MAX_PAGE, Analysis, packet_detail, packets_of_sessions, session_packets, session_stream
from backend.domain.export.json_export import build_report, to_json
from backend.domain.export.pcap_export import build_pcap
from backend.domain.files import ANALYZE_EXTENSIONS, require_allowed_file
from backend.domain.rules.engine import SEVERITIES
from backend.domain.sessions.query import compute_stats, filter_sessions

from backend.controllers.state import VERSION, CtxDep, clear_analysis, current, summary
from backend.controllers.analysis import (  # noqa: F401  (los tests parchean estos nombres desde la ruta)
    _add_processes,
    _add_triage,
    _alert_item,
    _analyze_path,
    _json_attachment,
    _process_of,
    _session_item,
)

router = APIRouter(prefix="/api")


class AnalyzeRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


class Filters:
    """Filtros opcionales protocol/ip/port, compartidos por sessions, stats y export."""

    def __init__(
        self,
        protocol: Optional[str] = None,
        ip: Optional[str] = None,
        port: Optional[int] = Query(None, ge=0, le=65535),
    ):
        self.protocol, self.ip, self.port = protocol, ip, port

    def given(self) -> dict:
        """Solo los filtros que el cliente mandó."""
        pairs = (("protocol", self.protocol), ("ip", self.ip), ("port", self.port))
        return {k: v for k, v in pairs if v is not None}

    def apply(self, a: Analysis):
        """Sesiones del análisis que cumplen los filtros."""
        return filter_sessions(a.result.sessions, protocol=self.protocol, ip=self.ip, port=self.port)


class Page:
    """Paginado limit/offset, compartido por sessions y packets."""

    def __init__(
        self,
        limit: int = Query(100, ge=1, le=MAX_PAGE),
        offset: int = Query(0, ge=0),
    ):
        self.limit, self.offset = limit, offset


FiltersDep = Annotated[Filters, Depends()]
PageDep = Annotated[Page, Depends()]


def _partial_stats(a: Analysis, filters: Filters) -> dict:
    """Estadísticas de lo filtrado, conservando los avisos de análisis parcial."""
    part = compute_stats(filters.apply(a))
    # Las cifras son de lo filtrado, pero "análisis parcial" es de la captura.
    part.truncated = a.result.truncated
    part.untracked_packets = a.result.untracked_packets
    return asdict(part)


@router.get("/health")
def health():
    return {"status": "ok", "version": VERSION}


@router.post("/analyze")
def analyze_file(req: AnalyzeRequest, ctx: CtxDep):
    path = require_allowed_file(req.path, ctx.allowed_dirs, "archivo .pcap/.pcapng", ANALYZE_EXTENSIONS)
    return _analyze_path(ctx, path)


@router.post("/demo")
def demo(ctx: CtxDep):
    path = Path(ctx.samples_dir) / "demo.pcap"
    if not path.is_file():
        raise HTTPException(404, "no se encontró samples/demo.pcap")
    return _analyze_path(ctx, path)


@router.get("/capture")
def capture(ctx: CtxDep):
    return summary(current(ctx), has_processes=ctx.state.processes is not None)


@router.delete("/capture")
def close_capture(ctx: CtxDep):
    """Descarta el análisis actual (volver a la pantalla de inicio)."""
    clear_analysis(ctx)
    return {"cleared": True}


@router.get("/timeline")
def timeline(ctx: CtxDep):
    """Paquetes y bytes por intervalo (para el gráfico). Vacío si la captura no tiene paquetes."""
    tl = current(ctx).timeline
    return asdict(tl) if tl is not None else {"start": 0.0, "bucket_seconds": 1.0, "packets": [], "bytes": []}


@router.get("/sessions")
def sessions(ctx: CtxDep, filters: FiltersDep, page: PageDep):
    a = current(ctx)
    found = filters.apply(a)
    chosen = found[page.offset:page.offset + page.limit]
    return {"total": len(found), "items": [_session_item(ctx, a, s) for s in chosen]}


@router.get("/stats")
def stats(ctx: CtxDep, filters: FiltersDep):
    a = current(ctx)
    # Sin filtros: estadísticas completas (incluye non_ip/malformed).
    if not filters.given():
        return asdict(compute_stats(a.result))
    return _partial_stats(a, filters)


@router.get("/alerts")
def alerts(ctx: CtxDep, severity: Optional[str] = None):
    a = current(ctx)
    if severity is not None and severity not in SEVERITIES:
        raise HTTPException(422, f"severity debe ser una de {list(SEVERITIES)}")
    return [_alert_item(x, a.rules) for x in a.alerts if severity is None or x.severity == severity]


@router.get("/sessions/{session_id}/packets")
def packets_of_session(session_id: int, ctx: CtxDep, page: PageDep):
    a = current(ctx)
    try:
        items, more = session_packets(a, session_id, page.offset, page.limit)
    except IndexError:
        raise HTTPException(404, "la sesión no existe") from None  # el IndexError interno no aporta al cliente
    return {"items": [asdict(p) for p in items], "has_more": more}


@router.get("/sessions/{session_id}/stream")
def stream_of_session(session_id: int, ctx: CtxDep):
    """Conversación reconstruida de una sesión TCP ("seguir la conversación")."""
    a = current(ctx)
    try:
        return asdict(session_stream(a, session_id))
    except IndexError:
        raise HTTPException(404, "la sesión no existe") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/packets/{index}")
def one_packet(index: int, ctx: CtxDep):
    a = current(ctx)
    try:
        return asdict(packet_detail(a, index))
    except IndexError:
        raise HTTPException(404, "el paquete no existe") from None


def _pcap_response(a: Analysis, sessions, filename: str) -> Response:
    """Descarga de un .pcap con los paquetes de `sessions`. 404 si no hay ninguno."""
    pcap = build_pcap(packets_of_sessions(a, sessions), linktype=a.info.linktype)
    if pcap.packets == 0:
        raise HTTPException(404, "no hay paquetes que exportar")
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if pcap.truncated:  # se avisa: el archivo está completo solo hasta el tope
        headers["X-Tracewell-Truncated"] = "true"
    return Response(content=pcap.data, media_type="application/vnd.tcpdump.pcap", headers=headers)


@router.get("/sessions/{session_id}/pcap")
def pcap_of_session(session_id: int, ctx: CtxDep):
    """Los paquetes de UNA sesión como un .pcap nuevo (para abrirlo en Wireshark o adjuntarlo a un ticket)."""
    a = current(ctx)
    if not 0 <= session_id < len(a.result.sessions):
        raise HTTPException(404, "la sesión no existe")
    return _pcap_response(a, [a.result.sessions[session_id]], f"tracewell-sesion-{session_id}.pcap")


@router.get("/pcap")
def pcap_filtered(ctx: CtxDep, filters: FiltersDep):
    """Los paquetes de TODAS las sesiones que cumplen los filtros (protocol, ip, port) como un .pcap."""
    a = current(ctx)
    return _pcap_response(a, filters.apply(a), "tracewell-filtrado.pcap")


@router.get("/export")
def export(
    ctx: CtxDep,
    filters: FiltersDep,
    # Por defecto el reporte NO lleva procesos
    processes: bool = Query(False, description="incluir el proceso de cada sesión (solo captura en vivo)"),
):
    a = current(ctx)
    given = filters.given()
    chosen = filters.apply(a) if given else None
    report = build_report(a.path, a.info, a.result, a.alerts, sessions=chosen, filters=given)
    if processes and ctx.state.processes is not None:
        _add_processes(ctx, a, report)
    return _json_attachment(to_json(report))
