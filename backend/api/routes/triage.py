"""Rutas de triaje: notas por sesión, lista de IOC e informe HTML."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.domain.export.html_report import build_html, select_ids
from backend.domain.export.json_export import build_report
from backend.domain.files import require_regular_file
from backend.domain.rules.iocs import load_iocs

from backend.controllers.analysis import _process_of
from backend.controllers.state import CtxDep, _session_id, current
from backend.controllers.triage import (  # noqa: F401  (los tests parchean estos nombres desde la ruta)
    _ioc_by_session,
    _ioc_summary,
    _matched_ips,
    _report_extras,
)

router = APIRouter(prefix="/api")

MAX_NOTES = 5000


class NoteRequest(BaseModel):
    note: str = Field("", max_length=2000)
    reviewed: bool = False


class IocRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


# ---------------------------------------------------------------------- notas

@router.put("/sessions/{session_id}/note")
def put_note(session_id: int, req: NoteRequest, ctx: CtxDep):
    """Guarda (o borra, si no hay nota ni marca) la nota de una sesión del análisis actual."""
    a = current(ctx)
    if not 0 <= session_id < len(a.result.sessions):
        raise HTTPException(404, "la sesión no existe")
    text = req.note.strip()
    state = ctx.state
    with state.lock:
        if not text and not req.reviewed:
            state.notes.pop(session_id, None)
        elif session_id in state.notes or len(state.notes) < MAX_NOTES:
            state.notes[session_id] = {"note": text, "reviewed": req.reviewed}
        else:
            raise HTTPException(409, f"demasiadas notas (máximo {MAX_NOTES})")
    return {"id": session_id, "note": text, "reviewed": req.reviewed}


# ------------------------------------------------------------------------ IOC


@router.get("/iocs")
def iocs_status(ctx: CtxDep):
    return _ioc_summary(ctx)


@router.post("/iocs")
def iocs_load(req: IocRequest, ctx: CtxDep):
    path = require_regular_file(req.path, "archivo de texto")
    ioc = load_iocs(path)  # IocError -> 422
    with ctx.state.lock:
        ctx.state.iocs, ctx.state.iocs_name = ioc, path.name  # solo el nombre: la ruta es del usuario
    return _ioc_summary(ctx)


@router.delete("/iocs")
def iocs_clear(ctx: CtxDep):
    with ctx.state.lock:
        ctx.state.iocs, ctx.state.iocs_name = None, None
    return _ioc_summary(ctx)


# -------------------------------------------------------------------- informe


@router.get("/report")
def report(
    ctx: CtxDep,
    # Igual que en el JSON: los procesos no salen por defecto, porque el informe se comparte.
    processes: bool = Query(False, description="incluir el proceso de las sesiones destacadas (solo captura en vivo)"),
):
    a = current(ctx)
    rep = build_report(a.path, a.info, a.result, a.alerts)
    extras = _report_extras(ctx, a)
    if processes and ctx.state.processes is not None:
        by_id = {_session_id(a, s): s for s in a.result.sessions}
        for sid in select_ids(rep, extras):
            extras.setdefault(sid, {})["process"] = _process_of(ctx, by_id[sid])
    body = build_html(rep, extras, ioc_source=ctx.state.iocs_name)
    return Response(
        content=body,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="tracewell-informe.html"'},
    )
