"""Controlador de «analysis»"""
from __future__ import annotations

from backend.controllers.state import Ctx, _session_id, set_analysis
from backend.domain.analysis.analyzer import Analysis
from backend.domain.analysis.direction import session_direction
from backend.domain.analysis.wireshark_filter import alert_filter
from backend.domain.export.json_export import session_to_dict
from dataclasses import asdict
from fastapi.responses import Response
from pathlib import Path
from typing import Optional


def _analyze_path(ctx: Ctx, path: Path) -> dict:
    """Analiza un pcap con las reglas cargadas y lo deja como análisis actual."""
    return set_analysis(ctx, ctx.analyze(path, ctx.rules))


def _json_attachment(body: str) -> Response:
    """Respuesta JSON descargable como tracewell-report.json."""
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="tracewell-report.json"'},
    )


def _process_of(ctx: Ctx, s) -> Optional[dict]:
    """Proceso dueño de la sesión ({pid, name}) o None si no se pudo saber."""
    table = ctx.state.processes
    if table is None:
        return None
    found = table.lookup(s.protocol, s.src_ip, s.src_port, s.dst_ip, s.dst_port)
    return {"pid": found.pid, "name": found.name} if found is not None else None


def _session_item(ctx: Ctx, a: Analysis, s) -> dict:
    """Sesión serializada."""
    item = session_to_dict(_session_id(a, s), s)
    item["direction"] = session_direction(s)  # clave EXTRA de la API: el JSON exportado no la lleva
    if ctx.state.processes is not None:
        item["process"] = _process_of(ctx, s)
    host = a.names.best_name(s)  # nombre del sitio (SNI o DNS de la propia captura)
    if host:
        item["host"] = host
    _add_triage(ctx, a, s, item)
    return item


def _add_triage(ctx: Ctx, a: Analysis, s, item: dict) -> None:
    """Notas del analista y coincidencias de IOC: solo aparecen en las sesiones que las tienen."""
    note = ctx.state.notes.get(item["id"])
    if note:
        item["reviewed"], item["note"] = note["reviewed"], note["note"]
    ioc = ctx.state.iocs
    found = ioc.match_session(s, a.names.names_for(s)) if ioc is not None else []
    if found:
        item["ioc"] = found


def _add_processes(ctx: Ctx, a: Analysis, report: dict) -> None:
    """Agrega `process` a cada sesión del reporte (solo si el usuario lo pidió y hay datos)."""
    by_id = {_session_id(a, s): s for s in a.result.sessions}
    for item in report["sessions"]:
        item["process"] = _process_of(ctx, by_id[item["id"]])


def _rule_guide(rule) -> dict:
    """Campos explicativos de la regla (falsos positivos, pasos, filtro). Solo los que la regla define."""
    guide = {
        "false_positives": list(rule.false_positives),
        "investigation_steps": list(rule.investigation_steps),
        "wireshark_filter": rule.wireshark_filter,
    }
    return {k: v for k, v in guide.items() if v}


def _alert_item(alert, rules=()) -> dict:
    """Alerta serializada para la API."""
    item = asdict(alert)
    rule = next((r for r in rules if r.id == alert.rule_id), None)
    guide = _rule_guide(rule) if rule is not None else {}
    if guide:
        item["guide"] = guide
    try:
        item["wireshark_filter"] = alert_filter(alert.src_ip, alert.dst_ip, alert.evidence)
    except ValueError:
        pass
    return item
