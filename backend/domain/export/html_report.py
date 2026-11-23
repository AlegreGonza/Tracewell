"""Informe de triaje en HTML: una sola página autocontenida, lista para adjuntar a un ticket."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

TOP_SESSIONS = 10  # además de las anotadas, con IOC o de las alertas
TICKET_MAX_EVENTS = 40  # líneas de la línea de tiempo del ticket
TICKET_MAX_EVIDENCE = 5  # alertas con su evidencia en el ticket
_VALUE_MAX = 120  # largo máximo de un valor de evidencia dentro del ticket
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

CSS = """
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;color:#121719;margin:2rem auto;max-width:60rem;padding:0 1rem}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.05rem;border-bottom:2px solid #00665c;padding-bottom:.25rem;margin-top:2rem}
.muted{color:#475358}table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #c1c9c5;padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:#ebeeeb}
code,pre{font-family:"Cascadia Mono",Consolas,monospace;font-size:.9em}pre{background:#eceeea;padding:.5rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
.sev{display:inline-block;padding:0 .4rem;border:1px solid;font-weight:600;font-size:.85em}
.sev-low{color:#1f5a8c}.sev-medium{color:#855400}.sev-high{color:#b23a05}.sev-critical{color:#a30f27}
.alert{border:1px solid #c1c9c5;border-left-width:4px;padding:.5rem .75rem;margin:.6rem 0;break-inside:avoid}
.ticket{background:#f4f6f3;border:1px solid #c1c9c5;user-select:all}
.warn{background:#f1e5c3;color:#5b3a00;padding:.5rem .75rem;border-left:4px solid #855400}
@media print{body{margin:0}}
"""

SEVERITY = {"low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica"}


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _endpoint(ip: Any, port: Any) -> str:
    if port is None:
        return _e(ip)
    return f"[{_e(ip)}]:{_e(port)}" if ":" in str(ip) else f"{_e(ip)}:{_e(port)}"


def _summary(report: Dict[str, Any]) -> str:
    st, src = report["stats"], report["source"]
    partial = ""
    if st.get("truncated") or st.get("untracked_packets"):
        partial = '<p class="warn">Análisis parcial: la captura superó el límite de sesiones seguidas.</p>'
    rows = [
        ("Archivo", src.get("file")), ("Formato", src.get("format")),
        ("Sesiones", st.get("sessions")), ("Paquetes", st.get("packets")), ("Bytes", st.get("bytes")),
        ("Sin IP (ARP, etc.)", st.get("non_ip")), ("Dañados", st.get("malformed")),
    ]
    body = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in rows)
    return f"<h2>Resumen</h2>{partial}<table>{body}</table>"


def _alert_block(a: Dict[str, Any]) -> str:
    sev = _e(a.get("severity"))
    evidence = json.dumps(a.get("evidence", {}), indent=2, ensure_ascii=False, default=str)
    return (
        f'<div class="alert sev-{sev}"><span class="sev sev-{sev}">{_e(SEVERITY.get(str(a.get("severity")), a.get("severity")))}</span> '
        f'<strong>{_e(a.get("name"))}</strong> '
        f'<span class="muted">{_e(a.get("src_ip"))} → {_e(a.get("dst_ip"))}</span>'
        f'<p>{_e(a.get("description"))}</p>'
        f'<p><strong>MITRE ATT&amp;CK:</strong> {_e(a.get("mitre_technique"))} — {_e(a.get("mitre_name"))} ({_e(a.get("mitre_tactic"))})</p>'
        f"<pre>{_e(evidence)}</pre></div>"
    )


def _alerts(report: Dict[str, Any]) -> str:
    alerts = report.get("alerts", [])
    if not alerts:
        return "<h2>Alertas</h2><p class=\"muted\">No hay alertas.</p>"
    return "<h2>Alertas</h2>" + "".join(_alert_block(a) for a in alerts)


def _session_row(s: Dict[str, Any], extra: Dict[str, Any]) -> str:
    marks: List[str] = []
    if extra.get("reviewed"):
        marks.append("revisada")
    if extra.get("ioc"):
        marks.append("IOC: " + ", ".join(extra["ioc"]))
    process = extra.get("process")
    return (
        f"<tr><td>{_e(s['id'])}</td><td>{_e(s['protocol'])}</td>"
        f"<td><code>{_endpoint(s['src_ip'], s['src_port'])}</code></td>"
        f"<td><code>{_endpoint(s['dst_ip'], s['dst_port'])}</code></td>"
        f"<td>{_e(process['name']) if process else ''}</td>"
        f"<td>{_e(s['packets'])}</td><td>{_e(s['bytes'])}</td>"
        f"<td>{_e('; '.join(marks))}{('<br>' if marks and extra.get('note') else '')}{_e(extra.get('note', ''))}</td></tr>"
    )


def select_ids(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> set:
    """Ids de las sesiones que van al informe: las anotadas o con IOC (las de `extras`) y las más pesadas."""
    heavy = sorted(report.get("sessions", []), key=lambda s: s["bytes"], reverse=True)[:TOP_SESSIONS]
    return {s["id"] for s in heavy} | set(extras)


def _sessions(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> str:
    wanted = select_ids(report, extras)
    chosen = [s for s in report.get("sessions", []) if s["id"] in wanted]
    if not chosen:
        return ""
    rows = "".join(_session_row(s, extras.get(s["id"], {})) for s in chosen)
    head = "".join(f"<th>{h}</th>" for h in ("#", "Proto.", "Origen", "Destino", "Proceso", "Paq.", "Bytes", "Notas"))
    return (
        "<h2>Sesiones destacadas</h2>"
        '<p class="muted">Las anotadas por el analista, las que coinciden con algún IOC y las más pesadas.</p>'
        f"<table><tr>{head}</tr>{rows}</table>"
    )


def _ioc_hits(extras: Dict[int, Dict[str, Any]]) -> int:
    """Cuántas sesiones coinciden con algún IOC."""
    return sum(1 for e in extras.values() if e.get("ioc"))


def _ioc_section(source: Optional[str], extras: Dict[int, Dict[str, Any]]) -> str:
    if source is None:
        return ""
    hits = _ioc_hits(extras)
    return f"<h2>Indicadores (IOC)</h2><p>Lista: <code>{_e(source)}</code> — sesiones con coincidencias: <strong>{hits}</strong>.</p>"


# --------------------------------------------------------------- para el ticket
# Texto PLANO, listo para pegar en un ticket (sin tablas ni formato). Se arma como líneas de texto y se
# escapa UNA sola vez al final con `_e`; cada valor que viene del tráfico pasa antes por `_plain`, que
# colapsa saltos de línea para que un dato hostil no pueda fingir líneas nuevas dentro del ticket.

_CONTAINMENT = {
    "port_scan": "Limitar o bloquear el origen del escaneo en el firewall y revisar qué respondió (puertos abiertos).",
    "ftp_cleartext": "Cambiar la contraseña expuesta y pasar el servicio a SFTP/FTPS; asumir la credencial como comprometida.",
    "dns_suspicious": "Revisar el equipo que hizo la consulta (posible túnel DNS/DGA) y bloquear el dominio en el resolvedor.",
    "beaconing": "Aislar el equipo emisor, identificar el proceso que habla con el destino y bloquear el destino.",
    "syn_flood": "Aplicar límite de conexiones o SYN cookies en el destino y pedir mitigación al proveedor si persiste.",
    "suspicious_ports": "Verificar qué programa usa ese puerto; si no es esperado, aislar el equipo y bloquear el destino.",
    "dns_unusual_resolver": "Forzar el resolvedor corporativo y bloquear el DNS directo hacia servidores externos.",
    "large_upload": "Confirmar si la subida es legítima; si no, cortar la conexión y revisar qué datos salieron (posible exfiltración).",
}
_CONTAINMENT_BY_SEVERITY = {
    "critical": "Aislar de inmediato los equipos involucrados y escalar al responsable de incidentes.",
    "high": "Aislar los equipos involucrados mientras se investiga y escalar si se confirma.",
    "medium": "Investigar el equipo y el destino; contener solo si se confirma actividad maliciosa.",
    "low": "Monitorear; no hace falta contener salvo que aparezcan más señales.",
}


def _plain(value: Any, limit: int = _VALUE_MAX) -> str:
    """Una sola línea de texto: espacios y saltos colapsados, controles fuera y largo acotado."""
    text = " ".join("" if value is None else str(value).split())
    text = "".join(c for c in text if c.isprintable())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _utc(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "hora desconocida"


def _sev(a: Dict[str, Any]) -> str:
    return SEVERITY.get(str(a.get("severity")), _plain(a.get("severity")))


def _rank(a: Dict[str, Any]) -> int:
    return -_SEV_RANK.get(str(a.get("severity")), 0)


def _flow(s: Dict[str, Any]) -> str:
    return f"{_plain(s['protocol'])} {_plain(s['src_ip'])}:{_plain(s['src_port'])} -> {_plain(s['dst_ip'])}:{_plain(s['dst_port'])}"


def _ticket_summary(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> List[str]:
    st, alerts = report["stats"], report.get("alerts", [])
    lines = ["RESUMEN EJECUTIVO", f"Captura {_plain(report['source'].get('file'))}: {st.get('sessions')} sesiones, {st.get('packets')} paquetes."]
    if alerts:
        counts = {sev: sum(1 for a in alerts if a.get("severity") == sev) for sev in _SEV_RANK}
        order = sorted(counts.items(), key=lambda kv: -_SEV_RANK[kv[0]])
        lines.append(f"Alertas: {len(alerts)} ({', '.join(f'{n} {SEVERITY[sev]}' for sev, n in order if n)}).")
    else:
        lines.append("Sin alertas.")
    hits = _ioc_hits(extras)
    if hits:
        lines.append(f"Sesiones que coinciden con un IOC: {hits}.")
    if st.get("truncated") or st.get("untracked_packets"):
        lines.append("Atención: análisis parcial (la captura superó el límite de sesiones seguidas).")
    return lines


def _marks(extra: Dict[str, Any]) -> str:
    marks = []
    if extra.get("reviewed"):
        marks.append("revisada")
    if extra.get("ioc"):
        marks.append("IOC: " + ", ".join(_plain(i) for i in extra["ioc"]))
    if extra.get("note"):
        marks.append("nota: " + _plain(extra["note"]))
    return "; ".join(marks)


def _ticket_events(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> List[Tuple[float, str]]:
    events = [
        (a.get("first_ts") or 0.0, f"[ALERTA {_sev(a)}] {_plain(a.get('name'))}: {_plain(a.get('src_ip'))} -> {_plain(a.get('dst_ip'))}")
        for a in report.get("alerts", [])
    ]
    for s in report.get("sessions", []):
        extra = extras.get(s["id"])
        if extra and _marks(extra):
            events.append((s["first_ts"], f"[SESIÓN #{s['id']}] {_flow(s)} ({_marks(extra)})"))
    return sorted(events, key=lambda e: e[0])  # estable: a igual hora conserva el orden de aparición


def _ticket_timeline(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> List[str]:
    events = _ticket_events(report, extras)
    lines = ["LÍNEA DE TIEMPO (alertas y sesiones marcadas)"]
    if not events:
        return lines + ["Sin eventos."]
    lines += [f"{_utc(ts)}  {text}" for ts, text in events[:TICKET_MAX_EVENTS]]
    if len(events) > TICKET_MAX_EVENTS:
        lines.append(f"… y {len(events) - TICKET_MAX_EVENTS} evento(s) más (ver el informe completo).")
    return lines


def _ticket_iocs(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]], ioc_source: Optional[str]) -> List[str]:
    lines = ["IOC CONFIRMADOS"]
    if ioc_source is None:
        return lines + ["No se cargó una lista de IOC."]
    by_id = {s["id"]: s for s in report.get("sessions", [])}
    rows = [
        f"- {', '.join(_plain(i) for i in e['ioc'])} en la sesión #{sid} ({_flow(by_id[sid])})"
        for sid, e in sorted(extras.items()) if e.get("ioc") and sid in by_id
    ]
    return lines + (rows or ["Ninguna sesión coincide con la lista."])


def _evidence_text(evidence: Any) -> str:
    if not isinstance(evidence, dict) or not evidence:
        return "sin evidencia"
    return "; ".join(f"{_plain(k, 40)}={_plain(json.dumps(v, ensure_ascii=False, default=str))}" for k, v in evidence.items())


def _ticket_evidence(report: Dict[str, Any]) -> List[str]:
    top = sorted(report.get("alerts", []), key=_rank)[:TICKET_MAX_EVIDENCE]
    lines = ["EVIDENCIA CLAVE"]
    if not top:
        return lines + ["Sin alertas."]
    return lines + [
        f"- {_plain(a.get('name'))} ({_plain(a.get('src_ip'))} -> {_plain(a.get('dst_ip'))}): {_evidence_text(a.get('evidence'))}"
        for a in top
    ]


def _ticket_containment(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]]) -> List[str]:
    lines = ["RECOMENDACIÓN DE CONTENCIÓN (sugerencias: validarlas antes de actuar)"]
    seen: Dict[str, str] = {}
    for a in sorted(report.get("alerts", []), key=_rank):
        text = _CONTAINMENT.get(str(a.get("rule_id"))) or _CONTAINMENT_BY_SEVERITY.get(str(a.get("severity")), "Investigar el equipo involucrado.")
        seen.setdefault(str(a.get("rule_id")), f"- {_plain(a.get('name'))}: {text} Equipo: {_plain(a.get('src_ip'))}.")
    lines += list(seen.values())
    if _ioc_hits(extras):
        lines.append("- Hay sesiones con IOC: aislar los equipos de tu red que hablaron con esos indicadores.")
    return lines if len(lines) > 1 else lines + ["Sin alertas ni IOC: no hay acciones de contención sugeridas."]


def build_ticket_text(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]], ioc_source: Optional[str] = None) -> str:
    """Texto plano del bloque «Para el ticket»"""
    blocks = [
        _ticket_summary(report, extras), _ticket_timeline(report, extras),
        _ticket_iocs(report, extras, ioc_source), _ticket_evidence(report), _ticket_containment(report, extras),
    ]
    return "\n\n".join("\n".join(b) for b in blocks)


def _ticket(report: Dict[str, Any], extras: Dict[int, Dict[str, Any]], ioc_source: Optional[str]) -> str:
    return (
        "<h2>Para el ticket</h2>"
        '<p class="muted">Texto plano para pegar en el ticket: un clic selecciona todo, después copiá.</p>'
        f'<pre class="ticket">{_e(build_ticket_text(report, extras, ioc_source))}</pre>'
    )


def build_html(
    report: Dict[str, Any],
    extras: Optional[Dict[int, Dict[str, Any]]] = None,
    ioc_source: Optional[str] = None,
) -> str:
    """HTML del informe. `extras[id]` puede traer: note, reviewed, ioc (lista) y process ({name, pid})."""
    extras = extras or {}
    body = (
        f"<h1>Informe de triaje</h1>"
        f'<p class="muted">Generado por Tracewell el {_e(report.get("generated_at"))} (UTC)</p>'
        f"{_summary(report)}{_ticket(report, extras, ioc_source)}{_alerts(report)}{_ioc_section(ioc_source, extras)}{_sessions(report, extras)}"
        '<p class="muted">Este informe puede contener datos sensibles de la red analizada: compartilo con cuidado.</p>'
    )
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Informe de triaje — Tracewell</title><style>{CSS}</style></head><body>{body}</body></html>"
    )
