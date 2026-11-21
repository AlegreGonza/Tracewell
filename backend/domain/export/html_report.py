"""Informe de triaje en HTML: una sola página autocontenida, lista para adjuntar a un ticket.

Todo lo que viene del tráfico o del analista se ESCAPA (`html.escape`): la
evidencia de una alerta puede ser hostil. Sin scripts ni recursos externos (una
política CSP lo refuerza). Del archivo solo va el NOMBRE, nunca la ruta.
"""
from __future__ import annotations

import html
import json
from typing import Any, Dict, Iterable, List, Optional

TOP_SESSIONS = 10  # además de las anotadas, con IOC o de las alertas, se listan las más pesadas

CSS = """
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;color:#121719;margin:2rem auto;max-width:60rem;padding:0 1rem}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.05rem;border-bottom:2px solid #00665c;padding-bottom:.25rem;margin-top:2rem}
.muted{color:#475358}table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #c1c9c5;padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:#ebeeeb}
code,pre{font-family:"Cascadia Mono",Consolas,monospace;font-size:.9em}pre{background:#eceeea;padding:.5rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
.sev{display:inline-block;padding:0 .4rem;border:1px solid;font-weight:600;font-size:.85em}
.sev-low{color:#1f5a8c}.sev-medium{color:#855400}.sev-high{color:#b23a05}.sev-critical{color:#a30f27}
.alert{border:1px solid #c1c9c5;border-left-width:4px;padding:.5rem .75rem;margin:.6rem 0;break-inside:avoid}
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


def _ioc_section(source: Optional[str], extras: Dict[int, Dict[str, Any]]) -> str:
    if source is None:
        return ""
    hits = sum(1 for e in extras.values() if e.get("ioc"))
    return f"<h2>Indicadores (IOC)</h2><p>Lista: <code>{_e(source)}</code> — sesiones con coincidencias: <strong>{hits}</strong>.</p>"


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
        f"{_summary(report)}{_alerts(report)}{_ioc_section(ioc_source, extras)}{_sessions(report, extras)}"
        '<p class="muted">Este informe puede contener datos sensibles de la red analizada: compartilo con cuidado.</p>'
    )
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>Informe de triaje — Tracewell</title><style>{CSS}</style></head><body>{body}</body></html>"
    )
