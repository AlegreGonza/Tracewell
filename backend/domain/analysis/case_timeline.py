"""Cronología del caso: alertas, DNS sospechoso, sesiones marcadas e IOC, juntos y en orden de tiempo."""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Mapping, Optional

DEFAULT_LIMIT = 500
MAX_LIMIT = 2000
_NOTE_MAX = 200
_KIND_ORDER = {"alerta": 0, "ioc": 1, "dns": 2, "sesion": 3}


def normalize_host(host: Optional[str]) -> Optional[str]:
    """IP comparable (sin zona IPv6, comprimida) o None si no se pidió; ValueError si no es una IP."""
    if host is None or (isinstance(host, str) and not host.strip()):
        return None
    if not isinstance(host, str):
        raise ValueError("host debe ser una IP")
    try:
        return ipaddress.ip_address(host.strip().split("%", 1)[0]).compressed
    except ValueError:
        raise ValueError(f"host inválido: {host[:60]!r}") from None


def _norm(ip: Any) -> str:
    try:
        return ipaddress.ip_address(str(ip).split("%", 1)[0]).compressed
    except ValueError:
        return str(ip)


def _event(ts: float, kind: str, title: str, detail: str, ips: Iterable[str], **extra: Any) -> Dict[str, Any]:
    event = {"ts": ts, "kind": kind, "title": title, "detail": detail, "ips": sorted({_norm(i) for i in ips})}
    event.update(extra)
    return event


def _alert_events(alerts: Iterable[Any]) -> List[Dict[str, Any]]:
    return [
        _event(a.first_ts, "alerta", a.name, f"{a.src_ip} → {a.dst_ip} · {a.mitre_technique} ({a.mitre_tactic})",
               (a.src_ip, a.dst_ip), severity=a.severity, rule_id=a.rule_id)
        for a in alerts
    ]


def _dns_events(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Solo las consultas con pistas (nombre aleatorio, NXDOMAIN, TTL bajo...)."""
    out = []
    for r in rows:
        if not r.get("hints"):
            continue
        clients = list(r.get("clients") or [])
        out.append(_event(r["first_ts"], "dns", f"DNS sospechoso: {r['name']}", " ".join(r["hints"]), clients, qtype=r.get("qtype")))
    return out


def _session_flow(s: Any) -> str:
    return f"{s.protocol} {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}"


def _session_events(sessions: List[Any], notes: Mapping[int, Mapping[str, Any]], ioc_hits: Mapping[int, List[str]]) -> List[Dict[str, Any]]:
    out = []
    for sid, found in ioc_hits.items():
        if 0 <= sid < len(sessions):
            s = sessions[sid]
            out.append(_event(s.first_ts, "ioc", "Coincide con un IOC: " + ", ".join(found), _session_flow(s), (s.src_ip, s.dst_ip), session_id=sid))
    for sid, n in notes.items():
        text = str(n.get("note") or "").strip()[:_NOTE_MAX]
        if 0 <= sid < len(sessions) and (text or n.get("reviewed")):
            s = sessions[sid]
            title = "Sesión revisada" if n.get("reviewed") else "Sesión con nota"
            out.append(_event(s.first_ts, "sesion", title, " · ".join(p for p in (_session_flow(s), text) if p), (s.src_ip, s.dst_ip), session_id=sid))
    return out


def build_case_timeline(
    alerts: Iterable[Any] = (),
    dns_rows: Iterable[Mapping[str, Any]] = (),
    sessions: Optional[List[Any]] = None,
    notes: Optional[Mapping[int, Mapping[str, Any]]] = None,
    ioc_hits: Optional[Mapping[int, List[str]]] = None,
    host: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
) -> Dict[str, Any]:
    """Hechos del caso en orden cronológico."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit debe ser un entero entre 1 y {MAX_LIMIT}")
    wanted = normalize_host(host)
    events = _alert_events(alerts) + _dns_events(dns_rows) + _session_events(sessions or [], notes or {}, ioc_hits or {})
    if wanted is not None:
        events = [e for e in events if wanted in e["ips"]]
    events.sort(key=lambda e: (e["ts"], _KIND_ORDER[e["kind"]]))
    return {"host": wanted, "total": len(events), "truncated": len(events) > limit, "items": events[:limit]}
