"""Controlador de «triage»"""
from __future__ import annotations

from backend.controllers.state import Ctx, _session_id
from backend.domain.rules.iocs import IocSet
from typing import Dict, List


def _matched_ips(ioc: IocSet, sessions) -> set:
    """IP de las sesiones que coinciden con la lista."""
    ips = {ip for s in sessions for ip in (s.src_ip, s.dst_ip)}
    return {ip for ip in ips if ioc.match_ip(ip)}


def _ioc_by_session(ctx: Ctx, a) -> Dict[int, List[str]]:
    """{id de sesión: indicadores que coinciden} para todo el análisis."""
    ioc = ctx.state.iocs
    if ioc is None:
        return {}
    hit = _matched_ips(ioc, a.result.sessions)
    if not hit and not ioc.domains:
        return {}
    out: Dict[int, List[str]] = {}
    for s in a.result.sessions:
        # Los nombres solo se consultan si la lista trae dominios; las IP ya se filtraron arriba.
        names = a.names.names_for(s) if ioc.domains else []
        if s.src_ip in hit or s.dst_ip in hit or names:
            found = ioc.match_session(s, names)
            if found:
                out[_session_id(a, s)] = found
    return out


def _ioc_summary(ctx: Ctx) -> dict:
    state = ctx.state
    ioc = state.iocs
    if ioc is None:
        return {"loaded": False, "source": None, "ips": 0, "networks": 0, "domains": 0, "sessions": 0}
    a = state.analysis
    return {
        "loaded": True,
        "source": state.iocs_name,
        "ips": len(ioc.ips),
        "networks": len(ioc.networks),
        "domains": len(ioc.domains),
        "sessions": len(_ioc_by_session(ctx, a)) if a is not None else 0,
    }


def _report_extras(ctx: Ctx, a) -> Dict[int, dict]:
    """Datos del analista por sesión: notas, marca de revisada y coincidencias de IOC."""
    extras: Dict[int, dict] = {sid: dict(n) for sid, n in ctx.state.notes.items()}
    for sid, found in _ioc_by_session(ctx, a).items():
        extras.setdefault(sid, {})["ioc"] = found
    return extras
