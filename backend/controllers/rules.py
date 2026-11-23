"""Controlador de «rules»: panel de reglas (vista previa, guardado y listado)."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException

from backend.controllers.state import Ctx
from backend.domain.pcap.reader import iter_packets
from backend.domain.rules import builder
from backend.domain.rules.builder import RuleForm


def list_rules(ctx: Ctx) -> Dict[str, Any]:
    return {"items": builder.summarize(ctx.rules), "example": builder.EXAMPLE}


def preview_rule(ctx: Ctx, form: RuleForm) -> Dict[str, Any]:
    """YAML en vivo y, si hay una captura abierta, cuántas sesiones y alertas daría la regla."""
    data = builder.to_dict(form)
    rule = builder.build_rule(data)  # RuleError -> 422 con el mensaje
    out: Dict[str, Any] = {
        "id": data["id"], "yaml": builder.render_yaml(data),
        "exists": data["id"] in {r.id for r in ctx.rules}, "matches": None,
    }
    a = ctx.state.analysis
    if a is not None:
        out["matches"] = builder.preview(rule, iter_packets(a.path), a.result.sessions, a.info.linktype)
    return out


def save_rule(ctx: Ctx, form: RuleForm) -> Dict[str, Any]:
    """Guarda la regla como YAML en rules/ y la suma a las reglas activas (valen desde la próxima captura)."""
    if ctx.rules_dir is None:
        raise HTTPException(503, "no hay carpeta de reglas configurada")
    data = builder.to_dict(form)
    rule = builder.build_rule(data)
    path = builder.save(ctx.rules_dir, data, (r.id for r in ctx.rules))
    ctx.rules.append(rule)
    return {"id": rule.id, "file": path.name, "yaml": builder.render_yaml(data)}
