"""Rutas del panel de reglas: listar, vista previa y guardar reglas nuevas por umbral."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.controllers import rules as controller
from backend.controllers.state import CtxDep
from backend.domain.rules.builder import RuleForm

router = APIRouter(prefix="/api")


class RuleRequest(BaseModel):
    name: str  # el largo y los caracteres los valida `builder.to_dict` (un solo límite y mensaje)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    description: str = Field("", max_length=2000)
    protocol: str = Field("any", max_length=10)
    src_ip: str = Field("", max_length=64)
    dst_ip: str = Field("", max_length=64)
    port: int = Field(0, ge=0, le=65535)
    min_events: int = Field(20, ge=2, le=1_000_000)
    window_seconds: float = Field(60.0, gt=0, le=1e9)
    id: str = Field("", max_length=64)
    mitre_technique: str = Field("", max_length=16)
    mitre_name: str = Field("", max_length=100)
    mitre_tactic: str = Field("", max_length=60)

    def form(self) -> RuleForm:
        return RuleForm(**self.model_dump())


@router.get("/rules")
def get_rules(ctx: CtxDep):
    return controller.list_rules(ctx)


@router.post("/rules/preview")
def post_preview(req: RuleRequest, ctx: CtxDep):
    return controller.preview_rule(ctx, req.form())


@router.post("/rules", status_code=201)
def post_rule(req: RuleRequest, ctx: CtxDep):
    return controller.save_rule(ctx, req.form())
