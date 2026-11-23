"""Rutas de captura en vivo: interfaces, iniciar, estado y detener."""
from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.domain.pcap.live import (
    DEFAULT_MAX_PACKETS,
    DEFAULT_MAX_SECONDS,
    CaptureStateError,
    LiveCapture,
    list_interfaces,
)
from backend.domain.pcap.processes import ProcessSampler

from backend.controllers.state import Ctx, CtxDep
from backend.controllers.live import (  # noqa: F401  (los tests parchean estos nombres desde la ruta)
    _finish_sampler,
    _release_previous,
    _start_or_cleanup,
    _stop_and_analyze,
)

logger = logging.getLogger("tracewell")

router = APIRouter(prefix="/api")

IDLE_STATUS = {"state": "idle", "packets": 0, "bytes": 0, "seconds": 0.0, "reason": None}


class LiveStartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=512)
    max_seconds: Optional[float] = Field(None, gt=0, le=3600)
    max_packets: Optional[int] = Field(None, gt=0, le=5_000_000)


def _make_capture(ctx: Ctx, req: LiveStartRequest) -> LiveCapture:
    """Arma (sin iniciar) la captura pedida, con límites por defecto."""
    return LiveCapture(
        ctx.make_source(req.interface),
        # Un nombre único por captura
        out_path=(Path(ctx.live_dir) / f"live-{uuid.uuid4().hex}.pcap") if ctx.live_dir else None,
        max_packets=req.max_packets or DEFAULT_MAX_PACKETS,
        max_seconds=req.max_seconds or DEFAULT_MAX_SECONDS,
    )


def _start_sampler(ctx: Ctx) -> Optional[ProcessSampler]:
    """Arranca el muestreador de procesos si hay uno disponible."""
    if ctx.make_sampler is None:
        return None
    try:
        sampler = ctx.make_sampler()
        if sampler is not None:
            sampler.start()
        return sampler
    except Exception:  # la captura no debe depender de esto
        logger.warning("no se pudo iniciar el muestreo de procesos", exc_info=True)
        return None


@router.get("/interfaces")
def interfaces(ctx: CtxDep):
    return [asdict(i) for i in list_interfaces(ctx.interface_lister)]


@router.post("/live/start")
def live_start(req: LiveStartRequest, ctx: CtxDep):
    state = ctx.state
    with state.lock:
        _release_previous(state)
        _finish_sampler(state)  # un muestreador que quedó de una captura anterior no debe
        cap = _make_capture(ctx, req)
        _start_or_cleanup(cap)
        state.live = cap
        state.live_result = None
        state.sampler = _start_sampler(ctx)
    return cap.status()


@router.get("/live/status")
def live_status(ctx: CtxDep):
    cap = ctx.state.live
    return cap.status() if cap is not None else dict(IDLE_STATUS)


@router.post("/live/stop")
def live_stop(ctx: CtxDep):
    state = ctx.state
    cap = state.live
    if cap is None:
        raise CaptureStateError("no hay una captura en vivo")
    with state.stop_lock:
        if state.live is not cap:
            raise CaptureStateError("la captura cambió mientras se detenía")
        # Idempotente de verdad
        if state.live_result is not None:
            return state.live_result
        return _stop_and_analyze(ctx, cap)
