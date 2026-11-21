"""Controlador de «live»: la lógica que las rutas HTTP de `api/routes/live.py` delegan (sin FastAPI de por medio
cuando se puede). Las rutas solo traducen HTTP <-> estas funciones."""
from __future__ import annotations

from backend.controllers.state import Ctx, CtxDep, _State, set_analysis
from backend.domain.pcap.live import DEFAULT_MAX_PACKETS, DEFAULT_MAX_SECONDS, CaptureStateError, LiveCapture, list_interfaces
from backend.domain.pcap.processes import ProcessSampler, ProcessTable
from typing import Optional


def _release_previous(state: _State) -> None:
    """Rechaza si la captura anterior sigue corriendo; si no, libera su carpeta temporal."""
    previous = state.live
    if previous is None:
        return
    if previous.running:
        raise CaptureStateError("ya hay una captura en vivo en curso")
    # La captura anterior ya terminó: si dejó una carpeta temporal y el
    # análisis actual no depende de ella, se borra (si no, se acumulan).
    if previous.temp_dir != state.owned_dir:
        previous.cleanup()


def _start_or_cleanup(cap: LiveCapture) -> None:
    """Inicia la captura; si falla, no deja una carpeta temporal huérfana."""
    try:
        cap.start()  # puede lanzar PermissionDenied / CaptureError
    except BaseException:
        cap.cleanup()
        raise


def _finish_sampler(state: _State) -> Optional[ProcessTable]:
    """Detiene el muestreador y devuelve lo observado, o None si no hay datos
    (sin muestreador, o ninguna muestra salió bien: mejor no ofrecer una columna vacía)."""
    sampler, state.sampler = state.sampler, None
    if sampler is None:
        return None
    sampler.stop()
    return sampler.table if sampler.samples > 0 else None


def _stop_and_analyze(ctx: Ctx, cap: LiveCapture) -> dict:
    """Detiene la captura, analiza su pcap y arma (y guarda) la respuesta."""
    state = ctx.state
    done = cap.stop()  # si ya terminó por un límite, devuelve el resumen
    processes = _finish_sampler(state)
    analysis = set_analysis(ctx, ctx.analyze(done.path, ctx.rules), owned_dir=cap.temp_dir, processes=processes)
    state.live_result = {
        "capture": {"packets": done.packets, "bytes": done.bytes,
                    "seconds": done.seconds, "reason": done.reason,
                    "warning": done.warning},
        "analysis": analysis,
    }
    return state.live_result
