"""Rutas de «Soporte de red → Sistema»: procesos, puertos, conexiones, servicios y programas de inicio."""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.domain.system import autostart, net, overview, procs
from backend.domain.system.common import SystemUnavailable



def _no_store(response: Response) -> None:
    """Lo que se ve del sistema cambia a cada segundo."""
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/api/system", dependencies=[Depends(_no_store)])


def _read(fn: Callable[[], Any]) -> Any:
    """Ejecuta una lectura del sistema; si falta psutil responde 503 con un texto claro."""
    try:
        return fn()
    except SystemUnavailable as e:
        raise HTTPException(503, str(e)) from e


@router.get("/overview")
def system_overview():
    return _read(overview.overview)


@router.get("/processes")
def processes(sort: str = Query("ram", pattern="^(ram|cpu|name|pid)$"), limit: int = Query(300, ge=1, le=2000)):
    return _read(lambda: procs.list_processes(sort, limit))


@router.get("/processes/{pid}")
def process_detail(pid: int):
    detail = _read(lambda: procs.process_detail(pid))
    if not detail:
        raise HTTPException(404, "el proceso no existe (o ya terminó)")
    return detail


@router.get("/processes/{pid}/file")
def process_file(pid: int):
    return _read(lambda: procs.file_info(pid))


@router.get("/ports")
def ports():
    return _read(net.listening_ports)


@router.get("/connections")
def connections():
    return _read(net.connections)


@router.get("/services")
def services():
    return _read(autostart.services)


@router.get("/startup")
def startup():
    return _read(autostart.startup_items)
