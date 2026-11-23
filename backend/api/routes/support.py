"""Rutas de «Soporte de red → Red»: pruebas y consultas de red de SOLO LECTURA."""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.domain.support import checks, devices, dupip, netinfo, wifi
from backend.domain.support.monitor import monitor
from backend.domain.system.common import SystemUnavailable


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/api/support", dependencies=[Depends(_no_store)])


def _call(fn: Callable[[], Any]) -> Any:
    """Corre una herramienta: un dato inválido es 422 con el motivo; si falta psutil, 503."""
    try:
        return fn()
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    except SystemUnavailable as e:
        raise HTTPException(503, str(e)) from e


@router.get("/config")
def config():
    return _call(lambda: netinfo.network_config(fresh=True))


@router.get("/config/raw")
def config_raw():
    return _call(netinfo.raw_config)


@router.get("/internet")
def internet():
    return _call(checks.internet_check)


@router.get("/latency")
def latency(host: str = "1.1.1.1", port: int = Query(443, ge=1, le=65535), samples: int = Query(8, ge=3, le=30)):
    return _call(lambda: checks.latency_test(host, port, samples))


@router.get("/ping")
def ping(host: str, count: int = Query(4, ge=1, le=20)):
    return _call(lambda: checks.ping(host, count))


@router.get("/traceroute")
def traceroute(host: str, max_hops: int = Query(20, ge=1, le=30)):
    return _call(lambda: checks.traceroute(host, max_hops))


@router.get("/ports")
def ports(host: str, ports: str = Query(..., max_length=200)):
    def work() -> Any:
        try:
            numbers = [int(p) for p in ports.replace(" ", "").split(",") if p]
        except ValueError as e:
            raise ValueError("los puertos van separados por coma, por ejemplo 22,80,443") from e
        return checks.port_check(host, numbers)

    return _call(work)


@router.get("/rdp")
def rdp(host: str, port: int = Query(3389, ge=1, le=65535)):
    return _call(lambda: checks.rdp_check(host, port))


@router.get("/time")
def time_offset(server: str = "time.windows.com"):
    return _call(lambda: checks.time_offset(server))


@router.get("/devices")
def list_devices(scan: bool = False):
    return _call(lambda: devices.list_devices(scan))


@router.get("/wifi")
def wifi_status():
    return _call(wifi.wifi_status)


@router.get("/wifi/history")
def wifi_history(limit: int = Query(100, ge=1, le=300)):
    return _call(lambda: wifi.wifi_history(limit))


@router.get("/duplicate-ip")
def duplicate_ip(probe: bool = True):
    return _call(lambda: dupip.check_duplicate_ip(probe))


# ---- monitoreo de cortes (el único con estado: un hilo de medición en memoria)

@router.get("/monitor")
def monitor_status():
    return monitor.status()


@router.post("/monitor/start")
def monitor_start(interval: float = Query(2.0, ge=1.0, le=30.0)):
    monitor.start(interval)
    return monitor.status()


@router.post("/monitor/stop")
def monitor_stop():
    monitor.stop()
    return monitor.status()


@router.post("/monitor/clear")
def monitor_clear():
    monitor.clear()
    return monitor.status()
