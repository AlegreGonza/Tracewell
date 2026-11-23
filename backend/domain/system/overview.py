"""Resumen del equipo: memoria, procesador, disco, red acumulada, batería y tiempo encendido."""
from __future__ import annotations

import time
from functools import partial
from typing import Any, Dict, List

from .common import psutil_or_raise, safe


def overview() -> Dict[str, Any]:
    ps = psutil_or_raise()
    mem = ps.virtual_memory()
    swap = safe(ps.swap_memory)
    battery = safe(ps.sensors_battery)
    net = safe(ps.net_io_counters)
    boot = safe(ps.boot_time)
    disks: List[Dict[str, Any]] = []
    for part in safe(lambda: ps.disk_partitions(all=False), []) or []:
        usage = safe(partial(ps.disk_usage, part.mountpoint))
        if usage is not None:
            disks.append({"mount": part.mountpoint, "fstype": part.fstype, "total": usage.total, "used": usage.used, "percent": usage.percent})
    return {
        "cpu_percent": ps.cpu_percent(interval=0.2),
        "cpu_count": ps.cpu_count(logical=True),
        "cpu_physical": safe(lambda: ps.cpu_count(logical=False)),
        "memory": {"total": mem.total, "available": mem.available, "used": mem.total - mem.available, "percent": mem.percent},
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent} if swap else None,
        "disks": disks,
        "network_total": {"sent": net.bytes_sent, "received": net.bytes_recv} if net else None,
        "battery": {"percent": round(battery.percent, 1), "plugged": battery.power_plugged} if battery else None,
        "uptime_seconds": int(time.time() - boot) if boot else None,
        "process_count": len(ps.pids()),
    }
