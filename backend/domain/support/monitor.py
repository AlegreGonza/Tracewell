"""Monitoreo continuo: detecta cortes intermitentes (el Wi-Fi o Internet que «va y viene») y arma su cronología.

Un hilo de fondo mide cada pocos segundos tres cosas: el router (ping), Internet (conexión TCP a 1.1.1.1:443) y el
DNS (resolver un nombre conocido). Cuando algo deja de responder abre un «corte» con la capa que falló, y lo cierra
cuando vuelve todo. Solo corre mientras Tracewell está abierto, y todo queda en memoria (no escribe archivos).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Deque, Dict, List, Optional

from .checks import DNS_PROBES, INTERNET_PROBES, ping, resolve, tcp_connect
from .netinfo import default_gateway
from .wifi import wifi_status

MIN_INTERVAL, MAX_INTERVAL = 1.0, 30.0
FAILS_TO_OPEN = 2  # fallos seguidos para abrir un corte: un solo tropiezo no cuenta
MAX_OUTAGES = 200
MAX_SAMPLES = 180
LAYER_ORDER = {"red local": 3, "internet": 2, "dns": 1}  # cuál es la capa más grave si varias fallan


def _layer(router: Optional[bool], internet: bool, dns: bool) -> Optional[str]:
    """La capa que falla, de abajo hacia arriba. None si todo anda."""
    if router is False:
        return "red local"
    if not internet:
        return "internet"
    if not dns:
        return "dns"
    return None


class Monitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._reset(1.0)

    def _reset(self, interval: float) -> None:
        self.interval = interval
        self.started_at: Optional[float] = None
        self.samples: Deque[Dict[str, Any]] = deque(maxlen=MAX_SAMPLES)
        self.outages: List[Dict[str, Any]] = []
        self.total = 0
        self.ok_count = 0
        self.gateway: Optional[str] = None
        self.wifi: Optional[Dict[str, Any]] = None
        self._fails = 0
        self._open: Optional[Dict[str, Any]] = None
        self._pending: Optional[Dict[str, Any]] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, interval: float = 2.0) -> None:
        with self._lock:
            if self.running:
                return
            self._reset(max(MIN_INTERVAL, min(float(interval), MAX_INTERVAL)))
            self.started_at = time.time()
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="tracewell-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        th = self._thread
        if th is not None and th is not threading.current_thread():
            th.join(5.0)
        with self._lock:
            self._close_open(time.time())  # un corte en curso se cierra al parar

    def clear(self) -> None:
        with self._lock:
            keep = self.interval
            was_running = self.running
            self._reset(keep)
            if was_running:
                self.started_at = time.time()

    # ------------------------------------------------------------------ hilo

    def _run(self) -> None:
        pool = ThreadPoolExecutor(max_workers=3)
        n = 0
        try:
            while not self._stop.is_set():
                if n % 30 == 0:
                    self.gateway = default_gateway()
                if n % 5 == 0:
                    try:
                        w = wifi_status()
                        self.wifi = {"signal": w.get("signal"), "ssid": w.get("ssid")} if w.get("available") else None
                    except Exception:  # noqa: BLE001 - el Wi-Fi es un dato extra: si falla, se sigue sin él
                        self.wifi = None
                self._sample(pool)
                n += 1
                self._stop.wait(self.interval)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _sample(self, pool: ThreadPoolExecutor) -> None:
        gw = self.gateway
        f_router = pool.submit(lambda: ping(gw, 1).get("received", 0) > 0) if gw else None
        f_net = pool.submit(lambda: [tcp_connect(h, p, 2.0) for h, p in INTERNET_PROBES[:1]][0])
        f_dns = pool.submit(lambda: any(resolve(n, 2.0)["ok"] for n in DNS_PROBES[:2]))
        router = bool(f_router.result()) if f_router else None
        net = f_net.result()
        dns = bool(f_dns.result())
        layer = _layer(router, bool(net["ok"]), dns)
        now = time.time()
        with self._lock:
            self.total += 1
            if layer is None:
                self.ok_count += 1
            self.samples.append({"t": now, "ms": net["ms"], "router": router, "internet": bool(net["ok"]), "dns": dns, "layer": layer})
            self._track(layer, now)

    def _track(self, layer: Optional[str], now: float) -> None:
        """Abre un corte tras `FAILS_TO_OPEN` fallos seguidos (contando desde el primero) y lo cierra al volver todo."""
        if layer is not None:
            self._fails += 1
            if self._pending is None:
                self._pending = {"start": now, "layer": layer, "samples": 0, "signal": (self.wifi or {}).get("signal")}
            self._pending["samples"] += 1
            if LAYER_ORDER.get(layer, 0) > LAYER_ORDER.get(self._pending["layer"], 0):
                self._pending["layer"] = layer
            if self._open is None and self._fails >= FAILS_TO_OPEN:
                self._open = self._pending
                self.outages.append(self._open)
                del self.outages[:-MAX_OUTAGES]
        else:
            self._fails = 0
            self._pending = None
            self._close_open(now)

    def _close_open(self, now: float) -> None:
        if self._open is not None:
            self._open["end"] = now
            self._open = None
        self._pending = None

    # ------------------------------------------------------------------ lectura

    def status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            last = self.samples[-1] if self.samples else None
            outages = [
                {**o, "duration": round((o.get("end") or now) - o["start"], 1), "ongoing": "end" not in o}
                for o in self.outages
            ]
            ms = [s["ms"] for s in self.samples if s["ms"] is not None]
            return {
                "running": self.running, "interval": self.interval, "started_at": self.started_at,
                "total": self.total, "availability_pct": round(100 * self.ok_count / self.total, 2) if self.total else None,
                "current": ("sin datos" if last is None else "ok" if last["layer"] is None else last["layer"]),
                "gateway": self.gateway, "wifi": self.wifi,
                "latency": {"last": last["ms"] if last else None, "avg": round(sum(ms) / len(ms), 1) if ms else None, "max": max(ms) if ms else None},
                "samples": [{"t": s["t"], "ms": s["ms"], "layer": s["layer"]} for s in self.samples],
                "outages": list(reversed(outages)),
                "outage_count": len(outages), "downtime_seconds": round(sum(o["duration"] for o in outages), 1),
            }


monitor = Monitor()  # uno por proceso: la API lo arranca, lo para y lo consulta
