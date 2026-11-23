"""Captura en vivo desde una interfaz de red."""
from __future__ import annotations

import logging
import math
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, List, Optional, Protocol

import dpkt

logger = logging.getLogger("tracewell")  # sin handlers acá: los configura main/api

ETHERNET = 1
# Límites por defecto: una captura olvidada no debe llenar el disco ni correr para siempre
DEFAULT_MAX_PACKETS = 1_000_000
DEFAULT_MAX_SECONDS = 600.0
DEFAULT_MAX_BYTES = 200 * 1024 * 1024
# Las carpetas temporales de captura empiezan con este prefijo
TEMP_PREFIX = "tracewell_"
STALE_AFTER = 24 * 3600.0
# Cuánto esperamos a que la fuente se detenga antes de cerrar el archivo igual.
STOP_TIMEOUT = 10.0
START_TIMEOUT = 5.0  # segundos que se espera a que Scapy abra el socket de captura


class CaptureError(RuntimeError):
    """No se pudo listar interfaces o capturar (permisos, driver, estado)."""


class CaptureStateError(CaptureError):
    """Uso incorrecto del ciclo de vida (iniciar dos veces, detener sin iniciar)."""


class PermissionDenied(CaptureError):
    """Falta de privilegios: la captura requiere administrador/root (Npcap en Windows)."""


@dataclass(frozen=True)
class InterfaceInfo:
    name: str  # identificador que se usa para capturar
    description: str  # texto legible para mostrar al usuario


class PacketSource(Protocol):
    """Contrato mínimo de una fuente de paquetes."""

    def start(self, on_packet: Callable[[float, bytes], None]) -> None:
        """Empieza a entregar (timestamp, bytes) a `on_packet`, desde otro hilo."""

    def stop(self) -> None:
        """Deja de capturar y espera a que termine su hilo."""


# ------------------------------------------------------------ fuente real

def _import_scapy():
    try:
        import scapy.all as scapy  # import perezoso: es pesado
    except ImportError as exc:
        raise CaptureError(
            "Scapy no está instalado. Instalalo con `pip install scapy` "
            "(en Windows también hace falta Npcap)."
        ) from exc
    return scapy


def list_interfaces(lister: Optional[Callable[[], List[InterfaceInfo]]] = None) -> List[InterfaceInfo]:
    """Interfaces disponibles. `lister` permite inyectar una lista simulada."""
    return (lister or _scapy_list_interfaces)()


def _scapy_list_interfaces() -> List[InterfaceInfo]:
    scapy = _import_scapy()
    try:
        ifaces = list(scapy.conf.ifaces.values())
    except Exception as exc:  # Scapy puede fallar de formas muy distintas según el SO
        raise CaptureError(f"no se pudieron listar las interfaces: {exc}") from exc
    infos = [InterfaceInfo(str(i.name), str(getattr(i, "description", "") or i.name)) for i in ifaces]
    return sorted(infos, key=_is_virtual)  # sorted es estable: las reales quedan primero, en su orden


# Fragmentos que delatan adaptadores virtuales o sin tráfico útil para triaje.
_VIRTUAL_HINTS = (
    "miniport", "loopback", "virtual", "vmware", "vbox", "hyper-v", "vethernet",
    "docker", "bluetooth", "pseudo", "tunnel", "isatap", "teredo",
)
_VIRTUAL_PREFIXES = ("docker0", "veth", "br-", "virbr", "tun", "tap")


def _is_virtual(info: InterfaceInfo) -> bool:
    """True si la interfaz parece virtual/loopback; sirve para no preseleccionarla."""
    text = f"{info.name} {info.description}".lower()
    name = info.name.lower()
    return any(h in text for h in _VIRTUAL_HINTS) or name == "lo" or name.startswith(_VIRTUAL_PREFIXES)


class ScapySource:
    """Fuente real basada en Scapy."""

    def __init__(self, interface: str, bpf_filter: Optional[str] = None):
        if not isinstance(interface, str) or not interface.strip():
            raise CaptureError("hay que indicar una interfaz")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._sniffer: Any = None  # scapy.AsyncSniffer (import perezoso, sin tipos)
        self.non_ethernet_dropped = 0

    def start(self, on_packet):
        scapy = _import_scapy()

        def handle(pkt):
            # Escribimos el pcap como Ethernet (linktype 1)
            if pkt.__class__.__name__ != "Ether":
                self.non_ethernet_dropped += 1
                return
            on_packet(float(pkt.time), bytes(pkt))

        ready = threading.Event()  # Scapy lo dispara cuando YA abrió el socket de captura
        try:
            self._sniffer = scapy.AsyncSniffer(
                iface=self.interface, prn=handle, store=False, filter=self.bpf_filter,
                started_callback=ready.set,
            )
            self._sniffer.start()
            self._wait_started(ready)
        except Exception as exc:
            raise self._start_error(exc) from exc

    def _wait_started(self, ready: threading.Event, timeout: float = START_TIMEOUT) -> None:
        """Espera a que el hilo de Scapy abra el socket; si murió antes, relanza su error."""
        deadline = time.monotonic() + timeout
        while not ready.wait(0.05):
            if self._sniffer.exception is not None:
                raise self._sniffer.exception
            thread = self._sniffer.thread
            if (thread is not None and not thread.is_alive()) or time.monotonic() >= deadline:
                break  # sin error visible: seguimos; stop() informará si algo falló
        if self._sniffer.exception is not None:
            raise self._sniffer.exception

    def _start_error(self, exc: Exception) -> CaptureError:
        """Traduce el error de arranque a uno propio, con un mensaje accionable."""
        if isinstance(exc, PermissionError):
            return PermissionDenied(
                "permiso denegado: ejecutá Tracewell como administrador (Windows) o root (Linux)"
            )
        return CaptureError(f"no se pudo iniciar la captura en {self.interface!r}: {exc}")

    def stop(self):
        if self._sniffer is not None and getattr(self._sniffer, "running", False):
            try:
                self._sniffer.stop()
            except Exception:  # detener nunca debe tumbar el cierre del archivo
                logger.warning("falló al detener el sniffer de Scapy", exc_info=True)


# -------------------------------------------------------- gestor de captura

@dataclass(frozen=True)
class CaptureSummary:
    path: Path
    packets: int
    bytes: int
    seconds: float
    reason: str  # "manual", "max_packets", "max_seconds", "max_bytes", "error"
    # Algo salió mal sin impedir cerrar el archivo
    warning: Optional[str] = None


def _is_finite_number(v) -> bool:
    """Número real y finito (ni bool, ni NaN, ni infinito)."""
    # isfinite: NaN no es <= 0 ni < 0 (toda comparación con NaN da False)
    return not isinstance(v, bool) and isinstance(v, (int, float)) and math.isfinite(v)


def _check_limit(name: str, v) -> None:
    """Falla si el límite no es un número positivo y finito."""
    if not _is_finite_number(v) or v <= 0:
        raise ValueError(f"{name} debe ser un número positivo y finito, recibí {v!r}")


def _resolve_out_path(out_path):
    """(ruta del pcap, carpeta temporal propia o None)."""
    # Si no nos dan ruta, creamos una carpeta temporal PROPIA
    if out_path:
        return Path(out_path), None
    temp_dir = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    return temp_dir / "live.pcap", temp_dir


def _is_stale_capture_dir(entry: os.DirEntry, cutoff: float) -> bool:
    """True si es una carpeta de captura NUESTRA, vieja y con solo el pcap adentro."""
    if not entry.name.startswith(TEMP_PREFIX) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
        return False
    if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
        return False
    return all(child == "live.pcap" for child in os.listdir(entry.path))


def _remove_if_stale(entry: os.DirEntry, cutoff: float) -> bool:
    """Borra la carpeta si es un resto viejo; un fallo al borrar se registra y se sigue."""
    try:
        if not _is_stale_capture_dir(entry, cutoff):
            return False
        shutil.rmtree(entry.path)
        return True
    except OSError:
        logger.debug("no se pudo limpiar %s", entry.path, exc_info=True)
        return False


def cleanup_stale_temp_dirs(max_age: float = STALE_AFTER, temp_root=None) -> List[Path]:
    """Borra las carpetas temporales de capturas que quedaron por un cierre abrupto."""
    # Con NaN todo contaba como "viejo" (borraba también las carpetas recientes)
    if not _is_finite_number(max_age) or max_age < 0:
        raise ValueError(f"max_age debe ser un número finito >= 0, recibí {max_age!r}")
    root = Path(temp_root) if temp_root else Path(tempfile.gettempdir())
    cutoff = time.time() - max_age
    try:
        entries = list(os.scandir(root))
    except OSError:
        return []
    return [Path(e.path) for e in entries if _remove_if_stale(e, cutoff)]


class LiveCapture:
    """Captura de una fuente a un archivo .pcap, con límites y detención segura."""

    def __init__(
        self,
        source: PacketSource,
        out_path=None,
        *,
        max_packets: int = DEFAULT_MAX_PACKETS,
        max_seconds: float = DEFAULT_MAX_SECONDS,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        for name, v in (("max_packets", max_packets), ("max_seconds", max_seconds), ("max_bytes", max_bytes)):
            _check_limit(name, v)
        self._source = source
        self._max_packets, self._max_seconds, self._max_bytes = max_packets, max_seconds, max_bytes
        self.path, self.temp_dir = _resolve_out_path(out_path)
        self._init_state()

    def _init_state(self) -> None:
        """Estado mutable inicial: sincronización, contadores y archivo sin abrir."""
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._finished = threading.Event()
        self._reason = "manual"
        self._packets = 0
        self._bytes = 0
        self._started_at: Optional[float] = None
        self._elapsed = 0.0
        self._fh: Optional[BinaryIO] = None
        self._writer: Any = None  # dpkt.pcap.Writer (dpkt no trae tipos)
        self._monitor: Optional[threading.Thread] = None
        self._summary: Optional[CaptureSummary] = None
        self.error: Optional[BaseException] = None

    # -- ciclo de vida
    def start(self) -> None:
        if self._started_at is not None:
            raise CaptureStateError("la captura ya fue iniciada")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "wb")
        self._writer = dpkt.pcap.Writer(self._fh, snaplen=65535, linktype=ETHERNET)
        self._started_at = time.monotonic()
        try:
            self._source.start(self._on_packet)
        except BaseException:
            self._close_file()
            self._started_at = None
            raise
        self._monitor = threading.Thread(target=self._watch, name="tracewell-live", daemon=True)
        self._monitor.start()

    def stop(self) -> CaptureSummary:
        """Detiene la captura (idempotente) y devuelve el resumen."""
        if self._started_at is None:
            raise CaptureStateError("la captura no fue iniciada")
        self._done.set()  # razón "manual" si nadie la fijó antes
        self._finished.wait()
        assert self._summary is not None
        return self._summary

    @property
    def running(self) -> bool:
        return self._started_at is not None and not self._finished.is_set()

    def cleanup(self) -> None:
        """Borra la carpeta temporal que creó esta captura (si la creó ella)."""
        if self.running:
            raise CaptureStateError("no se puede limpiar una captura en curso")
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _state_name(self) -> str:
        """Estado del ciclo de vida: idle, running o finished."""
        if self._started_at is None:
            return "idle"
        return "running" if self.running else "finished"

    def _elapsed_now(self) -> float:
        """Segundos transcurridos: congelados si ya terminó."""
        if self._finished.is_set():
            return self._elapsed
        return time.monotonic() - self._started_at if self._started_at is not None else 0.0

    def _warning(self) -> Optional[str]:
        """Texto del error que no impidió cerrar el archivo, o None."""
        return str(self.error) if self.error is not None else None

    def status(self) -> dict:
        with self._lock:
            return {
                "state": self._state_name(),
                "packets": self._packets, "bytes": self._bytes,
                "seconds": round(self._elapsed_now(), 3),
                "reason": self._reason if self._done.is_set() else None,
                "warning": self._warning(),
            }

    # -- internos
    def _write_packet(self, ts: float, data: bytes) -> bool:
        """Escribe el paquete al pcap; ante error de E/S registra y corta la captura."""
        try:
            self._writer.writepkt(data, ts=ts)
        except Exception as exc:  # borde del hilo del sniffer
            self.error = exc
            self._reason = "error"
            self._done.set()
            return False
        return True

    def _limit_reached(self) -> Optional[str]:
        """Razón de corte si se alcanzó un límite de paquetes o bytes."""
        if self._packets >= self._max_packets:
            return "max_packets"
        if self._bytes >= self._max_bytes:
            return "max_bytes"
        return None

    def _on_packet(self, ts: float, data: bytes) -> None:
        with self._lock:
            if self._done.is_set():  # ya se decidió terminar: ignoramos el resto
                return
            if self._writer is None:  # el archivo ya se cerró
                return
            if not self._write_packet(ts, data):
                return
            self._packets += 1
            self._bytes += len(data)
            reason = self._limit_reached()
            if reason:
                self._reason = reason
                self._done.set()

    def _wait_for_end(self) -> None:
        """Espera a que alguien termine la captura o venza el tiempo máximo."""
        if self._done.wait(self._max_seconds):
            return
        with self._lock:
            if not self._done.is_set():
                self._reason = "max_seconds"
                self._done.set()

    def _finalize(self) -> None:
        """Cierra el archivo y arma el resumen final."""
        with self._lock:
            started = self._started_at if self._started_at is not None else time.monotonic()
            self._elapsed = time.monotonic() - started
            self._close_file()
            self._summary = CaptureSummary(
                self.path, self._packets, self._bytes, round(self._elapsed, 3), self._reason,
                warning=self._warning())

    def _watch(self) -> None:
        self._wait_for_end()
        try:
            self._stop_source()
        finally:
            self._finalize()
            self._finished.set()

    def _stop_source(self) -> None:
        """Detiene la fuente SIN poder quedarse colgado más de STOP_TIMEOUT."""
        def run():
            try:
                self._source.stop()
            except Exception as exc:
                # Un fallo al detener la fuente no debe dejar un traceback suelto en el hilo ni impedir
                self.error = self.error or exc

        worker = threading.Thread(target=run, name="tracewell-live-stop", daemon=True)
        worker.start()
        worker.join(STOP_TIMEOUT)
        if worker.is_alive():
            self.error = self.error or CaptureError(
                f"la fuente no se detuvo en {STOP_TIMEOUT:g} s; se cerró el archivo igual")

    def _close_file(self) -> None:
        """Vacía y cierra el pcap."""
        fh = self._fh
        if fh is None or fh.closed:
            return
        for step in (fh.flush, fh.close):
            try:
                step()
            except OSError as exc:
                self.error = self.error or exc
