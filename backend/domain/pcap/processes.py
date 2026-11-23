"""Qué proceso tiene abierto cada socket (SOLO para la captura en vivo).

Por qué solo en vivo: un .pcap no dice qué programa generó cada paquete; esa
información la tiene únicamente el sistema operativo, y solo mientras la
conexión está abierta. Por eso, durante una captura en vivo, un hilo le pregunta
al sistema cada segundo "¿qué conexiones hay abiertas y de qué proceso son?" y
anota lo que ve. Al terminar, cada sesión se busca en esa tabla.

Límites (conscientes):
- Es una foto cada `SAMPLE_INTERVAL`: una conexión más corta que eso puede no verse.
- UDP sin "conexión" se identifica por el puerto local, que es menos preciso.
- psutil es OPCIONAL: sin él (o si falla) la función no existe y nada más se rompe.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Tuple

logger = logging.getLogger("tracewell")

SAMPLE_INTERVAL = 1.0  # segundos entre muestras
MAX_ENTRIES = 50_000  # tope por tabla: acota la memoria en capturas con muchísimas conexiones
STOP_JOIN_TIMEOUT = 2.0


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str


class Conn(NamedTuple):
    """Una conexión del sistema con su dueño. Las IP ya vienen normalizadas."""

    proto: str  # "TCP" | "UDP", igual que `Session.protocol`
    local_ip: str
    local_port: int
    remote_ip: Optional[str]  # None: socket sin conexión (UDP) o en escucha
    remote_port: Optional[int]
    process: ProcessInfo


def normalize_ip(text: Any) -> Optional[str]:
    """IP en forma canónica, o None si no es una IP.

    Quita el sufijo de zona (`fe80::1%12`) y convierte IPv4-mapeada
    (`::ffff:1.2.3.4`, típica de sockets de doble pila) a IPv4, para que
    coincida con lo que el lector de capturas entrega.
    """
    if not isinstance(text, str):
        return None
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).compressed


class ProcessTable:
    """Lo observado durante la captura. Segura entre hilos (el muestreador escribe, la API lee)."""

    def __init__(self, max_entries: int = MAX_ENTRIES):
        self._lock = threading.Lock()
        self._exact: Dict[Tuple[str, str, int, str, int], ProcessInfo] = {}
        self._by_port: Dict[Tuple[str, int], ProcessInfo] = {}
        self._local_ips: FrozenSet[str] = frozenset()
        self._max = max_entries
        self.full = False  # se alcanzó el tope: lo nuevo se ignora

    def __len__(self) -> int:
        with self._lock:
            return len(self._exact) + len(self._by_port)

    def set_local_ips(self, ips: Iterable[str]) -> None:
        """IP de esta máquina; sirven para saber qué extremo de una sesión es el local."""
        normalized = {n for n in (normalize_ip(i) for i in ips) if n}
        with self._lock:
            self._local_ips = frozenset(normalized)

    def add(self, conn: Conn) -> None:
        """Anota una conexión. Gana la PRIMERA vista: un puerto reutilizado después
        por otro programa no debe reetiquetar sesiones anteriores."""
        with self._lock:
            if conn.remote_ip is not None and conn.remote_port is not None:
                key = (conn.proto, conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port)
                self._put(self._exact, key, conn.process)
            else:
                self._put(self._by_port, (conn.proto, conn.local_port), conn.process)

    def _put(self, store: dict, key, process: ProcessInfo) -> None:
        if key in store:
            return
        if len(store) >= self._max:
            self.full = True
            return
        store[key] = process

    def lookup(self, protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[ProcessInfo]:
        """Proceso dueño de la sesión, o None si no se pudo saber (se muestra como "—")."""
        a, b = normalize_ip(src_ip), normalize_ip(dst_ip)
        if a is None or b is None:
            return None
        with self._lock:
            return (
                self._exact.get((protocol, a, src_port, b, dst_port))  # la conexión vista desde un extremo
                or self._exact.get((protocol, b, dst_port, a, src_port))  # o desde el otro
                or self._by_local_port(protocol, ((a, src_port), (b, dst_port)))
            )

    def _by_local_port(self, protocol: str, endpoints) -> Optional[ProcessInfo]:
        """Respaldo para sockets sin conexión: solo cuenta el extremo que es de esta máquina."""
        for ip, port in endpoints:
            if ip in self._local_ips:
                found = self._by_port.get((protocol, port))
                if found is not None:
                    return found
        return None


# ------------------------------------------------------------- fuente: psutil

def _import_psutil():
    try:
        import psutil  # import perezoso y opcional
    except ImportError:
        return None
    return psutil


class PsutilProvider:
    """Lee las conexiones del sistema con psutil. Cualquier error lo ve el muestreador."""

    def __init__(self, psutil_module):
        self._ps = psutil_module

    def local_ips(self) -> List[str]:
        """Direcciones de todas las interfaces de esta máquina."""
        found: List[str] = []
        for addrs in self._ps.net_if_addrs().values():
            found.extend(a.address for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6))
        return found

    def connections(self) -> List[Conn]:
        names: Dict[int, str] = {}  # solo dentro de esta muestra: los PID se reutilizan entre muestras
        conns = (self._to_conn(c, names) for c in self._ps.net_connections(kind="inet"))
        return [c for c in conns if c is not None]

    def _to_conn(self, c, names: Dict[int, str]) -> Optional[Conn]:
        proto = {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}.get(c.type)
        local_ip = normalize_ip(c.laddr.ip) if c.laddr else None
        # PID 0 (o None): conexiones sin dueño real, p. ej. TIME_WAIT. Windows las atribuye a
        # "System Idle Process", que NO es quien las abrió: etiquetarlas así sería mentir.
        if proto is None or not c.pid or local_ip is None:
            return None
        remote_ip = normalize_ip(c.raddr.ip) if c.raddr else None
        remote_port = c.raddr.port if remote_ip else None
        return Conn(proto, local_ip, c.laddr.port, remote_ip, remote_port, self._process(c.pid, names))

    def _process(self, pid: int, names: Dict[int, str]) -> ProcessInfo:
        if pid not in names:
            names[pid] = self._name_of(pid)
        return ProcessInfo(pid, names[pid])

    def _name_of(self, pid: int) -> str:
        """Nombre del proceso; sin permiso o si ya terminó, un texto neutro con el PID."""
        try:
            return self._ps.Process(pid).name()
        except Exception:  # NoSuchProcess / AccessDenied / ZombieProcess: el nombre es opcional
            logger.debug("no se pudo leer el nombre del proceso %s", pid, exc_info=True)
            return f"PID {pid}"


# ----------------------------------------------------------------- muestreador

class ProcessSampler:
    """Hilo que, mientras dura la captura, anota qué proceso tiene cada conexión."""

    def __init__(self, provider, interval: float = SAMPLE_INTERVAL, table: Optional[ProcessTable] = None):
        self._provider = provider
        self._interval = interval
        self.table = table if table is not None else ProcessTable()
        self.samples = 0  # muestras que salieron bien
        self.errors = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="tracewell-processes", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Detiene el hilo y toma una última muestra (atrapa lo abierto hasta el final). Idempotente."""
        if self._stop.is_set():
            return
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(STOP_JOIN_TIMEOUT)
            self._sample_safely()

    def _run(self) -> None:
        while True:
            self._sample_safely()
            if self._stop.wait(self._interval):
                return

    def _sample_safely(self) -> None:
        """Una muestra; un fallo (p. ej. sin permiso) se cuenta y se registra, nunca tumba la captura."""
        try:
            self.table.set_local_ips(self._provider.local_ips())
            for conn in self._provider.connections():
                self.table.add(conn)
        except Exception:  # borde de hilo: esta función es OPCIONAL y no puede afectar la captura
            self.errors += 1
            if self.errors == 1:
                logger.warning("no se pudieron leer las conexiones del sistema", exc_info=True)
        else:
            self.samples += 1


def make_default_sampler(interval: float = SAMPLE_INTERVAL) -> Optional[ProcessSampler]:
    """Muestreador real, o None si psutil no está instalado (la columna Proceso no se ofrece)."""
    psutil = _import_psutil()
    return ProcessSampler(PsutilProvider(psutil), interval) if psutil is not None else None
