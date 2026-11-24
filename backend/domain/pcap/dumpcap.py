"""Captura en Linux con `dumpcap` (Wireshark): solo él lleva el permiso; la API corre sin privilegios."""
from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import struct
import subprocess  # nosec B404 - lista fija de argumentos, sin shell
import sys
import threading
import time
from typing import BinaryIO, Callable, Optional, Tuple

from .live import ETHERNET, PacketSource, CaptureError, PermissionDenied, ScapySource

logger = logging.getLogger("tracewell")

ENV_BACKEND = "TRACEWELL_CAPTURE"  # "scapy" fuerza el camino anterior
EARLY_EXIT_WAIT = 1.0  # un permiso denegado hace salir a dumpcap casi al instante
STOP_WAIT = 3.0
MAX_RECORD = 262_144  # un registro más grande es un flujo corrupto, no un paquete
_MAGICS = {0xA1B2C3D4: 1e6, 0xA1B23C4D: 1e9}  # microsegundos / nanosegundos

# dumpcap acepta como "interfaz" un número, "-" (stdin), una ruta o rpcap://, TCP@host:puerto: solo nombres simples
_IFACE_OK = re.compile(r"[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,31}")

DUMPCAP_HELP = (
    "dumpcap no tiene permiso de captura. En Linux, solo a él: `sudo setcap cap_net_raw,cap_net_admin+ep "
    "$(readlink -f $(which dumpcap))` (o `sudo dpkg-reconfigure wireshark-common` y tu usuario en el grupo "
    "wireshark). Con setcap pueden capturar todos los usuarios; para limitarlo: `sudo groupadd packetcapture; "
    "sudo chgrp packetcapture <dumpcap>; sudo chmod 750 <dumpcap>` antes del setcap. Tracewell sigue sin privilegios"
)


def find_dumpcap() -> Optional[str]:
    """Ruta de dumpcap si se puede usar (solo Linux y sin TRACEWELL_CAPTURE=scapy)."""
    if not sys.platform.startswith("linux") or os.environ.get(ENV_BACKEND) == "scapy":
        return None
    return shutil.which("dumpcap")


def make_source(interface: str) -> PacketSource:
    """dumpcap si está instalado; si no, Scapy (el camino de siempre)."""
    exe = find_dumpcap()
    return DumpcapSource(interface, dumpcap=exe) if exe else ScapySource(interface)


def _read_exact(stream: BinaryIO, size: int) -> Optional[bytes]:
    """Lee exactamente `size` bytes de la tubería; None si se cerró antes."""
    chunks, left = [], size
    while left:
        chunk = stream.read(left)
        if not chunk:
            return None
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def parse_global_header(head: bytes) -> Tuple[str, float]:
    """(orden de bytes de struct, divisor del tiempo) de la cabecera pcap; CaptureError si no es Ethernet."""
    for order in ("<", ">"):
        (magic,) = struct.unpack(order + "I", head[:4])
        if magic in _MAGICS:
            linktype = struct.unpack(order + "I", head[20:24])[0]
            if linktype != ETHERNET:
                raise CaptureError(f"dumpcap entregó un tipo de enlace no Ethernet ({linktype})")
            return order, _MAGICS[magic]
    raise CaptureError("dumpcap no entregó un pcap válido")


class DumpcapSource:
    """Fuente de paquetes: lee el pcap que dumpcap escribe por su salida estándar."""

    def __init__(self, interface: str, bpf_filter: Optional[str] = None, dumpcap: str = "dumpcap"):
        if not isinstance(interface, str) or not _IFACE_OK.fullmatch(interface) or interface.isdigit():
            raise CaptureError("hay que indicar una interfaz válida (solo el nombre, por ejemplo eth0)")
        self.interface, self.bpf_filter, self._exe = interface, bpf_filter, dumpcap
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._failure: Optional[CaptureError] = None

    def start(self, on_packet: Callable[[float, bytes], None]) -> None:
        cmd = [self._exe, "-i", self.interface, "-P", "-q", "-w", "-"]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # nosec B603
        except OSError as exc:
            raise CaptureError(f"no se pudo ejecutar dumpcap: {exc}") from exc
        self._check_early_exit()
        self._thread = threading.Thread(target=self._read, args=(on_packet,), name="tracewell-dumpcap", daemon=True)
        self._thread.start()

    def _check_early_exit(self) -> None:
        """Si dumpcap sale enseguida (permiso, interfaz o filtro malos), traduce su mensaje."""
        deadline = time.monotonic() + EARLY_EXIT_WAIT
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise self._exit_error()
            time.sleep(0.05)

    def _exit_error(self) -> CaptureError:
        text = (self._proc.stderr.read() or b"").decode("utf-8", "replace").strip()
        # Mensaje real: "You don't have permission to capture on that device (socket: Operation not permitted)"
        if any(w in text.lower() for w in ("permission", "not permitted")):
            return PermissionDenied(DUMPCAP_HELP)
        return CaptureError(f"dumpcap no pudo capturar en {self.interface!r}: {text[-300:] or 'sin detalle'}")

    def _read(self, on_packet: Callable[[float, bytes], None]) -> None:
        out = self._proc.stdout
        try:
            head = _read_exact(out, 24)
            if head is None:
                self._failure = self._ended_early()
                return
            order, divisor = parse_global_header(head)
            while True:
                rec = _read_exact(out, 16)
                if rec is None:
                    return
                sec, frac, incl, _orig = struct.unpack(order + "IIII", rec)
                data = _read_exact(out, incl) if incl <= MAX_RECORD else None
                if data is None:
                    raise CaptureError("el flujo de dumpcap está cortado o corrupto")
                on_packet(sec + frac / divisor, data)
        except CaptureError as exc:  # borde del hilo: se informa en stop()
            self._failure = exc
            self._terminate()
        except (OSError, ValueError):  # la tubería se cerró durante stop()
            return

    def _ended_early(self) -> Optional[CaptureError]:
        """dumpcap cerró la salida antes de la cabecera: si salió con error, su mensaje; si no, None."""
        try:
            self._proc.wait(STOP_WAIT)
        except subprocess.TimeoutExpired:
            return None
        return self._exit_error() if self._proc.poll() else None

    def _terminate(self) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        proc.send_signal(signal.SIGINT)  # la forma documentada de detenerlo (Ctrl-C)
        try:
            proc.wait(STOP_WAIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def stop(self) -> None:
        self._terminate()
        if self._thread is not None:
            self._thread.join(STOP_WAIT)
        if self._failure is not None:
            raise self._failure
