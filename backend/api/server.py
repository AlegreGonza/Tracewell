"""Arranca la API en un hilo, en un puerto libre de esta misma máquina."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass

import uvicorn
from fastapi import FastAPI

from .app import create_app

LOCAL_HOST = "127.0.0.1"
READY_TIMEOUT = 10.0  # cuánto esperamos a que la API responda antes de rendirnos


class ServerStartError(RuntimeError):
    """La API no llegó a arrancar (puerto ocupado, error al cargar las reglas...)."""


@dataclass
class ServerHandle:
    server: uvicorn.Server
    thread: threading.Thread
    port: int

    @property
    def url(self) -> str:
        return f"http://{LOCAL_HOST}:{self.port}"

    def stop(self, timeout: float = 5.0) -> None:
        """Pide a uvicorn que termine y espera a su hilo (con tope)."""
        self.server.should_exit = True
        self.thread.join(timeout)


def bind_local_socket(port: int = 0) -> socket.socket:
    """Abre un socket en 127.0.0.1; con puerto 0 el sistema elige uno libre."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((LOCAL_HOST, port))
    except OSError:
        sock.close()
        raise
    return sock


def _wait_ready(handle: ServerHandle, timeout: float) -> None:
    """Espera a que uvicorn esté listo; falla si su hilo murió o se vence el plazo."""
    deadline = time.monotonic() + timeout
    while not handle.server.started:
        if not handle.thread.is_alive() or time.monotonic() > deadline:
            handle.server.should_exit = True
            raise ServerStartError("la API no llegó a arrancar")
        time.sleep(0.02)


def _make_server(app: FastAPI) -> uvicorn.Server:
    """Servidor uvicorn con logs mínimos (la interfaz ya muestra los errores)."""
    return uvicorn.Server(uvicorn.Config(app, host=LOCAL_HOST, log_level="warning"))


def start_in_thread(app: FastAPI | None = None, port: int = 0, **app_kwargs) -> ServerHandle:
    """Levanta la API en un hilo y devuelve cuando ya responde."""
    # La app se arma ANTES de abrir el socket
    server = _make_server(app or create_app(**app_kwargs))
    sock = bind_local_socket(port)
    try:
        return _launch(server, sock)
    except BaseException:
        sock.close()  # uvicorn no llegó a hacerse cargo del socket: lo cerramos acá
        raise


def _launch(server: uvicorn.Server, sock: socket.socket) -> ServerHandle:
    """Arranca el hilo de uvicorn con el socket ya abierto y espera a que responda."""
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, name="tracewell-api", daemon=True
    )
    thread.start()
    handle = ServerHandle(server, thread, sock.getsockname()[1])
    _wait_ready(handle, READY_TIMEOUT)
    return handle
