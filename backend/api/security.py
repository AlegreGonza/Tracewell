"""Defensa contra páginas web externas (solo se atiende a la propia máquina) y cabeceras de seguridad."""
from __future__ import annotations

import secrets
import threading
import time
from typing import Awaitable, Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Solo se atiende a la propia máquina. Ver `install_local_only`. IPv6 va con corchetes, como en `Host`.
LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]")

# El token viaja SOLO en esta cabecera. Las descargas (<a download>, sin cabeceras) usan un ticket.
TOKEN_HEADER = "X-Tracewell-Token"  # nosec B105 - nombre de cabecera, no un secreto
TICKET_QUERY = "ticket"
TICKET_TTL = 30.0  # segundos de vida de un ticket de descarga
MAX_TICKETS = 256  # tope de tickets pendientes (los más viejos se descartan)
MIN_TOKEN_LENGTH = 16
_token_scheme = APIKeyHeader(name=TOKEN_HEADER, auto_error=False)


class TicketStore:
    """Tickets de un solo uso y vida corta, atados a la ruta que van a descargar."""

    def __init__(self, ttl: float = TICKET_TTL, limit: int = MAX_TICKETS, clock=time.monotonic) -> None:
        self._ttl, self._limit, self._clock = ttl, limit, clock
        self._items: Dict[str, Tuple[str, float]] = {}  # ticket -> (ruta, vence)
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for key in [k for k, (_p, exp) in self._items.items() if exp <= now]:
            del self._items[key]
        while len(self._items) >= self._limit:
            del self._items[next(iter(self._items))]  # el más viejo: los dicts conservan el orden

    def issue(self, path: str) -> str:
        """Ticket nuevo para `path`."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            ticket = secrets.token_urlsafe(16)
            self._items[ticket] = (path, now + self._ttl)
            return ticket

    def redeem(self, path: str, ticket: str) -> bool:
        """Canjea (y gasta) el ticket: solo vale una vez, para esa ruta y antes de vencer."""
        with self._lock:
            entry = self._items.pop(ticket, None)
        return entry is not None and entry[0] == path and entry[1] > self._clock()

# Radix/sonner/cmdk ponen estilos en línea (atributo `style` y <style>): por eso `style-src 'unsafe-inline'` (probado: sin él se bloquean <style> y estilos en línea);
# los scripts, en cambio, solo los propios.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def _origin_host(origin: str) -> str:
    """Hostname en minúsculas de un Origin; vacío si es ilegible."""
    try:
        return (urlparse(origin).hostname or "").lower()
    except ValueError:  # p. ej. "http://[::1": urlparse lanza en vez de devolver
        return ""


def _origin_allowed(origin: str, hosts: set[str]) -> bool:
    """Un Origin ilegible se trata como no permitido."""
    return _origin_host(origin) in hosts


class OnlyLocalOrigin:
    """Middleware ASGI: rechaza con 403 una petición HTTP cuyo Origin no sea de esta máquina."""

    def __init__(self, app: ASGIApp, hosts: set[str]) -> None:
        self.app = app
        # `urlparse().hostname` devuelve el IPv6 sin corchetes; `Host` lo trae con ellos
        self.hosts = {h.strip("[]") for h in hosts}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            origin = Headers(scope=scope).get("origin")
            if origin is not None and not _origin_allowed(origin, self.hosts):
                response = JSONResponse(status_code=403, content={"detail": "origen no permitido"})
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class SecurityHeaders:
    """Middleware ASGI: agrega las cabeceras de `SECURITY_HEADERS` a toda respuesta HTTP."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)  # lo que una ruta ya fijó se respeta
            await send(message)

        await self.app(scope, receive, send_with_headers)


def install_local_only(app: FastAPI, allowed_hosts: Iterable[str]) -> None:
    """Instala los chequeos de Host y de Origin."""
    hosts = {h.lower() for h in allowed_hosts}
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=sorted(hosts))
    app.add_middleware(OnlyLocalOrigin, hosts=hosts)


def make_token_check(token: str) -> Callable[[Request], Awaitable[None]]:
    """Dependencia que exige el token (o un ticket de descarga) en toda ruta; no hay modo sin token."""
    if not token:
        raise ValueError("la API exige un token no vacío")
    expected = token.encode("utf-8")

    async def check_token(request: Request, header: Optional[str] = Depends(_token_scheme)) -> None:
        # compare_digest sobre bytes: tiempo constante y sin TypeError con texto no ASCII
        if header and secrets.compare_digest(header.encode("utf-8"), expected):
            return
        ticket = request.query_params.get(TICKET_QUERY)
        if ticket and request.method == "GET" and request.app.state.tickets.redeem(request.url.path, ticket):
            return
        raise HTTPException(status_code=401, detail="falta el token de la API o es inválido")

    return check_token


def install_security_headers(app: FastAPI) -> None:
    """Agrega las cabeceras de seguridad; va al final para que cubra también los rechazos 400/403."""
    app.add_middleware(SecurityHeaders)
