"""Defensa contra páginas web externas (solo se atiende a la propia máquina) y cabeceras de seguridad."""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Solo se atiende a la propia máquina. Ver `install_local_only`. IPv6 va con corchetes, como en `Host`.
LOCAL_HOSTS = ("127.0.0.1", "localhost", "[::1]")

# Mantine pone estilos en línea (atributo `style` y <style>): por eso `style-src 'unsafe-inline'`;
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


def install_security_headers(app: FastAPI) -> None:
    """Agrega las cabeceras de seguridad; va al final para que cubra también los rechazos 400/403."""
    app.add_middleware(SecurityHeaders)
