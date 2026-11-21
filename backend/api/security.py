"""Defensa contra páginas web externas (solo se atiende a la propia máquina)."""
from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Solo se atiende a la propia máquina. Ver `install_local_only`.
LOCAL_HOSTS = ("127.0.0.1", "localhost")


def _origin_host(origin: str) -> str:
    """Hostname en minúsculas de un Origin; vacío si es ilegible."""
    try:
        return (urlparse(origin).hostname or "").lower()
    except ValueError:  # p. ej. "http://[::1": urlparse lanza en vez de devolver
        return ""


def _origin_allowed(origin: str, hosts: set[str]) -> bool:
    """Un Origin ilegible se trata como no permitido."""
    return _origin_host(origin) in hosts


def install_local_only(app: FastAPI, allowed_hosts: Iterable[str]) -> None:
    """Instala los chequeos de Host y de Origin.

    La API puede leer rutas locales (/api/analyze) y escuchar en localhost, y
    CUALQUIER página que el usuario abra en su navegador puede intentar
    pegarle a localhost (CSRF) o resolver su propio dominio a 127.0.0.1
    (DNS rebinding). Dos defensas baratas:
     1. Host: solo nombres locales (frena el DNS rebinding, que llega con el
        Host del dominio atacante).
     2. Origin: si el navegador manda uno, debe ser local (frena el CSRF).
        Sin Origin (curl, TestClient, la propia app al navegar) se permite.
    """
    hosts = {h.lower() for h in allowed_hosts}
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=sorted(hosts))

    @app.middleware("http")
    async def only_local_origin(request, call_next):
        origin = request.headers.get("origin")
        if origin is not None and not _origin_allowed(origin, hosts):
            return JSONResponse(status_code=403, content={"detail": "origen no permitido"})
        return await call_next(request)
