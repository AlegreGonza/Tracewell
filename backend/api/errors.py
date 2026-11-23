"""Traducción de errores de `core` (y del SO) a códigos HTTP."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from backend.api.security import SECURITY_HEADERS
from backend.domain.files import NotRegularFile
from backend.domain.rules.builder import RuleExists
from backend.domain.rules.engine import RuleError
from backend.domain.rules.iocs import IocError
from backend.domain.pcap.live import CaptureError, CaptureStateError, PermissionDenied
from backend.domain.pcap.reader import PcapError
from backend.domain.sessions.grouper import UnsupportedLinktype
from backend.domain.sessions.query import InvalidFilter

logger = logging.getLogger("tracewell")

# Orden irrelevante para Starlette (resuelve por la clase más específica del MRO).
ERROR_STATUS = (
    (FileNotFoundError, 404),
    (PcapError, 422),
    (UnsupportedLinktype, 422),
    (InvalidFilter, 422),
    (IocError, 422),
    (RuleError, 422),
    (RuleExists, 409),
    (PermissionDenied, 403),
    (CaptureStateError, 409),
    (CaptureError, 503),
    (IsADirectoryError, 400),
    (NotRegularFile, 400),
    (PermissionError, 403),
)


def _handler_for(status: int):
    """Arma un handler que responde `{"detail": <mensaje>}` con ese código."""
    async def handler(_request, exc):
        return JSONResponse(status_code=status, content={"detail": str(exc)})
    return handler


async def _unexpected_handler(request, exc):
    """Red de seguridad."""
    logger.error("error no controlado en %s %s", request.method, request.url.path, exc_info=exc)
    # Este handler corre fuera de los middlewares: las cabeceras se agregan acá
    return JSONResponse(status_code=500, content={"detail": "error interno"}, headers=SECURITY_HEADERS)


def register_error_handlers(app: FastAPI) -> None:
    """Registra el mapeo excepción -> código HTTP en la app."""
    for exc_type, status in ERROR_STATUS:
        app.add_exception_handler(exc_type, _handler_for(status))
    app.add_exception_handler(Exception, _unexpected_handler)
