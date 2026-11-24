"""Tickets de descarga: un enlace <a download> no puede llevar la cabecera del token."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from backend.api.security import TICKET_QUERY

router = APIRouter(prefix="/api")

# Solo las rutas que son descargas; el ticket no sirve para ninguna otra.
DOWNLOAD_PATHS = re.compile(
    r"^/api/(export|export/siem|report|pcap|sessions/\d+/pcap|sessions/\d+/http/\d+/body)$"
)


class TicketRequest(BaseModel):
    path: str = Field(min_length=1, max_length=200)


@router.post("/download-ticket")
def download_ticket(req: TicketRequest, request: Request):
    """Ticket de un solo uso (30 s) para descargar `path`; se pide con la cabecera del token."""
    if not DOWNLOAD_PATHS.match(req.path):
        raise HTTPException(422, "esa ruta no es una descarga")
    return {"ticket": request.app.state.tickets.issue(req.path), "query": TICKET_QUERY}
