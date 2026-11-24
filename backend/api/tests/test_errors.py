"""Tests directos de backend/api/errors.py."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.errors import ERROR_STATUS, register_error_handlers
from backend.domain.files import BadExtension, NotRegularFile, OutsideAllowedDirs
from backend.domain.rules.builder import RuleExists, RuleSaveDenied, RuleSaveError
from backend.domain.rules.engine import RuleError
from backend.domain.rules.iocs import IocError
from backend.domain.pcap.live import CaptureError, CaptureStateError, PermissionDenied
from backend.domain.pcap.reader import PcapError
from backend.domain.sessions.grouper import UnsupportedLinktype
from backend.domain.sessions.query import InvalidFilter

ESPERADO = {
    FileNotFoundError: 404, PcapError: 422, UnsupportedLinktype: 422, InvalidFilter: 422,
    PermissionDenied: 403, CaptureStateError: 409, CaptureError: 503,
    IsADirectoryError: 400, NotRegularFile: 400, PermissionError: 403, IocError: 422, RuleError: 422, RuleExists: 409,
    RuleSaveDenied: 403, RuleSaveError: 500, OutsideAllowedDirs: 403, BadExtension: 400,
}
EXCS = list(ESPERADO)


def test_error_status_tabla():
    # ERROR_STATUS mapea cada excepción al código documentado, sin duplicados
    assert dict(ERROR_STATUS) == ESPERADO and len(ERROR_STATUS) == len(ESPERADO)


@pytest.fixture
def client():
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/boom/{n}")
    def boom(n: int):
        raise EXCS[n]("mensaje de prueba")

    @app.get("/otra")
    def otra():
        raise ValueError("x")

    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize("i,exc", list(enumerate(EXCS)))
def test_cada_excepcion_da_su_codigo(client, i, exc):
    # cada excepción levantada en una ruta responde su código y {"detail": msg}
    r = client.get(f"/boom/{i}")
    assert r.status_code == ESPERADO[exc]
    assert r.json() == {"detail": "mensaje de prueba"}


def test_subclases_ganan_sobre_base(client):
    # CaptureStateError da 409 y PermissionDenied 403 (no 503 de CaptureError)
    codes = {exc: client.get(f"/boom/{i}").status_code for i, exc in enumerate(EXCS)}
    assert codes[CaptureStateError] == 409 and codes[PermissionDenied] == 403
    assert codes[CaptureError] == 503


def test_excepcion_no_mapeada_es_500(client):
    # una excepción fuera de la tabla no se traduce (500)
    assert client.get("/otra").status_code == 500
