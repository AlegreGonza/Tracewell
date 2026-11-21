"""Fixtures compartidas de los tests de la API.

La app solo acepta Host local (TrustedHostMiddleware), pero TestClient usa por
defecto el Host "testserver". Este fixture autouse cambia el base_url por
defecto a http://127.0.0.1; los tests de seguridad lo pisan explícitamente.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _testclient_host_local(monkeypatch):
    original = TestClient.__init__

    def init(self, app, base_url="http://127.0.0.1", *args, **kwargs):
        original(self, app, base_url, *args, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", init)
