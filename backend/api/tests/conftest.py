"""Fixtures compartidas de los tests de la API."""
import tempfile

import pytest
from fastapi.testclient import TestClient

from backend.api.security import TOKEN_HEADER
from backend.domain.files import ENV_ALLOWED_DIRS
from backend.domain.rules.paths import ENV_USER_RULES_DIR


@pytest.fixture(autouse=True)
def _testclient_host_local(monkeypatch):
    original = TestClient.__init__

    def init(self, app, base_url="http://127.0.0.1", *args, **kwargs):
        # Con token autogenerado el cliente lo manda solo; `headers={TOKEN_HEADER: ""}` lo evita.
        state = getattr(app, "state", None)
        if getattr(state, "token_generated", False):
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault(TOKEN_HEADER, state.api_token)
            kwargs["headers"] = headers
        original(self, app, base_url, *args, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", init)


@pytest.fixture(autouse=True)
def _entorno_aislado(monkeypatch, tmp_path_factory):
    """Los tests no tocan el APPDATA real y abren pcaps desde la carpeta temporal."""
    monkeypatch.setenv(ENV_ALLOWED_DIRS, tempfile.gettempdir())
    monkeypatch.setenv(ENV_USER_RULES_DIR, str(tmp_path_factory.mktemp("reglas_usuario")))
