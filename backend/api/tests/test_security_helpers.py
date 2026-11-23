"""Tests directos de backend/api/security.py."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.security import LOCAL_HOSTS, _origin_allowed, _origin_host, install_local_only


@pytest.mark.parametrize("origin,esperado", [
    ("http://localhost:5173", "localhost"),
    ("https://127.0.0.1", "127.0.0.1"),
    ("HTTP://LOCALHOST:80", "localhost"),
    ("http://Evil.COM:8080/path", "evil.com"),
    ("http://[::1]:8000", "::1"),
    ("null", ""),
    ("", ""),
    ("localhost", ""),
    ("http://[::1", ""),
])
def test_origin_host(origin, esperado):
    # _origin_host normaliza a minúsculas y devuelve "" si es ilegible, sin lanzar
    assert _origin_host(origin) == esperado


def test_local_hosts_constante():
    # LOCAL_HOSTS contiene solo nombres locales
    assert set(LOCAL_HOSTS) == {"127.0.0.1", "localhost", "[::1]"}


@pytest.mark.parametrize("origin,ok", [
    ("http://localhost:3000", True), ("http://LOCALHOST", True), ("http://evil.com", False),
    ("null", False), ("", False), ("http://[::1", False), ("http://localhost.evil.com", False),
])
def test_origin_allowed(origin, ok):
    # _origin_allowed acepta solo hosts del conjunto; ilegible/vacío/null = no
    assert _origin_allowed(origin, {"localhost", "127.0.0.1"}) is ok


def make(hosts=LOCAL_HOSTS):
    app = FastAPI()
    install_local_only(app, hosts)

    @app.get("/x")
    def x():
        return {"ok": 1}

    return app


def test_host_local_ok():
    # Host local sin Origin pasa
    assert TestClient(make(), base_url="http://127.0.0.1").get("/x").status_code == 200


def test_host_malo_400():
    # Host ajeno da 400 (TrustedHostMiddleware)
    assert TestClient(make(), base_url="http://evil.com").get("/x").status_code == 400


def test_origin_malo_403():
    # Origin ajeno con Host local da 403
    r = TestClient(make(), base_url="http://127.0.0.1").get("/x", headers={"Origin": "http://evil.com"})
    assert r.status_code == 403 and r.json() == {"detail": "origen no permitido"}


def test_origin_null_403():
    # Origin "null" (iframes sandbox) se rechaza
    assert TestClient(make(), base_url="http://127.0.0.1").get("/x", headers={"Origin": "null"}).status_code == 403


def test_origin_ilegible_403_sin_500():
    # un Origin que rompe urlparse da 403, no 500
    r = TestClient(make(), base_url="http://127.0.0.1").get("/x", headers={"Origin": "http://[::1"})
    assert r.status_code == 403


def test_origin_local_ok():
    # Origin local pasa
    r = TestClient(make(), base_url="http://127.0.0.1").get("/x", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200


def test_allowed_hosts_custom():
    # con allowed_hosts custom se acepta ese Host/Origin y se rechaza localhost
    c = TestClient(make(["Mi.Host"]), base_url="http://mi.host")
    assert c.get("/x", headers={"Origin": "http://MI.host"}).status_code == 200
    assert c.get("/x", headers={"Origin": "http://localhost"}).status_code == 403
    assert TestClient(make(["mi.host"]), base_url="http://127.0.0.1").get("/x").status_code == 400
