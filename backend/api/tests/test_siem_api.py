"""Tests de GET /api/export/siem (alertas para un SIEM)."""
import json

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.api.security import TOKEN_HEADER


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


def test_ecs_por_defecto_es_ndjson_descargable(loaded):
    r = loaded.get("/api/export/siem")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert r.headers["content-disposition"] == 'attachment; filename="tracewell-alerts.ndjson"'
    docs = [json.loads(line) for line in r.text.splitlines()]
    assert sorted(d["rule"]["id"] for d in docs) == ["dns_suspicious", "ftp_cleartext", "port_scan"]
    scan = next(d for d in docs if d["rule"]["id"] == "port_scan")
    assert scan["threat"]["tactic"]["name"] == ["Discovery"] and scan["threat"]["technique"]["id"] == ["T1046"]
    assert scan["source"]["ip"] == "192.168.1.66" and scan["event"]["kind"] == "alert"


def test_cef_y_syslog(loaded):
    cef = loaded.get("/api/export/siem", params={"format": "cef"})
    assert cef.headers["content-type"].startswith("text/plain")
    assert cef.headers["content-disposition"].endswith('tracewell-alerts.cef"')
    assert len(cef.text.splitlines()) == 3
    assert all(x.startswith("CEF:0|Tracewell|") for x in cef.text.splitlines())
    syslog = loaded.get("/api/export/siem", params={"format": "syslog"})
    assert syslog.headers["content-disposition"].endswith('tracewell-alerts.log"')
    assert all(x.startswith("<") and " - tracewell - ALERT - CEF:0|" in x for x in syslog.text.splitlines())


def test_el_cef_lleva_la_version_de_la_app(loaded):
    version = loaded.get("/api/health").json()["version"]
    assert f"|Tracewell|Tracewell|{version}|" in loaded.get("/api/export/siem?format=cef").text


def test_min_severity(loaded):
    r = loaded.get("/api/export/siem", params={"min_severity": "high"})
    severities = {json.loads(x)["tracewell"]["severity"] for x in r.text.splitlines()}
    assert severities and severities <= {"high", "critical"}
    assert loaded.get("/api/export/siem", params={"min_severity": "critical"}).text == ""


@pytest.mark.parametrize("params", [{"format": "xml"}, {"min_severity": "alta"}, {"format": ""}])
def test_parametros_invalidos_422(loaded, params):
    assert loaded.get("/api/export/siem", params=params).status_code == 422


def test_sin_captura_409(client):
    assert client.get("/api/export/siem").status_code == 409


def test_exige_token(client):
    sin = TestClient(client.app, headers={TOKEN_HEADER: ""})
    assert sin.get("/api/export/siem").status_code == 401


def test_ticket_de_descarga_para_el_enlace(loaded):
    t = loaded.post("/api/download-ticket", json={"path": "/api/export/siem"}).json()["ticket"]
    sin = TestClient(loaded.app, headers={TOKEN_HEADER: ""})
    r = sin.get("/api/export/siem", params={"ticket": t, "format": "cef"})
    assert r.status_code == 200 and r.text.startswith("CEF:0|")
    assert sin.get("/api/export/siem", params={"ticket": t}).status_code == 401  # un solo uso


def test_sin_secretos_en_la_salida(loaded):
    text = loaded.get("/api/export/siem").text
    assert "admin" in text  # el usuario FTP es evidencia
    assert "<oculta>" in text  # la contraseña nunca viaja
    assert "demo.pcap" not in text and "samples" not in text  # ni rutas ni nombres de archivo locales
