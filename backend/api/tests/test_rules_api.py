"""API del panel de reglas: GET /api/rules, POST /api/rules/preview y POST /api/rules."""
import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.api.app import create_app

ROOT = Path(__file__).resolve().parents[3]
BODY = {"name": "Mucho SYN", "severity": "high", "description": "Prueba.", "protocol": "tcp", "min_events": 5, "window_seconds": 120}


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", d)
    return d


@pytest.fixture
def client(rules_dir):
    return TestClient(create_app(rules_dir=rules_dir, sampler_factory=None))


def test_lista_reglas_y_trae_el_ejemplo(client):
    j = client.get("/api/rules").json()
    assert {"port_scan", "brute_force_remote"} <= {r["id"] for r in j["items"]}
    assert j["example"]["protocol"] == "tcp" and not any(r["custom"] for r in j["items"])


def test_preview_sin_captura_da_yaml_y_sin_coincidencias(client):
    j = client.post("/api/rules/preview", json=BODY).json()
    assert j["id"] == "mucho_syn" and j["matches"] is None and j["exists"] is False
    assert yaml.safe_load(j["yaml"])["params"]["min_events"] == 5


def test_preview_con_demo_cuenta_y_no_guarda(client, rules_dir):
    client.post("/api/demo")
    alerts_before = client.get("/api/alerts").json()
    j = client.post("/api/rules/preview", json=BODY).json()
    assert j["matches"]["sessions"] > 0 and j["matches"]["alerts"] >= 1
    assert client.get("/api/alerts").json() == alerts_before  # la captura abierta no cambia
    assert not (rules_dir / "mucho_syn.yaml").exists()
    assert len(client.get("/api/rules").json()["items"]) == len(list(rules_dir.glob("*.yaml")))


def test_preview_sin_coincidencias(client):
    client.post("/api/demo")
    j = client.post("/api/rules/preview", json={**BODY, "dst_ip": "172.31.255.0/24"}).json()
    assert j["matches"]["sessions"] == 0 and j["matches"]["alerts"] == 0


@pytest.mark.parametrize("over", [{"name": ""}, {"src_ip": "nada"}, {"protocol": "icmp"}, {"id": "Mal Id"}, {"port": 99999}, {"severity": "x"}])
def test_formulario_invalido_422(client, over):
    assert client.post("/api/rules/preview", json={**BODY, **over}).status_code == 422
    assert client.post("/api/rules", json={**BODY, **over}).status_code == 422


def test_guardar_crea_el_yaml_y_la_regla_se_usa_en_la_proxima_captura(client, rules_dir):
    r = client.post("/api/rules", json=BODY)
    assert r.status_code == 201 and r.json()["file"] == "mucho_syn.yaml"
    assert yaml.safe_load((rules_dir / "mucho_syn.yaml").read_text(encoding="utf-8"))["detector"] == "threshold"
    assert any(x["id"] == "mucho_syn" and x["custom"] for x in client.get("/api/rules").json()["items"])
    demo = client.post("/api/demo").json()
    assert "mucho_syn" in {x["id"] for x in demo["rules"]}
    assert "mucho_syn" in {a["rule_id"] for a in client.get("/api/alerts").json()}


def test_guardar_dos_veces_da_409_y_no_pisa(client, rules_dir):
    assert client.post("/api/rules", json=BODY).status_code == 201
    first = (rules_dir / "mucho_syn.yaml").read_bytes()
    assert client.post("/api/rules", json={**BODY, "min_events": 99}).status_code == 409
    assert (rules_dir / "mucho_syn.yaml").read_bytes() == first


def test_no_se_pueden_modificar_las_reglas_existentes(client, rules_dir):
    original = (rules_dir / "port_scan.yaml").read_bytes()
    assert client.post("/api/rules", json={**BODY, "id": "port_scan"}).status_code == 409
    assert (rules_dir / "port_scan.yaml").read_bytes() == original


def test_id_con_ruta_no_escribe_fuera_de_la_carpeta(client, rules_dir):
    assert client.post("/api/rules", json={**BODY, "id": "../../escape"}).status_code == 422
    assert not list(rules_dir.parent.glob("*.yaml")) and not (rules_dir.parent.parent / "escape.yaml").exists()
