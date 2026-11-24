"""Reglas de usuario a través de la API: carpeta propia, creación y errores de escritura."""
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.domain.rules import builder

ROOT = Path(__file__).resolve().parents[3]
BODY = {"name": "Mucho SYN", "severity": "high", "protocol": "tcp", "min_events": 5, "window_seconds": 120}


def test_la_app_crea_la_carpeta_al_guardar_y_no_toca_las_incluidas(tmp_path):
    inc, user = tmp_path / "rules", tmp_path / "u" / "a" / "rules"
    shutil.copytree(ROOT / "rules", inc)
    antes = sorted(p.name for p in inc.iterdir())
    c = TestClient(create_app(rules_dir=inc, user_rules_dir=user, sampler_factory=None))
    assert not user.exists()  # el arranque no la necesita
    assert c.post("/api/rules", json=BODY).status_code == 201
    assert (user / "mucho_syn.yaml").is_file() and sorted(p.name for p in inc.iterdir()) == antes
    # al reiniciar la app, la regla del usuario se vuelve a cargar
    c2 = TestClient(create_app(rules_dir=inc, user_rules_dir=user, sampler_factory=None))
    assert any(r["id"] == "mucho_syn" for r in c2.get("/api/rules").json()["items"])


def test_sin_permiso_de_escritura_es_403_con_mensaje(tmp_path, monkeypatch):
    c = TestClient(create_app(user_rules_dir=tmp_path / "u", sampler_factory=None))

    def denegado(*a, **k):
        raise PermissionError(13, "denegado")

    monkeypatch.setattr(Path, "mkdir", denegado)
    r = c.post("/api/rules", json=BODY)
    assert r.status_code == 403 and "no hay permiso" in r.json()["detail"]


def test_otro_error_de_disco_es_500_con_mensaje(tmp_path, monkeypatch):
    def lleno(_data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(builder, "render_yaml", lleno)
    c = TestClient(create_app(user_rules_dir=tmp_path / "u", sampler_factory=None))
    r = c.post("/api/rules", json=BODY)
    assert r.status_code == 500 and "no se pudo guardar la regla" in r.json()["detail"]
