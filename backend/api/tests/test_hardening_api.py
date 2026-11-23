"""Endurecimiento de la API: rutas no regulares, pcapng corrupto, IOC sin eco y reglas con datos hostiles."""
import struct
import sys

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app

# Nombres reservados de Windows (abrirlos bloquea); en otros SO, un dispositivo de caracteres.
DISPOSITIVOS = ["con", "aux", "CON", "CONIN$", "nul", "com1"] if sys.platform == "win32" else ["/dev/null", "/dev/zero"]


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.mark.parametrize("endpoint", ["/api/analyze", "/api/iocs"])
@pytest.mark.parametrize("path", DISPOSITIVOS)
def test_dispositivo_es_400_json_rapido(client, endpoint, path):
    r = client.post(endpoint, json={"path": path})
    assert r.status_code == 400 and "detail" in r.json()


def test_pcapng_con_cabecera_de_seccion_corrupta_es_422(client, tmp_path):
    # bloque de sección: magic, longitud 28, byte-order magic y 16 bytes 0xff
    bad = tmp_path / "bad.pcapng"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a" + b"\xff" * 16)
    r = client.post("/api/analyze", json={"path": str(bad)})
    assert r.status_code == 422 and "cabecera inválida" in r.json()["detail"]


def test_ioc_invalido_no_reproduce_la_linea(client, tmp_path):
    f = tmp_path / "ioc.txt"
    f.write_text("1.2.3.4\nsecreto/con/barras\n", encoding="utf-8")
    r = client.post("/api/iocs", json={"path": str(f)})
    assert r.status_code == 422 and "línea 2" in r.json()["detail"] and "secreto" not in r.json()["detail"]


@pytest.mark.parametrize("name", ["a" * 81, "a" * 300])
def test_nombre_de_regla_largo_un_solo_limite_y_mensaje(client, name):
    r = client.post("/api/rules/preview", json={"name": name})
    assert r.status_code == 422 and r.json()["detail"] == "el nombre admite hasta 80 caracteres"


@pytest.mark.parametrize("name", ["con\x00nul", "salto\nde linea", "tab\tulado", "\x1bescape"])
def test_nombre_de_regla_con_control_es_422(client, name):
    r = client.post("/api/rules/preview", json={"name": name})
    assert r.status_code == 422 and "control" in r.json()["detail"]


def test_id_de_regla_con_salto_final_es_422(client):
    r = client.post("/api/rules/preview", json={"name": "Regla", "id": "regla\n"})
    assert r.status_code == 422


def test_ping_con_host_largo_dice_demasiado_largo(client):
    r = client.get("/api/support/ping", params={"host": "a" * 300})
    assert r.status_code == 422 and "demasiado largo" in r.json()["detail"]
    assert "escribí" in client.get("/api/support/ping", params={"host": " "}).json()["detail"]


def test_lifespan_apaga_aunque_falle_el_cuerpo(monkeypatch):
    import asyncio

    from backend.api import app as app_mod

    llamadas = []
    monkeypatch.setattr(app_mod, "_shutdown", lambda state: llamadas.append(state))

    async def correr():
        async with app_mod._make_lifespan("estado")(None):
            raise RuntimeError("falla el servidor")

    with pytest.raises(RuntimeError):
        asyncio.run(correr())
    assert llamadas == ["estado"]
