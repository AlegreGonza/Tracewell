"""Lista de carpetas permitidas de /api/analyze y /api/iocs."""
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from backend.api.app import ROOT, create_app
from backend.domain.files import ENV_ALLOWED_DIRS, default_allowed_dirs, resolve_allowed_dirs

DEMO = ROOT / "samples" / "demo.pcap"


@pytest.fixture
def zonas(tmp_path):
    ok, fuera = tmp_path / "permitida", tmp_path / "fuera"
    ok.mkdir()
    fuera.mkdir()
    return ok, fuera


@pytest.fixture
def client(zonas):
    return TestClient(create_app(sampler_factory=None, allowed_dirs=[zonas[0]]))


def analizar(client, path):
    return client.post("/api/analyze", json={"path": str(path)})


def test_archivo_dentro_se_analiza(client, zonas):
    shutil.copy(DEMO, zonas[0] / "a.pcap")
    assert analizar(client, zonas[0] / "a.pcap").status_code == 200


def test_archivo_fuera_es_403_en_espanol(client, zonas):
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    r = analizar(client, zonas[1] / "b.pcap")
    assert r.status_code == 403 and "fuera de las carpetas permitidas" in r.json()["detail"]


def test_ruta_inexistente_fuera_tambien_es_403(client, zonas):
    assert analizar(client, zonas[1] / "nada.pcap").status_code == 403


def test_punto_punto_no_escapa(client, zonas):
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    sneaky = zonas[0] / ".." / "fuera" / "b.pcap"
    assert analizar(client, sneaky).status_code == 403


def test_symlink_hacia_fuera_es_403(client, zonas):
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    link = zonas[0] / "enlace.pcap"
    try:
        link.symlink_to(zonas[1] / "b.pcap")
    except (OSError, NotImplementedError):
        pytest.skip("este sistema no permite crear enlaces simbólicos")
    assert analizar(client, link).status_code == 403


@pytest.mark.parametrize("name", ["secreto.txt", "x.exe", "sinextension", "a.pcap.txt"])
def test_extension_rara_es_400(client, zonas, name):
    (zonas[0] / name).write_bytes(b"x")
    r = analizar(client, zonas[0] / name)
    assert r.status_code == 400 and "extensión" in r.json()["detail"]


@pytest.mark.parametrize("name", ["a.PCAP", "a.pcapng", "a.cap"])
def test_extensiones_validas_pasan_el_filtro(client, zonas, name):
    (zonas[0] / name).write_bytes(b"")
    assert analizar(client, zonas[0] / name).status_code != 400  # 422: vacío, pero pasó el filtro


def test_iocs_tambien_respeta_la_lista(client, zonas):
    (zonas[1] / "i.txt").write_text("1.2.3.4\n", encoding="utf-8")
    assert client.post("/api/iocs", json={"path": str(zonas[1] / "i.txt")}).status_code == 403
    (zonas[0] / "i.txt").write_text("1.2.3.4\n", encoding="utf-8")
    assert client.post("/api/iocs", json={"path": str(zonas[0] / "i.txt")}).status_code == 200


def test_samples_siempre_esta_permitida(zonas):
    c = TestClient(create_app(sampler_factory=None, allowed_dirs=[zonas[0]]))
    assert analizar(c, DEMO).status_code == 200


def test_el_parametro_manda_sobre_la_variable_de_entorno(monkeypatch, zonas):
    monkeypatch.setenv(ENV_ALLOWED_DIRS, str(zonas[1]))
    assert zonas[1].resolve() in resolve_allowed_dirs()
    assert resolve_allowed_dirs([zonas[0]]) == (zonas[0].resolve(),)


def test_varias_carpetas_en_la_variable_de_entorno(monkeypatch, zonas):
    monkeypatch.setenv(ENV_ALLOWED_DIRS, os.pathsep.join(str(z) for z in zonas))
    assert set(resolve_allowed_dirs()) == {z.resolve() for z in zonas}


def test_por_defecto_son_descargas_documentos_escritorio_y_temporal(monkeypatch):
    monkeypatch.delenv(ENV_ALLOWED_DIRS)
    nombres = {p.name for p in default_allowed_dirs()}
    assert {"Downloads", "Documents", "Desktop", "tracewell"} <= nombres
