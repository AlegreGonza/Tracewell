"""Lista de carpetas permitidas de /api/analyze y /api/iocs."""
import os
import shutil

import pytest
from fastapi.testclient import TestClient

from backend.api.app import ROOT, create_app
from pathlib import Path

from backend.domain.files import ENV_ALLOWED_DIRS, FileGrants, default_allowed_dirs, resolve_allowed_dirs

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
    assert "TRACEWELL_ALLOWED_DIRS" in r.json()["detail"]  # dice cómo agregar otra carpeta


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


def test_por_defecto_solo_descargas_minimo_privilegio(monkeypatch):
    monkeypatch.delenv(ENV_ALLOWED_DIRS, raising=False)
    nombres = {p.name for p in default_allowed_dirs()}
    assert nombres == {"Downloads"}  # Documentos y Escritorio enteros ya no se abren por defecto
    assert "tracewell" not in nombres  # <temp>/tracewell era predecible: otro usuario la crea antes


# ------------------------------------------------------- permisos por archivo (diálogo nativo)
@pytest.fixture
def con_permisos(zonas):
    grants = FileGrants()
    return TestClient(create_app(sampler_factory=None, allowed_dirs=[zonas[0]], grants=grants)), grants


def test_un_archivo_fuera_se_abre_solo_tras_elegirlo_en_el_dialogo(con_permisos, zonas):
    c, grants = con_permisos
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    assert analizar(c, zonas[1] / "b.pcap").status_code == 403
    grants.grant(zonas[1] / "b.pcap")
    assert analizar(c, zonas[1] / "b.pcap").status_code == 200


def test_el_permiso_es_del_archivo_no_de_su_carpeta(con_permisos, zonas):
    c, grants = con_permisos
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    shutil.copy(DEMO, zonas[1] / "otra.pcap")
    grants.grant(zonas[1] / "b.pcap")
    assert analizar(c, zonas[1] / "otra.pcap").status_code == 403


def test_el_permiso_no_salta_la_extension(con_permisos, zonas):
    c, grants = con_permisos
    (zonas[1] / "clave.pem").write_text("x", encoding="utf-8")
    grants.grant(zonas[1] / "clave.pem")
    r = analizar(c, zonas[1] / "clave.pem")
    assert r.status_code == 400 and "extensión" in r.json()["detail"]


def test_un_enlace_cambiado_despues_del_permiso_ya_no_vale(con_permisos, zonas):
    c, grants = con_permisos
    shutil.copy(DEMO, zonas[1] / "b.pcap")
    shutil.copy(DEMO, zonas[1] / "secreto.pcap")
    destino = zonas[1] / "enlace.pcap"
    try:
        destino.symlink_to(zonas[1] / "b.pcap")
    except (OSError, NotImplementedError):
        pytest.skip("este sistema no permite crear enlaces simbólicos")
    grants.grant(destino)  # queda autorizado el archivo real (b.pcap)
    destino.unlink()
    destino.symlink_to(zonas[1] / "secreto.pcap")  # el enlace ahora apunta a otro archivo
    assert analizar(c, destino).status_code == 403


def test_los_permisos_estan_acotados():
    grants = FileGrants()
    for i in range(FileGrants.MAX + 10):
        grants.grant(f"/tmp/a{i}.pcap")
    assert not grants.allows(Path("/tmp/a0.pcap").resolve())  # los más viejos se olvidan
    assert grants.allows(Path(f"/tmp/a{FileGrants.MAX + 9}.pcap").resolve())


# ------------------------------------------------------------ listas de IOC: solo texto de listas
@pytest.mark.parametrize("name", [".env", "id_rsa", "clave.pem", "notas.docx", "x.exe"])
def test_iocs_rechaza_archivos_que_no_son_listas(client, zonas, name):
    (zonas[0] / name).write_text("1.2.3.4\n", encoding="utf-8")
    r = client.post("/api/iocs", json={"path": str(zonas[0] / name)})
    assert r.status_code == 400 and "extensión" in r.json()["detail"]


@pytest.mark.parametrize("name", ["i.txt", "i.csv", "i.json", "i.stix", "i.ioc"])
def test_iocs_acepta_las_extensiones_de_listas(client, zonas, name):
    (zonas[0] / name).write_text("1.2.3.4\n", encoding="utf-8")
    assert client.post("/api/iocs", json={"path": str(zonas[0] / name)}).status_code != 400
