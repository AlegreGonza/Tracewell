"""API de triaje: notas por sesión, lista de IOC e informe HTML (sin red ni captura real)."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.routes import triage as routes_triage
from backend.api.app import ROOT, create_app
from backend.domain.analysis.analyzer import Analysis
from backend.domain.pcap.reader import CaptureInfo
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import GroupingResult, Session

DEMO = ROOT / "samples" / "demo.pcap"
XSS = "<script>alert(1)</script>"
EMPTY = {"loaded": False, "source": None, "ips": 0, "networks": 0, "domains": 0, "sessions": 0}


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


def ioc_file(tmp_path, text, name="iocs.txt"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def load_ioc(client, tmp_path, text, name="iocs.txt"):
    r = client.post("/api/iocs", json={"path": str(ioc_file(tmp_path, text, name))})
    assert r.status_code == 200, r.text
    return r.json()


def items(client, **params):
    r = client.get("/api/sessions", params={"limit": 500, **params})
    assert r.status_code == 200
    return {s["id"]: s for s in r.json()["items"]}


def hostile_analysis():
    """Análisis armado a mano (sin pcap) con datos hostiles en alertas y ruta con carpetas."""
    sess = [Session("TCP", "10.0.0.1", 1, "10.0.0.2", 2, 1, 50, 1.0, 2.0, key=("k", 0))]
    alert = Alert(
        rule_id="R", name=XSS, severity="high", mitre_technique="T1", mitre_name="n", mitre_tactic="t",
        description="d", src_ip="10.0.0.1", dst_ip="10.0.0.2", first_ts=1.0,
        evidence={"payload": XSS, "q": "\"'&"},
    )
    return Analysis(path=Path("C:/Users/privado/secreto/cap.pcap"),
                    info=CaptureInfo(format="pcap", linktype=1, snaplen=65535),
                    result=GroupingResult(sessions=sess), alerts=[alert], rules=[])


# ======================================================================= notas
def test_nota_sin_analisis_409(client):
    r = client.put("/api/sessions/0/note", json={"note": "x"})
    assert r.status_code == 409 and "no hay una captura analizada" in r.json()["detail"]


def test_nota_sesion_inexistente_404(loaded):
    for sid in (32, 9999):
        assert loaded.put(f"/api/sessions/{sid}/note", json={"note": "x"}).status_code == 404
    assert loaded.put("/api/sessions/-1/note", json={"note": "x"}).status_code == 404
    assert loaded.put("/api/sessions/abc/note", json={"note": "x"}).status_code == 422


def test_nota_ciclo_completo(loaded):
    r = loaded.put("/api/sessions/3/note", json={"note": "  sospechosa  ", "reviewed": False})
    assert r.status_code == 200
    assert r.json() == {"id": 3, "note": "sospechosa", "reviewed": False}  # recortada
    s = items(loaded)
    assert s[3]["note"] == "sospechosa" and s[3]["reviewed"] is False
    assert "note" not in s[2] and "reviewed" not in s[2]  # solo las anotadas
    # cambia la nota
    loaded.put("/api/sessions/3/note", json={"note": "otra", "reviewed": True})
    assert items(loaded)[3]["note"] == "otra" and items(loaded)[3]["reviewed"] is True
    # vaciar nota y desmarcar la borra
    r = loaded.put("/api/sessions/3/note", json={"note": "   ", "reviewed": False})
    assert r.status_code == 200 and r.json() == {"id": 3, "note": "", "reviewed": False}
    s = items(loaded)[3]
    assert "note" not in s and "reviewed" not in s


def test_solo_revisada_sin_texto_se_conserva(loaded):
    loaded.put("/api/sessions/4/note", json={"note": "", "reviewed": True})
    s = items(loaded)[4]
    assert s["reviewed"] is True and s["note"] == ""


def test_cuerpo_vacio_usa_valores_por_defecto_y_borra(loaded):
    loaded.put("/api/sessions/4/note", json={"note": "x"})
    assert loaded.put("/api/sessions/4/note", json={}).status_code == 200
    assert "note" not in items(loaded)[4]


def test_borrar_nota_inexistente_no_falla(loaded):
    assert loaded.put("/api/sessions/7/note", json={}).status_code == 200


def test_limite_2000_caracteres(loaded):
    assert loaded.put("/api/sessions/0/note", json={"note": "a" * 2000}).status_code == 200
    assert loaded.put("/api/sessions/0/note", json={"note": "a" * 2001}).status_code == 422
    assert len(items(loaded)[0]["note"]) == 2000


def test_nota_tipos_invalidos_422(loaded):
    assert loaded.put("/api/sessions/0/note", json={"note": 5}).status_code == 422
    assert loaded.put("/api/sessions/0/note", json={"reviewed": "quizas"}).status_code == 422
    assert loaded.put("/api/sessions/0/note", content="no json").status_code == 422


def test_nota_hostil_se_guarda_tal_cual_y_se_devuelve_como_json(loaded):
    text = f"{XSS} \"'& ñ 😀\nlínea2"
    loaded.put("/api/sessions/0/note", json={"note": text})
    assert items(loaded)[0]["note"] == text


def test_notas_se_reinician_con_cada_analisis(loaded):
    loaded.put("/api/sessions/3/note", json={"note": "vieja", "reviewed": True})
    assert loaded.post("/api/demo").status_code == 200
    s = items(loaded)
    assert all("note" not in x and "reviewed" not in x for x in s.values())
    assert loaded.app.state.ctx.state.notes == {}


def test_notas_se_reinician_con_analyze(loaded, tmp_path):
    import shutil
    copy = tmp_path / "otra.pcap"
    shutil.copy(DEMO, copy)
    loaded.put("/api/sessions/3/note", json={"note": "vieja"})
    assert loaded.post("/api/analyze", json={"path": str(copy)}).status_code == 200
    assert "note" not in items(loaded)[3]


def test_tope_de_notas_409_y_actualizar_o_borrar_siguen_permitidos(loaded, monkeypatch):
    monkeypatch.setattr(routes_triage, "MAX_NOTES", 2)
    assert loaded.put("/api/sessions/0/note", json={"note": "a"}).status_code == 200
    assert loaded.put("/api/sessions/1/note", json={"note": "b"}).status_code == 200
    r = loaded.put("/api/sessions/2/note", json={"note": "c"})
    assert r.status_code == 409 and "demasiadas notas" in r.json()["detail"]
    assert "note" not in items(loaded)[2]
    # una existente se puede editar aunque estemos al tope
    assert loaded.put("/api/sessions/1/note", json={"note": "b2"}).status_code == 200
    # borrar una libera lugar
    assert loaded.put("/api/sessions/0/note", json={}).status_code == 200
    assert loaded.put("/api/sessions/2/note", json={"note": "c"}).status_code == 200


def test_tope_real_de_notas():
    assert routes_triage.MAX_NOTES == 5000


# ========================================================================= IOC
def test_iocs_estado_inicial(client):
    assert client.get("/api/iocs").json() == EMPTY


def test_iocs_sin_analisis_cargan_con_cero_sesiones(client, tmp_path):
    r = load_ioc(client, tmp_path, "1.2.3.4\n10.0.0.0/8\nevil.com\n", "mia.txt")
    assert r == {"loaded": True, "source": "mia.txt", "ips": 1, "networks": 1, "domains": 1, "sessions": 0}


def test_iocs_cargar_marca_sesiones_y_resumen(loaded, tmp_path):
    r = load_ioc(loaded, tmp_path, "# c2\n93.184.216.34\n203.0.113.0/24\nevil.com\n", "feed.txt")
    assert r["sessions"] == 2 and r["ips"] == 1 and r["networks"] == 1 and r["domains"] == 1
    s = items(loaded)
    assert s[3]["ioc"] == ["ip:93.184.216.34"] and s[4]["ioc"] == ["ip:93.184.216.34"]
    assert [i for i, x in s.items() if "ioc" in x] == [3, 4]
    assert loaded.get("/api/iocs").json() == r


def test_iocs_red_marca_por_cidr(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "192.168.1.64/26\n")
    s = items(loaded)
    assert s[6]["ioc"] == ["red:192.168.1.64/26"]
    assert "ioc" not in s[0]


def test_iocs_sin_coincidencias_no_pone_clave(loaded, tmp_path):
    r = load_ioc(loaded, tmp_path, "9.9.9.9\n")
    assert r["sessions"] == 0
    assert all("ioc" not in x for x in items(loaded).values())


def test_iocs_se_marcan_tambien_con_filtro(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n")
    got = loaded.get("/api/sessions", params={"ip": "93.184.216.34"}).json()
    assert got["total"] == 2 and all(i["ioc"] for i in got["items"])


def test_iocs_sobreviven_a_un_nuevo_analisis(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n", "persistente.txt")
    loaded.put("/api/sessions/3/note", json={"note": "n"})
    assert loaded.post("/api/demo").status_code == 200
    st = loaded.get("/api/iocs").json()
    assert st["loaded"] is True and st["source"] == "persistente.txt" and st["sessions"] == 2
    assert items(loaded)[3]["ioc"] == ["ip:93.184.216.34"]
    assert "note" not in items(loaded)[3]  # pero las notas sí se reiniciaron


def test_iocs_reemplazar_lista(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n", "a.txt")
    r = load_ioc(loaded, tmp_path, "192.168.1.66\n", "b.txt")
    assert r["source"] == "b.txt" and r["sessions"] == 25
    assert "ioc" not in items(loaded)[3]


def test_iocs_solo_guarda_el_nombre_no_la_ruta(client, tmp_path):
    sub = tmp_path / "carpeta-privada"
    sub.mkdir()
    r = client.post("/api/iocs", json={"path": str(ioc_file(sub, "1.1.1.1\n", "x.txt"))})
    assert r.json()["source"] == "x.txt"
    assert "carpeta-privada" not in r.text
    assert "carpeta-privada" not in client.get("/api/iocs").text
    assert client.app.state.ctx.state.iocs_name == "x.txt"


def test_iocs_quitar(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n")
    r = loaded.delete("/api/iocs")
    assert r.status_code == 200 and r.json() == EMPTY
    assert loaded.get("/api/iocs").json() == EMPTY
    assert all("ioc" not in x for x in items(loaded).values())
    assert loaded.delete("/api/iocs").json() == EMPTY  # idempotente


def test_iocs_archivo_inexistente_404(client, tmp_path):
    r = client.post("/api/iocs", json={"path": str(tmp_path / "no.txt")})
    assert r.status_code == 404 and r.json()["detail"] == "el archivo no existe"


def test_iocs_carpeta_400(client, tmp_path):
    r = client.post("/api/iocs", json={"path": str(tmp_path)})
    assert r.status_code == 400 and "carpeta" in r.json()["detail"]


def test_iocs_contenido_invalido_422_con_linea(client, tmp_path):
    p = ioc_file(tmp_path, "1.1.1.1\nbasura!!\n")
    r = client.post("/api/iocs", json={"path": str(p)})
    assert r.status_code == 422 and "línea 2" in r.json()["detail"]


def test_iocs_archivo_vacio_o_binario_422(client, tmp_path):
    assert client.post("/api/iocs", json={"path": str(ioc_file(tmp_path, "# nada\n"))}).status_code == 422
    b = tmp_path / "b.bin"
    b.write_bytes(b"\xff\xfe\x00\x80")
    assert client.post("/api/iocs", json={"path": str(b)}).status_code == 422


def test_iocs_red_cero_422(client, tmp_path):
    r = client.post("/api/iocs", json={"path": str(ioc_file(tmp_path, "0.0.0.0/0\n"))})
    assert r.status_code == 422 and "/0" in r.json()["detail"]


def test_iocs_error_no_cambia_la_lista_cargada(client, tmp_path):
    load_ioc(client, tmp_path, "1.1.1.1\n", "buena.txt")
    bad = ioc_file(tmp_path, "mala!!\n", "mala.txt")
    assert client.post("/api/iocs", json={"path": str(bad)}).status_code == 422
    assert client.get("/api/iocs").json()["source"] == "buena.txt"


def test_iocs_peticion_invalida_422(client):
    assert client.post("/api/iocs", json={}).status_code == 422
    assert client.post("/api/iocs", json={"path": ""}).status_code == 422
    assert client.post("/api/iocs", json={"path": "x" * 4097}).status_code == 422


def test_iocs_ruta_con_tilde_se_expande(client, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    ioc_file(tmp_path, "1.1.1.1\n", "casa.txt")
    r = client.post("/api/iocs", json={"path": "~/casa.txt"})
    assert r.status_code == 200 and r.json()["source"] == "casa.txt"


# ===================================================================== informe
def test_informe_sin_analisis_409(client):
    assert client.get("/api/report").status_code == 409


def test_informe_cabeceras_y_contenido(loaded):
    r = loaded.get("/api/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["content-disposition"] == 'attachment; filename="tracewell-informe.html"'
    h = r.text
    assert h.startswith("<!doctype html>") and "demo.pcap" in h
    assert "Escaneo de puertos" in h and "Credenciales FTP en texto claro" in h
    assert "<h2>Sesiones destacadas</h2>" in h
    assert "Indicadores (IOC)" not in h
    assert "<script" not in h.lower()
    assert str(ROOT) not in h and "samples" not in h


def test_informe_incluye_notas_e_ioc(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n", "feed.txt")
    loaded.put("/api/sessions/0/note", json={"note": "nota-del-analista", "reviewed": True})
    h = loaded.get("/api/report").text
    assert "nota-del-analista" in h and "revisada" in h
    assert "Indicadores (IOC)" in h and "<code>feed.txt</code>" in h
    assert "IOC: ip:93.184.216.34" in h
    assert "sesiones con coincidencias: <strong>2</strong>" in h
    assert str(tmp_path) not in h  # nunca la ruta de la lista


def test_informe_sesion_anotada_entra_aunque_no_sea_pesada(loaded):
    # la sesión 16 (54 bytes) no está entre las 10 más pesadas
    assert "visible-aunque-liviana" not in loaded.get("/api/report").text
    loaded.put("/api/sessions/16/note", json={"note": "visible-aunque-liviana"})
    assert "visible-aunque-liviana" in loaded.get("/api/report").text


def test_informe_sin_notas_de_otro_analisis(loaded):
    loaded.put("/api/sessions/0/note", json={"note": "vieja-nota"})
    loaded.post("/api/demo")
    assert "vieja-nota" not in loaded.get("/api/report").text


def test_informe_escapa_notas_y_evidencia_hostiles(tmp_path):
    app = create_app(sampler_factory=None)
    c = TestClient(app)
    app.state.ctx.state.analysis = hostile_analysis()
    assert c.put("/api/sessions/0/note", json={"note": f"{XSS} \"'&"}).status_code == 200
    h = c.get("/api/report").text
    assert XSS not in h and "<script" not in h.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "&quot;" in h or "&#x27;" in h
    assert "cap.pcap" in h and "privado" not in h and "secreto" not in h and "Users" not in h


def test_informe_nombre_de_lista_ioc_hostil_se_escapa(tmp_path):
    app = create_app(sampler_factory=None)
    c = TestClient(app)
    app.state.ctx.state.analysis = hostile_analysis()
    name = "a&b'c.txt"  # nombre válido en Windows y Linux
    load_ioc(c, tmp_path, "10.0.0.2\n", name)
    h = c.get("/api/report").text
    assert "a&amp;b&#x27;c.txt" in h


def test_informe_processes_sin_datos_no_agrega_columna_llena(loaded):
    # captura de archivo: ?processes=true es inocuo (no hay tabla de procesos)
    plain = loaded.get("/api/report").text
    asked = loaded.get("/api/report", params={"processes": "true"})
    assert asked.status_code == 200
    assert asked.text == plain.replace(re.search(r"Generado por Tracewell el [^<]*", plain).group(0),
                                       re.search(r"Generado por Tracewell el [^<]*", asked.text).group(0))


def test_informe_processes_valor_invalido_422(loaded):
    assert loaded.get("/api/report", params={"processes": "quizas"}).status_code == 422


class _Table:
    def lookup(self, proto, sip, sport, dip, dport):
        class P:
            pid, name = 77, "<b>miproc.exe</b>"
        return P if sip == "10.0.0.1" else None


def _con_procesos():
    app = create_app(sampler_factory=None)
    app.state.ctx.state.analysis = hostile_analysis()
    app.state.ctx.state.processes = _Table()
    return app, TestClient(app)


def test_informe_procesos_solo_con_flag_y_datos():
    app, c = _con_procesos()
    assert "miproc" not in c.get("/api/report").text  # por defecto NO salen
    h = c.get("/api/report", params={"processes": "true"}).text
    assert "&lt;b&gt;miproc.exe&lt;/b&gt;" in h and "<b>" not in h


def test_informe_flag_processes_sin_tabla_no_incluye_nada():
    app, c = _con_procesos()
    app.state.ctx.state.processes = None
    assert "miproc" not in c.get("/api/report", params={"processes": "true"}).text


def test_informe_alerta_sin_alertas_ni_sesiones(tmp_path):
    app = create_app(sampler_factory=None)
    c = TestClient(app)
    a = hostile_analysis()
    a.alerts, a.result.sessions = [], []
    a.__post_init__()
    app.state.ctx.state.analysis = a
    r = c.get("/api/report")
    assert r.status_code == 200 and "No hay alertas." in r.text
    assert "Sesiones destacadas" not in r.text


def test_informe_ioc_no_cargada_no_tiene_seccion_y_quitar_la_saca(loaded, tmp_path):
    load_ioc(loaded, tmp_path, "93.184.216.34\n")
    assert "Indicadores (IOC)" in loaded.get("/api/report").text
    loaded.delete("/api/iocs")
    assert "Indicadores (IOC)" not in loaded.get("/api/report").text
