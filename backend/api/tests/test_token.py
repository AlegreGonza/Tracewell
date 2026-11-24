"""Token de la API: toda ruta /api lo exige; la interfaz estática carga sin él."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.api.security import TOKEN_HEADER, TicketStore, make_token_check

TOKEN = "t0ken-de-prueba"


@pytest.fixture
def client(tmp_path):
    (tmp_path / "index.html").write_text("<html>ui</html>", encoding="utf-8")
    app = create_app(sampler_factory=None, api_token=TOKEN, frontend_dir=tmp_path)
    return TestClient(app)


@pytest.mark.parametrize("method,path", [
    ("get", "/api/health"), ("get", "/api/capture"), ("get", "/api/system/processes"),
    ("post", "/api/analyze"), ("post", "/api/demo"), ("post", "/api/live/start"),
    ("post", "/api/support/ping"), ("delete", "/api/capture"),
])
def test_sin_token_es_401(client, method, path):
    r = getattr(client, method)(path)
    assert r.status_code == 401 and "token" in r.json()["detail"]


def test_sin_token_no_ejecuta_la_accion(client):
    # el rechazo ocurre antes de la ruta: un /api/analyze sin token no llega a abrir el archivo
    r = client.post("/api/analyze", json={"path": "C:/no/existe.pcap"})
    assert r.status_code == 401


@pytest.mark.parametrize("bad", ["", "otro", TOKEN + "x", TOKEN[:-1]])
def test_token_incorrecto_es_401(client, bad):
    assert client.get("/api/health", headers={TOKEN_HEADER: bad}).status_code == 401


def test_token_en_la_cabecera_pasa(client):
    assert client.get("/api/health", headers={TOKEN_HEADER: TOKEN}).status_code == 200


def test_el_token_ya_no_vale_en_la_url(client):
    # el token real solo viaja en la cabecera: en la URL quedaría en historiales y registros
    assert client.get("/api/health", params={"token": TOKEN}).status_code == 401


def pedir_ticket(client, path):
    return client.post("/api/download-ticket", json={"path": path}, headers={TOKEN_HEADER: TOKEN})


def test_ticket_de_descarga_vale_una_vez_y_para_su_ruta(client):
    t = pedir_ticket(client, "/api/report").json()["ticket"]
    # pasa la autenticación (la ruta responde 409 porque no hay captura cargada)
    assert client.get("/api/report", params={"ticket": t}).status_code == 409
    assert client.get("/api/report", params={"ticket": t}).status_code == 401  # un solo uso


def test_ticket_de_otra_ruta_no_sirve(client):
    t = pedir_ticket(client, "/api/report").json()["ticket"]
    assert client.get("/api/export", params={"ticket": t}).status_code == 401
    assert client.get("/api/health", params={"ticket": t}).status_code == 401


def test_ticket_no_sirve_para_post(client):
    t = pedir_ticket(client, "/api/export").json()["ticket"]
    assert client.post("/api/demo", params={"ticket": t}).status_code == 401


def test_pedir_un_ticket_exige_el_token(client):
    assert client.post("/api/download-ticket", json={"path": "/api/report"}).status_code == 401


@pytest.mark.parametrize("path", [
    "/api/analyze", "/api/health", "/api/sessions", "/api/system/processes", "/api/report?x=1",
    "/api/sessions/x/pcap", "/api/sessions/1/http/abc/body", "../api/report",
])
def test_solo_se_dan_tickets_para_rutas_de_descarga(client, path):
    assert pedir_ticket(client, path).status_code == 422


@pytest.mark.parametrize("path", [
    "/api/export", "/api/report", "/api/pcap", "/api/sessions/3/pcap", "/api/sessions/3/http/0/body",
])
def test_rutas_de_descarga_permitidas(client, path):
    assert pedir_ticket(client, path).status_code == 200


def test_ticket_vence_y_los_pendientes_tienen_tope():
    ahora = [100.0]
    store = TicketStore(ttl=30, limit=3, clock=lambda: ahora[0])
    viejo = store.issue("/api/export")
    ahora[0] = 131.0
    assert store.redeem("/api/export", viejo) is False  # venció
    ts = [store.issue("/api/export") for _ in range(4)]
    assert store.redeem("/api/export", ts[0]) is False  # el más viejo se descartó por el tope
    assert store.redeem("/api/export", ts[3]) is True
    assert store.redeem("/api/export", "inventado") is False


def test_con_token_no_se_publica_el_mapa_de_la_api(client):
    for ruta in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(ruta).status_code == 404


def test_sin_token_explicito_se_genera_uno_y_se_exige():
    app = create_app(sampler_factory=None)
    assert len(app.state.api_token) >= 32 and app.state.token_generated
    assert create_app(sampler_factory=None).state.api_token != app.state.api_token
    c = TestClient(app, headers={TOKEN_HEADER: ""})  # sin token válido
    for method, path in [("get", "/api/health"), ("get", "/api/capture"), ("post", "/api/demo"),
                         ("post", "/api/analyze"), ("get", "/openapi.json"), ("get", "/docs")]:
        assert getattr(c, method)(path).status_code in (401, 403, 404)
    assert c.get("/api/health").status_code == 401
    assert c.post("/api/analyze", json={"path": "x.pcap"}).status_code == 401
    assert c.get("/api/health", headers={TOKEN_HEADER: app.state.api_token}).status_code == 200


def test_la_interfaz_estatica_carga_sin_token(client):
    r = client.get("/")
    assert r.status_code == 200 and "ui" in r.text


def test_no_existe_modo_sin_autenticacion():
    app = create_app(sampler_factory=None, api_token=None)
    c = TestClient(app, headers={TOKEN_HEADER: ""})
    assert c.get("/api/health").status_code == 401


def test_el_401_lleva_las_cabeceras_de_seguridad(client):
    r = client.get("/api/health")
    assert r.status_code == 401 and "content-security-policy" in r.headers


def test_make_token_check_rechaza_token_vacio_o_nulo():
    for bad in (None, ""):
        with pytest.raises((ValueError, AttributeError)):
            make_token_check(bad)
