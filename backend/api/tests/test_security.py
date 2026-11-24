"""Defensas Host/Origin de la API (DNS rebinding y CSRF desde páginas externas)."""
import pytest
from fastapi.testclient import TestClient

from backend.api.app import ROOT, create_app

DEMO = ROOT / "samples" / "demo.pcap"


def client_for(host="127.0.0.1", **kw):
    return TestClient(create_app(**{"sampler_factory": None, **kw}), base_url=f"http://{host}")


# ------------------------------------------------------------------ Host
@pytest.mark.parametrize("path", ["/api/health", "/api/capture", "/api/interfaces", "/"])
def test_host_ajeno_400(path):
    r = client_for("evil.com").get(path)
    assert r.status_code == 400 and r.text == "Invalid host header"


def test_host_ajeno_con_puerto_400():
    assert client_for("evil.com:8000").get("/api/health").status_code == 400


def test_host_ajeno_en_post_no_ejecuta():
    c = client_for("evil.com")
    assert c.post("/api/demo").status_code == 400
    app = create_app(sampler_factory=None)
    assert TestClient(app, base_url="http://evil.com").post("/api/demo").status_code == 400
    assert TestClient(app, base_url="http://127.0.0.1").get("/api/capture").status_code == 409


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:8000", "localhost", "localhost:5173", "LOCALHOST"])
def test_host_local_ok(host):
    r = client_for(host).get("/api/health")
    assert r.status_code == 200


@pytest.mark.parametrize("host", ["127.0.0.1.evil.com", "evil.com.localhost.evil.com", "0.0.0.0", "[::2]"])
def test_host_parecido_o_no_listado_400(host):
    assert client_for(host).get("/api/health").status_code == 400


@pytest.mark.parametrize("host", ["[::1]", "[::1]:8000", "[::1]:5173"])
def test_host_ipv6_loopback_ok(host):
    assert client_for(host).get("/api/health").status_code == 200


def test_host_ipv6_con_origin_ipv6_ok_y_ajeno_sigue_rechazado():
    c = client_for("[::1]:8000")
    assert c.get("/api/health", headers={"Origin": "http://[::1]:8000"}).status_code == 200
    assert c.get("/api/health", headers={"Origin": "http://evil.com"}).status_code == 403
    assert client_for("evil.com").get("/api/health").status_code == 400
    assert client_for("evil.com:8000").get("/api/health").status_code == 400


def test_allowed_hosts_custom():
    c = client_for("miapp.local", allowed_hosts=("miapp.local",))
    assert c.get("/api/health").status_code == 200
    # el default ya no vale
    assert client_for("127.0.0.1", allowed_hosts=("miapp.local",)).get("/api/health").status_code == 400
    # y un Origin con el host custom se acepta; con uno local por defecto, no
    assert c.get("/api/health", headers={"Origin": "http://miapp.local:3000"}).status_code == 200
    assert c.get("/api/health", headers={"Origin": "http://localhost"}).status_code == 403


def test_allowed_hosts_case_insensitive():
    assert client_for("miapp.local", allowed_hosts=("MiApp.Local",)).get("/api/health").status_code == 200


# ---------------------------------------------------------------- Origin
@pytest.mark.parametrize("origin", ["http://127.0.0.1:8000", "http://localhost:5173", "http://localhost",
                                    "https://127.0.0.1", "http://LOCALHOST:80"])
def test_origin_local_permitido(origin):
    assert client_for().get("/api/health", headers={"Origin": origin}).status_code == 200


def test_sin_origin_permitido():
    assert client_for().get("/api/health").status_code == 200


def test_origin_ajeno_get_403():
    r = client_for().get("/api/health", headers={"Origin": "http://evil.com"})
    assert r.status_code == 403 and r.json() == {"detail": "origen no permitido"}


def test_origin_ajeno_post_403_y_no_ejecuta():
    c = client_for()
    r = c.post("/api/demo", headers={"Origin": "http://evil.com"})
    assert r.status_code == 403 and r.json() == {"detail": "origen no permitido"}
    assert c.get("/api/capture").status_code == 409  # no se cargó el demo


def test_origin_ajeno_analyze_no_cambia_el_analisis():
    c = client_for()
    assert c.post("/api/demo").status_code == 200
    before = c.get("/api/capture").json()
    r = c.post("/api/analyze", json={"path": str(DEMO.parent / "nada.pcap")}, headers={"Origin": "http://evil.com"})
    assert r.status_code == 403
    # ni siquiera se evaluó la ruta (si no, daría 404)
    assert c.get("/api/capture").json() == before


def test_origin_ajeno_no_arranca_captura():
    c = client_for()
    r = c.post("/api/live/start", json={"interface": "eth0"}, headers={"Origin": "http://evil.com"})
    assert r.status_code == 403
    assert c.get("/api/live/status").json()["state"] == "idle"


def test_origin_ajeno_en_estaticos_403(tmp_path):
    (tmp_path / "index.html").write_text("hola")
    c = client_for(frontend_dir=tmp_path)
    assert c.get("/", headers={"Origin": "http://evil.com"}).status_code == 403
    assert c.get("/").status_code == 200


def test_origin_null_403():
    # páginas sandboxed / file:// / redirecciones cross-origin mandan "null"
    r = client_for().get("/api/health", headers={"Origin": "null"})
    assert r.status_code == 403


@pytest.mark.parametrize("origin", [
    "evil", "javascript:alert(1)", "http://127.0.0.1.evil.com", "http://user@evil.com",
    "http://evil.com#@127.0.0.1", "file://", "http://",
    "ftp://evil.com", "http://localhost.evil.com", "//evil.com",
])
def test_origin_malformado_o_ajeno_403_nunca_500(origin):
    r = client_for().get("/api/health", headers={"Origin": origin})
    assert r.status_code == 403, origin


def test_origin_vacio_se_rechaza_403():
    # Comportamiento real: Origin presente pero vacío NO se trata como ausente.
    r = client_for().get("/api/health", headers={"Origin": ""})
    assert r.status_code == 403


def test_origin_con_userinfo_local_se_permite():
    # hostname real = 127.0.0.1 (lo antes del @ es credencial): permitido.
    r = client_for().get("/api/health", headers={"Origin": "http://evil.com@127.0.0.1"})
    assert r.status_code == 200


def test_origin_con_backslash_y_host_local_se_permite():
    # urlparse toma "evil.com\" como userinfo
    r = client_for().get("/api/health", headers={"Origin": "http://evil.com\\@127.0.0.1"})
    assert r.status_code == 200


def test_origin_puerto_invalido_no_da_500():
    # urlparse().hostname no valida el puerto: se permite si el host es local.
    r = client_for().get("/api/health", headers={"Origin": "http://127.0.0.1:99999"})
    assert r.status_code in (200, 403)


def test_origin_ipv6_con_puerto_invalido_no_da_500():
    # [::1] es local (igual que 127.0.0.1): urlparse no valida el puerto y no debe lanzar un 500
    r = client_for().get("/api/health", headers={"Origin": "http://[::1]:abc"})
    assert r.status_code in (200, 403)


@pytest.mark.parametrize("origin", [
    "http://[::1", "http://[evil", "http://[", "http://]", "http://%",
    "http://\x00", "http://" + "a" * 10_000,
])
def test_origin_ilegible_es_403_nunca_500(origin):
    # urlparse lanza ValueError con estos Origin; el middleware lo captura y responde 403.
    c = TestClient(create_app(sampler_factory=None), base_url="http://127.0.0.1", raise_server_exceptions=False)
    try:
        r = c.get("/api/health", headers={"Origin": origin})
    except Exception as e:  # httpx puede rechazar el header (p. ej. \x00) antes de enviar
        pytest.skip(f"cliente rechaza el header: {e}")
    assert r.status_code == 403, origin


@pytest.mark.parametrize("origin", ["http://%00evil.com", "http://evil"])
def test_origin_raro_no_da_500(origin):
    c = TestClient(create_app(sampler_factory=None), base_url="http://127.0.0.1", raise_server_exceptions=False)
    try:
        r = c.get("/api/health", headers={"Origin": origin})
    except Exception as e:  # httpx puede rechazar el header antes de enviar
        pytest.skip(f"cliente rechaza el header: {e}")
    assert r.status_code in (200, 403)


# ------------------------------------------------------- cabeceras de seguridad
CABECERAS = {"x-frame-options": "DENY", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}


def _csp_ok(r):
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp  # la UI (Radix/sonner) usa estilos en línea
    assert "unsafe-eval" not in csp and "script-src 'self' 'unsafe-inline'" not in csp


def _cabeceras_ok(r):
    for k, v in CABECERAS.items():
        assert r.headers[k] == v, k
    _csp_ok(r)


def test_cabeceras_en_api_y_estaticos(tmp_path):
    (tmp_path / "index.html").write_text("hola")
    c = client_for(frontend_dir=tmp_path)
    _cabeceras_ok(c.get("/api/health"))
    _cabeceras_ok(c.get("/"))
    _cabeceras_ok(c.get("/api/no-existe"))  # 404 de la API


def test_cabeceras_tambien_en_los_rechazos_de_host_y_origin():
    _cabeceras_ok(client_for("evil.com").get("/api/health"))
    _cabeceras_ok(client_for().get("/api/health", headers={"Origin": "http://evil.com"}))


def test_cabecera_fijada_por_la_ruta_no_se_duplica(tmp_path):
    # una ruta que ya manda nosniff (descarga de cuerpos HTTP) deja un solo valor
    from fastapi import Response
    app = create_app(sampler_factory=None, frontend_dir=tmp_path / "sin_front")

    @app.get("/uno")
    def uno():
        return Response("x", headers={"X-Content-Type-Options": "nosniff"})

    r = TestClient(app, base_url="http://127.0.0.1").get("/uno")
    assert r.headers.get_list("x-content-type-options") == ["nosniff"]


def test_cabeceras_en_el_error_500(tmp_path):
    app = create_app(sampler_factory=None, frontend_dir=tmp_path / "sin_front")

    @app.get("/boom")
    def boom():
        raise RuntimeError("x")

    r = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    _cabeceras_ok(r)
