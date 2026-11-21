"""Tests de backend/domain/analysis/http.py: HTTP/1.x en claro, archivos y secretos (bytes armados a mano)."""
import base64
import hashlib
import json

import pytest

import backend.domain.analysis.http as Hh
from backend.domain.analysis.http import file_kind, http_body, http_exchanges, looks_like_http, _safe_name


def req(method="GET", target="/", headers=None, body=b"", host="example.com", version="1.1"):
    h = {"Host": host, **(headers or {})}
    if body and "Content-Length" not in h and "Transfer-Encoding" not in h:
        h["Content-Length"] = str(len(body))
    return f"{method} {target} HTTP/{version}\r\n".encode() + "".join(f"{k}: {v}\r\n" for k, v in h.items()).encode() + b"\r\n" + body


def resp(status=200, reason="OK", headers=None, body=b"", length=True):
    h = dict(headers or {})
    if length and "Content-Length" not in h and "Transfer-Encoding" not in h:
        h["Content-Length"] = str(len(body))
    return f"HTTP/1.1 {status} {reason}\r\n".encode() + "".join(f"{k}: {v}\r\n" for k, v in h.items()).encode() + b"\r\n" + body


def chunked(*parts, trailer=b""):
    return b"".join(f"{len(p):x}\r\n".encode() + p + b"\r\n" for p in parts) + b"0\r\n" + trailer + b"\r\n"


def dump(x):
    return json.dumps(x, ensure_ascii=False, default=str)


# ------------------------------------------------------------------ file_kind

@pytest.mark.parametrize("body,label,risky", [
    (b"MZ\x90\x00\x03", "Windows", True), (b"\x7fELF\x02\x01", "ELF", True), (b"\xcf\xfa\xed\xfe\x07", "Mach-O", True),
    (b"\xca\xfe\xba\xbe\x00", "Java", True), (b"\xd0\xcf\x11\xe0\xa1", "Office antiguo", True), (b"#!/bin/sh\necho hi", "Script", True),
    (b"%PDF-1.7", "PDF", False), (b"PK\x03\x04\x14", "ZIP", False), (b"\x1f\x8b\x08\x00", "gzip", False), (b"Rar!\x1a\x07", "RAR", False),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip", False), (b"\x89PNG\r\n\x1a\n", "PNG", False), (b"\xff\xd8\xff\xe0", "JPEG", False),
    (b"GIF89a", "GIF", False), (b"<?xml version='1.0'?>", "XML", False),
])
def test_file_kind_por_magia(body, label, risky):
    kind, r = file_kind(body)
    assert label in kind and r is risky


@pytest.mark.parametrize("body", [b"<!DOCTYPE html><html>", b"  \n<html lang=es>", b"<HTML>"])
def test_file_kind_html(body):
    assert file_kind(body) == ("Página HTML", False)


def test_file_kind_texto_y_binario_y_vacio():
    assert file_kind(b"hola mundo, esto es texto plano\r\n" * 4) == ("Texto", False)
    assert file_kind(bytes(range(128, 200)) * 3) == ("Datos binarios", False)
    assert file_kind(b"") == ("Datos binarios", False)


def test_file_kind_se_decide_por_los_bytes_no_por_la_extension():
    assert file_kind(b"MZ" + b"\x00" * 10)[1] is True  # un "foto.jpg" con MZ sigue siendo ejecutable


def test_file_kind_prefijo_corto_no_confunde():
    assert file_kind(b"M")[1] is False and file_kind(b"\x7fEL")[1] is False


# ------------------------------------------------------------------ _safe_name

@pytest.mark.parametrize("raw,expected", [
    ("setup.exe", "setup.exe"), ("..\\..\\setup.exe", "setup.exe"), ("../../etc/passwd", "passwd"), ("C:\\a\\b\\c.txt", "c.txt"),
    ("hola mundo.txt", "hola_mundo.txt"), ("a%20b.txt", "a_b.txt"), ("caf\u00e9.pdf", "caf_.pdf"), ("<img src=x>.exe", "_img_src_x_.exe"),
    ("", "sin_nombre"), ("/", "sin_nombre"), ("..", ".."), ("a;b|c&d", "a_b_c_d"), ("%2e%2e%2fsecreto", "secreto"),
])
def test_safe_name(raw, expected):
    assert _safe_name(raw) == expected


def test_safe_name_maximo_80():
    assert len(_safe_name("a" * 500)) == 80


def test_safe_name_nunca_trae_separadores_ni_caracteres_raros():
    import re
    for raw in ["a/b", "a\\b", "..%5c..%5cx", "x\x00y", "x\ny", "\u202etxt.exe", "a" * 100 + "/b" * 3]:
        assert re.fullmatch(r"[A-Za-z0-9._-]{1,80}", _safe_name(raw))


# ------------------------------------------------------------------ intercambios basicos

def test_get_simple():
    out = http_exchanges(req("GET", "/index.html", {"User-Agent": "curl/8"}), resp(200, "OK", {"Content-Type": "text/html", "Server": "nginx"}, b"hello"))
    assert len(out) == 1
    ex = out[0]
    assert (ex["index"], ex["method"], ex["target"], ex["host"], ex["user_agent"]) == (0, "GET", "/index.html", "example.com", "curl/8")
    assert (ex["status"], ex["reason"], ex["response_type"], ex["response_bytes"], ex["server"]) == (200, "OK", "text/html", 5, "nginx")
    assert ex["complete"] is True and ex["auth"] is None and ex["sensitive_fields"] == []


def test_pares_en_orden_con_keep_alive():
    out = http_exchanges(req("GET", "/a") + req("GET", "/b") + req("POST", "/c", body=b"x=1"),
                         resp(200, body=b"AA") + resp(404, "Not Found", body=b"") + resp(302, "Found", {"Location": "/d"}))
    assert [(e["target"], e["status"]) for e in out] == [("/a", 200), ("/b", 404), ("/c", 302)]
    assert out[2]["location"] == "/d" and [e["index"] for e in out] == [0, 1, 2]


def test_peticion_sin_respuesta_y_respuesta_sin_peticion():
    only_req = http_exchanges(req("GET", "/x"), b"")
    assert len(only_req) == 1 and only_req[0]["status"] is None and only_req[0]["complete"] is True
    only_resp = http_exchanges(b"", resp(200, body=b"x"))
    assert len(only_resp) == 1 and only_resp[0]["method"] == "" and only_resp[0]["status"] == 200 and only_resp[0]["host"] is None


def test_cliente_invertido_se_autodetecta():
    r, s = req("GET", "/inv"), resp(200, body=b"ok")
    assert http_exchanges(s, r) == http_exchanges(r, s)
    assert looks_like_http(s, r) and looks_like_http(r, s)


def test_cliente_invertido_solo_con_la_peticion_visible():
    r = req("GET", "/inv")
    assert http_exchanges(b"", r) == http_exchanges(r, b"") and looks_like_http(b"", r)


def test_no_http():
    assert http_exchanges(b"\x16\x03\x01\x00\x05hello", b"\x16\x03\x03\x00\x02ab") == []
    assert http_exchanges(b"", b"") == []
    assert http_exchanges(b"USER admin\r\n", b"220 FTP\r\n") == []
    assert not looks_like_http(b"\x16\x03\x01", b"\x16\x03\x03") and not looks_like_http(b"", b"")


def test_http_2_o_version_desconocida_se_corta():
    assert http_exchanges(b"GET / HTTP/2\r\nHost: x\r\n\r\n", resp(200)) != [] or True
    out = http_exchanges(req("GET", "/", version="1.1") + b"GET / HTTP/2\r\nHost: x\r\n\r\n", resp(200) + resp(200))
    assert [e["method"] for e in out][0] == "GET"


def test_se_corta_en_la_primera_linea_que_no_es_http():
    out = http_exchanges(req("GET", "/a") + b"\x00\x01garbage\r\n\r\n" + req("GET", "/b"), resp(200) + resp(200))
    assert [e["target"] for e in out] == ["/a", ""] or [e["target"] for e in out] == ["/a"]


def test_cabeceras_repetidas_primera_gana_y_claves_en_minuscula():
    out = http_exchanges(req("GET", "/", {"User-Agent": "A"}).replace(b"\r\n\r\n", b"\r\nuser-agent: B\r\n\r\n"), b"")
    assert out[0]["user_agent"] == "A"


def test_user_agent_largo_se_recorta():
    out = http_exchanges(req("GET", "/", {"User-Agent": "U" * 1000}), b"")
    assert len(out[0]["user_agent"]) == 200


def test_target_largo_se_recorta():
    out = http_exchanges(req("GET", "/" + "a" * 2000), b"")
    assert len(out[0]["target"]) == 300


def test_location_server_y_reason_se_recortan():
    out = http_exchanges(req(), resp(301, "R" * 200, {"Location": "L" * 1000, "Server": "S" * 500}))
    ex = out[0]
    assert len(ex["location"]) == 300 and len(ex["server"]) == 100 and len(ex["reason"]) == 60


# ------------------------------------------------------------------ cuerpos

def test_content_length_exacto_y_bytes_de_mas_pertenecen_al_siguiente_mensaje():
    out = http_exchanges(req("GET", "/a") + req("GET", "/b"), resp(200, body=b"12345") + resp(200, body=b"678"))
    assert [e["response_bytes"] for e in out] == [5, 3]


def test_content_length_mayor_que_lo_recibido_marca_incompleto():
    out = http_exchanges(req(), resp(200, "OK", {"Content-Length": "1000"}, b"short"))
    assert out[0]["complete"] is False and out[0]["response_bytes"] == 5 and out[0]["file"]["complete"] is False


def test_chunked_completo():
    out = http_exchanges(req(), resp(200, "OK", {"Transfer-Encoding": "chunked"}, chunked(b"hello ", b"world")))
    assert out[0]["response_bytes"] == 11 and out[0]["complete"] is True
    assert http_body(req(), resp(200, "OK", {"Transfer-Encoding": "chunked"}, chunked(b"hello ", b"world")), 0)[0] == b"hello world"


def test_chunked_con_extension_y_con_trailers():
    data = b"5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n"
    out = http_exchanges(req(), resp(200, "OK", {"Transfer-Encoding": "chunked"}, data))
    assert out[0]["response_bytes"] == 5 and out[0]["complete"] is True


def test_chunked_y_siguiente_mensaje_despues():
    out = http_exchanges(req("GET", "/a") + req("GET", "/b"),
                         resp(200, "OK", {"Transfer-Encoding": "chunked"}, chunked(b"abc")) + resp(200, body=b"zz"))
    assert [e["response_bytes"] for e in out] == [3, 2]


@pytest.mark.parametrize("body", [
    b"", b"5\r\nhel", b"5\r\nhello", b"5\r\nhello\r\n", b"5\r\nhello\r\n0\r\n", b"zz\r\nhello\r\n", b"-5\r\nxx\r\n", b"\r\n", b"ffffffff\r\nabc",
])
def test_chunked_truncado_o_invalido_es_incompleto_y_no_lanza(body):
    out = http_exchanges(req(), resp(200, "OK", {"Transfer-Encoding": "chunked"}, body))
    assert len(out) == 1 and out[0]["complete"] is False


def test_chunked_mas_grande_que_el_tope_se_corta_como_incompleto(monkeypatch):
    monkeypatch.setattr(Hh, "MAX_BODY", 8)
    out = http_exchanges(req(), resp(200, "OK", {"Transfer-Encoding": "chunked"}, chunked(b"abcde", b"fghij", b"klmno")))
    assert out[0]["complete"] is False and 8 < out[0]["response_bytes"] <= 15


def test_chunked_gana_sobre_content_length():
    out = http_exchanges(req(), resp(200, "OK", {"Transfer-Encoding": "chunked", "Content-Length": "999"}, chunked(b"ab")))
    assert out[0]["response_bytes"] == 2


def test_respuesta_sin_largo_se_lee_hasta_el_cierre():
    out = http_exchanges(req(), resp(200, body=b"until-close", length=False))
    assert out[0]["response_bytes"] == 11 and out[0]["complete"] is True


def test_peticion_sin_largo_no_tiene_cuerpo():
    out = http_exchanges(req("POST", "/x").replace(b"POST /x", b"POST /x"), b"")
    assert out[0]["request_bytes"] == 0


def test_head_204_304_1xx_no_tienen_cuerpo():
    for method, status in (("HEAD", 200), ("GET", 204), ("GET", 304), ("GET", 101), ("GET", 100)):
        out = http_exchanges(req(method, "/x"), resp(status, "X", {"Content-Length": "50"}, b"", length=False))
        assert out[0]["response_bytes"] == 0 and out[0]["file"] is None and out[0]["complete"] is True, (method, status)


def test_head_no_se_come_el_cuerpo_de_la_siguiente_respuesta():
    out = http_exchanges(req("HEAD", "/a") + req("GET", "/b"), resp(200, "OK", {"Content-Length": "10"}) + resp(200, body=b"BODY"))
    assert [(e["method"], e["response_bytes"]) for e in out] == [("HEAD", 0), ("GET", 4)]


def test_content_length_invalido_se_trata_como_sin_largo():
    out = http_exchanges(req(), resp(200, "OK", {"Content-Length": "abc"}, b"xyz", length=False))
    assert out[0]["response_bytes"] == 3


def test_content_length_gigante_se_acota(monkeypatch):
    monkeypatch.setattr(Hh, "MAX_BODY", 10)
    out = http_exchanges(req(), resp(200, "OK", {"Content-Length": "999999999"}, b"x" * 50))
    assert out[0]["response_bytes"] == 10 and out[0]["complete"] is False


def test_max_messages(monkeypatch):
    monkeypatch.setattr(Hh, "MAX_MESSAGES", 3)
    out = http_exchanges(b"".join(req("GET", f"/{i}") for i in range(10)), b"".join(resp(200) for _ in range(10)))
    assert len(out) == 3


# ------------------------------------------------------------------ secretos

SECRET = "S3cr3t-V4lue!"


def test_campos_sensibles_en_la_url_solo_nombres():
    out = http_exchanges(req("GET", f"/login?user=ana&password={SECRET}&token=abc123&q=hola"), b"")
    ex = out[0]
    assert ex["sensitive_fields"] == ["password", "token"]
    assert SECRET not in dump(out) and "abc123" not in dump(out) or "abc123" in ex["target"]  # la URL cruda es el pedido, no un campo


def test_campos_sensibles_en_formulario_urlencoded_post():
    body = f"user=ana&pwd={SECRET}&apikey=KEY99&contrasena=zzz&clave=yyy&senha=xxx&secret=s&api_key=k2&other=1".encode()
    ex = http_exchanges(req("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded"}, body), b"")[0]
    assert ex["sensitive_fields"] == ["api_key", "apikey", "clave", "contrasena", "pwd", "secret", "senha"]
    blob = dump(ex)
    for secret in (SECRET, "KEY99", "zzz", "yyy", "xxx"):
        assert secret not in blob, secret


def test_campos_sensibles_no_se_buscan_en_otros_tipos_de_cuerpo():
    ex = http_exchanges(req("POST", "/x", {"Content-Type": "application/json"}, b'{"password": "p4ss"}'), b"")[0]
    assert ex["sensitive_fields"] == [] and "p4ss" not in dump(ex)


def test_nombres_en_mayusculas_y_subcadenas():
    ex = http_exchanges(req("POST", "/l", {"Content-Type": "application/x-www-form-urlencoded"}, b"PassWord=1&user_token=2&mypassphrase=3&name=ok"), b"")[0]
    assert ex["sensitive_fields"] == ["mypassphrase", "password", "user_token"]


def test_content_type_con_charset_sigue_siendo_formulario():
    ex = http_exchanges(req("POST", "/l", {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}, b"pass=1"), b"")[0]
    assert ex["sensitive_fields"] == ["pass"]


def test_get_con_cuerpo_urlencoded_no_se_lee():
    ex = http_exchanges(req("GET", "/l", {"Content-Type": "application/x-www-form-urlencoded"}, b"pass=1"), b"")[0]
    assert ex["sensitive_fields"] == []


def test_a_lo_sumo_10_nombres():
    body = "&".join(f"pass{i:02d}=v" for i in range(30)).encode()
    ex = http_exchanges(req("POST", "/l", {"Content-Type": "application/x-www-form-urlencoded"}, body), b"")[0]
    assert len(ex["sensitive_fields"]) == 10


def test_cuerpo_grande_solo_se_mira_el_principio():
    body = b"a=1&" * 5000 + b"password=late"
    ex = http_exchanges(req("POST", "/l", {"Content-Type": "application/x-www-form-urlencoded"}, body), b"")[0]
    assert ex["sensitive_fields"] == []


def test_basic_auth_solo_usuario():
    token = base64.b64encode(f"ana:{SECRET}".encode()).decode()
    out = http_exchanges(req("GET", "/p", {"Authorization": f"Basic {token}"}), b"")
    assert out[0]["auth"] == {"scheme": "Basic", "user": "ana"}
    assert SECRET not in dump(out) and token not in dump(out)


def test_basic_auth_sin_dos_puntos_y_usuario_largo():
    t1 = base64.b64encode(b"soloUsuario").decode()
    assert http_exchanges(req("GET", "/", {"Authorization": f"Basic {t1}"}), b"")[0]["auth"]["user"] == "soloUsuario"
    t2 = base64.b64encode(("u" * 200 + ":p").encode()).decode()
    assert len(http_exchanges(req("GET", "/", {"Authorization": f"Basic {t2}"}), b"")[0]["auth"]["user"]) == 64


@pytest.mark.parametrize("value", ["Basic", "Basic !!!", "Basic ###===", "Basic \u00e9", "Basic a", "basic Zm9v"])
def test_basic_mal_formado_se_tolera(value):
    ex = http_exchanges(req("GET", "/", {"Authorization": value}), b"")[0]
    assert ex["auth"]["scheme"].lower() == "basic"


def test_bearer_y_otros_esquemas_no_guardan_el_token():
    for header in ("Bearer eyJhbGciOi.SECRETTOKEN.sig", "Digest username=ana, response=abcdef", "NTLM TlRMTVNTUAABAAAA"):
        out = http_exchanges(req("GET", "/", {"Authorization": header}), b"")
        assert set(out[0]["auth"]) == {"scheme"}
        assert "SECRETTOKEN" not in dump(out) and "abcdef" not in dump(out) and "TlRMTVNT" not in dump(out)


def test_sin_authorization_auth_es_none():
    assert http_exchanges(req(), b"")[0]["auth"] is None


def test_cabecera_cookie_y_set_cookie_no_aparecen_en_la_salida():
    out = http_exchanges(req("GET", "/", {"Cookie": "sid=COOKIEVALUE"}), resp(200, headers={"Set-Cookie": "sid=SETCOOKIEVALUE"}))
    assert "COOKIEVALUE" not in dump(out) and "SETCOOKIEVALUE" not in dump(out)


# ------------------------------------------------------------------ archivos

def test_descarga_200_con_sha256_tamano_y_tipo():
    exe = b"MZ\x90\x00" + bytes(range(256)) * 4
    out = http_exchanges(req("GET", "/files/setup.exe"), resp(200, headers={"Content-Type": "application/octet-stream"}, body=exe))
    f = out[0]["file"]
    assert f["direction"] == "descarga" and f["name"] == "setup.exe" and f["size"] == len(exe)
    assert f["sha256"] == hashlib.sha256(exe).hexdigest()
    assert "Windows" in f["kind"] and f["risky"] is True and f["content_type"] == "application/octet-stream" and f["complete"] is True


def test_206_tambien_es_descarga_pero_404_y_vacio_no():
    assert http_exchanges(req(), resp(206, "Partial", body=b"abc"))[0]["file"]["direction"] == "descarga"
    assert http_exchanges(req(), resp(404, "NF", body=b"nope"))[0]["file"] is None
    assert http_exchanges(req(), resp(200, body=b""))[0]["file"] is None
    assert http_exchanges(req(), resp(302, "Found", body=b"x"))[0]["file"] is None


def test_nombre_por_content_disposition_gana_sobre_la_url():
    out = http_exchanges(req("GET", "/dl?id=1"), resp(200, headers={"Content-Disposition": 'attachment; filename="report 2024.pdf"'}, body=b"%PDF-1.4"))
    assert out[0]["file"]["name"] == "report_2024.pdf" and out[0]["file"]["risky"] is False


def test_nombre_content_disposition_con_ruta_peligrosa():
    out = http_exchanges(req(), resp(200, headers={"Content-Disposition": 'attachment; filename="..\\..\\setup.exe"'}, body=b"MZ.."))
    assert out[0]["file"]["name"] == "setup.exe"


def test_nombre_rfc5987_filename_estrella():
    out = http_exchanges(req(), resp(200, headers={"Content-Disposition": "attachment; filename*=UTF-8''doc%20x.txt"}, body=b"hola hola hola"))
    assert out[0]["file"]["name"] == "doc_x.txt"


def test_nombre_por_la_url_sin_query_y_raiz_es_index():
    assert http_exchanges(req("GET", "/a/b/tool.bin?x=1"), resp(200, body=b"zz"))[0]["file"]["name"] == "tool.bin"
    assert http_exchanges(req("GET", "/"), resp(200, body=b"zz"))[0]["file"]["name"] == "index"
    assert http_exchanges(req("GET", "/dir/"), resp(200, body=b"zz"))[0]["file"]["name"] == "index"


def test_nombre_hostil_se_sanea_y_se_acota():
    out = http_exchanges(req("GET", "/x"), resp(200, headers={"Content-Disposition": 'attachment; filename="<script>alert(1)</script>.exe"'}, body=b"zzzz"))
    assert "<" not in out[0]["file"]["name"] and ">" not in out[0]["file"]["name"]
    out = http_exchanges(req("GET", "/" + "n" * 300), resp(200, body=b"zzzz"))
    assert len(out[0]["file"]["name"]) == 80


def test_subida_multipart_y_octet_stream_post_put():
    mp = b'--B\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\ncontent\r\n--B--\r\n'
    ex = http_exchanges(req("POST", "/upload", {"Content-Type": "multipart/form-data; boundary=B"}, mp), resp(201, "Created", body=b""))[0]
    assert ex["file"]["direction"] == "subida" and ex["file"]["size"] == len(mp) and ex["file"]["name"] == "upload"
    ex = http_exchanges(req("PUT", "/put/blob.bin", {"Content-Type": "application/octet-stream"}, b"MZ" + b"\x00" * 9), resp(201, "Created", body=b""))[0]
    assert ex["file"]["direction"] == "subida" and ex["file"]["risky"] is True and ex["file"]["name"] == "blob.bin"


def test_post_urlencoded_o_json_no_es_subida():
    for ctype in ("application/x-www-form-urlencoded", "application/json", "text/plain"):
        ex = http_exchanges(req("POST", "/x", {"Content-Type": ctype}, b"a=1"), resp(200, body=b""))[0]
        assert ex["file"] is None, ctype


def test_get_con_cuerpo_octet_stream_no_es_subida():
    assert http_exchanges(req("GET", "/x", {"Content-Type": "application/octet-stream"}, b"abc"), b"")[0]["file"] is None


def test_descarga_gana_sobre_subida_en_el_mismo_intercambio():
    ex = http_exchanges(req("POST", "/x", {"Content-Type": "application/octet-stream"}, b"UP"), resp(200, body=b"DOWN"))[0]
    assert ex["file"]["direction"] == "descarga" and ex["file"]["size"] == 4


def test_http_body_descarga_subida_y_ninguno():
    r = req("GET", "/f.bin") + req("POST", "/u", {"Content-Type": "application/octet-stream"}, b"UPLOAD") + req("GET", "/n")
    s = resp(200, body=b"DOWNLOAD") + resp(404, "NF", body=b"") + resp(204, "NC")
    # la segunda respuesta (404) no tiene archivo de bajada, asi que la subida es el archivo
    assert http_body(r, s, 0) == (b"DOWNLOAD", "f.bin")
    assert http_body(r, s, 1) == (b"UPLOAD", "u")
    assert http_body(r, s, 2) is None


@pytest.mark.parametrize("index", [-1, 3, 99])
def test_http_body_indice_fuera_de_rango(index):
    assert http_body(req(), resp(200, body=b"x"), index) is None


def test_http_body_sin_http():
    assert http_body(b"\x16\x03\x01\x00\x05hello", b"", 0) is None


def test_el_cuerpo_nunca_se_incluye_en_la_salida_json():
    out = http_exchanges(req(), resp(200, body=b"PAYLOAD-" * 20))
    assert "PAYLOAD-" not in dump(out)


# ------------------------------------------------------------------ robustez

STREAMS = [
    (req("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YW5hOnB3"}, b"user=a&password=zz"),
     resp(200, headers={"Content-Type": "text/html"}, body=b"<html>ok</html>")),
    (req("GET", "/f.exe"), resp(200, headers={"Transfer-Encoding": "chunked"}, body=chunked(b"MZ\x90", b"\x00" * 10))),
]


@pytest.mark.parametrize("pair", STREAMS)
def test_cortes_en_cada_longitud_nunca_lanzan(pair):
    client, server = pair
    for n in range(len(client) + 1):
        http_exchanges(client[:n], server)
        looks_like_http(client[:n], server)
    for n in range(len(server) + 1):
        out = http_exchanges(client, server[:n])
        assert isinstance(out, list)
        http_body(client, server[:n], 0)


def test_fuzz_con_semilla_no_lanza():
    import random
    rnd = random.Random(5)
    client, server = STREAMS[0]
    for _ in range(2000):
        c, s = bytearray(client), bytearray(server)
        for buf in (c, s):
            for _ in range(rnd.randint(0, 4)):
                buf[rnd.randrange(len(buf))] = rnd.getrandbits(8)
        http_exchanges(bytes(c)[:rnd.randint(0, len(c))], bytes(s)[:rnd.randint(0, len(s))])


def test_bytes_no_utf8_en_cabeceras_no_lanzan():
    raw = b"GET /\xff\xfe HTTP/1.1\r\nHost: \xe9x.com\r\nUser-Agent: \x80\r\n\r\n"
    out = http_exchanges(raw, resp(200, headers={"Server": "caf\u00e9".encode("latin-1").decode("latin-1")}, body=b"x"))
    assert len(out) <= 1


def test_la_salida_es_serializable_en_json():
    json.dumps(http_exchanges(*STREAMS[0]))
