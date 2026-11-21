"""Analizador de HTTP sin cifrar: qué pidió cada cliente y qué le respondieron, y los archivos que viajaron.

Trabaja sobre los bytes ya reconstruidos de cada sentido de una sesión TCP (`raw_directions`). Con HTTPS no
hay nada que leer: el contenido va cifrado.

Reglas de seguridad (a propósito):
- NUNCA se guardan valores de contraseñas ni tokens: de un formulario solo se informan los NOMBRES de los
  campos sensibles, y de una autenticación Basic solo el usuario.
- Los archivos extraídos se identifican por su huella SHA-256 y su tipo REAL (por los primeros bytes, no por
  la extensión). Si se descargan, es como `.bin`: son datos de la red y pueden ser malware.

Límites: HTTP/1.x (no HTTP/2); si faltan bytes en la captura, el intercambio se marca incompleto.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

MAX_MESSAGES = 500  # mensajes que se leen por sentido
MAX_BODY = 50_000_000
_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")
_REQUEST_LINE = re.compile(r"^([A-Z]+) (\S+) HTTP/1\.[01]$")
_STATUS_LINE = re.compile(r"^HTTP/1\.[01] (\d{3})(?: (.*))?$")
_SENSITIVE = ("pass", "pwd", "secret", "token", "senha", "contrasena", "clave", "apikey", "api_key")
_UPLOAD_TYPES = ("multipart/", "application/octet-stream")

# Tipo real de un archivo según sus primeros bytes: (prefijo, descripción, ¿es ejecutable o peligroso?).
_MAGIC: Tuple[Tuple[bytes, str, bool], ...] = (
    (b"MZ", "Ejecutable o librería de Windows (.exe/.dll)", True),
    (b"\x7fELF", "Ejecutable de Linux (ELF)", True),
    (b"\xcf\xfa\xed\xfe", "Ejecutable de macOS (Mach-O)", True),
    (b"\xca\xfe\xba\xbe", "Clase de Java o binario de macOS", True),
    (b"\xd0\xcf\x11\xe0", "Documento de Office antiguo (puede traer macros)", True),
    (b"#!", "Script (se ejecuta con un intérprete)", True),
    (b"%PDF", "PDF", False),
    (b"PK\x03\x04", "ZIP (también Office moderno, APK o JAR)", False),
    (b"\x1f\x8b", "Comprimido gzip", False),
    (b"Rar!", "Comprimido RAR", False),
    (b"7z\xbc\xaf", "Comprimido 7-Zip", False),
    (b"\x89PNG", "Imagen PNG", False),
    (b"\xff\xd8\xff", "Imagen JPEG", False),
    (b"GIF8", "Imagen GIF", False),
    (b"<?xml", "XML", False),
)


def file_kind(body: bytes) -> Tuple[str, bool]:
    """(descripción del tipo real, ¿riesgoso?). Por los primeros bytes: la extensión se puede falsear."""
    head = body[:8]
    for prefix, label, risky in _MAGIC:
        if head.startswith(prefix):
            return label, risky
    low = body[:200].lstrip().lower()
    if low.startswith((b"<!doctype html", b"<html")):
        return "Página HTML", False
    sample = body[:512]
    if sample and sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / len(sample) > 0.9:
        return "Texto", False
    return "Datos binarios", False


def _safe_name(raw: str) -> str:
    """Nombre de archivo apto para mostrar: sin rutas ni caracteres raros."""
    base = re.split(r"[\\/]", unquote(raw))[-1]
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80] or "sin_nombre"


# ----------------------------------------------------------- lectura de mensajes

@dataclass
class _Msg:
    line: str
    headers: Dict[str, str]
    body: bytes
    complete: bool  # el cuerpo llegó entero (no faltan bytes en la captura)


def _read_chunked(data: bytes, pos: int) -> Tuple[bytes, int, bool]:
    """Cuerpo `Transfer-Encoding: chunked` desde `pos`. (cuerpo, siguiente posición, completo)."""
    out = bytearray()
    while len(out) <= MAX_BODY:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            return bytes(out), len(data), False
        try:
            size = int(data[pos:eol].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(out), len(data), False
        pos = eol + 2
        if size == 0:
            end = data.find(b"\r\n\r\n", pos - 2)  # cola final (puede traer trailers)
            return bytes(out), (end + 4 if end >= 0 else len(data)), end >= 0
        if pos + size > len(data):
            out += data[pos:]
            return bytes(out), len(data), False
        out += data[pos:pos + size]
        pos += size + 2
    return bytes(out), len(data), False


def _read_body(data: bytes, pos: int, headers: Dict[str, str], no_body: bool, until_close: bool) -> Tuple[bytes, int, bool]:
    if no_body:
        return b"", pos, True
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return _read_chunked(data, pos)
    length = headers.get("content-length", "")
    if length.isdigit():
        n = min(int(length), MAX_BODY)
        body = data[pos:pos + n]
        return body, pos + len(body), len(body) == int(length)
    if until_close:  # una respuesta sin largo termina cuando se cierra la conexión
        return data[pos:], len(data), True
    return b"", pos, True


def _parse_head(data: bytes, pos: int) -> Optional[Tuple[str, Dict[str, str], int]]:
    end = data.find(b"\r\n\r\n", pos)
    if end < 0:
        return None
    lines = data[pos:end].decode("latin-1").split("\r\n")
    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        key, _, value = ln.partition(":")
        if key.strip():
            headers.setdefault(key.strip().lower(), value.strip())
    return lines[0], headers, end + 4


def _messages(data: bytes, responses: bool, request_methods: List[str]) -> List[_Msg]:
    out: List[_Msg] = []
    pos = 0
    while pos < len(data) and len(out) < MAX_MESSAGES:
        head = _parse_head(data, pos)
        if head is None:
            break
        line, headers, body_pos = head
        match = (_STATUS_LINE if responses else _REQUEST_LINE).match(line)
        if match is None:
            break  # ya no es HTTP (o se perdió el hilo): se corta en vez de inventar
        no_body = False
        if responses:
            status = int(match.group(1))
            method = request_methods[len(out)] if len(out) < len(request_methods) else ""
            no_body = method == "HEAD" or status in (204, 304) or 100 <= status < 200
        body, pos, complete = _read_body(data, body_pos, headers, no_body, until_close=responses)
        out.append(_Msg(line, headers, body, complete))
    return out


# ----------------------------------------------------------- intercambios

def _sensitive_fields(method: str, target: str, headers: Dict[str, str], body: bytes) -> List[str]:
    """NOMBRES de campos con pinta de contraseña (en la URL o en un formulario). Los valores nunca se guardan."""
    pairs = urlsplit(target).query
    if method in ("POST", "PUT") and headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
        pairs += "&" + body[:4096].decode("latin-1")
    names = {p.split("=", 1)[0].strip().lower() for p in pairs.split("&") if p}
    return sorted(n for n in names if any(s in n for s in _SENSITIVE))[:10]


def _auth(headers: Dict[str, str]) -> Optional[Dict[str, str]]:
    value = headers.get("authorization")
    if not value:
        return None
    scheme, _, rest = value.partition(" ")
    info = {"scheme": scheme}
    if scheme.lower() == "basic":
        try:
            info["user"] = base64.b64decode(rest.strip(), validate=False).decode("latin-1").split(":", 1)[0][:64]
        except (ValueError, UnicodeError):
            pass  # una cabecera Basic mal formada se informa solo como Basic
    return info  # nunca se guarda la contraseña ni el token


def _file_info(body: bytes, complete: bool, name_hint: str, content_type: str, direction: str) -> Dict[str, Any]:
    kind, risky = file_kind(body)
    return {
        "direction": direction, "name": _safe_name(name_hint), "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        "kind": kind, "risky": risky, "content_type": content_type, "complete": complete,
    }


def _name_hint(response_headers: Dict[str, str], target: str) -> str:
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', response_headers.get("content-disposition", ""))
    return match.group(1) if match else (urlsplit(target).path.rsplit("/", 1)[-1] or "index")


def _exchange(index: int, req: Optional[_Msg], resp: Optional[_Msg]) -> Dict[str, Any]:
    method, target = "", ""
    if req is not None:
        m = _REQUEST_LINE.match(req.line)
        method, target = (m.group(1), m.group(2)) if m else ("", "")
    ex: Dict[str, Any] = {
        "index": index, "method": method, "target": target[:300],
        "host": (req.headers.get("host") if req else None), "user_agent": (req.headers.get("user-agent", "")[:200] if req else None),
        "auth": _auth(req.headers) if req else None,
        "sensitive_fields": _sensitive_fields(method, target, req.headers, req.body) if req else [],
        "request_bytes": len(req.body) if req else 0, "request_type": (req.headers.get("content-type") if req else None),
        "status": None, "reason": None, "response_type": None, "response_bytes": 0,
        "location": None, "server": None, "encoding": None, "complete": bool(req and req.complete) and (resp is None or resp.complete),
        "file": None,
    }
    if resp is not None:
        m = _STATUS_LINE.match(resp.line)
        ex.update(status=int(m.group(1)) if m else None, reason=(m.group(2) or "")[:60] if m else None,
                  response_type=resp.headers.get("content-type"), response_bytes=len(resp.body),
                  location=resp.headers.get("location", "")[:300] or None, server=resp.headers.get("server", "")[:100] or None,
                  encoding=resp.headers.get("content-encoding"))
    ex["file"] = _file_of(ex, req, resp)
    return ex


def _file_of(ex: Dict[str, Any], req: Optional[_Msg], resp: Optional[_Msg]) -> Optional[Dict[str, Any]]:
    if resp is not None and resp.body and ex["status"] in (200, 206):
        return _file_info(resp.body, resp.complete, _name_hint(resp.headers, ex["target"]), ex["response_type"] or "", "descarga")
    ctype = (ex["request_type"] or "").lower()
    if req is not None and req.body and ex["method"] in ("POST", "PUT") and ctype.startswith(_UPLOAD_TYPES):
        return _file_info(req.body, req.complete, urlsplit(ex["target"]).path.rsplit("/", 1)[-1] or "subida", ctype, "subida")
    return None


def _client_server(origin: bytes, destination: bytes) -> Tuple[bytes, bytes]:
    """(bytes del cliente, bytes del servidor). El «origen» puede estar invertido si la captura empezó a mitad."""
    dest_is_request = destination.split(b" ", 1)[0] in _METHODS
    origin_is_request = origin.split(b" ", 1)[0] in _METHODS
    if dest_is_request and not origin_is_request:  # el destino manda las peticiones: el origen quedó invertido
        return destination, origin
    return origin, destination


def looks_like_http(origin: bytes, destination: bytes) -> bool:
    client, server = _client_server(origin, destination)
    return client.split(b" ", 1)[0] in _METHODS or server.startswith(b"HTTP/1.")


def _method_of(request_line: str) -> str:
    match = _REQUEST_LINE.match(request_line)
    return match.group(1) if match else ""


def _pairs(origin: bytes, destination: bytes) -> List[Tuple[Optional[_Msg], Optional[_Msg]]]:
    client, server = _client_server(origin, destination)
    requests = _messages(client, False, [])
    methods = [_method_of(r.line) for r in requests]
    responses = _messages(server, True, methods)
    count = max(len(requests), len(responses))
    return [(requests[i] if i < len(requests) else None, responses[i] if i < len(responses) else None) for i in range(count)]


def http_exchanges(origin: bytes, destination: bytes) -> List[Dict[str, Any]]:
    """Intercambios (petición + respuesta) de una sesión TCP, en orden. Vacío si no es HTTP/1.x en claro."""
    if not looks_like_http(origin, destination):
        return []
    return [_exchange(i, req, resp) for i, (req, resp) in enumerate(_pairs(origin, destination))]


def http_body(origin: bytes, destination: bytes, index: int) -> Optional[Tuple[bytes, str]]:
    """(cuerpo, nombre seguro) del archivo del intercambio `index`, o None si ese intercambio no tiene archivo."""
    pairs = _pairs(origin, destination)
    if not 0 <= index < len(pairs):
        return None
    ex = _exchange(index, *pairs[index])
    req, resp = pairs[index]
    if ex["file"] is None:
        return None
    body = resp.body if ex["file"]["direction"] == "descarga" and resp else (req.body if req else b"")
    return body, ex["file"]["name"]
