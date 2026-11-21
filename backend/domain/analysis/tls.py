"""TLS sin descifrar: la huella JA4 del cliente, la versión negociada y el certificado del servidor.

Con TLS el contenido va cifrado, pero el SALUDO inicial viaja en claro y dice mucho:
- el ClientHello trae la lista de cifrados y extensiones del cliente: de ahí sale la huella **JA4**, una
  «firma» de cómo se presenta el programa (dos programas distintos casi nunca dan la misma);
- el ServerHello dice qué versión y cifrado se acordaron;
- en TLS 1.2 (y anteriores) el servidor manda su certificado en claro. En **TLS 1.3 el certificado va
  cifrado** y no se puede ver: la interfaz lo explica.

JA4 sigue la especificación pública de FoxIO (BSD-3). Se implementa a mano, sin dependencias: ver las pruebas
contra la implementación de referencia en docs/decisiones.md.

Límites: solo TCP (no QUIC); un saludo partido en segmentos se reconstruye con la sesión; la lectura de
certificados es mínima (sujeto, emisor, validez, nombres alternativos y huella) y nunca lanza.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.domain.analysis.names import _skip_vector, _u16

HANDSHAKE, CLIENT_HELLO, SERVER_HELLO, CERTIFICATE = 0x16, 1, 2, 11
EXT_SNI, EXT_ALPN, EXT_SIGALGS, EXT_VERSIONS = 0x0000, 0x0010, 0x000D, 0x002B
MAX_CERT_NAMES = 20
MAX_DER_DEPTH = 6

_VERSION_CODES = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0200: "s2"}
VERSION_NAMES = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0", 0x0300: "SSL 3.0"}
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0x009C: "AES128-GCM-SHA256", 0x009D: "AES256-GCM-SHA384", 0x002F: "AES128-SHA", 0x0035: "AES256-SHA",
}


def _is_grease(value: int) -> bool:
    """Valores «GREASE» (0x0a0a, 0x1a1a... 0xfafa): relleno que los clientes meten a propósito; JA4 los ignora."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


# ------------------------------------------------------------------ ClientHello

@dataclass
class ClientHello:
    legacy_version: int
    ciphers: List[int]
    extensions: List[Tuple[int, bytes]]
    complete: bool  # el saludo llegó entero: sin esto la huella JA4 sería incorrecta


def _records(data: bytes) -> List[Tuple[int, bytes]]:
    """(tipo, contenido) de los registros TLS de un flujo; se corta en el primero que no encaja."""
    out, pos = [], 0
    while pos + 5 <= len(data):
        kind, major, length = data[pos], data[pos + 1], _u16(data, pos + 3)
        if major != 3 or length is None or length > 1 << 15:
            break
        out.append((kind, data[pos + 5:pos + 5 + length]))
        pos += 5 + length
    return out


def _handshakes(data: bytes) -> List[Tuple[int, bytes]]:
    """Mensajes de handshake (tipo, cuerpo) de los registros 0x16 del flujo, ya unidos (un mensaje puede ocupar varios)."""
    stream = b"".join(body for kind, body in _records(data) if kind == HANDSHAKE)
    out, pos = [], 0
    while pos + 4 <= len(stream):
        size = int.from_bytes(stream[pos + 1:pos + 4], "big")
        out.append((stream[pos], stream[pos + 4:pos + 4 + size]))
        pos += 4 + size
    return out


def _extensions(block: bytes) -> List[Tuple[int, bytes]]:
    out, pos = [], 0
    while pos + 4 <= len(block):
        kind, size = _u16(block, pos), _u16(block, pos + 2)
        if kind is None or size is None:
            break
        out.append((kind, block[pos + 4:pos + 4 + size]))
        pos += 4 + size
    return out


def parse_client_hello(stream: bytes) -> Optional[ClientHello]:
    """El ClientHello del primer mensaje de handshake del flujo del cliente, o None si no hay uno legible."""
    for kind, body in _handshakes(stream):
        if kind != CLIENT_HELLO:
            continue
        if len(body) < 35:
            return None
        legacy = _u16(body, 0) or 0
        pos = _skip_vector(body, 34, 1)  # session_id
        suites_end = _skip_vector(body, pos, 2) if pos is not None else None
        if pos is None or suites_end is None:
            return None
        ciphers = [_u16(body, i) or 0 for i in range(pos + 2, suites_end - 1, 2)]
        after = _skip_vector(body, suites_end, 1)  # compresión
        if after is None:
            return None
        ext_len = _u16(body, after)
        if ext_len is None:
            return ClientHello(legacy, ciphers, [], True)
        block = body[after + 2:after + 2 + ext_len]
        return ClientHello(legacy, ciphers, _extensions(block), len(block) == ext_len)
    return None


# ------------------------------------------------------------------------ JA4

def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def _alpn_code(data: bytes) -> str:
    """Primer y último carácter del primer valor ALPN («h2»): '00' si no hay."""
    if len(data) < 3:
        return "00"
    size = data[2]
    value = data[3:3 + size]
    if not value:
        return "00"
    first, last = value[0], value[-1]
    if chr(first).isalnum() and chr(last).isalnum() and first < 128 and last < 128:
        return chr(first) + chr(last)
    return f"{first:02x}"[0] + f"{last:02x}"[1]  # no alfanumérico: los dígitos hexadecimales de los extremos


def _highest_version(hello: ClientHello) -> int:
    for kind, data in hello.extensions:
        if kind == EXT_VERSIONS and data:
            offered = [_u16(data, i) or 0 for i in range(1, 1 + data[0], 2)]
            offered = [v for v in offered if not _is_grease(v)]
            if offered:
                return max(offered)
    return hello.legacy_version


def ja4(hello: ClientHello) -> str:
    """Huella JA4 del cliente: `t13d1516h2_<12>_<12>` (protocolo, versión, ¿nombre?, nº cifrados, nº extensiones, ALPN)."""
    ciphers = [c for c in hello.ciphers if not _is_grease(c)]
    exts = [(k, d) for k, d in hello.extensions if not _is_grease(k)]
    kinds = [k for k, _ in exts]
    alpn = next((d for k, d in exts if k == EXT_ALPN), b"")
    a = "t" + _VERSION_CODES.get(_highest_version(hello), "00") + ("d" if EXT_SNI in kinds else "i")
    a += f"{min(len(ciphers), 99):02d}{min(len(kinds), 99):02d}" + _alpn_code(alpn)
    b = _sha12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    ext_part = ",".join(f"{k:04x}" for k in sorted(k for k in kinds if k not in (EXT_SNI, EXT_ALPN)))
    sig = next((d for k, d in exts if k == EXT_SIGALGS), b"")
    algs = [_u16(sig, i) or 0 for i in range(2, 2 + (_u16(sig, 0) or 0), 2)] if len(sig) >= 2 else []
    algs_part = ",".join(f"{s:04x}" for s in algs)
    c = _sha12(ext_part + ("_" + algs_part if algs_part else "") if ext_part else "")
    return f"{a}_{b}_{c}"


def sni_of(hello: ClientHello) -> Optional[str]:
    for kind, data in hello.extensions:
        if kind == EXT_SNI and len(data) >= 5 and data[2] == 0:
            size = _u16(data, 3) or 0
            name = data[5:5 + size]
            return name.decode("ascii", "replace").lower() if len(name) == size and size else None
    return None


def alpn_of(hello: ClientHello) -> Optional[str]:
    for kind, data in hello.extensions:
        if kind == EXT_ALPN and len(data) >= 3 and 3 + data[2] <= len(data):
            return data[3:3 + data[2]].decode("ascii", "replace")
    return None


# ------------------------------------------------------------------ ServerHello

@dataclass
class ServerHello:
    version: int  # el NEGOCIADO (en TLS 1.3 sale de la extensión supported_versions)
    cipher: int


def parse_server_hello(stream: bytes) -> Optional[ServerHello]:
    for kind, body in _handshakes(stream):
        if kind != SERVER_HELLO or len(body) < 38:
            continue
        version = _u16(body, 0) or 0
        pos = _skip_vector(body, 34, 1)
        if pos is None or pos + 3 > len(body):
            return None
        cipher = _u16(body, pos) or 0
        ext_len = _u16(body, pos + 3)
        for k, d in _extensions(body[pos + 5:pos + 5 + (ext_len or 0)]):
            if k == EXT_VERSIONS and len(d) == 2:
                version = _u16(d, 0) or version
        return ServerHello(version, cipher)
    return None


# ------------------------------------------------------------- certificado (X.509)

def _tlv(data: bytes, pos: int) -> Optional[Tuple[int, int, int]]:
    """(etiqueta, inicio del valor, fin del valor) de un elemento DER en `pos`, o None si no cabe."""
    if pos + 2 > len(data):
        return None
    tag, first = data[pos], data[pos + 1]
    if first < 0x80:
        start, size = pos + 2, first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + 2 + n > len(data):
            return None
        start, size = pos + 2 + n, int.from_bytes(data[pos + 2:pos + 2 + n], "big")
    end = start + size
    return (tag, start, end) if end <= len(data) else None


def _children(data: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out, pos = [], start
    while pos < end:
        item = _tlv(data, pos)
        if item is None or item[2] > end:
            break
        out.append(item)
        pos = item[2]
    return out


def _parse_time(data: bytes, item: Tuple[int, int, int]) -> Optional[datetime]:
    tag, start, end = item
    text = data[start:end].decode("ascii", "replace")
    try:
        if tag == 0x17:  # UTCTime AAMMDDhhmmssZ
            year = int(text[:2])
            return datetime.strptime(f"{2000 + year if year < 50 else 1900 + year}{text[2:12]}", "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        if tag == 0x18:  # GeneralizedTime AAAAMMDDhhmmssZ
            return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return None


def _name_attr(data: bytes, name: Tuple[int, int, int], oid: bytes) -> Optional[str]:
    """Valor del atributo `oid` (por ejemplo CN) dentro de un Name (SEQUENCE de SET de SEQUENCE{OID, valor})."""
    for _t, s, e in _children(data, name[1], name[2]):
        for _t2, s2, e2 in _children(data, s, e):
            parts = _children(data, s2, e2)
            if len(parts) == 2 and data[parts[0][1]:parts[0][2]] == oid:
                return data[parts[1][1]:parts[1][2]].decode("utf-8", "replace")[:120]
    return None


def _san_names(data: bytes, extensions: Tuple[int, int, int]) -> List[str]:
    """Nombres alternativos (dNSName) de la extensión subjectAltName (OID 2.5.29.17)."""
    for _t, s, e in _children(data, extensions[1], extensions[2]):  # cada Extension: SEQUENCE { OID, [critical], OCTET STRING }
        parts = _children(data, s, e)
        if parts and data[parts[0][1]:parts[0][2]] == b"\x55\x1d\x11" and parts[-1][0] == 0x04:
            inner = _tlv(data, parts[-1][1])
            if inner is None:
                return []
            names = [data[a:b].decode("ascii", "replace") for tag, a, b in _children(data, inner[1], inner[2]) if tag == 0x82]
            return names[:MAX_CERT_NAMES]
    return []


def parse_certificate(der: bytes) -> Optional[Dict[str, Any]]:
    """Datos mínimos de un certificado X.509 en DER, o None si no se entiende. Nunca lanza."""
    try:
        top = _tlv(der, 0)
        if top is None or top[0] != 0x30:
            return None
        tbs = _tlv(der, top[1])
        if tbs is None or tbs[0] != 0x30:
            return None
        items = _children(der, tbs[1], tbs[2])
        if items and items[0][0] == 0xA0:  # versión explícita
            items = items[1:]
        if len(items) < 6:
            return None
        issuer, validity, subject = items[2], items[3], items[4]
        times = _children(der, validity[1], validity[2])
        not_before = _parse_time(der, times[0]) if len(times) == 2 else None
        not_after = _parse_time(der, times[1]) if len(times) == 2 else None
        ext_block = next((_tlv(der, i[1]) for i in items[6:] if i[0] == 0xA3), None)
        return {
            "subject": _name_attr(der, subject, b"\x55\x04\x03") or _name_attr(der, subject, b"\x55\x04\x0a"),
            "issuer": _name_attr(der, issuer, b"\x55\x04\x03") or _name_attr(der, issuer, b"\x55\x04\x0a"),
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "self_signed": der[subject[1]:subject[2]] == der[issuer[1]:issuer[2]],
            "names": _san_names(der, ext_block) if ext_block else [],
            "sha256": hashlib.sha256(der).hexdigest(),
        }
    except (IndexError, ValueError, UnicodeError):
        return None


def parse_certificates(stream: bytes) -> List[bytes]:
    """Certificados (DER) del mensaje Certificate de TLS ≤ 1.2, en claro. Vacío en TLS 1.3 (va cifrado)."""
    for kind, body in _handshakes(stream):
        if kind != CERTIFICATE or len(body) < 3:
            continue
        total = int.from_bytes(body[0:3], "big")
        pos = 3
        certs: List[bytes] = []
        while pos + 3 <= min(len(body), 3 + total) and len(certs) < 5:
            size = int.from_bytes(body[pos:pos + 3], "big")
            certs.append(body[pos + 3:pos + 3 + size])
            pos += 3 + size
        return certs
    return []


# ------------------------------------------------------------------ resultado

def _cert_view(info: Dict[str, Any], when: Optional[float]) -> Dict[str, Any]:
    """Datos del certificado más lo que se deduce de ellos (¿vencido en el momento de la captura?)."""
    view = dict(info)
    view["expired"] = None
    if when is not None and info.get("not_after") and info.get("not_before"):
        moment = datetime.fromtimestamp(when, timezone.utc).isoformat()
        view["expired"] = moment > info["not_after"]
        view["not_yet_valid"] = moment < info["not_before"]
    return view


def analyze_tls(client_stream: bytes, server_stream: bytes, when: Optional[float] = None) -> Dict[str, Any]:
    """Lo que se puede saber de una sesión TLS sin descifrarla. `{"tls": False}` si no hay un saludo TLS."""
    hello = parse_client_hello(client_stream)
    if hello is None:
        return {"tls": False}
    server = parse_server_hello(server_stream)
    version = server.version if server else None
    certs = parse_certificates(server_stream)
    cert = parse_certificate(certs[0]) if certs else None
    out: Dict[str, Any] = {
        "tls": True,
        "client": {
            "ja4": ja4(hello) if hello.complete else None, "sni": sni_of(hello), "alpn": alpn_of(hello),
            "ciphers": sum(1 for c in hello.ciphers if not _is_grease(c)), "complete": hello.complete,
        },
        "server": {
            "version": VERSION_NAMES.get(version, hex(version) if version else None) if version is not None else None,
            "cipher": CIPHER_NAMES.get(server.cipher, f"0x{server.cipher:04x}") if server else None,
        },
        "certificate": _cert_view(cert, when) if cert else None,
        "certificate_hidden": version == 0x0304,  # TLS 1.3: el certificado va cifrado
    }
    return out
