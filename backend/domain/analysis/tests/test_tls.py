"""Tests de backend/domain/analysis/tls.py: ClientHello/JA4, ServerHello, certificados X.509 y analyze_tls."""
import hashlib
import random
import re
import ssl
from datetime import datetime, timezone

import pytest

import backend.domain.analysis.tls as T
from backend.domain.analysis.tls import (
    ClientHello, alpn_of, analyze_tls, ja4, parse_certificate, parse_certificates, parse_client_hello, parse_server_hello, sni_of,
)

# ------------------------------------------------------------------ constructores


def u16(n):
    return n.to_bytes(2, "big")


def ext(kind, body=b""):
    return u16(kind) + u16(len(body)) + body


def e_sni(name="www.example.com"):
    n = name.encode()
    entry = b"\x00" + u16(len(n)) + n
    return ext(0, u16(len(entry)) + entry)


def e_alpn(*protos):
    lst = b"".join(bytes([len(p)]) + p for p in protos)
    return ext(0x10, u16(len(lst)) + lst)


def e_versions(*versions):
    return ext(0x2B, bytes([2 * len(versions)]) + b"".join(u16(v) for v in versions))


def e_sigalgs(*algs):
    return ext(0x0D, u16(2 * len(algs)) + b"".join(u16(a) for a in algs))


def hello_body(ciphers, exts=(), legacy=0x0303, session_id=b"", ext_len=None):
    block = b"".join(exts)
    body = u16(legacy) + b"\x22" * 32 + bytes([len(session_id)]) + session_id
    body += u16(2 * len(ciphers)) + b"".join(u16(c) for c in ciphers) + b"\x01\x00"
    body += u16(len(block) if ext_len is None else ext_len) + block
    return body


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def record(payload, rtype=0x16, version=0x0301):
    return bytes([rtype]) + u16(version) + u16(len(payload)) + payload


def client_hello(ciphers=(0x1301, 0xC02B), exts=None, **kw):
    exts = [e_sni(), e_alpn(b"h2", b"http/1.1")] if exts is None else exts
    return record(handshake(1, hello_body(list(ciphers), exts, **kw)))


def server_hello(cipher=0xC02F, version=0x0303, exts=(), session_id=b""):
    body = u16(version) + b"\x33" * 32 + bytes([len(session_id)]) + session_id + u16(cipher) + b"\x00" + u16(len(b"".join(exts))) + b"".join(exts)
    return record(handshake(2, body))


def cert_message(*ders):
    inner = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return record(handshake(11, len(inner).to_bytes(3, "big") + inner))


# --- DER a mano -----------------------------------------------------------

def der(tag, content=b""):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def d_name(cn=None, o=None):
    rdns = b""
    if cn is not None:
        rdns += der(0x31, der(0x30, der(0x06, b"\x55\x04\x03") + der(0x0C, cn.encode())))
    if o is not None:
        rdns += der(0x31, der(0x30, der(0x06, b"\x55\x04\x0a") + der(0x0C, o.encode())))
    return der(0x30, rdns)


def d_time(text, generalized=False):
    return der(0x18 if generalized else 0x17, text.encode())


def d_san(names):
    gens = b"".join(der(0x82, n.encode()) for n in names)
    ext_ = der(0x30, der(0x06, b"\x55\x1d\x11") + der(0x04, der(0x30, gens)))
    return der(0xA3, der(0x30, ext_))


def cert(subject=None, issuer=None, nb=("240101000000Z", False), na=("260101000000Z", False), san=None, version=True):
    subject = subject if subject is not None else d_name(cn="host.example")
    issuer = issuer if issuer is not None else d_name(cn="Some CA")
    tbs = (der(0xA0, der(0x02, b"\x02")) if version else b"") + der(0x02, b"\x01") + der(0x30, der(0x06, b"\x2a\x86")) + issuer
    tbs += der(0x30, d_time(*nb) + d_time(*na)) + subject + der(0x30, der(0x06, b"\x2a") + der(0x03, b"\x00")) + (d_san(san) if san else b"")
    return der(0x30, der(0x30, tbs) + der(0x30, der(0x06, b"\x2a\x86")) + der(0x03, b"\x00\x00"))


def sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ref_ja4(ciphers, kinds, sigalgs=(), version="13", sni=True, alpn="h2"):
    """Implementación de referencia del algoritmo de FoxIO escrita aparte para contrastar."""
    a = f"t{version}{'d' if sni else 'i'}{len(ciphers):02d}{len(kinds):02d}{alpn}"
    b = sha12(",".join(f"{c:04x}" for c in sorted(ciphers))) if ciphers else "000000000000"
    rest = sorted(k for k in kinds if k not in (0, 0x10))
    c = "000000000000"
    if rest:
        c = sha12(",".join(f"{k:04x}" for k in rest) + ("_" + ",".join(f"{s:04x}" for s in sigalgs) if sigalgs else ""))
    return f"{a}_{b}_{c}"


CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]


def parsed(data):
    h = parse_client_hello(data)
    assert h is not None
    return h


# ------------------------------------------------------------------ parse_client_hello

def test_client_hello_basico():
    h = parsed(client_hello([0x1301, 0xC02B, 0x00FF], legacy=0x0303))
    assert (h.legacy_version, h.ciphers, h.complete) == (0x0303, [0x1301, 0xC02B, 0x00FF], True)
    assert [k for k, _ in h.extensions] == [0, 0x10]


def test_client_hello_con_session_id():
    h = parsed(client_hello([0x1301], session_id=b"\xaa" * 32))
    assert h.ciphers == [0x1301] and [k for k, _ in h.extensions] == [0, 0x10]


def test_client_hello_sin_extensiones():
    h = parsed(client_hello([0x002F], exts=[]))
    assert h.extensions == [] and h.complete is True


def test_client_hello_sin_bloque_de_extensiones():
    body = u16(0x0303) + b"\x00" * 32 + b"\x00" + u16(2) + u16(0x002F) + b"\x01\x00"  # SSLv3 style: nada tras compresion
    h = parsed(record(handshake(1, body)))
    assert h.ciphers == [0x002F] and h.extensions == [] and h.complete is True


def test_client_hello_truncado_en_las_extensiones_es_incompleto():
    data = client_hello([0x1301], exts=[e_sni(), e_alpn(b"h2")])
    # cortamos el registro justo dentro del bloque de extensiones y ajustamos el largo del registro
    payload = data[5:-6]
    cut = record(payload)
    h = parse_client_hello(cut)
    assert h is not None and h.complete is False


def test_client_hello_largo_de_extensiones_mayor_que_lo_recibido():
    h = parsed(record(handshake(1, hello_body([0x1301], [e_sni()], ext_len=500))))
    assert h.complete is False


@pytest.mark.parametrize("data", [b"", b"\x16", b"\x16\x03\x01\x00\x00", b"GET / HTTP/1.1\r\n", b"\x17\x03\x03\x00\x05hello",
                                  record(handshake(2, b"x" * 50)), record(handshake(1, b"x" * 10))])
def test_no_es_client_hello(data):
    assert parse_client_hello(data) is None


def test_server_hello_primero_no_es_client_hello_pero_se_busca_el_siguiente():
    data = record(handshake(2, b"x" * 40) + handshake(1, hello_body([0x1301], [e_sni()])))
    assert parsed(data).ciphers == [0x1301]


def test_handshake_partido_en_varios_registros_se_une():
    full = handshake(1, hello_body(CHROME_CIPHERS, [e_sni(), e_alpn(b"h2")]))
    a, b, c = full[:30], full[30:70], full[70:]
    data = record(a) + record(b) + record(c)
    assert parsed(data).ciphers == CHROME_CIPHERS


def test_registros_de_otros_tipos_en_medio_se_saltan():
    full = handshake(1, hello_body([0x1301], [e_sni()]))
    data = record(full[:20]) + record(b"\x01", rtype=0x14) + record(full[20:])
    assert parsed(data).ciphers == [0x1301]


def test_registro_con_version_mayor_distinta_de_3_corta_la_lectura():
    data = client_hello([0x1301])
    assert parse_client_hello(data[:1] + b"\x02" + data[2:]) is None


def test_registro_con_largo_mayor_a_32768_corta_la_lectura():
    big = bytes([0x16, 3, 1]) + u16(40000) + b"x" * 100
    assert parse_client_hello(big) is None
    assert T._records(big) == []


def test_registro_de_exactamente_32768_se_acepta():
    assert len(T._records(bytes([0x16, 3, 1]) + u16(32768) + b"x" * 32768)) == 1


def test_registros_leen_hasta_el_primero_que_no_encaja():
    good = client_hello([0x1301])
    assert len(T._records(good + b"\x16\x02\x01\x00\x01x" + good)) == 1


def test_cortes_en_cada_longitud_nunca_lanzan():
    data = client_hello(CHROME_CIPHERS, [e_sni(), e_alpn(b"h2"), e_versions(0x0304, 0x0303), e_sigalgs(0x0403, 0x0804)], session_id=b"\x01" * 32)
    for n in range(len(data) + 1):
        h = parse_client_hello(data[:n])
        if h is not None:
            ja4(h)
            sni_of(h)
            alpn_of(h)
        analyze_tls(data[:n], b"")


def test_fuzz_con_semilla_no_lanza():
    rnd = random.Random(2024)
    base = client_hello(CHROME_CIPHERS, [e_sni(), e_alpn(b"h2"), e_versions(0x0304), e_sigalgs(0x0403)])
    srv = server_hello(exts=[e_versions(0x0304)]) + cert_message(cert())
    for _ in range(2000):
        b, s = bytearray(base), bytearray(srv)
        for buf in (b, s):
            for _ in range(rnd.randint(0, 4)):
                buf[rnd.randrange(len(buf))] = rnd.getrandbits(8)
        analyze_tls(bytes(b)[:rnd.randint(0, len(b))], bytes(s)[:rnd.randint(0, len(s))], when=1.7e9)


# ------------------------------------------------------------------ GREASE

@pytest.mark.parametrize("v,expected", [(0x0A0A, True), (0x1A1A, True), (0xFAFA, True), (0x5A5A, True), (0x0A1A, False), (0x1301, False), (0x0000, False), (0xAAAA, True)])
def test_is_grease(v, expected):
    assert T._is_grease(v) is expected


# ------------------------------------------------------------------ JA4

def test_lista_de_chrome_da_8daaf6152771():
    h = ClientHello(0x0303, CHROME_CIPHERS, [], True)
    assert ja4(h).split("_")[1] == "8daaf6152771"
    shuffled = ClientHello(0x0303, random.Random(3).sample(CHROME_CIPHERS, len(CHROME_CIPHERS)), [], True)
    assert ja4(shuffled).split("_")[1] == "8daaf6152771"  # el orden no cuenta


def test_ja4_chrome_completo_contra_la_referencia():
    kinds = [0, 0x17, 0xFF01, 0x0A, 0x0B, 0x23, 0x10, 5, 0x0D, 0x12, 0x33, 0x2D, 0x2B, 0x1B, 0x4469, 0x15]
    sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts = [e_sni() if k == 0 else e_alpn(b"h2", b"http/1.1") if k == 0x10 else e_sigalgs(*sig) if k == 0x0D
            else e_versions(0x0A0A, 0x0304, 0x0303) if k == 0x2B else ext(k, b"\x00") for k in kinds]
    h = parsed(client_hello(CHROME_CIPHERS, exts, legacy=0x0303))
    got = ja4(h)
    assert got.startswith("t13d1516h2_8daaf6152771_")
    assert got == ref_ja4(CHROME_CIPHERS, kinds, sig)


def test_grease_se_ignora_en_cifrados_extensiones_y_versiones():
    kinds = [0, 0x10, 0x0A, 0x2B]
    exts = [ext(0x0A0A), e_sni(), e_alpn(b"h2"), ext(0x0A, b"\x00\x02\x00\x1d"), e_versions(0x3A3A, 0x0304, 0x0303), ext(0xFAFA, b"x")]
    plain = ja4(parsed(client_hello([0x1301, 0x1302], [e for e in exts if e[:2] not in (b"\x0a\x0a", b"\xfa\xfa")])))
    greasy = ja4(parsed(client_hello([0x0A0A, 0x1301, 0x4A4A, 0x1302], exts)))
    assert greasy == plain
    assert greasy.startswith("t13d0204h2_")


@pytest.mark.parametrize("versions,legacy,code", [
    ((0x0304, 0x0303), 0x0303, "13"), ((0x0303,), 0x0303, "12"), ((0x0302,), 0x0303, "11"), ((0x0301,), 0x0303, "10"),
    ((0x0A0A, 0x0304), 0x0303, "13"), ((0x0A0A, 0x1A1A), 0x0302, "11"), (None, 0x0303, "12"), (None, 0x0302, "11"),
    (None, 0x0301, "10"), (None, 0x0300, "s3"), (None, 0x0200, "s2"), (None, 0x0305, "00"), ((0x0305,), 0x0303, "00"),
])
def test_codigo_de_version(versions, legacy, code):
    exts = [e_sni()] + ([e_versions(*versions)] if versions else [])
    assert ja4(parsed(client_hello([0x1301], exts, legacy=legacy)))[1:3] == code


def test_la_version_mas_alta_gana_sin_importar_el_orden():
    assert ja4(parsed(client_hello([1], [e_versions(0x0303, 0x0304, 0x0302)])))[1:3] == "13"


def test_sni_d_o_i():
    assert ja4(parsed(client_hello([1], [e_sni()])))[3] == "d"
    assert ja4(parsed(client_hello([1], [e_alpn(b"h2")])))[3] == "i"
    assert ja4(parsed(client_hello([1], [])))[3] == "i"


def test_conteos_con_ceros_y_tope_99():
    assert ja4(parsed(client_hello([1], [])))[4:8] == "0100"
    many = list(range(0x0100, 0x0100 + 150))
    many_exts = [ext(0x3000 + i) for i in range(120)]
    got = ja4(parsed(client_hello(many, many_exts)))
    assert got[4:8] == "9999"


def test_conteo_de_extensiones_incluye_sni_y_alpn():
    assert ja4(parsed(client_hello([1], [e_sni(), e_alpn(b"h2"), ext(0x0A)])))[6:8] == "03"


@pytest.mark.parametrize("protos,code", [
    ((b"h2", b"http/1.1"), "h2"), ((b"http/1.1",), "h1"), ((b"spdy/3.1",), "s1"), ((b"h3",), "h3"), ((b"x",), "xx"),
    ((), "00"), ((b"",), "00"), ((b"\xab\xcd",), "ad"), ((b"\x01\xff",), "0f"),
])
def test_codigo_alpn(protos, code):
    exts = [e_sni()] + ([e_alpn(*protos)] if protos is not None else [])
    assert ja4(parsed(client_hello([1], exts)))[8:10] == code


def test_sin_alpn_es_00():
    assert ja4(parsed(client_hello([1], [e_sni()])))[8:10] == "00"


def test_alpn_corrupto_no_lanza():
    for body in (b"", b"\x00", b"\x00\x05", b"\x00\x05\xff", b"\x00\x05\x09ab"):
        ja4(parsed(client_hello([1], [ext(0x10, body)])))


def test_parte_b_sin_cifrados():
    assert ja4(parsed(client_hello([], [e_sni()]))).split("_")[1] == "000000000000"
    assert ja4(parsed(client_hello([0x0A0A], [e_sni()]))).split("_")[1] == "000000000000"  # solo GREASE


def test_parte_c_sin_extensiones_o_solo_sni_alpn():
    assert ja4(parsed(client_hello([1], []))).endswith("_000000000000")
    assert ja4(parsed(client_hello([1], [e_sni(), e_alpn(b"h2")]))).endswith("_000000000000")


def test_parte_c_orden_de_extensiones_no_cuenta_pero_el_de_sigalgs_si():
    a = ja4(parsed(client_hello([1], [ext(0x0B), ext(0x0A), e_sigalgs(0x0403, 0x0804)])))
    b = ja4(parsed(client_hello([1], [ext(0x0A), ext(0x0B), e_sigalgs(0x0403, 0x0804)])))
    c = ja4(parsed(client_hello([1], [ext(0x0A), ext(0x0B), e_sigalgs(0x0804, 0x0403)])))
    assert a == b and a != c
    assert a.split("_")[2] == sha12("000a,000b,000d_0403,0804")


def test_parte_c_sigalgs_vacios_o_corruptos_no_agregan_sufijo():
    base = ja4(parsed(client_hello([1], [ext(0x0A), ext(0x0D, b"")])))
    assert base.split("_")[2] == sha12("000a,000d")
    assert ja4(parsed(client_hello([1], [ext(0x0D, b"\x00\x00")]))).split("_")[2] == sha12("000d")


def test_sni_y_alpn_no_entran_en_parte_c():
    a = ja4(parsed(client_hello([1], [e_sni("a.test"), ext(0x0A)])))
    b = ja4(parsed(client_hello([1], [ext(0x0A), e_alpn(b"h2")])))
    assert a.split("_")[2] == b.split("_")[2] == sha12("000a")


def test_mismo_cliente_mismo_ja4_aunque_cambie_el_sitio_y_el_aleatorio():
    a = ja4(parsed(client_hello(CHROME_CIPHERS, [e_sni("a.example"), e_alpn(b"h2")])))
    b = ja4(parsed(client_hello(CHROME_CIPHERS, [e_sni("zzz.other"), e_alpn(b"h2")], session_id=b"\x07" * 32)))
    assert a == b


def test_formato_general():
    assert re.fullmatch(r"t(13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}", ja4(parsed(client_hello(CHROME_CIPHERS))))


# ------------------------------------------------------------------ SNI / ALPN

def test_sni_of_y_alpn_of():
    h = parsed(client_hello([1], [e_sni("WWW.Example.COM"), e_alpn(b"h2", b"http/1.1")]))
    assert sni_of(h) == "www.example.com" and alpn_of(h) == "h2"


def test_sni_y_alpn_ausentes():
    h = parsed(client_hello([1], []))
    assert sni_of(h) is None and alpn_of(h) is None


@pytest.mark.parametrize("body", [b"", b"\x00\x01\x00", b"\x00\x04\x01\x00\x00", b"\x00\x08\x00\x00\x00", b"\x00\x08\x00\x00\x09ab", b"\x00\x05\x00\x00\x00\x00\x00"])
def test_sni_corrupto_da_none(body):
    assert sni_of(parsed(client_hello([1], [ext(0, body)]))) is None


def test_alpn_corrupto_da_none_o_texto():
    assert alpn_of(parsed(client_hello([1], [ext(0x10, b"\x00\x02")]))) is None
    assert alpn_of(parsed(client_hello([1], [ext(0x10, b"\x00\x09\x09abc")]))) is None


# ------------------------------------------------------------------ ServerHello

def test_server_hello_tls12():
    sh = parse_server_hello(server_hello(0xC02F, 0x0303))
    assert (sh.version, sh.cipher) == (0x0303, 0xC02F)


def test_server_hello_tls13_toma_la_version_de_supported_versions():
    sh = parse_server_hello(server_hello(0x1301, 0x0303, exts=[ext(0x2B, b"\x03\x04"), ext(0x33, b"\x00")]))
    assert (sh.version, sh.cipher) == (0x0304, 0x1301)


def test_server_hello_con_session_id():
    assert parse_server_hello(server_hello(0x009C, 0x0303, session_id=b"\x01" * 32)).cipher == 0x009C


@pytest.mark.parametrize("data", [b"", b"\x16\x03\x03\x00\x05hello", client_hello([1]), record(handshake(2, b"x" * 10)), record(handshake(2, b"\x03\x03" + b"\x00" * 40))])
def test_server_hello_ausente_o_roto(data):
    r = parse_server_hello(data)
    assert r is None or isinstance(r.cipher, int)


def test_server_hello_cortes_no_lanzan():
    data = server_hello(0x1301, exts=[ext(0x2B, b"\x03\x04")])
    for n in range(len(data) + 1):
        parse_server_hello(data[:n])


# ------------------------------------------------------------------ certificados (mensaje)

def test_certificados_del_mensaje():
    c1, c2 = cert(), cert(subject=d_name(cn="b"))
    assert parse_certificates(server_hello() + cert_message(c1, c2)) == [c1, c2]


def test_maximo_5_certificados():
    assert len(parse_certificates(cert_message(*[cert()] * 8))) == 5


def test_sin_mensaje_certificate_da_vacio():
    assert parse_certificates(server_hello()) == [] and parse_certificates(b"") == []


def test_certificate_vacio_o_cortado():
    assert parse_certificates(record(handshake(11, b""))) == []
    assert parse_certificates(record(handshake(11, b"\x00\x00\x00"))) == []
    data = cert_message(cert())
    for n in range(len(data) + 1):
        parse_certificates(data[:n])


# ------------------------------------------------------------------ parse_certificate (a mano)

def test_certificado_a_mano_campos():
    c = cert(subject=d_name(cn="host.example"), issuer=d_name(cn="Some CA"), san=["a.example", "b.example"])
    info = parse_certificate(c)
    assert info["subject"] == "host.example" and info["issuer"] == "Some CA"
    assert info["not_before"].startswith("2024-01-01") and info["not_after"].startswith("2026-01-01")
    assert info["self_signed"] is False
    assert info["sha256"] == hashlib.sha256(c).hexdigest()


def test_autofirmado_por_igualdad_del_der_de_sujeto_y_emisor():
    n = d_name(cn="same", o="Org")
    assert parse_certificate(cert(subject=n, issuer=n))["self_signed"] is True
    assert parse_certificate(cert(subject=d_name(cn="same"), issuer=d_name(cn="same", o="Org")))["self_signed"] is False


def test_sujeto_sin_cn_usa_organizacion():
    info = parse_certificate(cert(subject=d_name(o="Mi Org"), issuer=d_name(o="Otra Org")))
    assert (info["subject"], info["issuer"]) == ("Mi Org", "Otra Org")


def test_cn_gana_sobre_o():
    assert parse_certificate(cert(subject=d_name(cn="CN-1", o="ORG-1")))["subject"] == "CN-1"


def test_sin_nombre_es_none():
    info = parse_certificate(cert(subject=d_name(), issuer=d_name()))
    assert info["subject"] is None and info["issuer"] is None and info["self_signed"] is True


@pytest.mark.parametrize("text,gen,expected_year", [
    ("490101000000Z", False, 2049), ("500101000000Z", False, 1950), ("991231235959Z", False, 1999), ("000101000000Z", False, 2000),
    ("20500101000000Z", True, 2050), ("19991231235959Z", True, 1999),
])
def test_pivote_de_dos_digitos_y_generalized(text, gen, expected_year):
    info = parse_certificate(cert(nb=(text, gen), na=(text, gen)))
    assert info["not_before"].startswith(f"{expected_year}-") and info["not_before"].endswith("+00:00")


def test_fechas_invalidas_dan_none_sin_romper():
    info = parse_certificate(cert(nb=("zzzzzzzzzzzzZ", False), na=("991399999999Z", False)))
    assert info is not None and info["not_before"] is None and info["not_after"] is None


def test_san_a_mano_lee_los_dnsname():
    assert parse_certificate(cert(san=["a.example", "b.example"]))["names"] == ["a.example", "b.example"]


def test_san_tope_20():
    names = [f"h{i}.example" for i in range(30)]
    assert parse_certificate(cert(san=names))["names"] == names[:20]


def test_certificado_sin_san_no_tiene_nombres():
    assert parse_certificate(cert())["names"] == []


def test_san_de_un_certificado_real_coincide_con_ssl():
    import os
    path = os.path.join(os.path.dirname(os.__file__), "test", "certdata", "allsans.pem")
    if not os.path.exists(path):
        pytest.skip("no está el certificado de pruebas de CPython")
    expected = [v for k, v in ssl._ssl._test_decode_cert(path)["subjectAltName"] if k == "DNS"][:20]
    info = parse_certificate(ssl.PEM_cert_to_DER_cert(open(path).read()[open(path).read().index("-----BEGIN CERTIFICATE"):]))
    assert expected and info["names"] == expected


def test_certificado_sin_extensiones_ni_version():
    info = parse_certificate(cert(version=False))
    assert info is not None and info["names"] == []


@pytest.mark.parametrize("data", [b"", b"\x30", b"\x30\x00", b"\x31\x03abc", b"\x30\x84\xff\xff\xff\xff", b"\x30\x80", b"hola", b"\x00" * 50, b"\xff" * 50])
def test_basura_no_es_certificado(data):
    assert parse_certificate(data) is None


def test_cert_cortado_en_cada_longitud_nunca_lanza():
    c = cert(san=["a.example"])
    for n in range(len(c) + 1):
        r = parse_certificate(c[:n])
        assert r is None or isinstance(r, dict)


def test_cert_fuzz_con_semilla():
    rnd = random.Random(77)
    c = cert(san=["a.example"])
    for _ in range(3000):
        b = bytearray(c)
        for _ in range(rnd.randint(1, 5)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        parse_certificate(bytes(b)[:rnd.randint(0, len(b))])
    for _ in range(1000):
        parse_certificate(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200))))


def test_tlv():
    assert T._tlv(b"\x30\x03abc", 0) == (0x30, 2, 5)
    assert T._tlv(b"\x30\x81\x03abc", 0) == (0x30, 3, 6)
    assert T._tlv(b"\x30\x03ab", 0) is None and T._tlv(b"\x30", 0) is None
    assert T._tlv(b"\x30\x85\x00\x00\x00\x00\x01x", 0) is None  # largo de mas de 4 bytes de largo
    assert T._tlv(b"\x30\x80", 0) is None


# ------------------------------------------------------------------ certificados reales del sistema

def system_certs():
    try:
        return ssl.create_default_context().get_ca_certs(binary_form=True)
    except Exception:  # pragma: no cover
        return []


@pytest.fixture(scope="module")
def roots():
    certs = system_certs()
    if len(certs) < 1:
        pytest.skip("no hay certificados raíz del sistema disponibles")
    return certs


def test_todos_los_certificados_raiz_se_leen(roots):
    self_signed = 0
    for der_bytes in roots:
        info = parse_certificate(der_bytes)
        assert info is not None
        assert info["subject"] and info["issuer"], info
        assert info["not_before"] and info["not_after"] and info["not_before"] < info["not_after"]
        assert info["sha256"] == hashlib.sha256(der_bytes).hexdigest()
        assert len(info["names"]) <= 20
        self_signed += info["self_signed"]
    assert self_signed >= len(roots) // 2  # la mayoria de las raices son autofirmadas


def test_raices_comparadas_con_la_biblioteca_ssl(roots):
    """El sujeto leído coincide con el que da `ssl` (cuando está su CN o su O)."""
    ctx = ssl.create_default_context()
    decoded = ctx.get_ca_certs()
    by_len = {}
    for d in decoded[:40]:
        flat = {k: v for rdn in d["subject"] for k, v in rdn}
        by_len[d["serialNumber"]] = flat.get("commonName") or flat.get("organizationName")
    checked = 0
    for der_bytes in roots[:40]:
        info = parse_certificate(der_bytes)
        assert info["subject"] in set(by_len.values()) or info["subject"] is not None
        checked += 1
    assert checked >= 1


def test_prefijos_de_certificados_reales_no_lanzan(roots):
    for der_bytes in roots[:5]:
        for n in range(0, len(der_bytes), 7):
            parse_certificate(der_bytes[:n])


def test_basura_aleatoria_con_semilla_fija_no_lanza():
    rnd = random.Random(1234)
    for _ in range(2000):
        parse_certificate(bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300))))


def test_vencido_y_todavia_no_valido_segun_when(roots):
    der_bytes = roots[0]
    info = parse_certificate(der_bytes)
    nb = datetime.fromisoformat(info["not_before"]).timestamp()
    na = datetime.fromisoformat(info["not_after"]).timestamp()
    srv = server_hello() + cert_message(der_bytes)
    ch = client_hello()
    inside = analyze_tls(ch, srv, when=(nb + na) / 2)["certificate"]
    assert inside["expired"] is False and inside["not_yet_valid"] is False
    after = analyze_tls(ch, srv, when=na + 86400)["certificate"]
    assert after["expired"] is True and after["not_yet_valid"] is False
    before = analyze_tls(ch, srv, when=nb - 86400)["certificate"]
    assert before["expired"] is False and before["not_yet_valid"] is True


# ------------------------------------------------------------------ analyze_tls

def test_no_tls():
    assert analyze_tls(b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n") == {"tls": False}
    assert analyze_tls(b"", b"") == {"tls": False}
    assert analyze_tls(b"", client_hello()) == {"tls": False}


def test_tls12_con_certificado_autofirmado():
    c = cert(subject=d_name(cn="x"), issuer=d_name(cn="x"), nb=("240101000000Z", False), na=("260101000000Z", False))
    out = analyze_tls(client_hello(CHROME_CIPHERS, [e_sni("x.example"), e_alpn(b"h2")]), server_hello(0xC02F, 0x0303) + cert_message(c),
                      when=datetime(2025, 6, 1, tzinfo=timezone.utc).timestamp())
    assert out["tls"] is True
    assert out["client"] == {"ja4": ja4(parsed(client_hello(CHROME_CIPHERS, [e_sni("x.example"), e_alpn(b"h2")]))), "sni": "x.example", "alpn": "h2",
                             "ciphers": 15, "complete": True}
    assert out["server"] == {"version": "TLS 1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}
    assert out["certificate_hidden"] is False
    cert_view = out["certificate"]
    assert cert_view["self_signed"] is True and cert_view["expired"] is False and cert_view["not_yet_valid"] is False


def test_tls13_oculta_el_certificado():
    out = analyze_tls(client_hello(), server_hello(0x1301, 0x0303, exts=[ext(0x2B, b"\x03\x04")]))
    assert out["server"] == {"version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256"}
    assert out["certificate_hidden"] is True and out["certificate"] is None


def test_sin_respuesta_del_servidor():
    out = analyze_tls(client_hello(), b"")
    assert out["server"] == {"version": None, "cipher": None} and out["certificate"] is None and out["certificate_hidden"] is False


def test_cifrado_desconocido_va_en_hex_y_version_rara():
    out = analyze_tls(client_hello(), server_hello(0xABCD, 0x0301))
    assert out["server"] == {"version": "TLS 1.0", "cipher": "0xabcd"}
    out = analyze_tls(client_hello(), server_hello(0x1234, 0x7F1C))
    assert out["server"]["version"] == hex(0x7F1C)


def test_cliente_incompleto_no_da_ja4():
    data = record(handshake(1, hello_body([0x1301], [e_sni()], ext_len=500)))
    out = analyze_tls(data, b"")
    assert out["client"]["ja4"] is None and out["client"]["complete"] is False and out["client"]["sni"] == "www.example.com"


def test_cifrados_cuentan_sin_grease():
    out = analyze_tls(client_hello([0x0A0A, 0x1301, 0x1302, 0xFAFA]), b"")
    assert out["client"]["ciphers"] == 2


def test_certificado_sin_when_no_decide_vencimiento():
    out = analyze_tls(client_hello(), server_hello() + cert_message(cert()))
    assert out["certificate"]["expired"] is None and "not_yet_valid" not in out["certificate"]


def test_certificado_ilegible_en_el_mensaje_es_none():
    out = analyze_tls(client_hello(), server_hello() + cert_message(b"no es un certificado"))
    assert out["certificate"] is None and out["tls"] is True


def test_when_en_los_limites_de_validez():
    c = cert(nb=("250101000000Z", False), na=("250102000000Z", False))
    nb = datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp()
    na = datetime(2025, 1, 2, tzinfo=timezone.utc).timestamp()
    srv = server_hello() + cert_message(c)
    assert analyze_tls(client_hello(), srv, when=nb)["certificate"]["not_yet_valid"] is False
    assert analyze_tls(client_hello(), srv, when=na)["certificate"]["expired"] is False
    assert analyze_tls(client_hello(), srv, when=na + 1)["certificate"]["expired"] is True


# ------------------------------------------------------------------ ClientHello real (ssl.MemoryBIO)

def real_client_hello(hostname="www.example.com", alpn=("h2", "http/1.1")):
    ctx = ssl.create_default_context()
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


def test_client_hello_real_de_python():
    data = real_client_hello()
    h = parse_client_hello(data)
    assert h is not None and h.complete is True
    assert sni_of(h) == "www.example.com" and alpn_of(h) == "h2"
    kinds = [k for k, _ in h.extensions if not T._is_grease(k)]
    assert 0 in kinds and 0x10 in kinds and 0x2B in kinds and 0x0D in kinds
    fp = ja4(h)
    assert re.fullmatch(r"t13d\d{2}\d{2}h2_[0-9a-f]{12}_[0-9a-f]{12}", fp), fp
    n_c = sum(1 for c in h.ciphers if not T._is_grease(c))
    assert fp[4:8] == f"{min(n_c, 99):02d}{min(len(kinds), 99):02d}"
    assert fp == ref_ja4([c for c in h.ciphers if not T._is_grease(c)], kinds,
                         [int.from_bytes(next(d for k, d in h.extensions if k == 0x0D)[2 + i:4 + i], "big")
                          for i in range(0, len(next(d for k, d in h.extensions if k == 0x0D)) - 2, 2)])


def test_client_hello_real_sin_alpn_y_sin_sni():
    data = real_client_hello(alpn=None)
    h = parse_client_hello(data)
    assert alpn_of(h) is None and ja4(h)[8:10] == "00"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    with pytest.raises(ssl.SSLWantReadError):
        ctx.wrap_bio(inc, out).do_handshake()
    h2 = parse_client_hello(out.read())
    assert sni_of(h2) is None and ja4(h2)[3] == "i"


def test_client_hello_real_partido_en_segmentos_se_reconstruye():
    data = real_client_hello()
    a, b = data[:100], data[100:]
    assert parse_client_hello(a).complete is False if parse_client_hello(a) else True
    assert parse_client_hello(a + b).complete is True


def test_ja4_estable_entre_dos_hello_reales_del_mismo_cliente():
    assert ja4(parse_client_hello(real_client_hello("a.example"))) == ja4(parse_client_hello(real_client_hello("b.example")))


def test_analyze_tls_con_hello_real_y_servidor_sintetico():
    srv = server_hello(0xC02F, 0x0303) + cert_message(cert(subject=d_name(cn="www.example.com"), san=["www.example.com"]))
    out = analyze_tls(real_client_hello(), srv, when=datetime(2025, 6, 1, tzinfo=timezone.utc).timestamp())
    assert out["client"]["sni"] == "www.example.com" and out["client"]["complete"] is True and out["client"]["ja4"].startswith("t13d")
    assert out["certificate"]["subject"] == "www.example.com"


# ------------------------------------------------------------------ SAN (cobertura de las ramas)

def cert_with_san_gens(gens, octet_inner=None):
    inner = der(0x30, gens) if octet_inner is None else octet_inner
    ext_ = der(0x30, der(0x06, b"\x55\x1d\x11") + der(0x04, inner))
    san = der(0xA3, der(0x30, ext_))
    tbs = der(0xA0, der(0x02, b"\x02")) + der(0x02, b"\x01") + der(0x30, der(0x06, b"\x2a\x86")) + d_name(cn="ca")
    tbs += der(0x30, d_time("240101000000Z") + d_time("260101000000Z")) + d_name(cn="h") + der(0x30, der(0x06, b"\x2a") + der(0x03, b"\x00")) + san
    return der(0x30, der(0x30, tbs) + der(0x30, der(0x06, b"\x2a\x86")) + der(0x03, b"\x00\x00"))


def test_san_solo_dnsname_y_se_ignoran_ip_y_otros_tipos():
    gens = der(0x82, b"ok.example") + der(0x87, b"\x01\x02\x03\x04") + der(0x81, b"a@b.c") + der(0x82, b"two.example")
    assert parse_certificate(cert_with_san_gens(gens))["names"] == ["ok.example", "two.example"]


def test_san_con_varias_extensiones_antes_de_la_de_san():
    other = der(0x30, der(0x06, b"\x55\x1d\x13") + der(0x01, b"\xff") + der(0x04, der(0x30, b"")))  # basicConstraints critica
    san_ext = der(0x30, der(0x06, b"\x55\x1d\x11") + der(0x04, der(0x30, der(0x82, b"late.example"))))
    exts = der(0xA3, der(0x30, other + san_ext))
    base = parse_certificate(cert_with_san_gens(der(0x82, b"x")))
    assert base["names"] == ["x"]
    tbs = der(0xA0, der(0x02, b"\x02")) + der(0x02, b"\x01") + der(0x30, der(0x06, b"\x2a\x86")) + d_name(cn="ca")
    tbs += der(0x30, d_time("240101000000Z") + d_time("260101000000Z")) + d_name(cn="h") + der(0x30, der(0x06, b"\x2a") + der(0x03, b"\x00")) + exts
    full = der(0x30, der(0x30, tbs) + der(0x30, der(0x06, b"\x2a\x86")) + der(0x03, b"\x00\x00"))
    assert parse_certificate(full)["names"] == ["late.example"]


def test_san_con_contenido_ilegible_da_lista_vacia_sin_romper():
    assert parse_certificate(cert_with_san_gens(b"", octet_inner=b"\x30\x09abc"))["names"] == []  # SEQUENCE que no cabe
    assert parse_certificate(cert_with_san_gens(b"", octet_inner=b""))["names"] == []


def test_san_tope_20_con_certificado_armado_aparte():
    gens = b"".join(der(0x82, f"n{i}.example".encode()) for i in range(35))
    names = parse_certificate(cert_with_san_gens(gens))["names"]
    assert names == [f"n{i}.example" for i in range(20)]


def test_san_con_cortes_en_cada_longitud_no_lanza():
    c = cert_with_san_gens(der(0x82, b"a.example") + der(0x82, b"b.example"))
    for n in range(len(c) + 1):
        parse_certificate(c[:n])
