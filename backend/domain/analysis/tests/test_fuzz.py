"""Fuzz reproducible (semilla fija) de http, tls, stream y dns: sin excepciones ni consumo desmedido."""
import random
import struct
import time

import pytest

import backend.domain.analysis.http as H
import backend.domain.analysis.stream as S
from backend.domain.analysis.dns_log import DnsLog
from backend.domain.analysis.names import dns_names, sni_from_client_hello
from backend.domain.analysis.tests.test_stream import ACK, PSH, SESSION, SYN, seg
from backend.domain.analysis.tests.test_tls import cert, cert_message, client_hello, e_alpn, e_sni, server_hello
from backend.domain.analysis.tls import analyze_tls, parse_certificate

SEEDS = (1, 2, 3)
ROUNDS = 120  # mutaciones por semilla y por objetivo
MAX_SECONDS = 2.0  # tiempo máximo por entrada (un bucle o algo cuadrático lo supera)

HTTP_REQ = b"POST /a?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nAuthorization: Basic QTpC\r\n\r\nhello"
HTTP_RESP = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Disposition: attachment; "
             b"filename=a.exe\r\n\r\n4\r\nMZ\x90\x00\r\n0\r\n\r\n")
CLIENT = client_hello(exts=[e_sni(), e_alpn(b"h2")])
SERVER = server_hello() + cert_message(cert(san=["a.example.com"]))
DNS_RESP = (struct.pack(">HHHHHH", 7, 0x8180, 1, 1, 0, 0) + b"\x03www\x01a\x00\x00\x01\x00\x01"
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\x01\x02\x03\x04")


def mutate(rng: random.Random, data: bytes) -> bytes:
    """Una mutación al azar: bits, truncado, bloque repetido, relleno o bytes extremos."""
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(5)
        if op == 0 and buf:
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        elif op == 1 and buf:
            del buf[rng.randrange(len(buf)):]
        elif op == 2 and buf:
            i = rng.randrange(len(buf))
            buf[i:i] = buf[i:i + rng.randint(1, 16)] * rng.randint(2, 50)
        elif op == 3:
            buf += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
        elif buf:
            buf[rng.randrange(len(buf))] = rng.choice((0x00, 0x7F, 0x80, 0xFF, 0xC0))
    return bytes(buf)


def run(fn, *args):
    """Ejecuta `fn` y falla si lanza o tarda demasiado."""
    start = time.perf_counter()
    result = fn(*args)
    assert time.perf_counter() - start < MAX_SECONDS
    return result


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzz_http(seed):
    rng = random.Random(seed)
    for _ in range(ROUNDS):
        req, resp = mutate(rng, HTTP_REQ * 2), mutate(rng, HTTP_RESP * 2)
        out = run(H.http_exchanges, req, resp)
        assert len(out) <= H.MAX_MESSAGES
        for i in range(len(out)):
            run(H.http_body, req, resp, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzz_tls(seed):
    rng = random.Random(seed)
    for _ in range(ROUNDS):
        hello, server = mutate(rng, CLIENT), mutate(rng, SERVER)
        out = run(analyze_tls, hello, server, rng.choice((None, 1.7e9, 1e300)))
        assert isinstance(out, dict)
        run(sni_from_client_hello, hello)
        run(parse_certificate, mutate(rng, cert(san=["x.example.com"])))


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzz_dns(seed):
    rng = random.Random(seed)
    log = DnsLog()
    for _ in range(ROUNDS):
        payload = mutate(rng, DNS_RESP)
        run(dns_names, payload)
        run(log.add, 1.0, "10.0.0.1", "10.0.0.2", payload)
    assert log.summary()["names"] >= 0


@pytest.mark.parametrize("seed", SEEDS)
def test_fuzz_stream(seed):
    rng = random.Random(seed)
    for _ in range(40):
        pkts = [seg(1, "c", 1000, flags=SYN)]
        for n in range(rng.randint(1, 12)):
            who = rng.choice("cs")
            seq = rng.choice((1001, 1001 + n * 10, 0xFFFFFFF0, rng.getrandbits(32)))
            pkts.append(seg(2 + n, who, seq, mutate(rng, HTTP_REQ)[:200], PSH))
        st = run(S.follow_stream, SESSION, pkts)
        assert st.origin_bytes + st.destination_bytes <= S.MAX_BYTES + 70_000


# ------------------------------------------------- casos hostiles concretos (regresiones)

@pytest.mark.parametrize("body", [
    b"-2\r\nab\r\n0\r\n\r\n",  # tamaño negativo: retrocedía y repetía
    b"0x10\r\n" + b"a" * 16 + b"\r\n0\r\n\r\n",
    b"FFFFFFFFFFFFFFFF\r\n" + b"a" * 10,  # tamaño enorme mentiroso
    b"1_0\r\n" + b"a" * 16 + b"\r\n",
])
def test_chunked_hostil_no_falla_ni_repite(body):
    resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
    out = run(H._read_chunked, body, 0)
    assert len(out[0]) <= len(body)
    assert run(H.http_exchanges, b"GET / HTTP/1.1\r\n\r\n", resp)[0]["response_bytes"] <= len(body)


def test_content_length_absurdo_o_no_ascii():
    for value in ("9" * 5000, "²", "٣", "99999999999999"):
        resp = f"HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nabc".encode("utf-8")
        run(H.http_exchanges, b"GET / HTTP/1.1\r\n\r\n", resp)


def test_destino_con_corchete_no_lanza():
    req = b"GET //[x HTTP/1.1\r\nHost: h\r\n\r\n"
    out = run(H.http_exchanges, req, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz")
    assert out[0]["status"] == 200


def test_cabecera_gigante_se_descarta():
    big = b"GET / HTTP/1.1\r\nX: " + b"a" * (H.MAX_HEAD + 10) + b"\r\n\r\n"
    assert run(H.http_exchanges, big, b"") == []


def test_mensajes_se_cortan_y_se_marcan(monkeypatch):
    monkeypatch.setattr(H, "MAX_MESSAGES", 3)
    out = run(H.http_exchanges, b"GET / HTTP/1.1\r\n\r\n" * 10, b"")
    assert len(out) == 3 and out[-1]["truncated"] and not out[0]["truncated"]


def test_puntero_dns_en_bucle():
    loop = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    assert run(dns_names, loop) == []
    DnsLog().add(1.0, "a", "b", loop)


def test_tls_longitudes_mentirosas():
    hello = bytearray(CLIENT)
    hello[3:5] = b"\xff\xff"  # largo del registro
    hello[6:9] = b"\xff\xff\xff"  # largo del handshake
    assert run(analyze_tls, bytes(hello), SERVER)["tls"] in (True, False)
    assert run(analyze_tls, b"\x16\x03\x01" + b"\x00\x04" * 50_000, b"")["tls"] is False


def test_stream_tope_de_bytes_y_paquetes_marca_truncado(monkeypatch):
    monkeypatch.setattr(S, "MAX_BYTES", 100)
    st = S.follow_stream(SESSION, [seg(i, "c", 1000 + i * 40, b"x" * 40, PSH) for i in range(20)])
    assert st.truncated and st.origin_bytes < 200
    monkeypatch.setattr(S, "MAX_BYTES", 10**9)
    monkeypatch.setattr(S, "MAX_PACKETS", 5)
    st = S.follow_stream(SESSION, [seg(i, "c", 1000 + i, b"x", ACK) for i in range(20)])
    assert st.truncated and st.origin_bytes == 5


def test_stream_saltos_enormes_no_acumulan_bytes():
    pkts = [seg(i, "c", (i * 2**30) & 0xFFFFFFFF, b"x", PSH) for i in range(50)]
    st = S.follow_stream(SESSION, pkts)
    assert st.origin_bytes <= 50
