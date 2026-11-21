"""Tests de backend/domain/pcap/reader.py (archivos generados al vuelo, sin red)."""
import inspect
import struct
import types

import dpkt
import pytest

from backend.domain.pcap import reader as reader_mod
from backend.domain.pcap.reader import Packet, PcapError, capture_info, count_packets, iter_packets

PACKETS = [
    (1.0, b"\x01\x02\x03\x04"),
    (2.5, b"\xaa" * 10),
    (3.25, b"hola mundo!!"),
]


def _write_pcap(path, packets=PACKETS):
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for ts, buf in packets:
            w.writepkt(buf, ts=ts)
    return path


def _write_pcapng(path, packets=PACKETS):
    with open(path, "wb") as fh:
        w = dpkt.pcapng.Writer(fh)
        for ts, buf in packets:
            w.writepkt(buf, ts=ts)
    return path


# ---------- Normal ----------

def test_pcap_normal(tmp_path):
    p = _write_pcap(tmp_path / "a.pcap")
    assert count_packets(p) == 3
    got = list(iter_packets(p))
    assert all(isinstance(pk, Packet) for pk in got)
    assert [pk.data for pk in got] == [b for _, b in PACKETS]
    assert [pk.ts for pk in got] == pytest.approx([t for t, _ in PACKETS])
    assert [pk.origlen for pk in got] == [len(b) for _, b in PACKETS]
    assert not any(pk.snaplen_limited for pk in got)
    info = capture_info(p)
    assert info.format == "pcap"
    assert info.linktype == 1


def test_pcapng_normal(tmp_path):
    p = _write_pcapng(tmp_path / "a.pcapng")
    assert count_packets(p) == 3
    got = list(iter_packets(p))
    assert all(isinstance(pk, Packet) for pk in got)
    assert [pk.data for pk in got] == [b for _, b in PACKETS]
    assert [pk.ts for pk in got] == pytest.approx([t for t, _ in PACKETS])
    assert [pk.origlen for pk in got] == [None] * 3  # pcapng: dpkt no lo expone
    assert not any(pk.snaplen_limited for pk in got)
    info = capture_info(p)
    assert info.format == "pcapng"
    assert info.linktype == 1


def test_formato_por_magic_no_por_extension(tmp_path):
    # un pcapng con extension .pcap debe detectarse como pcapng
    p = _write_pcapng(tmp_path / "disfrazado.pcap")
    assert capture_info(p).format == "pcapng"


# ---------- Bordes ----------

def test_archivo_vacio(tmp_path):
    p = tmp_path / "vacio.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapError):
        capture_info(p)
    with pytest.raises(PcapError):
        count_packets(p)


def test_archivo_2_bytes(tmp_path):
    p = tmp_path / "dos.pcap"
    p.write_bytes(b"\xd4\xc3")
    with pytest.raises(PcapError):
        count_packets(p)


def test_pcap_solo_cabecera(tmp_path):
    p = _write_pcap(tmp_path / "h.pcap", packets=[])
    assert count_packets(p) == 0
    assert list(iter_packets(p)) == []
    assert capture_info(p).format == "pcap"


def test_payload_truncado_lanza_pcaperror(tmp_path):
    # Antes dpkt entregaba un buffer corto sin avisar (dato corrupto hacia las
    # reglas). Ahora el reader lo detecta con el tap y lanza PcapError ANTES de
    # entregar ese paquete; los anteriores si salen.
    p = _write_pcap(tmp_path / "t.pcap", packets=[(1.0, b"B" * 8), (2.0, b"A" * 20)])
    p.write_bytes(p.read_bytes()[:-5])
    it = iter_packets(p)
    primero = next(it)
    assert primero.data == b"B" * 8
    with pytest.raises(PcapError, match=r"esperado 20 bytes, le.do 15"):
        next(it)


def test_payload_truncado_unico_paquete(tmp_path):
    p = _write_pcap(tmp_path / "t1.pcap", packets=[(1.0, b"A" * 20)])
    p.write_bytes(p.read_bytes()[:-5])
    got = []
    with pytest.raises(PcapError, match="esperado 20.*15"):
        for pk in iter_packets(p):
            got.append(pk)
    assert got == []


def test_count_packets_payload_truncado(tmp_path):
    p = _write_pcap(tmp_path / "ct.pcap", packets=[(1.0, b"B" * 8), (2.0, b"A" * 20)])
    p.write_bytes(p.read_bytes()[:-1])
    with pytest.raises(PcapError, match="truncado"):
        count_packets(p)


def test_cabecera_de_paquete_truncada(tmp_path):
    p = _write_pcap(tmp_path / "c.pcap", packets=[(1.0, b"A" * 8), (2.0, b"B" * 8)])
    data = p.read_bytes()
    # corta dentro de la cabecera de 16 bytes del 2do paquete
    cut = 24 + 16 + 8 + 6
    p.write_bytes(data[:cut])
    with pytest.raises(PcapError):
        list(iter_packets(p))


def test_iter_packets_es_perezoso(tmp_path):
    p = _write_pcap(tmp_path / "l.pcap")
    it = iter_packets(p)
    assert isinstance(it, types.GeneratorType)
    assert not isinstance(it, list)
    assert inspect.isgenerator(it)
    # no abrio nada hasta el primer next(): una ruta inexistente no falla al crear el generador
    gen = iter_packets(tmp_path / "no_existe.pcap")
    assert inspect.isgenerator(gen)
    assert next(it).data == PACKETS[0][1]  # primer paquete disponible
    it.close()


# ---------- Errores esperados ----------

def test_ruta_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        capture_info(tmp_path / "nada.pcap")
    with pytest.raises(FileNotFoundError):
        count_packets(tmp_path / "nada.pcap")


def test_bytes_basura(tmp_path):
    p = tmp_path / "basura.pcap"
    p.write_bytes(b"\x13\x37\xbe\xef" * 16)  # 64 bytes sin magic valido
    with pytest.raises(PcapError):
        capture_info(p)
    with pytest.raises(PcapError):
        count_packets(p)


def test_pcapng_truncado_caracterizacion(tmp_path):
    # Se observa el comportamiento real al cortar un pcapng en distintos puntos.
    # El contrato deseado: o PcapError o una lectura parcial; nunca otra excepcion.
    p = _write_pcapng(tmp_path / "ng.pcapng")
    data = p.read_bytes()
    resultados = {}
    for cut in range(4, len(data)):
        q = tmp_path / "cut.pcapng"
        q.write_bytes(data[:cut])
        try:
            resultados[cut] = ("ok", count_packets(q))
        except PcapError:
            resultados[cut] = ("PcapError", None)
        except Exception as exc:  # noqa: BLE001
            resultados[cut] = (type(exc).__name__, str(exc))
    escapan = {k: v for k, v in resultados.items() if v[0] not in ("ok", "PcapError")}
    assert not escapan, f"excepciones que no son PcapError escapan: {escapan}"


# ---------- origlen / snaplen ----------

def _pcap_manual(endian, magic, pkts, snaplen=65535):
    """Arma un pcap a mano. pkts = [(sec, frac, caplen, origlen, payload)]."""
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, 1)
    for sec, frac, caplen, origlen, payload in pkts:
        out += struct.pack(endian + "IIII", sec, frac, caplen, origlen) + payload
    return out


def test_snaplen_limitado_no_es_error(tmp_path):
    # Paquete con origlen (100) > caplen (4) en la cabecera: captura con snaplen
    # bajo. Debe leerse sin error y marcarse snaplen_limited; el otro, normal.
    p = _write_pcap(tmp_path / "s.pcap", packets=[(1.0, b""), (2.0, b"hola")])
    raw = bytearray(p.read_bytes())
    # cabecera del 1er paquete en offset 24: ts_sec, ts_usec, caplen, origlen (LE)
    struct.pack_into("<I", raw, 24 + 12, 100)
    p.write_bytes(bytes(raw))
    a, b = list(iter_packets(p))
    assert (a.data, a.origlen, a.snaplen_limited) == (b"", 100, True)
    assert (b.data, b.origlen, b.snaplen_limited) == (b"hola", 4, False)


@pytest.mark.parametrize(
    "endian,magic",
    [(">", 0xA1B2C3D4), (">", 0xA1B23C4D), ("<", 0xA1B2C3D4), ("<", 0xA1B23C4D)],
    ids=["BE-us", "BE-ns", "LE-us", "LE-ns"],
)
def test_pcap_endianness_y_nanosegundos(tmp_path, endian, magic):
    # Big/little endian y magic micro/nano: origlen se lee bien en todos.
    pkts = [(5, 250, 3, 3, b"abc"), (6, 0, 2, 1500, b"xy")]
    p = tmp_path / "m.pcap"
    p.write_bytes(_pcap_manual(endian, magic, pkts))
    got = list(iter_packets(p))
    assert [g.data for g in got] == [b"abc", b"xy"]
    assert [g.origlen for g in got] == [3, 1500]
    assert [g.snaplen_limited for g in got] == [False, True]
    frac = 250 / (1e9 if magic == 0xA1B23C4D else 1e6)
    # nano: dpkt devuelve Decimal; el reader debe convertirlo a float nativo
    assert all(type(g.ts) is float for g in got)
    assert got[0].ts == pytest.approx(5 + frac)


def test_ts_es_float_con_magic_nanosegundos(tmp_path):
    # Regresion: con magic de nanosegundos dpkt entrega Decimal; Packet.ts debe
    # ser float exacto (no Decimal) o las restas de duracion de sesion rompen.
    from decimal import Decimal
    pkts = [(10, 500_000_000, 2, 2, b"ab"), (12, 250_000_000, 2, 2, b"cd")]
    p = tmp_path / "ns.pcap"
    p.write_bytes(_pcap_manual("<", 0xA1B23C4D, pkts))
    a, b = list(iter_packets(p))
    for pk in (a, b):
        assert type(pk.ts) is float
        assert not isinstance(pk.ts, Decimal)
    assert a.ts == pytest.approx(10.5)
    assert b.ts == pytest.approx(12.25)
    assert b.ts - a.ts == pytest.approx(1.75)  # la resta no debe lanzar TypeError


def test_pcap_magic_modificado_origlen_none(tmp_path):
    # Magic 0xa1b2cd34 (cabecera de paquete de 24 bytes): dpkt lo lee, el tap
    # no lo inspecciona -> origlen None, sin error ni snaplen_limited.
    out = struct.pack(">IHHiIII", 0xA1B2CD34, 2, 4, 0, 0, 65535, 1)
    for payload in (b"abcd", b"xy"):
        out += struct.pack(">IIIIIHBB", 7, 0, len(payload), len(payload), 0, 0, 0, 0) + payload
    p = tmp_path / "mod.pcap"
    p.write_bytes(out)
    got = list(iter_packets(p))
    assert [g.data for g in got] == [b"abcd", b"xy"]
    assert [g.origlen for g in got] == [None, None]
    assert not any(g.snaplen_limited for g in got)


def test_paquete_vacio_caplen_cero_no_es_truncamiento(tmp_path):
    # caplen=0: dpkt hace read(0) -> b"" que NO es una lectura corta (0 < 0 falso).
    pkts = [(1, 0, 0, 0, b""), (2, 0, 3, 3, b"abc"), (3, 0, 0, 60, b"")]
    p = tmp_path / "v.pcap"
    p.write_bytes(_pcap_manual("<", 0xA1B2C3D4, pkts))
    got = list(iter_packets(p))
    assert [g.data for g in got] == [b"", b"abc", b""]
    assert [g.origlen for g in got] == [0, 3, 60]
    assert [g.snaplen_limited for g in got] == [False, False, True]
    assert count_packets(p) == 3


def test_caracterizacion_patron_de_lecturas_de_dpkt(tmp_path):
    # Si dpkt cambia su patron (read(24); luego read(16)+read(caplen) por
    # paquete), este test falla y avisa que el tap dejo de ser confiable.
    p = _write_pcap(tmp_path / "g.pcap")
    with open(p, "rb") as fh:
        tap = reader_mod._TapFile(fh)
        calls = []
        real = tap._fh.read
        tap._fh = types.SimpleNamespace(read=lambda n=-1: (calls.append(n), real(n))[1])
        rd = dpkt.pcap.Reader(tap)
        seen = []
        for _ts, buf in rd:
            seen.append((tap.last_origlen, len(buf)))
    assert calls[:1] == [24]
    esperado = []
    for _, b in PACKETS:
        esperado += [16, len(b)]
    assert calls[1:1 + len(esperado)] == esperado
    assert calls[1 + len(esperado):] == [16]  # ultimo read: EOF
    assert seen == [(len(b), len(b)) for _, b in PACKETS]
    assert tap.short_read is None
