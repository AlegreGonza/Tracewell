"""Tests directos de los helpers de backend/domain/pcap (reader.py, live.py y hexdump.py)."""
import io
import math
import shutil
import struct
import threading

import dpkt
import pytest

from backend.domain.pcap import live
from backend.domain.pcap.hexdump import _hex_line
from backend.domain.pcap.live import CaptureSummary, LiveCapture, _check_limit, _resolve_out_path
from backend.domain.pcap.reader import (
    PcapError, _PCAP_ENDIAN, _PCAPNG_MAGIC, _BlockTap, _TapFile, _make_reader, _raise_if_truncated, _read_magic,
)


# ======================================================== reader._TapFile

def _global_header(magic=b"\xd4\xc3\xb2\xa1"):
    return magic + b"\x00" * 20


def _tap():
    return _TapFile(io.BytesIO(b""))


def test_on_global_little_endian_fija_struct():
    """El magic little-endian elige un struct '<IIII'."""
    t = _tap()
    t._on_global(_global_header(b"\xd4\xc3\xb2\xa1"))
    assert t._hdr_struct.format == "<IIII"


@pytest.mark.parametrize("magic", list(_PCAP_ENDIAN))
def test_on_global_todos_los_magics_conocidos(magic):
    """Cada magic conocido (micro y nanosegundos) deja un struct con su endianness."""
    t = _tap()
    t._on_global(magic + b"\x00" * 20)
    assert t._hdr_struct.format == _PCAP_ENDIAN[magic] + "IIII"


def test_on_global_magic_desconocido_deja_struct_none():
    """Un magic no estándar deja _hdr_struct en None (origlen no inspeccionable)."""
    t = _tap()
    t._on_global(b"\x12\x34\x56\x78" + b"\x00" * 20)
    assert t._hdr_struct is None


def test_on_global_vacio():
    """Datos vacíos no rompen: struct None."""
    t = _tap()
    t._on_global(b"")
    assert t._hdr_struct is None


def test_on_header_extrae_origlen():
    """De la cabecera de 16 bytes sale el cuarto campo (origlen)."""
    t = _tap()
    t._on_global(_global_header(b"\xd4\xc3\xb2\xa1"))
    t._on_header(16, struct.pack("<IIII", 1, 2, 10, 99))
    assert t.last_origlen == 99


def test_on_header_big_endian():
    """Con magic big-endian lee el origlen en ese orden."""
    t = _tap()
    t._on_global(_global_header(b"\xa1\xb2\xc3\xd4"))
    t._on_header(16, struct.pack(">IIII", 1, 2, 10, 77))
    assert t.last_origlen == 77


def test_on_header_sin_struct_origlen_none():
    """Sin struct (magic no estándar) el origlen es None."""
    t = _tap()
    t._on_global(b"\x00" * 24)
    t._on_header(16, struct.pack("<IIII", 1, 2, 3, 4))
    assert t.last_origlen is None


def test_on_header_lectura_corta_o_tamano_raro_origlen_none():
    """Si se pidieron o llegaron menos de 16 bytes, el origlen previo se resetea a None."""
    t = _tap()
    t._on_global(_global_header())
    t._on_header(16, struct.pack("<IIII", 1, 2, 3, 4))
    assert t.last_origlen == 4
    t._on_header(16, b"\x00" * 8)
    assert t.last_origlen is None
    t._on_header(16, struct.pack("<IIII", 1, 2, 3, 4))
    t._on_header(8, b"\x00" * 8)
    assert t.last_origlen is None


def test_on_payload_completo_no_marca_corte():
    """Si llegan todos los bytes pedidos, short_read sigue en None."""
    t = _tap()
    t._on_payload(5, b"abcde")
    assert t.short_read is None


def test_on_payload_corto_registra_esperado_y_leido():
    """Menos bytes de los pedidos deja (esperado, leído)."""
    t = _tap()
    t._on_payload(10, b"abc")
    assert t.short_read == (10, 3)


def test_on_payload_n_negativo_se_ignora():
    """read(-1) (todo el archivo) nunca cuenta como corte."""
    t = _tap()
    t._on_payload(-1, b"")
    assert t.short_read is None


def test_on_payload_cero_bytes_no_es_corte():
    """Pedir 0 bytes y recibir 0 no es un corte."""
    t = _tap()
    t._on_payload(0, b"")
    assert t.short_read is None


# ========================================================= reader._read_magic

def test_read_magic_devuelve_4_bytes_y_rebobina():
    """Devuelve el magic y deja el archivo en la posición 0."""
    fh = io.BytesIO(b"\xd4\xc3\xb2\xa1resto")
    assert _read_magic(fh) == b"\xd4\xc3\xb2\xa1"
    assert fh.tell() == 0


def test_read_magic_exactamente_4_bytes():
    """Un archivo de justo 4 bytes alcanza para el magic."""
    assert _read_magic(io.BytesIO(b"abcd")) == b"abcd"


@pytest.mark.parametrize("content", [b"", b"a", b"abc"])
def test_read_magic_vacio_o_corto(content):
    """Menos de 4 bytes lanza PcapError."""
    with pytest.raises(PcapError, match="vacío o demasiado corto"):
        _read_magic(io.BytesIO(content))


# ======================================================= reader._make_reader

def test_make_reader_pcap_devuelve_tap():
    """Un pcap clásico da formato 'pcap', lector dpkt y un _TapFile."""
    buf = io.BytesIO()
    dpkt.pcap.Writer(buf)
    buf.seek(0)
    fmt, rd, tap = _make_reader(buf, buf.getvalue()[:4])
    assert fmt == "pcap" and isinstance(rd, dpkt.pcap.Reader) and isinstance(tap, _TapFile)


def test_make_reader_pcapng_sin_tap():
    """Un pcapng da formato 'pcapng' y un _BlockTap (detecta cortes)."""
    buf = io.BytesIO()
    dpkt.pcapng.Writer(buf)
    buf.seek(0)
    assert buf.getvalue()[:4] == _PCAPNG_MAGIC
    fmt, rd, tap = _make_reader(buf, _PCAPNG_MAGIC)
    assert fmt == "pcapng" and isinstance(rd, dpkt.pcapng.Reader) and isinstance(tap, _BlockTap)


@pytest.mark.parametrize("content", [
    b"\x00" * 40,                                 # magic desconocido
    b"\xd4\xc3\xb2\xa1\x02\x00",                  # pcap con cabecera global cortada
    b"\x0a\x0d\x0d\x0a\x00\x00",                  # pcapng corto
    b"\x0a\x0d\x0d\x0a" + b"\x00" * 40,           # pcapng con cabecera basura
])
def test_make_reader_cabecera_invalida_lanza_pcaperror(content):
    """Cualquier cabecera inválida se traduce a PcapError (no filtra errores de dpkt)."""
    with pytest.raises(PcapError, match="cabecera inválida"):
        _make_reader(io.BytesIO(content), content[:4])


# =================================================== reader._raise_if_truncated

def test_raise_if_truncated_tap_none():
    """Sin tap (pcapng) no hace nada."""
    assert _raise_if_truncated(None) is None


def test_raise_if_truncated_sin_corte():
    """Un tap sin short_read no lanza."""
    assert _raise_if_truncated(_tap()) is None


def test_raise_if_truncated_con_corte_lanza():
    """Un tap con short_read lanza PcapError con esperado y leído."""
    t = _tap()
    t.short_read = (100, 40)
    with pytest.raises(PcapError, match="esperado 100 bytes, leído 40"):
        _raise_if_truncated(t)


# ============================================================ live._check_limit

@pytest.mark.parametrize("ok", [1, 0.001, 600.0, 10**9])
def test_check_limit_validos(ok):
    """Números positivos y finitos pasan."""
    assert _check_limit("max_x", ok) is None


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, 0, 0.0, -1, -0.5, True, False,
                                 "10", None, [1], 1 + 2j])
def test_check_limit_invalidos(bad):
    """NaN, infinito, cero, negativos, bool, str, None y otros tipos lanzan ValueError con el nombre."""
    with pytest.raises(ValueError, match="max_x"):
        _check_limit("max_x", bad)


# ======================================================= live._resolve_out_path

def test_resolve_out_path_con_ruta_no_crea_temp(tmp_path):
    """Con ruta explícita se usa tal cual y no hay carpeta temporal."""
    path, tmp = _resolve_out_path(tmp_path / "mia.pcap")
    assert path == tmp_path / "mia.pcap" and tmp is None


def test_resolve_out_path_acepta_str(tmp_path):
    """Una ruta en texto se convierte a Path."""
    path, tmp = _resolve_out_path(str(tmp_path / "a.pcap"))
    assert path.name == "a.pcap" and tmp is None


@pytest.mark.parametrize("vacio", [None, ""])
def test_resolve_out_path_sin_ruta_crea_mkdtemp(vacio):
    """Sin ruta crea una carpeta tracewell_* y devuelve live.pcap dentro de ella."""
    path, tmp = _resolve_out_path(vacio)
    try:
        assert tmp.is_dir() and tmp.name.startswith("tracewell_")
        assert path == tmp / "live.pcap"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================ LiveCapture helpers

class _Src:
    def start(self, on_packet):
        pass

    def stop(self):
        pass


class _BadWriter:
    def __init__(self, exc):
        self.exc = exc

    def writepkt(self, data, ts):
        raise self.exc


def _cap(tmp_path, **kw):
    return LiveCapture(_Src(), tmp_path / "c.pcap", **kw)


def test_init_state_valores_iniciales(tmp_path):
    """Estado inicial: contadores en 0, razón manual, sin archivo ni hilo ni error."""
    c = _cap(tmp_path)
    assert (c._packets, c._bytes, c._elapsed) == (0, 0, 0.0)
    assert c._reason == "manual" and c._started_at is None
    assert c._fh is None and c._writer is None and c._monitor is None
    assert c._summary is None and c.error is None
    assert not c._done.is_set() and not c._finished.is_set()


def test_init_state_es_reiniciable(tmp_path):
    """Volver a llamar _init_state deja el estado limpio y eventos nuevos."""
    c = _cap(tmp_path)
    c._packets, c._reason = 5, "error"
    c._done.set()
    c._init_state()
    assert c._packets == 0 and c._reason == "manual" and not c._done.is_set()


def test_state_name_idle_running_finished(tmp_path):
    """idle sin iniciar, running con _started_at, finished con el evento final."""
    c = _cap(tmp_path)
    assert c._state_name() == "idle"
    c._started_at = 1.0
    assert c._state_name() == "running"
    c._finished.set()
    assert c._state_name() == "finished"


def test_elapsed_now_sin_iniciar_es_cero(tmp_path):
    """Sin iniciar no hay tiempo transcurrido."""
    assert _cap(tmp_path)._elapsed_now() == 0.0


def test_elapsed_now_en_curso_usa_el_reloj(tmp_path, monkeypatch):
    """Mientras corre, es monotonic() - inicio."""
    c = _cap(tmp_path)
    c._started_at = 100.0
    monkeypatch.setattr(live.time, "monotonic", lambda: 107.5)
    assert c._elapsed_now() == 7.5


def test_elapsed_now_terminada_queda_congelado(tmp_path, monkeypatch):
    """Ya terminada devuelve _elapsed sin mirar el reloj."""
    c = _cap(tmp_path)
    c._started_at, c._elapsed = 100.0, 3.0
    c._finished.set()
    monkeypatch.setattr(live.time, "monotonic", lambda: 999.0)
    assert c._elapsed_now() == 3.0


def test_write_packet_ok_escribe_y_devuelve_true(tmp_path):
    """Un paquete bien escrito devuelve True y queda en el pcap."""
    c = _cap(tmp_path)
    buf = io.BytesIO()
    c._writer = dpkt.pcap.Writer(buf)
    assert c._write_packet(1.5, b"abc") is True
    assert not c._done.is_set() and c.error is None
    assert b"abc" in buf.getvalue()


@pytest.mark.parametrize("exc", [OSError("disco lleno"), ValueError("I/O operation on closed file")])
def test_write_packet_error_de_io_corta_la_captura(tmp_path, exc):
    """OSError/ValueError al escribir: devuelve False, guarda el error, razón 'error' y marca fin."""
    c = _cap(tmp_path)
    c._writer = _BadWriter(exc)
    assert c._write_packet(1.0, b"x") is False
    assert c.error is exc and c._reason == "error" and c._done.is_set()


def test_limit_reached_sin_limite(tmp_path):
    """Por debajo de ambos límites devuelve None."""
    c = _cap(tmp_path, max_packets=10, max_bytes=100)
    c._packets, c._bytes = 9, 99
    assert c._limit_reached() is None


def test_limit_reached_paquetes_en_el_borde(tmp_path):
    """Con exactamente max_packets corta por paquetes."""
    c = _cap(tmp_path, max_packets=10, max_bytes=100)
    c._packets = 10
    assert c._limit_reached() == "max_packets"


def test_limit_reached_bytes(tmp_path):
    """Con max_bytes alcanzado corta por bytes."""
    c = _cap(tmp_path, max_packets=10, max_bytes=100)
    c._bytes = 100
    assert c._limit_reached() == "max_bytes"


def test_limit_reached_ambos_prioriza_paquetes(tmp_path):
    """Si se alcanzan los dos a la vez, gana max_packets."""
    c = _cap(tmp_path, max_packets=1, max_bytes=1)
    c._packets, c._bytes = 1, 1
    assert c._limit_reached() == "max_packets"


def test_wait_for_end_vence_el_tiempo(tmp_path):
    """Si nadie termina antes, marca fin con razón max_seconds."""
    c = _cap(tmp_path, max_seconds=0.01)
    c._wait_for_end()
    assert c._done.is_set() and c._reason == "max_seconds"


def test_wait_for_end_ya_terminada_conserva_la_razon(tmp_path):
    """Si ya estaba marcada como terminada no pisa la razón."""
    c = _cap(tmp_path, max_seconds=5)
    c._reason = "max_packets"
    c._done.set()
    c._wait_for_end()
    assert c._reason == "max_packets"


def test_wait_for_end_termina_a_mitad_de_espera(tmp_path):
    """Si otro hilo la termina durante la espera, vuelve sin cambiar la razón (manual)."""
    c = _cap(tmp_path, max_seconds=30)
    threading.Timer(0.05, c._done.set).start()
    c._wait_for_end()
    assert c._reason == "manual"


def test_finalize_cierra_archivo_y_arma_resumen(tmp_path):
    """Cierra el archivo y deja un CaptureSummary con contadores, razón y sin warning."""
    c = _cap(tmp_path)
    c._fh = open(c.path, "wb")
    c._started_at = live.time.monotonic()
    c._packets, c._bytes, c._reason = 3, 30, "max_packets"
    c._finalize()
    assert c._fh.closed
    s = c._summary
    assert isinstance(s, CaptureSummary)
    assert (s.path, s.packets, s.bytes, s.reason, s.warning) == (c.path, 3, 30, "max_packets", None)
    assert s.seconds >= 0 and c._elapsed >= 0


def test_finalize_incluye_el_error_como_warning(tmp_path):
    """Si hubo un error registrado, el resumen lo trae en warning."""
    c = _cap(tmp_path)
    c._started_at = live.time.monotonic()
    c.error = OSError("disco lleno")
    c._finalize()
    assert c._summary.warning == "disco lleno" and c._fh is None


def test_finalize_sin_iniciar_no_falla(tmp_path):
    """Sin _started_at ni archivo igual produce un resumen (0 s aprox.)."""
    c = _cap(tmp_path)
    c._finalize()
    assert c._summary.packets == 0 and c._summary.seconds == 0.0


# ================================================================ hexdump._hex_line

def test_hex_line_linea_completa():
    """Una línea de 16 bytes: offset, hex y ASCII entre barras."""
    line = _hex_line(0, b"ABCDEFGHIJKLMNOP", 16)
    assert line == "00000000  " + " ".join(f"{b:02x}" for b in b"ABCDEFGHIJKLMNOP") + "  |ABCDEFGHIJKLMNOP|"


def test_hex_line_corta_se_rellena_a_ancho_fijo():
    """Una línea corta rellena la columna hex para alinear el ASCII."""
    corta = _hex_line(16, b"AB", 16)
    completa = _hex_line(0, b"A" * 16, 16)
    assert corta.index("|") == completa.index("|")
    assert corta.startswith("00000010  41 42 ") and corta.endswith("|AB|")


def test_hex_line_no_imprimibles_son_punto():
    """Bytes fuera de 32..126 se ven como '.'; 32 y 126 sí se muestran."""
    assert _hex_line(0, b"\x00\x1f \x7e\x7f\xff", 8).endswith("|.. ~..|")


def test_hex_line_vacia():
    """Un chunk vacío da la columna hex en blanco y ASCII vacío."""
    line = _hex_line(0, b"", 4)
    assert line == "00000000  " + " " * 11 + "  ||"


def test_hex_line_offset_en_8_digitos_hex():
    """El offset va en hexadecimal de 8 dígitos."""
    assert _hex_line(0x1A2B, b"a", 1).startswith("00001a2b  61  |a|")
