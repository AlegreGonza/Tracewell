"""Errores en backend.domain.pcap.live: sniffer que falla, cierre del pcap con OSError, hilo del sniffer, logging."""
import logging
import subprocess
import sys
import threading

from backend.domain.pcap.live import LiveCapture, ScapySource


class FakeSource:
    def __init__(self):
        self.on_packet = None

    def start(self, on_packet):
        self.on_packet = on_packet

    def stop(self):
        pass

    def emit(self, ts, data):
        self.on_packet(ts, data)


def _stop_en_hilo(cap, timeout=3):
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("s", cap.stop()), daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "stop() se colgó"
    return out["s"]


# ------------------------------------------------------------- ScapySource

class _Sniffer:
    running = True

    def stop(self):
        raise RuntimeError("npcap murió")


def test_scapy_stop_con_sniffer_que_falla_loguea_y_no_propaga(caplog):
    # un sniffer que lanza al detenerse -> warning, sin excepción
    src = ScapySource("eth0")
    src._sniffer = _Sniffer()
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        src.stop()
    recs = [r for r in caplog.records if r.levelno == logging.WARNING and r.exc_info]
    assert recs and recs[0].exc_info[0] is RuntimeError


def test_scapy_stop_sin_sniffer_ok():
    # sin sniffer iniciado, stop no hace nada
    ScapySource("eth0").stop()


# ------------------------------------------------------------- _close_file

class _FH:
    def __init__(self, flush_exc=None, close_exc=None):
        self.closed, self.flush_exc, self.close_exc = False, flush_exc, close_exc

    def flush(self):
        if self.flush_exc:
            raise self.flush_exc

    def close(self):
        if self.close_exc:
            raise self.close_exc
        self.closed = True


def _capturando(tmp_path):
    src = FakeSource()
    cap = LiveCapture(src, tmp_path / "a.pcap")
    cap.start()
    return src, cap


def test_flush_con_oserror_queda_en_error_y_stop_no_cuelga(tmp_path):
    # OSError en flush -> LiveCapture.error y _finished seteado
    src, cap = _capturando(tmp_path)
    real = cap._fh
    cap._fh = _FH(flush_exc=OSError("disco lleno"))
    s = _stop_en_hilo(cap)
    real.close()
    assert isinstance(cap.error, OSError) and cap._finished.is_set()
    assert s.warning and "disco lleno" in s.warning


def test_close_con_oserror_queda_en_error_y_stop_no_cuelga(tmp_path):
    # OSError en close -> error guardado, stop() vuelve
    src, cap = _capturando(tmp_path)
    real = cap._fh
    cap._fh = _FH(close_exc=OSError("no se pudo cerrar"))
    _stop_en_hilo(cap)
    real.close()
    assert isinstance(cap.error, OSError) and cap._finished.is_set()


def test_flush_falla_pero_se_intenta_close(tmp_path):
    # si flush falla igual se llama a close
    src, cap = _capturando(tmp_path)
    real = cap._fh
    fake = _FH(flush_exc=OSError("x"))
    cap._fh = fake
    _stop_en_hilo(cap)
    real.close()
    assert fake.closed


def test_primer_error_no_se_pisa(tmp_path):
    # con flush y close fallando se conserva el primero
    src, cap = _capturando(tmp_path)
    real = cap._fh
    cap._fh = _FH(OSError("primero"), OSError("segundo"))
    _stop_en_hilo(cap)
    real.close()
    assert str(cap.error) == "primero"


# ----------------------------------------------------------- _write_packet

class _WriterRoto:
    def writepkt(self, data, ts=0):
        raise RuntimeError("dato raro")


def test_writer_con_runtimeerror_corta_con_reason_error(tmp_path):
    # RuntimeError en el hilo del sniffer: se guarda, reason "error", la captura termina
    src, cap = _capturando(tmp_path)
    cap._writer = _WriterRoto()
    errores = []
    hook = threading.excepthook
    threading.excepthook = lambda a: errores.append(a)
    try:
        t = threading.Thread(target=src.emit, args=(1.0, b"abc"))
        t.start()
        t.join(2)
        assert cap._done.wait(2)
        s = _stop_en_hilo(cap)
    finally:
        threading.excepthook = hook
    assert not errores, "el hilo del sniffer no debe morir con traceback"
    assert isinstance(cap.error, RuntimeError)
    assert s.reason == "error" and s.packets == 0 and "dato raro" in (s.warning or "")
    assert not cap.running


# ----------------------------------------------------------------- logging

def test_core_y_api_no_configuran_handlers_en_tracewell():
    # tras importar core y api, el logger "tracewell" no tiene handlers (a lo sumo NullHandler)
    code = (
        "import logging, backend, backend.api, backend.api.app, backend.domain.pcap.live\n"
        "h = logging.getLogger('tracewell').handlers\n"
        "bad = [x for x in h if not isinstance(x, logging.NullHandler)]\n"
        "raise SystemExit(1 if bad else 0)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
