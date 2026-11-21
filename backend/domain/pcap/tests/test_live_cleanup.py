"""Tests de cleanup() y del timeout de detencion de backend.domain.pcap.live."""
import threading
import time

import pytest

from backend.domain.pcap import live
from backend.domain.pcap.live import CaptureError, CaptureStateError, LiveCapture
from backend.domain.pcap.reader import count_packets, iter_packets


class FakeSource:
    def __init__(self, start_exc=None):
        self.on_packet = None
        self.start_exc = start_exc
        self.stop_calls = 0

    def start(self, on_packet):
        if self.start_exc is not None:
            raise self.start_exc
        self.on_packet = on_packet

    def stop(self):
        self.stop_calls += 1

    def emit(self, ts, data):
        self.on_packet(ts, data)


class HangingSource(FakeSource):
    """stop() se bloquea hasta que el test llama a release()."""

    def __init__(self):
        super().__init__()
        self.gate = threading.Event()

    def stop(self):
        self.stop_calls += 1
        self.gate.wait(30)

    def release(self):
        self.gate.set()


@pytest.fixture
def hanging():
    src = HangingSource()
    yield src
    src.release()  # nunca dejar hilos colgados


# ------------------------------------------------------------------ cleanup

def test_temp_dir_se_crea_sin_out_path_y_cleanup_lo_borra():
    cap = LiveCapture(FakeSource())
    try:
        assert cap.temp_dir is not None and cap.temp_dir.is_dir()
        assert cap.path.parent == cap.temp_dir
    finally:
        cap.cleanup()
    assert not cap.temp_dir.exists()


def test_cleanup_tras_stop_borra_carpeta_y_archivo():
    src = FakeSource()
    cap = LiveCapture(src)
    cap.start()
    src.emit(1.0, b"abc")
    s = cap.stop()
    assert s.path.exists()
    cap.cleanup()
    assert not cap.temp_dir.exists() and not s.path.exists()


def test_cleanup_idempotente():
    cap = LiveCapture(FakeSource())
    cap.cleanup()
    cap.cleanup()
    assert not cap.temp_dir.exists()


def test_out_path_temp_dir_none_y_cleanup_no_borra(tmp_path):
    out = tmp_path / "carpeta" / "x.pcap"
    src = FakeSource()
    cap = LiveCapture(src, out)
    assert cap.temp_dir is None
    cap.start()
    src.emit(1.0, b"abc")
    cap.stop()
    cap.cleanup()
    assert out.exists() and out.parent.is_dir() and count_packets(out) == 1


def test_cleanup_con_captura_en_curso_falla():
    src = FakeSource()
    cap = LiveCapture(src)
    cap.start()
    try:
        with pytest.raises(CaptureStateError):
            cap.cleanup()
        assert cap.temp_dir.exists()
    finally:
        cap.stop()
        cap.cleanup()


def test_cleanup_sin_iniciar_ok(tmp_path):
    cap = LiveCapture(FakeSource(), tmp_path / "a.pcap")
    cap.cleanup()  # no iniciada: no es "en curso"


def test_dos_capturas_sin_out_path_carpetas_distintas():
    a, b = LiveCapture(FakeSource()), LiveCapture(FakeSource())
    try:
        assert a.temp_dir != b.temp_dir and a.path != b.path
    finally:
        a.cleanup()
        b.cleanup()


def test_start_falla_y_cleanup_borra_temporal():
    cap = LiveCapture(FakeSource(start_exc=CaptureError("boom")))
    with pytest.raises(CaptureError):
        cap.start()
    assert cap.temp_dir.exists()
    cap.cleanup()
    assert not cap.temp_dir.exists()


def test_status_started_at_nunca_none_en_finished():
    src = FakeSource()
    cap = LiveCapture(src)
    cap.start()
    cap.stop()
    st = cap.status()
    assert st["state"] == "finished" and isinstance(st["seconds"], float)
    cap.cleanup()


def test_on_packet_con_writer_none_se_ignora():
    src = FakeSource()
    cap = LiveCapture(src)
    cap.start()
    cap._writer = None  # simula archivo ya cerrado
    src.emit(1.0, b"x")
    assert cap.status()["packets"] == 0 and cap.error is None
    cap.stop()
    cap.cleanup()


# --------------------------------------------------- fuente que se cuelga

def test_stop_con_fuente_colgada_devuelve_con_timeout(tmp_path, monkeypatch, hanging):
    monkeypatch.setattr(live, "STOP_TIMEOUT", 0.2)
    cap = LiveCapture(hanging, tmp_path / "h.pcap")
    cap.start()
    sent = [(1.0 + i, bytes([i]) * 8) for i in range(3)]
    for ts, d in sent:
        hanging.emit(ts, d)
    t0 = time.monotonic()
    s = cap.stop()
    assert time.monotonic() - t0 < 2
    assert isinstance(cap.error, CaptureError)
    assert "no se detuvo" in str(cap.error) and "0.2" in str(cap.error)
    assert s.packets == 3 and s.reason == "manual"
    assert cap._fh.closed
    assert [(p.ts, p.data) for p in iter_packets(s.path)] == sent
    # paquetes tardios no se escriben
    hanging.emit(99.0, b"tarde")
    assert cap.status()["packets"] == 3
    assert count_packets(s.path) == 3


def test_stop_dos_veces_con_fuente_colgada_mismo_resumen(tmp_path, monkeypatch, hanging):
    monkeypatch.setattr(live, "STOP_TIMEOUT", 0.2)
    cap = LiveCapture(hanging, tmp_path / "h.pcap")
    cap.start()
    hanging.emit(1.0, b"a")
    s1 = cap.stop()
    t0 = time.monotonic()
    s2 = cap.stop()
    assert s1 == s2 and time.monotonic() - t0 < 1
    assert hanging.stop_calls == 1


def test_fuente_colgada_en_max_seconds_tambien_cierra(tmp_path, monkeypatch, hanging):
    monkeypatch.setattr(live, "STOP_TIMEOUT", 0.2)
    cap = LiveCapture(hanging, tmp_path / "h.pcap", max_seconds=0.1)
    cap.start()
    hanging.emit(1.0, b"a")
    assert cap._finished.wait(3)
    assert cap.status()["reason"] == "max_seconds" and isinstance(cap.error, CaptureError)


def test_fuente_que_lanza_en_stop_guarda_error_y_cierra(tmp_path):
    class Boom(FakeSource):
        def stop(self):
            raise RuntimeError("driver")

    src = Boom()
    cap = LiveCapture(src, tmp_path / "b.pcap")
    cap.start()
    src.emit(1.0, b"a")
    s = cap.stop()
    assert isinstance(cap.error, RuntimeError) and count_packets(s.path) == 1


def test_fuente_colgada_warning_menciona_no_se_detuvo(tmp_path, monkeypatch, hanging):
    import json
    monkeypatch.setattr(live, "STOP_TIMEOUT", 0.2)
    cap = LiveCapture(hanging, tmp_path / "h.pcap")
    cap.start()
    assert cap.status()["warning"] is None
    hanging.emit(1.0, b"a")
    s = cap.stop()
    assert isinstance(s.warning, str) and "no se detuvo" in s.warning
    assert s.reason == "manual"
    st = cap.status()
    assert isinstance(st["warning"], str) and "no se detuvo" in st["warning"]
    json.dumps(st)
