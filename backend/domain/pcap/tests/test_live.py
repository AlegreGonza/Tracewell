"""Tests de backend.domain.pcap.live con fuente simulada (nunca toca la red real)."""
import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from backend.domain.pcap import live
from backend.domain.pcap.live import (
    CaptureError,
    CaptureStateError,
    InterfaceInfo,
    LiveCapture,
    PERMISSION_HELP,
    PermissionDenied,
    ScapySource,
    list_interfaces,
)
from backend.domain.pcap.reader import capture_info, count_packets, iter_packets

ROOT = Path(__file__).resolve().parents[4]


class FakeSource:
    """Fuente controlable: los tests llaman emit() a mano (o desde hilos)."""

    def __init__(self, start_exc=None, stop_exc=None):
        self.on_packet = None
        self.start_exc = start_exc
        self.stop_exc = stop_exc
        self.start_calls = 0
        self.stop_calls = 0

    def start(self, on_packet):
        self.start_calls += 1
        if self.start_exc is not None:
            raise self.start_exc
        self.on_packet = on_packet

    def stop(self):
        self.stop_calls += 1
        if self.stop_exc is not None:
            raise self.stop_exc

    def emit(self, ts, data):
        self.on_packet(ts, data)


def make(tmp_path, src=None, **kw):
    src = src or FakeSource()
    return src, LiveCapture(src, tmp_path / "x.pcap", **kw)


# ------------------------------------------------------------------ normal

def test_captura_normal_conserva_bytes_y_timestamps(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    pkts = [(1700000000.0 + i * 0.25, bytes([i]) * (10 + i)) for i in range(5)]
    for ts, d in pkts:
        src.emit(ts, d)
    s = cap.stop()
    assert (s.packets, s.bytes, s.reason) == (5, sum(len(d) for _, d in pkts), "manual")
    assert count_packets(s.path) == 5
    assert capture_info(s.path).linktype == 1
    got = [(p.ts, p.data) for p in iter_packets(s.path)]
    assert got == pkts
    assert src.stop_calls == 1


def test_status_idle_running_finished(tmp_path):
    src, cap = make(tmp_path)
    assert cap.status()["state"] == "idle" and cap.status()["reason"] is None
    cap.start()
    src.emit(1.0, b"abc")
    st = cap.status()
    assert st["state"] == "running" and st["packets"] == 1 and st["bytes"] == 3 and st["reason"] is None
    cap.stop()
    st = cap.status()
    assert st["state"] == "finished" and st["reason"] == "manual"
    assert cap.running is False


# ------------------------------------------------------------------ límites

def test_max_packets_no_escribe_de_mas(tmp_path):
    src, cap = make(tmp_path, max_packets=3)
    cap.start()
    for i in range(10):
        src.emit(1.0 + i, b"x" * 5)
    s = cap.stop()
    assert (s.packets, s.reason) == (3, "max_packets")
    assert count_packets(s.path) == 3


def test_max_bytes(tmp_path):
    src, cap = make(tmp_path, max_bytes=25)
    cap.start()
    for i in range(10):
        src.emit(1.0, b"x" * 10)
    s = cap.stop()
    assert s.reason == "max_bytes" and s.packets == 3 and s.bytes == 30
    assert count_packets(s.path) == 3


def test_max_seconds(tmp_path):
    src, cap = make(tmp_path, max_seconds=0.2)
    cap.start()
    src.emit(1.0, b"hola")
    assert cap._finished.wait(2)
    assert cap.status()["state"] == "finished"
    s = cap.stop()
    assert s.reason == "max_seconds" and s.packets == 1
    assert src.stop_calls == 1


def test_stop_idempotente(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    src.emit(1.0, b"a")
    s1 = cap.stop()
    s2 = cap.stop()
    assert s1 is s2 or s1 == s2
    assert src.stop_calls == 1


def test_paquetes_despues_de_terminar_se_ignoran(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    src.emit(1.0, b"a")
    s = cap.stop()
    src.emit(2.0, b"b")
    src.emit(3.0, b"c")
    assert cap.status()["packets"] == 1
    assert count_packets(s.path) == 1


# ------------------------------------------------------------------ errores

def test_start_dos_veces(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    with pytest.raises(CaptureStateError):
        cap.start()
    cap.stop()
    with pytest.raises(CaptureStateError):  # tampoco después de terminar
        cap.start()


def test_stop_sin_start(tmp_path):
    _, cap = make(tmp_path)
    with pytest.raises(CaptureStateError):
        cap.stop()


@pytest.mark.parametrize("name", ["max_packets", "max_seconds", "max_bytes"])
@pytest.mark.parametrize("bad", [0, -1, -0.5, True, False, "5", None, [], "x"])
def test_limites_invalidos(tmp_path, name, bad):
    with pytest.raises(ValueError):
        LiveCapture(FakeSource(), tmp_path / "a.pcap", **{name: bad})


@pytest.mark.parametrize("name", ["max_packets", "max_seconds", "max_bytes"])
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")], ids=["nan", "inf", "-inf"])
def test_limite_no_finito_rechazado(tmp_path, name, bad):
    with pytest.raises(ValueError):
        LiveCapture(FakeSource(), tmp_path / "a.pcap", **{name: bad})


@pytest.mark.parametrize("exc", [PermissionDenied("sin permisos"), CaptureError("driver"), RuntimeError("boom")])
def test_fuente_falla_en_start_y_se_puede_reintentar(tmp_path, exc):
    src = FakeSource(start_exc=exc)
    _, cap = make(tmp_path, src)
    with pytest.raises(type(exc)):
        cap.start()
    assert cap._fh.closed
    assert cap.status()["state"] == "idle"
    src.start_exc = None  # reintento
    cap.start()
    src.emit(1.0, b"ok")
    s = cap.stop()
    assert s.packets == 1 and count_packets(s.path) == 1


def test_disco_falla_en_on_packet(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    src.emit(1.0, b"bien")

    class Roto:
        def writepkt(self, *a, **k):
            raise OSError("disco lleno")

    cap._writer = Roto()
    src.emit(2.0, b"mal")
    assert cap._finished.wait(2)
    s = cap.stop()
    assert s.reason == "error" and isinstance(cap.error, OSError)
    assert s.packets == 1


@pytest.fixture
def hilo_excepciones(monkeypatch):
    """Recolecta excepciones no manejadas en hilos (threading.excepthook)."""
    caidas = []
    monkeypatch.setattr(threading, "excepthook", lambda args: caidas.append(args))
    return caidas


def test_stop_de_la_fuente_lanza_se_guarda_en_error(tmp_path, hilo_excepciones):
    exc = RuntimeError("no para")
    src = FakeSource(stop_exc=exc)
    _, cap = make(tmp_path, src)
    cap.start()
    src.emit(1.0, b"a")
    s = cap.stop()
    cap._monitor.join(2)
    assert cap.error is exc
    assert s.packets == 1 and s.reason == "manual"
    assert cap._fh.closed
    assert count_packets(s.path) == 1
    assert hilo_excepciones == []


def test_stop_de_la_fuente_lanza_conserva_el_primer_error(tmp_path, hilo_excepciones):
    src = FakeSource(stop_exc=RuntimeError("segundo"))
    _, cap = make(tmp_path, src)
    cap.start()
    src.emit(1.0, b"bien")
    primero = OSError("disco lleno")

    class Roto:
        def writepkt(self, *a, **k):
            raise primero

    cap._writer = Roto()
    src.emit(2.0, b"mal")
    s = cap.stop()
    cap._monitor.join(2)
    assert s.reason == "error" and s.packets == 1
    assert cap.error is primero
    assert src.stop_calls == 1
    assert cap._fh.closed
    assert hilo_excepciones == []


# ------------------------------------------------------------------- bordes

def test_cero_paquetes_pcap_valido_y_analizable(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    s = cap.stop()
    assert s.packets == 0 and s.bytes == 0
    assert s.path.stat().st_size == 24
    assert count_packets(s.path) == 0
    from backend.domain.analysis.analyzer import analyze
    from backend.domain.rules.engine import load_rules

    a = analyze(s.path, load_rules(ROOT / "rules"))
    assert a.alerts == []


def test_paquete_de_0_y_65535_bytes(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    src.emit(1.0, b"")
    src.emit(2.0, b"\xab" * 65535)
    s = cap.stop()
    assert s.packets == 2 and s.bytes == 65535
    got = list(iter_packets(s.path))
    assert [len(p.data) for p in got] == [0, 65535]


def test_timestamps_iguales(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    for i in range(3):
        src.emit(5.5, bytes([i]))
    s = cap.stop()
    got = list(iter_packets(s.path))
    assert [p.ts for p in got] == [5.5] * 3 and [p.data for p in got] == [b"\x00", b"\x01", b"\x02"]


def test_out_path_en_carpeta_inexistente(tmp_path):
    out = tmp_path / "a" / "b" / "c.pcap"
    src = FakeSource()
    cap = LiveCapture(src, out)
    cap.start()
    s = cap.stop()
    assert out.is_file() and s.path == out


def test_out_path_por_defecto_carpeta_temporal():
    src = FakeSource()
    cap = LiveCapture(src)
    assert cap.path.parent.name.startswith("tracewell_") and cap.path.name == "live.pcap"
    cap.start()
    src.emit(1.0, b"z")
    s = cap.stop()
    try:
        assert count_packets(s.path) == 1
    finally:
        s.path.unlink()
        s.path.parent.rmdir()


def test_diez_mil_paquetes_desde_un_hilo_hasta_el_limite(tmp_path):
    src, cap = make(tmp_path, max_packets=10000)

    def run():
        for i in range(12000):
            src.emit(1.0 + i, b"p" * 20)

    cap.start()
    t = threading.Thread(target=run)
    t.start()
    t.join(10)
    assert cap._finished.wait(5)
    s = cap.stop()
    assert s.packets == 10000 and s.reason == "max_packets"
    assert count_packets(s.path) == 10000


def test_concurrencia_dos_hilos(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    go = threading.Event()

    def run(tag):
        go.wait()
        for i in range(500):
            src.emit(float(i), bytes([tag]) * 50)

    ts = [threading.Thread(target=run, args=(t,)) for t in (1, 2)]
    for t in ts:
        t.start()
    go.set()
    for t in ts:
        t.join(10)
    s = cap.stop()
    assert s.packets == 1000
    got = list(iter_packets(s.path))
    assert len(got) == 1000
    assert all(len(set(p.data)) == 1 and len(p.data) == 50 for p in got)
    assert sum(1 for p in got if p.data[0] == 1) == 500


# --------------------------------------------------------------- interfaces

def test_list_interfaces_con_lister():
    lst = [InterfaceInfo("eth0", "Ethernet")]
    assert list_interfaces(lambda: lst) == lst


def test_lister_que_lanza_capture_error_propaga():
    def bad():
        raise CaptureError("sin driver")

    with pytest.raises(CaptureError):
        list_interfaces(bad)


def test_interface_info_inmutable():
    i = InterfaceInfo("a", "b")
    with pytest.raises(Exception):
        i.name = "c"


@pytest.mark.parametrize("bad", ["", "   ", None, 5, b"eth0", ["eth0"]])
def test_scapy_source_interface_invalida(bad):
    with pytest.raises(CaptureError):
        ScapySource(bad)


def test_importar_live_no_importa_scapy():
    code = "import sys, backend.domain.pcap.live; sys.exit(1 if 'scapy' in sys.modules else 0)"
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _sin_scapy(monkeypatch):
    monkeypatch.setitem(sys.modules, "scapy", None)
    monkeypatch.setitem(sys.modules, "scapy.all", None)


def test_sin_scapy_mensaje_claro_en_start(monkeypatch):
    _sin_scapy(monkeypatch)
    with pytest.raises(CaptureError, match="Scapy no está instalado"):
        ScapySource("eth0").start(lambda *a: None)


def test_sin_scapy_list_interfaces(monkeypatch):
    _sin_scapy(monkeypatch)
    with pytest.raises(CaptureError, match="Scapy no está instalado"):
        list_interfaces()


def _fake_scapy(monkeypatch, sniffer_cls):
    pytest.importorskip("scapy.all")
    import scapy.all as scapy

    monkeypatch.setattr(scapy, "AsyncSniffer", sniffer_cls)


class Ether:  # el handle compara por nombre de clase
    time = 12.5

    def __bytes__(self):
        return b"\x01\x02\x03"


class Loopback:
    time = 1.0

    def __bytes__(self):
        return b"nope"


def test_scapy_source_handle_descarta_no_ether(monkeypatch):
    created = {}

    class FakeSniffer:
        running = True

        def __init__(self, started_callback=None, **kw):
            created.update(kw)
            created["started_callback"] = started_callback
            self.started_callback = started_callback
            self.exception = None
            self.thread = None
            self.stopped = False

        def start(self):
            if self.started_callback:  # como Scapy: avisa al abrir el socket
                self.started_callback()

        def stop(self):
            self.stopped = True

    _fake_scapy(monkeypatch, FakeSniffer)
    got = []
    src = ScapySource("eth0", bpf_filter="tcp")
    src.start(lambda ts, d: got.append((ts, d)))
    assert created["iface"] == "eth0" and created["filter"] == "tcp" and created["store"] is False
    prn = created["prn"]
    prn(Ether())
    prn(Loopback())
    prn(Loopback())
    assert got == [(12.5, b"\x01\x02\x03")]
    assert src.non_ethernet_dropped == 2
    src.stop()
    assert src._sniffer.stopped


def test_scapy_source_permiso_denegado(monkeypatch):
    class S:
        def __init__(self, **kw):
            pass

        def start(self):
            raise PermissionError("no")

    _fake_scapy(monkeypatch, S)
    with pytest.raises(PermissionDenied):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_source_error_generico(monkeypatch):
    class S:
        def __init__(self, **kw):
            pass

        def start(self):
            raise OSError("iface rara")

    _fake_scapy(monkeypatch, S)
    with pytest.raises(CaptureError, match="eth0"):
        ScapySource("eth0").start(lambda *a: None)


def _timeout(monkeypatch, value):
    # el default de _wait_started se fijó al definir la función
    monkeypatch.setattr(ScapySource._wait_started, "__defaults__", (value,))


class AliveThread:
    def is_alive(self):
        return True


class DeadThread:
    def is_alive(self):
        return False


def _sniffer_cls(*, call_ready=False, exception=None, thread=None, start_raises=None,
                 exc_after_polls=None, registry=None):
    """AsyncSniffer simulado: start() vuelve ya; el error de Scapy (si hay) queda en .exception."""

    class Sniffer:
        running = True

        def __init__(self, started_callback=None, **kw):
            self.started_callback = started_callback
            self.exception = None
            self.thread = thread
            self.polls = 0
            self.kw = kw
            if registry is not None:
                registry.append(self)

        def start(self):
            if start_raises is not None:
                raise start_raises
            if exception is not None and exc_after_polls is None:
                self.exception = exception
            if call_ready and self.started_callback:
                self.started_callback()

        def stop(self):
            pass

    if exc_after_polls is not None:
        # el hilo guarda el error unos instantes después de start()
        orig_start = Sniffer.start

        def start(self):
            orig_start(self)
            threading.Timer(0.15, lambda: setattr(self, "exception", exception)).start()

        Sniffer.start = start
    return Sniffer


def test_scapy_pasa_started_callback_evento(monkeypatch):
    made = []
    _fake_scapy(monkeypatch, _sniffer_cls(call_ready=True, registry=made))
    ScapySource("eth0").start(lambda *a: None)
    cb = made[0].started_callback
    assert callable(cb) and cb.__self__.__class__ is threading.Event


def test_scapy_ready_vuelve_enseguida(monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(call_ready=True, thread=AliveThread()))
    t0 = time.monotonic()
    ScapySource("eth0").start(lambda *a: None)
    assert time.monotonic() - t0 < 1.0


def test_scapy_permission_error_guardado_en_exception(monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(exception=PermissionError(1, "Operation not permitted")))
    with pytest.raises(PermissionDenied, match="administrador"):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_permission_error_guardado_con_hilo_muerto(monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(exception=PermissionError("no"), thread=DeadThread()))
    with pytest.raises(PermissionDenied):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_permission_error_directo_mensaje_exacto(monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(start_raises=PermissionError("no")))
    with pytest.raises(PermissionDenied) as ei:
        ScapySource("eth0").start(lambda *a: None)
    msg = str(ei.value)
    assert msg == PERMISSION_HELP
    assert msg.startswith("permiso denegado: ejecutá Tracewell como administrador (Windows) o root (Linux)")
    assert "dumpcap" in msg and "grupo" in msg
    assert "python3" not in msg  # nunca se aconseja dar el permiso al intérprete
    assert isinstance(ei.value, CaptureError)


def test_scapy_permission_error_aparece_tarde(monkeypatch):
    # el error se guarda después de varias vueltas del sondeo
    _fake_scapy(monkeypatch, _sniffer_cls(exception=PermissionError("no"), exc_after_polls=1,
                                          thread=AliveThread()))
    with pytest.raises(PermissionDenied):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_otro_error_guardado_menciona_interfaz(monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(exception=OSError("No such device exists")))
    with pytest.raises(CaptureError, match="'wlan9'") as ei:
        ScapySource("wlan9").start(lambda *a: None)
    assert not isinstance(ei.value, PermissionDenied)
    assert "No such device exists" in str(ei.value)
    assert isinstance(ei.value.__cause__, OSError)


def test_scapy_oserror_no_permiso_no_es_permission_denied(monkeypatch):
    # OSError genérico (errno de dispositivo) no debe confundirse con permisos
    _fake_scapy(monkeypatch, _sniffer_cls(start_raises=OSError(19, "No such device")))
    with pytest.raises(CaptureError) as ei:
        ScapySource("eth0").start(lambda *a: None)
    assert type(ei.value) is CaptureError


def test_scapy_excepcion_no_exception_se_traduce(monkeypatch):
    # .exception con un objeto que no es excepción
    _fake_scapy(monkeypatch, _sniffer_cls(exception="texto raro"))
    with pytest.raises(CaptureError, match="eth0"):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_timeout_sin_listo_ni_error_vuelve(monkeypatch):
    _timeout(monkeypatch, 0.2)
    _fake_scapy(monkeypatch, _sniffer_cls(thread=AliveThread()))
    t0 = time.monotonic()
    ScapySource("eth0").start(lambda *a: None)
    el = time.monotonic() - t0
    assert 0.15 <= el < 2.0


def test_start_timeout_por_defecto_es_5s():
    assert live.START_TIMEOUT == 5.0
    assert ScapySource._wait_started.__defaults__ == (live.START_TIMEOUT,)


def test_wait_started_timeout_explicito_corto():
    s = ScapySource("eth0")
    s._sniffer = _sniffer_cls(thread=AliveThread())()
    t0 = time.monotonic()
    s._wait_started(threading.Event(), timeout=0.1)
    assert time.monotonic() - t0 < 1.0


def test_wait_started_timeout_cero_con_error_lo_relanza():
    s = ScapySource("eth0")
    s._sniffer = _sniffer_cls(thread=AliveThread())()
    s._sniffer.exception = OSError("tarde")
    with pytest.raises(OSError, match="tarde"):
        s._wait_started(threading.Event(), timeout=0)


def test_scapy_hilo_muerto_sin_error_vuelve_pronto(monkeypatch):
    _timeout(monkeypatch, 30.0)  # si no corta por hilo muerto, el test tarda
    _fake_scapy(monkeypatch, _sniffer_cls(thread=DeadThread()))
    t0 = time.monotonic()
    ScapySource("eth0").start(lambda *a: None)
    assert time.monotonic() - t0 < 2.0


def test_scapy_thread_none_no_rompe(monkeypatch):
    _timeout(monkeypatch, 0.2)
    _fake_scapy(monkeypatch, _sniffer_cls(thread=None))
    ScapySource("eth0").start(lambda *a: None)  # sin hilo conocido: cae por timeout


def test_scapy_sniffer_sin_atributo_exception_se_traduce(monkeypatch):
    # Un AsyncSniffer sin .exception/.thread (versión rara)
    class Raro:
        def __init__(self, **kw):
            pass

        def start(self):
            pass

    _fake_scapy(monkeypatch, Raro)
    _timeout(monkeypatch, 0.2)
    with pytest.raises(CaptureError, match="eth0"):
        ScapySource("eth0").start(lambda *a: None)


def test_scapy_error_oculto_si_ready_ya_estaba_marcado(monkeypatch):
    # ready + exception a la vez: el error guardado gana (se revisa al final)
    _fake_scapy(monkeypatch, _sniffer_cls(call_ready=True, exception=PermissionError("no")))
    with pytest.raises(PermissionDenied):
        ScapySource("eth0").start(lambda *a: None)


@pytest.mark.parametrize("exc,cls", [
    (PermissionError("x"), PermissionDenied),
    (OSError("x"), CaptureError),
    (RuntimeError("x"), CaptureError),
    (ValueError("x"), CaptureError),
])
def test_start_error_traduccion(exc, cls):
    out = ScapySource("eth0")._start_error(exc)
    assert type(out) is cls


def test_live_capture_propaga_permission_denied_y_permite_reintento(tmp_path, monkeypatch):
    made = []
    _fake_scapy(monkeypatch, _sniffer_cls(exception=PermissionError("no"), registry=made))
    cap = LiveCapture(ScapySource("eth0"))  # sin out_path: carpeta temporal propia
    temp = cap.temp_dir
    try:
        assert temp is not None and temp.is_dir()
        with pytest.raises(PermissionDenied):
            cap.start()
        assert cap._fh.closed and cap.status()["state"] == "idle" and not cap.running
        assert temp.is_dir()  # start() NO borra la carpeta
        cap.cleanup()  # permitido: no está en curso
        assert not temp.exists()
        # reintento sobre el mismo objeto una vez resuelto el problema
        cap._source._sniffer = None
        _fake_scapy(monkeypatch, _sniffer_cls(call_ready=True))
        cap.start()
        assert cap.status()["state"] == "running"
        cap.stop()
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def test_live_capture_start_fallido_sin_temp_dir_no_borra_out_path(tmp_path, monkeypatch):
    _fake_scapy(monkeypatch, _sniffer_cls(start_raises=PermissionError("no")))
    out = tmp_path / "mia.pcap"
    cap = LiveCapture(ScapySource("eth0"), out)
    with pytest.raises(PermissionDenied):
        cap.start()
    cap.cleanup()
    assert out.exists()  # la ruta del llamador nunca se borra


def test_scapy_source_stop_sin_start_y_con_error():
    ScapySource("eth0").stop()  # no debe lanzar
    s = ScapySource("eth0")

    class Mal:
        running = True

        def stop(self):
            raise RuntimeError("x")

    s._sniffer = Mal()
    s.stop()


# ------------------------------------------------------------------ warning

def test_warning_none_en_captura_normal(tmp_path):
    src, cap = make(tmp_path)
    cap.start()
    assert cap.status()["warning"] is None
    src.emit(1.0, b"a")
    s = cap.stop()
    assert s.warning is None and cap.status()["warning"] is None


def test_status_tiene_claves_esperadas(tmp_path):
    # status() ahora incluye "warning"; por eso el conjunto de claves cambio.
    _, cap = make(tmp_path)
    assert set(cap.status()) == {"state", "packets", "bytes", "seconds", "reason", "warning"}


def test_warning_con_stop_que_lanza_tiene_mensaje_y_reason_real(tmp_path, hilo_excepciones):
    src = FakeSource(stop_exc=RuntimeError("el driver no responde"))
    _, cap = make(tmp_path, src)
    cap.start()
    assert cap.status()["warning"] is None  # antes de terminar
    src.emit(1.0, b"a")
    s = cap.stop()
    assert isinstance(s.warning, str) and "el driver no responde" in s.warning
    assert s.reason == "manual"
    st = cap.status()
    assert isinstance(st["warning"], str) and "el driver no responde" in st["warning"]
    assert st["reason"] == "manual"
    json.dumps(st)  # serializable


def test_warning_con_error_de_escritura(tmp_path):
    src, cap = make(tmp_path)
    cap.start()

    class Roto:
        def writepkt(self, *a, **k):
            raise OSError("disco lleno")

    cap._writer = Roto()
    src.emit(1.0, b"x")
    s = cap.stop()
    assert s.reason == "error"
    assert isinstance(s.warning, str) and "disco lleno" in s.warning
    st = cap.status()
    assert st["reason"] == "error" and isinstance(st["warning"], str) and "disco lleno" in st["warning"]
    json.dumps(st)
