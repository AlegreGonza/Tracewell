"""API de procesos por socket: captura en vivo con fuente y muestreador FALSOS (sin sistema real)."""
import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.app import _shutdown, create_app
from backend.controllers.state import _State
from backend.domain.pcap.live import InterfaceInfo
from backend.domain.pcap.processes import Conn, ProcessInfo, ProcessTable
from backend.domain.pcap.reader import iter_packets

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "samples" / "demo.pcap"

CHROME = ProcessInfo(100, "chrome.exe")
DNS = ProcessInfo(200, "dnsclient")


class FakeSource:
    def __init__(self):
        self.on_packet = None

    def start(self, on_packet):
        self.on_packet = on_packet

    def stop(self):
        pass

    def feed_demo(self):
        for p in iter_packets(DEMO):
            self.on_packet(p.ts, p.data)


class FakeSampler:
    """Muestreador falso: nada de hilos ni psutil. `samples` lo fija el test."""

    def __init__(self, samples=1, conns=None, stop_exc=None, start_exc=None):
        self.table = ProcessTable()
        self.samples = samples
        self.started = 0
        self.stopped = 0
        self.stop_exc = stop_exc
        self.start_exc = start_exc
        for c in conns if conns is not None else default_conns():
            self.table.add(c)
        self.table.set_local_ips(["192.168.1.10"])

    def start(self):
        if self.start_exc:
            raise self.start_exc
        self.started += 1

    def stop(self):
        self.stopped += 1
        if self.stop_exc:
            raise self.stop_exc


def default_conns():
    return [
        # sesión 3 (TCP 192.168.1.10:51000 -> 93.184.216.34:80), vista desde el lado local
        Conn("TCP", "192.168.1.10", 51000, "93.184.216.34", 80, CHROME),
        # sesión 0 (UDP 192.168.1.10:40000 -> 192.168.1.1:53), vista desde el lado remoto
        Conn("UDP", "192.168.1.1", 53, "192.168.1.10", 40000, DNS),
    ]


class Env:
    def __init__(self, tmp_path, sampler_factory):
        self.sources = []

        def factory(iface):
            s = FakeSource()
            self.sources.append(s)
            return s

        self.app = create_app(source_factory=factory, interface_lister=lambda: [InterfaceInfo("e", "E")],
                              live_dir=tmp_path, sampler_factory=sampler_factory)
        self.client = TestClient(self.app)
        self.state = self.app.state.ctx.state

    def start(self):
        r = self.client.post("/api/live/start", json={"interface": "eth0"})
        assert r.status_code == 200
        return r

    def run_capture(self):
        self.start()
        self.sources[-1].feed_demo()
        r = self.client.post("/api/live/stop")
        assert r.status_code == 200
        return r

    def sessions(self, **params):
        r = self.client.get("/api/sessions", params={"limit": 500, **params})
        assert r.status_code == 200
        return {s["id"]: s for s in r.json()["items"]}


def make_env(tmp_path, **sampler_kw):
    made = []

    def factory():
        s = FakeSampler(**sampler_kw)
        made.append(s)
        return s

    env = Env(tmp_path, factory)
    env.made = made
    return env


# ----------------------------------------------------------- flujo principal
def test_start_stop_sesiones_traen_process(tmp_path):
    env = make_env(tmp_path)
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is True
    s = env.made[0]
    assert s.started == 1 and s.stopped == 1
    items = env.sessions()
    assert items[3]["process"] == {"pid": 100, "name": "chrome.exe"}
    assert items[0]["process"] == {"pid": 200, "name": "dnsclient"}  # orientación inversa
    assert "process" in items[4] and items[4]["process"] is None  # ICMP: clave presente, valor null
    assert all("process" in s for s in items.values())  # presente en TODAS cuando hay datos
    assert env.client.get("/api/capture").json()["processes"] is True


def test_sin_sampler_no_hay_clave_ni_processes(tmp_path):
    env = Env(tmp_path, None)
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is False
    assert env.state.processes is None
    assert all("process" not in s for s in env.sessions().values())
    assert env.client.get("/api/capture").json()["processes"] is False


def test_factory_devuelve_none(tmp_path):
    env = Env(tmp_path, lambda: None)
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is False
    assert all("process" not in s for s in env.sessions().values())


def test_cero_muestras_exitosas_sin_datos(tmp_path):
    env = make_env(tmp_path, samples=0)
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is False
    assert env.state.processes is None
    assert env.made[0].stopped == 1  # igual se detuvo
    assert all("process" not in s for s in env.sessions().values())


def test_tabla_vacia_pero_con_muestras_ofrece_columna_con_nulls(tmp_path):
    env = make_env(tmp_path, conns=[])
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is True
    items = env.sessions()
    assert all(s["process"] is None for s in items.values())


def test_stop_repetido_no_detiene_dos_veces_ni_cambia_resultado(tmp_path):
    env = make_env(tmp_path)
    first = env.run_capture().json()
    again = env.client.post("/api/live/stop").json()
    assert first == again
    assert env.made[0].stopped == 1
    assert env.state.sampler is None


def test_fallo_en_make_sampler_no_impide_captura(tmp_path):
    def boom():
        raise RuntimeError("psutil roto")

    env = Env(tmp_path, boom)
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is False
    assert r.json()["capture"]["packets"] > 0
    assert env.state.sampler is None


def test_fallo_en_sampler_start_no_impide_captura(tmp_path):
    env = make_env(tmp_path, start_exc=RuntimeError("no arranca"))
    r = env.run_capture()
    assert r.json()["analysis"]["processes"] is False
    assert all("process" not in s for s in env.sessions().values())


# ------------------------------------------------- reemplazo y reinicio
def test_demo_despues_de_vivo_resetea_processes(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    assert env.state.processes is not None
    r = env.client.post("/api/demo")
    assert r.status_code == 200 and r.json()["processes"] is False
    assert env.state.processes is None
    assert all("process" not in s for s in env.sessions().values())
    assert env.client.get("/api/capture").json()["processes"] is False


def test_analyze_archivo_despues_de_vivo_resetea_processes(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    r = env.client.post("/api/analyze", json={"path": str(DEMO)})
    assert r.status_code == 200 and r.json()["processes"] is False
    assert env.state.processes is None


def test_demo_nunca_tiene_processes(tmp_path):
    env = make_env(tmp_path)
    r = env.client.post("/api/demo")
    assert r.json()["processes"] is False
    assert env.made == []  # no se creó muestreador fuera de la captura en vivo


def test_segunda_captura_reemplaza_la_tabla(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    first_table = env.state.processes
    env.run_capture()
    assert env.state.processes is not first_table
    assert len(env.made) == 2


def test_segunda_captura_sin_muestras_borra_la_tabla_previa(tmp_path):
    samples = iter([1, 0])

    def factory():
        return FakeSampler(samples=next(samples))

    env = Env(tmp_path, factory)
    env.run_capture()
    assert env.state.processes is not None
    env.run_capture()
    assert env.state.processes is None
    assert all("process" not in s for s in env.sessions().values())


def test_sampler_sobrante_se_finaliza_al_iniciar_otra_captura(tmp_path):
    env = make_env(tmp_path)
    leftover = FakeSampler()
    env.state.sampler = leftover  # quedó de una captura anterior
    env.start()
    assert leftover.stopped == 1
    assert env.state.sampler is env.made[0] and env.state.sampler is not leftover
    env.client.post("/api/live/stop")


def test_start_rechazado_por_captura_en_curso_no_toca_el_sampler(tmp_path):
    env = make_env(tmp_path)
    env.start()
    current = env.state.sampler
    r = env.client.post("/api/live/start", json={"interface": "eth0"})
    assert r.status_code == 409
    assert env.state.sampler is current and current.stopped == 0
    assert len(env.made) == 1
    env.client.post("/api/live/stop")


# -------------------------------------------------------------------- export
def _export(env, **params):
    r = env.client.get("/api/export", params=params)
    assert r.status_code == 200
    return json.loads(r.text)


def test_export_por_defecto_sin_process(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    rep = _export(env)
    assert rep["sessions"] and all("process" not in s for s in rep["sessions"])
    assert "chrome.exe" not in env.client.get("/api/export").text


@pytest.mark.parametrize("value", ["false", "0"])
def test_export_processes_false_sin_process(tmp_path, value):
    env = make_env(tmp_path)
    env.run_capture()
    assert all("process" not in s for s in _export(env, processes=value)["sessions"])


def test_export_processes_true_agrega_process(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    rep = _export(env, processes="true")
    by_id = {s["id"]: s for s in rep["sessions"]}
    assert by_id[3]["process"] == {"pid": 100, "name": "chrome.exe"}
    assert by_id[0]["process"] == {"pid": 200, "name": "dnsclient"}
    assert by_id[4]["process"] is None
    assert all("process" in s for s in rep["sessions"])


def test_export_processes_true_sin_datos_no_agrega(tmp_path):
    env = Env(tmp_path, None)
    env.run_capture()
    assert all("process" not in s for s in _export(env, processes="true")["sessions"])


def test_export_processes_true_de_un_archivo_no_agrega(tmp_path):
    env = make_env(tmp_path)
    env.client.post("/api/demo")
    assert all("process" not in s for s in _export(env, processes="true")["sessions"])


def test_export_filtrado_mapea_las_sesiones_correctas(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    # filtrando, los ids del reporte siguen siendo los del análisis original
    rep = _export(env, processes="true", protocol="TCP", ip="93.184.216.34")
    assert rep["sessions"]
    for s in rep["sessions"]:
        assert s["dst_ip"] == "93.184.216.34" or s["src_ip"] == "93.184.216.34"
        expected = env.sessions()[s["id"]]["process"]
        assert s["process"] == expected
    ids = {s["id"] for s in rep["sessions"]}
    assert 3 in ids and 0 not in ids
    assert {s["id"]: s for s in rep["sessions"]}[3]["process"]["name"] == "chrome.exe"


def test_export_filtrado_udp_toma_el_proceso_del_dns(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    rep = _export(env, processes="true", protocol="UDP", port=53)
    by_id = {s["id"]: s for s in rep["sessions"]}
    assert by_id[0]["process"]["name"] == "dnsclient"
    assert all(s["id"] != 3 for s in rep["sessions"])


# ---------------------------------------------------------------- shutdown
def test_shutdown_detiene_el_sampler():
    st = _State()
    st.sampler = FakeSampler()
    _shutdown(st)
    assert st.sampler.stopped == 1


def test_shutdown_detiene_el_sampler_aunque_falle_la_captura():
    class BadCap:
        running = True

        def stop(self):
            raise ValueError("no es CaptureError")

        def cleanup(self):
            pass

    st = _State()
    st.live = BadCap()
    st.sampler = FakeSampler()
    with pytest.raises(ValueError):
        _shutdown(st)
    assert st.sampler.stopped == 1


def test_shutdown_sin_sampler_ok():
    _shutdown(_State())


def test_lifespan_cierra_el_sampler_en_curso(tmp_path):
    env = make_env(tmp_path)
    with TestClient(env.app) as c:
        assert c.post("/api/live/start", json={"interface": "e"}).status_code == 200
        sampler = env.state.sampler
        assert sampler.stopped == 0
    assert sampler.stopped == 1


# ------------------------------------------------------ sesiones concurrentes
def test_sesiones_con_filtros_y_paginado_conservan_process(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    r = env.client.get("/api/sessions", params={"protocol": "TCP", "limit": 2, "offset": 0})
    items = r.json()["items"]
    assert len(items) == 2 and all("process" in s for s in items)


def test_lectura_de_tabla_mientras_otro_hilo_escribe(tmp_path):
    env = make_env(tmp_path)
    env.run_capture()
    table = env.state.processes
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            table.add(Conn("TCP", "10.9.9.9", 1 + i % 60000, "1.1.1.1", 1, CHROME))
            i += 1

    th = threading.Thread(target=writer)
    th.start()
    try:
        for _ in range(5):
            assert env.client.get("/api/sessions", params={"limit": 50}).status_code == 200
    finally:
        stop.set()
        th.join()


def test_stop_con_captura_cambiada_409(tmp_path):
    # camino de carrera: state.live cambió entre leer la captura y tomar el candado
    env = make_env(tmp_path)
    env.start()
    cap = env.state.live

    class Swap:
        def __enter__(self_inner):
            env.state.live = object()

        def __exit__(self_inner, *a):
            return False

    env.state.stop_lock = Swap()
    r = env.client.post("/api/live/stop")
    assert r.status_code == 409
    env.state.live = cap
