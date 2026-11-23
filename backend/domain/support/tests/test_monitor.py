"""monitor: máquina de estados de cortes y ciclo de vida del hilo (muestreo falso)."""
import threading
import time

import pytest

from backend.domain.support import monitor as M


@pytest.fixture
def mon():
    m = M.Monitor()
    yield m
    m.stop()


def feed(m, *layers, t0=100.0):
    for i, layer in enumerate(layers):
        m._track(layer, t0 + i)


def test_un_fallo_no_abre_corte(mon):
    feed(mon, "dns", None)
    assert mon.outages == []


def test_dos_fallos_abren_y_ok_cierra(mon):
    feed(mon, "dns", "dns")
    assert len(mon.outages) == 1 and "end" not in mon.outages[0] and mon.outages[0]["start"] == 100.0
    feed(mon, None, t0=105.0)
    assert mon.outages[0]["end"] == 105.0
    feed(mon, "dns", None, "dns", None)
    assert len(mon.outages) == 1  # fallos aislados no abren


def test_capa_mas_grave_gana(mon):
    feed(mon, "dns", "internet", "red local", "dns")
    assert len(mon.outages) == 1 and mon.outages[0]["layer"] == "red local"


def test_stop_cierra_corte_abierto(mon):
    feed(mon, "internet", "internet")
    mon.stop()
    assert "end" in mon.outages[0]


def test_clear(mon):
    feed(mon, "internet", "internet")
    mon.total = 5
    mon.clear()
    assert mon.outages == [] and mon.total == 0 and mon.status()["current"] == "sin datos"


def test_status_ordena_y_marca_ongoing(mon):
    feed(mon, "dns", "dns", None, t0=100.0)
    feed(mon, "internet", "internet", t0=200.0)
    s = mon.status()
    assert [o["start"] for o in s["outages"]] == [200.0, 100.0]
    assert [o["ongoing"] for o in s["outages"]] == [True, False]
    assert s["outage_count"] == 2 and s["outages"][1]["duration"] == 2.0


@pytest.fixture
def fast(monkeypatch):
    calls = []
    monkeypatch.setattr(M, "default_gateway", lambda: None)
    monkeypatch.setattr(M, "wifi_status", lambda: {"available": False})

    def sample(self, pool):
        calls.append(1)

    monkeypatch.setattr(M.Monitor, "_sample", sample)
    return calls


@pytest.mark.parametrize("given,expected", [(0.1, 1.0), (-5, 1.0), (500, 30.0), (3, 3.0)])
def test_intervalo_acotado(mon, fast, given, expected):
    mon.start(given)
    assert mon.interval == expected
    mon.stop()


def test_start_idempotente_y_stop_termina_hilo(mon, fast):
    mon.start(1.0)
    th = mon._thread
    time.sleep(0.05)
    mon.start(25)  # ya corre: no cambia nada
    assert mon._thread is th and mon.interval == 1.0 and mon.running
    mon.stop()
    assert not th.is_alive() and not mon.running
    assert fast  # llegó a muestrear
    assert not [t for t in threading.enumerate() if t.name == "tracewell-monitor" and t.is_alive()]
