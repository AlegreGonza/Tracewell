"""Tests de backend/domain/system/overview.py con psutil falso."""
import pytest

from backend.domain.system import overview as ov
from backend.domain.system.common import SystemUnavailable
from backend.domain.system.tests.fakes import FakePsutil, FakeProcess, patch_psutil


def run(monkeypatch, **kw):
    patch_psutil(monkeypatch, FakePsutil(**kw))
    return ov.overview()


def test_estructura_completa(monkeypatch):
    o = run(monkeypatch, procs=[FakeProcess(1), FakeProcess(2), FakeProcess(3)], boot=0.0)
    assert set(o) == {"cpu_percent", "cpu_count", "cpu_physical", "memory", "swap", "disks", "network_total", "battery", "uptime_seconds", "process_count"}
    assert o["cpu_percent"] == 12.5 and o["cpu_count"] == 4 and o["cpu_physical"] == 2 and o["process_count"] == 3


def test_memoria_usada_es_total_menos_disponible(monkeypatch):
    m = run(monkeypatch)["memory"]
    assert m == {"total": 8000, "available": 3000, "used": 5000, "percent": 62.5}


def test_swap_red_bateria(monkeypatch):
    o = run(monkeypatch)
    assert o["swap"] == {"total": 1000, "used": 100, "percent": 10.0}
    assert o["network_total"] == {"sent": 111, "received": 222}
    assert o["battery"] == {"percent": 80.0, "plugged": True}


def test_bateria_se_redondea(monkeypatch):
    assert run(monkeypatch, battery=(55.4567, False))["battery"] == {"percent": 55.5, "plugged": False}


@pytest.mark.parametrize("field,kw", [("swap", {"swap": None}), ("battery", {"battery": None}), ("network_total", {"net_io": None})])
def test_datos_ausentes_son_none(monkeypatch, field, kw):
    assert run(monkeypatch, **kw)[field] is None


@pytest.mark.parametrize("deny,field", [("swap_memory", "swap"), ("sensors_battery", "battery"), ("net_io_counters", "network_total")])
def test_accessdenied_en_una_lectura_no_rompe(monkeypatch, deny, field):
    o = run(monkeypatch, deny=[deny])
    assert o[field] is None and o["memory"]["total"] == 8000


def test_sin_hora_de_arranque_uptime_none(monkeypatch):
    assert run(monkeypatch, deny=["boot_time"])["uptime_seconds"] is None


def test_uptime_se_calcula(monkeypatch):
    monkeypatch.setattr(ov.time, "time", lambda: 5_000.0)
    assert run(monkeypatch, boot=1_000.0)["uptime_seconds"] == 4000


def test_discos_se_listan_y_los_ilegibles_se_omiten(monkeypatch):
    disks = run(monkeypatch)["disks"]
    assert disks == [{"mount": "C:\\", "fstype": "NTFS", "total": 1000, "used": 400, "percent": 40.0}]  # D: dio AccessDenied


def test_particiones_ilegibles_dan_lista_vacia(monkeypatch):
    assert run(monkeypatch, deny=["disk_partitions"])["disks"] == []


def test_sin_cpu_fisico_es_none(monkeypatch):
    o = run(monkeypatch, deny=["cpu_physical"])
    assert o["cpu_physical"] is None and o["cpu_count"] == 4


def test_cpu_se_mide_con_un_intervalo_corto(monkeypatch):
    seen = {}
    fake = FakePsutil()
    orig = fake.cpu_percent
    fake.cpu_percent = lambda interval=None: seen.setdefault("i", interval) or orig(interval)
    patch_psutil(monkeypatch, fake)
    ov.overview()
    assert seen["i"] == 0.2


def test_sin_psutil_se_propaga_systemunavailable(monkeypatch):
    def raise_():
        raise SystemUnavailable("falta")
    monkeypatch.setattr(ov, "psutil_or_raise", raise_)
    with pytest.raises(SystemUnavailable):
        ov.overview()


def test_la_salida_es_serializable_en_json(monkeypatch):
    import json
    json.dumps(run(monkeypatch))
