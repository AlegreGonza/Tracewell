"""main._allow_downloads."""
import sys
import types

import pytest

import main


class StrictSettings(dict):
    """Como el ImmutableDict de pywebview: lanza KeyError al escribir una clave desconocida."""

    def __init__(self, **known):
        super().__init__(known)

    def __setitem__(self, key, value):
        if key not in self:
            raise KeyError(key)
        super().__setitem__(key, value)


class FrozenSettings:
    def __setitem__(self, key, value):
        raise TypeError("'FrozenSettings' object does not support item assignment")


def install(monkeypatch, **attrs):
    events = []

    def create_window(title, url, **kw):
        events.append("create_window")
        return types.SimpleNamespace(events=events)

    fake = types.SimpleNamespace(create_window=create_window, **attrs)
    monkeypatch.setitem(sys.modules, "webview", fake)
    return fake, events


def test_el_ajuste_queda_en_true_tras_create_window(monkeypatch):
    fake, _ = install(monkeypatch, settings={"ALLOW_DOWNLOADS": False})
    main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert fake.settings["ALLOW_DOWNLOADS"] is True


def test_agrega_la_clave_si_el_dict_no_la_tiene_y_deja_las_otras(monkeypatch):
    fake, _ = install(monkeypatch, settings={"OTRA": 1})
    main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert fake.settings == {"OTRA": 1, "ALLOW_DOWNLOADS": True}


def test_allow_downloads_directo():
    wv = types.SimpleNamespace(settings={})
    main._allow_downloads(wv)
    assert wv.settings["ALLOW_DOWNLOADS"] is True


def test_sin_atributo_settings_no_rompe(monkeypatch):
    _, events = install(monkeypatch)  # el falso no tiene `settings`
    win = main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert events == ["create_window"] and win is not None


def test_settings_sin_la_clave_keyerror_no_rompe(monkeypatch):
    fake, events = install(monkeypatch, settings=StrictSettings(OTRA=1))
    main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert events == ["create_window"] and "ALLOW_DOWNLOADS" not in fake.settings


def test_settings_inmutable_typeerror_no_rompe(monkeypatch):
    _, events = install(monkeypatch, settings=FrozenSettings())
    main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert events == ["create_window"]


def test_settings_none_no_rompe(monkeypatch):
    _, events = install(monkeypatch, settings=None)
    main._create_window("http://x", main.DesktopApi(), hidden=True)
    assert events == ["create_window"]


def test_otras_excepciones_no_se_tragan():
    class Boom:
        def __setitem__(self, k, v):
            raise RuntimeError("inesperado")

    with pytest.raises(RuntimeError):
        main._allow_downloads(types.SimpleNamespace(settings=Boom()))


def test_orden_primero_settings_luego_create_window(monkeypatch):
    order = []

    class Settings(dict):
        def __setitem__(self, k, v):
            order.append(("set", k, v))
            super().__setitem__(k, v)

    def create_window(title, url, **kw):
        order.append("create_window")
        return types.SimpleNamespace()

    monkeypatch.setitem(sys.modules, "webview", types.SimpleNamespace(settings=Settings(), create_window=create_window))
    main._create_window("http://x", main.DesktopApi(), hidden=False)
    assert order == [("set", "ALLOW_DOWNLOADS", True), "create_window"]


def test_create_window_sigue_pasando_sus_argumentos_y_enlaza_la_api(monkeypatch):
    seen = {}

    def create_window(title, url, **kw):
        seen.update(title=title, url=url, **kw)
        return "WIN"

    monkeypatch.setitem(sys.modules, "webview", types.SimpleNamespace(settings={}, create_window=create_window))
    api = main.DesktopApi()
    assert main._create_window("http://x", api, hidden=True) == "WIN"
    assert seen["title"] == "Tracewell" and seen["js_api"] is api and seen["text_select"] is True and seen["hidden"] is True
    assert api._window == "WIN"
