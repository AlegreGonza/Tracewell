"""Punto de entrada de escritorio (main.py) con fakes: sin ventanas ni pywebview reales."""
import os
import subprocess
import sys
import types

import pytest

import main
from backend.api.server import ServerStartError


# ------------------------------------------------------------------ fakes

class FakeWindow:
    def __init__(self, dialog=None):
        self.dialog = dialog
        self.calls = []
        self.destroyed = 0

    def create_file_dialog(self, *a, **kw):
        self.calls.append((a, kw))
        return self.dialog

    def destroy(self):
        self.destroyed += 1


class FakeHandle:
    url = "http://127.0.0.1:5555"

    def __init__(self):
        self.stopped = 0
        self.joined = 0
        outer = self

        class T:
            def join(self_inner):
                outer.joined += 1

        self.thread = T()

    def stop(self):
        self.stopped += 1


def fake_webview(monkeypatch):
    fake = types.SimpleNamespace(FileDialog=types.SimpleNamespace(OPEN="OPEN_SENTINEL"))
    monkeypatch.setitem(sys.modules, "webview", fake)
    return fake


# ------------------------------------------------------------------ parse_args

def test_parse_args_defaults():
    # sin flags: ventana normal, puerto 0
    a = main.parse_args([])
    assert (a.serve_only, a.self_test, a.port) == (False, False, 0)


def test_parse_args_flags():
    # los tres flags se leen
    a = main.parse_args(["--serve-only", "--self-test", "--port", "8123"])
    assert (a.serve_only, a.self_test, a.port) == (True, True, 8123)


def test_parse_args_port_invalido():
    # --port abc -> SystemExit (argparse, código 2)
    with pytest.raises(SystemExit) as e:
        main.parse_args(["--port", "abc"])
    assert e.value.code == 2


@pytest.mark.parametrize("p", ["0", "1", "65535"])
def test_parse_args_puerto_limites_validos(p):
    # 0 a 65535 es válido
    assert main.parse_args(["--port", p]).port == int(p)


@pytest.mark.parametrize("p", ["99999", "65536", "-1", "abc", ""])
def test_parse_args_puerto_invalido_sin_traceback(p, capsys):
    # fuera de rango / no numérico -> SystemExit(2) de argparse y el mensaje menciona el puerto
    with pytest.raises(SystemExit) as e:
        main.parse_args(["--port", p])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "--port" in err and "Traceback" not in err


def test_parse_args_puerto_fuera_de_rango_mensaje(capsys):
    # el mensaje de rango se muestra
    with pytest.raises(SystemExit):
        main.parse_args(["--port", "99999"])
    assert "fuera de rango" in capsys.readouterr().err


def test_parse_args_help():
    # --help sale con código 0
    with pytest.raises(SystemExit) as e:
        main.parse_args(["--help"])
    assert e.value.code == 0


# ------------------------------------------------------------------ DesktopApi

def test_pick_file_devuelve_primera_ruta(monkeypatch):
    # devuelve la primera ruta del diálogo
    fake_webview(monkeypatch)
    api = main.DesktopApi()
    api._bind(FakeWindow(dialog=("C:/a.pcap", "C:/b.pcap")))
    assert api.pick_file() == "C:/a.pcap"


@pytest.mark.parametrize("valor", [None, (), []])
def test_pick_file_cancelado(monkeypatch, valor):
    # diálogo cancelado (None o vacío) -> None
    fake_webview(monkeypatch)
    api = main.DesktopApi()
    api._bind(FakeWindow(dialog=valor))
    assert api.pick_file() is None


def test_pick_file_argumentos(monkeypatch):
    # usa FileDialog.OPEN, allow_multiple=False y filtros pcap/pcapng
    fake_webview(monkeypatch)
    w = FakeWindow(dialog=("x",))
    api = main.DesktopApi()
    api._bind(w)
    api.pick_file()
    args, kw = w.calls[0]
    assert args == ("OPEN_SENTINEL",)
    assert kw["allow_multiple"] is False
    assert any("*.pcap" in t and "*.pcapng" in t for t in kw["file_types"])


def test_pick_file_abre_en_carpeta_permitida(monkeypatch, tmp_path):
    # el selector arranca en la primera carpeta permitida que existe
    fake_webview(monkeypatch)
    inexistente = tmp_path / "no_existe"
    monkeypatch.setenv("TRACEWELL_ALLOWED_DIRS", f"{inexistente}{os.pathsep}{tmp_path}")
    w = FakeWindow(dialog=("x",))
    api = main.DesktopApi()
    api._bind(w)
    api.pick_file()
    assert w.calls[0][1]["directory"] == str(tmp_path.resolve())


def test_pick_file_sin_carpetas_existentes_no_fija_directorio(monkeypatch, tmp_path):
    fake_webview(monkeypatch)
    monkeypatch.setenv("TRACEWELL_ALLOWED_DIRS", str(tmp_path / "no_existe"))
    w = FakeWindow(dialog=("x",))
    api = main.DesktopApi()
    api._bind(w)
    api.pick_file()
    assert w.calls[0][1]["directory"] == ""


def test_pick_file_sin_bind_falla_con_attributeerror(monkeypatch):
    # sin _bind(), _window es None
    fake_webview(monkeypatch)
    with pytest.raises(AttributeError):
        main.DesktopApi().pick_file()


def test_window_no_es_publico():
    # lo expuesto a JS (sin guion bajo) no incluye la ventana
    publicos = [n for n in dir(main.DesktopApi()) if not n.startswith("_")]
    assert sorted(publicos) == ["get_token", "pick_file"]
    assert "window" not in publicos


def test_importar_main_no_importa_webview():
    # la importación de pywebview es perezosa (proceso limpio)
    code = "import sys, main; sys.exit(1 if 'webview' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-c", code], cwd=str(main.__file__).rsplit("main.py", 1)[0]).returncode == 0


# ------------------------------------------------------------------ _wait_until / _probe

def test_wait_until_true_a_la_tercera(monkeypatch):
    # devuelve True cuando el script da verdadero a la 3ª evaluación
    monkeypatch.setattr(main.time, "sleep", lambda s: None)
    vals = iter([False, None, True])
    monkeypatch.setattr(main, "_eval", lambda w, s: next(vals))
    assert main._wait_until(object(), "x") is True


def test_wait_until_nunca_da_false_y_respeta_timeout(monkeypatch):
    # si nunca da verdadero devuelve False al agotar el plazo (reloj falso)
    reloj = {"t": 0.0}
    monkeypatch.setattr(main.time, "monotonic", lambda: reloj["t"])
    monkeypatch.setattr(main.time, "sleep", lambda s: reloj.__setitem__("t", reloj["t"] + s))
    n = []
    monkeypatch.setattr(main, "_eval", lambda w, s: n.append(1) or False)
    assert main._wait_until(object(), "x", timeout=1.0) is False
    assert 3 <= len(n) <= 6  # ~1s / 0.25s


def test_wait_until_timeout_real_chico():
    # con timeout real chico no se cuelga
    assert main._wait_until(types.SimpleNamespace(evaluate_js=lambda s: False), "x", timeout=0.3) is False


class ProbeWindow:
    def __init__(self, loaded=True, title="Tracewell", brand=True, picker=True, demo=True):
        self.cfg = dict(loaded=loaded, title=title, brand=brand, picker=picker, demo=demo)
        self.waited = None
        outer = self

        class Ev:
            def wait(self_inner, timeout):
                outer.waited = timeout
                return outer.cfg["loaded"]

        self.events = types.SimpleNamespace(loaded=Ev())
        self.scripts = []

    def evaluate_js(self, script):
        self.scripts.append(script)
        c = self.cfg
        if script == "document.title":
            return c["title"]
        if ".brand" in script:
            return c["brand"]
        if "pick_file" in script:
            return c["picker"]
        if "Credenciales FTP" in script:
            return c["demo"]
        return None  # el click


@pytest.fixture
def rapido(monkeypatch):
    monkeypatch.setattr(main.time, "sleep", lambda s: None)
    reloj = {"t": 0.0}

    def mono():
        reloj["t"] += 0.01
        return reloj["t"]

    monkeypatch.setattr(main.time, "monotonic", mono)


def test_probe_window_todo_ok(rapido):
    # ventana sana -> todos los checks verdaderos y se hizo click en demo
    w = ProbeWindow()
    r = main._probe_window(w)
    assert r == {"page_loaded": True, "title": "Tracewell", "brand": True, "native_picker": True, "demo_loaded": True}
    assert w.waited == main.LOAD_TIMEOUT
    assert any(".click()" in s for s in w.scripts)


def test_probe_window_carga_no_termina(rapido):
    # si events.loaded.wait da False -> page_loaded False
    r = main._probe_window(ProbeWindow(loaded=False))
    assert r["page_loaded"] is False


def test_probe_window_brand_se_castea_a_bool(rapido):
    # brand None/ausente -> False (bool)
    r = main._probe_window(ProbeWindow(brand=None))
    assert r["brand"] is False


# ------------------------------------------------------------------ _self_test

CAMPOS = ["page_loaded", "title", "brand", "native_picker", "demo_loaded"]
BUENO = {"page_loaded": True, "title": "Tracewell", "brand": True, "native_picker": True, "demo_loaded": True}


def _self_test_con(monkeypatch, checks):
    monkeypatch.setattr(main, "_probe_window", lambda w: dict(checks))
    w, res = FakeWindow(), {"ok": False}
    main._self_test(w, res)
    return w, res


def test_self_test_todo_bien(monkeypatch):
    # todo verdadero -> ok True y ventana destruida
    w, res = _self_test_con(monkeypatch, BUENO)
    assert res["ok"] is True and w.destroyed == 1


@pytest.mark.parametrize("campo", CAMPOS)
def test_self_test_un_campo_falso(monkeypatch, campo):
    # un solo campo malo alcanza para ok False; igual se destruye la ventana
    malo = dict(BUENO)
    malo[campo] = "Otro" if campo == "title" else False
    w, res = _self_test_con(monkeypatch, malo)
    assert res["ok"] is False and w.destroyed == 1


def test_self_test_destruye_aunque_probe_explote(monkeypatch):
    # try/except/finally
    def boom(w):
        raise RuntimeError("sonda rota")

    monkeypatch.setattr(main, "_probe_window", boom)
    w, res = FakeWindow(), {"ok": False}
    main._self_test(w, res)
    assert w.destroyed == 1
    assert res["ok"] is False and res["error"] == "sonda rota"


def test_self_test_ok_no_deja_error(monkeypatch):
    # camino sano: sin clave "error"
    _, res = _self_test_con(monkeypatch, BUENO)
    assert "error" not in res


# ------------------------------------------------------------------ main()

def test_main_start_falla_devuelve_1(monkeypatch, capsys):
    # ServerStartError al arrancar -> mensaje a stderr y 1
    def boom(**kw):
        raise ServerStartError("no arranca")

    monkeypatch.setattr(main, "start_in_thread", boom)
    assert main.main([]) == 1
    cap = capsys.readouterr()
    assert "no arranca" in cap.err and cap.out == ""


def test_main_oserror_devuelve_1(monkeypatch, capsys):
    # OSError (puerto ocupado) -> stderr y 1
    def boom(**kw):
        raise OSError("puerto ocupado")

    monkeypatch.setattr(main, "start_in_thread", boom)
    assert main.main(["--port", "80"]) == 1
    assert "puerto ocupado" in capsys.readouterr().err


def test_main_pasa_el_puerto(monkeypatch):
    # --port llega a start_in_thread
    visto = {}
    h = FakeHandle()

    def fake(**kw):
        visto.update(kw)
        return h

    monkeypatch.setattr(main, "start_in_thread", fake)
    monkeypatch.setattr(main, "_open_window", lambda *a, **k: {"ok": True})
    main.main(["--port", "4321"])
    assert visto["port"] == 4321
    assert isinstance(visto["api_token"], str) and len(visto["api_token"]) >= 32


def test_main_serve_only(monkeypatch, capsys):
    # --serve-only: imprime la URL, no abre ventana, stop() en finally, 0
    h = FakeHandle()
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)
    llamado = []
    monkeypatch.setattr(main, "_open_window", lambda *a, **k: llamado.append(1))
    assert main.main(["--serve-only"]) == 0
    assert "http://127.0.0.1:5555" in capsys.readouterr().out
    assert llamado == [] and h.joined == 1 and h.stopped == 1


def test_main_importerror_ventana(monkeypatch, capsys):
    # sin pywebview: mensaje con pywebview/--serve-only, 1, y stop() igual
    h = FakeHandle()
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)

    def sin_webview(*a, **k):
        raise ImportError("No module named 'webview'")

    monkeypatch.setattr(main, "_open_window", sin_webview)
    assert main.main([]) == 1
    err = capsys.readouterr().err
    assert "pywebview" in err and "--serve-only" in err
    assert h.stopped == 1


@pytest.mark.parametrize("exc", [RuntimeError("WebView2 no disponible"), OSError("WebView2 no disponible")])
def test_main_fallo_generico_de_ventana(monkeypatch, capsys, exc):
    # cualquier excepción al abrir la ventana
    h = FakeHandle()
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)

    def falla(*a, **k):
        raise exc

    monkeypatch.setattr(main, "_open_window", falla)
    assert main.main([]) == 1
    err = capsys.readouterr().err
    assert "WebView2 no disponible" in err and "--serve-only" in err and "Traceback" not in err
    assert h.stopped == 1


def test_main_ruleerror_al_iniciar_devuelve_1(monkeypatch, capsys):
    # RuleError (regla YAML mala) al iniciar: stderr y 1, sin traceback
    from backend.domain.rules.engine import RuleError

    def boom(**kw):
        raise RuleError("regla rota")

    monkeypatch.setattr(main, "start_in_thread", boom)
    assert main.main([]) == 1
    err = capsys.readouterr().err
    assert "regla rota" in err and "Traceback" not in err


def test_main_modo_normal(monkeypatch):
    # modo normal: _open_window recibe la URL y hidden False, self_test False; devuelve 0
    h = FakeHandle()
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)
    visto = {}

    def fake(url, hidden=False, self_test=False, token=None):
        visto.update(url=url, hidden=hidden, self_test=self_test, token=token)
        return {"ok": False}

    monkeypatch.setattr(main, "_open_window", fake)
    assert main.main([]) == 0
    token = visto.pop("token")
    assert isinstance(token, str) and len(token) >= 32
    assert visto == {"url": h.url, "hidden": False, "self_test": False}
    assert h.stopped == 1


@pytest.mark.parametrize("ok,code", [(True, 0), (False, 1)])
def test_main_self_test(monkeypatch, capsys, ok, code):
    # --self-test: ventana oculta; 0 si ok, 1 si no; imprime el JSON
    h = FakeHandle()
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)
    visto = {}

    def fake(url, hidden=False, self_test=False, token=None):
        visto.update(hidden=hidden, self_test=self_test)
        return {"ok": ok, "title": "Tracewell"}

    monkeypatch.setattr(main, "_open_window", fake)
    assert main.main(["--self-test"]) == code
    assert visto == {"hidden": True, "self_test": True}
    assert '"ok": %s' % str(ok).lower() in capsys.readouterr().out
    assert h.stopped == 1


def test_desktop_api_entrega_el_token():
    assert main.DesktopApi("abc").get_token() == "abc"
    assert main.DesktopApi().get_token() is None


def test_new_token_es_aleatorio_y_se_puede_fijar(monkeypatch):
    monkeypatch.delenv("TRACEWELL_API_TOKEN", raising=False)
    a, b = main._new_token(), main._new_token()
    assert a != b and len(a) >= 32
    monkeypatch.setenv("TRACEWELL_API_TOKEN", "fijo-de-16-chars!")
    assert main._new_token() == "fijo-de-16-chars!"


@pytest.mark.parametrize("corto", ["", "a", "123456789012345"])
def test_token_fijado_demasiado_corto_se_rechaza(monkeypatch, capsys, corto):
    monkeypatch.setenv("TRACEWELL_API_TOKEN", corto)
    with pytest.raises(ValueError, match="al menos 16"):
        main._new_token()
    # main() lo informa y sale con 1 sin levantar la API
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: pytest.fail("no debe arrancar"))
    assert main.main(["--serve-only"]) == 1
    assert "TRACEWELL_API_TOKEN" in capsys.readouterr().err


def test_serve_only_imprime_la_url_con_el_token_en_el_fragmento(capsys):
    h = FakeHandle()
    h.thread.join = lambda: None
    main._serve_forever(h, "tok123")
    assert f"{h.url}/#token=tok123" in capsys.readouterr().out


def test_serve_forever_keyboardinterrupt_no_propaga(capsys):
    # Ctrl+C durante el join se traga y la función vuelve
    h = FakeHandle()

    def join():
        raise KeyboardInterrupt

    h.thread.join = join
    main._serve_forever(h)
    assert "127.0.0.1:5555" in capsys.readouterr().out


def test_main_serve_only_ctrl_c_devuelve_0_y_para(monkeypatch):
    # Ctrl+C en --serve-only: sale con 0 y apaga la API
    h = FakeHandle()

    def join():
        raise KeyboardInterrupt

    h.thread.join = join
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: h)
    assert main.main(["--serve-only"]) == 0
    assert h.stopped == 1


# ------------------------------------------------------------------ ventana (con webview falso)

def test_open_window_modo_normal_y_self_test(monkeypatch):
    # _open_window crea la ventana con webview falso y llama a start (con/sin callback)
    llamadas = {}
    win = FakeWindow()

    def create_window(title, url, **kw):
        llamadas["create"] = (title, url, kw)
        return win

    def start(*a):
        llamadas["start"] = a

    fake = types.SimpleNamespace(create_window=create_window, start=start)
    monkeypatch.setitem(sys.modules, "webview", fake)

    r = main._open_window("http://x", hidden=True, self_test=False)
    assert r == {"ok": False} and llamadas["start"] == ()
    t, u, kw = llamadas["create"]
    assert (t, u) == ("Tracewell", "http://x")
    assert kw["hidden"] is True and kw["text_select"] is True
    assert isinstance(kw["js_api"], main.DesktopApi) and kw["js_api"]._window is win

    main._open_window("http://x", hidden=True, self_test=True)
    assert llamadas["start"][0] is main._self_test and llamadas["start"][1][0] is win


# ------------------------------------------------------------------ limpieza al arrancar

def test_main_limpia_una_vez_y_antes_de_levantar_la_api(monkeypatch):
    # --serve-only: cleanup_stale_temp_dirs corre UNA vez y antes de start_in_thread
    orden = []
    h = FakeHandle()
    monkeypatch.setattr(main, "cleanup_stale_temp_dirs", lambda *a, **k: orden.append("limpieza") or [])
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: orden.append("start") or h)
    assert main.main(["--serve-only"]) == 0
    assert orden == ["limpieza", "start"] and h.stopped == 1


def test_main_si_la_limpieza_lanza_se_propaga_y_no_arranca(monkeypatch):
    # comportamiento real: main no captura la excepcion de la limpieza; la API no arranca
    arranco = []

    def boom():
        raise RuntimeError("limpieza rota")

    monkeypatch.setattr(main, "cleanup_stale_temp_dirs", boom)
    monkeypatch.setattr(main, "start_in_thread", lambda **kw: arranco.append(1))
    with pytest.raises(RuntimeError):
        main.main(["--serve-only"])
    assert arranco == []
