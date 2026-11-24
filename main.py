"""Punto de entrada de escritorio: un solo comando abre Tracewell en su ventana."""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import time
from typing import Any, Dict, Optional, Sequence

from backend.domain.files import resolve_allowed_dirs
from backend.domain.pcap.live import cleanup_stale_temp_dirs
from backend.domain.rules.engine import RuleError
from backend.api.security import MIN_TOKEN_LENGTH
from backend.api.server import ServerHandle, ServerStartError, start_in_thread

logger = logging.getLogger("tracewell")

TITLE = "Tracewell"
WINDOW_SIZE = (1280, 800)
MIN_SIZE = (900, 600)
FILE_TYPES = ("Capturas de red (*.pcap;*.pcapng)", "Todos los archivos (*.*)")
LOAD_TIMEOUT = 20  # segundos que esperamos a que la ventana cargue la interfaz


class DesktopApi:
    """Métodos que la interfaz puede llamar desde JavaScript (`window.pywebview.api`)."""

    def __init__(self, token: Optional[str] = None) -> None:
        self._window: Any = None  # con "_": pywebview no expone atributos privados a la web
        self._token = token

    def get_token(self) -> Optional[str]:
        """Token de la API de este arranque: solo la ventana de Tracewell lo puede pedir."""
        return self._token

    def _bind(self, window: Any) -> None:
        """Guarda la ventana (con "_" no se expone a JavaScript)."""
        self._window = window

    def pick_file(self) -> Optional[str]:
        """Abre el diálogo nativo (en una carpeta permitida) y devuelve la ruta, o None si se cancela."""
        import webview

        chosen = self._window.create_file_dialog(
            webview.FileDialog.OPEN, directory=_start_dir(), allow_multiple=False, file_types=FILE_TYPES
        )
        return chosen[0] if chosen else None


def _start_dir() -> str:
    """Primera carpeta permitida que existe (donde abre el selector); '' si ninguna."""
    for folder in resolve_allowed_dirs():
        if folder.is_dir():
            return str(folder)
    return ""


def _port(text: str) -> int:
    """Puerto válido (0-65535); si no, argparse lo informa en vez de un traceback."""
    value = int(text)  # un ValueError acá lo traduce argparse a "valor inválido"
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError(f"puerto fuera de rango (0-65535): {value}")
    return value


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="tracewell", description="Análisis de tráfico de red para triaje SOC.")
    parser.add_argument("--serve-only", action="store_true", help="no abre ventana: sirve la interfaz en 127.0.0.1")
    parser.add_argument("--self-test", action="store_true", help="abre la ventana oculta, comprueba la interfaz y sale")
    parser.add_argument("--port", type=_port, default=0, help="puerto local (0 = que elija el sistema)")
    return parser.parse_args(argv)


def _allow_downloads(webview: Any) -> None:
    """pywebview CANCELA las descargas por defecto."""
    try:
        webview.settings["ALLOW_DOWNLOADS"] = True
    except (AttributeError, KeyError, TypeError):  # una versión sin esa opción
        logger.debug("esta versión de pywebview no permite activar las descargas", exc_info=True)


def _new_token() -> str:
    """Token aleatorio por arranque; TRACEWELL_API_TOKEN lo fija (solo para el servidor de Vite)."""
    fixed = os.environ.get("TRACEWELL_API_TOKEN")
    if fixed is None:
        return secrets.token_urlsafe(32)
    if len(fixed) < MIN_TOKEN_LENGTH:
        raise ValueError(f"TRACEWELL_API_TOKEN debe tener al menos {MIN_TOKEN_LENGTH} caracteres")
    return fixed


def _create_window(url: str, api: DesktopApi, hidden: bool) -> Any:
    """Crea la ventana. `text_select`: el analista necesita copiar evidencia y hex dump."""
    import webview

    _allow_downloads(webview)
    window = webview.create_window(
        TITLE, url, js_api=api, width=WINDOW_SIZE[0], height=WINDOW_SIZE[1],
        min_size=MIN_SIZE, text_select=True, hidden=hidden,
    )
    api._bind(window)
    return window


# ---------------------------------------------------------------- autoprueba

def _eval(window: Any, script: str) -> Any:
    return window.evaluate_js(script)


def _wait_until(window: Any, script: str, timeout: float = 8.0) -> bool:
    """Reevalúa `script` hasta que dé verdadero o se agote el plazo."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _eval(window, script):
            return True
        time.sleep(0.25)
    return False


def _probe_window(window: Any) -> Dict[str, Any]:
    """Comprueba, dentro de la ventana real, que la interfaz carga y funciona."""
    loaded = window.events.loaded.wait(LOAD_TIMEOUT)
    checks: Dict[str, Any] = {"page_loaded": bool(loaded)}
    checks["title"] = _eval(window, "document.title")
    checks["brand"] = bool(_eval(window, "!!document.querySelector('.brand')"))
    checks["native_picker"] = _wait_until(
        window, "typeof (window.pywebview && window.pywebview.api && window.pywebview.api.pick_file) === 'function'"
    )
    _eval(window, "[...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Modo demo').click()")
    checks["demo_loaded"] = _wait_until(window, "document.body.innerText.includes('Credenciales FTP')")
    return checks


def _self_test(window: Any, result: Dict[str, Any]) -> None:
    """Corre en un hilo aparte (pywebview lo pide): prueba, informa y cierra la ventana."""
    try:
        result.update(_probe_window(window))
        result["ok"] = result["page_loaded"] and result["title"] == TITLE and all(
            result[k] for k in ("brand", "native_picker", "demo_loaded")
        )
    except Exception as exc:  # borde de hilo: informamos el fallo en vez de perderlo
        result["error"] = str(exc)
    finally:
        window.destroy()  # siempre: si la sonda falla, la ventana oculta no puede


# ------------------------------------------------------------------ ejecución

def _open_window(
    url: str, hidden: bool = False, self_test: bool = False, token: Optional[str] = None
) -> Dict[str, Any]:
    """Abre la ventana y bloquea hasta que se cierre; devuelve el resultado de la autoprueba."""
    import webview

    result: Dict[str, Any] = {"ok": False}
    window = _create_window(url, DesktopApi(token), hidden)
    if self_test:
        webview.start(_self_test, (window, result))
    else:
        webview.start()
    return result


def _serve_forever(handle: ServerHandle, token: Optional[str] = None) -> None:
    # El token va en el fragmento (#): no viaja al servidor ni en el Referer.
    url = f"{handle.url}/#token={token}" if token else handle.url
    print(f"Tracewell en {url}  (Ctrl+C para salir)")
    try:
        handle.thread.join()
    except KeyboardInterrupt:
        pass  # Ctrl+C es la forma normal de salir en --serve-only


def _run(args: argparse.Namespace, handle: ServerHandle, token: Optional[str] = None) -> int:
    if args.serve_only:
        _serve_forever(handle, token)
        return 0
    result = _open_window(handle.url, hidden=args.self_test, self_test=args.self_test, token=token)
    if args.self_test:
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    cleanup_stale_temp_dirs()  # restos de capturas de un cierre abrupto anterior
    try:
        token = _new_token()
    except ValueError as exc:
        print(f"No se pudo iniciar la API: {exc}", file=sys.stderr)
        return 1
    try:
        handle = start_in_thread(port=args.port, api_token=token)
    except (ServerStartError, OSError, RuleError) as exc:  # RuleError: una regla YAML mal escrita
        print(f"No se pudo iniciar la API: {exc}", file=sys.stderr)
        return 1
    try:
        return _run(args, handle, token)
    except ImportError as exc:
        print(f"Falta una dependencia de la ventana ({exc}). Instalá pywebview o usá --serve-only.", file=sys.stderr)
        return 1
    except Exception as exc:  # borde del programa: cualquier fallo de la ventana
        logger.debug("fallo al abrir la ventana", exc_info=True)
        print(f"No se pudo abrir la ventana ({exc}). Probá con --serve-only y abrí la dirección en un navegador.", file=sys.stderr)
        return 1
    finally:
        handle.stop()  # apaga la API


if __name__ == "__main__":
    sys.exit(main())
