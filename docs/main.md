# Documentación de `main.py`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## main.py

Punto de entrada de escritorio: un solo comando abre Tracewell en su ventana.

    python main.py                # ventana de escritorio
    python main.py --serve-only   # solo la API y la interfaz, para abrir en un navegador
    python main.py --self-test    # abre la ventana OCULTA, comprueba la interfaz y sale

Este archivo es solo pegamento: levanta la API (backend/api/server.py) en segundo plano,
abre la ventana de pywebview apuntando a ella y, al cerrar la ventana, apaga la
API (lo que detiene una captura en curso y borra lo temporal). La lógica de
análisis vive en `core` y la de la API en `api`.


### Funciones y clases


**`DesktopApi`**: Métodos que la interfaz puede llamar desde JavaScript (`window.pywebview.api`). Solo expone lo que la ventana sabe hacer y la web no: elegir un archivo con el diálogo nativo del sistema.


**`_allow_downloads`**: pywebview CANCELA las descargas por defecto: sin esto "Exportar JSON" e "Informe HTML" no hacían nada dentro de la ventana. Activadas, muestra el diálogo nativo "Guardar como" con el nombre sugerido.


### Notas del código

- `_allow_downloads`: una versión sin esa opción: las descargas quedan como estaban
- `_self_test`: siempre: si la sonda falla, la ventana oculta no puede quedar abierta
- `main`: borde del programa: cualquier fallo de la ventana (p. ej. falta WebView2)
- `main`: apaga la API: detiene una captura en curso y borra lo temporal

