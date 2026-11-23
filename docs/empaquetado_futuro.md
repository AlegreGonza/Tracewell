# Empaquetado con PyInstaller: plan investigado (NO implementado)

**Decisión:** Tracewell se despliega desde el código fuente con `instalar.ps1` / `instalar.sh` (ver `docs/despliegue.md`). Este documento guarda la investigación (hecha sobre documentación oficial, sin construir nada) por si algún día se decide generar un ejecutable. Lo marcado **SIN CONFIRMAR** no se pudo verificar en documentación oficial y hay que comprobarlo al compilar.

## Resumen de recomendaciones
- **Formato:** carpeta (`onedir`), no un solo archivo. Arranca más rápido, no extrae a `_MEI…` en cada inicio y es más fácil de depurar. La doc de PyInstaller desaconseja correr el modo de un solo archivo como administrador en Windows, y la captura en vivo lo necesita. (https://pyinstaller.org/en/stable/operating-mode.html)
- **Archivo `.spec`** en vez de línea de comandos, para evitar ambigüedades con el separador de `--add-data` y versionar exclusiones e imports ocultos. (https://pyinstaller.org/en/stable/spec-files.html)
- **Primero con consola visible** (`console=True`), se prueba con `--self-test` y `--serve-only`, y recién después se pasa a modo ventana.

## Cambios de código necesarios antes de compilar
1. **`backend/api/app.py` línea 29:** `ROOT = Path(__file__).resolve().parent.parent` se rompe congelado: `rules/`, `samples/` y `frontend/dist` no se encontrarían (la app abriría sin reglas ni interfaz, en silencio). Hay que usar `sys._MEIPASS` cuando `sys.frozen` esté activo. (https://pyinstaller.org/en/stable/runtime-information.html)
2. **`main.py`:** con `--windowed`, `sys.stdout` y `sys.stderr` valen `None`; proteger al inicio de `main()` (por ejemplo, redirigir a `os.devnull` o a un log). El logging por defecto de uvicorn podría fallar (SIN CONFIRMAR en documentación oficial de uvicorn). (https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html)
3. **Opcional:** `webview.start(gui="edgechromium")` para que la falta de WebView2 sea un error claro en vez de caer en el motor antiguo (MSHTML); que `--self-test` escriba el JSON también a un archivo (en modo ventana no hay consola); avisar si falta `frontend/dist` cuando está congelado.

## Datos y módulos a incluir
- Datos: `rules/*.yaml`, `samples/demo.pcap` (no `generate_demo.py`) y `frontend/dist`.
- Imports ocultos: `collect_submodules("uvicorn")`, `scapy.all`, `scapy.arch.windows`; plan B `collect_all` de `webview`, `clr_loader` y `pythonnet` (SIN CONFIRMAR que los hooks los recojan solos).
- `excludes`: `tkinter`, `PyQt5/6`, `PySide2/6`, `gi`, `matplotlib` (PyInstaller empaqueta todo lo que encuentra instalado). (https://pywebview.flowrl.com/guide/freezing.html)

Esqueleto de `tracewell.spec` (a probar; rutas relativas a la raíz del proyecto):

```python
from PyInstaller.utils.hooks import collect_submodules, collect_all
datas = [("rules/*.yaml", "rules"), ("samples/demo.pcap", "samples"), ("frontend/dist", "frontend/dist")]
binaries = []
hidden = collect_submodules("uvicorn") + ["scapy.all", "scapy.arch.windows"]
for pkg in ("webview", "clr_loader", "pythonnet"):  # solo si hace falta
    d, b, h = collect_all(pkg); datas += d; binaries += b; hidden += h
a = Analysis(["main.py"], pathex=["."], datas=datas, binaries=binaries, hiddenimports=hidden,
             excludes=["tkinter", "PyQt5", "PyQt6", "PySide2", "PySide6", "gi", "matplotlib"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Tracewell", console=True)
coll = COLLECT(exe, a.binaries, a.datas, name="Tracewell")
```

## Requisitos en el equipo del usuario
- **Npcap (captura en vivo):** no se puede redistribuir sin licencia comercial (OEM); el usuario lo instala desde https://npcap.com. Analizar archivos no lo necesita. (https://npcap.com/oem/redist)
- **WebView2:** viene con Windows 11 y casi todos los Windows 10; si falta, instalar el bootstrapper de Microsoft. (https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)
- **Administrador:** no usar `--uac-admin` por defecto (toda la app correría elevada); mejor "Ejecutar como administrador" solo para capturar.

## Cómo verificar una compilación
1. `Tracewell.exe --self-test` y `--serve-only` (con consola visible).
2. Comprobar que cargaron las 3 reglas y que el modo demo responde.
3. Probar en un equipo/usuario limpio (sin Python, sin Npcap, idealmente sin WebView2).
4. Recién entonces `console=False` y repetir.
5. Antivirus: Defender local. Subir a VirusTotal es una subida externa del binario: decisión del dueño. Falsos positivos del modo de un solo archivo: SIN CONFIRMAR en la doc oficial.

## Licencia (orientación, no asesoría legal)
Scapy es GPL-2.0 (confirmar en su repositorio). Un ejecutable que lo incluye se distribuye bajo los términos de la GPL aunque el código propio sea MIT: habría que incluir los textos de licencia y ofrecer el código fuente. Distribuir solo el código fuente (como hoy) evita esa obligación. PyInstaller tiene una excepción que permite empaquetar aplicaciones con cualquier licencia.

## Limitaciones
PyInstaller no compila de forma cruzada: cada sistema operativo necesita su propia máquina de compilación. El tamaño esperado es de 100 a 200 MB en `onedir` (estimación, SIN CONFIRMAR).
