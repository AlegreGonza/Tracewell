# Despliegue de Tracewell

Tracewell se despliega **desde el código fuente** con un instalador de un solo comando. No hay ejecutable empaquetado (decisión en `docs/decisiones.md`; la investigación para hacerlo algún día está en `docs/empaquetado_futuro.md`).

## Qué necesitás

| Requisito | Para qué | ¿Lo instala el script? |
|---|---|---|
| Python 3.11 o superior (probado en 3.12) | Ejecutar la app | Sí, con `winget` (Windows), previa confirmación |
| Node.js | Compilar la interfaz, **solo si falta `frontend\dist`** | Sí, con `winget`, previa confirmación |
| WebView2 | La ventana de escritorio | Sí, con `winget`, previa confirmación |
| Npcap (Windows) / libpcap (Linux) | **Solo la captura en vivo** | **No**: se instala a mano (ver abajo) |
| Conexión a internet | Bajar los paquetes de Python desde PyPI | — |

Windows 10 (1809 o posterior) y Windows 11 traen `winget`. Si no lo tenés, el script te lo dice y tenés que instalar a mano lo que falte.

## Qué descargar: zip "solo para usar" o repositorio completo

| Si querés... | Descargá | Qué trae |
|---|---|---|
| **Solo usar Tracewell** | El `tracewell-<versión>.zip` de la página de Releases (unos 170 KB) | Código de la app, reglas, demo, interfaz ya compilada, documentación y scripts. **Sin tests**, sin código fuente de la interfaz, sin Node.js |
| **Programar o correr los tests** | El repositorio completo | Todo lo anterior, más los tests (`-Dev`) y el código fuente de la interfaz |

Con el zip, descomprimí, entrá a la carpeta `tracewell-<versión>` y seguí con la instalación de abajo. Junto al zip se publica un archivo `.sha256` para verificar que la descarga no se corrompió:

```powershell
(Get-FileHash .\tracewell-0.2.0.zip -Algorithm SHA256).Hash
```

El resultado tiene que coincidir con el contenido del `.sha256` (en minúsculas allá). En Linux/macOS los scripts `.sh` salen del zip sin permiso de ejecución: usá `bash instalar.sh` y `bash iniciar.sh`.

### Armar el zip (para quien publica)

Desde el repositorio completo, con `frontend\dist` ya compilada:

```powershell
powershell -ExecutionPolicy Bypass -File .\crear_zip.ps1
```

Genera `release\tracewell-<versión>.zip` y `release\tracewell-<versión>.zip.sha256` (la versión sale de `pyproject.toml`). No modifica el proyecto: arma todo en una carpeta temporal que borra al terminar. Se omiten `tests`, `__pycache__`, `.venv`, `node_modules` y el generador del demo. Si falta `frontend\dist`, avisa cómo compilarla. En el zip, `instalar.ps1 -Dev` da un error claro porque no hay tests que instalar.

## Instalar en Windows

Desde PowerShell, dentro de la carpeta del proyecto:

```powershell
powershell -ExecutionPolicy Bypass -File .\instalar.ps1
```

`-ExecutionPolicy Bypass` vale **solo para ese comando**: no cambia la configuración de tu equipo.

El script hace, en orden:

1. **Python:** busca 3.12, 3.13 o 3.11 (en ese orden de preferencia) y después cualquier 3.11+. Si no hay, ofrece instalar Python 3.12.
2. **Entorno virtual:** crea `.venv` en la carpeta del proyecto.
3. **Paquetes:** instala `requirements.txt` dentro de `.venv` (nada global).
4. **Interfaz:** si falta `frontend\dist`, la compila (instalando Node.js si hace falta).
5. **WebView2:** lo detecta; si falta, ofrece instalarlo.
6. **Npcap:** lo detecta y, si falta, te explica cómo instalarlo (no lo instala él).
7. **Autoprueba:** abre la ventana **oculta**, comprueba que la interfaz carga y que el modo demo funciona, e informa.

Se puede ejecutar varias veces: lo que ya está listo se omite (la segunda corrida tarda un par de segundos).

### Opciones

| Opción | Efecto |
|---|---|
| `-Check` | Solo informa qué falta. No instala ni descarga nada. |
| `-Yes` | No pregunta: acepta las instalaciones con `winget`. Útil para automatizar. |
| `-Dev` | Instala también `pytest`, `pytest-cov`, `httpx2` (para correr los tests) y `ruff` (linter). |
| `-SkipTest` | Omite la autoprueba final de la ventana. |

## Abrir Tracewell

```powershell
.\iniciar.ps1
```

| Comando | Qué hace |
|---|---|
| `.\iniciar.ps1` | Abre la ventana de escritorio. |
| `.\iniciar.ps1 --serve-only` | Sin ventana: imprime una dirección `http://127.0.0.1:<puerto>` para abrir en el navegador. `Ctrl+C` para salir. |
| `.\iniciar.ps1 --port 8000` | Usa un puerto fijo. |
| `.\iniciar.ps1 --self-test` | Autoprueba con la ventana oculta; imprime un JSON y sale con 0 si todo está bien. |

## Instalar en Linux / macOS

```bash
./instalar.sh
```

```bash
./iniciar.sh --serve-only
```

Opciones: `--check` (solo informa) y `--dev` (también las dependencias de tests). El script **no usa `sudo` ni instala paquetes del sistema**: si falta algo (por ejemplo `python3-venv` en Debian/Ubuntu), te lo indica. En Linux/macOS la ventana de escritorio depende de GTK/WebKit o Qt y **no está probada**; usá `--serve-only` y el navegador. En macOS nada se probó.

## Captura en vivo (opcional)

- **Analizar archivos `.pcap`/`.pcapng` no necesita nada de esto.**
- **Windows:** instalá [Npcap](https://npcap.com) a mano (la licencia de su edición gratuita no permite redistribuirlo ni instalarlo desde otro programa). Después abrí PowerShell **como administrador** antes de ejecutar `.\iniciar.ps1`.
- **Linux:** instalá `libpcap` y ejecutá con `sudo` (o con la capacidad `CAP_NET_RAW`).
- En el panel *Captura en vivo*, elegí tu Wi-Fi o Ethernet. Las interfaces virtuales (Miniport, Hyper-V, Docker, etc.) aparecen al final de la lista.
- **Columna Proceso:** durante la captura en vivo, Tracewell muestra qué programa tiene abierto cada socket (por ejemplo `chrome.exe`). Usa `psutil`, que el instalador deja instalado; si faltara, la columna simplemente no aparece. Es una foto cada segundo, así que una conexión muy corta puede salir como `—` (no identificado). En archivos `.pcap` no existe, porque un archivo no guarda qué programa generó cada paquete.
- Sin permisos, Tracewell muestra un error claro (`permiso denegado: ejecutá Tracewell como administrador (Windows) o root (Linux)`).

## Actualizar

Reemplazá los archivos del proyecto (conservando o no `.venv`) y volvé a ejecutar `.\instalar.ps1`. Si cambió el frontend y no tenés Node, borrá `frontend\dist` solo si querés recompilarlo; si el código nuevo ya trae `dist`, no hace falta.

## Desinstalar

Todo vive dentro de la carpeta del proyecto, salvo lo que haya instalado `winget`:

1. Cerrá Tracewell y borrá la carpeta del proyecto (incluye `.venv`).
2. Opcional: `winget uninstall Python.Python.3.12`, `winget uninstall OpenJS.NodeJS.LTS` y `winget uninstall Microsoft.EdgeWebView2Runtime`, si los instaló el script y ya no los usás.
3. Las capturas temporales de la captura en vivo se borran solas al cerrar; si un cierre abrupto dejó alguna carpeta `tracewell_*` en `%TEMP%`, Tracewell la limpia al iniciar cuando pasa de 24 h.

## Qué descarga el instalador y de dónde

| Qué | Origen | Cuándo |
|---|---|---|
| Paquetes de Python (`dpkt`, `pyyaml`, `fastapi`, `uvicorn`, `scapy`, `pywebview` y sus dependencias) | PyPI | Siempre, la primera vez |
| Python 3.12, Node.js LTS, WebView2 Runtime | `winget` (repositorio de Microsoft) | Solo si faltan y confirmás |
| Dependencias de la interfaz (`npm install`) | registro de npm | Solo si falta `frontend\dist` |

Los paquetes de Python **no están fijados a una versión exacta** (`requirements.txt` sin versiones): se instalan las más nuevas. Si una versión futura rompe algo, fijá la versión conocida en `requirements.txt`. Para ver lo que quedó instalado: `.\.venv\Scripts\python -m pip freeze`.

## Solución de problemas

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| `...instalar.ps1 no está firmado digitalmente` o "la ejecución de scripts está deshabilitada" | Política de ejecución de PowerShell | Usá el comando con `-ExecutionPolicy Bypass` (arriba). |
| "No se encontró Python 3.11+" y `winget` no existe | Equipo sin `winget` | Instalá Python desde python.org marcando *Add to PATH* y reabrí PowerShell. |
| Python recién instalado "no se ve" | La terminal conserva el `PATH` viejo | Cerrá y abrí PowerShell y volvé a ejecutar el instalador. |
| La autoprueba falla o la ventana no abre | Falta WebView2 u otro problema del motor web | Usá `.\iniciar.ps1 --serve-only` y abrí la dirección en el navegador. |
| Error al instalar paquetes (por ejemplo `pythonnet`) | Python demasiado nuevo para alguna dependencia | Instalá Python 3.12 (el instalador lo prefiere) y borrá `.venv` antes de reintentar. |
| `permiso denegado` al iniciar la captura | Sin administrador/root | Abrí PowerShell como administrador (Windows) o usá `sudo` (Linux). |
| La captura en vivo no ve tu red | Interfaz equivocada | Elegí tu Wi-Fi o Ethernet en la lista. |
| "puerto ocupado" | Otro programa usa el puerto fijo | Quitá `--port` (el sistema elige uno libre). |
| La página abre en blanco en el navegador | Falta `frontend\dist` | Ejecutá de nuevo `.\instalar.ps1` (o `-Check` para ver qué falta). |

## Seguridad al desplegar

- La API solo escucha en `127.0.0.1`. **No la expongas a tu red.**
- Las capturas pueden contener contraseñas de protocolos sin cifrar y datos privados; no las compartas.
- El instalador no cambia la política de ejecución ni ajustes del sistema, y pide confirmación antes de cada descarga con `winget` (salvo con `-Yes`).
