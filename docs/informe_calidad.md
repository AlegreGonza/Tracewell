# Informe de calidad y rendimiento - Tracewell

Fecha: 2026-11-17. Todo corrió local (herramientas en un venv/carpeta fuera del proyecto; no se subió código a ningún servicio). No se modificó código ni tests. "Medido" = ejecutado; "Inferido" = deducido de leer el código.

> **Actualización (2026-11-23).** Este informe es del 2026-11-17 y sus cifras (593 tests, cobertura, mypy, pylint) no se repitieron. Desde entonces se agregaron al proyecto: `ruff` (solo reglas `F`, en `pyproject.toml`), ESLint 10 con configuración flat mínima (`frontend/eslint.config.js`, sin `jsx-a11y` ni `prop-types`), cabeceras de seguridad en la API y el rechazo de rutas que no son archivos regulares (dispositivos de Windows como `con`); `/api/analyze` sigue leyendo cualquier archivo local, por eso la API solo escucha en `127.0.0.1` (ver `docs/desarrollo.md`). Estado actual de las suites: 4059 tests de backend y 1309 de frontend pasan. `mypy`, `pip-audit`, `vulture` y el resto de las herramientas recomendadas abajo siguen sin agregarse al proyecto.

## Resumen ejecutivo
- Calidad estática muy buena: 593 tests pasan, cobertura 99% de líneas y ~99% de ramas (producción), 0 vulnerabilidades en dependencias Python y 0 en las de runtime del frontend, bandit sin hallazgos reales, pylint 9.67/10, MI "A" en todos los módulos.
- Memoria: la hipótesis de diseño se confirma. 20x más paquetes (100k a 2M, sesiones casi fijas) movió la memoria pico de +0,4 MB a +1,2 MB en `group_packets`. La memoria crece con las SESIONES (~640 B/sesión; 361k sesiones = +231 MB).
- Rendimiento: `analyze` hace ~29k paquetes/s (500k paquetes = 17,8 s; un pcap de 1 GB tardaría de ~1 a 3 min según el tamaño medio de paquete). El 60% del tiempo es decodificación dpkt, hecha dos veces (grouper y engine).
- Cuello de botella de UX: cada página de `session_packets` relee TODO el pcap (6,1 s en 500k paquetes) y `get_packet` es O(índice) (1,2 s al final).
- Riesgos principales: memoria sin tope con muchas sesiones/pares, `/api/analyze` acepta cualquier ruta local, `LiveCapture.stop()` sin timeout, y `live.pcap` reutilizado mientras un análisis lo apunta.

## Herramientas ejecutadas
| Herramienta | Versión | Qué mide | Resultado |
|---|---|---|---|
| ruff (E,F,W,C90,B,S,SIM,PERF,UP,RET,PL) | 0.17.5 | lint, complejidad, seguridad | Prod: 128 avisos, 94 son UP (typing moderno). Reales: 3 C901, 2 B904, 1 F401, SIM102/105/115, S110 |
| mypy (--check-untyped-defs) | 2.4.1 | tipos | 12 errores en 4 archivos (Optional sin comprobar en live.py, engine.py, analyzer.py, app.py) |
| pylint | 4.1.4 | lint general | 9.67/10; solo R09xx (tamaño de `create_app`, `_parse_rule`, `filter_sessions`) |
| vulture | 2.16 | código muerto | Solo falsos positivos (rutas FastAPI) + `write_json`, `count_packets`, `non_ethernet_dropped` sin uso en producción; import sin uso en test_live.py:2 |
| radon cc / mi | 6.0.1 | complejidad / mantenibilidad | CC media A (3,5). Peores: `_parse_rule` D(22), `filter_sessions` C(19), `build_report` C(12), `DnsSuspiciousDetector.feed` C(12). MI: engine.py 34 (el más bajo, aún A) |
| bandit | 1.9.4 | seguridad | 3 LOW: B110 live.py:136, B101 live.py:213, B105 engine.py:242 (falso positivo, es el texto "<oculta>") |
| pip-audit | última | CVEs de dependencias | 0 vulnerabilidades |
| pytest-cov (--cov-branch) | del proyecto | cobertura | 593 passed. TOTAL 99%. Prod sin cubrir: live.py:84-88 (listado real de Scapy), ramas 257->260 y 275->exit |
| ESLint 9 + react + react-hooks 7 + jsx-a11y | 9.39.5 / 7.37.5 / 7.1.1 / 6.10.2 | lint frontend | 3 errores `set-state-in-effect`; 49 `react/prop-types` (ruido: el proyecto no usa PropTypes); jsx-a11y: 0 |
| npm audit | npm | CVEs frontend | 6 high, TODAS dev (picomatch ReDoS via vite/vitest/tinyglobby); `--omit=dev`: 0 |
| semgrep / pyright / SonarQube | - | - | No ejecutados (opcional / requiere servidor) |

## Hallazgos priorizados
**Alta**
1. Memoria sin tope en tablas de estado. `grouper.py:133` (`sessions` dict, ~640 B/sesión medido: 361k sesiones = +231 MB, y un escaneo/DDoS con millones de flujos escala a GB). Igual en `engine.py:183` (`_hist`), `:222` (`_users`), `:185/:223/:271` (`_alerted`). Arreglo: `max_sessions` configurable con aviso "análisis parcial", purga de `_users`/`_hist` por antigüedad.
2. `session_packets` relee y decodifica TODO el pcap por página: `analyzer.py:76-86` (medido 6,1 s en 500k paquetes, igual para la primera sesión). `get_packet` es O(n): `reader.py:170-176` (1,2 s al final de 500k). Arreglo: índice disperso de offsets + caché de índices por sesión (ver optimizaciones).
3. `/api/analyze` abre cualquier ruta local legible: `app.py:124-129` (`expanduser`, sin lista de carpetas permitidas). Aceptable en app de escritorio solo si el servidor escucha en 127.0.0.1; `main.py` está vacío, así que el bind no está definido ni verificable. Además 404 vs 422 permite saber si un archivo existe. Arreglo: fijar `host="127.0.0.1"`, validar cabecera `Host`/`Origin` (DNS rebinding), opcional lista de raíces permitidas y tope de tamaño.

**Media**
4. `LiveCapture.stop()` espera sin timeout: `live.py:212` (`self._finished.wait()`). Si `source.stop()` de Scapy se cuelga, el request y el hilo se bloquean para siempre. Arreglo: `wait(timeout)` y estado "error".
5. Archivo vivo reutilizado: con `live_dir`, `app.py:226` reescribe `live.pcap` (modo `wb`, `live.py:195`) mientras `state.analysis.path` aún apunta a él; `session_packets`/`get_packet` leerían datos distintos del análisis (inferido, no reproducido). Con `live_dir=None` se crea un `mkdtemp` por captura que nunca se borra (`live.py:175`, hasta 200 MB c/u). Arreglo: nombre único por captura y limpieza al reemplazar.
6. `/api/live/stop` reanaliza en cada llamada y pisa el análisis actual: `app.py:245`. Arreglo: cachear el resultado del primer stop.
7. Análisis síncrono sin progreso: `app.py:122-136` bloquea la petición (minutos en 1 GB). Arreglo: tarea en segundo plano + `/api/analyze/status`.
8. Tipos: 12 errores mypy; los más relevantes `live.py:124,236,268` (None no comprobado) y `analyzer.py:38` (clave `None` posible).
9. Frontend: `setState` síncrono en efecto en `SessionDetail.jsx:11,67` y `SessionsTable.jsx:22` (render extra en cascada). Arreglo: derivar estado o resetear con `key`.

**Baja**
10. `create_app` C901=32 (`app.py:60`): mover rutas a `APIRouter`. `_parse_rule` (`engine.py:314`), `filter_sessions` (`query.py:21`): extraer validadores.
11. `raise ... from` faltante: `app.py:187,196` (B904). `live.py:136` traga excepción sin log; `live.py:213` usa `assert` (se elimina con `-O`).
12. `reader.py:85-107` (`_TapFile`) depende del patrón de lecturas internas de dpkt; `pyproject.toml` no fija versiones (dpkt sin tope). Fijar `dpkt>=1.9.8,<2`.
13. `live.py:188,237`: el motivo "error" no expone el mensaje de `self.error` en `/api/live/status`.
14. Fuzz de 40x3000 paquetes mutados/truncados en `group_packets` y `evaluate`: 0 excepciones (medido). Robustez correcta.
15. Bundle: 238 KB JS (73,6 KB gzip) + 6,8 KB CSS, un solo chunk, casi todo React. Sin oportunidades obvias; no hace falta code-splitting.

## Rendimiento (medido, Windows, Python 3.12, un núcleo; pico = `peak_wset` extra sobre línea base de ~26 MB)
Pcap A: sesiones crecen con paquetes (~15% de paquetes = sesión nueva). Pcap F: ~900-2000 sesiones fijas.
| Etapa | Pcap | Paquetes | Tiempo | Pico extra | Paquetes/s |
|---|---|---|---|---|---|
| iter_packets | A 500k | 500k | 1,08 s | 0 MB | 465k |
| group_packets | A 100k | 100k | 1,37 s | 10 MB | 73k |
| group_packets | A 500k (74k sesiones) | 500k | 8,3 s | 49 MB | 60k |
| group_packets | A 500k (361k sesiones) | 500k | 9,0 s | 231 MB | 56k |
| group_packets | F 100k / 500k / 2M | 2M | 1,4 / 6,8 / 25,6 s | 0,4 / 0,6 / 1,2 MB | 70-78k |
| evaluate | A 500k | 500k | 9,1 s | 18 MB | 55k |
| analyze | A 10k / 100k / 500k | 500k | 0,31 / 4,4 / 17,8 s | 1,3 / 13 / 65 MB | 29-32k |
| analyze | F 2M (394 MB) | 2M | 66 s | 7,6 MB | 30k (6 MB/s) |
| session_packets (1ª pág.) | A 500k | 500k | 6,1 s | 0 | 81k |
| get_packet (índice 0 / último) | A 500k | - | 0,00 / 1,17 s | 0 | - |
**Constancia de memoria:** con sesiones casi fijas, 100k a 2M paquetes (20x) deja el pico en 28 a 34 MB totales; con sesiones crecientes la memoria crece con las sesiones, no con el tamaño del archivo. La hipótesis se cumple.
**Extrapolación a 1 GB** (inferido de 6 MB/s y 30k pkt/s): paquetes chicos (~200 B, mi sintético) ~170-180 s; mezcla realista (~700 B) ~1,5M paquetes, ~50-60 s. Memoria depende solo de las sesiones.

## Hotspots (cProfile, 100k paquetes; el overhead del perfilador infla ~2x)
- `group_packets` 3,4 s: 65% en dpkt (`Ethernet.__init__` 1,89 s acumulado, `dpkt.unpack` 0,9 s, `setattr` 0,24 s) llamado desde `grouper.py:59 _endpoints` (2,2 s acumulado). Bucle propio `grouper.py:124` 0,22 s; lectura `reader.py:88 _TapFile.read` 0,26 s.
- `evaluate` 4,6 s: `engine.py:116 _decode` 2,7 s acumulado (misma decodificación Ethernet/IP/TCP/UDP otra vez), de ahí dpkt 2,5 s; el resto es `feed` de detectores y el DNS.
- `analyze` = ambos hotspots en serie + dos lecturas del archivo: la misma decodificación se paga 2 veces.

## Optimizaciones propuestas (no implementadas) e impacto
1. Una sola pasada y decodificación compartida: un `iter_packets` que alimente grouper y engine con un `Decoded` común. Inferido: `analyze` de ~17,8 s a ~10-11 s (-40%).
2. Decodificador ligero con `struct`/slicing para IPv4 TCP/UDP, con fallback a dpkt para IPv6, fragmentos y casos raros. Prototipo medido: lectura + endpoints + agrupación de 500k paquetes en 1,9 s contra 8,3 s actuales (4x) en la etapa de sesiones; en total `analyze` quedaría en ~4-6 s.
3. Índice disperso de offsets (un checkpoint cada ~4096 paquetes, 8 B c/u: ~1 MB cada 4M paquetes) para `get_packet`: de O(n) a ms. Para `session_packets`: construir la lista de índices de la sesión en el primer pedido y cachearla (LRU de pocas sesiones): páginas 2+ pasan de 6 s a ms.
4. `Session` con `slots=True`: medido solo -9% (493 a 451 B/objeto), no vale como mejora principal. Mejor: internar IPs y guardar la clave como tupla de enteros (inferido ~25-30% menos memoria por sesión) y tope `max_sessions`.
5. Análisis en hilo de fondo con progreso (bytes leídos / tamaño) para que la UI no quede colgada en pcaps grandes.

## Dev-dependencies recomendadas
```
pip install -e ".[dev]"   # tras agregar a pyproject.toml: ruff, mypy, types-PyYAML, pip-audit, vulture
```
```toml
[tool.ruff]
line-length = 110
[tool.ruff.lint]
select = ["E","F","W","B","S","SIM","PERF","C90","UP","RET"]
per-file-ignores = {"**/tests/**" = ["S101","S105","S311"]}
[tool.ruff.lint.mccabe]
max-complexity = 15
[tool.mypy]
check_untyped_defs = true
ignore_missing_imports = true
exclude = ["tests"]
```
- ruff (reemplaza flake8/isort/bandit básico, corre en ms), mypy (los 12 errores son bugs latentes de None), pip-audit (dependencias nuevas), vulture solo ocasional (mucho ruido con FastAPI). bandit queda cubierto por las reglas S de ruff. pylint no suma sobre ruff+mypy.
- Frontend: `npm i -D eslint@9 @eslint/js eslint-plugin-react eslint-plugin-react-hooks eslint-plugin-jsx-a11y globals` (ESLint 10 aún choca con jsx-a11y). Configuración flat con `react/prop-types: off` (o migrar a TypeScript). Aviso: `npm audit fix --force` propone bajar vite a 6.2.7: no hacerlo; esperar parche de picomatch o usar `overrides`. Es solo dev-time.

## Nota sobre SonarQube
SonarQube Community necesita un servidor (Docker + base de datos) y se ejecuta con `sonar-scanner`; no se levantó. Aportaría un tablero histórico, deuda técnica y "quality gate" en CI, pero casi todo lo que detectaría ya lo cubren ruff + mypy + bandit + radon + coverage sin infraestructura. Para un proyecto de este tamaño (~1.300 líneas de producción, un desarrollador) no conviene; solo valdría si hay CI de equipo y se quiere tendencia en el tiempo.
