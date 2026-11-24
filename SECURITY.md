# Política de seguridad

## Cómo reportar una vulnerabilidad

Usá **GitHub Security Advisories** del repositorio (pestaña *Security > Report a vulnerability*,
https://github.com/AlegreGonza/Tracewell/security/advisories/new). Es privado: no abras un issue público con
detalles de explotación ni adjuntes pcaps con datos reales.

Incluí versión (`pyproject.toml`), sistema operativo, pasos para reproducir y, si podés, un pcap **sintético** que
lo dispare. Es un proyecto personal sin equipo de guardia: no hay plazos garantizados, pero se intenta
confirmar el reporte y corregirlo por orden de gravedad. Se agradece la divulgación coordinada: avisá antes de
publicar.

Versión con soporte: la última publicada (proyecto en versión 0.x; no hay ramas mantenidas en paralelo).

## Qué es Tracewell, a los efectos de seguridad

Una aplicación **de escritorio para un solo usuario**: un servidor FastAPI en el propio equipo y una interfaz
web (ventana pywebview o navegador). No es un servicio de red ni está pensado para exponerse.

## Modelo de amenazas

### Qué protege

| Amenaza | Defensa |
|---|---|
| Otra máquina de la red llega a la API | Escucha solo en `127.0.0.1`. |
| Una página web abierta en tu navegador llama a la API (CSRF, DNS rebinding) | Se aceptan solo `Host` locales (`127.0.0.1`, `localhost`, `[::1]`) y se rechaza todo `Origin` no local (403). Los sondeos que envían tráfico son `POST` para que un `GET` cruzado no los dispare. |
| Otro programa o usuario del mismo equipo llama a la API (importa si corre con privilegios) | **Token aleatorio por arranque** en cada ruta `/api` (cabecera `X-Tracewell-Token`, comparación en tiempo constante; nunca en la URL). No hay modo sin autenticación. Las descargas usan tickets de un solo uso y 30 s. |
| Inyección de script desde una captura | El contenido del tráfico se muestra como texto, nunca como HTML. CSP estricta (`default-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`. `/docs` y `/openapi.json` están apagados. |
| Leer archivos arbitrarios con la API | `/api/analyze` e `/api/iocs` solo abren archivos regulares dentro de una **lista de carpetas permitidas** (`TRACEWELL_ALLOWED_DIRS`; por defecto Descargas, Documentos y Escritorio) y rechazan dispositivos y rutas que no son archivos. Los mensajes de error no repiten el contenido del archivo. |
| Agotar memoria o disco con una captura o un ataque | Topes de sesiones seguidas, estado acotado en los detectores, tamaños máximos de lectura y límites en la captura en vivo (paquetes, tiempo, tamaño). Costo asumido: con muy pocos recursos un detector puede "olvidar" a los pares menos recientes. |
| Secretos en informes | No se guardan contraseñas FTP; los informes llevan el nombre del archivo, no las carpetas. |
| Dependencias alteradas | `requirements.lock` y `requirements-dev.lock` fijan versiones exactas **con hashes sha256** (`pip install --require-hashes`); el CI corre `pip-audit` y `bandit` y publica un **SBOM CycloneDX**. |

### Qué NO protege (limitaciones honestas)

- **Un atacante con ejecución de código en tu cuenta o con privilegios administrativos** puede leer el token del
  proceso o la memoria, o leer directamente los archivos: la defensa es contra páginas web y otros procesos
  sin esos privilegios, no contra un equipo ya comprometido.
- **El token y la API viajan por HTTP sin cifrar en el bucle local.** Cualquier proceso con permiso para
  inspeccionar el tráfico local o la lista de procesos del mismo usuario podría verlos.
- **Las capturas son entrada hostil.** El análisis es lectura de datos con `dpkt` y `scapy`, bibliotecas que
  parsean formatos complejos: un pcap malicioso podría explotar un defecto de esas bibliotecas o de Tracewell
  (caídas, consumo excesivo). Los límites mitigan el agotamiento de recursos, no garantizan ausencia de fallos.
  Analizá capturas sospechosas en una máquina aislada.
- **Los archivos extraídos de una captura pueden ser malware.** Por defecto solo se ven su SHA-256 y tipo;
  descargarlos guarda un `.bin` tras una confirmación. No los abras.
- **La captura en vivo requiere privilegios** (administrador/root, Npcap o libpcap). Mientras corre, Tracewell
  y sus dependencias (Scapy) trabajan con esos privilegios: úsala solo en redes que estés autorizado a
  monitorear y evitá correr el resto de la interfaz como administrador cuando no haga falta.
- **La lista de carpetas permitidas es una barrera de configuración, no un sandbox.** Si la ampliás con una
  carpeta sensible, la API podrá leerla.
- **No hay firma criptográfica de los lanzamientos** (ver abajo): el SHA-256 detecta corrupción y cambios si lo
  obtenés por un canal distinto del archivo, pero no prueba quién lo publicó.
- **Las reglas de detección son orientativas.** Que no haya alertas no significa que no haya actividad
  maliciosa, y no se midieron aún contra tráfico real (`docs/validacion_real.md`).
- **No hay auditoría de seguridad externa.** Las pruebas son las del repositorio (incluidas pruebas hostiles
  propias).
- **macOS no se probó.**

## Verificar un lanzamiento (SHA-256)

Cada zip de la página de Releases va acompañado de un `<zip>.sha256` (lo genera `crear_zip.ps1`). Comparalo con
el hash calculado localmente:

```powershell
(Get-FileHash .\tracewell-<versión>.zip -Algorithm SHA256).Hash.ToLower()
Get-Content .\tracewell-<versión>.zip.sha256
```

```bash
sha256sum -c tracewell-<versión>.zip.sha256     # mismo directorio; el nombre del zip debe coincidir
```

Si no coinciden, no instales. Para más confianza, mirá el hash en la página del release (otro canal que el
archivo descargado).

## SBOM y dependencias

El workflow `.github/workflows/ci.yml` genera `sbom.cdx.json` (CycloneDX 1.6) a partir de `requirements.lock` y lo
publica como artefacto de cada corrida (`sbom-cyclonedx`). Localmente:

```
python -m cyclonedx_py requirements requirements.lock --pyproject pyproject.toml --sv 1.6 --of JSON -o sbom.cdx.json
python -m pip_audit --require-hashes -r requirements.lock
```

El SBOM cubre las dependencias de **ejecución de Python**; no incluye las del frontend (ya compiladas dentro de
`frontend/dist`) ni las bibliotecas del sistema.

Más detalle técnico: `docs/en/security.md` (inglés) y `docs/desarrollo.md` (cabeceras, token y lock).
