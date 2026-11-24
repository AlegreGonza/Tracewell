# Documentación de `backend/api`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## app.py

API HTTP de Tracewell.

REGLA: este módulo solo ORQUESTA. Arma la app (reglas, contexto, ciclo de
vida, seguridad, errores, rutas, frontend); las rutas viven en `routes_*`, el
estado y casos de uso en `controllers`, y el análisis en `domain`. Si alguna vez te tienta poner
lógica de análisis acá, va en `domain`.


### Funciones y clases


**`_mount_frontend`**: Sirve el frontend compilado. Va al final: así "/" no tapa a /api. Si todavía no se compiló el frontend (Paso 8), la API funciona igual.


**`create_app`**: Fábrica de la app. Las dependencias externas (carpetas, fuente de captura, listado de interfaces, muestreo de procesos) se inyectan: así los tests no tocan la red real ni los archivos del usuario. `sampler_factory` en None desactiva la columna Proceso.


### Notas del código

- `create_app`: Se resuelve al llamar (no al crear): así `backend.api.app.analyze` sigue siendo parcheable.
- `_shutdown`: el monitoreo de cortes es un hilo de fondo: no debe sobrevivir al cierre


## errors.py


### Funciones y clases


**`_unexpected_handler`**: Red de seguridad: un fallo imprevisto responde JSON genérico (igual que el resto de la API) y el detalle va solo al log del servidor. El mensaje de `exc` NO se devuelve: podría traer rutas del usuario o datos internos.


## security.py


### Funciones y clases


**`make_token_check`**: Dependencia global que exige el token de la API (cabecera `X-Tracewell-Token`, con `secrets.compare_digest` sobre bytes) o, solo en un GET de descarga, un ticket de un solo uso (`TicketStore`, `?ticket=`). El token es obligatorio (vacío o `None` lanzan `ValueError`); `create_app` genera uno al azar si no se le pasa y apaga siempre `/docs`, `/redoc` y `/openapi.json`. Ver `docs/desarrollo.md`.


**`install_local_only`**: Instala los chequeos de Host y de Origin. La API puede leer rutas locales (/api/analyze) y escuchar en localhost, y CUALQUIER página que el usuario abra en su navegador puede intentar pegarle a localhost (CSRF) o resolver su propio dominio a 127.0.0.1 (DNS rebinding). Dos defensas baratas: 1. Host: solo nombres locales (frena el DNS rebinding, que llega con el Host del dominio atacante). 2. Origin: si el navegador manda uno, debe ser local (frena el CSRF). Sin Origin (curl, TestClient, la propia app al navegar) se permite.


## server.py

Arranca la API en un hilo, en un puerto libre de esta misma máquina.

Por qué existe: la ventana de escritorio necesita la API corriendo en segundo
plano y poder pararla al cerrarse, sin bloquear la ventana. Esto es lo único
que sabe "levantar" la API; `main.py` solo lo usa y abre la ventana.

Dos decisiones de seguridad y robustez:
- Escucha SOLO en 127.0.0.1. La API puede leer archivos locales (`/api/analyze`):
  exponerla a la red sería regalar la lectura de archivos de la máquina.
- El puerto lo elige el sistema operativo (puerto 0) y el socket se entrega ya
  abierto a uvicorn: así no hay una "carrera" entre buscar un puerto libre y
  que otro proceso lo tome antes de que lo usemos.


### Funciones y clases


**`start_in_thread`**: Levanta la API en un hilo y devuelve cuando ya responde. `app_kwargs` se pasan a `create_app` (carpetas, fuente de captura...). Los hilos de uvicorn no instalan manejadores de señales: la señal la maneja el programa principal.


### Notas del código

- `start_in_thread`: La app se arma ANTES de abrir el socket: si las reglas están mal, no queda un socket abierto.

## Carpetas permitidas y reglas de usuario (parámetros de `create_app`)

- Carpeta temporal: ya no hay `<temp>/tracewell` fija en la lista (en Linux multiusuario otro usuario podía crearla antes). Nada escribía allí: las capturas en vivo usan `tempfile.mkdtemp` (`tracewell_*`, permisos 0700) y el análisis de su resultado no pasa por la lista. Para abrir otra carpeta, `TRACEWELL_ALLOWED_DIRS`.
- Rutas del frontend (SPA): `SPAStaticFiles` (`app.py`) sirve `index.html` ante cualquier GET/HEAD que no sea archivo existente, no empiece con `/api` y no tenga extensión (`/capturas/alertas` al recargar). Los archivos faltantes (`/assets/x.js`) y `/api/...` inexistentes siguen en `404`; el recorrido de rutas (`..`) lo bloquea `StaticFiles`; las cabeceras de seguridad y la CSP se aplican igual (middleware externo).
- Versión: `VERSION` (`controllers/state.py`) sale de `pyproject.toml` (raíz) y, si no está, de la metadata del paquete instalado.
- `allowed_dirs`: carpetas desde las que `/api/analyze` y `/api/iocs` abren archivos (variable `TRACEWELL_ALLOWED_DIRS`; por defecto solo Descargas; `samples/` y la carpeta de captura en vivo se suman siempre; el diálogo nativo autoriza el archivo elegido con `grants=FileGrants()`; `/api/iocs` exige `.txt`, `.csv`, `.json`, `.stix` o `.ioc`). La ruta se resuelve con `Path.resolve()`; fuera de la lista responde `403` y `/api/analyze` solo admite `.pcap`, `.pcapng`, `.cap` (`400`). Lógica en `backend/domain/files.py`. El selector de archivos de la ventana (`main.py`) abre en la primera carpeta permitida que existe, y el `403` explica cómo agregar otra con `TRACEWELL_ALLOWED_DIRS`.
- `user_rules_dir`: carpeta escribible donde `POST /api/rules` guarda las reglas nuevas (variable `TRACEWELL_USER_RULES_DIR`; ver `backend/domain/rules/README.md`). Errores de escritura: `403` sin permiso, `500` otro fallo de disco.
- `api_token`: opcional; si falta se genera uno aleatorio y queda en `app.state.api_token`.

## Exportar alertas a un SIEM (`GET /api/export/siem`)

Descarga las alertas del análisis actual como texto, una línea por alerta (formatos en
`backend/domain/export/README.md`, sección `siem.py`). Exige el token (cabecera `X-Tracewell-Token`) o un ticket
de descarga de `POST /api/download-ticket` con `{"path": "/api/export/siem"}`, que se pasa como `?ticket=` (un
solo uso, 30 s) para los enlaces `<a download>`.

| Parámetro | Valores | Defecto |
|---|---|---|
| `format` | `ecs` (NDJSON), `cef`, `syslog` (RFC 5424 con CEF) | `ecs` |
| `min_severity` | `low`, `medium`, `high`, `critical`: solo esa severidad o mayor | todas |

Respuestas: `200` con `Content-Disposition: attachment` (`tracewell-alerts.ndjson`, `.cef` o `.log`; el cuerpo
queda vacío si no hay alertas); `409` si no hay captura cargada; `422` si `format` o `min_severity` no son válidos;
`401` sin token. No lleva rutas, nombres de archivo ni secretos (la contraseña de FTP va como `<oculta>`).

```
curl -H "X-Tracewell-Token: $TOKEN" "http://127.0.0.1:PUERTO/api/export/siem?format=cef&min_severity=high"
```
