# Desarrollo: linter, finales de línea y cabeceras de seguridad

## Linter (ruff)

Solo se activan las reglas de pyflakes (`F`: imports sin usar, nombres sin definir...). No reformatea nada.
La configuración está en `pyproject.toml` (`[tool.ruff]`) y `ruff` viene en `requirements-dev.txt`.

```
python -m ruff check backend main.py
```

La integración continua (`.github/workflows/ci.yml`) lo corre en cada push y pull request junto con el resto de
los controles; en local, `.erificar.ps1` / `./verificar.sh` los encadenan (ver `docs/pruebas.md`).

## Finales de línea

`.gitattributes` define `* text=auto`: Git decide qué es texto, guarda LF en el repositorio y deja que
`core.autocrlf` (Windows: `true`) ponga CRLF al descargar. Los `.sh` son siempre LF (`eol=lf`) y los
binarios (`.pcap`, `.pcapng`, imágenes) no se tocan.

Estado heredado: hoy el índice mezcla archivos con CRLF (la mayoría) y con LF. Eso NO se corrige en masa. Al
editar un archivo se conserva el final de línea que ya tiene. Si algún día se quiere unificar, el
comando es `git add --renormalize .` en una confirmación aparte (convertiría a LF los archivos que
hoy están con CRLF en el índice; mide antes con un índice temporal, sin tocar el real).

## Cabeceras de seguridad

`backend/api/security.py` agrega a TODA respuesta (API, estáticos y rechazos 400/403/500) una CSP
(`default-src 'self'`, scripts solo propios, `style-src 'unsafe-inline'` porque Mantine pone estilos en línea,
`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y
`Referrer-Policy: no-referrer`. Si la interfaz necesita cargar algo de otro origen, se agrega ahí y se
prueba en un navegador real (los tests no ven los errores de CSP).

El Host admitido incluye `[::1]` (con o sin puerto); cualquier otro (`evil.com`) sigue dando 400.

## Token de la API

Host y Origin frenan páginas web, pero no a otro programa del equipo: cualquiera puede llamar a
`127.0.0.1:<puerto>`. Por eso `main.py` genera un token aleatorio (`secrets.token_urlsafe(32)`) en cada
arranque y `create_app(api_token=...)` lo exige en TODA ruta `/api` (`security.make_token_check`, dependencia
global de FastAPI). Los estáticos (`/`) cargan sin token.

- Cabecera `X-Tracewell-Token`; el token NUNCA va en la URL. Los enlaces de descarga (`<a download>`, no
  pueden llevar cabeceras) usan un ticket: `POST /api/download-ticket` (con el token) devuelve un código de
  un solo uso, 30 s y atado a esa ruta (`TicketStore`, solo rutas de descarga); la descarga es
  `GET <ruta>?ticket=...`. El frontend lo hace en `frontend/src/features/exportar/downloads.ts` (sin token, p. ej. en
  desarrollo, es un enlace normal). Así se conserva la descarga nativa y no se carga el archivo en memoria.
- Ventana de escritorio: la interfaz lo pide con `window.pywebview.api.get_token()` (tras `pywebviewready`).
- `--serve-only`: imprime `http://127.0.0.1:<puerto>/#token=...`. El fragmento no viaja al servidor; la
  interfaz lo guarda en `sessionStorage` y lo borra de la barra.
- **No existe modo sin autenticación:** `create_app()` sin `api_token` genera uno al azar
  (`secrets.token_urlsafe(32)`, queda en `app.state.api_token`) y lo exige igual. `/docs`, `/redoc` y
  `/openapi.json` siempre están apagados: publicarían el mapa completo de la API. Los tests de la API
  reciben el token solo (`backend/api/tests/conftest.py` lo agrega a cada `TestClient`).
- Servidor de desarrollo de Vite (`npm run dev`, proxy a `:8000`): arrancá la API con una variable fija,
  `TRACEWELL_API_TOKEN=token-de-desarrollo-123 python main.py --serve-only --port 8000` (mínimo 16
  caracteres; si es más corto, `main.py` no arranca) y abrí `http://localhost:5173/#token=token-de-desarrollo-123`.

Los sondeos que mandan tráfico a la red (`/api/support/ping`, `/traceroute`, `/ports`, `/latency`, `/rdp`,
`/time`, `/devices`, `/duplicate-ip`, `/internet`) son `POST`: un GET de otra página no lleva `Origin` y el
chequeo de Origin no lo vería. `test_support_api.py` comprueba que con GET no se ejecutan.

## Dependencias fijadas (lock con hashes)

- `pyproject.toml` y `requirements*.txt` llevan cotas compatibles (`>=mínima probada,<siguiente mayor`).
- `requirements.lock` y `requirements-dev.lock` fijan versiones exactas **con hashes sha256** y son
  universales (marcadores de plataforma: `pythonnet` solo Windows, `pyobjc-*` solo macOS, etc.).
- Instalar desde el lock (lo hacen `instalar.ps1` / `instalar.sh`, que caen a `requirements.txt` si falta):

```
pip install --require-hashes -r requirements.lock          # uso
pip install --require-hashes -r requirements-dev.lock      # tests y linter
```

- Regenerar (hace falta [uv](https://docs.astral.sh/uv/); conserva las versiones actuales como
  restricción, así que solo cambia lo que las cotas obligan; para actualizar de verdad, quitá `-c`):

```
uv pip compile requirements.txt     --universal --generate-hashes --no-annotate --python-version 3.11 -c requirements.lock     -o requirements.lock
uv pip compile requirements-dev.txt --universal --generate-hashes --no-annotate --python-version 3.11 -c requirements-dev.lock -o requirements-dev.lock
```

  Con `-c` apuntando al mismo archivo de salida, copiá antes el lock viejo a otra ruta. Después de regenerar,
  verificá en un venv temporal que `pip install --require-hashes -r requirements.lock` funciona y corré los tests.
  Los `.lock` se dejan fuera del commit hasta que el usuario decida subirlos.

## Carpetas permitidas para abrir archivos

`/api/analyze` y `/api/iocs` reciben una ruta que escribe el usuario. La ruta se resuelve con
`Path.resolve()` (frena `..` y enlaces simbólicos) y debe quedar dentro de una carpeta permitida; si no, `403`
con mensaje en español, aunque el archivo no exista (no se revela qué hay fuera). Por defecto (mínimo
privilegio): Descargas del usuario (también la de OneDrive), la carpeta `samples/` del proyecto y la
carpeta de captura en vivo; además, cualquier archivo que el usuario elija en el diálogo nativo
(`DesktopApi.pick_file` lo autoriza con `FileGrants`: solo ese archivo, no su carpeta). `/api/analyze` admite solo `.pcap`, `.pcapng` y `.cap`
(`400` si no). Se configura con `create_app(allowed_dirs=[...])` o con la variable `TRACEWELL_ALLOWED_DIRS`
(carpetas separadas por `;` en Windows o `:` en el resto): reemplaza la lista por defecto, y `samples/` y la
carpeta de captura en vivo se suman siempre. El parámetro manda sobre la variable.

## Reglas del usuario

Las reglas nuevas del panel se guardan en una carpeta de usuario escribible (Windows:
`%APPDATA%\Tracewell\rules`; otros: `$XDG_CONFIG_HOME/tracewell/rules` o `~/.config/tracewell/rules`), no en
`rules/`, que puede estar en una ubicación sin permiso de escritura (Program Files). Se cambia con
`create_app(user_rules_dir=...)` o `TRACEWELL_USER_RULES_DIR`. Detalle del criterio en
`backend/domain/rules/README.md`.

## Verificación, CI, releases firmados y SBOM

- **Un solo comando:** `.\verificar.ps1` / `./verificar.sh` encadenan ruff, bandit (`[tool.bandit]` en `pyproject.toml`), pip-audit,
  pytest y el frontend; `-Linux` repite el backend en Docker. Detalle y cómo leer los fallos: `docs/pruebas.md`.
- **CI:** `.github/workflows/ci.yml` (Linux y Windows, Python 3.11 y 3.13, frontend con pnpm y SBOM). Cada action
  va fijada por SHA de commit completo (la versión queda en el comentario); para actualizar una, resolver el SHA
  nuevo con `git ls-remote --tags https://github.com/<org>/<repo>` y cambiar SHA y comentario juntos.
  `bandit`, `pip-audit` y `cyclonedx-bom` son dependencias de desarrollo (`requirements-dev.txt`, con hashes en el lock).
- **SHA-256 de los releases:** `crear_zip.ps1` genera `tracewell-<versión>.zip` y `tracewell-<versión>.zip.sha256`.
  Quien publica sube ambos a la página de Releases y pega el hash también en la descripción (segundo canal).
  Verificación: ver `SECURITY.md`. **El zip no está firmado criptográficamente** (no hay clave de firma ni
  atestación de procedencia): el hash prueba integridad, no autoría. Firmar (por ejemplo con `gh attestation`
  o Sigstore) queda como mejora pendiente.
- **SBOM:** el CI publica `sbom-cyclonedx` (CycloneDX 1.6, de `requirements.lock`) en cada corrida. Para
  adjuntarlo a un release, bajá el artefacto de la corrida del commit etiquetado y subilo junto al zip.
- **Regenerar `requirements-dev.lock`** (al agregar herramientas): igual que el comando de arriba, con
  `-c requirements-dev.lock`; instalar en un venv limpio y correr `verificar` antes de confirmar.
