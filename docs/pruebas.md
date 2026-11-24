# Pruebas: flujo unificado de verificación

Un solo comando corre, en orden, todos los controles del proyecto y corta en el primer fallo.

```powershell
.\verificar.ps1                 # Windows: backend y, si existe frontend/, también el frontend
.\verificar.ps1 -Seguir         # no corta: corre todo y lista al final lo que falló
.\verificar.ps1 -SinRed         # sin pip-audit ni pnpm/npm audit (no consultan servicios externos)
.\verificar.ps1 -Linux          # backend en Linux limpio dentro de Docker (python:3.12-slim)
.\verificar.ps1 -Linux -Imagen python:3.13-slim
```

```bash
./verificar.sh [--seguir] [--sin-red] [--sin-frontend] [--linux] [--imagen python:3.13-slim]
```

Prepará el entorno una vez con `pip install --require-hashes -r requirements-dev.lock` (en `.venv`). Los scripts
usan `.venv` si existe; con la variable `TRACEWELL_PYTHON` se elige otro Python (por ejemplo otro venv).

## Qué corre cada paso

| Paso | Comando | Qué detecta | Tiempo orientativo |
|---|---|---|---|
| ruff | `python -m ruff check backend main.py` | imports sin usar, nombres sin definir (reglas `F`) | segundos |
| bandit | `python -m bandit -r backend main.py -ll -c pyproject.toml -q` | patrones inseguros de severidad media o alta en el código de producción (los `tests/` se excluyen) | segundos |
| pip-audit | `python -m pip_audit --require-hashes -r requirements.lock` | vulnerabilidades conocidas en las dependencias fijadas | ~20 s, necesita red |
| pytest | `python -m pytest -q -p no:cacheprovider` | la suite del backend | 1 a 2 minutos |
| frontend: lint, tests, build | `pnpm` o `npm` `run lint`, `run test`, `run build` (en `frontend/`) | ESLint, vitest, compilación | decenas de segundos |
| frontend: audit | `pnpm audit --audit-level=high` (o `npm audit`) | vulnerabilidades altas o críticas en dependencias del frontend | segundos, necesita red |

El gestor del frontend se detecta solo: si existe `frontend/pnpm-lock.yaml` se usa pnpm, si no, npm. Si falta
`frontend/node_modules`, el script primero instala (`pnpm install --frozen-lockfile` o `npm ci`). Las cantidades
de tests no se escriben acá porque cambian en cada commit: se miden con el propio `pytest` y `vitest`.

bandit imprime avisos `nosec encountered ... no failed test` por una línea anotada con `# nosec B108` en
`backend/domain/system/common.py` (lista de carpetas sospechosas, no se escribe en ellas); son inofensivos.

## Linux con Docker

`verificar -Linux` monta el repositorio de solo lectura en un contenedor, copia el árbol sin `.venv`, `.git`,
`frontend*` ni `node_modules`, instala desde `requirements-dev.lock` **con `--require-hashes`** y corre ruff,
bandit, pip-audit y pytest (`scripts/verificar_linux.sh`). Sirve para ver lo que el CI verá en `ubuntu-latest`
sin depender de que el cambio ya esté en GitHub. Limpieza: el contenedor se borra solo (`--rm`); la imagen
queda en caché y se quita con `docker rmi python:3.12-slim`.

Los tests que solo tienen sentido en Windows (por ejemplo el códec `oem` de las páginas de códigos de consola)
se marcan con `pytest.mark.skipif(sys.platform != "win32", ...)`. Los que ejercitan código de Windows en otra
plataforma inyectan un módulo falso (por ejemplo `winreg`) en lugar de saltarse.

## Integración continua

`.github/workflows/ci.yml` corre en cada push a `main` y en cada pull request:

- **backend:** matriz `ubuntu-latest` y `windows-latest` por Python 3.11 y 3.13, mismos pasos que arriba.
- **frontend:** Node 22 con pnpm (`frontend/pnpm-lock.yaml`): `pnpm install --frozen-lockfile`, lint, tests,
  build y `pnpm audit`. Asume el layout final del repositorio (`frontend/` con pnpm).
- **sbom:** genera un SBOM CycloneDX de `requirements.lock` y lo sube como artefacto (`sbom-cyclonedx`).

Las actions están fijadas por SHA completo de commit, con `permissions: contents: read` y tiempo máximo por job.
Lo que el CI no puede probar: captura en vivo contra una red real (ver `docs/checklist_hardware.md`) ni la
ventana de escritorio.

## Cómo interpretar un fallo

- **ruff:** el mensaje trae archivo y línea; corregí el código (no se reformatea nada automáticamente).
- **bandit:** `-ll` solo muestra severidad media o alta. Un falso positivo se anota en la línea con
  `# nosec Bxxx` (el id de la regla); no se desactiva la regla en general.
- **pip-audit:** lista paquete, versión instalada, id del aviso y versión corregida. Subí esa dependencia en
  `requirements.txt` y regenerá el lock (`docs/desarrollo.md`). Si no hay corrección, decidí y documentá la
  excepción. Un fallo de red (no de vulnerabilidad) no lista avisos: reintentá o usá `-SinRed`.
- **pytest falla solo en Linux (o solo en Windows):** casi siempre es una suposición de plataforma (separador de
  rutas, `winreg`, códec `oem`, permisos de archivos). Reproducilo con `-Linux`.
- **pytest falla solo en Python 3.13:** corré `-Linux -Imagen python:3.13-slim`; suele ser una dependencia sin
  wheel para esa versión o una API retirada.
- **frontend audit:** un aviso de una dependencia de desarrollo (vitest, vite) no afecta lo que se distribuye
  (la interfaz compilada), pero igual conviene actualizar.
