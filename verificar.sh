#!/usr/bin/env bash
# Verificación completa: ruff, bandit, pip-audit, pytest y, si hay frontend/, lint, tests, build y audit.
# Uso: ./verificar.sh [--seguir] [--linux] [--imagen python:3.13-slim] [--sin-frontend] [--sin-red]
set -uo pipefail
cd "$(dirname "$0")"
seguir=0; linux=0; sin_front=0; sin_red=0; imagen="python:3.12-slim"
while [ $# -gt 0 ]; do
  case "$1" in
    --seguir) seguir=1 ;;
    --linux) linux=1 ;;
    --sin-frontend) sin_front=1 ;;
    --sin-red) sin_red=1 ;;
    --imagen) shift; imagen="${1:?falta la imagen}" ;;
    -h|--help) sed -n 2,3p "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$linux" = 1 ]; then
  echo "=== Linux en Docker ($imagen)"
  docker run --rm -v "$PWD:/src:ro" "$imagen" bash /src/scripts/verificar_linux.sh
  exit $?
fi

if [ -x .venv/bin/python ]; then PY=.venv/bin/python
elif [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe
else PY=$(command -v python3 || command -v python); fi

[ -n "${TRACEWELL_PYTHON:-}" ] && PY="$TRACEWELL_PYTHON"  # p. ej. otro venv con requirements-dev.lock
fallos=(); total=0
paso() {
  local nombre="$1"; shift
  total=$((total + 1)); echo; echo "=== $nombre"
  local t0=$SECONDS
  if "$@"; then echo "OK: $nombre ($((SECONDS - t0)) s)"; return 0; fi
  echo "FALLO: $nombre"; fallos+=("$nombre")
  if [ "$seguir" = 0 ]; then echo "Se corta en el primer fallo (use --seguir para continuar)."; exit 1; fi
}

paso "ruff" "$PY" -m ruff check backend main.py
paso "bandit" "$PY" -m bandit -r backend main.py -ll -c pyproject.toml -q
[ "$sin_red" = 1 ] || paso "pip-audit" "$PY" -m pip_audit --require-hashes -r requirements.lock
paso "pytest" "$PY" -m pytest -q -p no:cacheprovider

if [ "$sin_front" = 0 ] && [ -f frontend/package.json ]; then
  if [ -f frontend/pnpm-lock.yaml ]; then pm=pnpm; inst="pnpm install --frozen-lockfile"
  else pm=npm; inst="npm ci"; fi
  front() { (cd frontend && "$@"); }
  echo; echo "Frontend con $pm"
  # shellcheck disable=SC2086
  [ -d frontend/node_modules ] || paso "frontend: instalar" front $inst
  paso "frontend: lint" front "$pm" run lint
  paso "frontend: tests" front "$pm" run test
  paso "frontend: build" front "$pm" run build
  [ "$sin_red" = 1 ] || paso "frontend: audit" front "$pm" audit --audit-level=high
fi

echo; echo "Pasos: $total, con fallo: ${#fallos[@]}"
[ "${#fallos[@]}" = 0 ] || { printf ' - %s\n' "${fallos[@]}"; exit 1; }
