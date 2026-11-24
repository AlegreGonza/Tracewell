#!/usr/bin/env bash
# Verificación del backend en Linux limpio (se usa dentro de Docker; ver docs/pruebas.md).
# Uso: docker run --rm -v "<repo>:/src:ro" python:3.12-slim bash /src/scripts/verificar_linux.sh
set -uo pipefail
SRC="${1:-/src}"
WORK="${2:-/work}"
mkdir -p "$WORK"
# Copia de trabajo sin lo que no aplica (venv de Windows, git, frontend, dependencias de Node).
(cd "$SRC" && tar --exclude=./.venv --exclude=./.git --exclude='./frontend*' --exclude=node_modules \
  --exclude=__pycache__ --exclude=./release --exclude=./validacion/corpus -cf - .) | tar -xf - -C "$WORK"
cd "$WORK" || exit 2
python --version
pip install -q --disable-pip-version-check --require-hashes -r requirements-dev.lock || exit 2
fallos=0
paso() { echo; echo "=== $1"; shift; "$@" || { echo "FALLO: $*"; fallos=$((fallos + 1)); }; }
paso ruff python -m ruff check backend main.py
paso bandit python -m bandit -r backend main.py -ll -c pyproject.toml -q
paso pip-audit python -m pip_audit --require-hashes -r requirements.lock
paso pytest python -m pytest -q -p no:cacheprovider
echo; echo "Pasos con fallo: $fallos"
exit "$((fallos > 0))"
