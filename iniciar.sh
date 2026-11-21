#!/usr/bin/env bash
# Abre Tracewell (usa el entorno creado por instalar.sh).
#   ./iniciar.sh                 ventana de escritorio
#   ./iniciar.sh --serve-only    en el navegador
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  echo "Todavía no está instalado. Ejecutá primero:  ./instalar.sh"
  exit 1
fi
exec .venv/bin/python main.py "$@"
