#!/usr/bin/env bash
# Instalador de Tracewell para Linux / macOS.
#   ./instalar.sh           instala y verifica
#   ./instalar.sh --check   solo informa qué falta (no instala nada)
#   ./instalar.sh --dev     instala también pytest y compañía
# No usa sudo ni instala paquetes del sistema: si falta algo, lo indica.
set -u
cd "$(dirname "$0")"

CHECK=0; DEV=0
for a in "$@"; do
  case "$a" in
    --check) CHECK=1 ;;
    --dev) DEV=1 ;;
    *) echo "Opción desconocida: $a (usá --check o --dev)"; exit 2 ;;
  esac
done

MISSING=()
ok()   { printf '  [OK]    %s\n' "$1"; }
bad()  { printf '  [FALTA] %s\n' "$1"; }
warn() { printf '  [AVISO] %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

step "1. Python 3.11 o superior"
PY=""
for c in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -n "$PY" ]; then ok "Encontrado: $(command -v "$PY")"; else
  bad "No se encontró Python 3.11+."
  echo "         Linux: instalalo con tu gestor (p. ej. 'sudo apt install python3 python3-venv'). macOS: 'brew install python'."
  MISSING+=("Python 3.11+")
fi

VENV_PY=".venv/bin/python"
if [ -n "$PY" ]; then
  step "2. Entorno virtual (.venv)"
  if [ -x "$VENV_PY" ]; then ok ".venv ya existe"
  elif [ "$CHECK" -eq 1 ]; then bad ".venv no existe"; MISSING+=("entorno virtual .venv")
  else
    if "$PY" -m venv .venv; then ok ".venv creado"
    else bad "No se pudo crear .venv (en Debian/Ubuntu: 'sudo apt install python3-venv')."; MISSING+=("python3-venv"); fi
  fi

  if [ -x "$VENV_PY" ]; then
    step "3. Paquetes de Python"
    REQ="requirements.lock"; [ "$DEV" -eq 1 ] && REQ="requirements-dev.lock"
    HASHES="--require-hashes"
    if [ ! -f "$REQ" ]; then  # sin lock (p. ej. zip mínimo): versiones con cotas, sin hashes
      REQ="requirements.txt"; [ "$DEV" -eq 1 ] && REQ="requirements-dev.txt"; HASHES=""
    fi
    if [ "$DEV" -eq 0 ] && "$VENV_PY" -c 'import dpkt, yaml, fastapi, uvicorn, scapy, psutil' 2>/dev/null; then
      ok "Dependencias ya instaladas"
    elif [ "$CHECK" -eq 1 ]; then bad "Faltan paquetes de Python"; MISSING+=("paquetes de Python ($REQ)")
    else
      echo "  Instalando $REQ desde PyPI..."
      # shellcheck disable=SC2086
      if "$VENV_PY" -m pip install --disable-pip-version-check $HASHES -r "$REQ"; then ok "Paquetes instalados"
      else bad "pip falló"; MISSING+=("paquetes de Python"); fi
    fi
  fi
fi

step "4. Interfaz web (frontend/dist)"
if [ -f frontend/dist/index.html ]; then ok "La interfaz ya está compilada"
elif [ "$CHECK" -eq 1 ]; then bad "Falta frontend/dist"; MISSING+=("interfaz compilada (frontend/dist)")
elif command -v npm >/dev/null 2>&1; then
  (cd frontend && corepack pnpm install --frozen-lockfile && corepack pnpm run build) && ok "Interfaz compilada" || { bad "Falló la compilación"; MISSING+=("compilar la interfaz"); }
else
  bad "Falta frontend/dist y no hay Node.js para compilarla."
  MISSING+=("Node.js (https://nodejs.org) para compilar la interfaz")
fi

step "5. Captura en vivo y ventana (opcionales)"
warn "Captura en vivo: hace falta libpcap y ejecutar con sudo. Analizar archivos no lo necesita."
warn "Ventana de escritorio: en Linux pywebview necesita GTK/WebKit o Qt (la ventana se probó en Linux). Alternativa: ./iniciar.sh --serve-only"

echo
if [ "${#MISSING[@]}" -gt 0 ]; then
  echo "Falta para terminar:"; for m in "${MISSING[@]}"; do echo "  - $m"; done; exit 1
fi
if [ "$CHECK" -eq 1 ]; then echo "Todo está listo. Para abrir Tracewell: ./iniciar.sh"; exit 0; fi
echo "Listo. Para abrir Tracewell:  ./iniciar.sh --serve-only   (o ./iniciar.sh para la ventana)"
