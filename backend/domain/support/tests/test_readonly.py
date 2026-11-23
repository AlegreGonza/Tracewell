"""Garantía de SOLO LECTURA: el código de backend/domain/support no ejecuta nada que cambie el sistema.

Se inspecciona el código fuente con `ast`: los textos prohibidos no pueden aparecer en los argumentos de una llamada a
`run`/`powershell_json`/`subprocess.*` ni (los de PowerShell) en los guiones fijos que se le pasan. Los comandos
sugeridos («ipconfig /release») solo pueden vivir como texto de resultado, fuera de esas llamadas.
"""
import ast
import re
from pathlib import Path

SUPPORT = Path(__file__).resolve().parent.parent
FILES = sorted(p for p in SUPPORT.glob("*.py"))
FORBIDDEN = re.compile(r"/release|/renew|/flushdns|/resync|netsh\s+interface|\bSet-|\bNew-|\bRemove-|\bRestart-|\bStop-|winreg\.Set|shell\s*=\s*True", re.IGNORECASE)
EXEC_CALLS = {"run", "powershell_json", "Popen", "check_output", "call", "check_call", "system"}


def _strings(node):
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _is_exec_call(node):
    f = node.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
    return name in EXEC_CALLS


def test_hay_archivos():
    assert {p.name for p in FILES} >= {"common.py", "checks.py", "devices.py", "wifi.py", "dupip.py", "monitor.py", "netinfo.py"}


def test_ningun_comando_ejecutable_modifica_el_sistema():
    bad = []
    for p in FILES:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        scripts = {}  # variables de módulo con guiones fijos (_HISTORY_SCRIPT...) que se pasan a powershell_json
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                scripts[n.targets[0].id] = _strings(n.value)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _is_exec_call(n):
                texts = _strings(n)
                for a in n.args:
                    if isinstance(a, ast.Name):
                        texts += scripts.get(a.id, [])
                bad += [f"{p.name}:{n.lineno}: {t[:60]}" for t in texts if FORBIDDEN.search(t)]
            for kw in getattr(n, "keywords", []):
                if kw.arg == "shell":
                    bad.append(f"{p.name}:{n.lineno}: shell=")
    assert not bad, bad


def test_sin_shell_true_en_ningun_lado():
    for p in FILES:
        assert "shell=True" not in p.read_text(encoding="utf-8"), p.name


def test_los_comandos_sugeridos_son_solo_texto():
    """Los textos con /release, /flushdns, /resync existen únicamente como valores de resultado en checks.py."""
    src = (SUPPORT / "checks.py").read_text(encoding="utf-8")
    assert "ipconfig /release" in src and "ipconfig /flushdns" in src and "w32tm /resync" in src
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _is_exec_call(n):
            assert not any(re.search(r"/release|/renew|/flushdns|/resync", t) for t in _strings(n))
