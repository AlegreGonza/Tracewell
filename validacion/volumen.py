"""Volumen de alertas sobre un pcap SIN etiquetas: alertas por minuto, por regla y por origen."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from backend.domain.analysis.analyzer import analyze  # noqa: E402
from backend.domain.rules.engine import load_rules  # noqa: E402


def medir(alertas: List, segundos: float) -> Dict:
    """Resumen: total, alertas por minuto y por regla, y cuántos orígenes distintos las generan."""
    minutos = max(segundos, 1.0) / 60
    por_regla = Counter(a.rule_id for a in alertas)
    return {
        "alertas": len(alertas), "segundos": round(segundos, 1), "por_minuto": round(len(alertas) / minutos, 1),
        "origenes": len({a.src_ip for a in alertas}),
        "reglas": {r: {"alertas": n, "por_minuto": round(n / minutos, 1),
                       "origenes": len({a.src_ip for a in alertas if a.rule_id == r})} for r, n in por_regla.most_common()},
    }


def texto(m: Dict) -> str:
    """Tabla en Markdown del resumen."""
    filas = ["| Regla | Alertas | Por minuto | Orígenes |", "|---|---:|---:|---:|"]
    filas += [f"| `{r}` | {v['alertas']} | {v['por_minuto']} | {v['origenes']} |" for r, v in m["reglas"].items()]
    return (f"{m['alertas']} alertas en {m['segundos']} s ({m['por_minuto']} por minuto, {m['origenes']} orígenes)\n\n"
            + "\n".join(filas))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pcap", type=Path)
    p.add_argument("--reglas", type=Path, default=RAIZ / "rules")
    args = p.parse_args(argv)
    a = analyze(args.pcap, load_rules(args.reglas))
    tiempos = [(s.first_ts, s.last_ts) for s in a.result.sessions]
    segundos = (max(t[1] for t in tiempos) - min(t[0] for t in tiempos)) if tiempos else 0.0
    print(texto(medir(a.alerts, segundos)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
