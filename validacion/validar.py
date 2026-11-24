"""Valida las reglas de Tracewell contra pcaps con verdad terreno (manifiesto YAML)."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import yaml

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from backend.domain.analysis.analyzer import analyze  # noqa: E402
from backend.domain.rules.engine import load_rules  # noqa: E402


class ManifiestoError(ValueError):
    """Manifiesto mal formado."""


@dataclass(frozen=True)
class Esperada:
    regla: str
    origen: Optional[str] = None
    destino: Optional[str] = None


@dataclass(frozen=True)
class Obtenida:
    regla: str
    origen: str
    destino: str
    n: int = 1  # alertas repetidas que se agruparon


@dataclass
class Entrada:
    id: str
    ruta: Path
    descripcion: str
    esperadas: List[Esperada]
    etiquetas: List[str] = field(default_factory=list)


@dataclass
class Resultado:
    """Comparación de un pcap: aciertos (TP), alertas de más (FP) y alertas que faltan (FN)."""

    entrada: Entrada
    tp: List[Tuple[Esperada, Obtenida]] = field(default_factory=list)
    fp: List[Obtenida] = field(default_factory=list)
    fn: List[Esperada] = field(default_factory=list)
    error: str = ""


# ------------------------------------------------------------------ manifiesto

def _parse_esperada(raw, reglas: Optional[set], donde: str) -> Esperada:
    if not isinstance(raw, dict) or not isinstance(raw.get("regla"), str):
        raise ManifiestoError(f"{donde}: cada esperada necesita 'regla' (texto)")
    extra = set(raw) - {"regla", "origen", "destino"}
    if extra:
        raise ManifiestoError(f"{donde}: claves desconocidas {sorted(extra)}")
    if reglas is not None and raw["regla"] not in reglas:
        raise ManifiestoError(f"{donde}: regla desconocida {raw['regla']!r}")
    return Esperada(raw["regla"], raw.get("origen"), raw.get("destino"))


def _parse_esperadas(raw, reglas: Optional[set], donde: str) -> List[Esperada]:
    if raw in (None, "ninguna", []):
        return []
    if not isinstance(raw, list):
        raise ManifiestoError(f"{donde}: 'esperadas' debe ser una lista o 'ninguna'")
    return [_parse_esperada(r, reglas, donde) for r in raw]


def cargar_manifiesto(ruta, reglas: Optional[Iterable[str]] = None) -> List[Entrada]:
    """Lee el manifiesto; las rutas relativas se resuelven junto al archivo."""
    ruta = Path(ruta)
    try:
        datos = yaml.safe_load(ruta.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
        raise ManifiestoError(f"{ruta}: no se pudo leer: {exc}") from exc
    if not isinstance(datos, dict) or not isinstance(datos.get("pcaps"), list):
        raise ManifiestoError(f"{ruta}: falta la lista 'pcaps'")
    conocidas = set(reglas) if reglas is not None else None
    entradas, vistos = [], set()
    for i, raw in enumerate(datos["pcaps"]):
        donde = f"pcaps[{i}]"
        if not isinstance(raw, dict) or not raw.get("id") or not raw.get("ruta"):
            raise ManifiestoError(f"{donde}: necesita 'id' y 'ruta'")
        if raw["id"] in vistos:
            raise ManifiestoError(f"{donde}: id duplicado {raw['id']!r}")
        vistos.add(raw["id"])
        destino = Path(raw["ruta"])
        if not destino.is_absolute():
            destino = ruta.parent / destino
        entradas.append(Entrada(
            raw["id"], destino, str(raw.get("descripcion", "")),
            _parse_esperadas(raw.get("esperadas"), conocidas, f"{donde} ({raw['id']})"),
            list(raw.get("etiquetas") or []),
        ))
    return entradas


# ------------------------------------------------------------------ comparación

def _agrupar(alertas: Iterable) -> List[Obtenida]:
    """Una detección por (regla, origen, destino): evita contar cada consulta DNS por separado."""
    cuenta = Counter((a.rule_id, a.src_ip, a.dst_ip) for a in alertas)
    return [Obtenida(r, s, d, n) for (r, s, d), n in cuenta.items()]


def _coincide(e: Esperada, o: Obtenida) -> bool:
    return (e.regla == o.regla and e.origen in (None, o.origen) and e.destino in (None, o.destino))


def comparar(esperadas: List[Esperada], obtenidas: List[Obtenida]) -> Tuple[list, list, list]:
    """(TP, FP, FN): cada esperada consume como mucho una obtenida; lo demás es FP o FN."""
    libres = list(obtenidas)
    tp, fn = [], []
    for e in esperadas:
        hallada = next((o for o in libres if _coincide(e, o)), None)
        if hallada is None:
            fn.append(e)
            continue
        libres.remove(hallada)
        tp.append((e, hallada))
    return tp, libres, fn


def evaluar(entrada: Entrada, reglas) -> Resultado:
    """Analiza el pcap con las reglas y lo compara con la verdad terreno."""
    res = Resultado(entrada)
    try:
        alertas = analyze(entrada.ruta, reglas).alerts
    except Exception as exc:  # un pcap roto no debe tumbar toda la validación
        res.error = f"{type(exc).__name__}: {exc}"
        return res
    res.tp, res.fp, res.fn = comparar(entrada.esperadas, _agrupar(alertas))
    return res


# --------------------------------------------------------------------- métricas

def _ratio(num: int, den: int) -> Optional[float]:
    return num / den if den else None


def metricas(resultados: List[Resultado], ids_reglas: Iterable[str]) -> Dict[str, dict]:
    """Por regla: TP, FP, FN, precisión y recall (None si no hay base para calcularlos)."""
    tabla = {r: {"tp": 0, "fp": 0, "fn": 0} for r in ids_reglas}
    for res in resultados:
        for e, _ in res.tp:
            tabla[e.regla]["tp"] += 1
        for o in res.fp:
            tabla[o.regla]["fp"] += 1
        for e in res.fn:
            tabla[e.regla]["fn"] += 1
    for fila in tabla.values():
        fila["precision"] = _ratio(fila["tp"], fila["tp"] + fila["fp"])
        fila["recall"] = _ratio(fila["tp"], fila["tp"] + fila["fn"])
    return tabla


def _pct(valor: Optional[float]) -> str:
    return "n/d" if valor is None else f"{valor * 100:.0f}%"


# ---------------------------------------------------------------------- informe

def _total(tabla: Dict[str, dict]) -> dict:
    tp, fp, fn = (sum(f[k] for f in tabla.values()) for k in ("tp", "fp", "fn"))
    return {"tp": tp, "fp": fp, "fn": fn, "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn)}


def tabla_markdown(tabla: Dict[str, dict]) -> str:
    lineas = ["| Regla | TP | FP | FN | Precisión | Recall |", "|---|---:|---:|---:|---:|---:|"]
    for regla, f in sorted(tabla.items()):
        lineas.append(f"| `{regla}` | {f['tp']} | {f['fp']} | {f['fn']} | {_pct(f['precision'])} | {_pct(f['recall'])} |")
    t = _total(tabla)
    lineas.append(f"| **Total** | {t['tp']} | {t['fp']} | {t['fn']} | {_pct(t['precision'])} | {_pct(t['recall'])} |")
    return "\n".join(lineas)


def _fmt(regla: str, origen, destino) -> str:
    return f"`{regla}` ({origen or '*'} -> {destino or '*'})"


def detalle_markdown(resultados: List[Resultado]) -> str:
    """Una entrada por cada FP, FN y error, con el pcap que lo reproduce."""
    lineas = []
    for res in resultados:
        nombre = f"`{res.entrada.id}` ({res.entrada.ruta.name})"
        if res.error:
            lineas.append(f"- ERROR en {nombre}: {res.error}")
        lineas += [f"- FP en {nombre}: {_fmt(o.regla, o.origen, o.destino)}"
                   + (f", {o.n} alertas" if o.n > 1 else "") for o in res.fp]
        lineas += [f"- FN en {nombre}: {_fmt(e.regla, e.origen, e.destino)}" for e in res.fn]
    return "\n".join(lineas) if lineas else "Sin fallos."


def informe(resultados: List[Resultado], ids_reglas: Iterable[str], titulo: str = "Resultados de validación",
            nota: str = "") -> str:
    tabla = metricas(resultados, ids_reglas)
    errores = sum(1 for r in resultados if r.error)
    partes = [
        f"# {titulo}", "", *([f"> {nota}", ""] if nota else []),
        f"Pcaps analizados: {len(resultados) - errores} de {len(resultados)}.", "",
        "## Métricas por regla", "", tabla_markdown(tabla), "",
        "## Detalle de fallos", "", detalle_markdown(resultados), "",
    ]
    return "\n".join(partes)


# -------------------------------------------------------------------------- CLI

def _filtrar(entradas: List[Entrada], etiqueta: Optional[str], omitir_faltantes: bool) -> List[Entrada]:
    if etiqueta:
        entradas = [e for e in entradas if etiqueta in e.etiquetas]
    if omitir_faltantes:
        entradas = [e for e in entradas if e.ruta.exists()]
    return entradas


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("manifiesto", type=Path, help="manifiesto YAML")
    p.add_argument("--reglas", type=Path, default=RAIZ / "rules", help="carpeta de reglas (por defecto rules/)")
    p.add_argument("--salida", type=Path, help="escribe el informe aquí en vez de la pantalla")
    p.add_argument("--titulo", default="Resultados de validación")
    p.add_argument("--nota", default="", help="aviso que se muestra bajo el título")
    p.add_argument("--etiqueta", help="solo los pcaps con esta etiqueta (p. ej. benigno)")
    p.add_argument("--omitir-faltantes", action="store_true", help="ignora los pcaps que no existen")
    args = p.parse_args(argv)
    reglas = load_rules(args.reglas)
    ids = [r.id for r in reglas]
    entradas = _filtrar(cargar_manifiesto(args.manifiesto, ids), args.etiqueta, args.omitir_faltantes)
    texto = informe([evaluar(e, reglas) for e in entradas], ids, args.titulo, args.nota)
    if args.salida:
        args.salida.write_text(texto, encoding="utf-8")
    else:
        sys.stdout.buffer.write(texto.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
