"""Constructor de reglas: arma una regla por umbral a partir de los campos de un formulario.

Lógica pura (sin FastAPI): valida el formulario, genera el YAML con el MISMO formato que las reglas
de `rules/`, calcula la vista previa sobre una captura y guarda el archivo. La regla usa el detector
`threshold` (extra_detectors.py): el analista elige filtros y umbral, no escribe código.

Nunca modifica ni desactiva reglas existentes: guardar con un id o un archivo que ya existe falla.
"""
from __future__ import annotations

import re
import textwrap
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from backend.domain.pcap.reader import Packet
from backend.domain.rules.engine import SEVERITIES, Rule, RuleError, _parse_rule, evaluate
from backend.domain.rules.extra_detectors import _in_network
from backend.domain.sessions.grouper import ETHERNET

ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
# Nombres de dispositivo de Windows: un archivo con ese nombre (con.yaml, nul.yaml...) es problemático.
RESERVED_IDS = frozenset({"con", "prn", "aux", "nul"}
                         | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)})
MAX_NAME, MAX_DESCRIPTION = 80, 500
DEFAULT_MITRE = {"technique": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}
SAMPLE_ALERTS = 5


class RuleExists(Exception):
    """Ya hay una regla con ese id o ese archivo: no se pisa."""


@dataclass
class RuleForm:
    """Campos del formulario tal como llegan (ya con tipos básicos)."""

    name: str
    severity: str = "medium"
    description: str = ""
    protocol: str = "any"
    src_ip: str = ""
    dst_ip: str = ""
    port: int = 0
    min_events: int = 20
    window_seconds: float = 60.0
    id: str = ""
    mitre_technique: str = ""
    mitre_name: str = ""
    mitre_tactic: str = ""


def slugify(name: str) -> str:
    """Id sugerido a partir del nombre: minúsculas, sin tildes, con guiones bajos."""
    plain = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "_", plain.lower()).strip("_")
    if not slug or not slug[0].isalpha():
        slug = f"regla_{slug}".strip("_")
    return slug[:40].rstrip("_")


def to_dict(form: RuleForm) -> Dict[str, Any]:
    """Diccionario de la regla (claves en el orden de las reglas del repo). Valida lo que el motor no ve."""
    name = (form.name or "").strip()
    if not name or len(name) > MAX_NAME:
        raise RuleError(f"el nombre es obligatorio y de hasta {MAX_NAME} caracteres")
    description = " ".join((form.description or "").split())
    if len(description) > MAX_DESCRIPTION:
        raise RuleError(f"la descripción admite hasta {MAX_DESCRIPTION} caracteres")
    rule_id = (form.id or "").strip() or slugify(name)
    if rule_id in RESERVED_IDS:
        raise RuleError(f"el id {rule_id!r} es un nombre reservado del sistema; elige otro")
    if not ID_RE.match(rule_id):
        raise RuleError("el id debe empezar con una letra minúscula y tener 3 a 40 letras minúsculas, números o _")
    if form.severity not in SEVERITIES:
        raise RuleError(f"la severidad debe ser una de {list(SEVERITIES)}")
    mitre = {
        "technique": (form.mitre_technique or "").strip() or DEFAULT_MITRE["technique"],
        "name": (form.mitre_name or "").strip() or DEFAULT_MITRE["name"],
        "tactic": (form.mitre_tactic or "").strip() or DEFAULT_MITRE["tactic"],
    }
    params: Dict[str, Any] = {
        "protocol": form.protocol, "src_ip": (form.src_ip or "").strip(), "dst_ip": (form.dst_ip or "").strip(),
        "port": form.port, "min_events": form.min_events, "window_seconds": form.window_seconds,
    }
    return {
        "id": rule_id, "name": name, "description": description, "severity": form.severity,
        "detector": "threshold", "mitre": mitre, "params": params,
    }


def build_rule(data: Dict[str, Any]) -> Rule:
    """Regla validada por el mismo motor que carga los YAML (falla con RuleError si algo está mal)."""
    return _parse_rule(data, f"{data['id']}.yaml")


def _scalar(value: Any) -> str:
    """Un valor como lo escribiría YAML en una línea."""
    return yaml.safe_dump(value, allow_unicode=True, default_flow_style=True, width=10_000).split("\n...")[0].strip()


_PARAM_COMMENTS = {
    "protocol": "any, tcp o udp (en tcp se cuentan los intentos de conexión, SYN)",
    "src_ip": "IP o red CIDR de origen; vacío = cualquiera",
    "dst_ip": "IP o red CIDR de destino; vacío = cualquiera",
    "port": "puerto de destino; 0 = cualquiera",
    "min_events": "eventos para disparar",
    "window_seconds": "ventana de tiempo",
}


def render_yaml(data: Dict[str, Any]) -> str:
    """YAML con el formato de las reglas existentes (descripción en bloque `>`, params comentados)."""
    lines = [f"id: {_scalar(data['id'])}", f"name: {_scalar(data['name'])}"]
    if data["description"]:
        lines.append("description: >-")
        lines += [f"  {row}" for row in textwrap.wrap(data["description"], 74)]
    lines += [f"severity: {data['severity']}", f"detector: {data['detector']}", "mitre:"]
    lines += [f"  {k}: {_scalar(v)}" for k, v in data["mitre"].items()]
    lines.append("params:")
    for k, v in data["params"].items():
        lines.append(f"  {k}: {_scalar(v)}   # {_PARAM_COMMENTS[k]}")
    return "\n".join(lines) + "\n"


def _session_matches(s, params: Dict[str, Any]) -> bool:
    if params["protocol"] != "any" and s.protocol.lower() != params["protocol"]:
        return False
    if params["port"] and s.dst_port != params["port"]:
        return False
    if params["src_ip"] and not _in_network(s.src_ip, params["src_ip"]):
        return False
    return not (params["dst_ip"] and not _in_network(s.dst_ip, params["dst_ip"]))


def preview(rule: Rule, packets: Iterable[Packet], sessions: Iterable, linktype: int = ETHERNET) -> Dict[str, Any]:
    """Qué pasaría con la captura actual: sesiones que cumplen el filtro y alertas que daría el umbral.
    No guarda nada y no toca las alertas del análisis actual."""
    alerts = evaluate([rule], packets, linktype)
    return {
        "sessions": sum(1 for s in sessions if _session_matches(s, rule.params)),
        "alerts": len(alerts),
        "sample": [
            {"src_ip": a.src_ip, "dst_ip": a.dst_ip, "first_ts": a.first_ts, "evidence": a.evidence}
            for a in alerts[:SAMPLE_ALERTS]
        ],
    }


def save(rules_dir, data: Dict[str, Any], existing_ids: Iterable[str]) -> Path:
    """Escribe `<id>.yaml` en la carpeta de reglas. Falla si el id o el archivo ya existen (no pisa nada)."""
    if data["id"] in set(existing_ids):
        raise RuleExists(f"ya existe una regla con el id {data['id']!r}")
    path = Path(rules_dir) / f"{data['id']}.yaml"
    try:
        with open(path, "x", encoding="utf-8", newline="\n") as f:  # "x": falla si el archivo existe
            f.write(render_yaml(data))
    except FileExistsError:
        raise RuleExists(f"ya existe el archivo {path.name}") from None
    return path


def summarize(rules: List[Rule]) -> List[Dict[str, Any]]:
    """Lista corta de reglas para la interfaz."""
    return [
        {"id": r.id, "name": r.name, "severity": r.severity, "detector": r.detector, "custom": r.detector == "threshold"}
        for r in rules
    ]


EXAMPLE: Dict[str, Any] = {
    "name": "Muchos SYN hacia la red interna",
    "severity": "medium",
    "description": "Una IP abrió muchas conexiones nuevas hacia equipos de la red interna en poco tiempo.",
    "protocol": "tcp", "src_ip": "", "dst_ip": "192.168.0.0/16", "port": 0, "min_events": 15, "window_seconds": 60,
}
