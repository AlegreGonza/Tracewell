"""Exportación de alertas a un SIEM: ECS (NDJSON), CEF y syslog (RFC 5424 con CEF)."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.domain.rules.engine import SEVERITIES, Alert

ECS_VERSION = "8.11"
FORMATS = ("ecs", "cef", "syslog")
MAX_CEF_EVIDENCE = 900  # caracteres del JSON de evidencia en un campo CEF

# Identificadores de táctica de MITRE ATT&CK (los nombres canónicos viven en `engine.MITRE_TACTICS`).
TACTIC_IDS = {
    "Reconnaissance": "TA0043", "Initial Access": "TA0001", "Credential Access": "TA0006",
    "Discovery": "TA0007", "Lateral Movement": "TA0008", "Collection": "TA0009",
    "Command and Control": "TA0011", "Exfiltration": "TA0010", "Impact": "TA0040",
}
# event.severity (puntaje de riesgo de Elastic Security), severidad CEF (0-10) y syslog (RFC 5424).
_ECS_SEVERITY = {"low": 21, "medium": 47, "high": 73, "critical": 99}
_CEF_SEVERITY = {"low": 3, "medium": 5, "high": 8, "critical": 10}
_SYSLOG_SEVERITY = {"low": 6, "medium": 5, "high": 4, "critical": 2}
_SYSLOG_FACILITY = 16  # local0
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PORT_KEYS = ("destination_port", "port")


def _iso(ts: float) -> str:
    """Instante en UTC con milisegundos y 'Z' (un instante imposible cae en la época)."""
    try:
        moment = datetime.fromtimestamp(ts, timezone.utc)
    except (OverflowError, OSError, ValueError):
        moment = datetime.fromtimestamp(0, timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _epoch_ms(ts: float) -> int:
    try:
        return int(round(float(ts) * 1000))
    except (OverflowError, ValueError):
        return 0


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _port_of(evidence: Dict[str, Any]) -> Optional[int]:
    """Puerto de destino de la evidencia, si el detector lo guardó y es válido."""
    for key in _PORT_KEYS:
        value = evidence.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 65535:
            return value
    return None


def _split_technique(technique: str, name: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    """(id de técnica, nombre, id de subtécnica, nombre de subtécnica); `T1071.004` es subtécnica de T1071."""
    if "." not in technique:
        return technique, name, None, None
    parent, _, sub_name = name.partition(": ")
    return technique.split(".")[0], parent, technique, sub_name or name


def _technique_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def filter_min_severity(alerts: Iterable[Alert], minimum: Optional[str]) -> List[Alert]:
    """Alertas con severidad igual o mayor que `minimum` (None = todas)."""
    if minimum is None:
        return list(alerts)
    if minimum not in SEVERITIES:
        raise ValueError(f"severidad desconocida: {minimum!r}")
    floor = SEVERITIES.index(minimum)
    return [a for a in alerts if a.severity in SEVERITIES and SEVERITIES.index(a.severity) >= floor]


# ------------------------------------------------------------------------ ECS

def _threat_block(alert: Alert) -> Dict[str, Any]:
    """Bloque `threat.*` de ECS (los campos de tactic y technique son listas)."""
    tid, tname, sub_id, sub_name = _split_technique(alert.mitre_technique, alert.mitre_name)
    tactic: Dict[str, Any] = {"name": [alert.mitre_tactic]}
    if alert.mitre_tactic in TACTIC_IDS:
        tactic["id"] = [TACTIC_IDS[alert.mitre_tactic]]
        tactic["reference"] = [f"https://attack.mitre.org/tactics/{TACTIC_IDS[alert.mitre_tactic]}/"]
    technique: Dict[str, Any] = {"id": [tid], "name": [tname], "reference": [_technique_url(tid)]}
    if sub_id:
        technique["subtechnique"] = {"id": [sub_id], "name": [sub_name], "reference": [_technique_url(sub_id)]}
    return {"framework": "MITRE ATT&CK", "tactic": tactic, "technique": technique}


def alert_to_ecs(alert: Alert) -> Dict[str, Any]:
    """La alerta como documento ECS (Elastic Common Schema); lo propio de Tracewell va en `tracewell.*`."""
    doc: Dict[str, Any] = {
        "@timestamp": _iso(alert.first_ts),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert", "category": ["network", "intrusion_detection"], "type": ["info"],
            "severity": _ECS_SEVERITY.get(alert.severity, 0), "module": "tracewell", "dataset": "tracewell.alert",
        },
        "message": alert.description or alert.name,
        "rule": {"id": alert.rule_id, "name": alert.name, "description": alert.description},
        "threat": _threat_block(alert),
        "tracewell": {"severity": alert.severity, "evidence": alert.evidence},
        "tags": ["tracewell"],
    }
    if _is_ip(alert.src_ip):
        doc["source"] = {"ip": alert.src_ip}
    if _is_ip(alert.dst_ip):
        doc["destination"] = {"ip": alert.dst_ip}
        port = _port_of(alert.evidence)
        if port is not None:
            doc["destination"]["port"] = port
    return doc


def to_ndjson(alerts: Iterable[Alert]) -> str:
    """Un documento ECS por línea (NDJSON), listo para `_bulk` de Elasticsearch o Filebeat."""
    return "".join(
        json.dumps(alert_to_ecs(a), ensure_ascii=False, allow_nan=False, default=str, separators=(",", ":")) + "\n"
        for a in alerts
    )


# ------------------------------------------------------------------------ CEF

def _cef_header(text: Any) -> str:
    """Campo de la cabecera CEF: se escapan `\\` y `|`, y los saltos de línea pasan a espacio."""
    return _CONTROL.sub(" ", str(text)).replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(text: Any) -> str:
    """Valor de la extensión CEF: se escapan `\\` y `=`; los saltos de línea quedan como `\\n`."""
    out = str(text).replace("\\", "\\\\").replace("=", "\\=")
    return _CONTROL.sub(lambda m: {"\n": "\\n", "\r": "\\r"}.get(m.group(), " "), out)


def _cef_evidence(evidence: Dict[str, Any]) -> str:
    text = json.dumps(evidence, ensure_ascii=False, default=str, separators=(",", ":"))
    return text if len(text) <= MAX_CEF_EVIDENCE else text[:MAX_CEF_EVIDENCE] + "..."


def _cef_extension(alert: Alert) -> str:
    pairs: List[Tuple[str, Any]] = [("rt", _epoch_ms(alert.first_ts))]
    if _is_ip(alert.src_ip):
        pairs.append(("src", alert.src_ip))
    if _is_ip(alert.dst_ip):
        pairs.append(("dst", alert.dst_ip))
    port = _port_of(alert.evidence)
    if port is not None:
        pairs.append(("dpt", port))
    pairs += [
        ("cat", alert.mitre_tactic), ("msg", alert.description or alert.name),
        ("cs1Label", "mitreTactic"), ("cs1", alert.mitre_tactic),
        ("cs2Label", "mitreTechnique"), ("cs2", alert.mitre_technique),
        ("cs3Label", "mitreTechniqueName"), ("cs3", alert.mitre_name),
        ("cs4Label", "severity"), ("cs4", alert.severity),
        ("cs5Label", "evidence"), ("cs5", _cef_evidence(alert.evidence)),
    ]
    return " ".join(f"{k}={_cef_value(v)}" for k, v in pairs)


def alert_to_cef(alert: Alert, version: str = "0") -> str:
    """Línea CEF:0 de la alerta (ArcSight Common Event Format)."""
    head = "|".join(_cef_header(x) for x in (
        "Tracewell", "Tracewell", version, alert.rule_id, alert.name, _CEF_SEVERITY.get(alert.severity, 0),
    ))
    return f"CEF:0|{head}|{_cef_extension(alert)}"


def to_cef(alerts: Iterable[Alert], version: str = "0") -> str:
    """Una línea CEF por alerta."""
    return "".join(alert_to_cef(a, version) + "\n" for a in alerts)


# --------------------------------------------------------------------- syslog

def alert_to_syslog(alert: Alert, version: str = "0") -> str:
    """Mensaje syslog RFC 5424 (facilidad local0) que lleva la línea CEF; sin nombre de equipo (`-`)."""
    priority = _SYSLOG_FACILITY * 8 + _SYSLOG_SEVERITY.get(alert.severity, 6)
    return f"<{priority}>1 {_iso(alert.first_ts)} - tracewell - ALERT - {alert_to_cef(alert, version)}"


def to_syslog(alerts: Iterable[Alert], version: str = "0") -> str:
    """Un mensaje syslog por línea."""
    return "".join(alert_to_syslog(a, version) + "\n" for a in alerts)


# ------------------------------------------------------------------- fachada

_MEDIA = {
    "ecs": ("application/x-ndjson", "tracewell-alerts.ndjson"),
    "cef": ("text/plain; charset=utf-8", "tracewell-alerts.cef"),
    "syslog": ("text/plain; charset=utf-8", "tracewell-alerts.log"),
}


def media_info(fmt: str) -> Tuple[str, str]:
    """(tipo de contenido, nombre de archivo) del formato."""
    if fmt not in _MEDIA:
        raise ValueError(f"formato desconocido: {fmt!r}; usar uno de {list(FORMATS)}")
    return _MEDIA[fmt]


def render(alerts: Iterable[Alert], fmt: str, version: str = "0", min_severity: Optional[str] = None) -> str:
    """Texto del formato pedido (ecs, cef o syslog), con las alertas desde `min_severity`."""
    media_info(fmt)  # valida el formato antes de trabajar
    chosen = filter_min_severity(alerts, min_severity)
    if fmt == "ecs":
        return to_ndjson(chosen)
    return to_cef(chosen, version) if fmt == "cef" else to_syslog(chosen, version)
