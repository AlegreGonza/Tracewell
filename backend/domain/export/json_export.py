"""Exportación del análisis a JSON.

Por qué un módulo aparte: el formato de salida es un CONTRATO con quien lo
consuma (otro analista, un SIEM, un script). Lo aislamos para poder versionarlo
(`schema_version`) y cambiarlo sin tocar el análisis.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Iterable, List, Optional

from backend.domain.pcap.reader import CaptureInfo
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import GroupingResult, Session
from backend.domain.sessions.query import compute_stats

# Subir este número cuando el formato cambie de forma incompatible.
SCHEMA_VERSION = 1


def _session_dict(index: int, s: Session) -> Dict[str, Any]:
    # Armado a mano (no asdict): así un campo interno que agreguemos después a
    # Session no se filtra al archivo exportado sin que lo decidamos.
    return {
        "id": index,
        "protocol": s.protocol,
        "src_ip": s.src_ip,
        "src_port": s.src_port,
        "dst_ip": s.dst_ip,
        "dst_port": s.dst_port,
        "packets": s.packets,
        "bytes": s.bytes,
        "first_ts": s.first_ts,
        "last_ts": s.last_ts,
        "duration": s.duration,
    }


def session_to_dict(index: int, s: Session) -> Dict[str, Any]:
    """Forma pública de serializar una sesión (la usa también la API)."""
    return _session_dict(index, s)


def _file_name(source) -> Optional[str]:
    """Solo el nombre del archivo, sea cual sea el estilo de la ruta.

    PureWindowsPath entiende `\\` y `/`; `Path` en Linux no separaría
    `C:\\Users\\x\\cap.pcap` y el reporte filtraría la carpeta del usuario.
    """
    return PureWindowsPath(str(source)).name if source is not None else None


def _source_info(source, info: Optional[CaptureInfo]) -> Dict[str, Any]:
    """Bloque `source` del reporte: solo el NOMBRE del archivo y los datos de la captura."""
    return {
        "file": _file_name(source),
        "format": info.format if info else None,
        "linktype": info.linktype if info else None,
        "snaplen": info.snaplen if info else None,
    }


def _stats_for(result: GroupingResult, sessions: Optional[List[Session]]):
    """Estadísticas de lo exportado (todo el análisis o solo `sessions`)."""
    stats = compute_stats(result if sessions is None else sessions)
    # Aunque las cifras sean de lo filtrado, la bandera de "análisis parcial" es
    # de la CAPTURA: un reporte filtrado de una captura truncada no puede
    # decir que el análisis fue completo (quien lo reciba creería que vio todo).
    stats.truncated = result.truncated
    stats.untracked_packets = result.untracked_packets
    return stats


def _session_rows(result: GroupingResult, sessions: Optional[List[Session]]) -> List[Dict[str, Any]]:
    """Sesiones a exportar; los ids siguen siendo los del análisis completo."""
    ids = {id(s): i for i, s in enumerate(result.sessions)}
    chosen = result.sessions if sessions is None else sessions
    return [_session_dict(ids.get(id(s), i), s) for i, s in enumerate(chosen)]


def build_report(
    source,
    info: Optional[CaptureInfo],
    result: GroupingResult,
    alerts: Iterable[Alert],
    sessions: Optional[List[Session]] = None,
    filters: Optional[Dict[str, Any]] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Arma el reporte como dict (listo para json.dumps).

    - `sessions`: si se pasa (p. ej. ya filtradas), se exportan esas y las
      estadísticas se calculan sobre ellas, para que el reporte sea coherente
      consigo mismo. Los ids siguen siendo los del análisis completo.
    - `source`: se guarda solo el NOMBRE del archivo. Un reporte se comparte, y
      la ruta completa filtraría el nombre de usuario y la estructura de carpetas.
    - `generated_at` se inyecta para poder testear sin depender del reloj.
    """
    when = generated_at or datetime.now(timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": when.isoformat(),
        "source": _source_info(source, info),
        "filters": filters or {},
        "stats": asdict(_stats_for(result, sessions)),
        "sessions": _session_rows(result, sessions),
        "alerts": [asdict(a) for a in alerts],
    }


def to_json(report: Dict[str, Any], indent: Optional[int] = 2) -> str:
    # allow_nan=False: NaN/Infinity no son JSON válido; preferimos un error
    # claro a un archivo que otros parsers rechazan.
    # ensure_ascii=False: la evidencia puede traer texto no ASCII legible.
    return json.dumps(report, indent=indent, ensure_ascii=False, allow_nan=False)


def write_json(report: Dict[str, Any], path) -> Path:
    """Escribe el reporte de forma atómica: nunca queda un JSON a medio escribir."""
    target = Path(path)
    tmp = target.with_name(target.name + ".tmp")
    text = to_json(report)  # serializar ANTES de tocar el disco
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    return target
