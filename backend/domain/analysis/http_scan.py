"""Busca HTTP en TODA la captura (no solo en una sesión): una fila por petición, con su respuesta."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from backend.domain.analysis.http import http_exchanges
from backend.domain.analysis.stream import raw_directions
from backend.domain.pcap.reader import Packet, iter_packets
from backend.domain.sessions.grouper import packet_session_key

HTTP_PORTS = (80, 8000, 8008, 8080, 8888, 3128, 5000)
MAX_SESSIONS = 200
MAX_BYTES = 50_000_000
MAX_EXCHANGES = 500


def candidate_sessions(analysis) -> List[tuple]:
    """[(id, sesión)] de las sesiones TCP a puertos de HTTP, hasta `MAX_SESSIONS`."""
    out = []
    for i, s in enumerate(analysis.result.sessions):
        if s.protocol == "TCP" and s.key is not None and (s.dst_port in HTTP_PORTS or s.src_port in HTTP_PORTS):
            out.append((i, s))
            if len(out) >= MAX_SESSIONS:
                break
    return out


def _collect(analysis, wanted: Dict[Any, Any]):
    packets: Dict[Any, List[Packet]] = defaultdict(list)
    total = 0
    for pkt in iter_packets(analysis.path):
        key = packet_session_key(pkt)
        if key in wanted:
            total += len(pkt.data)
            if total > MAX_BYTES:
                return packets, True
            packets[key].append(pkt)
    return packets, False


def scan_http(analysis) -> Dict[str, Any]:
    """{'scanned', 'capped', 'items': [...]} de las sesiones candidatas."""
    candidates = candidate_sessions(analysis)
    packets, capped = _collect(analysis, {s.key: i for i, s in candidates})
    items: List[Dict[str, Any]] = []
    cut = 0  # sesiones cuyo flujo se recortó por el tope de bytes o de paquetes
    for sid, s in candidates:
        raw = raw_directions(s, packets.get(s.key, []))
        cut += raw.truncated
        for ex in http_exchanges(raw.origin, raw.destination):
            if len(items) >= MAX_EXCHANGES:
                return {"scanned": len(candidates), "capped": True, "items": items}
            items.append({
                **ex, "session_id": sid, "src_ip": s.src_ip, "dst_ip": s.dst_ip,
                "src": f"{s.src_ip}:{s.src_port}", "dst": f"{s.dst_ip}:{s.dst_port}",
            })
    return {"scanned": len(candidates), "capped": capped or cut > 0, "items": items}
