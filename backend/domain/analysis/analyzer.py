"""Orquestador: lee un pcap, agrupa sesiones y evalúa reglas.

Por qué vive en `core` y no en `api`: es lógica de negocio ("qué significa
analizar una captura"). Si la dejáramos en la API, una CLI o la ventana de
escritorio tendrían que duplicarla o levantar un servidor para usarla.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from backend.domain.analysis.stream import Stream, follow_stream
from backend.domain.analysis.timeline import Timeline, TimelineCollector
from backend.domain.analysis.names import NameBook, NameCollector
from backend.domain.pcap.hexdump import hexdump
from backend.domain.pcap.layers import dissect
from backend.domain.pcap.reader import CaptureInfo, Packet, capture_info, get_packet, iter_packets
from backend.domain.rules.engine import Alert, Rule, evaluate
from backend.domain.sessions.grouper import (
    GroupingResult,
    _PROTO_NAMES,
    group_packets,
    packet_endpoints,
    packet_session_key,
)

MAX_PAGE = 1000


@dataclass
class Analysis:
    path: Path
    info: CaptureInfo
    result: GroupingResult
    alerts: List[Alert]
    rules: List[Rule]
    names: NameBook = field(default_factory=NameBook)  # nombres de sitio sacados de la captura (DNS y SNI)
    timeline: Optional[Timeline] = None  # paquetes y bytes por intervalo (None si la captura no tiene paquetes)
    # clave de sesión -> id (posición en result.sessions)
    _ids: Dict[Tuple, int] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self):
        # Las sesiones armadas a mano pueden no tener clave: no entran al índice.
        self._ids = {s.key: i for i, s in enumerate(self.result.sessions) if s.key is not None}

    def session_id(self, key) -> Optional[int]:
        return self._ids.get(key)


@dataclass(frozen=True)
class PacketSummary:
    index: int
    ts: float
    caplen: int
    origlen: Optional[int]
    snaplen_limited: bool


@dataclass(frozen=True)
class PacketDetail:
    index: int
    ts: float
    caplen: int
    origlen: Optional[int]
    snaplen_limited: bool
    session_id: Optional[int]
    endpoints: Optional[Dict[str, Any]]
    hexdump: str
    # Capas decodificadas con el rango de bytes de cada campo (para resaltar en el hex dump).
    layers: List[Dict[str, Any]] = field(default_factory=list)


def analyze(path, rules: List[Rule]) -> Analysis:
    """Tres pasadas en streaming sobre el archivo (sesiones, reglas y nombres de sitio).

    Varias pasadas en vez de una: cada consumidor queda simple e independiente y
    la memoria no crece con el archivo. Si el costo duele en capturas enormes,
    se unifica después (decisión anotada en docs/decisiones.md).
    """
    path = Path(path)
    info = capture_info(path)  # valida el archivo antes de gastar tiempo
    result = group_packets(iter_packets(path), info.linktype)
    alerts = evaluate(rules, iter_packets(path), info.linktype)
    names, timeline = _enrich(path)
    return Analysis(path=path, info=info, result=result, alerts=alerts, rules=list(rules), names=names, timeline=timeline)


def _enrich(path: Path):
    """Tercera pasada: nombres de sitio y línea de tiempo comparten el mismo recorrido del archivo."""
    names, timeline = NameCollector(), TimelineCollector()
    for pkt in iter_packets(path):
        timeline.add(pkt)
        names.add(pkt)
    return names.book, timeline.result()


def _require_int(name: str, value) -> None:
    """Exige un entero de verdad: bool es subclase de int, así que True no vale."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} debe ser un entero, recibí {value!r}")


def _check_page_args(analysis: Analysis, session_id, offset: int, limit: int) -> None:
    """Valida el id de sesión y el paginado antes de releer el pcap."""
    if isinstance(session_id, bool) or not isinstance(session_id, int) \
            or not 0 <= session_id < len(analysis.result.sessions):
        raise IndexError(f"la sesión {session_id!r} no existe")
    _require_int("offset", offset)  # sin esto, "1" o None fallaban con TypeError al comparar
    _require_int("limit", limit)
    if offset < 0 or not 1 <= limit <= MAX_PAGE:
        raise ValueError(f"offset >= 0 y 1 <= limit <= {MAX_PAGE}")


def session_packets(analysis: Analysis, session_id: int, offset: int = 0, limit: int = 100):
    """Paquetes de una sesión, paginados -> (lista de PacketSummary, hay_más).

    No guardamos los paquetes de cada sesión (la memoria crecería con el
    archivo): releemos el pcap y nos quedamos con los de esa clave.
    """
    _check_page_args(analysis, session_id, offset, limit)
    key = analysis.result.sessions[session_id].key
    out, seen, more = [], 0, False
    for index, pkt in enumerate(iter_packets(analysis.path)):
        if packet_session_key(pkt) != key:
            continue
        if seen >= offset + limit:
            more = True  # hay al menos uno más: no hace falta seguir leyendo
            break
        if seen >= offset:
            out.append(PacketSummary(index, pkt.ts, len(pkt.data), pkt.origlen, pkt.snaplen_limited))
        seen += 1
    return out, more


def session_stream(analysis: Analysis, session_id: int) -> Stream:
    """Conversación de una sesión TCP, reconstruida releyendo el archivo (como `session_packets`).

    IndexError si la sesión no existe; ValueError si no es TCP (los otros protocolos no tienen "conversación").
    """
    if isinstance(session_id, bool) or not isinstance(session_id, int) or not 0 <= session_id < len(analysis.result.sessions):
        raise IndexError(f"la sesión {session_id!r} no existe")
    session = analysis.result.sessions[session_id]
    if session.protocol != "TCP":
        raise ValueError("solo las sesiones TCP tienen una conversación para reconstruir")
    key = session.key
    return follow_stream(session, (p for p in iter_packets(analysis.path) if packet_session_key(p) == key))


def packets_of_sessions(analysis: Analysis, sessions) -> Iterator[Packet]:
    """Paquetes del archivo que pertenecen a alguna de `sessions`, en orden de captura (una sola pasada)."""
    keys = {s.key for s in sessions if s.key is not None}
    if not keys:
        return
    for pkt in iter_packets(analysis.path):
        if packet_session_key(pkt) in keys:
            yield pkt


def _endpoints_dict(ends) -> Optional[Dict[str, Any]]:
    """Endpoints legibles para la API, o None si el paquete no es IP."""
    if ends is None:
        return None
    src, sport, dst, dport, proto = ends
    return {
        "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
        "protocol": _PROTO_NAMES.get(proto, f"IP-{proto}"),
    }


def packet_detail(analysis: Analysis, index: int) -> PacketDetail:
    """Detalle de un paquete: metadatos, endpoints decodificados y hex dump."""
    pkt = get_packet(analysis.path, index)  # IndexError si no existe
    return PacketDetail(
        index=index, ts=pkt.ts, caplen=len(pkt.data), origlen=pkt.origlen,
        snaplen_limited=pkt.snaplen_limited,
        session_id=analysis.session_id(packet_session_key(pkt)),
        endpoints=_endpoints_dict(packet_endpoints(pkt.data)), hexdump=hexdump(pkt.data),
        layers=dissect(pkt.data),
    )
