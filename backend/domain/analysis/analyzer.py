"""Orquestador: lee un pcap, agrupa sesiones y evalúa reglas."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from backend.domain.analysis.stream import Stream, follow_stream
from backend.domain.analysis.timeline import Timeline, TimelineCollector
from backend.domain.analysis.names import NameBook, NameCollector
from backend.domain.analysis.session_scan import ScanCache
from backend.domain.pcap.hexdump import hexdump
from backend.domain.pcap.layers import dissect
from backend.domain.pcap.reader import (
    CaptureInfo,
    Packet,
    capture_info,
    get_packet,
    iter_indexed,
    iter_packets,
    packet_index,
)
from backend.domain.rules.engine import Alert, Rule, RuleRunner, decode_layer
from backend.domain.sessions.grouper import (
    GroupingResult,
    SessionGrouper,
    _PROTO_NAMES,
    packet_endpoints,
    packet_session_key,
    parse_ip,
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
    timeline: Optional[Timeline] = None  # paquetes y bytes por intervalo
    # clave de sesión -> id (posición en result.sessions)
    _ids: Dict[Tuple, int] = field(init=False, repr=False, default_factory=dict)
    # escaneos por sesión ya hechos: las páginas siguientes de `session_packets` no releen el pcap
    _scans: ScanCache = field(init=False, repr=False, default_factory=ScanCache)

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
    """Una sola pasada en streaming: sesiones, reglas, nombres de sitio y línea de tiempo."""
    path = Path(path)
    info = capture_info(path)  # valida el archivo antes de gastar tiempo
    grouper = SessionGrouper(info.linktype)
    runner = RuleRunner(rules, info.linktype)
    names, timeline = NameCollector(), TimelineCollector()
    positions = packet_index(path)  # la misma pasada deja listo el índice de `get_packet`
    for i, pos, pkt in iter_indexed(path):
        positions.note(i + 1, pos)
        layer, malformed = parse_ip(pkt.data)  # la capa IP se decodifica una sola vez
        grouper.add(pkt, layer, malformed)
        runner.feed(decode_layer(pkt, layer))
        timeline.add(pkt)
        names.add_layer(pkt, layer)
    return Analysis(
        path=path, info=info, result=grouper.result(), alerts=runner.alerts(), rules=list(rules),
        names=names.book, timeline=timeline.result(),
    )


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
    """Paquetes de una sesión, paginados -> (lista de PacketSummary, hay_más)."""
    _check_page_args(analysis, session_id, offset, limit)
    key = analysis.result.sessions[session_id].key
    scan = analysis._scans.get(analysis.path, key)
    wanted = offset + limit + 1  # uno de más para saber si hay otra página
    scan.fill(wanted)
    if not scan.covers(wanted):  # sesión enorme: más allá del tope se relee el archivo
        return _stream_page(analysis.path, key, offset, limit)
    rows, more = scan.page(offset, limit)
    return [PacketSummary(i, ts, caplen, origlen, origlen is not None and caplen < origlen)
            for i, ts, caplen, origlen in rows], more


def _stream_page(path, key, offset: int, limit: int):
    """Página de una sesión releyendo el archivo desde el inicio (sin guardar nada)."""
    out, seen, more = [], 0, False
    for index, pkt in enumerate(iter_packets(path)):
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
    """Conversación de una sesión TCP, reconstruida releyendo el archivo (como `session_packets`)."""
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
