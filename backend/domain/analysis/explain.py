"""«¿Qué pasó en esta sesión?» explicado en palabras simples."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from backend.domain.analysis.hosts import _server_is_src
from backend.domain.analysis.stream import _tcp_segment
from backend.domain.pcap.layers import SERVICES
from backend.domain.pcap.reader import Packet

MAX_STEPS = 16
_SYN, _FIN, _RST, _ACK = 0x02, 0x01, 0x04, 0x10
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")


def _looks_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] in (0x14, 0x15, 0x16, 0x17) and data[1] == 3 and data[2] <= 4


class _Tcp:
    """Recorre los paquetes de una sesión TCP y anota qué pasó (pasos, banderas vistas, volumen)."""

    def __init__(self, session) -> None:
        self.session = session
        self.steps: List[Dict[str, Any]] = []
        self.syn = self.synack = self.established = False
        self.fin = self.rst = 0
        self.keepalive = 0
        self.first_data: Optional[bytes] = None
        self.bytes = {"origen": 0, "destino": 0}
        self.packets = 0
        self._group: Optional[Dict[str, Any]] = None
        self._syn_sender: Optional[str] = None

    def _who(self, ip: str, port: int) -> str:
        return "origen" if (ip, port) == (self.session.src_ip, self.session.src_port) else "destino"

    def _step(self, who: str, label: str, detail: str, index: int, ts: float) -> None:
        self._flush()
        self.steps.append({"who": who, "label": label, "detail": detail, "packet": index, "ts": ts})

    def _flush(self) -> None:
        g, self._group = self._group, None
        if g is not None:
            self.steps.append({
                "who": g["who"], "label": "Datos", "packet": g["packet"], "ts": g["ts"],
                "detail": f"Envía {g['bytes']:,} B en {g['count']} paquete(s)".replace(",", "."),
            })

    def _data(self, who: str, size: int, index: int, ts: float) -> None:
        if self._group is not None and self._group["who"] == who:
            self._group["bytes"] += size
            self._group["count"] += 1
        else:
            self._flush()
            self._group = {"who": who, "bytes": size, "count": 1, "packet": index, "ts": ts}

    def feed(self, index: int, pkt: Packet) -> None:
        seg = _tcp_segment(pkt)
        if seg is None:
            return
        ip, port, _seq, flags, data = seg
        who = self._who(ip, port)
        self.packets += 1
        if flags & _SYN and not flags & _ACK:
            self.syn, self._syn_sender = True, who
            self._step(who, "SYN", "Pide abrir la conexión («¿hablamos?»)", index, pkt.ts)
        elif flags & _SYN:
            self.synack = True
            self._step(who, "SYN+ACK", "Acepta («sí, hablemos»)", index, pkt.ts)
        elif flags & _RST:
            self.rst += 1
            self._step(who, "RST", "Corta la conexión de golpe", index, pkt.ts)
        elif flags & _FIN:
            self.fin += 1
            self._step(who, "FIN", "Cierra la conexión con educación", index, pkt.ts)
        elif data:
            self._on_data(who, data, index, pkt.ts)
        elif self.synack and not self.established and who == self._syn_sender:
            self.established = True
            self._step(who, "ACK", "Confirma: la conexión queda abierta (fin del saludo de 3 pasos)", index, pkt.ts)

    def _on_data(self, who: str, data: bytes, index: int, ts: float) -> None:
        if self.first_data is None:
            self.first_data = data
        if len(data) == 1:
            self.keepalive += 1  # un solo byte repetido suele ser un keep-alive
        self.bytes[who] += len(data)
        self._data(who, len(data), index, ts)

    def finish(self) -> None:
        self._flush()
        if len(self.steps) > MAX_STEPS:
            hidden = len(self.steps) - MAX_STEPS
            self.steps = self.steps[:MAX_STEPS] + [{"who": "ambos", "label": "…", "detail": f"y {hidden} paso(s) más", "packet": None, "ts": None}]


def _label(ip: str, name: Optional[str]) -> str:
    return f"{name} ({ip})" if name else ip


def _labels(session, names) -> tuple:
    """(origen, destino) con el nombre del sitio pegado al SERVIDOR, que no siempre es el destino."""
    name = names.best_name(session) if names else None
    src_is_server = _server_is_src(session)
    return _label(session.src_ip, name if src_is_server else None), _label(session.dst_ip, None if src_is_server else name)


def _outcome(t: _Tcp) -> str:
    if t.rst and not t.established and t.syn:
        return "rechazada"
    if t.syn and not t.synack:
        return "sin_respuesta"
    if t.established or t.synack:
        return "cortada" if t.rst else ("cerrada" if t.fin else "abierta")
    return "en_curso"


_OUTCOME_TEXT = {
    "rechazada": "Intentó conectarse y el otro lado lo rechazó (RST): lo más probable es que ese puerto esté cerrado.",
    "sin_respuesta": "Intentó conectarse y nadie respondió: el equipo puede estar apagado o un firewall descartó el tráfico.",
    "cortada": "La conexión se abrió bien, pero alguno de los dos la cortó de golpe (RST).",
    "cerrada": "La conexión se abrió bien (saludo de 3 pasos) y se cerró con normalidad.",
    "abierta": "La conexión se abrió bien y, hasta donde llega la captura, sigue abierta.",
    "en_curso": "La captura empezó con la conversación ya en curso, así que no se ve cómo comenzó (el «origen» puede no ser quien la inició).",
}


def _content_sentence(t: _Tcp) -> Optional[str]:
    first = t.first_data
    if first is None:
        return None
    if _looks_tls(first):
        return "El contenido va cifrado (TLS): se ven los metadatos, no lo que se dijeron."
    if first.startswith(_HTTP_METHODS):
        return "Es HTTP sin cifrar: podés leer todo en «Conversación»."
    return None


def _service(session) -> str:
    port = min(p for p in (session.src_port, session.dst_port) if p is not None) if session.dst_port is not None else None
    for p in (session.dst_port, session.src_port):
        if p in SERVICES:
            return f"{SERVICES[p]} (puerto {p})"
    return f"puerto {port}" if port is not None else "sin puerto"


def _is_single_probe(t: _Tcp) -> bool:
    """Una sesión de pocos paquetes cuyo ÚNICO dato es 1 byte 00, sin saludo ni cierre."""
    return (
        t.keepalive == 1 and t.first_data == b"\x00" and t.bytes["origen"] + t.bytes["destino"] == 1
        and t.packets <= 3 and not (t.syn or t.synack or t.fin or t.rst)
    )


def _summary_tcp(session, t: _Tcp, names, process) -> List[str]:
    src, dst = _labels(session, names)
    sentences = [f"{src} habló con {dst} por TCP, servicio {_service(session)}.", _OUTCOME_TEXT[_outcome(t)]]
    if t.bytes["origen"] or t.bytes["destino"]:
        sentences.append(f"Se intercambiaron {t.packets} paquetes: {t.bytes['origen']:,} B del origen y {t.bytes['destino']:,} B del destino.".replace(",", "."))
    if t.keepalive >= 2:
        sentences.append("Los paquetes de 1 byte repetidos son un keep-alive: el programa pregunta «¿seguís ahí?» para mantener viva la conexión. No es un ataque.")
    elif _is_single_probe(t):
        sentences.append(
            "Probable keep-alive: un único byte sin sentido (00) y una confirmación vacía de vuelta. "
            "El sistema comprueba que la conexión sigue viva; no es contenido ni un ataque. "
            "Es una conclusión por la forma del paquete: como la captura no muestra paquetes anteriores, no se puede confirmar del todo."
        )
    content = _content_sentence(t)
    if content:
        sentences.append(content)
    if process:
        sentences.append(f"El programa dueño de esta conexión es {process['name']} (PID {process['pid']}).")
    return sentences


def _summary_other(session, packets: int, names, process) -> List[str]:
    src, dst = _labels(session, names)
    if session.protocol == "UDP":
        sentences = [
            f"{src} le mandó datagramas a {dst} por UDP, servicio {_service(session)}.",
            "UDP no abre una conexión: manda y no espera confirmación. Por eso no hay saludo ni cierre.",
            f"Hubo {packets} paquete(s) en total.",
        ]
        if session.dst_port == 53 or session.src_port == 53:
            sentences.append("Es DNS: alguien pregunta por un nombre y espera su dirección IP.")
    elif session.protocol.startswith("ICMP"):
        sentences = [f"{src} y {dst} intercambiaron mensajes de control ({session.protocol}), como un «ping». Hubo {packets} paquete(s)."]
    else:
        sentences = [f"{src} y {dst} intercambiaron {packets} paquete(s) de {session.protocol}."]
    if process:
        sentences.append(f"El programa dueño es {process['name']} (PID {process['pid']}).")
    return sentences


def explain_session(session, packets: Iterable[Packet], names=None, process: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resumen en frases y pasos de la conexión de `session`, a partir de SUS paquetes."""
    packets = list(packets)
    if session.protocol != "TCP":
        return {"protocol": session.protocol, "outcome": None, "summary": _summary_other(session, len(packets), names, process), "steps": []}
    t = _Tcp(session)
    for i, pkt in enumerate(packets):
        t.feed(i, pkt)
    t.finish()
    return {"protocol": "TCP", "outcome": _outcome(t), "summary": _summary_tcp(session, t, names, process), "steps": t.steps}
