"""Tráfico a lo largo del tiempo: paquetes y bytes por intervalo, para dibujar un gráfico."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from backend.domain.pcap.reader import Packet

MAX_BINS = 120  # barras del gráfico
MAX_KEYS = 20_000  # intervalos finos que se guardan antes de volverlos más


@dataclass(frozen=True)
class Timeline:
    start: float  # instante (epoch, UTC) en que empieza la primera barra
    bucket_seconds: float  # duración de cada barra
    packets: List[int] = field(default_factory=list)
    bytes: List[int] = field(default_factory=list)


class TimelineCollector:
    def __init__(self) -> None:
        self._g = 1.0
        self._packets: Dict[int, int] = {}
        self._bytes: Dict[int, int] = {}

    def add(self, pkt: Packet) -> None:
        idx = int(pkt.ts // self._g)
        size = pkt.origlen if pkt.origlen is not None else len(pkt.data)
        self._packets[idx] = self._packets.get(idx, 0) + 1
        self._bytes[idx] = self._bytes.get(idx, 0) + size
        if len(self._packets) > MAX_KEYS:
            self._coarsen()

    def _coarsen(self) -> None:
        """Duplica el intervalo y fusiona: floor(ts / 2g) == floor(floor(ts / g) / 2)."""
        self._g *= 2
        packets: Dict[int, int] = {}
        sizes: Dict[int, int] = {}
        for idx, n in self._packets.items():
            packets[idx // 2] = packets.get(idx // 2, 0) + n
            sizes[idx // 2] = sizes.get(idx // 2, 0) + self._bytes[idx]
        self._packets, self._bytes = packets, sizes

    def result(self, max_bins: int = MAX_BINS) -> Optional[Timeline]:
        """La línea de tiempo en a lo sumo `max_bins` barras, o None si no hubo paquetes."""
        if not self._packets:
            return None
        first, last = min(self._packets), max(self._packets)
        factor = max(1, -(-(last - first + 1) // max_bins))  # techo de la división
        bins = (last - first) // factor + 1
        packets, sizes = [0] * bins, [0] * bins
        for idx, n in self._packets.items():
            b = (idx - first) // factor
            packets[b] += n
            sizes[b] += self._bytes[idx]
        return Timeline(start=first * self._g, bucket_seconds=self._g * factor, packets=packets, bytes=sizes)
