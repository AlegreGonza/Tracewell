"""Escaneo reanudable de los paquetes de una sesión: páginas siguientes sin releer el pcap."""
from __future__ import annotations

import threading
from array import array
from collections import OrderedDict
from typing import List, Tuple

from backend.domain.pcap.reader import file_signature, iter_indexed
from backend.domain.sessions.grouper import packet_session_key

MAX_SCAN_PACKETS = 500_000  # por sesión (~24 B c/u => ~12 MB); más allá se relee el archivo
MAX_SCANS = 4  # sesiones con escaneo guardado a la vez
_NO_ORIGLEN = -1  # origlen desconocido (pcapng)


class SessionScan:
    """Resumen (índice, ts, largo, origlen) de los paquetes de UNA sesión leídos hasta ahora."""

    def __init__(self, path, key, signature):
        self.path, self.key, self.signature = path, key, signature
        self.indices = array("I")
        self.ts = array("d")
        self.caplen = array("I")
        self.origlen = array("q")
        self.done = False  # se llegó al final del archivo
        self._next_index = 0  # por dónde seguir: índice y posición del próximo paquete
        self._next_pos = None
        self.lock = threading.Lock()

    def __len__(self) -> int:
        return len(self.indices)

    def covers(self, wanted: int) -> bool:
        """True si ya se puede responder una página que necesita `wanted` paquetes."""
        return self.done or len(self) >= wanted

    def fill(self, wanted: int) -> None:
        """Sigue leyendo el archivo hasta tener `wanted` paquetes de la sesión (o el tope/fin)."""
        wanted = min(wanted, MAX_SCAN_PACKETS)
        with self.lock:
            if self.done or len(self) >= wanted:
                return
            for i, pos, pkt in iter_indexed(self.path, self._next_index, self._next_pos):
                self._next_index, self._next_pos = i + 1, pos
                if packet_session_key(pkt) != self.key:
                    continue
                self.indices.append(i)
                self.ts.append(pkt.ts)
                self.caplen.append(len(pkt.data))
                self.origlen.append(_NO_ORIGLEN if pkt.origlen is None else pkt.origlen)
                if len(self) >= wanted:
                    return
            self.done = True

    def page(self, offset: int, limit: int) -> Tuple[List[tuple], bool]:
        """([(índice, ts, caplen, origlen o None)], hay_más) de las filas offset..offset+limit."""
        end = min(offset + limit, len(self))
        rows = [
            (self.indices[n], self.ts[n], self.caplen[n], None if self.origlen[n] == _NO_ORIGLEN else self.origlen[n])
            for n in range(offset, end)
        ]
        return rows, len(self) > offset + limit


class ScanCache:
    """LRU chica de escaneos por sesión; uno de un archivo que cambió se descarta."""

    def __init__(self, maxsize: int = MAX_SCANS):
        self._maxsize = maxsize
        self._items: "OrderedDict[tuple, SessionScan]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, path, key) -> SessionScan:
        """Escaneo de la sesión `key` del archivo `path` (nuevo si no hay o si el archivo cambió)."""
        signature = file_signature(path)
        with self._lock:
            scan = self._items.get(key)
            if scan is None or scan.signature != signature:
                scan = self._items[key] = SessionScan(path, key, signature)
            self._items.move_to_end(key)
            while len(self._items) > self._maxsize:
                self._items.popitem(last=False)
            return scan
