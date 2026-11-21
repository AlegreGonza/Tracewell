"""Volcado hexadecimal de bytes crudos, al estilo de Wireshark / `hexdump -C`."""
from __future__ import annotations


def _hex_line(off: int, chunk: bytes, width: int) -> str:
    """Una línea: offset | bytes en hex | ASCII imprimible."""
    hexes = " ".join(f"{b:02x}" for b in chunk)
    # Rellenamos a ancho fijo para que la columna ASCII quede alineada
    # aunque la última línea tenga menos bytes.
    hexes = hexes.ljust(width * 3 - 1)
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{off:08x}  {hexes}  |{text}|"


def hexdump(data: bytes, width: int = 16) -> str:
    """Una línea por `width` bytes: offset | bytes en hex | ASCII imprimible.

    Por qué el panel ASCII: el analista busca texto legible (un USER/PASS, un
    dominio) dentro de los bytes; los no imprimibles se muestran como '.'.
    """
    if not isinstance(width, int) or isinstance(width, bool) or width < 1:
        raise ValueError(f"width debe ser un entero positivo, recibí {width!r}")
    data = bytes(data)
    return "\n".join(
        _hex_line(off, data[off:off + width], width) for off in range(0, len(data), width)
    )
