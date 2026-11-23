"""Tests de backend/domain/pcap/hexdump.py."""
import pytest

from backend.domain.pcap.hexdump import hexdump


def test_vacio():
    assert hexdump(b"") == ""


def test_un_byte_formato_exacto():
    assert hexdump(b"A") == "00000000  41" + " " * 45 + "  |A|"


def test_16_bytes_formato_exacto():
    d = bytes(range(0x41, 0x51))
    esperado = "00000000  " + " ".join(f"{b:02x}" for b in d) + "  |ABCDEFGHIJKLMNOP|"
    assert hexdump(d) == esperado


def test_15_bytes_una_linea_alineada():
    out = hexdump(b"A" * 15)
    assert "\n" not in out
    assert len(out.split("|")[0]) == len(hexdump(b"A" * 16).split("|")[0])


def test_17_bytes_dos_lineas():
    out = hexdump(b"A" * 17).split("\n")
    assert len(out) == 2
    assert out[1].startswith("00000010  41 ")
    assert out[1].endswith("|A|")


def test_32_bytes_dos_lineas():
    out = hexdump(bytes(32)).split("\n")
    assert [l[:8] for l in out] == ["00000000", "00000010"]


def test_columna_ascii_alineada_en_ultima_linea():
    lines = hexdump(b"x" * 20).split("\n")
    assert lines[0].index("|") == lines[1].index("|")


def test_no_imprimibles_son_punto():
    assert hexdump(b"\x00\x01\x1f\x80\xff").endswith("|.....|")


def test_bordes_ascii():
    assert hexdump(b"\x7f").endswith("|.|")
    assert hexdump(b" ").endswith("| |")
    assert hexdump(b"~").endswith("|~|")
    assert hexdump(b"\x1f").endswith("|.|")


def test_width_8():
    out = hexdump(b"ABCDEFGHI", width=8).split("\n")
    assert out[0] == "00000000  41 42 43 44 45 46 47 48  |ABCDEFGH|"
    assert out[1] == "00000008  49" + " " * 21 + "  |I|"


def test_width_1():
    assert hexdump(b"AB", width=1) == "00000000  41  |A|\n00000001  42  |B|"


@pytest.mark.parametrize("w", [0, -1, True, "16", 2.5, None])
def test_width_invalido(w):
    with pytest.raises(ValueError):
        hexdump(b"abc", width=w)


def test_acepta_bytearray_y_memoryview():
    ref = hexdump(b"hola mundo")
    assert hexdump(bytearray(b"hola mundo")) == ref
    assert hexdump(memoryview(b"hola mundo")) == ref


def test_un_mega():
    out = hexdump(b"\xab" * (1024 * 1024))
    assert out.count("\n") + 1 == 65536
    assert out.rsplit("\n", 1)[1].startswith("000ffff0")
