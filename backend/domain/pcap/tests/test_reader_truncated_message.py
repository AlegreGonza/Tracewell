"""Mensaje de "captura truncada": nunca queda con el motivo vacío."""
import contextlib
import struct

import dpkt
import pytest

from backend.domain.pcap import reader
from backend.domain.pcap.reader import PcapError, _truncated_detail, iter_packets

DEFAULT = "el archivo termina antes de lo esperado"


def _fake_open(exc):
    class R:
        def __iter__(self):
            raise exc
            yield  # pragma: no cover

    @contextlib.contextmanager
    def fake(path):
        yield None, R(), None

    return fake


@pytest.mark.parametrize("texto", ["", "   ", "\n\t "])
def test_detail_vacio_usa_texto_por_defecto(texto):
    # texto vacío o solo espacios -> motivo por defecto
    assert _truncated_detail(dpkt.NeedData(texto)) == DEFAULT


def test_detail_sin_args():
    # NeedData() sin argumentos -> str vacío -> motivo por defecto
    assert _truncated_detail(dpkt.NeedData()) == DEFAULT


def test_detail_str_none_literal_se_conserva():
    # NeedData(None): str() da "None", que no es vacío (comportamiento real: se conserva)
    assert _truncated_detail(dpkt.NeedData(None)) == "None"


def test_detail_texto_normal_y_strip():
    # texto normal se conserva y se recortan espacios
    assert _truncated_detail(dpkt.NeedData("got 12, 32 needed")) == "got 12, 32 needed"
    assert _truncated_detail(dpkt.NeedData("  x  ")) == "x"


def test_iter_packets_needdata_sin_mensaje(monkeypatch):
    # NeedData vacío -> "captura truncada: <default>", sin ": " colgando
    monkeypatch.setattr(reader, "_open", _fake_open(dpkt.NeedData()))
    with pytest.raises(PcapError) as e:
        list(iter_packets("x"))
    assert str(e.value) == f"captura truncada: {DEFAULT}"
    assert not str(e.value).endswith(": ")


def test_iter_packets_needdata_con_mensaje(monkeypatch):
    # el mensaje de dpkt se conserva y el prefijo no cambia
    monkeypatch.setattr(reader, "_open", _fake_open(dpkt.NeedData("got 12, 32 needed")))
    with pytest.raises(PcapError) as e:
        list(iter_packets("x"))
    assert str(e.value) == "captura truncada: got 12, 32 needed"
    assert isinstance(e.value.__cause__, dpkt.NeedData)


def test_pcap_real_cortado_en_cabecera_de_paquete(tmp_path):
    # pcap real con cabecera de paquete cortada: prefijo y motivo no vacío
    p = tmp_path / "cut.pcap"
    p.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"\x01\x02\x03\x04\x05")
    with pytest.raises(PcapError) as e:
        list(iter_packets(p))
    msg = str(e.value)
    assert msg.startswith("captura truncada") and msg.split(":", 1)[1].strip()
