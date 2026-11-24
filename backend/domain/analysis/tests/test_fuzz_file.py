"""Fuzz a nivel de ARCHIVO: pcap/pcapng mutados por lector, agrupador, reglas e índice de offsets."""
import random
import time

import pytest

from backend.domain.analysis.tests import fuzz_file_support as ff

LIMITE = 5.0  # segundos por entrada: un archivo hostil no puede colgar el análisis
SEEDS = ff.seeds()
PEQUENOS = [k for k in SEEDS if k != "demo"]


def correr(data, tmp_path):
    t0 = time.perf_counter()
    resultado = ff.analyze_bytes(data, tmp_path)
    assert time.perf_counter() - t0 < LIMITE, "una entrada tardó demasiado"
    return resultado


@pytest.mark.parametrize("nombre", sorted(SEEDS))
def test_las_semillas_validas_se_analizan(nombre, tmp_path):
    assert correr(SEEDS[nombre], tmp_path) == "ok"


@pytest.mark.parametrize("nombre", PEQUENOS)
def test_truncado_en_cada_byte_de_las_cabeceras_y_al_azar(nombre, tmp_path):
    rng = random.Random(11)
    for corte in ff.truncations(SEEDS[nombre], rng):
        correr(corte, tmp_path)


@pytest.mark.parametrize("nombre", PEQUENOS)
def test_cada_byte_de_las_cabeceras_con_valores_extremos(nombre, tmp_path):
    for variante in ff.header_variants(SEEDS[nombre]):
        correr(variante, tmp_path)


@pytest.mark.parametrize("seed", [1, 2])
@pytest.mark.parametrize("nombre", sorted(SEEDS))
def test_mutaciones_al_azar(nombre, seed, tmp_path):
    rng = random.Random(seed)
    for _ in range(15):
        correr(ff.mutate(rng, SEEDS[nombre]), tmp_path)


def test_archivo_grande_mutado_cruza_los_puntos_del_indice(tmp_path):
    rng = random.Random(5)
    grande = ff.big_pcap()
    assert correr(grande, tmp_path) == "ok"
    for _ in range(6):
        correr(ff.mutate(rng, grande), tmp_path)
    for corte in (len(grande) // 2, len(grande) - 7, len(grande) - 1):
        correr(grande[:corte], tmp_path)


@pytest.mark.parametrize("campo,valor", [
    ("incl_len", 0xFFFFFFFF), ("incl_len", 0x7FFFFFFF), ("incl_len", 0), ("orig_len", 0xFFFFFFFF),
    ("linktype", 0), ("linktype", 113), ("linktype", 0xFFFFFFFF), ("snaplen", 0), ("snaplen", 0xFFFFFFFF),
])
def test_campos_de_cabecera_mentirosos_en_pcap(campo, valor, tmp_path):
    import struct
    data = bytearray(SEEDS["pcap_le"])
    pos = {"snaplen": (16, "<I"), "linktype": (20, "<I"), "incl_len": (24 + 8, "<I"), "orig_len": (24 + 12, "<I")}[campo]
    data[pos[0]:pos[0] + 4] = struct.pack(pos[1], valor)
    correr(bytes(data), tmp_path)


@pytest.mark.parametrize("largo", [0, 1, 4, 8, 11, 12, 13, 0xFFFFFFFF, 0x7FFFFFFF])
def test_longitud_de_bloque_mentirosa_en_pcapng(largo, tmp_path):
    import struct
    data = bytearray(SEEDS["pcapng"])
    for bloque in (0, 28, 28 + 20):  # SHB, IDB y el primer EPB empiezan acá
        copia = bytearray(data)
        if bloque + 8 <= len(copia):
            copia[bloque + 4:bloque + 8] = struct.pack("<I", largo)
        correr(bytes(copia), tmp_path)


@pytest.mark.parametrize("basura", [b"", b"\x00", b"\xff" * 3, b"\x0a\x0d\x0d\x0a", b"\xd4\xc3\xb2\xa1",
                                    bytes(100_000), b"\xd4\xc3\xb2\xa1" + b"\xff" * 5000])
def test_basura_y_archivos_casi_vacios(basura, tmp_path):
    correr(basura, tmp_path)
