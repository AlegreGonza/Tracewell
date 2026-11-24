"""Tests del arnés: comparación, métricas y manifiesto."""
from pathlib import Path

import pytest

from validacion.validar import (
    Entrada, Esperada, ManifiestoError, Obtenida, Resultado, cargar_manifiesto, comparar,
    detalle_markdown, informe, metricas, tabla_markdown,
)

A = Obtenida("port_scan", "1.1.1.1", "2.2.2.2")


def test_acierto_exacto():
    tp, fp, fn = comparar([Esperada("port_scan", "1.1.1.1", "2.2.2.2")], [A])
    assert len(tp) == 1 and not fp and not fn


def test_comodin_en_origen_y_destino():
    tp, fp, fn = comparar([Esperada("port_scan")], [A])
    assert len(tp) == 1 and not fp and not fn


def test_falso_positivo_y_negativo():
    tp, fp, fn = comparar([Esperada("syn_flood")], [A])
    assert not tp and fp == [A] and fn == [Esperada("syn_flood")]


def test_origen_distinto_no_coincide():
    tp, fp, fn = comparar([Esperada("port_scan", "9.9.9.9")], [A])
    assert not tp and len(fp) == 1 and len(fn) == 1


def test_una_esperada_consume_una_sola_obtenida():
    otra = Obtenida("port_scan", "3.3.3.3", "2.2.2.2")
    tp, fp, fn = comparar([Esperada("port_scan")], [A, otra])
    assert len(tp) == 1 and fp == [otra] and not fn


def test_trafico_benigno_sin_alertas():
    assert comparar([], []) == ([], [], [])


def _res(tp=0, fp=0, fn=0, regla="port_scan"):
    r = Resultado(Entrada("x", Path("x.pcap"), "", []))
    r.tp = [(Esperada(regla), A)] * tp
    r.fp = [Obtenida(regla, "a", "b")] * fp
    r.fn = [Esperada(regla)] * fn
    return r


def test_metricas_precision_y_recall():
    t = metricas([_res(tp=3, fp=1, fn=2)], ["port_scan", "syn_flood"])
    assert t["port_scan"]["precision"] == pytest.approx(0.75)
    assert t["port_scan"]["recall"] == pytest.approx(0.6)


def test_metricas_sin_datos_es_none():
    t = metricas([], ["syn_flood"])
    assert t["syn_flood"]["precision"] is None and t["syn_flood"]["recall"] is None


def test_metricas_suman_entre_pcaps():
    t = metricas([_res(tp=1), _res(fp=2), _res(fn=1)], ["port_scan"])
    assert (t["port_scan"]["tp"], t["port_scan"]["fp"], t["port_scan"]["fn"]) == (1, 2, 1)


def test_tabla_y_detalle():
    res = [_res(tp=1, fp=1, fn=1)]
    tabla = tabla_markdown(metricas(res, ["port_scan"]))
    assert "| `port_scan` | 1 | 1 | 1 | 50% | 50% |" in tabla and "**Total**" in tabla
    assert "FP en `x`" in detalle_markdown(res) and "FN en `x`" in detalle_markdown(res)
    assert "Sin fallos" in detalle_markdown([_res(tp=1)])
    assert "## Métricas por regla" in informe(res, ["port_scan"])


def _manifiesto(tmp_path, texto):
    ruta = tmp_path / "m.yaml"
    ruta.write_text(texto, encoding="utf-8")
    return ruta


def test_manifiesto_valido(tmp_path):
    ruta = _manifiesto(tmp_path, (
        "pcaps:\n  - {id: a, ruta: a.pcap, esperadas: ninguna}\n"
        "  - {id: b, ruta: /abs/b.pcap, esperadas: [{regla: port_scan, origen: 1.1.1.1}]}\n"))
    a, b = cargar_manifiesto(ruta, ["port_scan"])
    assert a.esperadas == [] and a.ruta == tmp_path / "a.pcap"
    assert b.esperadas == [Esperada("port_scan", "1.1.1.1")]


@pytest.mark.parametrize("texto", [
    "otra: 1\n",
    "pcaps:\n  - {ruta: a.pcap}\n",
    "pcaps:\n  - {id: a, ruta: a.pcap}\n  - {id: a, ruta: b.pcap}\n",
    "pcaps:\n  - {id: a, ruta: a.pcap, esperadas: [{regla: inexistente}]}\n",
    "pcaps:\n  - {id: a, ruta: a.pcap, esperadas: [{regla: port_scan, puerto: 1}]}\n",
    "pcaps:\n  - {id: a, ruta: a.pcap, esperadas: 5}\n",
])
def test_manifiesto_invalido(tmp_path, texto):
    with pytest.raises(ManifiestoError):
        cargar_manifiesto(_manifiesto(tmp_path, texto), ["port_scan"])
