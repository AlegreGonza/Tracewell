"""Campos explicativos opcionales de las reglas YAML: false_positives, investigation_steps, wireshark_filter."""
from pathlib import Path

import pytest

from backend.domain.rules.engine import RuleError, load_rules
from backend.domain.rules.tests.test_engine import REAL_RULES, base, write_rule


def load_one(tmp_path, **over):
    return load_rules(write_rule(tmp_path, base(**over)))[0]


def test_regla_sin_campos_opcionales_sigue_valida_y_vacia(tmp_path):
    r = load_one(tmp_path)
    assert r.false_positives == () and r.investigation_steps == () and r.wireshark_filter == ""


def test_campos_validos_se_cargan_y_se_limpian(tmp_path):
    r = load_one(
        tmp_path,
        false_positives=["  Escáner autorizado ", "Monitoreo"],
        investigation_steps=["Ver sesiones"],
        wireshark_filter="  tcp.flags.syn==1 ",
    )
    assert r.false_positives == ("Escáner autorizado", "Monitoreo")
    assert r.investigation_steps == ("Ver sesiones",)
    assert r.wireshark_filter == "tcp.flags.syn==1"


def test_lista_vacia_es_valida(tmp_path):
    assert load_one(tmp_path, false_positives=[]).false_positives == ()


def test_clave_con_null_se_toma_como_ausente(tmp_path):
    r = load_one(tmp_path, false_positives=None, wireshark_filter=None)
    assert r.false_positives == () and r.wireshark_filter == ""


@pytest.mark.parametrize("key", ["false_positives", "investigation_steps"])
@pytest.mark.parametrize("bad", ["un texto suelto", 5, {"a": 1}, [1, 2], ["ok", ""], ["ok", "   "], [["anidada"]], [None]])
def test_listas_con_tipo_incorrecto_fallan(tmp_path, key, bad):
    with pytest.raises(RuleError, match=f"'{key}' debe ser una lista de textos no vacíos"):
        load_one(tmp_path, **{key: bad})


@pytest.mark.parametrize("bad", ["", "   ", 5, ["tcp"], {"a": 1}, True])
def test_wireshark_filter_con_tipo_incorrecto_falla(tmp_path, bad):
    with pytest.raises(RuleError, match="'wireshark_filter' debe ser texto no vacío"):
        load_one(tmp_path, wireshark_filter=bad)


@pytest.mark.parametrize("key", ["false_positive", "investigation_step", "wireshark", "falsepositives"])
def test_claves_desconocidas_siguen_fallando(tmp_path, key):
    with pytest.raises(RuleError, match="campos desconocidos"):
        load_one(tmp_path, **{key: ["x"]})


def test_el_error_nombra_el_archivo(tmp_path):
    with pytest.raises(RuleError, match="r.yaml"):
        load_one(tmp_path, false_positives="x")


def test_port_scan_de_ejemplo_trae_los_tres_campos():
    r = {x.id: x for x in load_rules(REAL_RULES)}["port_scan"]
    assert len(r.false_positives) >= 2 and len(r.investigation_steps) >= 3
    assert r.wireshark_filter == "tcp.flags.syn==1 && tcp.flags.ack==0"


def test_las_demas_reglas_reales_no_cambian():
    for r in load_rules(REAL_RULES):
        if r.id != "port_scan":
            assert (r.false_positives, r.investigation_steps, r.wireshark_filter) == ((), (), "")
