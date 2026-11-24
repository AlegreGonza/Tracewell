"""Tests del constructor de reglas (builder): validación, YAML generado, vista previa y guardado."""
import shutil
from pathlib import Path

import pytest
import yaml

from backend.domain.rules import builder
from backend.domain.rules.builder import EXAMPLE, RuleExists, RuleForm
from backend.domain.rules.engine import RuleError, load_rules
from backend.domain.rules.tests.test_brute_force import ATTACKER, VICTIM, attempts, write_pcap
from backend.domain.pcap.reader import iter_packets
from backend.domain.sessions.grouper import group_packets

ROOT = Path(__file__).resolve().parents[4]


def form(**over):
    return RuleForm(**{**EXAMPLE, **over})


def test_el_ejemplo_genera_una_regla_valida():
    data = builder.to_dict(form())
    rule = builder.build_rule(data)
    assert rule.id == "muchos_syn_hacia_la_red_interna" and rule.detector == "threshold"
    assert rule.params["port"] == 0 and rule.params["dst_ip"] == "192.168.0.0/16"


def test_el_yaml_generado_se_lee_igual_y_carga_con_el_motor(tmp_path):
    data = builder.to_dict(form(description="Una descripción: con dos puntos y # numeral."))
    text = builder.render_yaml(data)
    assert yaml.safe_load(text) == data  # lo que se muestra es exactamente lo que se guarda
    f = tmp_path / "r.yaml"
    f.write_text(text, encoding="utf-8")
    (rule,) = load_rules(f)
    assert rule.name == data["name"] and rule.severity == "medium"


def test_mismo_formato_que_las_reglas_del_repo():
    text = builder.render_yaml(builder.to_dict(form()))
    head = [row.split(":")[0] for row in text.splitlines() if not row.startswith(" ")]
    assert head == ["id", "name", "description", "severity", "detector", "mitre", "params"]
    repo_head = [row.split(":")[0] for row in (ROOT / "rules" / "port_scan.yaml").read_text(encoding="utf-8").splitlines()
                 if row and not row.startswith((" ", "#"))][:7]
    assert head == repo_head


@pytest.mark.parametrize("over", [
    {"name": ""}, {"name": "x" * 81}, {"severity": "urgente"}, {"id": "Mal Id"}, {"id": "../hack"},
    {"protocol": "icmp"}, {"src_ip": "no-ip"}, {"port": 70000}, {"min_events": 1}, {"window_seconds": 0},
    {"description": "d" * 501},
])
def test_formularios_invalidos_fallan_con_rule_error(over):
    with pytest.raises(RuleError):
        builder.build_rule(builder.to_dict(form(**over)))


def test_el_id_se_arma_del_nombre_sin_tildes():
    assert builder.slugify("Conexión rara à Ñandú!") == "conexion_rara_a_nandu"
    assert builder.slugify("123") == "regla_123"


def test_texto_hostil_no_rompe_el_yaml():
    data = builder.to_dict(form(name="x: [y] {z} # w - q", description="a: b\n\nc: d"))
    assert yaml.safe_load(builder.render_yaml(data)) == data


def test_nombre_con_salto_de_linea_o_nul_se_rechaza():
    # lo que antes llegaba al YAML ahora ni entra (los caracteres de control se rechazan)
    for name in ("x\n- q", "a\x00b", "a\rb", "a\x1bb"):
        with pytest.raises(RuleError, match="control"):
            builder.to_dict(form(name=name))


def test_id_con_salto_de_linea_final_se_rechaza():
    with pytest.raises(RuleError, match="el id debe empezar"):
        builder.to_dict(form(id="regla\n"))
    assert builder.to_dict(form(id="regla"))["id"] == "regla"


def test_nombre_largo_y_limite_unico():
    assert builder.to_dict(form(name="n" * builder.MAX_NAME))["name"] == "n" * builder.MAX_NAME
    with pytest.raises(RuleError, match=f"hasta {builder.MAX_NAME} caracteres"):
        builder.to_dict(form(name="n" * (builder.MAX_NAME + 1)))


def test_vista_previa_cuenta_sesiones_y_alertas(tmp_path):
    pcap = write_pcap(tmp_path / "t.pcap", attempts(10))
    rule = builder.build_rule(builder.to_dict(form(dst_ip="10.0.0.0/24", min_events=5, port=22)))
    result = group_packets(iter_packets(pcap), 1)
    out = builder.preview(rule, iter_packets(pcap), result.sessions)
    assert out["alerts"] == 1 and out["sessions"] == 10
    assert out["sample"][0]["src_ip"] == ATTACKER and out["sample"][0]["dst_ip"] == VICTIM


def test_vista_previa_sin_coincidencias(tmp_path):
    pcap = write_pcap(tmp_path / "t.pcap", attempts(10))
    rule = builder.build_rule(builder.to_dict(form(dst_ip="192.168.0.0/16")))
    out = builder.preview(rule, iter_packets(pcap), group_packets(iter_packets(pcap), 1).sessions)
    assert out == {"sessions": 0, "alerts": 0, "sample": []}


def test_guardar_crea_el_archivo_y_no_pisa_nada(tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    before = {p.name: p.read_bytes() for p in rules.glob("*.yaml")}
    data = builder.to_dict(form())
    path = builder.save(rules, data, [r.id for r in load_rules(rules)])
    assert path.name == f"{data['id']}.yaml" and len(load_rules(rules)) == len(before) + 1
    assert all((rules / n).read_bytes() == b for n, b in before.items())  # las existentes quedan intactas
    with pytest.raises(RuleExists):
        builder.save(rules, data, [])  # mismo archivo
    with pytest.raises(RuleExists):
        builder.save(rules, data, [data["id"]])  # mismo id


def test_no_se_puede_pisar_una_regla_existente(tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", rules)
    original = (rules / "port_scan.yaml").read_bytes()
    data = builder.to_dict(form(id="port_scan"))
    with pytest.raises(RuleExists):
        builder.save(rules, data, [r.id for r in load_rules(rules)])
    assert (rules / "port_scan.yaml").read_bytes() == original


def test_id_reservado_de_windows_se_rechaza():
    import pytest
    from backend.domain.rules.builder import RuleError, RuleForm, to_dict
    for reservado in ("con", "nul", "com1", "lpt9"):
        with pytest.raises(RuleError):
            to_dict(RuleForm(id=reservado, name="Prueba", severity="low"))


@pytest.mark.parametrize("over", [
    {"description": "!!python/object/apply:os.system ['calc']"},
    {"description": "&a [*a]"},
    {"name": "x\nseverity: critical"},
    {"description": "a\r\nid: pwn"},
    {"src_ip": "1.2.3.4\nport: 1"},
    {"src_ip": "999.1.1.1"},
    {"dst_ip": "10.0.0.0/99"},
    {"port": -1}, {"port": 70000}, {"min_events": 0}, {"min_events": -5},
    {"window_seconds": float("nan")}, {"window_seconds": float("inf")}, {"window_seconds": -1},
    {"protocol": "tcp: {a: b}"}, {"severity": "critical\nx: y"},
])
def test_entradas_hostiles_se_rechazan_o_viajan_como_dato(over):
    try:
        data = builder.to_dict(form(**over))
        builder.build_rule(data)  # el motor valida los parámetros
    except RuleError:
        return
    text = builder.render_yaml(data)
    assert yaml.safe_load(text) == data and "!!" not in text.replace(over.get("description", ""), "")
