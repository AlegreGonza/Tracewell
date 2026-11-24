"""Carpeta de reglas del usuario: carga combinada, creación y errores de escritura."""
import logging
from pathlib import Path

import pytest

from backend.domain.rules import paths
from backend.domain.rules.engine import RuleError, load_all_rules, load_rules
from backend.domain.rules.paths import ENV_USER_RULES_DIR, default_user_rules_dir

ROOT = Path(__file__).resolve().parents[4]


def yaml_de(rule_id, name="x"):
    return "\n".join([
        f"id: {rule_id}", f"name: {name}", "severity: low", "detector: threshold",
        "mitre: {technique: T1046, name: Prueba, tactic: Discovery}",
        "params: {protocol: tcp, port: 0, src_ip: '', dst_ip: '', min_events: 5, window_seconds: 60}", "",
    ])


def test_carga_las_incluidas_mas_las_del_usuario(tmp_path):
    (tmp_path / "mia.yaml").write_text(yaml_de("mia"), encoding="utf-8")
    ids = {r.id for r in load_all_rules(ROOT / "rules", tmp_path)}
    assert "mia" in ids and {r.id for r in load_rules(ROOT / "rules")} <= ids


def test_carpeta_de_usuario_inexistente_no_rompe(tmp_path):
    base = [r.id for r in load_rules(ROOT / "rules")]
    assert [r.id for r in load_all_rules(ROOT / "rules", tmp_path / "nada")] == base
    assert [r.id for r in load_all_rules(ROOT / "rules")] == base


def test_id_duplicado_de_una_incluida_se_ignora_con_aviso(tmp_path, caplog):
    (tmp_path / "pisa.yaml").write_text(yaml_de("port_scan", "falsa"), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        rules = load_all_rules(ROOT / "rules", tmp_path)
    assert [r.name for r in rules if r.id == "port_scan"] != ["falsa"]
    assert sum(r.id == "port_scan" for r in rules) == 1
    assert "port_scan" in caplog.text and "ignorada" in caplog.text


def test_duplicado_entre_archivos_de_usuario_gana_el_primero(tmp_path):
    (tmp_path / "a.yaml").write_text(yaml_de("dup", "primera"), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(yaml_de("dup", "segunda"), encoding="utf-8")
    assert [r.name for r in load_all_rules(ROOT / "rules", tmp_path) if r.id == "dup"] == ["primera"]


def test_archivo_roto_del_usuario_se_ignora(tmp_path, caplog):
    (tmp_path / "rota.yaml").write_text("id: [sin cerrar\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        rules = load_all_rules(ROOT / "rules", tmp_path)
    assert len(rules) == len(load_rules(ROOT / "rules")) and "rota.yaml" in caplog.text


def test_las_incluidas_rotas_siguen_fallando(tmp_path):
    malas = tmp_path / "inc"
    malas.mkdir()
    (malas / "m.yaml").write_text("id: [x\n", encoding="utf-8")
    with pytest.raises(RuleError):
        load_all_rules(malas, tmp_path)


def test_carpeta_por_defecto_en_windows_y_otros(monkeypatch, tmp_path):
    monkeypatch.delenv(ENV_USER_RULES_DIR, raising=False)
    monkeypatch.setattr(paths, "_is_windows", lambda: True)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert default_user_rules_dir() == tmp_path / "Tracewell" / "rules"
    monkeypatch.setattr(paths, "_is_windows", lambda: False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert default_user_rules_dir() == tmp_path / "tracewell" / "rules"


def test_la_variable_de_entorno_manda(monkeypatch, tmp_path):
    monkeypatch.setenv(ENV_USER_RULES_DIR, str(tmp_path / "x"))
    assert default_user_rules_dir() == tmp_path / "x"
