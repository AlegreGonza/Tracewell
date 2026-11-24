"""Tests de las excepciones (allow_hosts / allow_services) y de los nombres MITRE canónicos."""
import re
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml

from backend.domain.rules.builder import DEFAULT_MITRE, RuleForm, build_rule, to_dict
from backend.domain.rules.engine import (
    MITRE_TACTICS, Allowlist, Decoded, RuleError, evaluate, load_all_rules, load_rules,
)
from backend.domain.rules.tests.test_engine import SYN, dns_pkt, tcp, udp

ROOT = Path(__file__).resolve().parents[4]
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def rule_file(tmp_path, detector="port_scan", params=None, mitre=None, name="r.yaml"):
    data = {"id": "r1", "name": "R", "description": "d", "severity": "high", "detector": detector,
            "mitre": mitre or {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}}
    if params is not None:
        data["params"] = params
    f = tmp_path / name
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    return f


def scan(src="10.0.0.1", dst="10.0.0.2", start=1.0):
    return [tcp(start + i * 0.1, src=src, dst=dst, dport=1000 + i, flags=SYN) for i in range(15)]


# ------------------------------------------------------------------ MITRE canónico

def test_las_tacticas_canonicas_y_su_orden():
    assert MITRE_TACTICS == (
        "Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    )


def test_todas_las_reglas_incluidas_llevan_tactica_y_tecnica_validas():
    rules = load_rules(ROOT / "rules")
    assert len(rules) == 16
    for r in rules:
        assert r.mitre_tactic in MITRE_TACTICS, r.id
        assert TECHNIQUE.match(r.mitre_technique), r.id
        assert r.mitre_name.strip(), r.id


@pytest.mark.parametrize("rule_id,technique,tactic", [
    ("brute_force_remote", "T1110", "Credential Access"),
    ("syn_flood", "T1498", "Impact"),
    ("port_scan", "T1046", "Discovery"),
    ("dns_suspicious", "T1071.004", "Command and Control"),
    ("large_upload", "T1048", "Exfiltration"),
    ("smb_rpc_lateral", "T1021", "Lateral Movement"),
    ("icmp_tunnel", "T1095", "Command and Control"),
    ("dga_nxdomain", "T1568.002", "Command and Control"),
])
def test_tecnica_y_tactica_de_reglas_clave(rule_id, technique, tactic):
    rule = next(r for r in load_rules(ROOT / "rules") if r.id == rule_id)
    assert (rule.mitre_technique, rule.mitre_tactic) == (technique, tactic)


def test_la_alerta_lleva_tactica_tecnica_y_nombre_con_los_campos_planos(tmp_path):
    f = rule_file(tmp_path)
    (a,) = evaluate(load_rules(f), scan())
    item = asdict(a)
    assert (item["mitre_tactic"], item["mitre_technique"], item["mitre_name"]) == (
        "Discovery", "T1046", "Network Service Discovery")


@pytest.mark.parametrize("tactic", ["C2", "discovery", "Defense Evasion", " Discovery", "Command And Control"])
def test_tactica_no_canonica_se_rechaza(tmp_path, tactic):
    f = rule_file(tmp_path, mitre={"technique": "T1046", "name": "n", "tactic": tactic})
    with pytest.raises(RuleError, match="mitre.tactic debe ser una de"):
        load_rules(f)


def test_regla_de_usuario_con_tactica_no_canonica_se_ignora(tmp_path, caplog):
    bundled, user = tmp_path / "b", tmp_path / "u"
    bundled.mkdir()
    user.mkdir()
    rule_file(bundled, name="a.yaml")
    bad = rule_file(user, mitre={"technique": "T1046", "name": "n", "tactic": "Persistence"}, name="b.yaml")
    assert bad.exists()
    assert [r.id for r in load_all_rules(bundled, user)] == ["r1"]
    assert "mitre.tactic" in caplog.text


def test_el_constructor_usa_una_tactica_canonica_y_rechaza_otra():
    assert DEFAULT_MITRE["tactic"] in MITRE_TACTICS
    assert build_rule(to_dict(RuleForm(name="Regla de prueba"))).mitre_tactic == "Reconnaissance"
    with pytest.raises(RuleError, match="mitre.tactic"):
        build_rule(to_dict(RuleForm(name="Regla de prueba", mitre_tactic="Persistence")))


# ------------------------------------------------------------------ excepciones

def test_sin_excepciones_la_regla_alerta_y_los_params_no_las_incluyen(tmp_path):
    (rule,) = load_rules(rule_file(tmp_path))
    assert "allow_hosts" not in rule.params and "allow_services" not in rule.params
    assert len(evaluate([rule], scan())) == 1


def test_allow_hosts_ip_y_red_cidr_en_origen_o_destino(tmp_path):
    for allowed in (["10.0.0.1"], ["10.0.0.0/24"], ["10.0.0.2"], ["192.168.0.0/16", "10.0.0.2/32"]):
        f = rule_file(tmp_path, params={"allow_hosts": allowed})
        assert evaluate(load_rules(f), scan()) == [], allowed
    f = rule_file(tmp_path, params={"allow_hosts": ["10.9.0.0/16", "2001:db8::/32"]})
    assert len(evaluate(load_rules(f), scan())) == 1


def test_allow_hosts_solo_silencia_ese_host(tmp_path):
    f = rule_file(tmp_path, params={"allow_hosts": ["10.0.0.1"]})
    assert [a.src_ip for a in evaluate(load_rules(f), scan() + scan(src="10.0.0.9", start=100))] == ["10.0.0.9"]


def test_allow_services_por_numero_y_por_nombre(tmp_path):
    ssh = [tcp(1 + i * 0.01, src="10.0.0.1", dst="10.0.0.2", dport=22, flags=SYN) for i in range(300)]
    params = {"min_syns": 200, "window_seconds": 10}
    assert len(evaluate(load_rules(rule_file(tmp_path, "syn_flood", params, {
        "technique": "T1498", "name": "n", "tactic": "Impact"})), ssh)) == 1
    for allowed in ([22], ["ssh"], ["SSH", 80]):
        f = rule_file(tmp_path, "syn_flood", {**params, "allow_services": allowed},
                      {"technique": "T1498", "name": "n", "tactic": "Impact"})
        assert evaluate(load_rules(f), ssh) == [], allowed


def test_allow_services_se_normaliza_a_puertos(tmp_path):
    (rule,) = load_rules(rule_file(tmp_path, params={"allow_services": ["smb", 445, "rdp", 22]}))
    assert rule.params["allow_services"] == [22, 445, 3389]


def test_allow_services_deja_pasar_los_otros_puertos(tmp_path):
    f = rule_file(tmp_path, params={"allow_services": [1000, 1001], "min_ports": 13})
    assert len(evaluate(load_rules(f), scan())) == 1  # quedan 13 de 15 puertos
    f = rule_file(tmp_path, params={"allow_services": [1000, 1001], "min_ports": 14})
    assert evaluate(load_rules(f), scan()) == []
    f = rule_file(tmp_path, params={"allow_services": list(range(1000, 1015))})
    assert evaluate(load_rules(f), scan()) == []


def test_allow_hosts_en_una_regla_dns_ademas_de_ignore_suffixes(tmp_path):
    name = "x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1.evil-c2.example"
    mitre = {"technique": "T1071.004", "name": "DNS", "tactic": "Command and Control"}
    packets = [dns_pkt(1, name, src="10.0.0.1"), dns_pkt(2, name, src="10.0.0.7")]
    f = rule_file(tmp_path, "dns_suspicious", {"allow_hosts": ["10.0.0.7"]}, mitre)
    assert [a.src_ip for a in evaluate(load_rules(f), packets)] == ["10.0.0.1"]
    f = rule_file(tmp_path, "dns_suspicious", {"ignore_suffixes": ["evil-c2.example"]}, mitre)
    assert evaluate(load_rules(f), packets) == []


def test_allow_services_en_udp_y_en_respuestas_dns(tmp_path):
    name = "x9f3a7c1e5b2d8046f1a9c3e7b5d2f80a4c6e1.evil-c2.example"
    mitre = {"technique": "T1071.004", "name": "DNS", "tactic": "Command and Control"}
    f = rule_file(tmp_path, "dns_suspicious", {"allow_services": ["dns"]}, mitre)
    assert evaluate(load_rules(f), [dns_pkt(1, name)]) == []


@pytest.mark.parametrize("params,texto", [
    ({"allow_hosts": "10.0.0.1"}, "lista"),
    ({"allow_hosts": ["no-es-ip"]}, "IP ni una red"),
    ({"allow_hosts": [True]}, "IP ni una red"),
    ({"allow_services": 22}, "lista"),
    ({"allow_services": ["ssh2"]}, "puerto"),
    ({"allow_services": [70000]}, "puerto"),
    ({"allow_services": [True]}, "puerto"),
])
def test_excepciones_invalidas_fallan_al_cargar(tmp_path, params, texto):
    with pytest.raises(RuleError, match=texto):
        load_rules(rule_file(tmp_path, params=params))


def test_allowlist_unidad():
    allow = Allowlist({"allow_hosts": ["10.0.0.0/24", "2001:db8::/32"], "allow_services": [445]})
    tcp_d = lambda **k: Decoded(1.0, k.get("src", "1.1.1.1"), k.get("dst", "2.2.2.2"), 6,  # noqa: E731
                                k.get("sport", 4000), k.get("dport", 80), 0, b"")
    assert allow.allows(tcp_d(src="10.0.0.5")) and allow.allows(tcp_d(dst="2001:db8::1"))
    assert allow.allows(tcp_d(dport=445)) and allow.allows(tcp_d(sport=445))
    assert not allow.allows(tcp_d()) and not allow.allows(tcp_d(src="not-an-ip"))
    icmp = Decoded(1.0, "1.1.1.1", "2.2.2.2", 1, 0, 0, 8, b"")
    assert not Allowlist({"allow_services": [0]}).allows(icmp)  # los puertos no aplican a ICMP
    assert not Allowlist({}).allows(tcp_d(src="10.0.0.5"))


def test_las_excepciones_valen_tambien_en_reglas_de_usuario(tmp_path):
    bundled, user = tmp_path / "b", tmp_path / "u"
    bundled.mkdir()
    user.mkdir()
    rule_file(bundled, name="a.yaml")
    rule_file(user, "port_scan", {"allow_hosts": ["10.0.0.1"]}, name="b.yaml").write_text(
        (user / "b.yaml").read_text(encoding="utf-8").replace("id: r1", "id: r2"), encoding="utf-8")
    alerts = evaluate(load_all_rules(bundled, user), scan())
    assert [a.rule_id for a in alerts] == ["r1"]  # r2 tiene el origen en la lista permitida


def test_udp_sin_puerto_de_servicio_no_se_confunde(tmp_path):
    f = rule_file(tmp_path, "suspicious_ports", {"ports": [4444], "allow_services": [53]},
                  {"technique": "T1571", "name": "n", "tactic": "Command and Control"})
    assert len(evaluate(load_rules(f), [tcp(1, dport=4444, flags=SYN)])) == 1
    assert evaluate(load_rules(f), [udp(1, dport=53, payload=b"x")]) == []
