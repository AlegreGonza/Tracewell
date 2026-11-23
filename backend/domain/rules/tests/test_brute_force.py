"""Tests del detector de fuerza bruta (SSH/RDP) y de la regla personalizada por umbral, con pcap sintéticos."""
from pathlib import Path

import dpkt
import pytest
import yaml

from backend.domain.analysis.analyzer import analyze
from backend.domain.rules.engine import RuleError, load_rules
from backend.domain.rules.tests.test_engine import ACK, SYN, SYNACK, tcp, udp

ROOT = Path(__file__).resolve().parents[4]
ATTACKER, VICTIM = "45.33.32.156", "10.0.0.5"


def write_pcap(path, packets):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=1)
        for p in packets:
            w.writepkt(p.data, p.ts)
    return path


def brute_rules():
    return load_rules(ROOT / "rules" / "brute_force_remote.yaml")


def attempts(n, dport=22, step=1.0, src=ATTACKER, dst=VICTIM):
    return [tcp(1000 + i * step, src=src, dst=dst, sport=40000 + i, dport=dport, flags=SYN) for i in range(n)]


def alerts_of(tmp_path, packets, rules):
    return analyze(write_pcap(tmp_path / "t.pcap", packets), rules).alerts


# ------------------------------------------------------------ fuerza bruta

def test_la_regla_del_repo_carga_y_tiene_guia():
    (rule,) = brute_rules()
    assert rule.detector == "brute_force" and rule.mitre_technique == "T1110"
    assert rule.false_positives and rule.investigation_steps and "22" in rule.wireshark_filter


@pytest.mark.parametrize("port,service", [(22, "SSH"), (3389, "RDP")])
def test_muchos_intentos_a_ssh_o_rdp_alertan(tmp_path, port, service):
    alerts = alerts_of(tmp_path, attempts(12, dport=port), brute_rules())
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.src_ip, a.dst_ip, a.rule_id) == (ATTACKER, VICTIM, "brute_force_remote")
    assert a.evidence["service"] == service and a.evidence["attempts"] == 10


def test_pocos_intentos_no_alertan(tmp_path):
    assert alerts_of(tmp_path, attempts(9), brute_rules()) == []


def test_intentos_lentos_fuera_de_la_ventana_no_alertan(tmp_path):
    assert alerts_of(tmp_path, attempts(12, step=30.0), brute_rules()) == []


def test_otro_puerto_no_cuenta(tmp_path):
    assert alerts_of(tmp_path, attempts(20, dport=8080), brute_rules()) == []


def test_las_respuestas_del_servidor_no_cuentan(tmp_path):
    replies = [tcp(1000 + i, src=VICTIM, dst=ATTACKER, sport=22, dport=40000 + i, flags=SYNACK) for i in range(20)]
    assert alerts_of(tmp_path, replies, brute_rules()) == []


def test_origenes_distintos_no_se_suman(tmp_path):
    packets = []
    for k in range(5):
        packets += [tcp(1000 + i, src=f"45.33.32.{k + 10}", dst=VICTIM, sport=40000 + i, dport=22, flags=SYN) for i in range(4)]
    assert alerts_of(tmp_path, sorted(packets, key=lambda p: p.ts), brute_rules()) == []


def test_una_sola_alerta_por_origen_destino_y_puerto(tmp_path):
    assert len(alerts_of(tmp_path, attempts(60), brute_rules())) == 1


def test_sesion_normal_con_un_solo_syn_no_alerta(tmp_path):
    normal = [tcp(1000, src=ATTACKER, dst=VICTIM, dport=22, flags=SYN), tcp(1001, src=VICTIM, dst=ATTACKER, sport=22, dport=40000, flags=SYNACK),
              tcp(1002, src=ATTACKER, dst=VICTIM, dport=22, flags=ACK)]
    assert alerts_of(tmp_path, normal, brute_rules()) == []


def test_umbral_configurable(tmp_path):
    f = tmp_path / "r.yaml"
    data = yaml.safe_load((ROOT / "rules" / "brute_force_remote.yaml").read_text(encoding="utf-8"))
    data["params"]["min_attempts"] = 3
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert len(alerts_of(tmp_path, attempts(3), load_rules(f))) == 1


def test_params_invalidos_fallan_al_cargar(tmp_path):
    f = tmp_path / "r.yaml"
    data = yaml.safe_load((ROOT / "rules" / "brute_force_remote.yaml").read_text(encoding="utf-8"))
    data["params"]["min_attempts"] = 1
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(RuleError):
        load_rules(f)


# --------------------------------------------------- regla personalizada

def custom(tmp_path, **params):
    data = {"id": "mi_regla", "name": "Mi regla", "severity": "medium", "detector": "threshold",
            "mitre": {"technique": "T1046", "name": "n", "tactic": "Discovery"}, "params": params}
    f = tmp_path / "mi_regla.yaml"
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_rules(f)


def test_umbral_tcp_con_puerto_y_destino(tmp_path):
    rules = custom(tmp_path, protocol="tcp", dst_ip="10.0.0.0/24", port=22, min_events=5, window_seconds=30)
    assert len(alerts_of(tmp_path, attempts(6), rules)) == 1
    assert alerts_of(tmp_path, attempts(6, dst="192.168.9.9"), rules) == []
    assert alerts_of(tmp_path, attempts(6, dport=80), rules) == []


def test_umbral_udp(tmp_path):
    pk = [udp(1000 + i, src=ATTACKER, dst=VICTIM, dport=5060) for i in range(5)]
    assert len(alerts_of(tmp_path, pk, custom(tmp_path, protocol="udp", min_events=5))) == 1
    assert alerts_of(tmp_path, pk, custom(tmp_path, protocol="tcp", min_events=5)) == []


def test_umbral_origen_por_red(tmp_path):
    rules = custom(tmp_path, src_ip="45.33.32.0/24", min_events=4)
    assert len(alerts_of(tmp_path, attempts(4), rules)) == 1
    assert alerts_of(tmp_path, attempts(4, src="8.8.8.8"), rules) == []


@pytest.mark.parametrize("params", [{"protocol": "icmp"}, {"src_ip": "no-ip"}, {"port": 70000}, {"min_events": 1}, {"window_seconds": 0}])
def test_umbral_rechaza_params_invalidos(tmp_path, params):
    with pytest.raises(RuleError):
        custom(tmp_path, **params)
