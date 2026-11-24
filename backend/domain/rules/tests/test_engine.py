"""Tests del motor de reglas (backend/domain/rules/engine.py)."""
import random
import socket
import struct
from dataclasses import asdict
from pathlib import Path

import dpkt
import pytest
import yaml

from backend.domain.pcap.reader import Packet
from backend.domain.rules.engine import Alert, Rule, RuleError, evaluate, load_rules
from backend.domain.sessions.grouper import UnsupportedLinktype

ROOT = Path(__file__).resolve().parents[4]
REAL_RULES = ROOT / "rules"

SYN, SYNACK, ACK = 0x02, 0x12, 0x10


# ------------------------------------------------------------------ helpers

def _eth(ip_bytes_pkt, ethertype=dpkt.ethernet.ETH_TYPE_IP):
    return dpkt.ethernet.Ethernet(
        dst=b"\x00" * 6, src=b"\x11" * 6, type=ethertype, data=ip_bytes_pkt
    )


def _ip(l4, proto, src, dst):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, data=l4)
    ip.len = 20 + len(bytes(l4))
    return ip


def tcp(ts, src="10.0.0.1", dst="10.0.0.2", sport=40000, dport=80, flags=SYN, payload=b""):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    eth = _eth(_ip(t, dpkt.ip.IP_PROTO_TCP, src, dst))
    raw = bytes(eth)
    return Packet(ts, raw, len(raw))


def udp(ts, src="10.0.0.1", dst="10.0.0.2", sport=40000, dport=53, payload=b""):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = 8 + len(payload)
    eth = _eth(_ip(u, dpkt.ip.IP_PROTO_UDP, src, dst))
    raw = bytes(eth)
    return Packet(ts, raw, len(raw))


def dns_query(name, qr=False):
    op = dpkt.dns.DNS_RD | (dpkt.dns.DNS_QR if qr else 0)
    return bytes(dpkt.dns.DNS(id=1, op=op, qd=[dpkt.dns.DNS.Q(name=name, type=1)]))


def dns_pkt(ts, name, src="10.0.0.1", dport=53, qr=False):
    return udp(ts, src=src, dport=dport, payload=dns_query(name, qr))


RULE_TMPL = {
    "port_scan": {
        "id": "port_scan", "name": "Scan", "description": "d", "severity": "high",
        "detector": "port_scan",
        "mitre": {"technique": "T1046", "name": "NSD", "tactic": "Discovery"},
    },
    "ftp_cleartext": {
        "id": "ftp_cleartext", "name": "FTP", "description": "d", "severity": "medium",
        "detector": "ftp_cleartext",
        "mitre": {"technique": "T1040", "name": "Sniff", "tactic": "Credential Access"},
    },
    "dns_suspicious": {
        "id": "dns_suspicious", "name": "DNS", "description": "d", "severity": "low",
        "detector": "dns_suspicious",
        "mitre": {"technique": "T1071.004", "name": "DNS", "tactic": "C2"},
    },
}


@pytest.fixture
def mk(tmp_path):
    """Fábrica: mk('port_scan', min_ports=3) -> Rule cargada vía YAML."""
    counter = [0]

    def make(detector, **params):
        data = dict(RULE_TMPL[detector])
        if params:
            data["params"] = params
        counter[0] += 1
        d = tmp_path / f"r{counter[0]}"
        d.mkdir()
        f = d / f"{detector}.yaml"
        f.write_text(yaml.safe_dump(data), encoding="utf-8")
        return load_rules(f)[0]

    return make


def write_rule(tmp_path, data, name="r.yaml"):
    f = tmp_path / name
    f.write_text(data if isinstance(data, str) else yaml.safe_dump(data), encoding="utf-8")
    return f


def base(_tmpl="port_scan", **over):
    d = dict(RULE_TMPL[_tmpl])
    d.update(over)
    return d


# -------------------------------------------------------------------- carga

def test_load_real_rules():
    rules = {r.id: r for r in load_rules(REAL_RULES)}
    assert set(rules) == {
        "port_scan", "ftp_cleartext", "dns_suspicious", "beaconing", "syn_flood", "suspicious_ports",
        "dns_unusual_resolver", "large_upload", "brute_force_remote",
    }
    ps, ftp, dns = rules["port_scan"], rules["ftp_cleartext"], rules["dns_suspicious"]
    assert (ps.severity, ps.mitre_technique, ps.mitre_tactic) == ("high", "T1046", "Discovery")
    assert ps.params == {
        "min_ports": 15, "window_seconds": 60.0, "long_window_seconds": 900.0, "long_threshold": 20,
    }
    assert (ftp.severity, ftp.mitre_technique) == ("medium", "T1040")
    assert ftp.params == {"ports": [21]}
    assert (dns.severity, dns.mitre_technique) == ("medium", "T1071.004")
    assert dns.params == {
        "max_label_length": 40, "min_entropy": 3.5, "entropy_min_label": 20,
        "ignore_suffixes": ["elb.amazonaws.com"], "min_total_length": 50,
        "min_unique_subdomains": 0, "volume_window_seconds": 60.0,
    }
    assert all(isinstance(r, Rule) and r.source.endswith(".yaml") for r in rules.values())


def test_load_single_file_vs_folder(tmp_path):
    a = write_rule(tmp_path, base(), "a.yaml")
    write_rule(tmp_path, base("ftp_cleartext"), "b.yaml")
    assert len(load_rules(a)) == 1
    assert [r.id for r in load_rules(tmp_path)] == ["port_scan", "ftp_cleartext"]  # ordenados por archivo


def test_load_empty_folder(tmp_path):
    assert load_rules(tmp_path) == []


def test_load_yml_extension(tmp_path):
    write_rule(tmp_path, base(), "x.yml")
    assert [r.id for r in load_rules(tmp_path)] == ["port_scan"]


def test_defaults_when_params_missing(tmp_path):
    write_rule(tmp_path, base("port_scan"), "a.yaml")
    write_rule(tmp_path, base("ftp_cleartext", id="f"), "b.yaml")
    write_rule(tmp_path, base("dns_suspicious", id="d"), "c.yaml")
    r = {x.id: x for x in load_rules(tmp_path)}
    assert r["port_scan"].params == {
        "min_ports": 15, "window_seconds": 60.0, "long_window_seconds": 0.0, "long_threshold": 20,
    }
    assert r["f"].params == {"ports": [21]}
    assert r["d"].params == {
        "max_label_length": 40, "min_entropy": 3.5, "entropy_min_label": 20, "ignore_suffixes": [],
        "min_total_length": 50, "min_unique_subdomains": 0, "volume_window_seconds": 60.0,
    }


def test_params_none_is_ok(tmp_path):
    f = write_rule(tmp_path, base(params=None))
    assert load_rules(f)[0].params["min_ports"] == 15


def test_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope")


@pytest.mark.parametrize("content", [
    "id: [unclosed\n  - : :",
    "\tkey: : bad",
])
def test_invalid_yaml(tmp_path, content):
    f = write_rule(tmp_path, content, "broken.yaml")
    with pytest.raises(RuleError, match="broken.yaml"):
        load_rules(f)


@pytest.mark.parametrize("content", ["- a\n- b\n", "hola", "", "42"])
def test_not_a_mapping(tmp_path, content):
    f = write_rule(tmp_path, content, "lista.yaml")
    with pytest.raises(RuleError, match="lista.yaml"):
        load_rules(f)


@pytest.mark.parametrize("missing", ["id", "name", "severity", "detector", "mitre"])
def test_missing_required_fields(tmp_path, missing):
    d = base()
    del d[missing]
    with pytest.raises(RuleError, match="faltan campos"):
        load_rules(write_rule(tmp_path, d))


def test_unknown_field_typo(tmp_path):
    d = base()
    d["severty"] = "low"
    with pytest.raises(RuleError, match="severty"):
        load_rules(write_rule(tmp_path, d))


def test_invalid_severity(tmp_path):
    with pytest.raises(RuleError, match="severity"):
        load_rules(write_rule(tmp_path, base(severity="urgent")))


def test_unknown_detector(tmp_path):
    with pytest.raises(RuleError, match="detector desconocido"):
        load_rules(write_rule(tmp_path, base(detector="nope")))


@pytest.mark.parametrize("tech", ["T12", "1046", "T1046.1", "t1046", "T1046.0001", "", 1046, None])
def test_bad_technique(tmp_path, tech):
    d = base(mitre={"technique": tech, "name": "n", "tactic": "t"})
    with pytest.raises(RuleError, match="technique"):
        load_rules(write_rule(tmp_path, d))


@pytest.mark.parametrize("tech", ["T1046", "T1071.004"])
def test_good_technique(tmp_path, tech):
    d = base(mitre={"technique": tech, "name": "n", "tactic": "t"})
    assert load_rules(write_rule(tmp_path, d))[0].mitre_technique == tech


def test_mitre_without_tactic(tmp_path):
    with pytest.raises(RuleError, match="mitre.tactic"):
        load_rules(write_rule(tmp_path, base(mitre={"technique": "T1046", "name": "n"})))


def test_mitre_without_name(tmp_path):
    with pytest.raises(RuleError, match="mitre.name"):
        load_rules(write_rule(tmp_path, base(mitre={"technique": "T1046", "tactic": "t"})))


def test_mitre_not_a_map(tmp_path):
    with pytest.raises(RuleError, match="technique"):
        load_rules(write_rule(tmp_path, base(mitre="T1046")))


def test_unknown_param(tmp_path):
    with pytest.raises(RuleError, match="params desconocidos"):
        load_rules(write_rule(tmp_path, base(params={"min_portz": 5})))


def test_params_not_a_map(tmp_path):
    with pytest.raises(RuleError, match="params"):
        load_rules(write_rule(tmp_path, base(params=[1, 2])))


@pytest.mark.parametrize("detector,params", [
    ("port_scan", {"min_ports": 1}),
    ("port_scan", {"min_ports": "15"}),
    ("port_scan", {"min_ports": True}),
    ("port_scan", {"min_ports": -3}),
    ("port_scan", {"min_ports": 5.5}),
    ("port_scan", {"window_seconds": 0}),
    ("port_scan", {"window_seconds": "60"}),
    ("port_scan", {"window_seconds": False}),
    ("ftp_cleartext", {"ports": [70000]}),
    ("ftp_cleartext", {"ports": [-1]}),
    ("ftp_cleartext", {"ports": []}),
    ("ftp_cleartext", {"ports": 21}),
    ("ftp_cleartext", {"ports": [True]}),
    ("ftp_cleartext", {"ports": ["21"]}),
    ("dns_suspicious", {"max_label_length": 64}),
    ("dns_suspicious", {"max_label_length": 0}),
    ("dns_suspicious", {"min_entropy": 9}),
    ("dns_suspicious", {"min_entropy": -1}),
    ("dns_suspicious", {"entropy_min_label": 0}),
])
def test_param_out_of_range_or_type(tmp_path, detector, params):
    with pytest.raises(RuleError, match="param"):
        load_rules(write_rule(tmp_path, base(detector, params=params)))


@pytest.mark.parametrize("bad_id", ["PortScan", "port-scan", "port scan", "", "ñandú"])
def test_invalid_id(tmp_path, bad_id):
    with pytest.raises(RuleError):
        load_rules(write_rule(tmp_path, base(id=bad_id)))


def test_duplicate_id_across_files(tmp_path):
    write_rule(tmp_path, base(), "a.yaml")
    write_rule(tmp_path, base(), "b.yaml")
    with pytest.raises(RuleError, match="duplicado") as e:
        load_rules(tmp_path)
    assert "b.yaml" in str(e.value) and "a.yaml" in str(e.value)


def test_error_message_has_filename(tmp_path):
    f = write_rule(tmp_path, base(severity="x"), "mi_regla.yaml")
    with pytest.raises(RuleError, match="mi_regla.yaml"):
        load_rules(f)


def test_valid_params_accepted(tmp_path):
    f = write_rule(tmp_path, base(params={"min_ports": 2, "window_seconds": 0.5}))
    params = load_rules(f)[0].params
    assert (params["min_ports"], params["window_seconds"]) == (2, 0.5)


# ---------------------------------------------------------------- port_scan

def syns(n, start_ts=100.0, step=0.1, **kw):
    return [tcp(start_ts + i * step, dport=1000 + i, **kw) for i in range(n)]


def test_port_scan_basic(mk):
    alerts = evaluate([mk("port_scan")], syns(15))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.first_ts == 100.0
    assert a.src_ip == "10.0.0.1" and a.dst_ip == "10.0.0.2"
    assert a.evidence["distinct_ports"] == 15
    assert a.evidence["sample_ports"] == list(range(1000, 1015))
    assert a.evidence["threshold"] == 15
    assert a.evidence["window_seconds"] == 60.0


def test_port_scan_copies_rule_metadata(mk):
    rule = mk("port_scan")
    a = evaluate([rule], syns(15))[0]
    assert (a.rule_id, a.severity, a.mitre_technique, a.mitre_name, a.mitre_tactic, a.name) == (
        "port_scan", "high", "T1046", "NSD", "Discovery", "Scan")


def test_port_scan_14_ports_no_alert(mk):
    assert evaluate([mk("port_scan")], syns(14)) == []


def test_port_scan_repeated_ports_no_alert(mk):
    pkts = [tcp(100 + i * 0.1, dport=1000 + (i % 5)) for i in range(60)]
    assert evaluate([mk("port_scan")], pkts) == []


def test_port_scan_outside_window(mk):
    # 15 puertos pero separados 10 s entre sí: nunca hay 15 en 60 s
    assert evaluate([mk("port_scan")], syns(15, step=10)) == []


def test_port_scan_window_slides(mk):
    # 10 lentos al principio quedan fuera de la ventana; después 15 rápidos
    pkts = syns(10, start_ts=0, step=30) + syns(15, start_ts=1000, step=0.1)
    # los 15 rápidos usan los mismos puertos 1000-1014 -> 15 distintos
    a = evaluate([mk("port_scan")], pkts)
    assert len(a) == 1 and a[0].first_ts == 1000.0


def test_port_scan_second_scan_not_duplicated(mk):
    pkts = syns(15) + syns(15, start_ts=500)
    assert len(evaluate([mk("port_scan")], pkts)) == 1


def test_port_scan_synack_ignored(mk):
    assert evaluate([mk("port_scan")], syns(20, flags=SYNACK)) == []


def test_port_scan_ack_only_ignored(mk):
    assert evaluate([mk("port_scan")], syns(20, flags=ACK)) == []


def test_port_scan_different_destinations_not_summed(mk):
    pkts = []
    for i in range(20):
        pkts.append(tcp(100 + i * 0.1, dst=f"10.0.1.{i % 4}", dport=1000 + i))
    # 20 puertos repartidos entre 4 destinos: 5 por destino
    assert evaluate([mk("port_scan")], pkts) == []


def test_port_scan_different_sources_not_summed(mk):
    pkts = [tcp(100 + i * 0.1, src=f"10.0.2.{i % 3}", dport=1000 + i) for i in range(20)]
    assert evaluate([mk("port_scan")], pkts) == []


def test_port_scan_udp_ignored(mk):
    pkts = [udp(100 + i * 0.1, dport=1000 + i) for i in range(30)]
    assert evaluate([mk("port_scan")], pkts) == []


def test_port_scan_custom_thresholds(mk):
    rule = mk("port_scan", min_ports=3, window_seconds=1)
    a = evaluate([rule], syns(3, step=0.1))
    assert len(a) == 1 and a[0].evidence["threshold"] == 3 and a[0].evidence["window_seconds"] == 1.0
    assert evaluate([rule], syns(3, step=2)) == []


def test_port_scan_sample_ports_capped_at_20(mk):
    rule = mk("port_scan", min_ports=30)
    a = evaluate([rule], syns(30))[0]
    assert len(a.evidence["sample_ports"]) == 20 and a.evidence["distinct_ports"] == 30


# ----------------------------------------------------------- ftp_cleartext

FLOW = dict(sport=50000, dport=21)


def ftp(ts, data, **kw):
    kw2 = dict(FLOW)
    kw2.update(kw)
    return tcp(ts, flags=0x18, payload=data, **kw2)


def test_ftp_basic_and_password_never_leaks(mk):
    pkts = [ftp(1, b"USER bob\r\n"), ftp(2, b"PASS secreto\r\n")]
    alerts = evaluate([mk("ftp_cleartext")], pkts)
    assert len(alerts) == 1
    ev = alerts[0].evidence
    assert ev["username"] == "bob"
    assert ev["password"] == "<oculta>"
    assert ev["password_length"] == len("secreto")
    assert ev["port"] == 21
    assert "secreto" not in str(asdict(alerts[0]))
    assert "secreto" not in repr(alerts[0])


def test_ftp_pass_without_user(mk):
    a = evaluate([mk("ftp_cleartext")], [ftp(1, b"PASS xyz\r\n")])
    assert a[0].evidence["username"] == "<no visto>"


@pytest.mark.parametrize("payload", [b"", b"LIST\r\n", b"QUIT\r\n", b"USER bob\r\n", b"\r\n"])
def test_ftp_nothing(mk, payload):
    assert evaluate([mk("ftp_cleartext")], [ftp(1, payload)]) == []


def test_ftp_other_port_detected_by_content(mk):
    pkts = [ftp(1, b"USER bob\r\n", dport=2121), ftp(2, b"PASS pw\r\n", dport=2121)]
    a = evaluate([mk("ftp_cleartext")], pkts)
    assert len(a) == 1 and a[0].evidence["port"] == 2121 and a[0].evidence["username"] == "bob"


def test_ftp_pass_without_user_only_on_trusted_ports(mk):
    pkts = [ftp(1, b"PASS pw\r\n", dport=2121)]
    assert evaluate([mk("ftp_cleartext")], pkts) == []
    assert len(evaluate([mk("ftp_cleartext", ports=[2121])], pkts)) == 1


def test_ftp_same_user_not_duplicated(mk):
    pkts = [ftp(1, b"USER bob\r\n"), ftp(2, b"PASS a\r\n"), ftp(3, b"USER bob\r\n"), ftp(4, b"PASS b\r\n")]
    assert len(evaluate([mk("ftp_cleartext")], pkts)) == 1


def test_ftp_different_users_both_alert(mk):
    pkts = [ftp(1, b"USER bob\r\n"), ftp(2, b"PASS a\r\n"), ftp(3, b"USER eve\r\n"), ftp(4, b"PASS b\r\n")]
    a = evaluate([mk("ftp_cleartext")], pkts)
    assert [x.evidence["username"] for x in a] == ["bob", "eve"]


def test_ftp_newline_only(mk):
    a = evaluate([mk("ftp_cleartext")], [ftp(1, b"USER bob\n"), ftp(2, b"PASS secreto\n")])
    assert a[0].evidence["username"] == "bob" and a[0].evidence["password_length"] == 7
    assert "secreto" not in str(asdict(a[0]))


def test_ftp_lowercase_commands(mk):
    a = evaluate([mk("ftp_cleartext")], [ftp(1, b"user bob\r\n"), ftp(2, b"pass pw\r\n")])
    assert len(a) == 1 and a[0].evidence["username"] == "bob"


def test_ftp_user_in_other_flow_not_linked(mk):
    pkts = [ftp(1, b"USER bob\r\n", sport=50001), ftp(2, b"PASS pw\r\n", sport=50002)]
    assert evaluate([mk("ftp_cleartext")], pkts)[0].evidence["username"] == "<no visto>"


def test_ftp_udp_ignored(mk):
    p = udp(1, dport=21, payload=b"PASS pw\r\n")
    assert evaluate([mk("ftp_cleartext")], [p]) == []


def test_ftp_long_username_truncated(mk):
    pkts = [ftp(1, b"USER " + b"a" * 200 + b"\r\n"), ftp(2, b"PASS x\r\n")]
    assert len(evaluate([mk("ftp_cleartext")], pkts)[0].evidence["username"]) == 64


# ---------------------------------------------------------- dns_suspicious

def test_dns_long_label(mk):
    name = "a" * 45 + ".evil.com"
    a = evaluate([mk("dns_suspicious")], [dns_pkt(1, name)])
    assert len(a) == 1
    ev = a[0].evidence
    assert ev["query"] == name and ev["qtype"] == 1
    assert any("45" in r for r in ev["reasons"])
    assert a[0].mitre_technique == "T1071.004"


def test_dns_high_entropy_label(mk):
    name = "q8x2kz7vb1mw4jr9tc5yh3ne.example.com"  # 24 chars, todos distintos
    a = evaluate([mk("dns_suspicious")], [dns_pkt(1, name)])
    assert len(a) == 1
    assert any("entrop" in r for r in a[0].evidence["reasons"])
    assert a[0].evidence["label_entropy"] >= 3.5


@pytest.mark.parametrize("name", ["google.com", "www.example.org", "aaaaaaaaaaaaaaaaaaaaaaaa.com"])
def test_dns_benign(mk, name):
    # el último: largo 24 pero entropía 0 -> no alerta
    assert evaluate([mk("dns_suspicious")], [dns_pkt(1, name)]) == []


def test_dns_responses_ignored(mk):
    assert evaluate([mk("dns_suspicious")], [dns_pkt(1, "a" * 50 + ".com", qr=True)]) == []


def test_dns_dedupe_by_source_and_name(mk):
    name = "a" * 50 + ".com"
    pkts = [dns_pkt(1, name), dns_pkt(2, name), dns_pkt(3, name, src="10.0.0.9")]
    a = evaluate([mk("dns_suspicious")], pkts)
    assert [x.src_ip for x in a] == ["10.0.0.1", "10.0.0.9"]


def test_dns_different_names_same_source(mk):
    pkts = [dns_pkt(1, "a" * 50 + ".com"), dns_pkt(2, "b" * 50 + ".com")]
    assert len(evaluate([mk("dns_suspicious")], pkts)) == 2


@pytest.mark.parametrize("payload", [b"\x00", b"\xff" * 12, b"\x00" * 12, b"A" * 100, bytes(range(256))])
def test_dns_garbage_payload_no_exception(mk, payload):
    evaluate([mk("dns_suspicious")], [udp(1, payload=payload)])


def test_dns_other_port_ignored(mk):
    assert evaluate([mk("dns_suspicious")], [dns_pkt(1, "a" * 50 + ".com", dport=5353)]) == []


def test_dns_tcp_ignored(mk):
    p = tcp(1, dport=53, flags=0x18, payload=dns_query("a" * 50 + ".com"))
    assert evaluate([mk("dns_suspicious")], [p]) == []


def test_dns_custom_thresholds(mk):
    name = "abcdefghij.example.com"  # label de 10, 10 chars distintos (entropía 3.32)
    assert evaluate([mk("dns_suspicious")], [dns_pkt(1, name)]) == []
    assert len(evaluate([mk("dns_suspicious", max_label_length=5)], [dns_pkt(1, name)])) == 1
    rule = mk("dns_suspicious", entropy_min_label=10, min_entropy=3.0)
    assert len(evaluate([rule], [dns_pkt(1, name)])) == 1


# ----------------------------------------------------------------- evaluate

def test_evaluate_alerts_sorted_by_first_ts(mk):
    rules = [mk("port_scan", min_ports=3), mk("ftp_cleartext"), mk("dns_suspicious")]
    pkts = [
        dns_pkt(50, "a" * 50 + ".com"),
        ftp(30, b"USER bob\r\n"), ftp(31, b"PASS pw\r\n"),
        tcp(10, dport=1), tcp(11, dport=2), tcp(12, dport=3),
    ]
    alerts = evaluate(rules, pkts)
    assert [a.rule_id for a in alerts] == ["port_scan", "ftp_cleartext", "dns_suspicious"]
    ts = [a.first_ts for a in alerts]
    assert ts == sorted(ts)


def test_evaluate_empty_packets(mk):
    assert evaluate([mk("port_scan")], []) == []


def test_evaluate_empty_rules():
    assert evaluate([], syns(20)) == []


def test_evaluate_rejects_non_ethernet(mk):
    with pytest.raises(UnsupportedLinktype):
        evaluate([mk("port_scan")], [], linktype=101)


def test_evaluate_accepts_generator(mk):
    gen = (p for p in syns(15))
    assert len(evaluate([mk("port_scan")], gen)) == 1


def test_evaluate_accepts_generator_of_rules(mk):
    assert len(evaluate((r for r in [mk("port_scan")]), syns(15))) == 1


def test_evaluate_tolerates_junk_packets(mk):
    rules = [mk("port_scan", min_ports=3), mk("ftp_cleartext"), mk("dns_suspicious")]
    arp = bytes(dpkt.ethernet.Ethernet(
        dst=b"\xff" * 6, src=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28))
    good = tcp(1, dport=21, flags=0x18, payload=b"PASS x\r\n")
    trunc_ip = bytes(good.data)[:20]  # Ethernet + 6 bytes de IP
    trunc_tcp = bytes(good.data)[:40]  # IP completo pero TCP cortado
    ip_pkt = _ip(dpkt.tcp.TCP(sport=1, dport=2, flags=SYN), dpkt.ip.IP_PROTO_TCP, "1.1.1.1", "2.2.2.2")
    ip_pkt.offset = 100  # fragmento no inicial (campo vigente; `off` está deprecado)
    frag = bytes(_eth(ip_pkt))
    icmp = bytes(_eth(_ip(dpkt.icmp.ICMP(), dpkt.ip.IP_PROTO_ICMP, "1.1.1.1", "2.2.2.2")))
    pkts = [Packet(0, x, len(x)) for x in
            (arp, b"", b"\x00", trunc_ip, trunc_tcp, frag, icmp, b"\xff" * 14)] + [good]
    alerts = evaluate(rules, pkts)
    assert len(alerts) == 1 and alerts[0].rule_id == "ftp_cleartext"


def test_evaluate_ipv6_tcp(mk):
    t = dpkt.tcp.TCP(sport=1, dport=21, flags=0x18, data=b"PASS x\r\n")
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, "fe80::1"),
                       dst=socket.inet_pton(socket.AF_INET6, "fe80::2"),
                       nxt=dpkt.ip.IP_PROTO_TCP, data=t, plen=len(bytes(t)))
    raw = bytes(_eth(ip6, dpkt.ethernet.ETH_TYPE_IP6))
    a = evaluate([mk("ftp_cleartext")], [Packet(1, raw, len(raw))])
    assert len(a) == 1 and a[0].src_ip == "fe80::1"
    assert isinstance(a[0], Alert)


# ------------------------------------------------------------------- fuzz

def _fuzz_frames(seed, n):
    rng = random.Random(seed)
    frames = []
    for _ in range(n):
        et = rng.choice([0x0800, 0x86DD])
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 120)))
        if rng.random() < 0.7:  # cabecera IP/IPv6 plausible con L4 TCP/UDP
            proto = rng.choice([6, 17])
            if et == 0x0800:
                hdr = bytes([0x45, 0]) + struct.pack(">H", 20 + len(body)) + b"\x00\x00\x00\x00\x40" \
                    + bytes([proto]) + b"\x00\x00" + bytes(rng.getrandbits(8) for _ in range(8))
            else:
                hdr = b"\x60\x00\x00\x00" + struct.pack(">H", len(body)) + bytes([proto, 64]) \
                    + bytes(rng.getrandbits(8) for _ in range(32))
            ports = struct.pack(">HH", rng.randint(1, 65535), rng.choice([53, 21, 80]))
            if rng.random() < 0.5:
                # la parte dnsish: cabecera DNS con conteos pequeños + basura
                body = ports + body
            else:
                body = ports + bytes(rng.getrandbits(8) for _ in range(rng.choice([4, 8])))\
                    + bytes([0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]) + body
            frame = b"\x00" * 6 + b"\x11" * 6 + struct.pack(">H", et) + hdr + body
        else:
            frame = b"\x00" * 6 + b"\x11" * 6 + struct.pack(">H", et) + body
        frames.append(frame)
    return frames


def test_fuzz_random_frames_never_raise():
    rules = load_rules(REAL_RULES)
    frames = _fuzz_frames(1234, 6000)
    failures = []
    for i, fr in enumerate(frames):
        try:
            evaluate(rules, [Packet(float(i), fr, len(fr))])
        except Exception as exc:  # noqa: BLE001
            failures.append((type(exc).__name__, str(exc)[:80], fr.hex()))
            if len(failures) >= 3:
                break
    assert not failures, failures


def _udp53_frame(dns_payload):
    return bytes(udp(1, payload=dns_payload).data)


def test_fuzz_random_dns_payloads_never_raise():
    rules = load_rules(REAL_RULES)
    rng = random.Random(99)
    failures = []
    for _ in range(4000):
        n = rng.randint(1, 80)
        payload = bytes(rng.getrandbits(8) for _ in range(n))
        if rng.random() < 0.7:  # cabecera DNS con 1 pregunta, qr=0
            payload = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + payload
        fr = _udp53_frame(payload)
        try:
            evaluate(rules, [Packet(1.0, fr, len(fr))])
        except Exception as exc:  # noqa: BLE001
            failures.append((type(exc).__name__, str(exc)[:80], fr.hex()))
            if len(failures) >= 3:
                break
    assert not failures, failures
