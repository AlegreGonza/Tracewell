"""Tests de decode_layer y RuleRunner (reglas alimentadas con paquetes ya decodificados)."""
import pytest

from backend.domain.pcap.reader import Packet
from backend.domain.rules.engine import RuleRunner, _decode, decode_layer, evaluate, load_rules
from backend.domain.rules.tests.test_engine import REAL_RULES, tcp, udp
from backend.domain.sessions.grouper import UnsupportedLinktype, parse_ip


def mezcla():
    syns = [tcp(i * 0.01, dst="10.0.0.9", sport=40000, dport=1000 + i) for i in range(20)]
    corto = Packet(9.0, syns[0].data[:30], 30)
    arp = Packet(9.5, b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + bytes(28), 42)
    return syns + [udp(8.0, dport=53), corto, arp]


def test_decode_layer_igual_a_decode():
    for p in mezcla():
        capa, _ = parse_ip(p.data)
        assert decode_layer(p, capa) == _decode(p)
    assert decode_layer(mezcla()[0], None) is None


def test_runner_igual_a_evaluate():
    reglas = load_rules(REAL_RULES)
    runner = RuleRunner(reglas)
    for p in mezcla():
        runner.feed(decode_layer(p, parse_ip(p.data)[0]))
    esperado = evaluate(reglas, mezcla())
    assert runner.alerts() == esperado
    assert "port_scan" in [a.rule_id for a in esperado]


def test_runner_valida_el_linktype():
    with pytest.raises(UnsupportedLinktype):
        RuleRunner([], linktype=113)
