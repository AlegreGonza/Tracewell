"""Tests de backend/domain/rules/extra_detectors.py."""
import subprocess
import sys
from pathlib import Path

import dpkt
import pytest
import yaml

from backend.domain.pcap.reader import Packet
from backend.domain.rules import extra_detectors as X
from backend.domain.rules.engine import Decoded, RuleError, evaluate, load_rules
from backend.domain.rules.tests.test_engine import ACK, SYN, SYNACK, _eth, dns_query, tcp, udp

ROOT = Path(__file__).resolve().parents[4]
PUB = "45.33.32.156"  # IP publica (is_global)
PUB2 = "185.199.108.153"

MITRE = {"technique": "T1071", "name": "n", "tactic": "Command and Control"}


def make_rules(tmp_path, detector, params=None, rid=None, fname=None):
    rid = rid or detector
    data = {"id": rid, "name": rid, "description": "d", "severity": "medium", "detector": detector, "mitre": MITRE}
    if params is not None:
        data["params"] = params
    f = tmp_path / (fname or f"{rid}.yaml")
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_rules(f)


def run(tmp_path, detector, packets, params=None):
    return evaluate(make_rules(tmp_path, detector, params), packets)


def udp6(ts, src, dst, dport=53, payload=b"", sport=40000):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    u.ulen = 8 + len(payload)
    import socket
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src), dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=dpkt.ip.IP_PROTO_UDP, plen=len(bytes(u)), data=u)
    raw = bytes(_eth(ip, dpkt.ethernet.ETH_TYPE_IP6))
    return Packet(ts, raw, len(raw))


def dec(ts, src="10.0.0.1", dst=PUB, proto=6, sport=1000, dport=80, flags=SYN, payload=b""):
    return Decoded(ts, src, dst, proto, sport, dport, flags, payload)


# ================================================================= beaconing

def beacon_syns(times, dport=8443, dst=PUB, src="10.0.0.1"):
    return [tcp(t, src=src, dst=dst, sport=40000 + i, dport=dport, flags=SYN) for i, t in enumerate(times)]


def test_beaconing_regular_cada_30s_alerta(tmp_path):
    alerts = run(tmp_path, "beaconing", beacon_syns([i * 30.0 for i in range(10)]))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "beaconing" and (a.src_ip, a.dst_ip) == ("10.0.0.1", PUB)
    assert a.first_ts == 0.0  # el primer instante de la serie
    assert a.evidence == {"events": 8, "mean_interval_seconds": 30.0, "jitter": 0.0,
                          "destination_port": 8443, "protocol": "TCP"}


def test_beaconing_con_poco_jitter_alerta_y_con_mucho_no(tmp_path):
    ok = [i * 30.0 + (1.0 if i % 2 else -1.0) * 0.5 + 100 for i in range(10)]  # jitter ~ 3%
    assert len(run(tmp_path, "beaconing", beacon_syns(ok))) == 1
    irregular = [0, 3, 40, 41, 90, 200, 203, 330, 500, 507, 900]
    assert run(tmp_path, "beaconing", beacon_syns(irregular)) == []


def test_beaconing_keepalive_de_1s_no_es_beacon(tmp_path):
    assert run(tmp_path, "beaconing", beacon_syns([float(i) for i in range(30)])) == []


def test_beaconing_intervalo_justo_en_el_minimo(tmp_path):
    assert len(run(tmp_path, "beaconing", beacon_syns([i * 5.0 for i in range(8)]))) == 1
    assert run(tmp_path, "beaconing", beacon_syns([i * 4.9 for i in range(8)])) == []


def test_beaconing_pocos_eventos_no_alerta(tmp_path):
    assert run(tmp_path, "beaconing", beacon_syns([i * 30.0 for i in range(7)])) == []


def test_beaconing_params_min_events_min_interval_max_jitter(tmp_path):
    pk = beacon_syns([i * 30.0 for i in range(5)])
    assert run(tmp_path, "beaconing", pk) == []  # por defecto necesita 8
    a = run(tmp_path, "beaconing", pk, {"min_events": 5})
    assert len(a) == 1 and a[0].evidence["events"] == 5
    fast = beacon_syns([i * 2.0 for i in range(10)])
    assert run(tmp_path, "beaconing", fast) == []
    assert len(run(tmp_path, "beaconing", fast, {"min_interval_seconds": 1})) == 1
    wobbly = beacon_syns([0, 30, 62, 90, 121, 150, 181, 210, 242])
    assert run(tmp_path, "beaconing", wobbly, {"max_jitter": 0.0}) == []
    assert len(run(tmp_path, "beaconing", wobbly, {"max_jitter": 0.1})) == 1


def test_beaconing_ignora_puertos_regulares_por_defecto(tmp_path):
    ntp = [udp(i * 30.0, dst=PUB, dport=123, payload=b"x") for i in range(10)]
    assert run(tmp_path, "beaconing", ntp) == []
    dns = [udp(i * 30.0, dst=PUB, dport=53, payload=b"x") for i in range(10)]
    assert run(tmp_path, "beaconing", dns) == []


def test_beaconing_ignore_ports_personalizado_y_vacio(tmp_path):
    ntp = [udp(i * 30.0, dst=PUB, dport=123, payload=b"x") for i in range(10)]
    assert len(run(tmp_path, "beaconing", ntp, {"ignore_ports": []})) == 1
    assert run(tmp_path, "beaconing", beacon_syns([i * 30.0 for i in range(10)]), {"ignore_ports": [8443]}) == []


def test_beaconing_udp_cuenta_y_marca_protocolo(tmp_path):
    pk = [udp(i * 30.0, dst=PUB, dport=9999, payload=b"x") for i in range(9)]
    a = run(tmp_path, "beaconing", pk)
    assert len(a) == 1 and a[0].evidence["protocol"] == "UDP" and a[0].evidence["destination_port"] == 9999


def test_beaconing_solo_cuentan_syn_puros(tmp_path):
    synack = [tcp(i * 30.0, dst=PUB, dport=8443, flags=SYNACK) for i in range(10)]
    ack = [tcp(i * 30.0, dst=PUB, dport=8443, flags=ACK) for i in range(10)]
    assert run(tmp_path, "beaconing", synack + ack) == []


def test_beaconing_una_alerta_por_clave_y_claves_distintas_separadas(tmp_path):
    a = beacon_syns([i * 30.0 for i in range(40)], dport=8443)
    b = beacon_syns([i * 30.0 for i in range(40)], dport=9443)
    c = beacon_syns([i * 30.0 for i in range(40)], dst=PUB2)
    alerts = run(tmp_path, "beaconing", a + b + c)
    assert len(alerts) == 3
    assert {(x.dst_ip, x.evidence["destination_port"]) for x in alerts} == {(PUB, 8443), (PUB, 9443), (PUB2, 8443)}


def test_beaconing_destinos_mezclados_no_se_confunden(tmp_path):
    """Intercalar dos destinos: cada uno es regular por separado y debe detectarse por separado."""
    mix = []
    for i in range(10):
        mix += beacon_syns([i * 30.0], dst=PUB) + beacon_syns([i * 30.0 + 7], dst=PUB2)
    assert len(run(tmp_path, "beaconing", mix)) == 2


def test_beaconing_marcas_repetidas_con_intervalo_cero_no_dividen_por_cero(tmp_path):
    assert run(tmp_path, "beaconing", beacon_syns([5.0] * 20)) == []


def test_beaconing_guarda_a_lo_sumo_200_instantes():
    det = X.BeaconingDetector(make_rules_obj("beaconing", {"min_events": 1000}))
    for i in range(500):
        det.feed(dec(i * 60.0, proto=17, dport=9999))
    assert len(next(iter(det._times.values()))) == X._MAX_TRACKED_EVENTS


def make_rules_obj(detector, params=None):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        return make_rules(Path(d), detector, params)[0]


def test_beaconing_lru_acotado():
    det = X.BeaconingDetector(make_rules_obj("beaconing"))
    det._times.maxsize = 3
    for i in range(10):
        det.feed(dec(1.0, dst=f"45.0.0.{i}", dport=8443))
    assert len(det._times) == 3
    assert [k[2] for k in det._times] == ["45.0.0.7", "45.0.0.8", "45.0.0.9"]  # quedan los mas recientes


def test_beaconing_lru_de_alertadas_acotado():
    det = X.BeaconingDetector(make_rules_obj("beaconing", {"min_events": 4}))
    det._alerted.maxsize = 2
    for n in range(5):
        for i in range(4):
            det.feed(dec(i * 30.0, dst=f"45.0.1.{n}", dport=8443))
    assert len(det._alerted) == 2


def test_beaconing_regularidad_directa():
    det = X.BeaconingDetector(make_rules_obj("beaconing"))
    assert det._regularity([0.0, 10.0, 20.0]) == (10.0, 0.0)
    mean, jitter = det._regularity([0.0, 0.0, 0.0])
    assert mean == 0.0 and jitter == float("inf")


# ================================================================= syn_flood

def syns(n, start=0.0, step=0.01, dst="10.0.0.2", dport=80, many_sources=True):
    return [tcp(start + i * step, src=f"192.168.{i // 250}.{i % 250 + 1}" if many_sources else "192.168.0.9",
                dst=dst, sport=1024 + i, dport=dport, flags=SYN) for i in range(n)]


def test_syn_flood_250_syn_en_2s_alerta(tmp_path):
    alerts = run(tmp_path, "syn_flood", syns(250, step=2 / 250))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.dst_ip == "10.0.0.2" and a.first_ts == 0.0
    ev = a.evidence
    assert ev["syn_packets"] == 200 and ev["distinct_sources"] == 200 and ev["destination_port"] == 80
    assert 0 < ev["window_seconds"] <= 10


def test_syn_flood_un_solo_origen(tmp_path):
    a = run(tmp_path, "syn_flood", syns(250, step=0.01, many_sources=False))
    assert a[0].evidence["distinct_sources"] == 1


def test_syn_flood_100_syn_no_alerta(tmp_path):
    assert run(tmp_path, "syn_flood", syns(100, step=0.01)) == []


def test_syn_flood_lento_250_syn_en_10min_no_alerta(tmp_path):
    assert run(tmp_path, "syn_flood", syns(250, step=600 / 250)) == []


def test_syn_flood_tras_una_fase_lenta_una_rafata_si_alerta(tmp_path):
    pk = syns(150, step=5.0) + syns(250, start=1000.0, step=0.01)
    assert len(run(tmp_path, "syn_flood", pk)) == 1


def test_syn_flood_syn_ack_y_ack_se_ignoran(tmp_path):
    synack = [tcp(i * 0.001, src=f"1.1.{i // 250}.{i % 250}", dst="10.0.0.2", flags=SYNACK) for i in range(300)]
    ack = [tcp(i * 0.001, dst="10.0.0.2", flags=ACK) for i in range(300)]
    assert run(tmp_path, "syn_flood", synack + ack) == []


def test_syn_flood_cuenta_por_destino_y_puerto(tmp_path):
    pk = syns(150, dport=80) + syns(150, dport=81, start=0.001)
    assert run(tmp_path, "syn_flood", pk) == []
    pk = syns(300, dport=80)[:150] + syns(300, dst="10.0.0.3")[:150]
    assert run(tmp_path, "syn_flood", pk) == []


def test_syn_flood_una_alerta_por_destino_y_puerto(tmp_path):
    pk = syns(500, step=0.001)
    assert len(run(tmp_path, "syn_flood", pk)) == 1
    two = syns(300, step=0.001, dport=80) + syns(300, step=0.001, dport=443)
    assert len(run(tmp_path, "syn_flood", two)) == 2


def test_syn_flood_params(tmp_path):
    assert len(run(tmp_path, "syn_flood", syns(20, step=0.1), {"min_syns": 20, "window_seconds": 5})) == 1
    assert run(tmp_path, "syn_flood", syns(20, step=1.0), {"min_syns": 20, "window_seconds": 5}) == []
    assert len(run(tmp_path, "syn_flood", syns(20, step=1.0), {"min_syns": 20, "window_seconds": 30})) == 1


def test_syn_flood_udp_y_syn_con_payload(tmp_path):
    pk = [udp(i * 0.001, dst="10.0.0.2", dport=80, payload=b"x") for i in range(300)]
    assert run(tmp_path, "syn_flood", pk) == []


def test_syn_flood_lru():
    det = X.SynFloodDetector(make_rules_obj("syn_flood"))
    det._seen.maxsize = 2
    for i in range(6):
        det.feed(dec(0.0, dst=f"45.0.0.{i}", dport=80))
    assert len(det._seen) == 2


# ================================================================= suspicious_ports

def test_suspicious_ports_syn_a_4444_alerta(tmp_path):
    a = run(tmp_path, "suspicious_ports", [tcp(1.0, src="10.0.0.5", dst=PUB, sport=51000, dport=4444, flags=SYN)])
    assert len(a) == 1
    assert (a[0].src_ip, a[0].dst_ip, a[0].evidence) == ("10.0.0.5", PUB, {"port": 4444, "source_port": 51000})


@pytest.mark.parametrize("port", [4444, 31337, 1337, 12345, 54321, 9001])
def test_suspicious_ports_lista_por_defecto(tmp_path, port):
    assert len(run(tmp_path, "suspicious_ports", [tcp(1.0, dport=port)])) == 1


def test_suspicious_ports_puertos_normales_no(tmp_path):
    assert run(tmp_path, "suspicious_ports", [tcp(1.0, dport=p) for p in (80, 443, 22, 4443, 4445)]) == []


def test_suspicious_ports_respuesta_synack_al_puerto_efimero_no_alerta(tmp_path):
    pk = [tcp(1.0, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=4444, flags=SYNACK),
          tcp(2.0, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=4444, flags=ACK),
          tcp(3.0, dport=4444, flags=ACK, payload=b"data")]
    assert run(tmp_path, "suspicious_ports", pk) == []


def test_suspicious_ports_udp_no_cuenta(tmp_path):
    assert run(tmp_path, "suspicious_ports", [udp(1.0, dport=4444, payload=b"x")]) == []


def test_suspicious_ports_personalizado_reemplaza_la_lista(tmp_path):
    pk = [tcp(1.0, dport=4444), tcp(2.0, dport=8080)]
    a = run(tmp_path, "suspicious_ports", pk, {"ports": [8080]})
    assert [x.evidence["port"] for x in a] == [8080]


def test_suspicious_ports_dedupe_por_origen_destino_puerto(tmp_path):
    pk = [tcp(float(i), sport=40000 + i, dport=4444) for i in range(5)]
    assert len(run(tmp_path, "suspicious_ports", pk)) == 1
    pk = [tcp(1.0, src="10.0.0.1", dport=4444), tcp(2.0, src="10.0.0.9", dport=4444),
          tcp(3.0, src="10.0.0.1", dport=31337), tcp(4.0, src="10.0.0.1", dst=PUB, dport=4444)]
    assert len(run(tmp_path, "suspicious_ports", pk)) == 4


def test_suspicious_ports_lru():
    det = X.SuspiciousPortsDetector(make_rules_obj("suspicious_ports"))
    det._alerted.maxsize = 2
    for i in range(5):
        det.feed(dec(0.0, dst=f"45.0.0.{i}", dport=4444))
    assert len(det._alerted) == 2


# ================================================================= dns_unusual_resolver

def q(ts, dst, name="example.com", src="10.0.0.1", qr=False):
    return udp(ts, src=src, dst=dst, dport=53, payload=dns_query(name, qr=qr))


def test_dns_resolvedor_publico_desconocido_alerta(tmp_path):
    a = run(tmp_path, "dns_unusual_resolver", [q(1.0, PUB, "Evil.Example.COM")])
    assert len(a) == 1
    assert (a[0].src_ip, a[0].dst_ip) == ("10.0.0.1", PUB)
    assert a[0].evidence == {"resolver": PUB, "first_query": "evil.example.com", "qtype": 1}


@pytest.mark.parametrize("dst", ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222"])
def test_dns_resolvedores_publicos_conocidos_permitidos(tmp_path, dst):
    assert run(tmp_path, "dns_unusual_resolver", [q(1.0, dst)]) == []


@pytest.mark.parametrize("dst", ["10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "169.254.1.1",
                                 "100.64.0.1", "0.0.0.0"])
def test_dns_destinos_no_globales_nunca_alertan(tmp_path, dst):
    assert run(tmp_path, "dns_unusual_resolver", [q(1.0, dst)]) == []


def test_dns_respuestas_qr1_se_ignoran(tmp_path):
    assert run(tmp_path, "dns_unusual_resolver", [q(1.0, PUB, qr=True)]) == []


def test_dns_basura_y_vacio_se_ignoran(tmp_path):
    pk = [udp(1.0, dst=PUB, dport=53, payload=b"\xff" * 30), udp(2.0, dst=PUB, dport=53, payload=b"\x00"),
          udp(3.0, dst=PUB, dport=53, payload=b""), udp(4.0, dst=PUB, dport=53, payload=b"basura" * 10)]
    assert run(tmp_path, "dns_unusual_resolver", pk) == []


def test_dns_sin_pregunta_se_ignora(tmp_path):
    empty = bytes(dpkt.dns.DNS(id=1, op=dpkt.dns.DNS_RD))
    assert run(tmp_path, "dns_unusual_resolver", [udp(1.0, dst=PUB, dport=53, payload=empty)]) == []


def test_dns_otro_puerto_o_tcp_se_ignora(tmp_path):
    pk = [udp(1.0, dst=PUB, dport=5353, payload=dns_query("a.com")), tcp(2.0, dst=PUB, dport=53, payload=dns_query("a.com"))]
    assert run(tmp_path, "dns_unusual_resolver", pk) == []


def test_dns_dedupe_por_origen_y_resolvedor(tmp_path):
    pk = [q(1.0, PUB, "a.com"), q(2.0, PUB, "b.com"), q(3.0, PUB, "c.com", src="10.0.0.2"), q(4.0, PUB2, "d.com")]
    a = run(tmp_path, "dns_unusual_resolver", pk)
    assert len(a) == 3 and a[0].evidence["first_query"] == "a.com"


def test_dns_ipv6_resolvedor_raro_alerta_y_conocido_no(tmp_path):
    pay = dns_query("v6.test")
    assert run(tmp_path, "dns_unusual_resolver", [udp6(1.0, "2001:db8::1", "2606:4700:4700::1111", payload=pay)]) == []
    a = run(tmp_path, "dns_unusual_resolver", [udp6(1.0, "2001:db8::1", "2a00:1450:4001:81b::200e", payload=pay)])
    assert len(a) == 1 and a[0].evidence["resolver"] == "2a00:1450:4001:81b::200e"
    for dst in ("::1", "fe80::1", "fd00::1"):
        assert run(tmp_path, "dns_unusual_resolver", [udp6(1.0, "2001:db8::1", dst, payload=pay)]) == []


def test_dns_ipv6_conocido_en_otra_notacion_no_alerta(tmp_path):
    pk = [udp6(1.0, "2001:db8::1", "2606:4700:4700:0:0:0:0:1111", payload=dns_query("x.test"))]
    assert run(tmp_path, "dns_unusual_resolver", pk) == []


def test_dns_allowed_resolvers_personalizado(tmp_path):
    p = {"allowed_resolvers": [PUB]}
    assert run(tmp_path, "dns_unusual_resolver", [q(1.0, PUB)], p) == []
    assert len(run(tmp_path, "dns_unusual_resolver", [q(1.0, "8.8.8.8")], p)) == 1  # la lista REEMPLAZA a la de fabrica


def test_dns_allowed_resolvers_vacio_todo_publico_alerta(tmp_path):
    a = run(tmp_path, "dns_unusual_resolver", [q(1.0, "8.8.8.8"), q(2.0, "1.1.1.1")], {"allowed_resolvers": []})
    assert len(a) == 2


def test_dns_allowed_resolvers_se_normalizan_en_ipv6(tmp_path):
    rules = make_rules(tmp_path, "dns_unusual_resolver", {"allowed_resolvers": ["2A00:1450:0:0::1"]})
    assert rules[0].params["allowed_resolvers"] == ["2a00:1450::1"]


def test_dns_lru():
    det = X.DnsUnusualResolverDetector(make_rules_obj("dns_unusual_resolver"))
    det._alerted.maxsize = 2
    payload = dns_query("a.test")
    for i in range(5):
        det.feed(dec(0.0, dst=f"45.0.0.{i}", proto=17, dport=53, payload=payload))
    assert len(det._alerted) == 2


@pytest.mark.parametrize("dst", ["224.0.0.251", "239.255.255.250", "ff02::fb", "ff05::1:3"])
def test_dns_a_multicast_no_alerta(tmp_path, dst):
    if ":" in dst:
        pk = [udp6(1.0, "2001:db8::1", dst, payload=dns_query("a.test"))]
    else:
        pk = [q(1.0, dst)]
    assert run(tmp_path, "dns_unusual_resolver", pk) == []


@pytest.mark.parametrize("dst", ["224.0.0.251", "239.255.255.250"])
def test_large_upload_multicast_no_es_externo(tmp_path, dst):
    pk = upload(30, 1000, dst=dst)
    assert run(tmp_path, "large_upload", pk, {"min_bytes": 20_000}) == []
    assert len(run(tmp_path, "large_upload", pk, {"min_bytes": 20_000, "external_only": False})) == 1


def test_is_external():
    assert not X._is_external("224.0.0.251") and not X._is_external("ff02::fb") and not X._is_external("239.1.1.1")
    assert X._is_external("8.8.8.8") and X._is_external("2a00:1450::1")
    assert not any(X._is_external(x) for x in ("10.1.1.1", "127.0.0.1", "169.254.0.1", "::1", "fe80::1", "no-ip", ""))


# ================================================================= large_upload

def upload(n_packets, size, dst=PUB, src="10.0.0.1", start=0.0, sport=40000, dport=443):
    return [tcp(start + i, src=src, dst=dst, sport=sport, dport=dport, flags=ACK, payload=b"x" * size)
            for i in range(n_packets)]


def test_large_upload_12mb_a_ip_publica_alerta(tmp_path):
    a = run(tmp_path, "large_upload", upload(200, 60000))
    assert len(a) == 1
    ev = a[0].evidence
    assert (a[0].src_ip, a[0].dst_ip) == ("10.0.0.1", PUB)
    assert ev["bytes_received"] == 0 and ev["destination_port"] == 443
    assert ev["bytes_sent"] >= 10_000_000 and ev["ratio"] == float(ev["bytes_sent"])
    assert ev["bytes_sent"] < 10_000_000 + 60000  # alerta en cuanto cruza el umbral


def test_large_upload_bajo_el_umbral_no_alerta(tmp_path):
    assert run(tmp_path, "large_upload", upload(100, 60000)) == []


def test_large_upload_destino_privado_segun_external_only(tmp_path):
    pk = upload(30, 1000, dst="10.0.0.9")
    assert run(tmp_path, "large_upload", pk, {"min_bytes": 20_000}) == []
    a = run(tmp_path, "large_upload", pk, {"min_bytes": 20_000, "external_only": False})
    assert len(a) == 1 and a[0].dst_ip == "10.0.0.9"


def test_large_upload_trafico_bidireccional_bajo_ratio_no_alerta(tmp_path):
    # Intercalados: el detector decide en streaming, con lo visto hasta ese momento.
    pk = []
    for i in range(30):
        pk += upload(1, 1000, start=i * 2.0)
        if i < 20:
            pk += upload(1, 1000, dst="10.0.0.1", src=PUB, start=i * 2.0 + 1, sport=443, dport=40000)
    # 30 KB enviados vs 20 KB recibidos: ratio 1.5 < 5
    assert run(tmp_path, "large_upload", pk, {"min_bytes": 20_000}) == []


def test_large_upload_decide_en_streaming_segun_lo_visto_hasta_el_umbral(tmp_path):
    """Limitacion conocida: si lo enviado cruza el umbral ANTES de que llegue la respuesta, alerta igual."""
    pk = upload(30, 1000) + upload(20, 1000, dst="10.0.0.1", src=PUB, start=100.0, sport=443, dport=40000)
    assert len(run(tmp_path, "large_upload", pk, {"min_bytes": 20_000})) == 1


def test_large_upload_ratio_alto_con_algo_de_respuesta_alerta(tmp_path):
    pk = upload(1, 100, dst="10.0.0.1", src=PUB, start=0.0, sport=443, dport=40000) + upload(30, 1000, start=1.0)
    a = run(tmp_path, "large_upload", pk, {"min_bytes": 20_000})
    assert len(a) == 1 and a[0].evidence["bytes_received"] == 100
    assert a[0].evidence["ratio"] == round(a[0].evidence["bytes_sent"] / 100, 1)


def test_large_upload_min_ratio_parametro(tmp_path):
    back = upload(10, 1000, dst="10.0.0.1", src=PUB, sport=443, dport=40000)
    out = upload(30, 1000, start=100.0)
    assert run(tmp_path, "large_upload", back + out, {"min_bytes": 20_000}) == []  # 3x < 5
    assert len(run(tmp_path, "large_upload", back + out, {"min_bytes": 20_000, "min_ratio": 2})) == 1


def test_large_upload_payload_vacio_se_ignora(tmp_path):
    pk = [tcp(float(i), dst=PUB, flags=SYN) for i in range(5000)]
    assert run(tmp_path, "large_upload", pk, {"min_bytes": 1000}) == []


def test_large_upload_cuenta_tcp_y_udp(tmp_path):
    pk = [udp(float(i), dst=PUB, dport=9999, payload=b"x" * 1000) for i in range(30)]
    assert len(run(tmp_path, "large_upload", pk, {"min_bytes": 20_000})) == 1


def test_large_upload_una_alerta_por_par_y_pares_distintos(tmp_path):
    pk = upload(100, 1000) + upload(100, 1000, dst=PUB2, start=200.0)
    a = run(tmp_path, "large_upload", pk, {"min_bytes": 20_000})
    assert len(a) == 2


def test_large_upload_acumula_entre_conexiones_del_mismo_par(tmp_path):
    pk = upload(15, 1000, sport=1111) + upload(15, 1000, sport=2222, start=100.0)
    assert len(run(tmp_path, "large_upload", pk, {"min_bytes": 20_000})) == 1


def test_large_upload_justo_en_el_umbral(tmp_path):
    assert len(run(tmp_path, "large_upload", upload(20, 1000), {"min_bytes": 20_000})) == 1
    assert run(tmp_path, "large_upload", upload(19, 1000), {"min_bytes": 20_000}) == []


def test_large_upload_lru():
    det = X.LargeUploadDetector(make_rules_obj("large_upload"))
    det._sent.maxsize = 3
    for i in range(10):
        det.feed(dec(0.0, dst=f"45.0.0.{i}", payload=b"x"))
    assert len(det._sent) == 3


# ================================================================= validadores

def test_ports_or_empty():
    assert X._ports_or_empty([]) == []
    assert X._ports_or_empty([53, 123]) == [53, 123]
    for bad in ("53", None, [70000], [-1], [True], ["a"], 53):
        with pytest.raises(ValueError):
            X._ports_or_empty(bad)


def test_bool_validador():
    assert X._bool(True) is True and X._bool(False) is False
    for bad in (1, 0, "true", None, "yes", []):
        with pytest.raises(ValueError, match="true o false"):
            X._bool(bad)


def test_ip_list_validador():
    assert X._ip_list([]) == []
    assert X._ip_list(["8.8.8.8", "2A00:1450:0:0::1"]) == ["8.8.8.8", "2a00:1450::1"]
    for bad in ("8.8.8.8", None, {"a": 1}, ["nope"], ["8.8.8.8", "300.1.1.1"], [None], [""]):
        with pytest.raises(ValueError):
            X._ip_list(bad)


@pytest.mark.parametrize("detector,params,fragment", [
    ("beaconing", {"min_events": 3}, "min_events"),
    ("beaconing", {"min_events": "8"}, "min_events"),
    ("beaconing", {"min_events": True}, "min_events"),
    ("beaconing", {"min_interval_seconds": 0.05}, "min_interval_seconds"),
    ("beaconing", {"max_jitter": 1.5}, "max_jitter"),
    ("beaconing", {"max_jitter": -0.1}, "max_jitter"),
    ("beaconing", {"ignore_ports": "53"}, "ignore_ports"),
    ("beaconing", {"ignore_ports": [70000]}, "ignore_ports"),
    ("beaconing", {"nope": 1}, "desconocidos"),
    ("syn_flood", {"min_syns": 5}, "min_syns"),
    ("syn_flood", {"window_seconds": 0}, "window_seconds"),
    ("syn_flood", {"window_seconds": "10"}, "window_seconds"),
    ("suspicious_ports", {"ports": []}, "ports"),
    ("suspicious_ports", {"ports": [99999]}, "ports"),
    ("suspicious_ports", {"ports": "4444"}, "ports"),
    ("dns_unusual_resolver", {"allowed_resolvers": "8.8.8.8"}, "allowed_resolvers"),
    ("dns_unusual_resolver", {"allowed_resolvers": ["nope"]}, "allowed_resolvers"),
    ("dns_unusual_resolver", {"allowed_resolvers": [None]}, "allowed_resolvers"),
    ("large_upload", {"min_bytes": 10}, "min_bytes"),
    ("large_upload", {"min_ratio": 0.5}, "min_ratio"),
    ("large_upload", {"external_only": "si"}, "external_only"),
    ("large_upload", {"external_only": 1}, "external_only"),
])
def test_parametros_invalidos_nombran_archivo_y_parametro(tmp_path, detector, params, fragment):
    with pytest.raises(RuleError) as exc:
        make_rules(tmp_path, detector, params, fname="mi_regla_rota.yaml")
    assert "mi_regla_rota.yaml" in str(exc.value) and fragment in str(exc.value)


def test_parametros_validos_extremos_se_aceptan(tmp_path):
    assert make_rules(tmp_path, "beaconing", {"min_events": 4, "max_jitter": 0.0, "ignore_ports": []})
    assert make_rules(tmp_path, "beaconing", {"min_events": 1000, "max_jitter": 1.0, "min_interval_seconds": 0.1}, rid="b2")
    assert make_rules(tmp_path, "syn_flood", {"min_syns": 10, "window_seconds": 0.001}, rid="s2")
    assert make_rules(tmp_path, "large_upload", {"min_bytes": 1000, "min_ratio": 1, "external_only": False}, rid="l2")


def test_defaults_de_los_detectores(tmp_path):
    p = {d: make_rules(tmp_path, d)[0].params for d in X.DETECTORS}
    assert p["beaconing"] == {"min_events": 8, "min_interval_seconds": 5.0, "max_jitter": 0.15,
                              "ignore_ports": [53, 123, 5353, 137, 138, 1900, 67, 68]}
    assert p["syn_flood"] == {"min_syns": 200, "window_seconds": 10.0}
    assert p["suspicious_ports"] == {"ports": [4444, 31337, 1337, 12345, 54321, 9001]}
    assert "8.8.8.8" in p["dns_unusual_resolver"]["allowed_resolvers"]
    assert p["large_upload"] == {"min_bytes": 10_000_000, "min_ratio": 5.0, "external_only": True}


# ================================================================= reglas reales

def test_reglas_reales_cargan_y_mapean_a_detectores_conocidos():
    rules = load_rules(ROOT / "rules")
    assert len(rules) == 16
    # "threshold" es la regla que arma el analista desde la interfaz
    assert {r.detector for r in rules} == set(X._engine.DETECTORS) - {"threshold"}


def test_demo_sigue_dando_exactamente_3_alertas():
    from backend.domain.pcap.reader import iter_packets
    alerts = evaluate(load_rules(ROOT / "rules"), iter_packets(ROOT / "samples" / "demo.pcap"))
    assert sorted(a.rule_id for a in alerts) == ["dns_suspicious", "ftp_cleartext", "port_scan"]


# ================================================================= registro (orden de import)

def _names(first):
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        f"import {first};"
        "from backend.domain.rules import engine, extra_detectors;"
        "print(','.join(sorted(engine.DETECTORS)))"
    )
    out = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().split(",")


EXPECTED = sorted(["port_scan", "ftp_cleartext", "dns_suspicious", "beaconing", "syn_flood", "suspicious_ports",
                   "dns_unusual_resolver", "large_upload", "brute_force", "threshold", "dga_nxdomain",
                   "ja4_blocklist", "tls_certificate", "user_agent", "smb_rpc_lateral", "icmp_tunnel"])


@pytest.mark.parametrize("first", ["backend.domain.rules.engine", "backend.domain.rules.extra_detectors"])
def test_detectors_completo_sin_importar_el_orden_de_import(first):
    assert _names(first) == EXPECTED


def test_detectors_en_proceso_actual():
    assert sorted(X._engine.DETECTORS) == EXPECTED
