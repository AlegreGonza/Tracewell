"""Tests de backend/domain/rules/threat_detectors.py con tráfico sintético."""
import logging
import random
import socket
from pathlib import Path

import dpkt
import pytest
import yaml

from backend.domain.analysis.tests.test_tls import (
    cert, cert_message, client_hello, d_name, server_hello,
)
from backend.domain.analysis.tls import ja4, parse_client_hello
from backend.domain.pcap.reader import Packet
from backend.domain.rules.engine import RuleError, evaluate, load_rules
from backend.domain.rules.tests.test_engine import SYN, SYNACK, _eth, _ip, tcp, udp

ROOT = Path(__file__).resolve().parents[4]
PUB, PUB2 = "45.33.32.156", "185.199.108.153"
CC = {"technique": "T1071", "name": "n", "tactic": "Command and Control"}


def rules_for(tmp_path, detector, params=None, rid=None, mitre=None):
    rid = rid or detector
    data = {"id": rid, "name": rid, "description": "d", "severity": "medium", "detector": detector,
            "mitre": mitre or CC}
    if params is not None:
        data["params"] = params
    f = tmp_path / f"{rid}.yaml"
    f.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_rules(f)


def run(tmp_path, detector, packets, params=None):
    return evaluate(rules_for(tmp_path, detector, params), packets)


def shipped(rule_id, packets):
    """Alertas de UNA regla incluida en `rules/`, con sus valores por defecto."""
    rules = [r for r in load_rules(ROOT / "rules") if r.id == rule_id]
    assert len(rules) == 1
    return evaluate(rules, packets)


def icmp(ts, src="10.0.0.1", dst="10.0.0.2", size=56, kind=8):
    echo = dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"A" * size)
    msg = dpkt.icmp.ICMP(type=kind, code=0, data=echo)
    raw = bytes(_eth(_ip(msg, dpkt.ip.IP_PROTO_ICMP, src, dst)))
    return Packet(ts, raw, len(raw))


def icmp6(ts, src="fd00::1", dst="fd00::2", size=56, kind=128):
    echo = dpkt.icmp6.ICMP6.Echo(id=1, seq=1, data=b"A" * size)
    msg = dpkt.icmp6.ICMP6(type=kind, code=0, data=echo)
    ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src), dst=socket.inet_pton(socket.AF_INET6, dst),
                      nxt=dpkt.ip.IP_PROTO_ICMP6, plen=len(bytes(msg)), data=msg)
    raw = bytes(_eth(ip, dpkt.ethernet.ETH_TYPE_IP6))
    return Packet(ts, raw, len(raw))


# ====================================================================== DGA / NXDOMAIN

def nx(ts, name, client="10.0.0.5", resolver="10.0.0.1", rcode=3):
    msg = dpkt.dns.DNS(id=7, qr=1, rcode=rcode, qd=[dpkt.dns.DNS.Q(name=name, type=1)])
    return udp(ts, src=resolver, dst=client, sport=53, dport=40000, payload=bytes(msg))


def random_names(n, seed=1):
    rng = random.Random(seed)
    return [("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(12, 16))) + ".com")
            for _ in range(n)]


def human_names(n):
    return [f"printer{i}.officenetwork.com" for i in range(n)]


def test_dga_dispara_con_nxdomain_aleatorios(tmp_path):
    packets = [nx(i, name) for i, name in enumerate(random_names(20))]
    (a,) = run(tmp_path, "dga_nxdomain", packets)
    assert (a.src_ip, a.dst_ip) == ("10.0.0.5", "10.0.0.1")  # cliente -> resolvedor
    assert a.evidence["nxdomain_count"] == 20 and a.evidence["random_looking"] >= 10
    assert len(a.evidence["sample_domains"]) == 10 and a.evidence["resolver"] == "10.0.0.1"


def test_dga_no_dispara_bajo_el_umbral(tmp_path):
    packets = [nx(i, name) for i, name in enumerate(random_names(19))]
    assert run(tmp_path, "dga_nxdomain", packets) == []


def test_dga_control_de_falsos_positivos_nombres_legibles(tmp_path):
    """Muchos NXDOMAIN de nombres humanos (sufijo de búsqueda mal puesto) no es DGA."""
    assert run(tmp_path, "dga_nxdomain", [nx(i, n) for i, n in enumerate(human_names(60))]) == []


def test_dga_ratio_cero_alcanza_con_el_volumen(tmp_path):
    packets = [nx(i, n) for i, n in enumerate(human_names(20))]
    assert len(run(tmp_path, "dga_nxdomain", packets, {"min_random_ratio": 0})) == 1


def test_dga_fuera_de_la_ventana_no_cuenta(tmp_path):
    packets = [nx(i * 10, name) for i, name in enumerate(random_names(20))]  # 190 s para 20
    assert run(tmp_path, "dga_nxdomain", packets) == []
    assert len(run(tmp_path, "dga_nxdomain", packets, {"window_seconds": 300})) == 1


def test_dga_ignora_respuestas_que_no_son_nxdomain_y_consultas(tmp_path):
    noerror = [nx(i, n, rcode=0) for i, n in enumerate(random_names(30))]
    queries = [udp(i, dport=53, payload=bytes(dpkt.dns.DNS(id=1, qd=[dpkt.dns.DNS.Q(name=n, type=1)])))
               for i, n in enumerate(random_names(30))]
    assert run(tmp_path, "dga_nxdomain", noerror + queries) == []


def test_dga_ignore_suffixes(tmp_path):
    packets = [nx(i, n) for i, n in enumerate(random_names(20))]
    assert len(run(tmp_path, "dga_nxdomain", packets)) == 1
    assert run(tmp_path, "dga_nxdomain", packets, {"ignore_suffixes": ["com"]}) == []
    assert run(tmp_path, "dga_nxdomain", [nx(i, f"{i}x.lan.local") for i in range(40)]) == []  # local ignorado


def test_dga_basura_no_lanza(tmp_path):
    junk = [udp(i, sport=53, dport=4000, payload=b"\xff" * 12) for i in range(5)]
    assert run(tmp_path, "dga_nxdomain", junk) == []


def test_dga_una_alerta_por_cliente_y_clientes_separados(tmp_path):
    names = random_names(40)
    a = [nx(i, n) for i, n in enumerate(names[:20])] + [nx(100 + i, n) for i, n in enumerate(names[20:])]
    b = [nx(i, n, client="10.0.0.6") for i, n in enumerate(names[:19])]  # solo 19
    alerts = run(tmp_path, "dga_nxdomain", sorted(a + b, key=lambda p: p.ts))
    assert [x.src_ip for x in alerts] == ["10.0.0.5"]


def test_dga_regla_incluida(tmp_path):
    alerts = shipped("dga_nxdomain", [nx(i, n) for i, n in enumerate(random_names(25))])
    assert len(alerts) == 1 and alerts[0].mitre_technique == "T1568.002"


# ====================================================================== JA4

def hello_ja4(**kw):
    data = client_hello(**kw)
    return data, ja4(parse_client_hello(data))


def tls_pkt(ts, payload, src="10.0.0.1", dst=PUB, sport=40000, dport=443, flags=0x18):
    return tcp(ts, src=src, dst=dst, sport=sport, dport=dport, flags=flags, payload=payload)


def ja4_rule(tmp_path, csv_text=None, params=None):
    base = dict(params or {})
    if csv_text is not None:
        (tmp_path / "data").mkdir(exist_ok=True)
        (tmp_path / "data" / "ja4.csv").write_text(csv_text, encoding="utf-8")
        base.setdefault("fingerprints_file", "data/ja4.csv")
    return rules_for(tmp_path, "ja4_blocklist", base)


def test_ja4_coincide_con_la_lista(tmp_path):
    data, fp = hello_ja4()
    rules = ja4_rule(tmp_path, f"# comentario\n\n{fp},Malware de prueba,https://ejemplo.invalid/ref\n")
    (a,) = evaluate(rules, [tls_pkt(1, data)])
    assert a.evidence["ja4"] == fp and a.evidence["label"] == "Malware de prueba"
    assert a.evidence["reference"] == "https://ejemplo.invalid/ref"
    assert a.evidence["sni"] == "www.example.com" and (a.src_ip, a.dst_ip) == ("10.0.0.1", PUB)


def test_ja4_otra_huella_no_alerta(tmp_path):
    data, _ = hello_ja4()
    _, other = hello_ja4(ciphers=(0x1302, 0xC030, 0x002F))
    assert evaluate(ja4_rule(tmp_path, f"{other},x\n"), [tls_pkt(1, data)]) == []


def test_ja4_huellas_en_linea_y_mayusculas_en_el_csv(tmp_path):
    data, fp = hello_ja4()
    assert len(evaluate(ja4_rule(tmp_path, params={"fingerprints": [fp.upper()]}), [tls_pkt(1, data)])) == 1
    rules = ja4_rule(tmp_path, fp.upper() + "\n")
    assert len(evaluate(rules, [tls_pkt(1, data)])) == 1


def test_ja4_una_alerta_por_origen_destino_y_huella(tmp_path):
    data, fp = hello_ja4()
    rules = ja4_rule(tmp_path, f"{fp}\n")
    pk = [tls_pkt(1, data), tls_pkt(2, data, sport=40001), tls_pkt(3, data, dst=PUB2)]
    assert [a.dst_ip for a in evaluate(rules, pk)] == [PUB, PUB2]


def test_ja4_saludo_partido_en_dos_segmentos(tmp_path):
    data, fp = hello_ja4()
    rules = ja4_rule(tmp_path, f"{fp}\n")
    cut = len(data) - 20
    assert len(evaluate(rules, [tls_pkt(1, data[:cut]), tls_pkt(2, data[cut:])])) == 1


def test_ja4_linea_invalida_se_ignora_y_avisa(tmp_path, caplog):
    data, fp = hello_ja4()
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        rules = ja4_rule(tmp_path, f"no-es-una-huella,x\n{fp},ok\n")
    assert len(evaluate(rules, [tls_pkt(1, data)])) == 1
    assert "huella JA4 inválida" in caplog.text


def test_ja4_archivo_inexistente_no_tumba_el_analisis(tmp_path, caplog):
    data, _ = hello_ja4()
    with caplog.at_level(logging.WARNING, logger="tracewell"):
        rules = rules_for(tmp_path, "ja4_blocklist", {"fingerprints_file": "data/no_existe.csv"})
    assert evaluate(rules, [tls_pkt(1, data)]) == [] and "no se pudo leer" in caplog.text


@pytest.mark.parametrize("path", ["../fuera.csv", "/etc/passwd", "C:/Windows/x.csv"])
def test_ja4_ruta_del_archivo_no_puede_salir_de_la_carpeta(tmp_path, path):
    if not (path.startswith("/") or path[1:3] == ":/" or ".." in path):
        pytest.skip("no aplica")
    with pytest.raises((RuleError, ValueError)):
        rules_for(tmp_path, "ja4_blocklist", {"fingerprints_file": path})


def test_ja4_huella_en_linea_invalida_es_error(tmp_path):
    with pytest.raises(RuleError, match="JA4"):
        rules_for(tmp_path, "ja4_blocklist", {"fingerprints": ["xyz"]})


def test_ja4_regla_incluida_carga_con_lista_vacia():
    data, _ = hello_ja4()
    assert shipped("malicious_ja4", [tls_pkt(1, data)]) == []
    assert (ROOT / "rules" / "data" / "ja4_malicious.csv").is_file()


def test_ja4_ignora_trafico_que_no_es_hello(tmp_path):
    rules = ja4_rule(tmp_path, params={"fingerprints": ["t13d1516h2_8daaf6152771_b186095e22b6"]})
    assert evaluate(rules, [tls_pkt(1, b"GET / HTTP/1.1\r\n\r\n"), tls_pkt(2, b"\x16\x03\x01\x00")]) == []


# ====================================================================== certificados TLS

SELF = d_name(cn="srv.evil.example")
VALID_NA = ("490101000000Z", False)
OLD_NA = ("200101000000Z", False)
NOW = 1_700_000_000.0  # 2023


def server_pkts(der, ts=NOW, src=PUB, dst="10.0.0.1", split=0, version=0x0303, extra=()):
    hello = server_hello(version=version if version != 0x0304 else 0x0303, exts=extra)
    flight = cert_message(der)
    pk = [tcp(ts, src=src, dst=dst, sport=443, dport=40000, flags=0x18, payload=hello)]
    parts = [flight[:split], flight[split:]] if split else [flight]
    return pk + [tcp(ts + 0.01 * (i + 1), src=src, dst=dst, sport=443, dport=40000, flags=0x18, payload=p)
                 for i, p in enumerate(parts)]


def test_cert_autofirmado_alerta(tmp_path):
    (a,) = run(tmp_path, "tls_certificate", server_pkts(cert(subject=SELF, issuer=SELF, na=VALID_NA)))
    assert "certificado autofirmado" in a.evidence["reasons"] and a.evidence["self_signed"] is True
    assert (a.src_ip, a.dst_ip) == ("10.0.0.1", PUB) and a.evidence["subject"] == "srv.evil.example"
    assert len(a.evidence["sha256"]) == 64 and a.evidence["server_port"] == 443


def test_cert_vencido_alerta_con_la_hora_de_la_captura(tmp_path):
    der = cert(na=OLD_NA)
    (a,) = run(tmp_path, "tls_certificate", server_pkts(der))
    assert a.evidence["reasons"] == ["certificado vencido el 2020-01-01"]
    # Con la captura de antes del vencimiento (2019) el mismo certificado era válido
    assert run(tmp_path, "tls_certificate", server_pkts(der, ts=1_560_000_000.0)) == []


def test_cert_valido_y_firmado_por_ca_no_alerta(tmp_path):
    assert run(tmp_path, "tls_certificate", server_pkts(cert(na=VALID_NA))) == []


def test_cert_servidor_interno_no_alerta_salvo_que_se_pida(tmp_path):
    der = cert(subject=SELF, issuer=SELF, na=VALID_NA)
    pk = server_pkts(der, src="192.168.1.5")
    assert run(tmp_path, "tls_certificate", pk) == []
    assert len(run(tmp_path, "tls_certificate", pk, {"external_only": False})) == 1


def test_cert_banderas_se_pueden_apagar(tmp_path):
    der = cert(subject=SELF, issuer=SELF, na=OLD_NA)
    both = run(tmp_path, "tls_certificate", server_pkts(der))[0].evidence["reasons"]
    assert len(both) == 2
    only = run(tmp_path, "tls_certificate", server_pkts(der), {"flag_expired": False})[0].evidence["reasons"]
    assert only == ["certificado autofirmado"]
    assert run(tmp_path, "tls_certificate", server_pkts(der), {"flag_expired": False, "flag_self_signed": False}) == []


def test_cert_en_dos_segmentos(tmp_path):
    der = cert(subject=SELF, issuer=SELF, na=VALID_NA)
    assert len(run(tmp_path, "tls_certificate", server_pkts(der, split=40))) == 1


def test_cert_tls13_no_se_evalua(tmp_path):
    der = cert(subject=SELF, issuer=SELF, na=VALID_NA)
    pk = server_pkts(der, version=0x0304, extra=(b"\x00\x2b\x00\x02\x03\x04",))
    assert run(tmp_path, "tls_certificate", pk) == []


def test_cert_una_alerta_por_servidor_y_certificado(tmp_path):
    der = cert(subject=SELF, issuer=SELF, na=VALID_NA)
    pk = server_pkts(der) + server_pkts(der, ts=NOW + 10)
    assert len(run(tmp_path, "tls_certificate", pk)) == 1


def test_cert_basura_no_lanza(tmp_path):
    junk = [tcp(1, src=PUB, sport=443, dport=40000, flags=0x18, payload=b"\x16\x03\x03\x00\x05\x02\xff\xff\xff\x00")]
    assert run(tmp_path, "tls_certificate", junk) == []


# ====================================================================== User-Agent

def http(ts, ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", path="/", src="10.0.0.1", dst=PUB,
         dport=80, headers=None, method="GET"):
    lines = [f"{method} {path} HTTP/1.1", "Host: www.example.com"]
    if ua is not None:
        lines.append(f"User-Agent: {ua}")
    lines += headers or []
    return tcp(ts, src=src, dst=dst, dport=dport, flags=0x18, payload=("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))


SCAN = {"patterns": ["sqlmap", "nmap"]}


@pytest.mark.parametrize("ua", ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"])
def test_ua_herramienta_conocida(tmp_path, ua):
    (a,) = run(tmp_path, "user_agent", [http(1, ua=ua, path="/login?id=1&pw=secreto")], SCAN)
    assert a.evidence["user_agent"] == ua and a.evidence["path"] == "/login"  # sin la query
    assert a.evidence["host"] == "www.example.com" and a.evidence["method"] == "GET"
    assert a.evidence["reasons"][0].startswith("contiene")


def test_ua_navegador_normal_no_alerta(tmp_path):
    params = {"patterns": ["curl/"], "flag_empty": True, "min_length": 6}
    assert run(tmp_path, "user_agent", [http(1), http(2, ua="okhttp/4.12.0")], params) == []


def test_ua_vacio_y_ausente(tmp_path):
    (a,) = run(tmp_path, "user_agent", [http(1, ua="")], {"flag_empty": True})
    assert a.evidence["reasons"] == ["User-Agent vacío"]
    assert run(tmp_path, "user_agent", [http(1, ua="")], {}) == []
    absent = http(1, ua=None)
    assert run(tmp_path, "user_agent", [absent], {"flag_empty": True}) == []  # ausente no es vacío
    (b,) = run(tmp_path, "user_agent", [absent], {"flag_missing": True})
    assert b.evidence["reasons"] == ["sin User-Agent"]


def test_ua_ausente_en_cabecera_incompleta_no_se_acusa(tmp_path):
    partial = tcp(1, dst=PUB, dport=80, flags=0x18, payload=b"GET / HTTP/1.1\r\nHost: a\r\n")  # sin \r\n\r\n
    assert run(tmp_path, "user_agent", [partial], {"flag_missing": True}) == []


def test_ua_muy_corto(tmp_path):
    (a,) = run(tmp_path, "user_agent", [http(1, ua="x1")], {"min_length": 6})
    assert "muy corto (2 caracteres)" in a.evidence["reasons"]
    assert run(tmp_path, "user_agent", [http(1, ua="x1")], {"min_length": 0}) == []


def test_ua_dedupe_y_puertos(tmp_path):
    pk = [http(1, ua="curl/8.0", dport=8080), http(2, ua="curl/8.0", dport=8080), http(3, ua="curl/8.0", dport=80)]
    assert len(run(tmp_path, "user_agent", pk, {"patterns": ["curl/"]})) == 1  # una por origen, destino y agente
    only = run(tmp_path, "user_agent", pk[2:], {"patterns": ["curl/"], "ports": [8080]})
    assert only == []
    assert len(run(tmp_path, "user_agent", pk, {"patterns": ["curl/"], "ports": [8080]})) == 1


def test_ua_texto_que_no_es_http_y_binario_no_lanzan(tmp_path):
    odd = [tcp(1, flags=0x18, payload=p) for p in (b"GET algo raro\r\n", b"GET / HTTP/1.1\xff\xfe", b"POST ", b"")]
    assert run(tmp_path, "user_agent", odd, {"patterns": ["x"], "flag_empty": True, "flag_missing": True}) == []


def test_ua_se_sanea_y_se_trunca(tmp_path):
    ua = "sqlmap\x01\x02" + "A" * 400
    (a,) = run(tmp_path, "user_agent", [http(1, ua=ua)], SCAN)
    assert len(a.evidence["user_agent"]) == 200 and "\x01" not in a.evidence["user_agent"]


def test_ua_reglas_incluidas():
    assert [a.rule_id for a in shipped("user_agent_scanner", [http(1, ua="sqlmap/1.7")])] == ["user_agent_scanner"]
    assert shipped("user_agent_scanner", [http(1, ua="curl/8.0")]) == []
    assert len(shipped("user_agent_script", [http(1, ua="python-requests/2.31.0")])) == 1
    assert len(shipped("user_agent_script", [http(1, ua="")])) == 1
    assert shipped("user_agent_script", [http(1, ua=None)]) == []  # sin cabecera: no por defecto


# ====================================================================== SMB / RPC lateral

def syn_to(ts, dst, dport=445, src="192.168.1.10"):
    return tcp(ts, src=src, dst=dst, dport=dport, flags=SYN)


def lan(n):
    return [f"192.168.1.{100 + i}" for i in range(n)]


def test_smb_dispara_con_muchos_equipos_internos(tmp_path):
    pk = [syn_to(i, h, 445 if i % 2 else 135) for i, h in enumerate(lan(8))]
    (a,) = run(tmp_path, "smb_rpc_lateral", pk)
    assert a.evidence["distinct_hosts"] == 8 and a.evidence["ports"] == [135, 445]
    assert a.src_ip == "192.168.1.10" and a.evidence["threshold"] == 8


def test_smb_bajo_el_umbral_o_mismo_destino_repetido(tmp_path):
    assert run(tmp_path, "smb_rpc_lateral", [syn_to(i, h) for i, h in enumerate(lan(7))]) == []
    assert run(tmp_path, "smb_rpc_lateral", [syn_to(i, "192.168.1.9") for i in range(50)]) == []


def test_smb_destinos_publicos_no_cuentan(tmp_path):
    pk = [syn_to(i, f"45.33.32.{i + 1}") for i in range(20)]
    assert run(tmp_path, "smb_rpc_lateral", pk) == []
    assert len(run(tmp_path, "smb_rpc_lateral", pk, {"internal_only": False})) == 1


def test_smb_fuera_de_la_ventana(tmp_path):
    pk = [syn_to(i * 100, h) for i, h in enumerate(lan(8))]
    assert run(tmp_path, "smb_rpc_lateral", pk) == []
    assert len(run(tmp_path, "smb_rpc_lateral", pk, {"window_seconds": 3600})) == 1


def test_smb_otros_puertos_y_respuestas_se_ignoran(tmp_path):
    other = [syn_to(i, h, dport=8080) for i, h in enumerate(lan(10))]
    replies = [tcp(i, src=h, dst="192.168.1.10", sport=445, dport=40000, flags=SYNACK) for i, h in enumerate(lan(10))]
    assert run(tmp_path, "smb_rpc_lateral", other + replies) == []


def test_smb_allow_hosts_de_un_servidor_de_archivos(tmp_path):
    pk = [syn_to(i, h) for i, h in enumerate(lan(10))]
    assert run(tmp_path, "smb_rpc_lateral", pk, {"allow_hosts": ["192.168.1.10"]}) == []
    assert run(tmp_path, "smb_rpc_lateral", pk, {"allow_hosts": ["192.168.1.0/28"]}) == []  # cubre al origen
    assert len(run(tmp_path, "smb_rpc_lateral", pk, {"allow_hosts": ["10.9.9.9"]})) == 1


def test_smb_memoria_acotada_por_origen(tmp_path):
    rule = rules_for(tmp_path, "smb_rpc_lateral", {"min_hosts": 8, "window_seconds": 1})
    from backend.domain.rules.engine import DETECTORS
    det = DETECTORS["smb_rpc_lateral"](rule[0])
    from backend.domain.rules.engine import Decoded
    for i in range(500):  # destinos distintos pero espaciados: nunca 8 en la ventana
        det.feed(Decoded(i * 5.0, "192.168.1.10", f"192.168.{i // 250}.{i % 250 + 1}", 6, 4000, 445, SYN, b""))
    assert len(det._seen["192.168.1.10"]) <= 8


# ====================================================================== ICMP tunnel

def test_icmp_cargas_grandes(tmp_path):
    (a,) = run(tmp_path, "icmp_tunnel", [icmp(i, size=800) for i in range(10)])
    assert a.evidence["large_packets"] == 10 and a.evidence["max_payload_bytes"] == 800
    assert "10 ecos con carga >= 256 bytes" in a.evidence["reasons"]


def test_icmp_ping_normal_no_alerta(tmp_path):
    windows = [icmp(i, size=32) for i in range(100)]
    linux = [icmp(i + 200, size=56, kind=0 if i % 2 else 8) for i in range(100)]
    assert run(tmp_path, "icmp_tunnel", windows + linux) == []


def test_icmp_pocos_ecos_grandes_no_alertan(tmp_path):
    assert run(tmp_path, "icmp_tunnel", [icmp(i, size=1400) for i in range(9)]) == []  # prueba de MTU


def test_icmp_volumen_alto_con_cargas_normales(tmp_path):
    (a,) = run(tmp_path, "icmp_tunnel", [icmp(i * 0.05, size=56) for i in range(600)])
    assert a.evidence["echo_packets"] == 600 and "600 ecos en 60 s" in a.evidence["reasons"]


def test_icmp_volumen_en_bytes(tmp_path):
    pk = [icmp(i, size=200) for i in range(50)]
    (a,) = run(tmp_path, "icmp_tunnel", pk, {"min_bytes": 10_000, "min_packets": 0})
    assert a.evidence["payload_bytes"] >= 10_000


def test_icmp_ventana_fija_reinicia_contadores(tmp_path):
    pk = [icmp(i * 20, size=800) for i in range(10)]  # un eco grande cada 20 s
    assert run(tmp_path, "icmp_tunnel", pk) == []


def test_icmp_ignora_mensajes_que_no_son_eco(tmp_path):
    unreachable = [icmp(i, size=800, kind=3) for i in range(30)]
    assert run(tmp_path, "icmp_tunnel", unreachable) == []


def test_icmp_responde_y_una_sola_alerta_por_par(tmp_path):
    pk = [icmp(i, size=800, kind=0) for i in range(30)]
    assert len(run(tmp_path, "icmp_tunnel", pk)) == 1


def test_icmp_v6(tmp_path):
    assert len(run(tmp_path, "icmp_tunnel", [icmp6(i, size=800) for i in range(10)])) == 1
    assert run(tmp_path, "icmp_tunnel", [icmp6(i, size=56) for i in range(50)]) == []


def test_icmp_allow_hosts(tmp_path):
    pk = [icmp(i, size=800) for i in range(10)]
    assert run(tmp_path, "icmp_tunnel", pk, {"allow_hosts": ["10.0.0.0/24"]}) == []


def test_icmp_no_afecta_a_los_otros_detectores(tmp_path):
    """Los ecos ICMP no cuentan como subida (large_upload) ni como evento de umbral."""
    big = [icmp(i, dst=PUB, size=1400) for i in range(2000)]
    assert run(tmp_path, "large_upload", big, {"min_bytes": 1000, "min_ratio": 1.0}) == []
    assert run(tmp_path, "threshold", big, {"min_events": 2}) == []


def test_icmp_regla_incluida():
    assert len(shipped("icmp_tunnel", [icmp(i, size=900) for i in range(10)])) == 1
