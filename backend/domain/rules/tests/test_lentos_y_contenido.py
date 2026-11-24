"""Escaneo/fuerza bruta lentos, FTP/POP3 por contenido y túneles DNS de etiquetas cortas."""
import dataclasses
import random

import pytest

from backend.domain.rules.engine import PortScanDetector, _decode, evaluate, load_rules, split_registrable
from backend.domain.rules.tests.test_engine import REAL_RULES, SYN, SYNACK, dns_pkt, mk, tcp  # noqa: F401

CLIENT, SERVER = "10.0.0.20", "10.0.0.5"


def real(rule_id):
    return [r for r in load_rules(REAL_RULES) if r.id == rule_id]


def syns(n, step, dst=SERVER, first_port=2000, flags=SYN):
    return [tcp(i * step, src=CLIENT, dst=dst, sport=40000, dport=first_port + i, flags=flags)
            for i in range(n)]


# ------------------------------------------------------- escaneo lento

def test_escaneo_lento_alerta_con_la_ventana_larga():
    (a,) = evaluate(real("port_scan"), syns(25, 10))
    assert a.evidence["window_seconds"] == 900.0 and a.evidence["threshold"] == 20
    assert a.evidence["distinct_ports"] == 20


def test_escaneo_lento_apagado_por_defecto(mk):
    assert evaluate([mk("port_scan")], syns(25, 10)) == []


@pytest.mark.parametrize("n,expected", [(19, 0), (20, 1)])
def test_escaneo_lento_borde_del_umbral(n, expected):
    assert len(evaluate(real("port_scan"), syns(n, 10))) == expected


def test_escaneo_lento_fuera_de_la_ventana_larga():
    assert evaluate(real("port_scan"), syns(30, 60)) == []  # 20 puertos tardan 1140 s


def test_puertos_con_respuesta_no_suman_en_la_ventana_larga():
    pkts = []
    for i in range(25):
        pkts.append(tcp(i * 10, src=CLIENT, dst=SERVER, sport=40000, dport=2000 + i, flags=SYN))
        pkts.append(tcp(i * 10 + 0.01, src=SERVER, dst=CLIENT, sport=2000 + i, dport=40000, flags=SYNACK))
    assert evaluate(real("port_scan"), pkts) == []


def test_escaneo_lento_no_duplica_con_el_rapido():
    assert len(evaluate(real("port_scan"), syns(40, 0.1))) == 1


def test_escaneo_lento_libera_estado_tras_alertar():
    det = PortScanDetector(real("port_scan")[0])
    for p in syns(25, 10):
        det.feed(_decode(p))
    assert len(det._seen_long) == 0 and len(det._answered) == 0


# ---------------------------------------------------- fuerza bruta lenta

def ssh(n, step, port=22):
    return [tcp(i * step, src="203.0.113.50", dst=SERVER, sport=41000 + i, dport=port, flags=SYN)
            for i in range(n)]


def test_ssh_lento_alerta_con_la_ventana_larga():
    (a,) = evaluate(real("brute_force_remote"), ssh(12, 20))
    assert a.evidence["threshold"] == 10 and a.evidence["window_seconds"] == 180.0


def test_ssh_lento_apagado_con_ventana_cero():
    rule = real("brute_force_remote")[0]
    rule = dataclasses.replace(rule, params={**rule.params, "long_window_seconds": 0.0})
    assert evaluate([rule], ssh(12, 20)) == []


def test_monitoreo_cada_60s_no_alerta():
    assert evaluate(real("brute_force_remote"), ssh(30, 60)) == []


def test_ssh_lento_borde_de_la_ventana():
    assert len(evaluate(real("brute_force_remote"), ssh(10, 33))) == 1  # 297 s
    assert evaluate(real("brute_force_remote"), ssh(10, 34)) == []  # 306 s


# ------------------------------------------------------- FTP / POP3

def cmd(ts, data, dport=2121, sport=52000):
    return tcp(ts, src=CLIENT, dst=SERVER, sport=sport, dport=dport, flags=0x18, payload=data)


def banner(ts, data, sport=2121, dport=52000):
    return tcp(ts, src=SERVER, dst=CLIENT, sport=sport, dport=dport, flags=0x18, payload=data)


def test_ftp_en_puerto_no_estandar_con_banner_220(mk):
    pkts = [banner(0, b"220 ready\r\n"), cmd(1, b"USER admin\r\n"), cmd(2, b"PASS hunter2\r\n")]
    (a,) = evaluate([mk("ftp_cleartext")], pkts)
    assert a.evidence["protocol"] == "FTP" and a.evidence["port"] == 2121
    assert a.evidence["password"] == "<oculta>" and "hunter2" not in repr(a)


def test_pop3_se_distingue_por_el_banner(mk):
    pkts = [banner(0, b"+OK POP3 ready\r\n", sport=110), cmd(1, b"USER ana\r\n", dport=110),
            cmd(2, b"PASS clave-pop\r\n", dport=110)]
    (a,) = evaluate([mk("ftp_cleartext")], pkts)
    assert a.evidence["protocol"] == "POP3" and "clave-pop" not in repr(a)


def test_user_pass_sin_banner_queda_generico(mk):
    (a,) = evaluate([mk("ftp_cleartext")], [cmd(1, b"USER a\r\n"), cmd(2, b"PASS b\r\n")])
    assert a.evidence["protocol"] == "USER/PASS"


@pytest.mark.parametrize("payloads", [
    [b"USER admin\r\n"],  # falta el PASS
    [b"PASS hunter2\r\n"],  # PASS suelto en un puerto desconocido
    [b"USER guest 0 * :Real Name\r\n", b"PASS x\r\n"],  # USER de IRC con varios argumentos
    [b"GET / HTTP/1.1\r\n", b"PASS the salt\r\n"],  # texto cualquiera
])
def test_no_marca_trafico_que_no_es_user_pass(mk, payloads):
    pkts = [cmd(i, p) for i, p in enumerate(payloads)]
    assert evaluate([mk("ftp_cleartext")], pkts) == []


def test_user_y_pass_en_flujos_distintos_no_se_juntan(mk):
    pkts = [cmd(1, b"USER bob\r\n", sport=52000), cmd(2, b"PASS pw\r\n", sport=52001)]
    assert evaluate([mk("ftp_cleartext")], pkts) == []


# ------------------------------------------------------ DNS agregado

TUNEL = "a1b2c3d4e5f6a7b8c9.0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d.t.exfil-example.net"


def test_split_registrable():
    assert split_registrable("a.b.example.com") == ("a.b", "example.com")
    assert split_registrable("example.com") == ("", "example.com")
    assert split_registrable("x.y.tienda.co.uk") == ("x.y", "tienda.co.uk")
    assert split_registrable("www.example.co") == ("www", "example.co")


def test_tunel_de_etiquetas_cortas_alerta_por_el_conjunto(mk):
    (a,) = evaluate([mk("dns_suspicious")], [dns_pkt(1, TUNEL)])
    assert any("etiquetas" in r for r in a.evidence["reasons"])


def test_agregado_apagado_con_cero(mk):
    assert evaluate([mk("dns_suspicious", min_total_length=0)], [dns_pkt(1, TUNEL)]) == []


@pytest.mark.parametrize("name", [
    "www.example.com", "mail.eu-west-1.corp.example.org", "a.b.c.d.e.example.com",
    "internal-svc-prod-alb-1234567890.us-east-1.elb.amazonaws.com",  # ignorado por sufijo
    "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijab.example.com",  # una sola etiqueta
])
def test_nombres_normales_no_alertan_por_el_agregado(name):
    alerts = evaluate(real("dns_suspicious"), [dns_pkt(1, name)])
    assert not any("etiquetas" in r for a in alerts for r in a.evidence["reasons"])


def test_agregado_borde_de_longitud(mk):
    rnd = random.Random(7)
    hexs = "".join(rnd.choice("0123456789abcdef") for _ in range(50))
    justo_debajo = f"{hexs[:20]}.{hexs[21:]}.example.net"  # 49 caracteres
    justo_en = f"{hexs[:20]}.{hexs[20:]}.example.net"  # 50 caracteres
    assert evaluate([mk("dns_suspicious")], [dns_pkt(1, justo_debajo)]) == []
    assert len(evaluate([mk("dns_suspicious")], [dns_pkt(1, justo_en)])) == 1


# ------------------------------------------------------- DNS volumen

def volume_rule(mk, **kw):
    return mk("dns_suspicious", min_total_length=0, min_unique_subdomains=10, **kw)


def many(n, step, parent="t.example.net"):
    return [dns_pkt(i * step, f"s{i}.{parent}") for i in range(n)]


def test_volumen_de_subdominios_unicos_alerta_una_vez(mk):
    alerts = evaluate([volume_rule(mk)], many(25, 1))
    assert len(alerts) == 1 and "subdominios únicos" in alerts[0].evidence["reasons"][0]


def test_volumen_apagado_por_defecto(mk):
    assert evaluate([mk("dns_suspicious")], many(25, 1)) == []


def test_volumen_fuera_de_ventana_o_repetido_no_alerta(mk):
    assert evaluate([volume_rule(mk)], many(25, 10)) == []  # 6 por ventana de 60 s
    repetidas = [dns_pkt(i, "www.example.com") for i in range(30)]
    assert evaluate([volume_rule(mk)], repetidas) == []


def test_volumen_respeta_ignore_suffixes(mk):
    rule = volume_rule(mk, ignore_suffixes=["example.net"])
    assert evaluate([rule], many(25, 1)) == []
