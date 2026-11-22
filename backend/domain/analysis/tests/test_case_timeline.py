"""Cronología del caso: unión de alertas, DNS sospechoso, sesiones marcadas e IOC, en orden cronológico."""
import pytest

from backend.domain.analysis.case_timeline import MAX_LIMIT, build_case_timeline, normalize_host
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import Session


def alert(ts, src="10.0.0.5", dst="8.8.8.8", name="Alerta", rule="r1", sev="high"):
    return Alert(rule, name, sev, "T1046", "n", "Discovery", "d", src, dst, ts)


def dns(ts, name="x9f3.evil.test", clients=("10.0.0.5",), hints=("parece aleatorio",)):
    return {"name": name, "qtype": "A", "first_ts": ts, "clients": list(clients), "hints": list(hints)}


def sess(ts, src="10.0.0.5", dst="1.2.3.4", sport=5000, dport=443):
    return Session("TCP", src, sport, dst, dport, 3, 300, ts, ts + 1)


def kinds(result):
    return [e["kind"] for e in result["items"]]


# ----------------------------------------------------------- orden cronológico

def test_mezcla_las_cuatro_fuentes_en_orden_de_tiempo():
    r = build_case_timeline(
        alerts=[alert(30.0)], dns_rows=[dns(10.0)], sessions=[sess(20.0), sess(40.0, sport=1)],
        notes={0: {"note": "revisar", "reviewed": False}}, ioc_hits={1: ["ip:1.2.3.4"]},
    )
    assert kinds(r) == ["dns", "sesion", "alerta", "ioc"]
    assert [e["ts"] for e in r["items"]] == [10.0, 20.0, 30.0, 40.0]


def test_entradas_desordenadas_salen_ordenadas():
    r = build_case_timeline(alerts=[alert(300.0, name="C"), alert(100.0, name="A"), alert(200.0, name="B")])
    assert [e["title"] for e in r["items"]] == ["A", "B", "C"]


def test_a_igual_hora_el_orden_es_alerta_ioc_dns_sesion():
    r = build_case_timeline(
        alerts=[alert(5.0)], dns_rows=[dns(5.0)], sessions=[sess(5.0)], notes={0: {"reviewed": True}}, ioc_hits={0: ["ip:1.2.3.4"]},
    )
    assert kinds(r) == ["alerta", "ioc", "dns", "sesion"]


def test_a_igual_hora_y_clase_conserva_el_orden_de_llegada():
    r = build_case_timeline(alerts=[alert(5.0, name="primera"), alert(5.0, name="segunda")])
    assert [e["title"] for e in r["items"]] == ["primera", "segunda"]


def test_horas_negativas_y_cero_se_ordenan():
    r = build_case_timeline(alerts=[alert(0.0, name="cero"), alert(-5.0, name="antes")])
    assert [e["title"] for e in r["items"]] == ["antes", "cero"]


# ------------------------------------------------------------------ contenido

def test_alerta_trae_severidad_regla_y_extremos():
    e = build_case_timeline(alerts=[alert(1.0, sev="critical", rule="beaconing")])["items"][0]
    assert (e["kind"], e["severity"], e["rule_id"]) == ("alerta", "critical", "beaconing")
    assert e["ips"] == ["10.0.0.5", "8.8.8.8"] and "T1046" in e["detail"]


def test_dns_sin_pistas_se_descarta():
    r = build_case_timeline(dns_rows=[dns(1.0, hints=()), dns(2.0, name="malo.test")])
    assert [e["title"] for e in r["items"]] == ["DNS sospechoso: malo.test"]


def test_dns_lleva_los_clientes_como_ips():
    e = build_case_timeline(dns_rows=[dns(1.0, clients=("10.0.0.5", "10.0.0.6"))])["items"][0]
    assert e["ips"] == ["10.0.0.5", "10.0.0.6"] and e["qtype"] == "A"


def test_sesion_revisada_y_con_nota():
    r = build_case_timeline(sessions=[sess(1.0), sess(2.0, sport=2)], notes={0: {"reviewed": True, "note": ""}, 1: {"reviewed": False, "note": "raro"}})
    assert [e["title"] for e in r["items"]] == ["Sesión revisada", "Sesión con nota"]
    assert "raro" in r["items"][1]["detail"] and r["items"][1]["session_id"] == 1


def test_nota_vacia_y_sin_marca_no_genera_hecho():
    assert build_case_timeline(sessions=[sess(1.0)], notes={0: {"note": "  ", "reviewed": False}})["total"] == 0


def test_nota_larga_se_recorta():
    e = build_case_timeline(sessions=[sess(1.0)], notes={0: {"note": "x" * 1000, "reviewed": False}})["items"][0]
    assert len(e["detail"]) < 300


def test_ioc_trae_los_indicadores_y_la_sesion():
    e = build_case_timeline(sessions=[sess(1.0)], ioc_hits={0: ["ip:1.2.3.4", "dominio:evil.test"]})["items"][0]
    assert e["kind"] == "ioc" and "ip:1.2.3.4, dominio:evil.test" in e["title"] and e["session_id"] == 0


def test_ids_de_sesion_fuera_de_rango_se_ignoran():
    assert build_case_timeline(sessions=[sess(1.0)], notes={5: {"reviewed": True}, -1: {"reviewed": True}}, ioc_hits={9: ["x"]})["total"] == 0


def test_sin_nada_da_cronologia_vacia():
    assert build_case_timeline() == {"host": None, "total": 0, "truncated": False, "items": []}


# ----------------------------------------------------------------------- host

def test_filtra_por_host_en_todas_las_fuentes():
    r = build_case_timeline(
        alerts=[alert(1.0, src="10.0.0.5"), alert(2.0, src="10.0.0.9", dst="8.8.4.4")],
        dns_rows=[dns(3.0, clients=("10.0.0.9",))], sessions=[sess(4.0, src="10.0.0.9")], notes={0: {"reviewed": True}}, host="10.0.0.9",
    )
    assert kinds(r) == ["alerta", "dns", "sesion"] and r["host"] == "10.0.0.9"


def test_host_tambien_coincide_como_destino():
    r = build_case_timeline(alerts=[alert(1.0, src="10.0.0.5", dst="10.0.0.9")], host="10.0.0.9")
    assert r["total"] == 1


def test_host_ipv6_se_compara_normalizado():
    r = build_case_timeline(alerts=[alert(1.0, src="2001:0db8::1", dst="8.8.8.8")], host="2001:db8:0:0:0:0:0:1")
    assert r["total"] == 1


def test_host_sin_hechos_da_vacio_no_error():
    assert build_case_timeline(alerts=[alert(1.0)], host="10.9.9.9")["total"] == 0


@pytest.mark.parametrize("bad", ["no-es-ip", "300.1.1.1", 5])
def test_host_invalido_falla(bad):
    with pytest.raises(ValueError):
        build_case_timeline(host=bad)


def test_host_vacio_equivale_a_sin_filtro():
    assert normalize_host("  ") is None and normalize_host(None) is None
    assert build_case_timeline(alerts=[alert(1.0)], host="")["total"] == 1


def test_host_con_zona_ipv6():
    assert normalize_host("fe80::1%eth0") == "fe80::1"


# ----------------------------------------------------------------------- tope

def test_limit_corta_y_avisa():
    r = build_case_timeline(alerts=[alert(float(i)) for i in range(10)], limit=3)
    assert r["total"] == 10 and r["truncated"] is True and [e["ts"] for e in r["items"]] == [0.0, 1.0, 2.0]


def test_limit_exacto_no_marca_truncado():
    assert build_case_timeline(alerts=[alert(1.0)], limit=1)["truncated"] is False


@pytest.mark.parametrize("bad", [0, -1, MAX_LIMIT + 1, True, "5", None, 2.5])
def test_limit_invalido_falla(bad):
    with pytest.raises(ValueError):
        build_case_timeline(limit=bad)
