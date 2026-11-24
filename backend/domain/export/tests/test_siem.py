"""Tests de backend/domain/export/siem.py (ECS/NDJSON, CEF y syslog)."""
import json
import re

import pytest

from backend.domain.export import siem
from backend.domain.rules.engine import MITRE_TACTICS, Alert


def mk(rule_id="port_scan", severity="high", technique="T1046", name="Network Service Discovery",
       tactic="Discovery", evidence=None, **kw):
    base = dict(
        rule_id=rule_id, name="Escaneo de puertos", severity=severity, mitre_technique=technique,
        mitre_name=name, mitre_tactic=tactic, description="Muchos SYN", src_ip="10.0.0.1", dst_ip="10.0.0.2",
        first_ts=1_700_000_000.123, evidence=evidence if evidence is not None else {"distinct_ports": 15},
    )
    base.update(kw)
    return Alert(**base)


# ------------------------------------------------------------------ ECS

def test_ecs_campos_principales():
    doc = siem.alert_to_ecs(mk(evidence={"destination_port": 445, "x": 1}))
    assert doc["@timestamp"] == "2023-11-14T22:13:20.123Z"
    assert doc["ecs"]["version"] == siem.ECS_VERSION
    assert doc["event"] == {
        "kind": "alert", "category": ["network", "intrusion_detection"], "type": ["info"],
        "severity": 73, "module": "tracewell", "dataset": "tracewell.alert",
    }
    assert doc["rule"] == {"id": "port_scan", "name": "Escaneo de puertos", "description": "Muchos SYN"}
    assert doc["source"] == {"ip": "10.0.0.1"} and doc["destination"] == {"ip": "10.0.0.2", "port": 445}
    assert doc["tracewell"] == {"severity": "high", "evidence": {"destination_port": 445, "x": 1}}


def test_ecs_threat_tecnica_y_tactica_son_listas():
    t = siem.alert_to_ecs(mk())["threat"]
    assert t["framework"] == "MITRE ATT&CK"
    assert t["tactic"] == {"name": ["Discovery"], "id": ["TA0007"],
                           "reference": ["https://attack.mitre.org/tactics/TA0007/"]}
    assert t["technique"] == {"id": ["T1046"], "name": ["Network Service Discovery"],
                              "reference": ["https://attack.mitre.org/techniques/T1046/"]}


def test_ecs_subtecnica_separa_el_nombre_del_padre():
    t = siem.alert_to_ecs(mk(technique="T1071.004", name="Application Layer Protocol: DNS",
                             tactic="Command and Control"))["threat"]
    assert t["technique"]["id"] == ["T1071"] and t["technique"]["name"] == ["Application Layer Protocol"]
    assert t["technique"]["subtechnique"] == {
        "id": ["T1071.004"], "name": ["DNS"], "reference": ["https://attack.mitre.org/techniques/T1071/004/"]}
    assert t["tactic"]["id"] == ["TA0011"]


def test_todas_las_tacticas_canonicas_tienen_id():
    assert set(siem.TACTIC_IDS) == set(MITRE_TACTICS)
    assert all(re.fullmatch(r"TA\d{4}", v) for v in siem.TACTIC_IDS.values())


def test_ecs_sin_ip_valida_o_sin_puerto_omite_los_campos():
    doc = siem.alert_to_ecs(mk(src_ip="no-ip", dst_ip="2001:db8::1", evidence={"port": True}))
    assert "source" not in doc and doc["destination"] == {"ip": "2001:db8::1"}
    assert "destination" not in siem.alert_to_ecs(mk(dst_ip="x"))


def test_ecs_severidad_y_timestamp_imposible():
    severities = [siem.alert_to_ecs(mk(severity=s))["event"]["severity"] for s in ("low", "medium", "high", "critical")]
    assert severities == [21, 47, 73, 99]
    assert siem.alert_to_ecs(mk(first_ts=1e30))["@timestamp"] == "1970-01-01T00:00:00.000Z"


def test_ndjson_una_linea_json_por_alerta():
    text = siem.to_ndjson([mk(), mk(rule_id="otra", evidence={"q": "ñandú\n"})])
    lines = text.split("\n")
    assert lines[-1] == "" and len(lines) == 3
    docs = [json.loads(line) for line in lines[:2]]
    assert [d["rule"]["id"] for d in docs] == ["port_scan", "otra"]
    assert "ñandú" in lines[1] and "\\n" in lines[1]  # UTF-8 sin escapar y el salto escapado
    assert siem.to_ndjson([]) == ""


# ------------------------------------------------------------------ CEF

def test_cef_cabecera_y_extension():
    line = siem.alert_to_cef(mk(evidence={"destination_port": 445}), "0.3.0")
    assert line.startswith("CEF:0|Tracewell|Tracewell|0.3.0|port_scan|Escaneo de puertos|8|")
    ext = line.split("|", 7)[7]
    for piece in ("rt=1700000000123", "src=10.0.0.1", "dst=10.0.0.2", "dpt=445", "cat=Discovery",
                  "msg=Muchos SYN", "cs1Label=mitreTactic cs1=Discovery", "cs2Label=mitreTechnique cs2=T1046",
                  "cs3Label=mitreTechniqueName cs3=Network Service Discovery", "cs4Label=severity cs4=high",
                  "cs5Label=evidence"):
        assert piece in ext
    assert "\n" not in line


def test_cef_escapes_en_cabecera_y_extension():
    hostile = mk(rule_id="a|b", severity="critical", description="x=1\\y\nz\r| fin", evidence={"k": "v=1"})
    hostile.name = "N|m\\\n"
    line = siem.alert_to_cef(hostile)
    assert line.startswith("CEF:0|Tracewell|Tracewell|0|a\\|b|N\\|m\\\\ |10|")
    assert "msg=x\\=1\\\\y\\nz\\r| fin" in line  # el `|` de la extensión no se escapa
    assert "\n" not in line and "\r" not in line


def test_cef_evidencia_larga_se_trunca():
    line = siem.alert_to_cef(mk(evidence={"muestra": "a" * 5000}))
    value = line.split("cs5=")[1]
    assert len(value) <= siem.MAX_CEF_EVIDENCE + 5 and value.endswith("...")


def test_to_cef_una_linea_por_alerta():
    out = siem.to_cef([mk(), mk()])
    assert out.count("\n") == 2 and out.endswith("\n") and siem.to_cef([]) == ""


# ------------------------------------------------------------------ syslog

@pytest.mark.parametrize("severity,prio", [("low", 134), ("medium", 133), ("high", 132), ("critical", 130)])
def test_syslog_5424_prioridad_local0(severity, prio):
    line = siem.alert_to_syslog(mk(severity=severity))
    assert line.startswith(f"<{prio}>1 2023-11-14T22:13:20.123Z - tracewell - ALERT - CEF:0|Tracewell|")


def test_syslog_no_filtra_nombre_de_equipo():
    assert " - tracewell - ALERT - " in siem.alert_to_syslog(mk())  # HOSTNAME = «-»


# ------------------------------------------------------------------ fachada

def test_render_formatos_y_media():
    alerts = [mk(), mk(severity="low", rule_id="b")]
    assert siem.render(alerts, "ecs").count("\n") == 2
    assert siem.render(alerts, "cef").startswith("CEF:0|")
    assert siem.render(alerts, "syslog").startswith("<")
    assert siem.media_info("ecs") == ("application/x-ndjson", "tracewell-alerts.ndjson")
    assert siem.media_info("cef")[1] == "tracewell-alerts.cef"
    assert siem.media_info("syslog")[1] == "tracewell-alerts.log"
    with pytest.raises(ValueError, match="formato"):
        siem.render(alerts, "xml")


def test_render_filtra_por_severidad_minima():
    alerts = [mk(severity="low", rule_id="l"), mk(severity="medium", rule_id="m"),
              mk(severity="high", rule_id="h"), mk(severity="critical", rule_id="c")]

    def ids(minimum):
        return [a.rule_id for a in siem.filter_min_severity(alerts, minimum)]

    assert ids(None) == ["l", "m", "h", "c"] and ids("high") == ["h", "c"] and ids("low") == ["l", "m", "h", "c"]
    rendered = siem.render(alerts, "ecs", min_severity="critical").splitlines()
    assert [json.loads(x)["rule"]["id"] for x in rendered] == ["c"]
    with pytest.raises(ValueError, match="severidad"):
        siem.filter_min_severity(alerts, "alta")


def test_la_evidencia_no_trae_rutas_ni_datos_del_equipo():
    text = siem.render([mk(evidence={"password": "<oculta>", "password_length": 7})], "ecs")
    assert "<oculta>" in text and "C:\\" not in text and "/home/" not in text
