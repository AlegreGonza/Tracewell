import json
from datetime import datetime, timezone

import pytest

from backend.domain.export.json_export import SCHEMA_VERSION, build_report, to_json, write_json
from backend.domain.pcap.reader import CaptureInfo
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import GroupingResult, Session
from backend.domain.sessions.query import compute_stats

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def mk_session(proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=80,
               packets=3, nbytes=300, first=10.0, last=12.5):
    return Session(proto, src, sport, dst, dport, packets, nbytes, first, last)


def mk_alert(evidence=None, **kw):
    base = dict(
        rule_id="R1", name="Scan", severity="high", mitre_technique="T1046",
        mitre_name="Network Service Discovery", mitre_tactic="Discovery",
        description="desc", src_ip="10.0.0.1", dst_ip="10.0.0.2", first_ts=10.0,
        evidence=evidence if evidence is not None else {"ports": 30},
    )
    base.update(kw)
    return Alert(**base)


@pytest.fixture
def result():
    return GroupingResult(
        sessions=[
            mk_session(),
            mk_session("UDP", sport=5353, dport=53, packets=1, nbytes=60, first=1.0, last=1.0),
            mk_session("ICMP", sport=None, dport=None, packets=2, nbytes=200),
        ],
        non_ip=4, malformed=1,
    )


INFO = CaptureInfo(format="pcap", linktype=1, snaplen=65535)

TOP_KEYS = {"schema_version", "generated_at", "source", "filters", "stats", "sessions", "alerts"}
SESSION_KEYS = {"id", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                "packets", "bytes", "first_ts", "last_ts", "duration"}


# ------------------------------------------------------------- normal
def test_reporte_normal_claves_y_contenido(result):
    r = build_report("cap.pcap", INFO, result, [mk_alert()], generated_at=FIXED)
    assert r["schema_version"] == 1 == SCHEMA_VERSION
    assert r["generated_at"] == "2026-01-02T03:04:05+00:00"
    assert r["source"] == {"file": "cap.pcap", "format": "pcap", "linktype": 1, "snaplen": 65535}
    assert r["filters"] == {}
    assert [s["id"] for s in r["sessions"]] == [0, 1, 2]
    s0 = r["sessions"][0]
    assert s0["protocol"] == "TCP" and s0["duration"] == 2.5 and s0["src_port"] == 1234
    a = r["alerts"][0]
    assert a["rule_id"] == "R1" and a["severity"] == "high"
    assert a["mitre_technique"] == "T1046" and a["evidence"] == {"ports": 30}


def test_stats_coinciden_con_compute_stats(result):
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    st = r["stats"]
    assert st["sessions"] == 3 and st["packets"] == 6 and st["bytes"] == 560
    assert st["non_ip"] == 4 and st["malformed"] == 1
    assert st["by_protocol"]["TCP"] == {"sessions": 1, "packets": 3, "bytes": 300}
    from dataclasses import asdict
    assert st == asdict(compute_stats(result))


def test_generated_at_por_defecto_es_utc_iso(result):
    r = build_report("c.pcap", INFO, result, [])
    dt = datetime.fromisoformat(r["generated_at"])
    assert dt.tzinfo is not None and dt.utcoffset().total_seconds() == 0


def test_ida_y_vuelta_json(result):
    r = build_report("c.pcap", INFO, result, [mk_alert()], generated_at=FIXED)
    assert json.loads(to_json(r)) == r
    assert json.loads(to_json(r, indent=None)) == r


def test_write_json_roundtrip(result, tmp_path):
    r = build_report("c.pcap", INFO, result, [mk_alert()], generated_at=FIXED)
    out = write_json(r, tmp_path / "out.json")
    assert out == tmp_path / "out.json"
    assert json.loads(out.read_text(encoding="utf-8")) == r
    assert not (tmp_path / "out.json.tmp").exists()


def test_alerts_acepta_iterable_generador(result):
    r = build_report("c.pcap", INFO, result, (a for a in [mk_alert(), mk_alert(rule_id="R2")]),
                     generated_at=FIXED)
    assert [a["rule_id"] for a in r["alerts"]] == ["R1", "R2"]


# ------------------------------------------------------------ privacidad
@pytest.mark.parametrize("path", [
    r"C:\Users\juan\Desktop\cap.pcap",
    "/home/juan/capturas/cap.pcap",
    "cap.pcap",
])
def test_source_solo_basename(result, path):
    r = build_report(path, INFO, result, [], generated_at=FIXED)
    assert r["source"]["file"] == "cap.pcap"
    txt = to_json(r)
    assert "juan" not in txt


def test_source_pathlib(result, tmp_path):
    r = build_report(tmp_path / "x.pcap", INFO, result, [], generated_at=FIXED)
    assert r["source"]["file"] == "x.pcap"


def test_source_none_e_info_none(result):
    r = build_report(None, None, result, [], generated_at=FIXED)
    assert r["source"] == {"file": None, "format": None, "linktype": None, "snaplen": None}
    assert json.loads(to_json(r))["source"]["file"] is None


# --------------------------------------------------- sesiones filtradas
def test_filtradas_conservan_ids_y_stats_sobre_filtradas(result):
    chosen = [result.sessions[2], result.sessions[0]]
    r = build_report("c.pcap", INFO, result, [], sessions=chosen,
                     filters={"protocol": "TCP"}, generated_at=FIXED)
    assert [s["id"] for s in r["sessions"]] == [2, 0]
    assert r["filters"] == {"protocol": "TCP"}
    assert r["stats"]["sessions"] == 2
    assert r["stats"]["packets"] == 5
    assert set(r["stats"]["by_protocol"]) == {"TCP", "ICMP"}
    # al pasar lista, non_ip/malformed no se arrastran
    assert r["stats"]["non_ip"] == 0 and r["stats"]["malformed"] == 0


def test_sesion_ajena_al_resultado_no_rompe(result):
    ajena = mk_session("UDP", src="9.9.9.9")
    r = build_report("c.pcap", INFO, result, [], sessions=[result.sessions[1], ajena],
                     generated_at=FIXED)
    assert r["sessions"][0]["id"] == 1
    assert r["sessions"][1]["id"] == 1  # fallback: índice posicional (puede colisionar)
    assert r["sessions"][1]["src_ip"] == "9.9.9.9"
    json.loads(to_json(r))


def test_sessions_lista_vacia_explicita_no_es_none(result):
    r = build_report("c.pcap", INFO, result, [], sessions=[], generated_at=FIXED)
    assert r["sessions"] == [] and r["stats"]["sessions"] == 0


# ------------------------------------------------------------------ borde
def test_sin_sesiones_ni_alertas():
    r = build_report("c.pcap", INFO, GroupingResult(), [], generated_at=FIXED)
    assert r["sessions"] == [] and r["alerts"] == []
    assert r["stats"] == {"sessions": 0, "packets": 0, "bytes": 0,
                          "by_protocol": {}, "non_ip": 0, "malformed": 0,
                          # claves ADITIVAS (schema_version sigue en 1): tope de sesiones
                          "truncated": False, "untracked_packets": 0}


def test_unicode_se_conserva_sin_escapar_y_archivo_utf8(result, tmp_path):
    ev = {"user": "Peña ñandú áéíóú", "emoji": "alerta 🚨"}
    r = build_report("c.pcap", INFO, result, [mk_alert(ev)], generated_at=FIXED)
    txt = to_json(r)
    assert "Peña ñandú áéíóú" in txt and "🚨" in txt and "\\u" not in txt
    out = write_json(r, tmp_path / "u.json")
    raw = out.read_bytes()
    assert "🚨".encode("utf-8") in raw
    assert json.loads(raw.decode("utf-8"))["alerts"][0]["evidence"] == ev


def test_caracteres_de_control_escapados_json_valido(result):
    ev = {"payload": "a\x00b\x1f\n\t\"\\c\x7f"}
    r = build_report("c.pcap", INFO, result, [mk_alert(ev)], generated_at=FIXED)
    txt = to_json(r)
    assert "\x00" not in txt and "\x1f" not in txt
    assert "\\u0000" in txt and "\\u001f" in txt
    assert json.loads(txt)["alerts"][0]["evidence"] == ev


def test_puertos_none_son_null(result):
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    icmp = r["sessions"][2]
    assert icmp["src_port"] is None and icmp["dst_port"] is None
    parsed = json.loads(to_json(r))
    assert parsed["sessions"][2]["src_port"] is None
    assert '"src_port": null' in to_json(r)


def test_numeros_grandes(result):
    big = 2 ** 70
    s = mk_session(packets=big, nbytes=big, first=1e300, last=1e300)
    r = build_report("c.pcap", INFO, GroupingResult(sessions=[s]), [], generated_at=FIXED)
    back = json.loads(to_json(r))
    assert back["sessions"][0]["bytes"] == big
    assert back["stats"]["bytes"] == big
    assert back["sessions"][0]["first_ts"] == 1e300


# ----------------------------------------------------------------- errores
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_nan_inf_en_sesion_valueerror(result, bad):
    s = mk_session(last=bad)
    r = build_report("c.pcap", INFO, GroupingResult(sessions=[s]), [], generated_at=FIXED)
    with pytest.raises(ValueError):
        to_json(r)


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_write_json_nan_no_deja_archivos(result, tmp_path, bad):
    r = build_report("c.pcap", INFO, result, [mk_alert({"x": bad})], generated_at=FIXED)
    with pytest.raises(ValueError):
        write_json(r, tmp_path / "o.json")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("bad", [{1, 2}, b"bytes", object()])
def test_evidence_no_serializable_typeerror_sin_archivo(result, tmp_path, bad):
    r = build_report("c.pcap", INFO, result, [mk_alert({"x": bad})], generated_at=FIXED)
    with pytest.raises(TypeError):
        write_json(r, tmp_path / "o.json")
    assert list(tmp_path.iterdir()) == []


def test_directorio_inexistente_error_so_sin_tmp(result, tmp_path):
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    target = tmp_path / "no_existe" / "o.json"
    with pytest.raises(OSError):
        write_json(r, target)
    assert not target.parent.exists()
    assert list(tmp_path.iterdir()) == []


def test_write_json_reemplaza_archivo_existente(result, tmp_path):
    target = tmp_path / "o.json"
    target.write_text("viejo " * 5000, encoding="utf-8")
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    write_json(r, target)
    assert json.loads(target.read_text(encoding="utf-8")) == r
    assert [p.name for p in tmp_path.iterdir()] == ["o.json"]


def test_fallo_de_serializacion_deja_archivo_anterior_intacto(result, tmp_path):
    target = tmp_path / "o.json"
    target.write_text('{"viejo": true}', encoding="utf-8")
    r = build_report("c.pcap", INFO, result, [mk_alert({"x": float("nan")})], generated_at=FIXED)
    with pytest.raises(ValueError):
        write_json(r, target)
    assert target.read_text(encoding="utf-8") == '{"viejo": true}'
    assert [p.name for p in tmp_path.iterdir()] == ["o.json"]


# ---------------------------------------------------------------- contrato
def test_contrato_claves_exactas(result):
    r = build_report("c.pcap", INFO, result, [mk_alert()], generated_at=FIXED)
    assert set(r) == TOP_KEYS
    assert set(r["source"]) == {"file", "format", "linktype", "snaplen"}
    # truncated/untracked_packets se sumaron al contrato de forma aditiva (schema_version 1)
    assert set(r["stats"]) == {"sessions", "packets", "bytes", "by_protocol", "non_ip",
                               "malformed", "truncated", "untracked_packets"}
    for s in r["sessions"]:
        assert set(s) == SESSION_KEYS
    assert set(r["alerts"][0]) == {
        "rule_id", "name", "severity", "mitre_technique", "mitre_name", "mitre_tactic",
        "description", "src_ip", "dst_ip", "first_ts", "evidence",
    }


# ------------------------------------------------- tope de sesiones (truncated)
def test_reporte_truncado_incluye_flags_en_stats(result):
    result.truncated, result.untracked_packets = True, 7
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    assert r["stats"]["truncated"] is True and r["stats"]["untracked_packets"] == 7
    back = json.loads(to_json(r))
    assert back["stats"]["truncated"] is True and back["stats"]["untracked_packets"] == 7


def test_reporte_no_truncado_flags_por_defecto(result):
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    assert r["stats"]["truncated"] is False and r["stats"]["untracked_packets"] == 0


def test_filtrado_sobre_resultado_truncado_conserva_flags(result):
    # Las cifras son de lo filtrado, pero la bandera de analisis parcial es de la captura.
    result.truncated, result.untracked_packets = True, 7
    r = build_report("c.pcap", INFO, result, [], sessions=result.sessions[:1], generated_at=FIXED)
    assert r["stats"]["truncated"] is True and r["stats"]["untracked_packets"] == 7
    # el resto de las stats siguen siendo de lo filtrado
    assert r["stats"]["sessions"] == 1 and r["stats"]["packets"] == 3 and r["stats"]["bytes"] == 300
    assert len(r["sessions"]) == 1


def test_filtrado_sobre_resultado_no_truncado_false_y_cero(result):
    r = build_report("c.pcap", INFO, result, [], sessions=result.sessions[:2], generated_at=FIXED)
    assert r["stats"]["truncated"] is False and r["stats"]["untracked_packets"] == 0
    assert r["stats"]["sessions"] == 2 and r["stats"]["packets"] == 4 and r["stats"]["bytes"] == 360


def test_sessions_lista_vacia_de_truncado_true_y_stats_en_cero(result):
    result.truncated, result.untracked_packets = True, 5
    r = build_report("c.pcap", INFO, result, [], sessions=[], generated_at=FIXED)
    st = r["stats"]
    assert st["truncated"] is True and st["untracked_packets"] == 5
    assert st["sessions"] == 0 and st["packets"] == 0 and st["bytes"] == 0
    assert r["sessions"] == []


def test_reporte_filtrado_truncado_round_trip_json(result):
    result.truncated, result.untracked_packets = True, 7
    r = build_report("c.pcap", INFO, result, [], sessions=result.sessions[1:], generated_at=FIXED)
    back = json.loads(to_json(r))
    assert back["stats"]["truncated"] is True and back["stats"]["untracked_packets"] == 7
    assert back["stats"]["sessions"] == 2


def test_no_truncado_sin_filtro_sin_cambios(result):
    r = build_report("c.pcap", INFO, result, [], generated_at=FIXED)
    st = r["stats"]
    assert st["truncated"] is False and st["untracked_packets"] == 0
    assert st["sessions"] == 3 and st["packets"] == 6 and st["bytes"] == 560
