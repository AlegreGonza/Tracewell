"""Tests de backend/domain/export/html_report.py: escape de datos hostiles, secciones y ausencia de rutas."""
import re
from datetime import datetime, timezone

import pytest

from backend.domain.export.html_report import TOP_SESSIONS, build_html, select_ids
from backend.domain.export.json_export import build_report
from backend.domain.pcap.reader import CaptureInfo
from backend.domain.rules.engine import Alert
from backend.domain.sessions.grouper import GroupingResult, Session

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
INFO = CaptureInfo(format="pcap", linktype=1, snaplen=65535)
XSS = "<script>alert(1)</script>"


def mk_session(proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=80, nbytes=300, packets=3):
    return Session(proto, src, sport, dst, dport, packets, nbytes, 10.0, 12.5)


def mk_alert(**kw):
    base = dict(
        rule_id="R1", name="Scan", severity="high", mitre_technique="T1046",
        mitre_name="Network Service Discovery", mitre_tactic="Discovery",
        description="desc", src_ip="10.0.0.1", dst_ip="10.0.0.2", first_ts=10.0,
        evidence={"ports": 30},
    )
    base.update(kw)
    return Alert(**base)


def report_of(sessions=None, alerts=None, path="cap.pcap", **result_kw):
    result = GroupingResult(sessions=sessions if sessions is not None else [mk_session()], **result_kw)
    return build_report(path, INFO, result, alerts if alerts is not None else [mk_alert()], generated_at=FIXED)


def many_sessions(n):
    # bytes crecientes: el id n-1 es el más pesado
    return [mk_session(sport=1000 + i, nbytes=100 + i) for i in range(n)]


# ------------------------------------------------------------- estructura
def test_documento_completo_y_secciones():
    h = build_html(report_of())
    assert h.startswith("<!doctype html>") and h.rstrip().endswith("</html>")
    for t in ("<h1>Informe de triaje</h1>", "<h2>Resumen</h2>", "<h2>Alertas</h2>", "<h2>Sesiones destacadas</h2>"):
        assert t in h
    assert "2026-01-02T03:04:05" in h
    assert "<th>Archivo</th><td>cap.pcap</td>" in h
    assert "Baja" not in h and "Alta" in h  # severidad en español


def test_csp_y_sin_scripts_ni_recursos_externos():
    h = build_html(report_of())
    assert "Content-Security-Policy" in h and "default-src 'none'" in h
    assert "<script" not in h.lower()
    assert not re.search(r"(src|href)\s*=", h, re.I)
    assert "http://" not in h and "https://" not in h


def test_sin_alertas():
    h = build_html(report_of(alerts=[]))
    assert "No hay alertas." in h
    assert 'class="alert' not in h


def test_sin_sesiones_omite_seccion():
    h = build_html(report_of(sessions=[], alerts=[]))
    assert "Sesiones destacadas" not in h
    assert "<h2>Resumen</h2>" in h


def test_ioc_seccion_solo_si_hay_lista():
    assert "Indicadores (IOC)" not in build_html(report_of())
    h = build_html(report_of(), {0: {"ioc": ["ip:10.0.0.2"]}}, ioc_source="lista.txt")
    assert "Indicadores (IOC)" in h and "<code>lista.txt</code>" in h
    assert "sesiones con coincidencias: <strong>1</strong>" in h
    assert "IOC: ip:10.0.0.2" in h


def test_ioc_cargada_sin_coincidencias_cuenta_cero():
    h = build_html(report_of(), {0: {"note": "x"}}, ioc_source="l.txt")
    assert "<strong>0</strong>" in h


# ------------------------------------------------------------- aviso parcial
@pytest.mark.parametrize("kw", [{"truncated": True}, {"untracked_packets": 5}])
def test_aviso_de_analisis_parcial(kw):
    assert "Análisis parcial" in build_html(report_of(**kw))


def test_sin_aviso_parcial_en_captura_completa():
    assert "Análisis parcial" not in build_html(report_of())


# ----------------------------------------------------------------- escape
def test_alerta_hostil_se_escapa_en_todos_los_campos():
    a = mk_alert(
        name=XSS, description='"><img src=x onerror=alert(1)>', src_ip=XSS, dst_ip="<b>",
        mitre_technique="<i>", mitre_name="&amp;<", mitre_tactic="'quote'",
        evidence={"payload": XSS, "k<": "v&", "uni": "ñ\u202e✓"},
    )
    h = build_html(report_of(alerts=[a]))
    assert XSS not in h and "<img" not in h and "<b>" not in h and "<i>" not in h
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in h
    assert "&amp;amp;&lt;" in h  # '&amp;<' se muestra literal
    assert "&#x27;quote&#x27;" in h
    assert "ñ" in h  # unicode intacto


def test_severidad_desconocida_hostil_no_rompe_el_atributo_class():
    h = build_html(report_of(alerts=[mk_alert(severity='x"><script>')]))
    assert "<script" not in h
    assert 'class="alert sev-x&quot;&gt;&lt;script&gt;"' in h


def test_nota_y_marcas_hostiles_se_escapan():
    extras = {0: {"note": XSS + '"\'&', "reviewed": True, "ioc": ["dominio:<x>.com"],
                  "process": {"name": "<svg onload=1>", "pid": 1}}}
    h = build_html(report_of(), extras, ioc_source="<l>.txt")
    for raw in (XSS, "<x>", "<svg", "<l>"):
        assert raw not in h
    assert "revisada" in h
    assert "&lt;svg onload=1&gt;" in h
    assert "&lt;l&gt;.txt" in h


def test_nota_con_saltos_de_linea_y_unicode():
    h = build_html(report_of(), {0: {"note": "línea1\nlínea2 😀", "reviewed": False}})
    assert "línea1\nlínea2 😀" in h


def test_nombre_de_archivo_hostil_se_escapa():
    h = build_html(report_of(path="<img src=x onerror=alert(1)>.pcap"))
    assert "<img" not in h and "&lt;img src=x onerror=alert(1)&gt;.pcap" in h


def test_cabecera_de_campo_none_no_imprime_none():
    a = mk_alert(mitre_technique=None)
    h = build_html(report_of(alerts=[a]))
    assert "None" not in h.split("<h2>Alertas</h2>")[1].split("MITRE")[1][:30]


# --------------------------------------------------------- rutas filtradas
def test_solo_nombre_de_archivo_nunca_la_ruta():
    secret = "C:\\Users\\alguien\\secreto\\cap.pcap"
    h = build_html(report_of(path=secret))
    assert "cap.pcap" in h
    assert "alguien" not in h and "secreto" not in h
    h2 = build_html(report_of(path="/home/alguien/privado/cap.pcap"))
    assert "privado" not in h2 and "alguien" not in h2


# ----------------------------------------------------------- endpoints IPv6
def test_endpoint_ipv6_con_corchetes_y_sin_puerto():
    rep = report_of(sessions=[
        mk_session(src="2001:db8::1", dst="2001:db8::2", sport=1, dport=2),
        mk_session("ICMP", src="10.0.0.1", dst="10.0.0.2", sport=None, dport=None),
    ])
    h = build_html(rep)
    assert "<code>[2001:db8::1]:1</code>" in h
    assert "<code>10.0.0.1</code>" in h
    assert "10.0.0.1:None" not in h


# ------------------------------------------------------------ select_ids
def test_select_ids_top_10_por_bytes():
    rep = report_of(sessions=many_sessions(15))
    ids = select_ids(rep, {})
    assert len(ids) == TOP_SESSIONS == 10
    assert ids == set(range(5, 15))


def test_select_ids_une_extras_y_top():
    rep = report_of(sessions=many_sessions(15))
    ids = select_ids(rep, {0: {"note": "x"}, 1: {"ioc": ["ip:1.1.1.1"]}})
    assert ids == set(range(5, 15)) | {0, 1}


def test_select_ids_pocas_sesiones_y_vacio():
    assert select_ids(report_of(sessions=many_sessions(3)), {}) == {0, 1, 2}
    assert select_ids(report_of(sessions=[]), {}) == set()


def test_select_ids_empates_estable_y_extras_inexistentes_no_rompen_html():
    rep = report_of(sessions=[mk_session(sport=i, nbytes=50) for i in range(12)])
    assert len(select_ids(rep, {})) == 10
    # un id de extras que no existe en el reporte se ignora al dibujar la tabla
    h = build_html(report_of(sessions=many_sessions(2)), {99: {"note": "fantasma"}})
    assert "fantasma" not in h


def test_tabla_de_sesiones_lista_anotadas_mas_pesadas_y_omite_el_resto():
    rep = report_of(sessions=many_sessions(15))
    h = build_html(rep, {0: {"note": "mi-nota-visible", "reviewed": True}})
    rows = h.split("<h2>Sesiones destacadas</h2>")[1].count("<tr><td>")
    assert rows == 11
    assert "mi-nota-visible" in h
    assert "<td>1</td>" not in h.split("Sesiones destacadas")[1]  # id 1 no es ni pesada ni anotada


def test_proceso_solo_si_viene_en_extras():
    rep = report_of()
    assert "chrome.exe" not in build_html(rep)
    assert "chrome.exe" in build_html(rep, {0: {"process": {"name": "chrome.exe", "pid": 4}}})
    assert "<th>Proceso</th>" in build_html(rep)  # la columna existe aunque esté vacía


# ------------------------------------------------------------ Para el ticket
import html as _html

from backend.domain.export.html_report import build_ticket_text


def ticket_of(h):
    m = re.search(r'<pre class="ticket">(.*?)</pre>', h, re.S)
    assert m, "falta el bloque del ticket"
    return _html.unescape(m.group(1))


def test_ticket_tiene_las_cinco_partes_y_es_texto_plano():
    h = build_html(report_of(), {0: {"ioc": ["ip:10.0.0.2"], "note": "visto"}}, ioc_source="iocs.txt")
    assert "<h2>Para el ticket</h2>" in h
    t = ticket_of(h)
    for title in ("RESUMEN EJECUTIVO", "LÍNEA DE TIEMPO", "IOC CONFIRMADOS", "EVIDENCIA CLAVE", "RECOMENDACIÓN DE CONTENCIÓN"):
        assert title in t
    assert "<" not in t and "Captura cap.pcap" in t
    assert "1 Alta" in t and "ip:10.0.0.2" in t


def test_ticket_timeline_en_orden_cronologico_con_sesiones_marcadas():
    alerts = [mk_alert(name="Tardía", first_ts=300.0), mk_alert(name="Temprana", first_ts=100.0)]
    sessions = [mk_session()]
    sessions[0].first_ts = 200.0
    t = build_ticket_text(report_of(sessions=sessions, alerts=alerts), {0: {"reviewed": True}})
    assert t.index("Temprana") < t.index("SESIÓN #0") < t.index("Tardía")
    assert "1970-01-01 00:01:40 UTC" in t


def test_ticket_escapa_datos_hostiles_en_el_html():
    alert = mk_alert(name=XSS, evidence={"q": XSS}, src_ip=XSS)
    h = build_html(report_of(alerts=[alert]), {0: {"note": XSS, "ioc": [XSS]}}, ioc_source=XSS)
    assert "<script" not in h.lower()
    assert _html.unescape(re.search(r'<pre class="ticket">(.*?)</pre>', h, re.S).group(1)).count(XSS) >= 1


def test_ticket_un_dato_hostil_no_puede_fingir_lineas():
    alert = mk_alert(evidence={"q": "a\nRECOMENDACIÓN DE CONTENCIÓN falsa\r\nb"})
    t = build_ticket_text(report_of(alerts=[alert]), {})
    # el dato queda dentro de UNA línea de evidencia: ninguna línea nueva empieza con el título falso
    assert sum(1 for l in t.splitlines() if l.startswith("RECOMENDACIÓN DE CONTENCIÓN")) == 1
    assert len(t.splitlines()) == len(build_ticket_text(report_of(alerts=[mk_alert(evidence={"q": "ab"})]), {}).splitlines())


def test_ticket_sin_alertas_ni_ioc():
    t = build_ticket_text(report_of(alerts=[]), {})
    assert "Sin alertas." in t and "Sin eventos." in t and "No se cargó una lista de IOC." in t
    assert "no hay acciones de contención" in t


def test_ticket_ioc_sin_coincidencias():
    t = build_ticket_text(report_of(), {}, ioc_source="x.txt")
    assert "Ninguna sesión coincide" in t


def test_ticket_recomendacion_por_regla_y_por_severidad():
    t = build_ticket_text(report_of(alerts=[mk_alert(rule_id="port_scan", name="Escaneo"), mk_alert(rule_id="nueva", severity="critical", name="Otra")]), {})
    assert "bloquear el origen del escaneo" in t and "Aislar de inmediato" in t


def test_ticket_limita_eventos_y_evidencia():
    alerts = [mk_alert(first_ts=float(i), name=f"A{i}") for i in range(60)]
    t = build_ticket_text(report_of(alerts=alerts), {})
    assert "… y 20 evento(s) más" in t
    evidence = t.split("EVIDENCIA CLAVE")[1].split("RECOMENDACIÓN")[0]
    assert evidence.count("\n- ") == 5


def test_ticket_acota_el_largo_de_un_valor():
    t = build_ticket_text(report_of(alerts=[mk_alert(evidence={"x": "z" * 5000})]), {})
    assert "z" * 200 not in t and "…" in t


def test_ticket_analisis_parcial_y_hora_invalida():
    t = build_ticket_text(report_of(truncated=True, untracked_packets=5, alerts=[mk_alert(first_ts=float("1e30"))]), {})
    assert "análisis parcial" in t and "hora desconocida" in t
