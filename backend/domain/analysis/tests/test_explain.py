"""Tests de backend/domain/analysis/explain.py: explicación didáctica de una sesión."""
import pytest

import backend.domain.analysis.explain as E
from backend.domain.analysis.analyzer import analyze, packets_of_sessions
from backend.domain.analysis.explain import explain_session
from backend.domain.analysis.tests.convo import ACK, FIN, PSH, RST, SYN, SYNACK, as_packets, conversation, frame
from backend.domain.analysis.tests.test_analyzer import DEMO
from backend.domain.analysis.names import NameBook
from backend.domain.pcap.reader import Packet
from backend.domain.sessions.grouper import Session

C, SRV = "10.0.0.1", "93.184.216.34"


def sess(proto="TCP", src=C, sport=40000, dst=SRV, dport=80):
    return Session(proto, src, sport, dst, dport, 1, 1, 0.0, 0.0, key=("k",))


def explain(turns=(), session=None, names=None, process=None, **kw):
    return explain_session(session or sess(), as_packets(conversation(turns=turns, **kw)), names, process)


def labels(out):
    return [s["label"] for s in out["steps"]]


# ------------------------------------------------------------------ resultados TCP

def test_cerrada_con_http():
    out = explain([("c", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])
    assert out["protocol"] == "TCP" and out["outcome"] == "cerrada"
    assert labels(out) == ["SYN", "SYN+ACK", "ACK", "Datos", "Datos", "FIN", "FIN"]
    assert any("Es HTTP sin cifrar" in s for s in out["summary"])
    assert any("se cerró con normalidad" in s for s in out["summary"])


def test_abierta():
    out = explain([("c", b"USER x\r\n")], close=None)
    assert out["outcome"] == "abierta" and "sigue abierta" in " ".join(out["summary"])


def test_cortada_rst_tras_establecer():
    out = explain([("c", b"hola")], close="rst")
    assert out["outcome"] == "cortada" and labels(out)[-1] == "RST"
    assert any("RST" in s for s in out["summary"])


def test_rechazada_syn_y_rst():
    frames = [frame(C, 40000, SRV, 80, 1000, SYN), frame(SRV, 80, C, 40000, 0, RST | ACK)]
    out = explain_session(sess(), as_packets(frames))
    assert out["outcome"] == "rechazada" and labels(out) == ["SYN", "RST"]
    assert "puerto esté cerrado" in " ".join(out["summary"])


def test_sin_respuesta_solo_syn():
    out = explain_session(sess(), as_packets([frame(C, 40000, SRV, 80, 1000, SYN)]))
    assert out["outcome"] == "sin_respuesta" and labels(out) == ["SYN"]
    assert "nadie respondió" in " ".join(out["summary"])


def test_sin_respuesta_con_syn_repetidos():
    out = explain_session(sess(), as_packets([frame(C, 40000, SRV, 80, 1000, SYN)] * 3))
    assert out["outcome"] == "sin_respuesta" and labels(out) == ["SYN"] * 3


def test_en_curso_sin_syn_visto():
    out = explain([("c", b"hola"), ("s", b"mundo")], handshake=False, close=None)
    assert out["outcome"] == "en_curso" and labels(out) == ["Datos", "Datos"]
    assert "ya en curso" in " ".join(out["summary"])


def test_en_curso_con_fin_o_rst_sin_syn_tambien_es_en_curso():
    assert explain([("c", b"x")], handshake=False, close="fin")["outcome"] == "en_curso"


def test_sesion_sin_paquetes_validos():
    out = explain_session(sess(), [Packet(1.0, b"\x00\x01", None)])
    assert out["outcome"] == "en_curso" and out["steps"] == []


def test_sin_paquetes():
    out = explain_session(sess(), [])
    assert out["protocol"] == "TCP" and out["outcome"] == "en_curso" and out["steps"] == [] and len(out["summary"]) >= 2


# ------------------------------------------------------------------ pasos

def test_pasos_detalle_y_origen_destino():
    out = explain([("c", b"abc")])
    syn, synack, ack = out["steps"][:3]
    assert (syn["who"], synack["who"], ack["who"]) == ("origen", "destino", "origen")
    assert "¿hablamos?" in syn["detail"] and "sí, hablemos" in synack["detail"] and "saludo de 3 pasos" in ack["detail"]
    assert all(set(s) == {"who", "label", "detail", "packet", "ts"} for s in out["steps"])
    assert [s["packet"] for s in out["steps"]][:3] == [0, 1, 2]
    assert out["steps"][0]["ts"] == 1.0


def test_ack_del_saludo_solo_una_vez_y_solo_del_iniciador():
    frames = conversation(turns=[], close=None)
    frames += [frame(C, 40000, SRV, 80, 1001, ACK)] * 3  # mas ACK puros: no son pasos
    out = explain_session(sess(), as_packets(frames))
    assert labels(out) == ["SYN", "SYN+ACK", "ACK"]


def test_datos_se_agrupan_por_turno_con_bytes_y_paquetes():
    out = explain([("c", b"x" * 2500), ("s", b"y" * 10)], mss=1000, close=None)
    datos = [s for s in out["steps"] if s["label"] == "Datos"]
    assert [d["detail"] for d in datos] == ["Envía 2.500 B en 3 paquete(s)", "Envía 10 B en 1 paquete(s)"]
    assert [d["who"] for d in datos] == ["origen", "destino"]


def test_turnos_alternados_dan_un_paso_por_turno():
    out = explain([("c", b"a"), ("s", b"b"), ("c", b"c"), ("s", b"d")], close=None)
    assert labels(out) == ["SYN", "SYN+ACK", "ACK"] + ["Datos"] * 4


def test_orden_fin_rst_y_cierre_aplicado_a_los_datos_pendientes():
    out = explain([("c", b"aaa")])
    assert labels(out)[-3:] == ["Datos", "FIN", "FIN"]  # el grupo pendiente se vuelca antes del FIN


def test_syn_ack_a_mitad_sin_syn_cuenta_como_aceptacion():
    frames = [frame(SRV, 80, C, 40000, 5000, SYNACK), frame(C, 40000, SRV, 80, 1001, ACK)]
    out = explain_session(sess(), as_packets(frames))
    assert out["outcome"] == "abierta" and labels(out)[0] == "SYN+ACK"


def test_max_steps_con_paso_final(monkeypatch):
    monkeypatch.setattr(E, "MAX_STEPS", 5)
    out = explain([("c", b"a"), ("s", b"b")] * 10, close=None)
    assert len(out["steps"]) == 6
    last = out["steps"][-1]
    assert last["label"] == "…" and last["who"] == "ambos" and last["packet"] is None and last["ts"] is None
    assert last["detail"] == f"y {len(explain([('c', b'a'), ('s', b'b')] * 10, close=None)['steps'])} paso(s) más" or "paso(s) más" in last["detail"]


def test_exactamente_max_steps_no_agrega_puntos(monkeypatch):
    monkeypatch.setattr(E, "MAX_STEPS", 4)
    out = explain([("c", b"a")], close=None)  # SYN, SYN+ACK, ACK, Datos
    assert len(out["steps"]) == 4 and out["steps"][-1]["label"] == "Datos"


# ------------------------------------------------------------------ frases

def test_bytes_intercambiados_y_paquetes():
    out = explain([("c", b"x" * 1500), ("s", b"y" * 20)], mss=1000)
    assert any("Se intercambiaron 8 paquetes: 1.500 B del origen y 20 B del destino" in s for s in out["summary"])


def test_sin_datos_no_hay_frase_de_bytes():
    assert not any("Se intercambiaron" in s for s in explain([])["summary"])


def test_keepalive_con_dos_o_mas_paquetes_de_un_byte():
    out = explain([("c", b"\x00"), ("c", b"\x00")], close=None)
    assert any("keep-alive" in s for s in out["summary"])
    out1 = explain([("c", b"\x00")], close=None)
    assert not any("keep-alive" in s for s in out1["summary"])


def test_tls_por_los_primeros_bytes():
    out = explain([("c", b"\x16\x03\x01\x00\x05hello")], close=None)
    assert any("cifrado (TLS)" in s for s in out["summary"]) and not any("Es HTTP" in s for s in out["summary"])


@pytest.mark.parametrize("first", [b"GET / HTTP/1.1\r\n", b"POST /x HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\n", b"HEAD / HTTP/1.1", b"OPTIONS * HTTP/1.1"])
def test_http_por_los_primeros_bytes(first):
    assert any("Es HTTP sin cifrar" in s for s in explain([("c", first)], close=None)["summary"])


def test_sin_frase_de_contenido_para_otros_datos():
    out = explain([("c", b"USER admin\r\n")], close=None)
    assert not any("Es HTTP" in s or "(TLS)" in s for s in out["summary"])


def test_frase_del_proceso():
    out = explain([("c", b"x")], process={"name": "chrome.exe", "pid": 4321})
    assert any("chrome.exe (PID 4321)" in s for s in out["summary"])
    assert not any("PID" in s for s in explain([("c", b"x")])["summary"])


def test_servicio_conocido_y_desconocido():
    assert "HTTP (puerto 80)" in explain([])["summary"][0]
    assert "puerto 12345" in explain([], session=sess(dport=12345))["summary"][0]
    assert "HTTPS (puerto 443)" in explain([], session=sess(dport=443))["summary"][0]


def test_el_nombre_va_al_servidor_normal():
    s = sess()
    s.key = ("k",)
    names = NameBook(sni={("k",): "example.com"})
    first = explain([], session=s, names=names)["summary"][0]
    assert first.startswith(f"{C} habló con example.com ({SRV})")


def test_el_nombre_va_al_servidor_aunque_este_invertido():
    s = Session("TCP", SRV, 443, C, 51000, 1, 1, 0.0, 0.0, key=("k",))
    names = NameBook(sni={("k",): "example.com"})
    first = explain_session(s, [], names)["summary"][0]
    assert first.startswith(f"example.com ({SRV}) habló con {C} ")


def test_sin_nombres_solo_ips():
    assert explain([])["summary"][0].startswith(f"{C} habló con {SRV} por TCP")


# ------------------------------------------------------------------ otros protocolos

def test_udp_dns():
    out = explain_session(sess("UDP", dport=53), [object(), object()])
    assert out["protocol"] == "UDP" and out["outcome"] is None and out["steps"] == []
    text = " ".join(out["summary"])
    assert "Es DNS" in text and "2 paquete(s)" in text and "UDP no abre una conexión" in text


def test_udp_otro_puerto_sin_frase_dns():
    out = explain_session(sess("UDP", dport=5000), [object()])
    assert not any("DNS" in s for s in out["summary"])


def test_udp_con_dns_como_puerto_origen():
    assert any("Es DNS" in s for s in explain_session(sess("UDP", sport=53, dport=40000), [])["summary"])


def test_icmp_e_icmpv6():
    for proto in ("ICMP", "ICMPv6"):
        s = Session(proto, C, None, SRV, None, 1, 1, 0.0, 0.0, key=("k",))
        out = explain_session(s, [object()] * 4)
        assert out["outcome"] is None and out["steps"] == [] and "ping" in out["summary"][0] and "4 paquete(s)" in out["summary"][0]
        assert proto in out["summary"][0]


def test_otro_protocolo():
    s = Session("IP-47", C, None, SRV, None, 1, 1, 0.0, 0.0, key=("k",))
    out = explain_session(s, [object()] * 3)
    assert out["outcome"] is None and "IP-47" in out["summary"][0] and "3 paquete(s)" in out["summary"][0]


def test_proceso_en_udp_e_icmp():
    p = {"name": "dnsd", "pid": 9}
    assert any("dnsd (PID 9)" in s for s in explain_session(sess("UDP", dport=53), [], None, p)["summary"])
    assert any("dnsd (PID 9)" in s for s in explain_session(Session("ICMP", C, None, SRV, None, key=("k",)), [], None, p)["summary"])


# ------------------------------------------------------------------ demo

@pytest.fixture(scope="module")
def demo():
    return analyze(DEMO, [])


def demo_explain(demo, sid):
    s = demo.result.sessions[sid]
    return explain_session(s, packets_of_sessions(demo, [s]), demo.names)


def test_demo_http_cerrada(demo):
    out = demo_explain(demo, 3)
    assert out["outcome"] == "cerrada"
    assert labels(out) == ["SYN", "SYN+ACK", "ACK", "Datos", "Datos", "FIN"] or labels(out)[:5] == ["SYN", "SYN+ACK", "ACK", "Datos", "Datos"]
    assert "FIN" in labels(out) and any("Es HTTP sin cifrar" in s for s in out["summary"])


def test_demo_ftp_abierta(demo):
    assert demo_explain(demo, 5)["outcome"] == "abierta"


def test_demo_escaneo_sin_respuesta(demo):
    out = demo_explain(demo, 7)
    assert out["outcome"] == "sin_respuesta" and labels(out) == ["SYN"]


def test_demo_todas_las_sesiones_se_explican(demo):
    for i, s in enumerate(demo.result.sessions):
        out = demo_explain(demo, i)
        assert out["summary"] and all(isinstance(x, str) and x for x in out["summary"])
        assert (out["outcome"] is None) == (s.protocol != "TCP")


# ------------------------------------------------------------------ sonda keep-alive de un solo byte 00

PROBE = "Probable keep-alive"
OLD_KA = "son un keep-alive"


def probe(*parts, session=None, names=None, process=None):
    """parts: ('c'|'s', seq, flags, data). Sin saludo: la captura empezo a mitad."""
    frames = []
    for who, seq, flags, data in parts:
        a, ap, b, bp = (C, 40000, SRV, 80) if who == "c" else (SRV, 80, C, 40000)
        frames.append(frame(a, ap, b, bp, seq, flags, data))
    return explain_session(session or sess(), as_packets(frames), names, process)


def has_probe(out):
    return any(PROBE in s for s in out["summary"])


def test_sonda_caso_real_un_byte_00_y_ack_vacio():
    out = probe(("c", 1000, PSH, b"\x00"), ("s", 5000, ACK, b""))
    assert has_probe(out)
    assert out["outcome"] == "en_curso"
    assert any("Se intercambiaron 2 paquetes: 1 B del origen y 0 B del destino" in s for s in out["summary"])


def test_sonda_el_texto_dice_que_no_es_un_ataque_ni_contenido():
    text = next(s for s in probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""))["summary"] if PROBE in s)
    assert "no es contenido ni un ataque" in text and "no se puede confirmar" in text and "(00)" in text


def test_sonda_con_el_origen_invertido_tambien_dispara():
    inv = Session("TCP", SRV, 80, C, 40000, 2, 120, 0.0, 0.0, key=("k",))  # el origen es el servidor
    out = probe(("s", 5000, PSH, b"\x00"), ("c", 1000, ACK, b""), session=inv)
    assert has_probe(out)
    out2 = probe(("c", 1000, PSH, b"\x00"), ("s", 5000, ACK, b""), session=inv)  # el byte lo manda el destino
    assert has_probe(out2) and any("0 B del origen y 1 B del destino" in s for s in out2["summary"])


def test_sonda_un_solo_paquete_o_tres_paquetes_si_cuenta():
    assert has_probe(probe(("c", 1, PSH, b"\x00")))
    assert has_probe(probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""), ("c", 2, ACK, b"")))


def test_sonda_mas_de_tres_paquetes_no():
    out = probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""), ("c", 2, ACK, b""), ("s", 9, ACK, b""))
    assert not has_probe(out)
    assert not any(OLD_KA in s for s in out["summary"])


@pytest.mark.parametrize("byte", [b"\x01", b"\xff", b"A", b"\x20", b"\x0a"])
def test_sonda_un_byte_distinto_de_00_no(byte):
    assert not has_probe(probe(("c", 1, PSH, byte), ("s", 9, ACK, b"")))


@pytest.mark.parametrize("data", [b"\x00\x00", b"\x00\x01", b"\x00" * 10, b"hola"])
def test_sonda_mas_de_un_byte_no(data):
    assert not has_probe(probe(("c", 1, PSH, data), ("s", 9, ACK, b"")))


def test_sonda_sin_datos_no():
    assert not has_probe(probe(("c", 1, ACK, b""), ("s", 9, ACK, b"")))


@pytest.mark.parametrize("flags,label", [(SYN, "SYN"), (SYNACK, "SYN+ACK"), (FIN, "FIN"), (RST, "RST"), (RST | ACK, "RST+ACK"), (FIN | ACK, "FIN+ACK")])
def test_sonda_con_syn_synack_fin_o_rst_no(flags, label):
    out = probe(("c", 1000, flags, b""), ("c", 1001, PSH, b"\x00"))
    assert not has_probe(out), label


def test_sonda_con_fin_despues_del_byte_tampoco():
    assert not has_probe(probe(("c", 1, PSH, b"\x00"), ("c", 2, FIN, b"")))
    assert not has_probe(probe(("c", 1, PSH, b"\x00"), ("s", 9, RST, b"")))


def test_sonda_con_saludo_completo_no():
    out = explain([("c", b"\x00")], close=None)
    assert not has_probe(out)


def test_dos_keepalives_usan_la_frase_vieja_y_no_la_nueva():
    out = probe(("c", 1, PSH, b"\x00"), ("c", 2, PSH, b"\x00"))
    assert any(OLD_KA in s for s in out["summary"])
    assert not has_probe(out)
    out3 = probe(("c", 1, PSH, b"\x00"), ("s", 9, PSH, b"\x00"), ("c", 2, PSH, b"\x00"))
    assert any(OLD_KA in s for s in out3["summary"]) and not has_probe(out3)


def test_un_keepalive_con_otros_datos_no_es_sonda():
    assert not has_probe(probe(("c", 1, PSH, b"\x00"), ("c", 2, PSH, b"hola")))
    assert not has_probe(probe(("c", 1, PSH, b"hola"), ("c", 5, PSH, b"\x00")))


def test_no_se_duplican_frases_de_keepalive():
    out = probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""))
    assert sum("keep-alive" in s for s in out["summary"]) == 1
    assert sum(PROBE in s for s in out["summary"]) == 1
    two = probe(("c", 1, PSH, b"\x00"), ("c", 2, PSH, b"\x00"))
    assert sum("keep-alive" in s for s in two["summary"]) == 1


def test_sonda_orden_de_las_frases_y_conserva_proceso_y_nombre():
    out = probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""), process={"name": "svchost.exe", "pid": 7})
    s = out["summary"]
    i_bytes = next(i for i, x in enumerate(s) if "Se intercambiaron" in x)
    i_probe = next(i for i, x in enumerate(s) if PROBE in x)
    i_proc = next(i for i, x in enumerate(s) if "svchost.exe (PID 7)" in x)
    assert i_bytes < i_probe < i_proc
    assert s[0].startswith(f"{C} habló con {SRV}")


def test_sonda_no_toca_los_pasos_ni_el_resultado():
    out = probe(("c", 1, PSH, b"\x00"), ("s", 9, ACK, b""))
    assert [st["label"] for st in out["steps"]] == ["Datos"]
    assert out["outcome"] == "en_curso" and out["protocol"] == "TCP"


def test_sonda_no_aplica_a_udp_ni_icmp():
    assert not any(PROBE in s for s in explain_session(sess("UDP", dport=53), [object()])["summary"])


def test_is_single_probe_directo():
    t = E._Tcp(sess())
    for i, pkt in enumerate(as_packets([frame(C, 40000, SRV, 80, 1, PSH, b"\x00")])):
        t.feed(i, pkt)
    assert E._is_single_probe(t) is True
    t.keepalive = 2
    assert E._is_single_probe(t) is False
    t.keepalive = 1
    t.packets = 4
    assert E._is_single_probe(t) is False
