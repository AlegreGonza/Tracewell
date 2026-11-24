"""Tests directos de los helpers de backend/domain/rules/engine.py."""
import dpkt
import pytest

from backend.domain.rules.engine import (
    DETECTORS, Decoded, DnsSuspiciousDetector, FtpCleartextDetector, PortScanDetector, Rule,
    RuleError, TCP_ACK, TCP_SYN, _build_params, _check_keys, _check_mitre, _check_port,
    _check_severity, _check_text_fields, _fail, _is_int, _is_text, _l4_info, _read_yaml,
    _resolve_detector, _rule_files,
)


def _rule(detector="port_scan", **params):
    return Rule(id="r1", name="Regla", description="desc", severity="high", detector=detector,
                mitre_technique="T1046", mitre_name="Scan", mitre_tactic="Discovery",
                params=params, source="r.yaml")


def _dec(proto=6, flags=TCP_SYN, sport=1000, dport=80, payload=b"", ts=1.0,
         src="10.0.0.1", dst="10.0.0.2"):
    return Decoded(ts, src, dst, proto, sport, dport, flags, payload)


def _data(**over):
    base = {"id": "r1", "name": "N", "severity": "low", "detector": "port_scan",
            "mitre": {"technique": "T1046", "name": "Scan", "tactic": "Discovery"}}
    base.update(over)
    return base


# ---------- _is_int / _check_port ----------

def test_is_int_acepta_enteros():
    """Un entero normal es int."""
    assert _is_int(5) and _is_int(0) and _is_int(-3)


@pytest.mark.parametrize("v", [True, False, 1.0, "1", None])
def test_is_int_rechaza_bool_y_otros(v):
    """bool, float, str y None no cuentan como int."""
    assert not _is_int(v)


@pytest.mark.parametrize("ok", [0, 21, 65535])
def test_check_port_validos(ok):
    """Puertos 0..65535 pasan."""
    assert _check_port(ok) is None


@pytest.mark.parametrize("bad", [-1, 65536, True, "80", 80.0, None])
def test_check_port_invalidos(bad):
    """Fuera de rango, bool, str, float y None lanzan ValueError."""
    with pytest.raises(ValueError, match="puerto"):
        _check_port(bad)


# ---------- _fail / _is_text ----------

def test_fail_lanza_ruleerror_con_nombre_de_archivo():
    """_fail prefija el mensaje con el archivo."""
    with pytest.raises(RuleError, match=r"^mi_regla\.yaml: algo falló$"):
        _fail("mi_regla.yaml", "algo falló")


def test_is_text():
    """Texto no vacío es True; vacío, solo espacios y no-str son False."""
    assert _is_text("a") and _is_text(" a ")
    assert not _is_text("") and not _is_text("   ")
    assert not _is_text(None) and not _is_text(5)


# ---------- _check_keys ----------

def test_check_keys_valido():
    """Un mapa con los campos obligatorios pasa."""
    assert _check_keys(_data(), "x.yaml") is None


def test_check_keys_no_es_mapa():
    """Una lista no es una regla."""
    with pytest.raises(RuleError, match="x.yaml: la regla debe ser un mapa"):
        _check_keys([1, 2], "x.yaml")


def test_check_keys_none_no_es_mapa():
    """Un YAML vacío (None) no es una regla."""
    with pytest.raises(RuleError, match="mapa"):
        _check_keys(None, "x.yaml")


def test_check_keys_faltantes():
    """Faltan campos obligatorios: se listan ordenados."""
    d = _data()
    del d["severity"], d["id"]
    with pytest.raises(RuleError, match=r"faltan campos: \['id', 'severity'\]"):
        _check_keys(d, "x.yaml")


def test_check_keys_desconocidos():
    """Un typo en un campo se rechaza."""
    with pytest.raises(RuleError, match=r"campos desconocidos: \['severty'\]"):
        _check_keys(_data(severty="x"), "x.yaml")


# ---------- _check_text_fields ----------

def test_check_text_fields_valido():
    """Campos de texto válidos y id en minúsculas/números/_."""
    assert _check_text_fields(_data(id="port_scan_2"), "x.yaml") is None


@pytest.mark.parametrize("key", ["id", "name", "severity", "detector"])
@pytest.mark.parametrize("bad", ["", "  ", 5, None])
def test_check_text_fields_no_texto(key, bad):
    """Cada campo de texto vacío o no-str lanza RuleError con su nombre."""
    with pytest.raises(RuleError, match=f"'{key}' debe ser texto"):
        _check_text_fields(_data(**{key: bad}), "x.yaml")


@pytest.mark.parametrize("bad_id", ["Mayus", "con-guion", "con espacio", "ñandú"])
def test_check_text_fields_id_formato(bad_id):
    """Un id con caracteres no permitidos falla."""
    with pytest.raises(RuleError, match="'id' solo admite"):
        _check_text_fields(_data(id=bad_id), "x.yaml")


# ---------- _check_severity ----------

@pytest.mark.parametrize("sev", ["low", "medium", "high", "critical"])
def test_check_severity_validas(sev):
    """Las cuatro severidades pasan."""
    assert _check_severity(_data(severity=sev), "x.yaml") is None


@pytest.mark.parametrize("sev", ["HIGH", "urgent", ""])
def test_check_severity_invalida(sev):
    """Severidad fuera de la lista (incluida otra capitalización) falla."""
    with pytest.raises(RuleError, match="severity debe ser una de"):
        _check_severity(_data(severity=sev), "x.yaml")


# ---------- _resolve_detector ----------

def test_resolve_detector_conocido():
    """Devuelve la clase registrada."""
    assert _resolve_detector(_data(detector="ftp_cleartext"), "x.yaml") is FtpCleartextDetector


def test_resolve_detector_desconocido_lista_disponibles():
    """Un detector inexistente falla y lista los disponibles."""
    with pytest.raises(RuleError, match="detector desconocido 'nada'.*port_scan"):
        _resolve_detector(_data(detector="nada"), "x.yaml")


# ---------- _check_mitre ----------

def test_check_mitre_valido_con_y_sin_subtecnica():
    """T1234 y T1234.001 pasan."""
    ok = {"technique": "T1046", "name": "n", "tactic": "t"}
    assert _check_mitre(ok, "x.yaml") is None
    assert _check_mitre({**ok, "technique": "T1046.001"}, "x.yaml") is None


@pytest.mark.parametrize("mitre", [None, "T1046", {}, {"technique": 1046},
                                   {"technique": "T104", "name": "n", "tactic": "t"},
                                   {"technique": "t1046", "name": "n", "tactic": "t"},
                                   {"technique": "T1046.01", "name": "n", "tactic": "t"}])
def test_check_mitre_tecnica_invalida(mitre):
    """No-mapa o técnica con mal formato falla."""
    with pytest.raises(RuleError, match="mitre.technique"):
        _check_mitre(mitre, "x.yaml")


@pytest.mark.parametrize("campo", ["name", "tactic"])
def test_check_mitre_nombre_o_tactica_faltante(campo):
    """name/tactic ausente o vacío falla con su nombre."""
    m = {"technique": "T1046", "name": "n", "tactic": "t"}
    m[campo] = "  "
    with pytest.raises(RuleError, match=f"mitre.{campo}"):
        _check_mitre(m, "x.yaml")
    del m[campo]
    with pytest.raises(RuleError, match=f"mitre.{campo}"):
        _check_mitre(m, "x.yaml")


# ---------- _build_params ----------

def test_build_params_defaults():
    """Sin params salen los defaults del detector."""
    out = _build_params(_data(), PortScanDetector, "x.yaml")
    assert (out["min_ports"], out["window_seconds"], out["long_window_seconds"]) == (15, 60.0, 0.0)


def test_build_params_params_none_usa_defaults():
    """`params:` vacío en YAML (None) equivale a sin params."""
    assert _build_params(_data(params=None), FtpCleartextDetector, "x.yaml") == {"ports": [21]}


def test_build_params_valor_valido_y_normalizado():
    """Un valor válido pisa el default y se normaliza (int -> float)."""
    out = _build_params(_data(params={"min_ports": 5, "window_seconds": 10}), PortScanDetector, "x.yaml")
    assert (out["min_ports"], out["window_seconds"]) == (5, 10.0)
    assert isinstance(out["window_seconds"], float)


def test_build_params_no_es_mapa():
    """params que no es mapa falla."""
    with pytest.raises(RuleError, match="'params' debe ser un mapa"):
        _build_params(_data(params=[1]), PortScanDetector, "x.yaml")


def test_build_params_desconocido():
    """Un param que el detector no define falla."""
    with pytest.raises(RuleError, match=r"params desconocidos para port_scan: \['foo'\]"):
        _build_params(_data(params={"foo": 1}), PortScanDetector, "x.yaml")


def test_build_params_valor_invalido_nombra_el_param():
    """Un valor fuera de rango falla nombrando el param y el archivo."""
    with pytest.raises(RuleError, match=r"x.yaml: param 'min_ports'"):
        _build_params(_data(params={"min_ports": 1}), PortScanDetector, "x.yaml")


def test_build_params_bool_no_vale_como_numero():
    """True no es un entero válido para min_ports."""
    with pytest.raises(RuleError, match="min_ports"):
        _build_params(_data(params={"min_ports": True}), PortScanDetector, "x.yaml")


# ---------- _rule_files / _read_yaml ----------

def test_rule_files_archivo_unico(tmp_path):
    """Un archivo devuelve solo ese archivo."""
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert _rule_files(f) == [f]


def test_rule_files_carpeta_ordenada_yaml_y_yml(tmp_path):
    """En una carpeta toma .yaml y .yml (no otros) y los ordena."""
    for n in ("b.yaml", "a.yaml", "c.yml", "z.txt"):
        (tmp_path / n).write_text("x")
    assert _rule_files(tmp_path) == sorted([tmp_path / "a.yaml", tmp_path / "b.yaml", tmp_path / "c.yml"])


def test_rule_files_carpeta_vacia(tmp_path):
    """Una carpeta sin reglas devuelve lista vacía."""
    assert _rule_files(tmp_path) == []


def test_rule_files_inexistente(tmp_path):
    """Una ruta inexistente lanza FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="no existe"):
        _rule_files(tmp_path / "nada.yaml")


def test_read_yaml_valido(tmp_path):
    """Devuelve la estructura parseada."""
    f = tmp_path / "a.yaml"
    f.write_text("id: x\nlista: [1, 2]\n", encoding="utf-8")
    assert _read_yaml(f) == {"id": "x", "lista": [1, 2]}


def test_read_yaml_vacio_devuelve_none(tmp_path):
    """Un archivo vacío da None (lo rechaza _check_keys después)."""
    f = tmp_path / "a.yaml"
    f.write_text("", encoding="utf-8")
    assert _read_yaml(f) is None


def test_read_yaml_invalido_nombra_el_archivo(tmp_path):
    """YAML mal formado lanza RuleError con el nombre del archivo."""
    f = tmp_path / "rota.yaml"
    f.write_text("a: [1, 2\nb: : :", encoding="utf-8")
    with pytest.raises(RuleError, match=r"^rota\.yaml: YAML inválido"):
        _read_yaml(f)


def test_read_yaml_no_ejecuta_tags_python(tmp_path):
    """safe_load rechaza tags !!python (no ejecuta código)."""
    f = tmp_path / "mala.yaml"
    f.write_text("x: !!python/object/apply:os.system ['echo hi']\n", encoding="utf-8")
    with pytest.raises(RuleError, match="YAML inválido"):
        _read_yaml(f)


# ---------- _l4_info ----------

def test_l4_info_tcp_devuelve_flags():
    """TCP -> (6, flags)."""
    assert _l4_info(dpkt.tcp.TCP(flags=TCP_SYN)) == (6, TCP_SYN)


def test_l4_info_udp():
    """UDP -> (17, 0)."""
    assert _l4_info(dpkt.udp.UDP()) == (17, 0)


@pytest.mark.parametrize("other", [b"\x00\x01", None, dpkt.icmp.ICMP()])
def test_l4_info_otro_devuelve_none(other):
    """Bytes crudos, None o ICMP -> None."""
    assert _l4_info(other) is None


# ---------- PortScanDetector helpers ----------

def test_is_pure_syn():
    """SYN sin ACK es puro; SYN+ACK, ACK solo y UDP no."""
    assert PortScanDetector._is_pure_syn(_dec(flags=TCP_SYN))
    assert not PortScanDetector._is_pure_syn(_dec(flags=TCP_SYN | TCP_ACK))
    assert not PortScanDetector._is_pure_syn(_dec(flags=TCP_ACK))
    assert not PortScanDetector._is_pure_syn(_dec(proto=17, flags=0))
    assert not PortScanDetector._is_pure_syn(_dec(proto=17, flags=TCP_SYN))  # UDP nunca es SYN


def test_record_port_crea_y_actualiza():
    """Anota el puerto con su ts; repetirlo solo refresca el instante."""
    det = PortScanDetector(_rule(min_ports=3, window_seconds=10.0))
    key = ("a", "b")
    ports = det._record_port(key, _dec(dport=22, ts=1.0))
    assert ports == {22: 1.0}
    ports = det._record_port(key, _dec(dport=22, ts=5.0))
    assert ports == {22: 5.0} and det._seen[key] is ports
    det._record_port(key, _dec(dport=80, ts=6.0))
    assert set(det._seen[key]) == {22, 80}


def test_record_port_pares_distintos_son_independientes():
    """Cada par origen/destino tiene su propio dict."""
    det = PortScanDetector(_rule())
    det._record_port(("a", "b"), _dec(dport=1))
    det._record_port(("a", "c"), _dec(dport=2))
    assert det._seen[("a", "b")] == {1: 1.0} and det._seen[("a", "c")] == {2: 1.0}


def test_prune_old_descarta_solo_fuera_de_ventana():
    """Quita los puertos más viejos que la ventana; el borde exacto se queda."""
    ports = {1: 0.0, 2: 40.0, 3: 50.0, 4: 100.0}
    PortScanDetector._prune_old(ports, now=100.0, window=50.0)
    assert ports == {3: 50.0, 4: 100.0}


def test_prune_old_vacio_no_falla():
    """Un dict vacío queda vacío."""
    ports = {}
    PortScanDetector._prune_old(ports, 10.0, 5.0)
    assert ports == {}


def test_build_alert_evidencia_y_ts_minimo():
    """La alerta lleva puertos, umbral, ventana y first_ts = el puerto más antiguo."""
    det = PortScanDetector(_rule(min_ports=3, window_seconds=10.0))
    ports = {80: 4.0, 22: 2.0, 443: 3.0}
    a = det._build_alert(_dec(ts=9.0), ports, 10.0, 3)
    assert a.first_ts == 2.0 and (a.src_ip, a.dst_ip) == ("10.0.0.1", "10.0.0.2")
    assert a.evidence == {"distinct_ports": 3, "sample_ports": [22, 80, 443],
                          "window_seconds": 10.0, "threshold": 3}


def test_build_alert_muestra_a_lo_sumo_20_puertos():
    """sample_ports se corta en 20 (los menores) aunque distinct_ports sea mayor."""
    det = PortScanDetector(_rule())
    ports = {p: float(p) for p in range(1, 31)}
    a = det._build_alert(_dec(), ports, 60.0, 30)
    assert a.evidence["distinct_ports"] == 30
    assert a.evidence["sample_ports"] == list(range(1, 21))


# ---------- FtpCleartextDetector helpers ----------

def test_split_command_pass():
    """Devuelve el comando de 5 bytes en mayúsculas y el resto."""
    assert FtpCleartextDetector._split_command(b"pass secreto\r\n") == (b"PASS ", b"secreto")


def test_split_command_solo_primera_linea():
    """Solo mira la primera línea (CRLF o LF)."""
    assert FtpCleartextDetector._split_command(b"USER ana\r\nPASS x\r\n") == (b"USER ", b"ana")
    assert FtpCleartextDetector._split_command(b"USER ana\nPASS x") == (b"USER ", b"ana")


def test_split_command_vacio_y_corto():
    """Payload vacío o comando corto no rompen."""
    assert FtpCleartextDetector._split_command(b"") == (b"", b"")
    assert FtpCleartextDetector._split_command(b"QU") == (b"QU", b"")


def test_password_alert_nunca_incluye_la_contrasena():
    """La alerta oculta la contraseña: solo guarda su largo y no aparece en ninguna parte."""
    det = FtpCleartextDetector(_rule("ftp_cleartext", ports=[21]))
    secreto = b"S3cr3t0-unico"
    alerts = det._password_alert(_dec(dport=21), secreto + b"\r", "ana")
    assert len(alerts) == 1
    ev = alerts[0].evidence
    assert ev == {"username": "ana", "password": "<oculta>", "password_length": len(secreto), "port": 21,
                  "protocol": "FTP"}
    assert secreto.decode() not in repr(alerts[0])


def test_password_alert_una_por_origen_destino_usuario():
    """Repetir el mismo (src, dst, usuario) no genera otra alerta; otro usuario sí."""
    det = FtpCleartextDetector(_rule("ftp_cleartext", ports=[21]))
    d = _dec(dport=21)
    assert len(det._password_alert(d, b"x", "ana")) == 1
    assert det._password_alert(d, b"y", "ana") == []
    assert len(det._password_alert(d, b"y", "beto")) == 1


def test_password_alert_contrasena_vacia_largo_cero():
    """Una contraseña vacía o con solo espacios tiene largo 0."""
    det = FtpCleartextDetector(_rule("ftp_cleartext", ports=[21]))
    a = det._password_alert(_dec(dport=21), b"  \r", "ana")
    assert a[0].evidence["password_length"] == 0


# ---------- DnsSuspiciousDetector helpers ----------

def _dns_det(**p):
    params = {"max_label_length": 40, "min_entropy": 3.5, "entropy_min_label": 20}
    params.update(p)
    return DnsSuspiciousDetector(_rule("dns_suspicious", **params))


def _query_bytes(name, qr=0):
    return bytes(dpkt.dns.DNS(qr=qr, qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)]))


def test_is_dns_payload():
    """UDP al 53 con datos sí; TCP, otro puerto o payload vacío no."""
    assert DnsSuspiciousDetector._is_dns_payload(_dec(proto=17, dport=53, payload=b"x"))
    assert not DnsSuspiciousDetector._is_dns_payload(_dec(proto=6, dport=53, payload=b"x"))
    assert not DnsSuspiciousDetector._is_dns_payload(_dec(proto=17, dport=5353, payload=b"x"))
    assert not DnsSuspiciousDetector._is_dns_payload(_dec(proto=17, dport=53, payload=b""))


def test_parse_query_consulta_valida():
    """Una consulta (qr=0) se devuelve parseada."""
    dns = DnsSuspiciousDetector._parse_query(_query_bytes("ejemplo.com"))
    assert dns is not None and dns.qd[0].name == "ejemplo.com"


def test_parse_query_respuesta_devuelve_none():
    """Una respuesta (qr=1) se ignora."""
    assert DnsSuspiciousDetector._parse_query(_query_bytes("ejemplo.com", qr=1)) is None


@pytest.mark.parametrize("junk", [b"", b"\x00\x01", b"\xff" * 5])
def test_parse_query_basura_devuelve_none(junk):
    """Bytes ilegibles dan None, no una excepción."""
    assert DnsSuspiciousDetector._parse_query(junk) is None


def test_reasons_label_normal_sin_motivos():
    """Un label corto y de baja entropía no tiene motivos."""
    assert _dns_det()._reasons("www", 1.5) == []


def test_reasons_label_largo():
    """Un label más largo que el máximo da el motivo de largo."""
    r = _dns_det(max_label_length=10)._reasons("a" * 11, 0.0)
    assert len(r) == 1 and "11 caracteres" in r[0]


def test_reasons_entropia_alta_solo_si_label_suficientemente_largo():
    """La entropía solo cuenta desde entropy_min_label; en el borde exacto cuenta."""
    det = _dns_det(entropy_min_label=20, min_entropy=3.5)
    assert det._reasons("a" * 19, 4.0) == []
    r = det._reasons("a" * 20, 3.5)
    assert len(r) == 1 and "entropía" in r[0]


def test_reasons_ambos_motivos():
    """Largo y entropía a la vez dan dos motivos."""
    assert len(_dns_det(max_label_length=5)._reasons("a" * 25, 4.5)) == 2


def test_query_alert_sospechosa():
    """Un label largo y aleatorio genera alerta con evidencia (nombre en minúsculas)."""
    det = _dns_det()
    q = dpkt.dns.DNS.Q(name="QWERTYUIOPASDFGHJKLZXCVBNM1234567890abcdef.Evil.com", type=dpkt.dns.DNS_A)
    a = det._query_alert(_dec(proto=17, dport=53), q)
    assert a is not None
    assert a.evidence["query"] == q.name.lower() and a.evidence["qtype"] == dpkt.dns.DNS_A
    assert a.evidence["reasons"] and isinstance(a.evidence["label_entropy"], float)


def test_query_alert_normal_devuelve_none():
    """Un dominio común no alerta."""
    q = dpkt.dns.DNS.Q(name="www.ejemplo.com", type=dpkt.dns.DNS_A)
    assert _dns_det()._query_alert(_dec(proto=17, dport=53), q) is None


def test_query_alert_no_repite_para_mismo_origen_y_nombre():
    """La segunda vez para el mismo (src, nombre) da None; otro origen sí alerta."""
    det = _dns_det(max_label_length=5)
    q = dpkt.dns.DNS.Q(name="abcdefghij.com", type=dpkt.dns.DNS_A)
    assert det._query_alert(_dec(proto=17, dport=53), q) is not None
    assert det._query_alert(_dec(proto=17, dport=53), q) is None
    assert det._query_alert(_dec(proto=17, dport=53, src="10.0.0.9"), q) is not None


def test_detectores_registrados_tienen_params_con_validador_y_default():
    """Cada detector declara PARAMS como nombre -> (validador, default válido)."""
    for cls in DETECTORS.values():
        for check, default in cls.PARAMS.values():
            check(default)  # el default debe pasar su propio validador
