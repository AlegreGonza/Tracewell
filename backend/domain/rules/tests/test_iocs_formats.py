"""IOC en CSV y STIX 2.1."""
import ipaddress
import json
import time

import pytest

from backend.domain.rules import iocs
from backend.domain.rules.iocs import (
    IocError, detect_format, load_iocs, parse_csv_iocs, parse_ioc_text, parse_stix_iocs,
)


def bundle(*objects):
    return json.dumps({"type": "bundle", "id": "bundle--1", "objects": list(objects)})


def indicator(pattern, **extra):
    return {"type": "indicator", "spec_version": "2.1", "id": "indicator--1", "pattern": pattern, "pattern_type": "stix", **extra}


# ------------------------------------------------------------------ detección

@pytest.mark.parametrize("name,text,expected", [
    ("lista.json", "1.2.3.4", "stix"),
    ("lista.STIX", "1.2.3.4", "stix"),
    ("lista.csv", "1.2.3.4", "csv"),
    ("lista.tsv", "1.2.3.4", "csv"),
    ("lista.txt", "a,b", "texto"),
    ("", '{"objects": []}', "stix"),
    ("sin_extension", "[1]", "stix"),
    ("", "value,type\n1.2.3.4,ip", "csv"),
    ("", "# comentario, con coma\n1.2.3.4", "texto"),
    ("", "1.2.3.4\nevil.com", "texto"),
    ("", "1.2.3.4  # con coma, en comentario", "texto"),
    ("", "", "texto"),
])
def test_detecta_el_formato(name, text, expected):
    assert detect_format(text, name) == expected


def test_el_formato_de_texto_sigue_igual():
    s = parse_ioc_text("1.2.3.4\n10.0.0.0/8\nevil.com\n")
    assert s.ips == frozenset({"1.2.3.4"}) and s.domains == frozenset({"evil.com"})
    assert s.networks == (ipaddress.ip_network("10.0.0.0/8"),)


# ------------------------------------------------------------------------ CSV

def test_csv_con_columna_value_y_otras_ignoradas():
    s = parse_csv_iocs("type,value,comment\nip,1.2.3.4,malo\ndomain,Evil.COM,c2\nnet,10.0.0.0/8,lab\n")
    assert s.ips == frozenset({"1.2.3.4"}) and s.domains == frozenset({"evil.com"}) and len(s.networks) == 1


@pytest.mark.parametrize("header", ["valor", "Indicator", "IOC", "ip", "Dominio", "﻿value"])
def test_csv_reconoce_nombres_de_columna(header):
    assert parse_csv_iocs(f"id,{header}\n1,9.9.9.9\n").ips == frozenset({"9.9.9.9"})


def test_csv_dominio_en_columna_dominio():
    assert parse_csv_iocs("id,dominio\n1,evil.com\n").domains == frozenset({"evil.com"})


def test_csv_punto_y_coma_y_tabulador():
    assert parse_csv_iocs("tipo;valor\nip;1.2.3.4\n").ips == frozenset({"1.2.3.4"})
    assert parse_csv_iocs("tipo\tvalue\nip\t5.6.7.8\n").ips == frozenset({"5.6.7.8"})


def test_csv_de_una_columna_sin_encabezado():
    s = parse_csv_iocs("1.2.3.4\nevil.com\n")
    assert s.ips == frozenset({"1.2.3.4"}) and s.domains == frozenset({"evil.com"})


def test_csv_con_comillas_y_comentarios_y_filas_vacias():
    s = parse_csv_iocs('# lista\nvalue,note\n\n"1.2.3.4","dice, con coma"\n,sin valor\n')
    assert s.ips == frozenset({"1.2.3.4"}) and len(s) == 1


def test_csv_vacio_da_conjunto_vacio():
    assert len(parse_csv_iocs("")) == 0 and len(parse_csv_iocs("value\n")) == 0


def test_csv_sin_columna_de_valor_falla():
    with pytest.raises(IocError, match="sin columna de valor"):
        parse_csv_iocs("a,b\n1.2.3.4,x\n")


def test_csv_error_indica_la_linea_real():
    with pytest.raises(IocError, match="línea 4: parece una IP mal escrita"):
        parse_csv_iocs("# nota\nvalue\n1.2.3.4\n256.1.1.1\n")


def test_csv_rechaza_red_cero_y_red_invalida_y_basura():
    with pytest.raises(IocError, match="/0"):
        parse_csv_iocs("value\n0.0.0.0/0\n")
    with pytest.raises(IocError, match="red inválida"):
        parse_csv_iocs("value\n10.0.0.0/33\n")
    with pytest.raises(IocError, match="no es una IP"):
        parse_csv_iocs("value\nesto no es nada\n")


def test_csv_fila_corta_se_ignora():
    assert len(parse_csv_iocs("tipo,nota,value\nip\nip,x,1.2.3.4\n")) == 1


# ----------------------------------------------------------------------- STIX

def test_stix_ipv4_ipv6_y_dominio():
    s = parse_stix_iocs(bundle(
        indicator("[ipv4-addr:value = '198.51.100.7']"),
        indicator("[ipv6-addr:value = '2001:DB8::1']"),
        indicator("[domain-name:value = 'Evil.Example.com']"),
    ))
    assert s.ips == frozenset({"198.51.100.7", "2001:db8::1"}) and s.domains == frozenset({"evil.example.com"})


def test_stix_cidr_en_ipv4_addr():
    s = parse_stix_iocs(bundle(indicator("[ipv4-addr:value = '203.0.113.0/24']")))
    assert s.networks == (ipaddress.ip_network("203.0.113.0/24"),)


def test_stix_network_traffic_src_y_dst():
    s = parse_stix_iocs(bundle(indicator("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '192.0.2.9']")))
    assert s.ips == frozenset({"192.0.2.9"})
    s = parse_stix_iocs(bundle(indicator("[network-traffic:src_ref.value = '192.0.2.10']")))
    assert s.ips == frozenset({"192.0.2.10"})


def test_stix_or_e_in():
    s = parse_stix_iocs(bundle(
        indicator("[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.2']"),
        indicator("[domain-name:value IN ('a.test', 'b.test')]"),
    ))
    assert s.ips == frozenset({"192.0.2.1", "192.0.2.2"}) and s.domains == frozenset({"a.test", "b.test"})


def test_stix_objetos_de_observacion_sueltos():
    s = parse_stix_iocs(bundle({"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "192.0.2.50"},
                               {"type": "domain-name", "id": "domain-name--1", "value": "x.test"}))
    assert s.ips == frozenset({"192.0.2.50"}) and s.domains == frozenset({"x.test"})


def test_stix_lista_suelta_y_objeto_unico():
    assert parse_stix_iocs(json.dumps([indicator("[ipv4-addr:value = '192.0.2.3']")])).ips == frozenset({"192.0.2.3"})
    assert parse_stix_iocs(json.dumps(indicator("[ipv4-addr:value = '192.0.2.4']"))).ips == frozenset({"192.0.2.4"})


def test_stix_ignora_lo_que_no_es_ip_ni_dominio():
    s = parse_stix_iocs(bundle(
        indicator("[file:hashes.'SHA-256' = 'abc']"),
        indicator("[url:value = 'http://evil.test/x']"),
        indicator("[ipv4-addr:value = '192.0.2.5']", pattern_type="snort"),
        {"type": "malware", "name": "x"},
        {"type": "identity", "name": "y"},
    ))
    assert len(s) == 0


def test_stix_ignora_revocados_y_negaciones_y_like():
    s = parse_stix_iocs(bundle(
        indicator("[ipv4-addr:value = '192.0.2.6']", revoked=True),
        indicator("[NOT ipv4-addr:value = '192.0.2.7']"),
        indicator("[domain-name:value LIKE '%.evil.test']"),
    ))
    assert len(s) == 0


def test_stix_comilla_escapada_en_el_valor_falla_como_dominio_invalido():
    with pytest.raises(IocError, match="objeto 1"):
        parse_stix_iocs(bundle(indicator("[domain-name:value = 'a\\'b.test']")))


def test_stix_valores_invalidos_dan_error_con_el_objeto():
    with pytest.raises(IocError, match="objeto 2: parece una IP mal escrita"):
        parse_stix_iocs(bundle(indicator("[ipv4-addr:value = '192.0.2.8']"), indicator("[ipv4-addr:value = '256.1.1.1']")))
    with pytest.raises(IocError, match="/0"):
        parse_stix_iocs(bundle(indicator("[ipv4-addr:value = '0.0.0.0/0']")))
    with pytest.raises(IocError, match="red inválida"):
        parse_stix_iocs(bundle(indicator("[ipv4-addr:value = '10.0.0.0/40']")))


@pytest.mark.parametrize("text,msg", [
    ("{no es json", "no es un JSON válido"),
    ("", "no es un JSON válido"),
    ("42", "sin forma de STIX"),
    ('"texto"', "sin forma de STIX"),
    ('{"hola": 1}', "sin forma de STIX"),
    ('{"objects": "x"}', "sin forma de STIX"),
    ("[1, 2]", "se esperaba un objeto STIX"),
])
def test_stix_formas_invalidas(text, msg):
    with pytest.raises(IocError, match=msg):
        parse_stix_iocs(text)


def test_stix_indicador_sin_patron_o_con_patron_no_texto_se_ignora():
    s = parse_stix_iocs(bundle({"type": "indicator", "id": "i--1"}, {"type": "indicator", "pattern": 5}))
    assert len(s) == 0


def test_stix_respeta_el_tope_de_redes(monkeypatch):
    monkeypatch.setattr(iocs, "MAX_NETWORKS", 2)
    objs = [indicator(f"[ipv4-addr:value = '10.{i}.0.0/16']") for i in range(3)]
    with pytest.raises(IocError, match="demasiadas redes"):
        parse_stix_iocs(bundle(*objs))


def test_respeta_el_tope_de_entradas_en_csv(monkeypatch):
    monkeypatch.setattr(iocs, "MAX_ENTRIES", 2)
    with pytest.raises(IocError, match="demasiados indicadores"):
        parse_csv_iocs("value\n1.1.1.1\n2.2.2.2\n3.3.3.3\n")


# ------------------------------------------------------------- carga de archivos

def test_load_csv_por_extension(tmp_path):
    f = tmp_path / "lista.csv"
    f.write_text("value\n1.2.3.4\n", encoding="utf-8")
    assert load_iocs(f).ips == frozenset({"1.2.3.4"})


def test_load_stix_por_extension_y_por_contenido(tmp_path):
    body = bundle(indicator("[ipv4-addr:value = '192.0.2.77']"))
    (tmp_path / "a.json").write_text(body, encoding="utf-8")
    (tmp_path / "sin_ext").write_text(body, encoding="utf-8")
    assert load_iocs(tmp_path / "a.json").ips == load_iocs(tmp_path / "sin_ext").ips == frozenset({"192.0.2.77"})


def test_load_stix_sin_indicadores_utiles_falla(tmp_path):
    f = tmp_path / "vacio.json"
    f.write_text(bundle({"type": "malware", "name": "x"}), encoding="utf-8")
    with pytest.raises(IocError, match="ningún indicador"):
        load_iocs(f)


def test_load_json_roto_falla(tmp_path):
    f = tmp_path / "roto.json"
    f.write_text("{", encoding="utf-8")
    with pytest.raises(IocError, match="JSON"):
        load_iocs(f)


def test_load_txt_con_comas_sigue_siendo_texto_y_falla_como_antes(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("1.2.3.4,5.6.7.8\n", encoding="utf-8")
    with pytest.raises(IocError, match="línea 1"):
        load_iocs(f)


def test_load_csv_con_bom_y_crlf(tmp_path):
    f = tmp_path / "bom.csv"
    f.write_bytes("﻿value,note\r\n1.2.3.4,x\r\n".encode("utf-8"))
    assert load_iocs(f).ips == frozenset({"1.2.3.4"})


@pytest.mark.parametrize("pattern", [
    "[ipv4-addr:value = '" + "\\" * 200_000,  # comilla sin cerrar, solo barras
    "[ipv4-addr:value = '" + "a\'" * 100_000,  # escapes sin cierre
    "[ipv4-addr:value IN (" + "'x'," * 100_000,  # lista IN sin paréntesis de cierre
    "[" + "domain-name:value = '" * 50_000,  # muchos inicios de literal
])
def test_patron_stix_largo_no_causa_redos(pattern):
    start = time.perf_counter()
    iocs._pattern_values(pattern)
    assert time.perf_counter() - start < 2
