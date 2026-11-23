"""Tests de backend/domain/rules/iocs.py: parseo, errores con número de línea, topes y coincidencias."""
import ipaddress
from types import SimpleNamespace

import pytest

from backend.domain.rules import iocs
from backend.domain.rules.iocs import IocError, IocSet, load_iocs, parse_iocs


def sess(src="10.0.0.1", dst="10.0.0.2"):
    return SimpleNamespace(src_ip=src, dst_ip=dst)


# ------------------------------------------------------------------ parseo
def test_parsea_ip_red_y_dominio():
    s = parse_iocs("1.2.3.4\n10.0.0.0/8\nEvil.COM\n")
    assert s.ips == frozenset({"1.2.3.4"})
    assert s.networks == (ipaddress.ip_network("10.0.0.0/8"),)
    assert s.domains == frozenset({"evil.com"})
    assert len(s) == 3


def test_ipv6_se_normaliza_comprimida():
    s = parse_iocs("2001:0DB8:0000:0000:0000:0000:0000:0001\n")
    assert s.ips == frozenset({"2001:db8::1"})
    assert s.match_ip("2001:db8::1") == "ip:2001:db8::1"
    assert s.match_ip("2001:DB8:0:0:0:0:0:1") == "ip:2001:db8::1"


def test_comentarios_lineas_vacias_y_comentario_en_linea():
    text = "# encabezado\n\n   \n1.1.1.1  # servidor C2\n  # otro\n\t8.8.8.8\t\n#solo\n"
    assert parse_iocs(text).ips == frozenset({"1.1.1.1", "8.8.8.8"})


def test_finales_de_linea_crlf_y_duplicados():
    s = parse_iocs("1.1.1.1\r\n1.1.1.1\r\nevil.com\r\nEVIL.com\r\n")
    assert len(s.ips) == 1 and len(s.domains) == 1


def test_texto_vacio_o_solo_comentarios_da_conjunto_vacio():
    assert len(parse_iocs("")) == 0
    assert len(parse_iocs("# nada\n\n")) == 0


def test_cidr_no_estricto_normaliza_bits_de_host():
    s = parse_iocs("10.1.2.3/8\n")
    assert s.networks == (ipaddress.ip_network("10.0.0.0/8"),)
    assert s.match_ip("10.200.0.1") == "red:10.0.0.0/8"


def test_cidr_ipv6():
    s = parse_iocs("2001:db8::/32\n")
    assert s.match_ip("2001:db8:ffff::1") == "red:2001:db8::/32"
    assert s.match_ip("2001:db9::1") is None


@pytest.mark.parametrize("entry,expected", [
    ("evil.com.", "evil.com"),
    ("*.evil.com", "evil.com"),
    (".evil.com", "evil.com"),
    ("*.EVIL.Com.", "evil.com"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ("a-b.c-d.example", "a-b.c-d.example"),
    ("1abc.com", "1abc.com"),
])
def test_dominios_validos_normalizados(entry, expected):
    assert parse_iocs(entry).domains == frozenset({expected})


@pytest.mark.parametrize("entry", [
    "localhost", "a..b", "-evil.com", "evil-.com", "evil .com", "ev!l.com", "evil.com/path",
    "http://evil.com", "a" * 64 + ".com", ".", "*.", "..", "evil..com", "ünicode.com",
])
def test_entradas_invalidas(entry):
    with pytest.raises(IocError):
        parse_iocs(entry)


@pytest.mark.parametrize("entry", ["256.1.1.1", "1.2.3", "1.2.3.4.5", "999.999.999.999", "*.1.2.3", "evil.123"])
def test_ip_mal_escrita_da_error_con_linea(entry):
    with pytest.raises(IocError, match=r"línea 3: parece una IP mal escrita"):
        parse_iocs("1.1.1.1" + chr(10) + "# c" + chr(10) + entry + chr(10))


@pytest.mark.parametrize("entry", ["evil.com", "a.b.c1", "x.co9", "1.evil.com"])
def test_dominios_con_digitos_siguen_validos(entry):
    assert parse_iocs(entry).domains == frozenset({entry})


def test_red_33_sigue_siendo_error_de_red():
    with pytest.raises(IocError, match="línea 1: red inválida"):
        parse_iocs("10.0.0.0/33")


def test_dominio_demasiado_largo():
    label = "a" * 60
    ok = ".".join([label] * 3) + ".com"
    assert parse_iocs(ok).domains
    too_long = ".".join([label] * 5) + ".com"
    with pytest.raises(IocError):
        parse_iocs(too_long)


@pytest.mark.parametrize("entry", ["0.0.0.0/0", "::/0", "1.2.3.4/0"])
def test_red_cero_rechazada(entry):
    with pytest.raises(IocError, match="/0"):
        parse_iocs(entry)


@pytest.mark.parametrize("entry", ["1.2.3.4/33", "10.0.0.0/abc", "::1/129", "evil.com/8", "/8"])
def test_red_invalida(entry):
    with pytest.raises(IocError, match="red inválida"):
        parse_iocs(entry)


# ------------------------------------------------------------------ errores
def test_error_nombra_numero_de_linea_contando_vacias_y_comentarios():
    with pytest.raises(IocError) as e:
        parse_iocs("1.1.1.1\n# c\n\nbasura!!\n")
    assert "línea 4" in str(e.value)


def test_error_en_linea_uno():
    with pytest.raises(IocError, match="línea 1"):
        parse_iocs("???")


def test_error_no_reproduce_el_texto_de_la_linea():
    # solo número de línea y motivo: el contenido del archivo no vuelve en el mensaje (ni a la API)
    with pytest.raises(IocError) as e:
        parse_iocs("x!" * 100)
    msg = str(e.value)
    assert msg.startswith("línea 1:") and "x!" not in msg


def test_error_de_red_tampoco_reproduce_el_texto():
    with pytest.raises(IocError) as e:
        parse_iocs("1" * 100 + "/8")
    msg = str(e.value)
    assert "línea 1" in msg and "111" not in msg


def test_el_comentario_no_se_cuenta_como_parte_del_error():
    with pytest.raises(IocError) as e:
        parse_iocs("mala!  # comentario largo")
    assert "comentario" not in str(e.value)


# -------------------------------------------------------------------- topes
def test_tope_de_redes(monkeypatch):
    monkeypatch.setattr(iocs, "MAX_NETWORKS", 3)
    parse_iocs("10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n")
    with pytest.raises(IocError, match="demasiadas redes"):
        parse_iocs("10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n10.0.3.0/24\n")


def test_tope_de_redes_real_5000():
    assert iocs.MAX_NETWORKS == 5000
    ok = "\n".join(f"10.{i // 256}.{i % 256}.0/24" for i in range(5000))
    assert len(parse_iocs(ok).networks) == 5000
    with pytest.raises(IocError, match="demasiadas redes"):
        parse_iocs(ok + "\n11.0.0.0/24")


def test_tope_de_entradas(monkeypatch):
    monkeypatch.setattr(iocs, "MAX_ENTRIES", 5)
    parse_iocs("\n".join(f"10.0.0.{i}" for i in range(5)))
    with pytest.raises(IocError, match="demasiados indicadores"):
        parse_iocs("\n".join(f"10.0.0.{i}" for i in range(6)))


def test_duplicados_no_cuentan_para_el_tope(monkeypatch):
    monkeypatch.setattr(iocs, "MAX_ENTRIES", 2)
    assert len(parse_iocs("1.1.1.1\n" * 50 + "2.2.2.2\n")) == 2


# --------------------------------------------------------------- match_ip
def test_match_ip_exacta_antes_que_red():
    s = parse_iocs("10.0.0.5\n10.0.0.0/8\n")
    assert s.match_ip("10.0.0.5") == "ip:10.0.0.5"
    assert s.match_ip("10.9.9.9") == "red:10.0.0.0/8"
    assert s.match_ip("11.0.0.1") is None


def test_red_ipv4_no_coincide_con_ipv6_y_viceversa():
    s = parse_iocs("0.0.0.0/1\n::/1\n")
    assert s.match_ip("1.2.3.4") == "red:0.0.0.0/1"
    assert s.match_ip("::1") == "red:::/1"
    only4 = parse_iocs("0.0.0.0/1\n")
    assert only4.match_ip("::1") is None
    only6 = parse_iocs("::/1\n")
    assert only6.match_ip("1.2.3.4") is None
    assert only4.match_ip("::ffff:1.2.3.4") is None


def test_match_ip_quita_zone_id():
    s = parse_iocs("fe80::1\n")
    assert s.match_ip("fe80::1%eth0") == "ip:fe80::1"
    assert s.match_ip("fe80::1%12") == "ip:fe80::1"


@pytest.mark.parametrize("bad", ["", "no-ip", None, "1.2.3", "1.2.3.4/8", "%eth0"])
def test_match_ip_basura_da_none(bad):
    assert parse_iocs("1.2.3.4\n10.0.0.0/8\n").match_ip(bad) is None


# ------------------------------------------------------------ match_domain
def test_match_domain_exacto_y_subdominio():
    s = parse_iocs("evil.com\n")
    assert s.match_domain("evil.com") == "dominio:evil.com"
    assert s.match_domain("www.evil.com") == "dominio:evil.com"
    assert s.match_domain("a.b.c.evil.com") == "dominio:evil.com"


def test_match_domain_sin_coincidencia_de_sufijo_sin_limite_de_label():
    s = parse_iocs("evil.com\n")
    assert s.match_domain("notevil.com") is None
    assert s.match_domain("evil.com.attacker.net") is None
    assert s.match_domain("evilxcom") is None


def test_match_domain_insensible_a_mayusculas_y_punto_final():
    s = parse_iocs("evil.com\n")
    assert s.match_domain("WWW.Evil.COM.") == "dominio:evil.com"


def test_match_domain_nunca_coincide_con_tld_suelto():
    s = IocSet(domains=frozenset({"com"}))  # a mano: el parser lo rechazaría
    assert s.match_domain("com") is None
    assert s.match_domain("evil.com") is None


def test_match_domain_devuelve_el_mas_especifico():
    s = parse_iocs("evil.com\nsub.evil.com\n")
    assert s.match_domain("x.sub.evil.com") == "dominio:sub.evil.com"


def test_match_domain_vacio_y_numerico():
    s = parse_iocs("evil.com\n")
    assert s.match_domain("") is None
    assert s.match_domain(".") is None
    assert s.match_domain(123) is None


# ----------------------------------------------------------- match_session
def test_match_session_ordenada_sin_duplicados():
    s = parse_iocs("10.0.0.0/8\n10.0.0.2\nevil.com\n")
    found = s.match_session(sess("10.0.0.1", "10.0.0.2"), names=["evil.com", "www.evil.com", "ok.org"])
    assert found == sorted(found)
    assert found == ["dominio:evil.com", "ip:10.0.0.2", "red:10.0.0.0/8"]


def test_match_session_misma_red_en_ambos_extremos_aparece_una_vez():
    s = parse_iocs("10.0.0.0/8\n")
    assert s.match_session(sess("10.0.0.1", "10.0.0.2")) == ["red:10.0.0.0/8"]


def test_match_session_sin_coincidencias():
    assert parse_iocs("9.9.9.9\n").match_session(sess()) == []
    assert IocSet().match_session(sess()) == []


def test_iocset_vacio_len_cero():
    assert len(IocSet()) == 0


# ------------------------------------------------------------------ loader
def test_load_iocs_ok(tmp_path):
    p = tmp_path / "lista.txt"
    p.write_text("1.2.3.4\nevil.com\n", encoding="utf-8")
    s = load_iocs(p)
    assert s.ips == frozenset({"1.2.3.4"}) and s.domains == frozenset({"evil.com"})
    assert len(load_iocs(str(p))) == 2


def test_load_iocs_tolera_bom(tmp_path):
    p = tmp_path / "bom.txt"
    p.write_bytes(b"\xef\xbb\xbf1.2.3.4\n")
    assert load_iocs(p).ips == frozenset({"1.2.3.4"})


def test_load_iocs_no_utf8(tmp_path):
    p = tmp_path / "latin.txt"
    p.write_bytes("é.com\n".encode("latin-1") + b"\xff\xfe\x00")
    with pytest.raises(IocError, match="UTF-8"):
        load_iocs(p)


def test_load_iocs_binario(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(bytes(range(128, 256)))
    with pytest.raises(IocError):
        load_iocs(p)


def test_load_iocs_vacio_o_solo_comentarios(tmp_path):
    p = tmp_path / "vacio.txt"
    p.write_text("", encoding="utf-8")
    with pytest.raises(IocError, match="ningún indicador"):
        load_iocs(p)
    p.write_text("# nada\n\n", encoding="utf-8")
    with pytest.raises(IocError, match="ningún indicador"):
        load_iocs(p)


def test_load_iocs_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_iocs(tmp_path / "no-existe.txt")


def test_load_iocs_demasiado_grande(tmp_path, monkeypatch):
    p = tmp_path / "grande.txt"
    p.write_text("1.1.1.1\n" * 10, encoding="utf-8")
    monkeypatch.setattr(iocs, "MAX_FILE_BYTES", 20)
    with pytest.raises(IocError, match="demasiado grande"):
        load_iocs(p)


def test_load_iocs_limite_de_tamano_exacto_se_acepta(tmp_path, monkeypatch):
    p = tmp_path / "justo.txt"
    p.write_text("1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(iocs, "MAX_FILE_BYTES", p.stat().st_size)
    assert len(load_iocs(p)) == 1


def test_load_iocs_error_de_linea_propaga(tmp_path):
    p = tmp_path / "mala.txt"
    p.write_text("1.1.1.1\nmala!\n", encoding="utf-8")
    with pytest.raises(IocError, match="línea 2"):
        load_iocs(p)


def test_iocerror_es_valueerror():
    assert issubclass(IocError, ValueError)
