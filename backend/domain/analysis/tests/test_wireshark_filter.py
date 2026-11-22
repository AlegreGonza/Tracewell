import pytest

from backend.domain.analysis.wireshark_filter import alert_filter, ip_filter, session_filter


# ------------------------------------------------------------------ IP

def test_ip_v4():
    assert ip_filter("10.0.0.5") == "ip.addr==10.0.0.5"


def test_ip_v6_se_compacta():
    assert ip_filter("2001:0db8:0000:0000:0000:0000:0000:0001") == "ipv6.addr==2001:db8::1"


def test_ip_v6_con_zona_la_ignora():
    assert ip_filter("fe80::1%eth0") == "ipv6.addr==fe80::1"


@pytest.mark.parametrize("bad", ["", "  ", "no-es-ip", "10.0.0", "300.1.1.1", None, 5])
def test_ip_invalida_falla(bad):
    with pytest.raises(ValueError):
        ip_filter(bad)


def test_ip_invalida_no_filtra_texto_largo():
    with pytest.raises(ValueError) as exc:
        ip_filter("x" * 500)
    assert len(str(exc.value)) < 100


# -------------------------------------------------------------- sesión

def test_sesion_tcp_v4():
    f = session_filter("TCP", "10.0.0.5", 51000, "93.184.216.34", 443)
    assert f == "ip.addr==10.0.0.5 && ip.addr==93.184.216.34 && tcp.port==51000 && tcp.port==443"


def test_sesion_udp_v4():
    f = session_filter("UDP", "10.0.0.5", 5353, "8.8.8.8", 53)
    assert f == "ip.addr==10.0.0.5 && ip.addr==8.8.8.8 && udp.port==5353 && udp.port==53"


def test_sesion_tcp_v6():
    f = session_filter("TCP", "2001:db8::1", 40000, "2001:db8::2", 22)
    assert f == "ipv6.addr==2001:db8::1 && ipv6.addr==2001:db8::2 && tcp.port==40000 && tcp.port==22"


def test_sesion_udp_v6():
    f = session_filter("UDP", "fe80::1", 546, "ff02::1:2", 547)
    assert f.startswith("ipv6.addr==fe80::1 && ipv6.addr==ff02::1:2")
    assert f.endswith("udp.port==546 && udp.port==547")


def test_sesion_icmp_sin_puertos():
    assert session_filter("ICMP", "10.0.0.1", None, "10.0.0.2", None) == "ip.addr==10.0.0.1 && ip.addr==10.0.0.2 && icmp"


def test_sesion_icmpv6():
    assert session_filter("ICMPv6", "fe80::1", None, "fe80::2", None).endswith("&& icmpv6")


def test_sesion_otro_protocolo_v4_y_v6():
    assert session_filter("IP-2", "10.0.0.1", None, "224.0.0.22", None).endswith("ip.proto==2")
    assert session_filter("IP-50", "2001:db8::1", None, "2001:db8::2", None).endswith("ipv6.nxt==50")


def test_sesion_protocolo_desconocido_solo_extremos():
    assert session_filter("RARO", "10.0.0.1", None, "10.0.0.2", None) == "ip.addr==10.0.0.1 && ip.addr==10.0.0.2"


def test_sesion_mismo_puerto_en_ambos_extremos_no_se_repite():
    f = session_filter("UDP", "10.0.0.1", 123, "10.0.0.2", 123)
    assert f.count("udp.port==123") == 1


def test_sesion_misma_ip_en_ambos_extremos():
    assert session_filter("TCP", "127.0.0.1", 5000, "127.0.0.1", 6000) == "ip.addr==127.0.0.1 && tcp.port==5000 && tcp.port==6000"


def test_sesion_tcp_sin_puertos_usa_solo_el_protocolo():
    assert session_filter("TCP", "10.0.0.1", None, "10.0.0.2", None).endswith("&& tcp")


def test_sesion_puerto_cero_y_maximo_son_validos():
    f = session_filter("TCP", "10.0.0.1", 0, "10.0.0.2", 65535)
    assert "tcp.port==0" in f and "tcp.port==65535" in f


def test_sesion_puerto_fuera_de_rango_o_bool_se_ignora():
    f = session_filter("TCP", "10.0.0.1", 70000, "10.0.0.2", True)
    assert f.endswith("&& tcp")


def test_sesion_ip_invalida_falla():
    with pytest.raises(ValueError):
        session_filter("TCP", "x", 1, "10.0.0.2", 2)


# -------------------------------------------------------------- alerta

def test_alerta_sin_evidencia_son_los_dos_extremos():
    assert alert_filter("10.0.0.1", "10.0.0.2") == "ip.addr==10.0.0.1 && ip.addr==10.0.0.2"
    assert alert_filter("10.0.0.1", "10.0.0.2", None) == "ip.addr==10.0.0.1 && ip.addr==10.0.0.2"
    assert alert_filter("10.0.0.1", "10.0.0.2", "texto") == "ip.addr==10.0.0.1 && ip.addr==10.0.0.2"


def test_alerta_escaneo_usa_syn_y_puertos():
    f = alert_filter("10.0.0.9", "10.0.0.1", {"sample_ports": [443, 22, 80, 22], "distinct_ports": 3})
    assert f == (
        "ip.src==10.0.0.9 && ip.dst==10.0.0.1 && tcp.flags.syn==1 && tcp.flags.ack==0 "
        "&& tcp.dstport in {22 80 443}"
    )


def test_alerta_escaneo_limita_los_puertos():
    f = alert_filter("10.0.0.9", "10.0.0.1", {"sample_ports": list(range(1, 100))})
    inside = f.split("{")[1].rstrip("}").split()
    assert len(inside) == 20


def test_alerta_escaneo_ignora_puertos_invalidos():
    f = alert_filter("10.0.0.9", "10.0.0.1", {"sample_ports": [80, -1, 70000, "x", True]})
    assert "in {80}" in f


def test_alerta_escaneo_v6():
    f = alert_filter("2001:db8::9", "2001:db8::1", {"sample_ports": [80]})
    assert f.startswith("ipv6.src==2001:db8::9 && ipv6.dst==2001:db8::1")


def test_alerta_dns_usa_el_nombre():
    f = alert_filter("10.0.0.5", "8.8.8.8", {"query": "Abc.Evil.com"})
    assert f == 'ip.addr==10.0.0.5 && ip.addr==8.8.8.8 && dns.qry.name=="Abc.Evil.com"'


def test_alerta_dns_resolvedor_raro_usa_first_query():
    f = alert_filter("10.0.0.5", "203.0.113.7", {"resolver": "203.0.113.7", "first_query": "x.test"})
    assert f.endswith('dns.qry.name=="x.test"')


def test_alerta_dns_escapa_comillas_y_barras():
    f = alert_filter("10.0.0.5", "8.8.8.8", {"query": 'a" || ip.addr==1.1.1.1 || "b\\c'})
    name = f.split("dns.qry.name==", 1)[1]
    assert name.startswith('"') and name.endswith('"')
    inner = name[1:-1]
    # toda comilla del interior está precedida de una barra: no puede cerrar la cadena
    assert '\\"' in inner and inner.replace('\\\\', "").replace('\\"', "").count('"') == 0


def test_alerta_dns_descarta_caracteres_de_control():
    f = alert_filter("10.0.0.5", "8.8.8.8", {"query": "a\nb\x00c.test"})
    assert "\n" not in f and "\x00" not in f
    assert 'dns.qry.name=="abc.test"' in f


def test_alerta_dns_nombre_vacio_se_ignora():
    assert alert_filter("10.0.0.5", "8.8.8.8", {"query": "  "}) == "ip.addr==10.0.0.5 && ip.addr==8.8.8.8"


def test_alerta_con_puerto_destino_tcp_por_defecto():
    f = alert_filter("10.0.0.5", "10.0.0.6", {"port": 6667, "source_port": 4000})
    assert f.endswith("&& tcp.port==6667")


def test_alerta_con_puerto_y_protocolo_udp():
    f = alert_filter("10.0.0.5", "10.0.0.6", {"destination_port": 4444, "protocol": "UDP"})
    assert f.endswith("&& udp.port==4444")


def test_alerta_inundacion_syn_filtra_por_la_victima():
    ev = {"syn_packets": 500, "distinct_sources": 40, "window_seconds": 1.2, "destination_port": 80}
    f = alert_filter("198.51.100.4", "10.0.0.1", ev)
    assert f == "ip.dst==10.0.0.1 && tcp.dstport==80 && tcp.flags.syn==1 && tcp.flags.ack==0"
    assert "198.51.100.4" not in f


def test_alerta_un_solo_origen_no_es_inundacion():
    ev = {"syn_packets": 500, "distinct_sources": 1, "destination_port": 80}
    assert alert_filter("198.51.100.4", "10.0.0.1", ev).startswith("ip.addr==198.51.100.4")


def test_alerta_ip_invalida_falla():
    with pytest.raises(ValueError):
        alert_filter("no", "10.0.0.1", {})
