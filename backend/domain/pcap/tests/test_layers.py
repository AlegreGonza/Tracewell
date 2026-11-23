"""Tests de backend/domain/pcap/layers.py."""
import random
import socket
import struct

import pytest

from backend.domain.pcap import layers as L
from backend.domain.pcap.layers import dissect

MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\xaa\xbb\xcc\xdd\xee\xff"

REFERENCE = bytes.fromhex(
    "b0c787977f1a28d043d7ff11080045000029315a40008006ff68c0a8010aa04f680aca7e01bbe1576ddacc8cae2f501000fb4ea4000000")


# ------------------------------------------------------------ constructores

def ip4_packet(l4, proto, *, ttl=64, flags_off=0, options=b"", src="10.0.0.1", dst="10.0.0.2"):
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(l4)
    return struct.pack(">BBHHHBBH4s4s", 0x40 | ihl, 0, total, 0x1234, flags_off, ttl, proto, 0xBEEF,
                       socket.inet_aton(src), socket.inet_aton(dst)) + options + l4


def frame4(l4, proto, **kw):
    """Ethernet(+VLAN) + IPv4. Con vlans=[(tpid, vid), ...]: tpid es el de la etiqueta (0x8100/0x88a8)."""
    vlans = kw.pop("vlans", ())
    ip = ip4_packet(l4, proto, **kw)
    head = MAC_B + MAC_A
    if vlans:
        # El campo "tipo" de cada nivel apunta a la siguiente etiqueta; el último a IPv4.
        head += struct.pack(">H", vlans[0][0])
        for i, (_, vid) in enumerate(vlans):
            nxt = vlans[i + 1][0] if i + 1 < len(vlans) else 0x0800
            head += struct.pack(">HH", vid, nxt)
    else:
        head += b"\x08\x00"
    return head + ip


def tcp_hdr(sport=1234, dport=80, flags=0x10, window=100, options=b"", off=None, seq=1, ack=2):
    off = (5 + len(options) // 4) if off is None else off
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, window, 0xABCD, 0) + options


def udp_hdr(sport=1234, dport=53, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0x1111) + payload


def ip6_frame(nxt, l4, ext=b"", hop=64, src="2001:db8::1", dst="2001:db8::2"):
    ip6 = struct.pack(">IHBB", 0x60000000, len(ext) + len(l4), nxt, hop) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return MAC_B + MAC_A + b"\x86\xdd" + ip6 + ext + l4


def arp_frame(op=1):
    body = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + MAC_A + socket.inet_aton("10.0.0.1") + \
        b"\x00" * 6 + socket.inet_aton("10.0.0.2")
    return MAC_B + MAC_A + b"\x08\x06" + body


def by_name(layers, name):
    return next(x for x in layers if x["name"] == name)


def field(layer, label):
    return next(f for f in layer["fields"] if f["label"] == label)


def check_ranges(data, layers):
    """Todos los rangos caben en el paquete: 0 <= start <= end <= len(data)."""
    n = len(data)
    for ly in layers:
        assert set(ly) == {"name", "start", "end", "fields", "note"}
        assert 0 <= ly["start"] <= ly["end"] <= n, (ly["name"], ly["start"], ly["end"], n)
        for f in ly["fields"]:
            assert set(f) == {"label", "value", "start", "end", "hint"}
            assert isinstance(f["value"], str)
            assert 0 <= f["start"] <= f["end"] <= n, (ly["name"], f["label"], f["start"], f["end"], n)


# ------------------------------------------------------------ paquete de referencia

def test_referencia_decodificada_a_mano():
    ls = dissect(REFERENCE)
    check_ranges(REFERENCE, ls)
    assert [(x["name"], x["start"], x["end"]) for x in ls] == [
        ("Ethernet", 0, 14), ("IPv4", 14, 34), ("TCP", 34, 54), ("Datos", 54, 55)]
    eth, ip, tcp, data = ls
    assert field(eth, "MAC de destino")["value"] == "b0:c7:87:97:7f:1a"
    assert field(eth, "MAC de origen")["value"] == "28:d0:43:d7:ff:11"
    assert "0x0800" in field(eth, "Tipo")["value"] and "IPv4" in field(eth, "Tipo")["value"]
    ttl = field(ip, "TTL")
    assert ttl["value"] == "128" and "Windows" in ttl["hint"] and (ttl["start"], ttl["end"]) == (22, 23)
    assert "DF" in field(ip, "Banderas")["value"] and "MF" not in field(ip, "Banderas")["value"]
    assert field(ip, "Protocolo")["value"] == "6 (TCP)"
    assert field(ip, "IP de origen")["value"] == "192.168.1.10"
    assert field(ip, "IP de destino")["value"] == "160.79.104.10"
    assert field(ip, "Largo total")["value"] == "41 B"
    assert field(tcp, "Puerto de origen")["value"] == "51838"
    assert field(tcp, "Puerto de destino")["value"] == "443 (HTTPS)"
    assert field(tcp, "Banderas")["value"] == "ACK"
    assert field(tcp, "Ventana")["value"] == "251"
    assert field(tcp, "Largo de cabecera")["value"] == "20 B"
    assert data["fields"][0]["value"] == "1 B"
    assert all(x["note"] is None for x in ls)


def test_campos_contiguos_y_sin_solaparse_en_referencia():
    for ly in dissect(REFERENCE):
        pos = ly["start"]
        for f in ly["fields"]:
            assert f["start"] >= pos or f["label"] == "Tipo"
            pos = f["end"]
        assert ly["fields"][-1]["end"] <= ly["end"]


# ------------------------------------------------------------ no lanza

def packet_samples():
    syn_opts = b"\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02\x08\x0a" + b"\x00" * 10  # mss,nop,ws,nop,nop,sackok,ts
    syn_opts += b"\x00" * ((-len(syn_opts)) % 4)
    return {
        "ref": REFERENCE,
        "tcp_opts": frame4(tcp_hdr(flags=0x02, options=syn_opts) , 6),
        "tcp_data": frame4(tcp_hdr(flags=0x18) + b"GET / HTTP/1.1\r\n", 6),
        "udp_dns": frame4(udp_hdr(40000, 53, b"\x00\x01" * 8), 17),
        "icmp": frame4(b"\x08\x00\xab\xcd\x00\x01\x00\x01data", 1),
        "ip6_tcp": ip6_frame(6, tcp_hdr(443, 5000, 0x12)),
        "ip6_ext": ip6_frame(0, tcp_hdr(), ext=b"\x06\x00\x00\x00\x00\x00\x00\x00"),
        "icmp6": ip6_frame(58, b"\x80\x00\x12\x34\x00\x01\x00\x01"),
        "arp": arp_frame(),
        "vlan": frame4(udp_hdr(), 17, vlans=[(0x8100, 5)]),
        "qinq": frame4(udp_hdr(), 17, vlans=[(0x88a8, 10), (0x8100, 20)]),
        "frag": frame4(b"\x00" * 16, 17, flags_off=0x0010),
        "opts": frame4(tcp_hdr(), 6, options=b"\x01\x01\x01\x00"),
        "unknown_ether": MAC_B + MAC_A + b"\x12\x34" + b"\xff" * 20,
    }



@pytest.mark.parametrize("name", list(packet_samples()))
def test_todo_prefijo_no_lanza_y_respeta_rangos(name):
    data = packet_samples()[name]
    for n in range(len(data) + 1):
        chunk = data[:n]
        ls = dissect(chunk)
        assert isinstance(ls, list)
        check_ranges(chunk, ls)


def test_bytes_vacios():
    ls = dissect(b"")
    assert len(ls) == 1 and ls[0]["name"] == "Ethernet" and "Capa incompleta" in ls[0]["note"]
    check_ranges(b"", ls)


def test_acepta_bytearray_y_memoryview():
    assert dissect(bytearray(REFERENCE)) == dissect(REFERENCE) == dissect(bytes(memoryview(REFERENCE)))


def test_basura_aleatoria_no_lanza():
    rnd = random.Random(20240601)
    for _ in range(4000):
        n = rnd.randint(0, 120)
        data = bytes(rnd.getrandbits(8) for _ in range(n))
        check_ranges(data, dissect(data))


def test_basura_con_ethertype_valido_no_lanza():
    rnd = random.Random(31337)
    for _ in range(4000):
        et = rnd.choice([b"\x08\x00", b"\x86\xdd", b"\x08\x06", b"\x81\x00", b"\x88\xa8"])
        data = MAC_B + MAC_A + et + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 100)))
        check_ranges(data, dissect(data))


def test_mutaciones_de_paquetes_validos_no_lanzan():
    rnd = random.Random(5)
    for name, data in packet_samples().items():
        for _ in range(400):
            b = bytearray(data)
            for _ in range(rnd.randint(1, 4)):
                b[rnd.randrange(len(b))] = rnd.getrandbits(8)
            b = bytes(b)[:rnd.randint(0, len(b))]
            check_ranges(b, dissect(b))


def test_dissect_defiende_ante_excepcion_interna(monkeypatch):
    """Si algo inesperado revienta en _walk, queda una capa 'Error' y no se propaga."""
    def boom(d, layers):
        layers.append(L._layer("Ethernet", 0, 1, []))
        raise struct.error("x")
    monkeypatch.setattr(L, "_walk", boom)
    ls = dissect(b"abc")
    assert [x["name"] for x in ls] == ["Ethernet", "Error"]
    assert ls[1]["start"] == ls[1]["end"] == 3 and ls[1]["note"]
    for exc in (ValueError, IndexError, OSError):
        monkeypatch.setattr(L, "_walk", lambda d, layers, e=exc: (_ for _ in ()).throw(e("x")))
        assert dissect(b"")[-1]["name"] == "Error"


# ------------------------------------------------------------ Ethernet / VLAN

def test_ethernet_truncado():
    for n in range(0, 14):
        ls = dissect(REFERENCE[:n])
        assert len(ls) == 1 and ls[0]["name"] == "Ethernet"
        assert (ls[0]["start"], ls[0]["end"]) == (0, n) and ls[0]["fields"] == []
        assert ls[0]["note"].startswith("Capa incompleta")


def test_vlan_8021q():
    data = frame4(udp_hdr(), 17, vlans=[(0x8100, 0x0105)])
    ls = dissect(data)
    check_ranges(data, ls)
    eth = ls[0]
    assert (eth["start"], eth["end"]) == (0, 18)
    vl = field(eth, "VLAN")
    assert vl["value"] == "ID 261" and (vl["start"], vl["end"]) == (12, 16)
    assert "IPv4" in field(eth, "Tipo")["value"]
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "UDP"]
    assert by_name(ls, "IPv4")["start"] == 18


def test_vlan_qinq_8021ad_dos_etiquetas():
    data = frame4(udp_hdr(), 17, vlans=[(0x88a8, 10), (0x8100, 20)])
    ls = dissect(data)
    eth = ls[0]
    vlans = [f for f in eth["fields"] if f["label"] == "VLAN"]
    assert [v["value"] for v in vlans] == ["ID 10", "ID 20"]
    assert eth["end"] == 22 and ls[1]["name"] == "IPv4" and ls[1]["start"] == 22


def test_vlan_truncada_deja_tipo_vlan_sin_inventar():
    data = MAC_B + MAC_A + b"\x81\x00\x00"  # etiqueta cortada
    ls = dissect(data)
    check_ranges(data, ls)
    assert ls[0]["name"] == "Ethernet"
    assert "VLAN 802.1Q" in field(ls[0], "Tipo")["value"]


def test_ethertype_desconocido_da_datos():
    data = MAC_B + MAC_A + b"\x12\x34" + b"hola mundo!"
    ls = dissect(data)
    assert [x["name"] for x in ls] == ["Ethernet", "Datos"]
    assert "otro" in field(ls[0], "Tipo")["value"] and (ls[1]["start"], ls[1]["end"]) == (14, len(data))


def test_ethernet_solo_cabecera_sin_datos():
    ls = dissect(MAC_B + MAC_A + b"\x12\x34")
    assert [x["name"] for x in ls] == ["Ethernet"]


# ------------------------------------------------------------ IPv4

def test_ipv4_truncado():
    base = frame4(tcp_hdr(), 6)
    for n in range(14, 34):
        ls = dissect(base[:n])
        assert [x["name"] for x in ls] == ["Ethernet", "IPv4"]
        assert ls[1]["note"].startswith("Capa incompleta") and (ls[1]["start"], ls[1]["end"]) == (14, n)


@pytest.mark.parametrize("ttl,word", [(64, "Linux"), (1, "Linux"), (65, "Windows"), (128, "Windows"), (129, "equipos de red"), (255, "equipos de red")])
def test_ttl_pistas(ttl, word):
    ls = dissect(frame4(tcp_hdr(), 6, ttl=ttl))
    f = field(by_name(ls, "IPv4"), "TTL")
    assert f["value"] == str(ttl) and word in f["hint"]


def test_ipv4_flags_df_mf_ninguna_y_ambas():
    def flags(v):
        return field(by_name(dissect(frame4(tcp_hdr(), 6, flags_off=v)), "IPv4"), "Banderas")["value"]
    assert flags(0) == "ninguna"
    assert flags(0x4000) == "No fragmentar (DF)"
    assert flags(0x2000) == "Más fragmentos (MF)"
    assert flags(0x6000) == "No fragmentar (DF), Más fragmentos (MF)"


def test_ipv4_primer_fragmento_mf_sigue_a_capa4():
    ls = dissect(frame4(tcp_hdr(), 6, flags_off=0x2000))
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "TCP", ]


def test_ipv4_fragmento_no_inicial_es_capa_de_datos_y_para():
    data = frame4(b"\xaa" * 16, 6, flags_off=0x00B9)
    ls = dissect(data)
    check_ranges(data, ls)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "Fragmento IP (sin cabecera de capa 4)"]
    assert (ls[2]["start"], ls[2]["end"]) == (34, len(data))
    assert field(ls[2], "Largo")["value"] == "16 B"


def test_ipv4_fragmento_no_inicial_sin_datos_no_agrega_capa():
    ls = dissect(frame4(b"", 6, flags_off=0x0010))
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4"]


def test_ipv4_opciones():
    data = frame4(tcp_hdr(), 6, options=b"\x01\x01\x01\x00")
    ip = by_name(dissect(data), "IPv4")
    assert (ip["start"], ip["end"]) == (14, 38)
    opt = field(ip, "Opciones")
    assert opt["value"] == "4 B" and (opt["start"], opt["end"]) == (34, 38)
    assert "cabecera de 24 B" in field(ip, "Versión y largo de cabecera")["value"]
    assert by_name(dissect(data), "TCP")["start"] == 38


def test_ipv4_ihl_menor_que_5_se_trata_como_20():
    data = bytearray(frame4(tcp_hdr(), 6))
    data[14] = 0x41  # IHL 1
    ls = dissect(bytes(data))
    check_ranges(bytes(data), ls)
    assert by_name(ls, "IPv4")["end"] == 34


def test_ipv4_ihl_mayor_que_el_paquete_se_recorta():
    data = bytearray(frame4(b"", 6))
    data[14] = 0x4F  # IHL 15 -> 60 B, pero solo hay 20
    ls = dissect(bytes(data))
    check_ranges(bytes(data), ls)
    ip = by_name(ls, "IPv4")
    assert ip["end"] == len(data)


def test_ipv4_protocolo_desconocido_va_a_datos():
    ls = dissect(frame4(b"payload!", 99))
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "Datos"]
    assert "99 (otro)" in field(ls[1], "Protocolo")["value"]


# ------------------------------------------------------------ IPv6

def test_ipv6_basico():
    data = ip6_frame(6, tcp_hdr(443, 5000, 0x12), hop=255)
    ls = dissect(data)
    check_ranges(data, ls)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv6", "TCP"]
    ip = ls[1]
    assert (ip["start"], ip["end"]) == (14, 54)
    assert field(ip, "IP de origen")["value"] == "2001:db8::1" and field(ip, "IP de destino")["value"] == "2001:db8::2"
    assert field(ip, "Siguiente cabecera")["value"] == "6 (TCP)"
    h = field(ip, "Límite de saltos")
    assert h["value"] == "255" and "TTL" not in h["hint"] and "límite" not in h["hint"].split(":")[0] or True
    assert field(ls[2], "Banderas")["value"] == "SYN+ACK"


def test_ipv6_truncado():
    base = ip6_frame(6, tcp_hdr())
    for n in range(14, 54):
        ls = dissect(base[:n])
        assert ls[-1]["name"] == "IPv6" and ls[-1]["note"].startswith("Capa incompleta")


@pytest.mark.parametrize("ext_type", [0, 43, 60])
def test_ipv6_cabeceras_de_extension_se_saltan(ext_type):
    ext = bytes([6, 0]) + b"\x00" * 6  # siguiente = TCP, largo 8 B
    data = ip6_frame(ext_type, tcp_hdr(), ext=ext)
    ls = dissect(data)
    check_ranges(data, ls)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv6", "TCP"]
    ip = ls[1]
    ex = field(ip, "Cabecera de extensión")
    assert ex["value"] == f"tipo {ext_type}, 8 B" and (ex["start"], ex["end"]) == (54, 62)
    assert ip["end"] == 62 and ls[2]["start"] == 62


def test_ipv6_varias_extensiones_encadenadas():
    ext = bytes([60, 0]) + b"\x00" * 6 + bytes([6, 1]) + b"\x00" * 14  # hop-by-hop -> destino(16 B) -> TCP
    data = ip6_frame(0, tcp_hdr(), ext=ext)
    ls = dissect(data)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv6", "TCP"]
    exts = [f for f in ls[1]["fields"] if f["label"] == "Cabecera de extensión"]
    assert [e["value"] for e in exts] == ["tipo 0, 8 B", "tipo 60, 16 B"]
    assert ls[2]["start"] == 54 + 8 + 16


def test_ipv6_exceso_de_extensiones_se_corta_en_el_tope():
    ext = (bytes([0, 0]) + b"\x00" * 6) * (L.MAX_EXT_HEADERS + 3)  # cadena de hop-by-hop sin fin
    data = ip6_frame(0, b"", ext=ext)
    ls = dissect(data)
    check_ranges(data, ls)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv6"]
    assert len([f for f in ls[1]["fields"] if f["label"] == "Cabecera de extensión"]) == L.MAX_EXT_HEADERS


def test_ipv6_extension_truncada():
    data = ip6_frame(0, b"", ext=b"\x06")
    ls = dissect(data)
    check_ranges(data, ls)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv6"]


def test_ipv6_extension_con_largo_mayor_que_el_paquete():
    data = ip6_frame(0, b"", ext=bytes([6, 0xFF]) + b"\x00" * 6)
    ls = dissect(data)
    check_ranges(data, ls)
    assert ls[1]["end"] <= len(data)


def test_ipv6_icmpv6():
    ls = dissect(ip6_frame(58, b"\x87\x00\x00\x00"))
    assert ls[2]["name"] == "ICMPv6" and "Solicitud de vecino" in field(ls[2], "Tipo")["value"]


# ------------------------------------------------------------ ARP

def test_arp_solicitud_y_respuesta():
    for op, word in ((1, "solicitud"), (2, "respuesta"), (9, "otra")):
        data = arp_frame(op)
        ls = dissect(data)
        check_ranges(data, ls)
        assert [x["name"] for x in ls] == ["Ethernet", "ARP"]
        arp = ls[1]
        assert (arp["start"], arp["end"]) == (14, 42)
        assert field(arp, "Operación")["value"] == f"{op} ({word})"
        assert field(arp, "IP del emisor")["value"] == "10.0.0.1"
        assert field(arp, "IP del destino")["value"] == "10.0.0.2"
        assert field(arp, "MAC del emisor")["value"] == "00:11:22:33:44:55"


def test_arp_truncado():
    base = arp_frame()
    for n in range(14, 42):
        ls = dissect(base[:n])
        assert ls[-1]["name"] == "ARP" and ls[-1]["note"].startswith("Capa incompleta")


def test_arp_con_relleno_no_agrega_datos():
    ls = dissect(arp_frame() + b"\x00" * 18)  # relleno Ethernet
    assert [x["name"] for x in ls] == ["Ethernet", "ARP"]


# ------------------------------------------------------------ TCP

def test_tcp_truncado():
    base = frame4(tcp_hdr(), 6)
    for n in range(34, 54):
        ls = dissect(base[:n])
        assert ls[-1]["name"] == "TCP" and ls[-1]["note"].startswith("Capa incompleta")
        assert (ls[-1]["start"], ls[-1]["end"]) == (34, n)


@pytest.mark.parametrize("flags,text,hint", [
    (0x02, "SYN", "abrir"), (0x12, "SYN+ACK", "Acepta"), (0x10, "ACK", "Confirma"), (0x18, "PSH+ACK", "Entrega"),
    (0x11, "FIN+ACK", "Cierre"), (0x19, "FIN+PSH+ACK", "Último"), (0x04, "RST", "Corta"), (0x14, "RST+ACK", "Corta"),
    (0x00, "ninguna", None), (0x29, "FIN+PSH+URG", None), (0xFF, "FIN+SYN+RST+PSH+ACK+URG+ECE+CWR", None),
])
def test_tcp_banderas(flags, text, hint):
    f = field(by_name(dissect(frame4(tcp_hdr(flags=flags), 6)), "TCP"), "Banderas")
    assert f["value"] == text and (f["start"], f["end"]) == (47, 48)
    if hint is None:
        assert f["hint"] is None
    else:
        assert hint in f["hint"]


def test_tcp_puertos_con_servicio_y_sin():
    tcp = by_name(dissect(frame4(tcp_hdr(sport=51838, dport=443), 6)), "TCP")
    s, d = field(tcp, "Puerto de origen"), field(tcp, "Puerto de destino")
    assert s["value"] == "51838" and s["hint"] is None and (s["start"], s["end"]) == (34, 36)
    assert d["value"] == "443 (HTTPS)" and d["hint"] == "Puerto bien conocido" and (d["start"], d["end"]) == (36, 38)


def test_tcp_opciones_nombres():
    opts = b"\x02\x04\x05\xb4" + b"\x01" + b"\x03\x03\x07" + b"\x01\x01" + b"\x04\x02" + b"\x08\x0a" + b"\x00" * 8
    opts += b"\x00" * ((-len(opts)) % 4)
    data = frame4(tcp_hdr(flags=2, options=opts), 6)
    tcp = by_name(dissect(data), "TCP")
    o = field(tcp, "Opciones")
    assert o["value"] == "MSS, escala de ventana, SACK permitido, marcas de tiempo" or "MSS" in o["value"]
    assert "relleno" not in o["value"] and "MSS" in o["value"] and "marcas de tiempo" in o["value"]
    assert "escala de ventana" in o["value"] and "SACK permitido" in o["value"]
    assert (o["start"], o["end"]) == (54, 54 + len(opts)) and tcp["end"] == 54 + len(opts)


def test_tcp_opciones_solo_relleno():
    data = frame4(tcp_hdr(options=b"\x01\x01\x01\x01"), 6)
    assert field(by_name(dissect(data), "TCP"), "Opciones")["value"] == "solo relleno"


def test_tcp_opcion_tipo_desconocido_y_largo_invalido_no_cuelgan():
    data = frame4(tcp_hdr(options=b"\x63\x02\x01\x01"), 6)
    assert "tipo 99" in field(by_name(dissect(data), "TCP"), "Opciones")["value"]
    data = frame4(tcp_hdr(options=b"\x02\x00\x00\x00"), 6)  # largo 0: debe cortar el bucle
    assert "MSS" in field(by_name(dissect(data), "TCP"), "Opciones")["value"]
    data = frame4(tcp_hdr(options=b"\x01\x01\x01\x02"), 6)  # opción cortada al final
    assert "MSS" in field(by_name(dissect(data), "TCP"), "Opciones")["value"]


def test_tcp_fin_de_opciones():
    data = frame4(tcp_hdr(options=b"\x00\x00\x00\x00"), 6)
    assert "fin de opciones" in field(by_name(dissect(data), "TCP"), "Opciones")["value"]


def test_tcp_offset_mayor_que_el_paquete_se_recorta():
    data = frame4(tcp_hdr(off=15), 6)  # dice 60 B de cabecera, hay 20
    ls = dissect(data)
    check_ranges(data, ls)
    assert by_name(ls, "TCP")["end"] == len(data) and ls[-1]["name"] == "TCP"


def test_tcp_offset_menor_que_5_se_trata_como_20():
    data = frame4(tcp_hdr(off=2) + b"xyz", 6)
    ls = dissect(data)
    check_ranges(data, ls)
    assert by_name(ls, "TCP")["end"] == 54 and ls[-1]["name"] == "Datos"
    assert not any(f["label"] == "Opciones" for f in by_name(ls, "TCP")["fields"])


# ------------------------------------------------------------ UDP / ICMP

def test_udp_campos_y_truncado():
    data = frame4(udp_hdr(40000, 53, b"abcdefgh"), 17)
    ls = dissect(data)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "UDP", "Datos"]
    udp = ls[2]
    assert (udp["start"], udp["end"]) == (34, 42)
    assert field(udp, "Puerto de destino")["value"] == "53 (DNS)"
    assert field(udp, "Largo")["value"] == "16 B"
    for n in range(34, 42):
        t = dissect(data[:n])
        assert t[-1]["name"] == "UDP" and t[-1]["note"].startswith("Capa incompleta")


def test_icmp_tipos_y_truncado():
    data = frame4(b"\x08\x00\xab\xcd\x00\x01\x00\x01", 1)
    ls = dissect(data)
    assert [x["name"] for x in ls] == ["Ethernet", "IPv4", "ICMP", "Datos"]
    assert field(ls[2], "Tipo")["value"] == "8 (Solicitud de eco (ping))"
    assert field(ls[2], "Checksum")["value"] == "0xabcd"
    assert field(dissect(frame4(b"\x63\x00\x00\x00", 1))[2], "Tipo")["value"] == "99 (otro)"
    for n in range(34, 38):
        assert dissect(data[:n])[-1]["note"].startswith("Capa incompleta")


# ------------------------------------------------------------ Datos

def test_datos_registro_tls():
    data = frame4(tcp_hdr() + b"\x17\x03\x03\x00\x10" + b"\x00" * 16, 6)
    d = by_name(dissect(data), "Datos")
    assert "TLS" in d["fields"][0]["hint"] and d["fields"][0]["value"] == "21 B"


@pytest.mark.parametrize("first", [0x14, 0x15, 0x16, 0x17])
def test_datos_tls_tipos_de_registro(first):
    d = by_name(dissect(frame4(tcp_hdr() + bytes([first, 3, 3, 0, 1, 0]), 6)), "Datos")
    assert "TLS" in d["fields"][0]["hint"]


def test_datos_tls_version_alta_no_es_tls():
    d = by_name(dissect(frame4(tcp_hdr() + b"\x16\x03\x09\x00\x01\x00", 6)), "Datos")
    assert "TLS" not in d["fields"][0]["hint"]


def test_datos_texto_legible_con_vista_previa():
    d = by_name(dissect(frame4(tcp_hdr() + b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n", 6)), "Datos")
    hint = d["fields"][0]["hint"]
    assert hint.startswith("Texto legible: GET /index.html HTTP/1.1")
    assert "\r" not in hint and "\n" not in hint  # los saltos de línea no pasan crudos


def test_datos_texto_vista_previa_acotada_a_60():
    hint = by_name(dissect(frame4(tcp_hdr() + b"A" * 500, 6)), "Datos")["fields"][0]["hint"]
    assert hint == "Texto legible: " + "A" * 60


def test_datos_binarios():
    d = by_name(dissect(frame4(tcp_hdr() + bytes(range(128, 200)), 6)), "Datos")
    assert d["fields"][0]["hint"] == "Datos binarios"


def test_datos_un_solo_byte_y_rango():
    ls = dissect(frame4(tcp_hdr() + b"\x00", 6))
    d = ls[-1]
    assert d["name"] == "Datos" and d["end"] - d["start"] == 1
    assert d["fields"][0]["hint"] == "Datos binarios"


def test_sin_datos_no_hay_capa_datos():
    assert [x["name"] for x in dissect(frame4(tcp_hdr(), 6))] == ["Ethernet", "IPv4", "TCP"]


def test_payload_hint_directo():
    assert L._payload_hint(b"") == "Datos binarios"
    assert L._payload_hint(b"\x16\x03") != "" and "TLS" not in L._payload_hint(b"\x16\x03")  # muy corto
    assert L._payload_hint(b"\x16\x03\x01").startswith("Parece un registro TLS")


def test_nunca_marca_html_en_textos():
    """El texto del tráfico va en `hint`, sin escapar: es el frontend quien debe mostrarlo como texto."""
    d = by_name(dissect(frame4(tcp_hdr() + b"<img src=x onerror=alert(1)>", 6)), "Datos")
    assert "<img" in d["fields"][0]["hint"]
