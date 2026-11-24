"""Tests de los topes de memoria del motor de reglas (_LRU y detectores)."""
import dpkt
import pytest
import yaml

from backend.domain.rules.engine import (
    MAX_TRACKED, Decoded, DnsSuspiciousDetector, FtpCleartextDetector,
    PortScanDetector, Rule, RuleError, _LRU, load_rules,
)

SYN = 0x02


def rule(detector, **params):
    defaults = {"port_scan": {"min_ports": 15, "window_seconds": 60.0}}.get(detector, {})
    return Rule(id=detector, name="n", description="", severity="high", detector=detector,
                mitre_technique="T1046", mitre_name="x", mitre_tactic="y",
                params={**defaults, **params})


def syn(ts, dport, src="10.0.0.1", dst="10.0.0.2"):
    return Decoded(ts, src, dst, 6, 40000, dport, SYN, b"")


def scan(min_ports=15, window=60.0):
    return PortScanDetector(rule("port_scan", min_ports=min_ports, window_seconds=window))


# ------------------------------------------------------------------- _LRU

def test_lru_default_maxsize():
    assert _LRU().maxsize == MAX_TRACKED == 100_000


def test_lru_tope_exacto():
    d = _LRU(5)
    for i in range(5):
        d[i] = i
    assert len(d) == 5 and list(d) == [0, 1, 2, 3, 4]
    d[5] = 5
    assert len(d) == 5 and 0 not in d and list(d) == [1, 2, 3, 4, 5]


def test_lru_descarta_menos_reciente_y_reinsertar_refresca():
    d = _LRU(3)
    d["a"], d["b"], d["c"] = 1, 2, 3
    d["a"] = 10  # refresca a: ahora el menos reciente es b
    d["d"] = 4
    assert "b" not in d and set(d) == {"a", "c", "d"} and d["a"] == 10


def test_lru_maxsize_chico():
    d = _LRU(1)
    d["a"] = 1
    d["b"] = 2
    assert list(d) == ["b"]
    d["b"] = 3
    assert list(d.items()) == [("b", 3)]


def test_lru_get_no_refresca():
    # documentado: solo escribir refresca (get no mueve al final)
    d = _LRU(2)
    d["a"], d["b"] = 1, 2
    d.get("a")
    d["c"] = 3
    assert "a" not in d


# -------------------------------------------------------------- port_scan

def test_scan_100k_syn_mismo_puerto_una_entrada():
    det = scan()
    for i in range(100_000):
        assert det.feed(syn(i * 0.0001, 80)) == []
    (ports,) = det._seen.values()
    assert len(ports) == 1


def test_scan_estado_por_par_no_pasa_de_min_ports():
    det = scan(min_ports=5, window=1.0)
    for i in range(2000):  # puertos nuevos separados > ventana: nunca alerta
        assert det.feed(syn(i * 10.0, 1000 + i)) == []
        assert all(len(p) <= 5 for p in det._seen.values())


def test_scan_mas_pares_que_el_tope_queda_acotado():
    det = scan()
    det._seen = _LRU(50)
    for i in range(500):
        det.feed(syn(float(i), 80, src=f"10.1.{i // 250}.{i % 250}"))
    assert len(det._seen) == 50


def test_scan_default_tiene_tope_max_tracked():
    det = scan()
    assert det._seen.maxsize == MAX_TRACKED and det._alerted.maxsize == MAX_TRACKED


def test_scan_puertos_fuera_de_ventana_se_podan_y_no_disparan():
    det = scan(min_ports=3, window=10.0)
    assert det.feed(syn(0, 1)) == [] and det.feed(syn(1, 2)) == []
    assert det.feed(syn(100, 3)) == []  # 3 entradas, pero 1 y 2 vencidas
    (ports,) = det._seen.values()
    assert ports == {3: 100}


def test_scan_lento_no_dispara():
    det = scan(min_ports=3, window=10.0)
    assert all(det.feed(syn(i * 11.0, 1000 + i)) == [] for i in range(100))


def test_scan_dos_tandas_dentro_de_ventana_first_ts_mas_viejo():
    det = scan(min_ports=4, window=60.0)
    assert det.feed(syn(100, 1)) == [] and det.feed(syn(101, 2)) == []
    assert det.feed(syn(130, 3)) == []
    alerts = det.feed(syn(150, 4))
    assert len(alerts) == 1
    assert alerts[0].first_ts == 100 and alerts[0].evidence["distinct_ports"] == 4


def test_scan_first_ts_ignora_puertos_podados():
    det = scan(min_ports=3, window=10.0)
    det.feed(syn(0, 1))
    det.feed(syn(5, 2))
    det.feed(syn(100, 3))  # poda 1 y 2 (solo queda 3)
    det.feed(syn(101, 4))
    alerts = det.feed(syn(102, 5))
    assert len(alerts) == 1 and alerts[0].first_ts == 100


def test_scan_alerta_una_sola_vez_y_libera_estado():
    det = scan(min_ports=3)
    out = [a for i in range(10) for a in det.feed(syn(i, 100 + i))]
    assert len(out) == 1
    assert ("10.0.0.1", "10.0.0.2") not in det._seen


def test_scan_par_evictado_de_alerted_puede_volver_a_alertar():
    # Costo asumido y documentado
    det = scan(min_ports=2)
    det._alerted = _LRU(1)
    assert len(det.feed(syn(0, 1)) + det.feed(syn(1, 2))) == 1
    assert det.feed(syn(2, 3)) == []  # sigue silenciado
    other = det.feed(syn(3, 1, src="9.9.9.9")) + det.feed(syn(4, 2, src="9.9.9.9"))
    assert len(other) == 1  # desplaza al primer par de _alerted
    again = det.feed(syn(5, 7)) + det.feed(syn(6, 8))
    assert len(again) == 1  # el primer par volvio a alertar


def test_scan_par_evictado_de_seen_pierde_progreso():
    det = scan(min_ports=3)
    det._seen = _LRU(1)
    det.feed(syn(0, 1))
    det.feed(syn(1, 2))
    det.feed(syn(2, 1, src="9.9.9.9"))  # evicta el par original
    assert det.feed(syn(3, 3)) == []  # empieza de cero: solo 1 puerto


@pytest.mark.parametrize("v,ok", [(2, True), (65535, True), (65536, False), (1, False), (0, False)])
def test_min_ports_limites(tmp_path, v, ok):
    f = tmp_path / "r.yaml"
    f.write_text(yaml.safe_dump({
        "id": "ps", "name": "n", "severity": "high", "detector": "port_scan",
        "mitre": {"technique": "T1046", "name": "x", "tactic": "Discovery"},
        "params": {"min_ports": v}}), encoding="utf-8")
    if ok:
        assert load_rules(f)[0].params["min_ports"] == v
    else:
        with pytest.raises(RuleError, match="min_ports"):
            load_rules(f)


def test_min_ports_2_dispara_con_dos_puertos():
    det = scan(min_ports=2)
    assert len(det.feed(syn(0, 1)) + det.feed(syn(1, 2))) == 1


# ---------------------------------------------------------------- FTP / DNS

def ftp(ts, data, sport=5000, src="10.0.0.1"):
    return Decoded(ts, src, "10.0.0.2", 6, sport, 21, 0x18, data)


def test_ftp_dedupe_y_alerted_acotado():
    det = FtpCleartextDetector(rule("ftp_cleartext", ports=[21]))
    det._alerted = _LRU(3)
    det._users = _LRU(3)
    for i in range(10):
        out = det.feed(ftp(i, f"USER u{i}\r\n".encode(), sport=5000 + i))
        out += det.feed(ftp(i, b"PASS clave\r\n", sport=5000 + i))
        assert len(out) == 1
        assert out[0].evidence["password"] == "<oculta>" and out[0].evidence["password_length"] == 5
        assert "clave" not in repr(out[0].evidence)
        assert len(det._alerted) <= 3 and len(det._users) <= 3
    # dedupe sigue: mismo usuario reciente no vuelve a alertar
    det.feed(ftp(20, b"USER u9\r\n", sport=7000))
    assert det.feed(ftp(21, b"PASS otra\r\n", sport=7000)) == []


def test_ftp_usuario_evictado_queda_no_visto():
    det = FtpCleartextDetector(rule("ftp_cleartext", ports=[21]))
    det._users = _LRU(1)
    det.feed(ftp(0, b"USER a\r\n", sport=1))
    det.feed(ftp(1, b"USER b\r\n", sport=2))
    (a,) = det.feed(ftp(2, b"PASS x\r\n", sport=1))
    assert a.evidence["username"] == "<no visto>"


def dns(ts, name, src="10.0.0.1"):
    payload = bytes(dpkt.dns.DNS(id=1, op=dpkt.dns.DNS_RD,
                                 qd=[dpkt.dns.DNS.Q(name=name, type=1)]))
    return Decoded(ts, src, "10.0.0.2", 17, 4000, 53, 0, payload)


def test_dns_dedupe_y_alerted_acotado():
    det = DnsSuspiciousDetector(rule("dns_suspicious", max_label_length=40,
                                     min_entropy=3.5, entropy_min_label=20))
    det._alerted = _LRU(3)

    def long(i):
        return "a" * 45 + str(i) + ".evil.com"

    assert len(det.feed(dns(0, long(0)))) == 1
    assert det.feed(dns(1, long(0))) == []  # dedupe
    for i in range(1, 10):
        assert len(det.feed(dns(i, long(i)))) == 1
        assert len(det._alerted) <= 3
    assert len(det.feed(dns(99, long(0)))) == 1  # evictado: puede repetir
