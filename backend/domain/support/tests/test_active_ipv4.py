"""Helpers compartidos: active_ipv4, resumen de IP duplicada y subred de una IPv4."""
import ipaddress

from backend.domain.support import devices, dupip
from backend.domain.support.netinfo import active_ipv4


def adapter(name, ip, **kw):
    base = {"name": name, "up": True, "loopback": False, "apipa": False, "mac": "aa:bb:cc:dd:ee:ff",
            "gateway": ["192.168.1.1"], "ipv4": [{"ip": ip, "mask": "255.255.255.0"}]}
    return {**base, **kw}


def config(*adapters):
    return {"adapters": list(adapters), "hostname": "pc"}


def test_active_ipv4_descarta_caidos_loopback_y_apipa():
    cfg = config(
        adapter("ok", "192.168.1.10"),
        adapter("caido", "10.0.0.2", up=False),
        adapter("lo", "127.0.0.1", loopback=True),
        adapter("apipa", "169.254.1.1", apipa=True),
    )
    assert [(a["name"], v["ip"]) for a, v in active_ipv4(cfg)] == [("ok", "192.168.1.10")]


def test_active_ipv4_exige_mac_o_puerta_si_se_pide():
    cfg = config(adapter("sin_mac", "10.0.0.2", mac=None), adapter("sin_puerta", "10.0.1.2", gateway=[]))
    assert len(list(active_ipv4(cfg))) == 2
    assert [a["name"] for a, _ in active_ipv4(cfg, need_mac=True)] == ["sin_puerta"]
    assert [a["name"] for a, _ in active_ipv4(cfg, need_gateway=True)] == ["sin_mac"]


def test_active_ipv4_un_par_por_cada_ip():
    two = adapter("dos", "192.168.1.10", ipv4=[{"ip": "192.168.1.10", "mask": "255.255.255.0"}, {"ip": "192.168.1.11", "mask": "255.255.255.0"}])
    assert [v["ip"] for _a, v in active_ipv4(config(two))] == ["192.168.1.10", "192.168.1.11"]


def test_dupip_resumen_en_orden_de_prioridad():
    ok, fail = [{"probed": True}], [{"probed": False}]
    assert "misma IP" in dupip._summary(True, [{"time": "t"}], ok)
    assert "conflictos" in dupip._summary(False, [{"time": "t"}], ok)
    assert "no tiene una IP" in dupip._summary(False, [], [])
    assert "no se detectó duplicado" in dupip._summary(False, [], ok)
    assert "No se pudo hacer la sonda" in dupip._summary(False, [], ok + fail)


def test_subnet_of_mascara_invalida_y_red_enorme():
    assert devices._subnet_of({"ip": "192.168.1.10", "mask": "255.255.255.0"}) == ipaddress.IPv4Network("192.168.1.0/24")
    assert devices._subnet_of({"ip": "192.168.1.10", "mask": None}) is None
    assert devices._subnet_of({"ip": "10.1.2.3", "mask": "255.0.0.0"}) == ipaddress.IPv4Network("10.1.2.0/24")
