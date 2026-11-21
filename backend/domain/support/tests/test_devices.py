"""devices: ARP, MAC, fabricantes y lista de dispositivos, sin tocar la red."""
import ipaddress

import pytest

from backend.domain.support import devices as D
from backend.domain.support.common import RunResult

WIN_ES = """
Interfaz: 192.168.1.10 --- 0x7
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           aa-bb-cc-00-11-22     dinámico
  192.168.1.20          10-20-30-40-50-60     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  239.255.255.250       01-00-5e-7f-ff-fa     estático
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
"""
WIN_EN = """
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-00-11-22     dynamic
  192.168.1.30          10-20-30-40-50-61     static
  ff02::1               33-33-00-00-00-01     static
"""
LINUX = "192.168.1.1 dev eth0 lladdr aa:bb:cc:00:11:22 REACHABLE\n192.168.1.9 dev eth0  FAILED\nfe80::1 dev eth0 lladdr aa:bb:cc:00:11:22 router STALE\n"


def arp_with(monkeypatch, text, win=True):
    monkeypatch.setattr(D, "IS_WINDOWS", win)
    monkeypatch.setattr(D, "IS_LINUX", not win)
    monkeypatch.setattr(D, "run", lambda cmd, timeout=15.0, env_extra=None: RunResult(True, 0, text, ""))
    return D.arp_table()


def test_arp_windows_es_y_descarta_multicast_broadcast(monkeypatch):
    t = arp_with(monkeypatch, WIN_ES)
    assert t == [{"ip": "192.168.1.1", "mac": "aa:bb:cc:00:11:22", "kind": "dinámico"},
                 {"ip": "192.168.1.20", "mac": "10:20:30:40:50:60", "kind": "estático"}]


def test_arp_windows_en(monkeypatch):
    t = arp_with(monkeypatch, WIN_EN)
    assert [(e["ip"], e["kind"]) for e in t] == [("192.168.1.1", "dinámico"), ("192.168.1.30", "estático")]


def test_arp_linux_ip_neigh(monkeypatch):
    t = arp_with(monkeypatch, LINUX, win=False)
    assert t == [{"ip": "192.168.1.1", "mac": "aa:bb:cc:00:11:22", "kind": "reachable"}]


def test_mac_helpers():
    assert D.norm_mac("AA-BB:cc.00 11 22") == "aabbcc001122"
    assert D.fmt_mac("AA-BB-CC-00-11-22") == "aa:bb:cc:00:11:22"
    assert D.is_random_mac("da:a1:19:00:00:01") and D.is_random_mac("02:00:00:00:00:00")
    assert not D.is_random_mac("00:1a:2b:3c:4d:5e") and not D.is_random_mac("zz")


def test_vendor_of_con_oui_temporal(monkeypatch, tmp_path):
    f = tmp_path / "oui.csv"
    f.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Acme Corp,Somewhere\nMA-L,xyz,Mala,x\n", encoding="utf-8")
    monkeypatch.setattr(D, "OUI_FILE", f)
    monkeypatch.setattr(D, "_oui_cache", None)
    assert D.vendor_of("aa:bb:cc:00:11:22") == "Acme Corp" and D.vendor_of("11:22:33:44:55:66") is None and D.vendor_of("aa") is None
    assert D.oui_available()
    monkeypatch.setattr(D, "_oui_cache", None)
    monkeypatch.setattr(D, "OUI_FILE", tmp_path / "no-existe.csv")
    assert not D.oui_available()
    monkeypatch.setattr(D, "_oui_cache", None)  # que no quede cacheado el vacío


def ad(name, ip, mask="255.255.255.0", gw=("192.168.1.1",), up=True, loop=False, apipa=False, mac="00:11:22:33:44:55"):
    return {"name": name, "up": up, "loopback": loop, "apipa": apipa, "mac": mac, "gateway": list(gw), "ipv4": [{"ip": ip, "mask": mask}]}


def test_local_subnets_only_routed(monkeypatch):
    cfg = {"adapters": [ad("eth", "192.168.1.10"), ad("wsl", "172.20.0.1", gw=()), ad("lo", "127.0.0.1", "255.0.0.0", loop=True),
                        ad("apipa", "169.254.1.1", "255.255.0.0", apipa=True), ad("down", "10.9.9.9", up=False), ad("big", "10.0.0.5", "255.0.0.0")]}
    monkeypatch.setattr(D, "network_config", lambda: cfg)
    allnets = {str(n) for n in D.local_subnets()}
    assert allnets == {"192.168.1.0/24", "172.20.0.0/24", "10.0.0.0/24"}  # la /8 se acota a /24
    routed = {str(n) for n in D.local_subnets(only_routed=True)}
    assert routed == {"192.168.1.0/24", "10.0.0.0/24"}


def test_list_devices(monkeypatch):
    cfg = {"adapters": [ad("eth", "192.168.1.10", mac="02:aa:bb:cc:dd:ee")], "hostname": "MI-PC"}
    monkeypatch.setattr(D, "network_config", lambda: cfg)
    monkeypatch.setattr(D, "default_gateway", lambda c=None: "192.168.1.1")
    monkeypatch.setattr(D, "arp_table", lambda: [
        {"ip": "192.168.1.30", "mac": "da:a1:19:00:00:01", "kind": "dinámico"},
        {"ip": "192.168.1.1", "mac": "00:bb:cc:00:11:22", "kind": "dinámico"},
        {"ip": "10.50.0.2", "mac": "aa:bb:cc:00:11:23", "kind": "dinámico"}])
    monkeypatch.setattr(D, "_resolve_names", lambda ips: {ip: None for ip in ips})
    monkeypatch.setattr(D, "vendor_of", lambda m: "Acme")
    monkeypatch.setattr(D, "oui_available", lambda: True)
    monkeypatch.setattr(D, "sweep", lambda nets: pytest.fail("sin scan no se barre"))
    r = D.list_devices()
    ips = [d["ip"] for d in r["devices"]]
    assert ips == ["192.168.1.1", "192.168.1.10", "192.168.1.30"]  # ordenado por IP, fuera de subred descartado
    by = {d["ip"]: d for d in r["devices"]}
    assert by["192.168.1.1"]["is_gateway"] and by["192.168.1.1"]["vendor"] == "Acme"
    assert by["192.168.1.10"]["is_self"] and by["192.168.1.10"]["hostname"] == "MI-PC"
    assert by["192.168.1.30"]["random_mac"] and by["192.168.1.30"]["vendor"] is None
    assert r["scanned"] is False and r["vendor_db"] is True and r["subnets"] == ["192.168.1.0/24"]


def test_list_devices_scan_barre_solo_subredes_ruteadas(monkeypatch):
    cfg = {"adapters": [ad("eth", "192.168.1.10")], "hostname": "h"}
    monkeypatch.setattr(D, "network_config", lambda: cfg)
    monkeypatch.setattr(D, "default_gateway", lambda c=None: None)
    monkeypatch.setattr(D, "arp_table", lambda: [])
    monkeypatch.setattr(D, "_resolve_names", lambda ips: {})
    got = []
    monkeypatch.setattr(D, "sweep", lambda nets: got.append(nets) or 254)
    r = D.list_devices(scan=True)
    assert r["scanned"] and r["swept_hosts"] == 254 and got == [[ipaddress.ip_network("192.168.1.0/24")]]
