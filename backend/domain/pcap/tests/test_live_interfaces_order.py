"""Orden de interfaces (virtuales al final) y _is_virtual."""
import types

import pytest

from backend.domain.pcap import live
from backend.domain.pcap.live import InterfaceInfo, _is_virtual, _scapy_list_interfaces


@pytest.mark.parametrize("name,desc", [
    ("\\Device\\NPF_{1}", "WAN Miniport (IP)"),
    ("lo", "lo"), ("docker0", "docker0"), ("veth123", "veth123"), ("br-abc", "br-abc"),
    ("virbr0", "virbr0"), ("tun0", "tun0"), ("tap1", "tap1"),
    ("x", "Microsoft Loopback Adapter"), ("x", "VMware Virtual Ethernet"), ("x", "VirtualBox Host-Only (vbox)"),
    ("x", "Hyper-V Virtual Switch"), ("x", "vEthernet (Default Switch)"), ("x", "Bluetooth Device"),
    ("x", "Teredo Tunneling Pseudo-Interface"), ("x", "isatap adapter"), ("LO", "LO"),
])
def test_virtual(name, desc):
    assert _is_virtual(InterfaceInfo(name, desc)) is True


@pytest.mark.parametrize("name,desc", [
    ("eth0", "eth0"), ("Wi-Fi", "Wi-Fi"), ("Ethernet", "Ethernet"), ("wlan0", "wlan0"),
    ("\\Device\\NPF_{2}", "Intel(R) Ethernet Connection"), ("enp3s0", "enp3s0"), ("local0", "local0"),
])
def test_real(name, desc):
    assert _is_virtual(InterfaceInfo(name, desc)) is False


def _fake_scapy(monkeypatch, ifaces):
    objs = {i: types.SimpleNamespace(name=n, description=d) for i, (n, d) in enumerate(ifaces)}
    scapy = types.SimpleNamespace(conf=types.SimpleNamespace(ifaces=types.SimpleNamespace(values=lambda: objs.values())))
    monkeypatch.setattr(live, "_import_scapy", lambda: scapy)


def test_virtual_go_last_stable(monkeypatch):
    _fake_scapy(monkeypatch, [("lo", ""), ("docker0", ""), ("eth0", ""), ("veth123", ""),
                              ("Wi-Fi", "Wi-Fi"), ("br-abc", ""), ("Ethernet", "")])
    assert [i.name for i in _scapy_list_interfaces()] == [
        "eth0", "Wi-Fi", "Ethernet", "lo", "docker0", "veth123", "br-abc"]


def test_windows_order_and_empty_description(monkeypatch):
    _fake_scapy(monkeypatch, [("x1", "WAN Miniport (Network Monitor)"), ("x2", "Realtek PCIe"), ("x3", None)])
    res = _scapy_list_interfaces()
    assert [i.name for i in res] == ["x2", "x3", "x1"]
    assert res[1].description == "x3"  # description vacía -> usa el nombre


def test_all_virtual_keeps_order(monkeypatch):
    _fake_scapy(monkeypatch, [("lo", ""), ("docker0", "")])
    assert [i.name for i in _scapy_list_interfaces()] == ["lo", "docker0"]


def test_empty(monkeypatch):
    _fake_scapy(monkeypatch, [])
    assert _scapy_list_interfaces() == []
