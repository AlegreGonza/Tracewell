"""wifi (netsh, calidad, historial) y dupip (sonda ARP falsa)."""
import pytest

from backend.domain.support import dupip, wifi as W

NETSH_ES = """
Hay 1 interfaz en el sistema:

    Nombre                 : Wi-Fi
    Estado                 : conectado
    SSID                   : MiRed
    BSSID                  : aa:bb:cc:dd:ee:ff
    Tipo de radio          : 802.11ac
    Autenticación          : WPA2-Personal
    Banda                  : 5 GHz
    Canal                  : 36
    Velocidad de recepción (Mbps)  : 433.3
    Velocidad de transmisión (Mbps) : 390
    Señal                  : 82%
"""
NETSH_EN = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : HomeNet
    Radio type             : 802.11n
    Channel                : 6
    Receive rate (Mbps)    : 72
    Transmit rate (Mbps)   : 65
    Signal                 : 35%
"""


def test_parse_netsh_es_con_acentos():
    i = W.parse_netsh(NETSH_ES)
    assert i["ssid"] == "MiRed" and i["signal"] == 82 and i["channel"] == 36 and i["rx"] == 433 and i["tx"] == 390
    assert i["auth"] == "WPA2-Personal" and i["state"] == "conectado" and i["band"] == "5 GHz"


def test_parse_netsh_en():
    i = W.parse_netsh(NETSH_EN)
    assert i["ssid"] == "HomeNet" and i["signal"] == 35 and i["channel"] == 6 and i["rx"] == 72 and i["state"] == "connected"


def test_parse_netsh_sin_interfaz():
    assert W.parse_netsh("El servicio Configuración automática de WLAN (wlansvc) no se está ejecutando.") is None
    assert W.parse_netsh("") is None


@pytest.mark.parametrize("s,q", [(100, "buena"), (70, "buena"), (69, "regular"), (40, "regular"), (39, "débil"), (0, "débil"), (None, None)])
def test_quality(s, q):
    assert W.quality(s) == q


def test_wifi_history(monkeypatch):
    monkeypatch.setattr(W, "IS_WINDOWS", True)
    lst = [{"t": "2026-01-01T10:00:00", "id": 8003, "m": "desc"}, {"t": "2026-01-01T09:00:00", "id": 8001, "m": "con"}]
    monkeypatch.setattr(W, "powershell_json", lambda s, timeout=20.0: lst)
    r = W.wifi_history(100)
    assert r["available"] and r["disconnections"] == 1 and [e["kind"] for e in r["events"]] == ["desconectado", "conectado"]
    monkeypatch.setattr(W, "powershell_json", lambda s, timeout=20.0: lst[1])  # un solo dict
    assert len(W.wifi_history()["events"]) == 1
    monkeypatch.setattr(W, "powershell_json", lambda s, timeout=20.0: {"error": "Access denied"})
    assert W.wifi_history()["available"] is False
    monkeypatch.setattr(W, "powershell_json", lambda s, timeout=20.0: None)
    assert W.wifi_history()["available"] is False
    monkeypatch.setattr(W, "IS_WINDOWS", False)
    monkeypatch.setattr(W, "powershell_json", lambda *a, **k: pytest.fail("no debe llamar"))
    assert W.wifi_history()["available"] is False


# ------------------------------------------------------------------ dupip
@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.setattr(dupip, "IS_WINDOWS", False)
    monkeypatch.setattr(dupip, "network_config", lambda: {"adapters": [
        {"name": "eth", "up": True, "loopback": False, "apipa": False, "mac": "00:11:22:33:44:55", "ipv4": [{"ip": "192.168.1.10"}]}]})


def test_dup_duplicado(cfg, monkeypatch):
    monkeypatch.setattr(dupip, "_arp_probe", lambda ip, mac: {"ip": ip, "probed": True, "other_macs": ["aa:bb:cc:dd:ee:ff"], "duplicate": True})
    r = dupip.check_duplicate_ip()
    assert r["duplicate"] and r["advice"] and "misma IP" in r["summary"]


def test_dup_no_duplicado(cfg, monkeypatch):
    monkeypatch.setattr(dupip, "_arp_probe", lambda ip, mac: {"ip": ip, "probed": True, "other_macs": [], "duplicate": False})
    r = dupip.check_duplicate_ip()
    assert not r["duplicate"] and r["advice"] is None and "no se detectó" in r["summary"]


def test_dup_sonda_no_disponible(cfg, monkeypatch):
    monkeypatch.setattr(dupip, "_arp_probe", lambda ip, mac: {"ip": ip, "probed": False, "reason": "sin Npcap"})
    r = dupip.check_duplicate_ip()
    assert not r["duplicate"] and "No se pudo hacer la sonda" in r["summary"]


def test_dup_sin_sonda_pedida(cfg, monkeypatch):
    monkeypatch.setattr(dupip, "_arp_probe", lambda *a: pytest.fail("probe=False no sondea"))
    assert dupip.check_duplicate_ip(probe=False)["probes"] == []
