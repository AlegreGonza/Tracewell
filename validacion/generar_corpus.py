"""Genera el corpus SINTÉTICO de validación (pcaps + manifiesto) con semilla fija."""
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import dpkt
import yaml

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from samples.generate_demo import dns_answer, dns_query, tcp, udp  # noqa: E402

SEMILLA = 20260101
T0 = 1_700_000_000.0
SYN, ACK, PSH, FIN, RST = (dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH,
                           dpkt.tcp.TH_FIN, dpkt.tcp.TH_RST)

ROUTER, SERVIDOR, MONITOR, CLIENTE = "10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.20"
ATACANTE_LAN, ATACANTE_WAN = "10.0.0.66", "203.0.113.50"
WEB, CDN, NUBE = "93.184.216.34", "151.101.1.69", "52.95.110.1"
SEGMENTO_GRANDE = 65000  # bytes de datos por segmento en las subidas grandes
SEGMENTOS_GRANDES = 156  # 156 * 65000 = 10,14 MB (> min_bytes de large_upload)


@dataclass
class Caso:
    """Un pcap del corpus con su verdad terreno."""

    id: str
    descripcion: str
    construir: Callable[["Linea", random.Random], None]
    esperadas: List[Dict[str, str]] = field(default_factory=list)
    etiquetas: List[str] = field(default_factory=list)
    grande: bool = False


class Linea:
    """Línea de tiempo de paquetes (instante, trama)."""

    def __init__(self):
        self.t = T0
        self.paquetes: List[Tuple[float, bytes]] = []

    def add(self, trama: bytes, dt: float = 0.01) -> None:
        self.t += dt
        self.paquetes.append((self.t, trama))

    def conexion(self, cli: str, srv: str, sport: int, dport: int, dt: float = 0.01) -> None:
        """Saludo de tres vías."""
        self.add(tcp(cli, srv, sport, dport, SYN), dt)
        self.add(tcp(srv, cli, dport, sport, SYN | ACK, ack=2), 0.01)
        self.add(tcp(cli, srv, sport, dport, ACK, seq=2, ack=2), 0.01)

    def cierre(self, cli: str, srv: str, sport: int, dport: int) -> None:
        self.add(tcp(cli, srv, sport, dport, FIN | ACK, seq=2, ack=2), 0.02)
        self.add(tcp(srv, cli, dport, sport, FIN | ACK, seq=2, ack=3), 0.01)

    def dns(self, cli: str, srv: str, nombre: str, sport: int, resp: str = WEB) -> None:
        self.add(udp(cli, srv, sport, 53, dns_query(nombre, sport & 0xFFFF)), 0.05)
        self.add(udp(srv, cli, 53, sport, dns_answer(nombre, resp, sport & 0xFFFF)), 0.02)

    def subida(self, cli: str, srv: str, sport: int, dport: int) -> None:
        """Sube ~10 MB de datos con respuestas pequeñas del servidor."""
        self.conexion(cli, srv, sport, dport)
        datos = b"A" * SEGMENTO_GRANDE
        for i in range(SEGMENTOS_GRANDES):
            self.add(tcp(cli, srv, sport, dport, PSH | ACK, datos, seq=2 + i, ack=2), 0.001)
            if i % 10 == 9:
                self.add(tcp(srv, cli, dport, sport, ACK, seq=2, ack=2 + i), 0.001)
        self.cierre(cli, srv, sport, dport)


def _esp(regla: str, origen: Optional[str] = None, destino: Optional[str] = None) -> Dict[str, str]:
    esperada = {"regla": regla}
    if origen:
        esperada["origen"] = origen
    if destino:
        esperada["destino"] = destino
    return esperada


# ------------------------------------------------------------------ positivos

def _escaneo_rapido(tl, rng):
    for i in range(30):
        tl.add(tcp(ATACANTE_LAN, SERVIDOR, 40000, 1000 + i, SYN), rng.uniform(0.02, 0.1))
        tl.add(tcp(SERVIDOR, ATACANTE_LAN, 1000 + i, 40000, RST | ACK), 0.001)


def _escaneo_lento(tl, rng):
    for i in range(25):
        tl.add(tcp(ATACANTE_LAN, SERVIDOR, 40000, 2000 + i, SYN), rng.uniform(9, 11))


def _fuerza_bruta(origen, destino, puerto, intentos, lo, hi):
    def construir(tl, rng):
        for i in range(intentos):
            tl.conexion(origen, destino, 41000 + i, puerto, rng.uniform(lo, hi))
            tl.cierre(origen, destino, 41000 + i, puerto)
    return construir


def _syn_flood(tl, rng):
    for i in range(300):
        origen = f"198.51.100.{rng.randint(1, 254)}"
        tl.add(tcp(origen, SERVIDOR, rng.randint(1024, 65535), 80, SYN), 0.01)


def _beacon_tcp(media, variacion, eventos):
    def construir(tl, rng):
        for i in range(eventos):
            tl.conexion(CLIENTE, "104.21.45.12", 42000 + i, 8080, media * (1 + rng.uniform(-variacion, variacion)))
            tl.cierre(CLIENTE, "104.21.45.12", 42000 + i, 8080)
    return construir


def _beacon_udp(tl, rng):
    for i in range(10):
        tl.add(udp(CLIENTE, "91.121.5.9", 43000, 5000, b"ping%02d" % i), 30 * (1 + rng.uniform(-0.02, 0.02)))


def _dns_tunel(tl, rng):
    for i in range(6):
        etiqueta = "".join(rng.choice("0123456789abcdef") for _ in range(52))
        tl.dns(CLIENTE, ROUTER, f"{etiqueta}.t.exfil-example.net", 44000 + i)


def _dns_dga(tl, rng):
    for i in range(5):
        etiqueta = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(22))
        tl.dns(CLIENTE, ROUTER, f"{etiqueta}.com", 44100 + i)


def _dns_tunel_corto(tl, rng):
    for i in range(6):
        a = "".join(rng.choice("0123456789abcdef") for _ in range(18))
        b = "".join(rng.choice("0123456789abcdef") for _ in range(40))
        tl.dns(CLIENTE, ROUTER, f"{a}.{b}.t.exfil-example.net", 44200 + i)


def _ftp(puerto):
    def construir(tl, rng):
        tl.conexion(CLIENTE, SERVIDOR, 52000, puerto)
        tl.add(tcp(SERVIDOR, CLIENTE, puerto, 52000, PSH | ACK, b"220 FTP ready\r\n", seq=2, ack=2))
        tl.add(tcp(CLIENTE, SERVIDOR, 52000, puerto, PSH | ACK, b"USER admin\r\n", seq=2, ack=17))
        tl.add(tcp(SERVIDOR, CLIENTE, puerto, 52000, PSH | ACK, b"331 Password required\r\n", seq=17, ack=14))
        tl.add(tcp(CLIENTE, SERVIDOR, 52000, puerto, PSH | ACK, b"PASS hunter2\r\n", seq=14, ack=40))
    return construir


def _subida_a(destino, puerto=443):
    def construir(tl, rng):
        tl.subida(CLIENTE, destino, 45000, puerto)
    return construir


def _puerto_sospechoso(destino, puerto):
    def construir(tl, rng):
        tl.conexion(CLIENTE, destino, 46000, puerto)
        tl.add(tcp(CLIENTE, destino, 46000, puerto, PSH | ACK, b"hello\r\n", seq=2, ack=2), 0.05)
        tl.cierre(CLIENTE, destino, 46000, puerto)
    return construir


def _dns_a(resolvedor, nombres):
    def construir(tl, rng):
        for i, nombre in enumerate(nombres):
            tl.dns(CLIENTE, resolvedor, nombre, 47000 + i)
    return construir


def _ataque_combinado(tl, rng):
    _escaneo_rapido(tl, rng)
    _fuerza_bruta(ATACANTE_LAN, SERVIDOR, 22, 15, 0.3, 1.0)(tl, rng)
    tl.conexion(ATACANTE_LAN, SERVIDOR, 52100, 21)
    tl.add(tcp(ATACANTE_LAN, SERVIDOR, 52100, 21, PSH | ACK, b"USER root\r\n", seq=2, ack=2))
    tl.add(tcp(ATACANTE_LAN, SERVIDOR, 52100, 21, PSH | ACK, b"PASS toor\r\n", seq=14, ack=2))


# -------------------------------------------------------------------- benignos

def _navegacion(tl, rng):
    sitios = [WEB, CDN, "142.250.80.46", "13.107.42.14", "104.18.32.7", "31.13.72.36"]
    for i, nombre in enumerate(["www.example.com", "fonts.googleapis.com", "cdn.example.org"]):
        tl.dns(CLIENTE, ROUTER, nombre, 48000 + i)
    for i in range(40):
        sitio = rng.choice(sitios)
        tl.conexion(CLIENTE, sitio, 49000 + i, 443, rng.expovariate(1 / 3.0))
        tl.add(tcp(CLIENTE, sitio, 49000 + i, 443, PSH | ACK, b"\x16\x03\x01" + bytes(200), seq=2, ack=2))
        tl.cierre(CLIENTE, sitio, 49000 + i, 443)


def _cdn_rafaga(tl, rng):
    for i in range(70):
        tl.conexion(CLIENTE, CDN, 50000 + i, 443, rng.expovariate(1 / 0.08))


def _pico_legitimo(tl, rng):
    for i in range(250):
        origen = f"172.16.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        tl.add(tcp(origen, "10.0.0.80", rng.randint(1024, 65535), 443, SYN), rng.uniform(0.01, 0.05))


def _bateria_tiempos(tl, rng):  # ssh automatizado de un administrador
    _fuerza_bruta(MONITOR, SERVIDOR, 22, 14, 1.0, 3.0)(tl, rng)


def _login_ad(tl, rng):
    puertos = [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 49152, 49153, 49154, 5985, 9389, 593]
    for i, puerto in enumerate(puertos):
        tl.conexion(CLIENTE, "10.0.0.2", 51000 + i, puerto, rng.uniform(0.05, 0.15))


def _dns_normal(tl, rng):
    nombres = ["www.example.com", "mail.example.org", "api.github.com", "login.microsoftonline.com",
               "internal-svc-prod-alb-1234567890.us-east-1.elb.amazonaws.com"]
    for i, nombre in enumerate(nombres):
        tl.dns(CLIENTE, ROUTER, nombre, 52000 + i)
    tl.dns(CLIENTE, "8.8.8.8", "www.example.com", 52100)


def _dns_label_largo(tl, rng):
    largo = "campana-primavera-oferta-especial-envio-gratis-todo-el-pais"
    tl.dns(CLIENTE, ROUTER, f"{largo}.tienda-example.com", 52200)


def _dns_hash(tl, rng):
    tl.dns(CLIENTE, ROUTER, "5f4dcc3b5aa765d61d8327deb882cf99.reputation.example.net", 52300)


def _backup(destino):
    def construir(tl, rng):
        tl.subida(CLIENTE, destino, 53000, 443 if destino == NUBE else 445)
    return construir


def _ntp_mdns(tl, rng):
    for i in range(12):
        tl.add(udp(CLIENTE, "162.159.200.1", 123, 123, bytes(48)), 64)
    for i in range(12):
        tl.add(udp(CLIENTE, "224.0.0.251", 5353, 5353, bytes(30)), 30)
        tl.add(udp(CLIENTE, "239.255.255.250", 50000, 1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"), 0.5)


def _monitoreo(tl, rng):
    for i in range(15):
        tl.conexion(MONITOR, CLIENTE, 54000 + i, 10050, 60 + rng.uniform(-0.4, 0.4))
        tl.cierre(MONITOR, CLIENTE, 54000 + i, 10050)


def _ssh_normal(tl, rng):
    tl.conexion(CLIENTE, SERVIDOR, 55000, 22)
    for i in range(20):
        tl.add(tcp(CLIENTE, SERVIDOR, 55000, 22, PSH | ACK, b"x" * 64, seq=2 + i, ack=2), rng.uniform(0.1, 2))
    tl.cierre(CLIENTE, SERVIDOR, 55000, 22)


NOMBRES_NORMALES = ["www.example.com", "mail.example.org", "api.github.com"]
ISP_DNS = "80.58.61.250"

CASOS: List[Caso] = [
    Caso("pos_escaneo_rapido", "30 puertos en ~2 s contra un servidor", _escaneo_rapido,
         [_esp("port_scan", ATACANTE_LAN, SERVIDOR)], ["positivo"]),
    Caso("pos_escaneo_lento", "25 puertos, uno cada ~10 s (evasión por lentitud)", _escaneo_lento,
         [_esp("port_scan", ATACANTE_LAN, SERVIDOR)], ["positivo", "evasion"]),
    Caso("pos_ssh_fuerza_bruta", "18 conexiones SSH en ~18 s desde fuera", _fuerza_bruta(
        ATACANTE_WAN, SERVIDOR, 22, 18, 0.5, 1.5), [_esp("brute_force_remote", ATACANTE_WAN, SERVIDOR)], ["positivo"]),
    Caso("pos_rdp_fuerza_bruta", "12 conexiones RDP en ~24 s", _fuerza_bruta(
        "10.0.0.77", "10.0.0.6", 3389, 12, 1.0, 3.0), [_esp("brute_force_remote", "10.0.0.77", "10.0.0.6")], ["positivo"]),
    Caso("pos_ssh_lento", "12 intentos SSH, uno cada ~20 s con variación (evasión por lentitud)", _fuerza_bruta(
        ATACANTE_WAN, SERVIDOR, 22, 12, 12, 28), [_esp("brute_force_remote", ATACANTE_WAN, SERVIDOR)],
         ["positivo", "evasion"]),
    Caso("pos_syn_flood", "300 SYN de orígenes falsificados en 3 s contra :80", _syn_flood,
         [_esp("syn_flood", None, SERVIDOR)], ["positivo"]),
    Caso("pos_beaconing_tcp", "12 conexiones cada 60 s con 2% de variación", _beacon_tcp(60, 0.02, 12),
         [_esp("beaconing", CLIENTE, "104.21.45.12")], ["positivo"]),
    Caso("pos_beaconing_udp", "10 datagramas UDP cada 30 s", _beacon_udp,
         [_esp("beaconing", CLIENTE, "91.121.5.9")], ["positivo"]),
    Caso("pos_beaconing_jitter", "12 conexiones cada 60 s con 35% de variación (evasión por jitter)",
         _beacon_tcp(60, 0.35, 12), [_esp("beaconing", CLIENTE, "104.21.45.12")], ["positivo", "evasion"]),
    Caso("pos_dns_tunel", "6 consultas con etiqueta hex de 52 caracteres", _dns_tunel,
         [_esp("dns_suspicious", CLIENTE, ROUTER)], ["positivo"]),
    Caso("pos_dns_dga", "5 dominios de 22 caracteres aleatorios", _dns_dga,
         [_esp("dns_suspicious", CLIENTE, ROUTER)], ["positivo"]),
    Caso("pos_dns_tunel_etiquetas_cortas", "datos repartidos en 2a etiqueta (evasión)", _dns_tunel_corto,
         [_esp("dns_suspicious", CLIENTE, ROUTER)], ["positivo", "evasion"]),
    Caso("pos_ftp_claro", "USER/PASS por el puerto 21", _ftp(21),
         [_esp("ftp_cleartext", CLIENTE, SERVIDOR)], ["positivo"]),
    Caso("pos_ftp_puerto_2121", "USER/PASS por un puerto FTP no estándar (evasión)", _ftp(2121),
         [_esp("ftp_cleartext", CLIENTE, SERVIDOR)], ["positivo", "evasion"]),
    Caso("pos_subida_grande", "10 MB subidos a un destino público", _subida_a(WEB),
         [_esp("large_upload", CLIENTE, WEB)], ["positivo"], grande=True),
    Caso("pos_puerto_4444", "conexión al puerto 4444 de un host público", _puerto_sospechoso("45.77.12.8", 4444),
         [_esp("suspicious_ports", CLIENTE, "45.77.12.8")], ["positivo"]),
    Caso("pos_resolver_raro", "consultas DNS a un resolvedor público fuera de la lista", _dns_a(
        "185.228.168.9", NOMBRES_NORMALES), [_esp("dns_unusual_resolver", CLIENTE, "185.228.168.9")], ["positivo"]),
    Caso("pos_ataque_combinado", "escaneo + fuerza bruta SSH + FTP en claro del mismo origen", _ataque_combinado,
         [_esp("port_scan", ATACANTE_LAN, SERVIDOR), _esp("brute_force_remote", ATACANTE_LAN, SERVIDOR),
          _esp("ftp_cleartext", ATACANTE_LAN, SERVIDOR)], ["positivo"]),
    Caso("ben_navegacion", "navegación normal: DNS local y 40 conexiones HTTPS irregulares", _navegacion, [], ["benigno"]),
    Caso("ben_cdn_rafaga", "70 conexiones HTTPS a un CDN en ~6 s (navegador)", _cdn_rafaga, [], ["benigno", "dificil"]),
    Caso("ben_pico_visitas", "250 clientes distintos a un servidor web en ~8 s (pico legítimo)", _pico_legitimo,
         [], ["benigno", "dificil"]),
    Caso("ben_ssh_automatizado", "14 conexiones SSH de un script de administración", _bateria_tiempos,
         [], ["benigno", "dificil"]),
    Caso("ben_login_dominio", "inicio de sesión de dominio: 16 puertos de un controlador en ~2 s", _login_ad,
         [], ["benigno", "dificil"]),
    Caso("ben_dns_normal", "DNS normal, un ELB de AWS (ignorado) y 8.8.8.8", _dns_normal, [], ["benigno"]),
    Caso("ben_dns_label_largo", "subdominio legible de 57 caracteres con guiones", _dns_label_largo,
         [], ["benigno", "dificil"]),
    Caso("ben_dns_hash_hex", "consulta de reputación con un hash MD5 como etiqueta", _dns_hash,
         [], ["benigno", "dificil"]),
    Caso("ben_backup_interno", "10 MB subidos a un servidor de la LAN", _backup("10.0.0.50"), [],
         ["benigno"], grande=True),
    Caso("ben_backup_nube", "copia de seguridad de 10 MB a un destino público", _backup(NUBE), [],
         ["benigno", "dificil"], grande=True),
    Caso("ben_ntp_mdns_ssdp", "NTP, mDNS y SSDP periódicos", _ntp_mdns, [], ["benigno", "dificil"]),
    Caso("ben_monitoreo_periodico", "agente de monitoreo que conecta cada 60 s", _monitoreo,
         [], ["benigno", "dificil"]),
    Caso("ben_dns_proveedor", "DNS al resolvedor del proveedor (público, no listado)", _dns_a(
        ISP_DNS, NOMBRES_NORMALES), [], ["benigno", "dificil"]),
    Caso("ben_servicio_9001", "servicio interno legítimo en el puerto 9001", _puerto_sospechoso("10.0.0.30", 9001),
         [], ["benigno", "dificil"]),
    Caso("ben_ssh_normal", "una sola sesión SSH interactiva", _ssh_normal, [], ["benigno"]),
]


# ----------------------------------------------------------------- escritura

def construir_paquetes(caso: Caso, semilla: int = SEMILLA) -> List[Tuple[float, bytes]]:
    """Paquetes del caso; la semilla se mezcla con el id para que cada caso sea independiente."""
    linea = Linea()
    caso.construir(linea, random.Random(f"{semilla}:{caso.id}"))
    return linea.paquetes


def escribir_pcap(ruta: Path, paquetes: List[Tuple[float, bytes]]) -> None:
    with open(ruta, "wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, trama in paquetes:
            w.writepkt(trama, ts=ts)


def entrada_manifiesto(caso: Caso, carpeta: str) -> dict:
    return {
        "id": caso.id, "ruta": f"{carpeta}/{caso.id}.pcap", "descripcion": caso.descripcion,
        "etiquetas": caso.etiquetas, "esperadas": caso.esperadas or "ninguna",
    }


def generar(destino: Path, casos: Optional[List[Caso]] = None, con_grandes: bool = True) -> Path:
    """Escribe los pcaps en destino/corpus y destino/manifiesto_sintetico.yaml."""
    casos = CASOS if casos is None else casos
    carpeta = destino / "corpus"
    carpeta.mkdir(parents=True, exist_ok=True)
    for caso in casos:
        if caso.grande and not con_grandes:
            continue
        escribir_pcap(carpeta / f"{caso.id}.pcap", construir_paquetes(caso))
    manifiesto = {
        "version": 1, "sintetico": True, "semilla": SEMILLA,
        "pcaps": [entrada_manifiesto(c, "corpus") for c in casos],
    }
    ruta = destino / "manifiesto_sintetico.yaml"
    ruta.write_text(yaml.safe_dump(manifiesto, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")
    return ruta


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--destino", type=Path, default=Path(__file__).resolve().parent)
    p.add_argument("--sin-grandes", action="store_true", help="omite los pcaps de ~10 MB")
    args = p.parse_args(argv)
    ruta = generar(args.destino, con_grandes=not args.sin_grandes)
    print(f"manifiesto: {ruta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
