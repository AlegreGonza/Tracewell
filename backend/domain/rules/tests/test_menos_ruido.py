"""Menos ruido: agrupar barridos, contar solo lo que no respondió y no tomar un protocolo por beacon."""

from backend.domain.rules.tests.test_engine import SYN, SYNACK, tcp, udp
from backend.domain.rules.tests.test_extra_detectors import PUB, run, syns

def host(i):
    """Destino público número i (hasta ~64 000)."""
    return f"203.0.{i // 250}.{i % 250 + 1}"


def sweep(n, port=4444, src=PUB, step=0.1, answered=()):
    pk = []
    for i in range(n):
        dst = host(i)
        pk.append(tcp(i * step, src=src, dst=dst, sport=40000 + i, dport=port, flags=SYN))
        if i in answered:
            pk.append(tcp(i * step + 0.01, src=dst, dst=src, sport=port, dport=40000 + i, flags=SYNACK))
    return pk


# --------------------------------------------------------- suspicious_ports
def test_origen_publico_en_un_solo_destino_no_alerta():
    assert run_sp(sweep(1)) == []
    assert run_sp(sweep(2)) == []


def test_barrido_de_internet_da_una_sola_alerta_al_tercer_destino(tmp_path):
    a = run(tmp_path, "suspicious_ports", sweep(500))
    assert len(a) == 1
    assert a[0].evidence["distinct_hosts"] == 3 and a[0].evidence["first_destination"] == host(0)


def test_origen_interno_alerta_al_primer_intento(tmp_path):
    a = run(tmp_path, "suspicious_ports", [tcp(1.0, src="10.0.0.5", dst=PUB, dport=4444, flags=SYN)])
    assert len(a) == 1 and "distinct_hosts" not in a[0].evidence


def test_min_hosts_1_alerta_siempre(tmp_path):
    assert len(run(tmp_path, "suspicious_ports", sweep(1), {"min_hosts": 1})) == 1


def test_9001_ya_no_esta_en_la_lista_por_defecto(tmp_path):
    assert run(tmp_path, "suspicious_ports", sweep(10, port=9001)) == []


def run_sp(packets):
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        return run(Path(d), "suspicious_ports", packets)


# --------------------------------------------------------------- host_sweep
def test_barrido_de_un_puerto_a_20_destinos_alerta_una_vez(tmp_path):
    a = run(tmp_path, "host_sweep", sweep(60, port=445))
    assert len(a) == 1
    assert a[0].evidence["distinct_hosts"] == 20 and a[0].evidence["destination_port"] == 445


def test_destinos_que_responden_no_cuentan_como_barrido(tmp_path):
    # 30 sitios web que contestan: navegar no es un barrido
    assert run(tmp_path, "host_sweep", sweep(30, port=443, answered=set(range(30)))) == []


def test_poco_a_poco_fuera_de_la_ventana_no_alerta(tmp_path):
    assert run(tmp_path, "host_sweep", sweep(25, port=445, step=10.0)) == []


def test_menos_de_20_destinos_no_alerta(tmp_path):
    assert run(tmp_path, "host_sweep", sweep(19, port=445)) == []


# ---------------------------------------------------------------- port_scan
def ports_to_one_host(n, answered=()):
    pk = []
    for i in range(n):
        pk.append(tcp(i * 0.1, src="10.0.0.20", dst="10.0.0.2", sport=51000 + i, dport=1000 + i, flags=SYN))
        if i in answered:
            pk.append(tcp(i * 0.1 + 0.01, src="10.0.0.2", dst="10.0.0.20", sport=1000 + i, dport=51000 + i, flags=SYNACK))
    return pk


def test_port_scan_sin_respuestas_alerta(tmp_path):
    assert len(run(tmp_path, "port_scan", ports_to_one_host(20))) == 1


def test_port_scan_ignora_los_puertos_que_respondieron_en_la_ventana_corta(tmp_path):
    # un inicio de sesion de dominio: 20 servicios reales que contestan
    assert run(tmp_path, "port_scan", ports_to_one_host(20, answered=set(range(20)))) == []


def test_port_scan_con_mayoria_sin_respuesta_sigue_alertando(tmp_path):
    assert len(run(tmp_path, "port_scan", ports_to_one_host(30, answered=set(range(5))))) == 1


# ---------------------------------------------------------------- beaconing
def heartbeats(pairs, port=20001, events=10, interval=5.0):
    pk = []
    for p in range(pairs):
        for i in range(events):
            pk.append(udp(i * interval + p * 0.01, src=f"198.51.100.{p + 1}", dst=f"192.0.2.{p + 1}", dport=port))
    return sorted(pk, key=lambda x: x.ts)


def test_un_par_periodico_sigue_siendo_beacon(tmp_path):
    assert len(run(tmp_path, "beaconing", heartbeats(1))) == 1


def test_muchos_pares_con_el_mismo_ritmo_son_un_protocolo(tmp_path):
    assert run(tmp_path, "beaconing", heartbeats(12)) == []


def test_pocos_pares_con_el_mismo_ritmo_siguen_alertando(tmp_path):
    assert len(run(tmp_path, "beaconing", heartbeats(3))) == 3


def test_max_pairs_per_port_0_apaga_el_filtro(tmp_path):
    assert len(run(tmp_path, "beaconing", heartbeats(12), {"max_pairs_per_port": 0})) == 12


# --------------------------------------------------------------- syn_flood
def test_una_rafaga_lenta_de_un_origen_no_es_inundacion(tmp_path):
    # 200 SYN en ~5,7 s (35 por segundo) desde una sola IP al 3306
    assert run(tmp_path, "syn_flood", syns(200, step=0.0285)) == []


def test_una_inundacion_rapida_sigue_alertando(tmp_path):
    assert len(run(tmp_path, "syn_flood", syns(300, step=0.001))) == 1


def test_min_pps_0_vuelve_al_comportamiento_anterior(tmp_path):
    assert len(run(tmp_path, "syn_flood", syns(200, step=0.0285), {"min_pps": 0})) == 1
