"""Tests del corpus sintético: determinismo y extremo a extremo con las reglas reales."""
from backend.domain.rules.engine import load_rules
from validacion.generar_corpus import CASOS, RAIZ, construir_paquetes, generar
from validacion.validar import cargar_manifiesto, evaluar

CHICOS = [c for c in CASOS if not c.grande]


def test_generacion_determinista(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    generar(a, CHICOS)
    generar(b, CHICOS)
    for caso in CHICOS:
        assert (a / "corpus" / f"{caso.id}.pcap").read_bytes() == (b / "corpus" / f"{caso.id}.pcap").read_bytes()
    assert (a / "manifiesto_sintetico.yaml").read_bytes() == (b / "manifiesto_sintetico.yaml").read_bytes()


def test_semilla_distinta_cambia_el_trafico():
    caso = next(c for c in CASOS if c.id == "pos_syn_flood")
    assert construir_paquetes(caso, 1) != construir_paquetes(caso, 2)


def test_ids_unicos():
    ids = [c.id for c in CASOS]
    assert len(ids) == len(set(ids))


# Reglas que todavía no tienen caso en el corpus: su precisión NO está medida. Al agregarles un caso,
# sacarlas de acá (el test falla si una regla sale cubierta y sigue en la lista).
SIN_CASO_TODAVIA = {"dga_nxdomain", "icmp_tunnel", "malicious_ja4", "smb_rpc_lateral", "tls_certificate",
                    "user_agent_scanner", "user_agent_script"}


def test_cada_regla_tiene_caso_positivo_o_esta_declarada_sin_medir():
    reglas = {r.id for r in load_rules(RAIZ / "rules")}
    cubiertas = {e["regla"] for c in CASOS for e in c.esperadas}
    assert cubiertas <= reglas  # ningún caso apunta a una regla que no existe
    assert reglas - cubiertas == SIN_CASO_TODAVIA  # una regla nueva sin caso (o ya cubierta) obliga a decidir
    assert sum(1 for c in CASOS if not c.esperadas) >= 10


def test_manifiesto_del_repo_coincide_con_el_generador(tmp_path):
    generar(tmp_path, CASOS, con_grandes=False)
    nuevo = (tmp_path / "manifiesto_sintetico.yaml").read_bytes()
    assert nuevo == (RAIZ / "validacion" / "manifiesto_sintetico.yaml").read_bytes()


def test_extremo_a_extremo_positivo_y_benigno(tmp_path):
    reglas = load_rules(RAIZ / "rules")
    ids = {"pos_escaneo_rapido", "ben_navegacion", "pos_ftp_claro", "pos_escaneo_lento"}
    casos = [c for c in CHICOS if c.id in ids]
    entradas = {e.id: e for e in cargar_manifiesto(generar(tmp_path, casos))}
    res = {i: evaluar(entradas[i], reglas) for i in ids}
    assert len(res["pos_escaneo_rapido"].tp) == 1 and not res["pos_escaneo_rapido"].fp
    assert len(res["pos_ftp_claro"].tp) == 1
    assert res["ben_navegacion"].fp == [] and res["ben_navegacion"].fn == []
    assert len(res["pos_escaneo_lento"].tp) == 1 and not res["pos_escaneo_lento"].fn  # ventana larga


def test_pcap_inexistente_se_reporta_como_error(tmp_path):
    ruta = tmp_path / "m.yaml"
    ruta.write_text("pcaps:\n  - {id: x, ruta: no_existe.pcap}\n", encoding="utf-8")
    entrada = cargar_manifiesto(ruta)[0]
    assert evaluar(entrada, load_rules(RAIZ / "rules")).error
