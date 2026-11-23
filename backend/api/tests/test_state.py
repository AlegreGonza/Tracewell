"""Tests directos de backend/controllers/state.py (helpers aislados)."""
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend.controllers.state import VERSION, Ctx, _rmtree, _session_id, _State, current, set_analysis, summary
from backend.domain.analysis.analyzer import analyze
from backend.domain.rules.engine import load_rules

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "rules")


@pytest.fixture(scope="module")
def an(rules):
    return analyze(ROOT / "samples" / "demo.pcap", rules)


def make_ctx(rules):
    return Ctx(state=_State(), rules=rules, samples_dir=ROOT / "samples", live_dir=None,
               make_source=lambda i: None, interface_lister=None, analyze=analyze)


def test_version_es_string():
    # VERSION es un string no vacío
    assert isinstance(VERSION, str) and VERSION


def test_state_inicial_vacio():
    # un _State nuevo no tiene análisis, captura ni carpeta propia
    s = _State()
    assert s.analysis is None and s.live is None and s.live_result is None and s.owned_dir is None


def test_rmtree_none_no_falla():
    # _rmtree(None) es no-op
    _rmtree(None)


def test_rmtree_ruta_inexistente(tmp_path):
    # _rmtree tolera rutas que no existen
    _rmtree(tmp_path / "nope")


def test_rmtree_borra_carpeta(tmp_path):
    # _rmtree borra la carpeta con contenido
    d = tmp_path / "x"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "f").write_text("a")
    _rmtree(d)
    assert not d.exists()


def test_current_sin_analisis_409(rules):
    # current() sin análisis lanza HTTPException 409
    with pytest.raises(HTTPException) as e:
        current(make_ctx(rules))
    assert e.value.status_code == 409


def test_current_devuelve_analisis(rules, an):
    # current() devuelve el análisis guardado
    ctx = make_ctx(rules)
    ctx.state.analysis = an
    assert current(ctx) is an


def test_session_id_valido(an):
    # _session_id devuelve el id de una sesión del análisis
    s = an.result.sessions[0]
    assert _session_id(an, s) == an.session_id(s.key)


def test_session_id_fuera_del_indice(an):
    # _session_id lanza RuntimeError si la sesión no está en el índice
    with pytest.raises(RuntimeError):
        _session_id(an, SimpleNamespace(key=("no", "existe")))


def test_summary_claves(an):
    # summary tiene las claves esperadas y alerts es un entero
    s = summary(an)
    assert set(s) == {"source", "format", "linktype", "snaplen", "stats", "alerts", "rules", "processes"}
    assert s["source"] == "demo.pcap" and s["alerts"] == len(an.alerts)
    assert set(s["rules"][0]) == {"id", "name", "severity"}
    assert isinstance(s["stats"], dict)


def test_set_analysis_primera_vez(rules, an, tmp_path):
    # set_analysis guarda análisis y owned_dir y devuelve el summary
    ctx = make_ctx(rules)
    out = set_analysis(ctx, an, owned_dir=tmp_path)
    assert ctx.state.analysis is an and ctx.state.owned_dir == tmp_path
    assert out == summary(an)


def test_set_analysis_borra_carpeta_previa(rules, an, tmp_path):
    # al reemplazar con otra carpeta, se borra la previa
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    ctx = make_ctx(rules)
    set_analysis(ctx, an, owned_dir=a_dir)
    set_analysis(ctx, an, owned_dir=b_dir)
    assert not a_dir.exists() and b_dir.exists()


def test_set_analysis_misma_carpeta_no_borra(rules, an, tmp_path):
    # si owned_dir es la misma, no se borra
    d = tmp_path / "a"
    d.mkdir()
    ctx = make_ctx(rules)
    set_analysis(ctx, an, owned_dir=d)
    set_analysis(ctx, an, owned_dir=d)
    assert d.exists()


def test_set_analysis_sin_owned_borra_previa(rules, an, tmp_path):
    # un análisis sin owned_dir libera la carpeta previa
    d = tmp_path / "a"
    d.mkdir()
    ctx = make_ctx(rules)
    set_analysis(ctx, an, owned_dir=d)
    set_analysis(ctx, an)
    assert not d.exists() and ctx.state.owned_dir is None


def test_set_analysis_previa_inexistente(rules, an, tmp_path):
    # si la carpeta previa ya no existe no falla
    ctx = make_ctx(rules)
    set_analysis(ctx, an, owned_dir=tmp_path / "ya_no_esta")
    set_analysis(ctx, an)


def test_summary_processes_por_defecto_false_y_true_si_se_pide(an):
    assert summary(an)["processes"] is False
    assert summary(an, has_processes=True)["processes"] is True


def test_set_analysis_guarda_y_resetea_processes(rules, an):
    from backend.domain.pcap.processes import ProcessTable
    ctx = make_ctx(rules)
    assert ctx.state.processes is None and ctx.state.sampler is None and ctx.make_sampler is None
    table = ProcessTable()
    out = set_analysis(ctx, an, processes=table)
    assert ctx.state.processes is table and out["processes"] is True
    out = set_analysis(ctx, an)
    assert ctx.state.processes is None and out["processes"] is False
