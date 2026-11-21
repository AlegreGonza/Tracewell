"""DELETE /api/capture (Salir del demo / Cerrar captura) y clear_analysis."""
import pytest
from fastapi.testclient import TestClient

from backend.controllers import state as state_mod
from backend.api.app import create_app
from backend.api.tests.test_live_lifecycle import go, make_client, tmpdirs, tw_dirs  # noqa: F401  (fixture)


@pytest.fixture
def client():
    return TestClient(create_app(sampler_factory=None))


@pytest.fixture
def loaded(client):
    assert client.post("/api/demo").status_code == 200
    return client


def test_delete_devuelve_cleared_true(loaded):
    r = loaded.delete("/api/capture")
    assert r.status_code == 200 and r.json() == {"cleared": True}


def test_despues_de_cerrar_capture_y_sessions_dan_409(loaded):
    loaded.delete("/api/capture")
    for url in ("/api/capture", "/api/sessions", "/api/alerts", "/api/stats", "/api/timeline", "/api/export", "/api/report",
                "/api/packets/0", "/api/sessions/0/packets", "/api/sessions/0/stream"):
        r = loaded.get(url)
        assert r.status_code == 409, url
        assert "no hay una captura analizada" in r.json()["detail"]


def test_es_idempotente_y_funciona_sin_nada_cargado(client):
    for _ in range(3):
        r = client.delete("/api/capture")
        assert r.status_code == 200 and r.json() == {"cleared": True}
    assert client.get("/api/capture").status_code == 409


def test_cerrar_dos_veces_seguidas_tras_cargar(loaded):
    assert loaded.delete("/api/capture").status_code == 200
    assert loaded.delete("/api/capture").status_code == 200


def test_un_analisis_nuevo_funciona_despues_de_cerrar(loaded):
    loaded.delete("/api/capture")
    assert loaded.post("/api/demo").status_code == 200
    assert loaded.get("/api/capture").json()["source"] == "demo.pcap"
    assert loaded.get("/api/sessions").json()["total"] == 32


def test_la_lista_de_ioc_sobrevive(loaded, tmp_path):
    f = tmp_path / "ioc.txt"
    f.write_text("93.184.216.34\n", encoding="utf-8")
    assert loaded.post("/api/iocs", json={"path": str(f)}).json()["sessions"] > 0
    loaded.delete("/api/capture")
    st = loaded.get("/api/iocs").json()
    assert st["loaded"] is True and st["source"] == "ioc.txt" and st["ips"] == 1 and st["sessions"] == 0
    loaded.post("/api/demo")  # y se vuelve a aplicar a la captura nueva
    assert loaded.get("/api/iocs").json()["sessions"] > 0


def test_las_notas_se_reinician(loaded):
    assert loaded.put("/api/sessions/3/note", json={"note": "sospechosa", "reviewed": True}).status_code == 200
    loaded.delete("/api/capture")
    loaded.post("/api/demo")
    item = loaded.get("/api/sessions", params={"limit": 100}).json()["items"][3]
    assert "note" not in item and "reviewed" not in item


def test_poner_nota_tras_cerrar_da_409(loaded):
    loaded.delete("/api/capture")
    assert loaded.put("/api/sessions/0/note", json={"note": "x"}).status_code == 409


def test_el_demo_no_borra_samples(loaded):
    from backend.api.app import ROOT
    loaded.delete("/api/capture")
    assert (ROOT / "samples" / "demo.pcap").is_file()


def test_captura_en_vivo_borra_su_carpeta_temporal(tmpdirs):  # noqa: F811
    c, src = make_client()
    assert go(c).status_code == 200
    src[0].feed_demo(20)
    assert c.post("/api/live/stop").status_code == 200
    dirs = tw_dirs(tmpdirs)
    assert len(dirs) == 1 and (dirs[0] / "live.pcap").exists()
    assert c.delete("/api/capture").json() == {"cleared": True}
    assert tw_dirs(tmpdirs) == []
    assert c.get("/api/capture").status_code == 409
    assert c.get("/api/sessions").status_code == 409


def test_se_puede_capturar_en_vivo_de_nuevo_tras_cerrar(tmpdirs):  # noqa: F811
    c, src = make_client()
    go(c)
    src[0].feed_demo(10)
    c.post("/api/live/stop")
    c.delete("/api/capture")
    assert go(c).status_code == 200
    src[1].feed_demo(10)
    assert c.post("/api/live/stop").status_code == 200
    assert c.get("/api/sessions").status_code == 200
    assert len(tw_dirs(tmpdirs)) == 1
    c.delete("/api/capture")
    assert tw_dirs(tmpdirs) == []


def test_clear_analysis_directo_reinicia_el_estado(tmp_path):
    from types import SimpleNamespace
    import threading
    owned = tmp_path / "owned"
    owned.mkdir()
    (owned / "live.pcap").write_bytes(b"x")
    st = SimpleNamespace(lock=threading.RLock(), analysis=object(), owned_dir=owned, processes=object(), notes={1: {"note": "a"}},
                         iocs="se-queda")
    ctx = SimpleNamespace(state=st)
    state_mod.clear_analysis(ctx)
    assert (st.analysis, st.owned_dir, st.processes, st.notes) == (None, None, None, {})
    assert st.iocs == "se-queda"
    assert not owned.exists()
    state_mod.clear_analysis(ctx)  # otra vez: no falla


def test_clear_analysis_con_carpeta_ya_borrada_no_falla(tmp_path):
    from types import SimpleNamespace
    import threading
    st = SimpleNamespace(lock=threading.RLock(), analysis=None, owned_dir=tmp_path / "no-existe", processes=None, notes={})
    state_mod.clear_analysis(SimpleNamespace(state=st))
    assert st.owned_dir is None


def test_solo_delete_borra(loaded):
    assert loaded.post("/api/capture").status_code == 405
    assert loaded.get("/api/capture").status_code == 200
