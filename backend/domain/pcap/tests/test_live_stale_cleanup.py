"""cleanup_stale_temp_dirs: borra solo restos viejos y propios; nunca lanza."""
import os
import shutil
import time

import pytest

from backend.domain.pcap import live
from backend.domain.pcap.live import (STALE_AFTER, TEMP_PREFIX, LiveCapture, cleanup_stale_temp_dirs,
                            _resolve_out_path)

OLD = time.time() - 3 * 24 * 3600


def mk(root, name="tracewell_a", files=("live.pcap",), old=True):
    d = root / name
    d.mkdir()
    for f in files:
        (d / f).write_bytes(b"x")
    if old:
        os.utime(d, (OLD, OLD))
    return d


class Fake:
    def start(self, cb):
        pass

    def stop(self):
        pass


def test_constantes():
    # prefijo y antigüedad por defecto
    assert TEMP_PREFIX == "tracewell_" and STALE_AFTER == 24 * 3600


def test_borra_vieja_con_solo_live_pcap(tmp_path):
    # carpeta tracewell_* vieja con solo live.pcap -> borrada y devuelta
    d = mk(tmp_path)
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [d]
    assert not d.exists()


def test_no_borra_reciente(tmp_path):
    # carpeta reciente se conserva
    d = mk(tmp_path, old=False)
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


def test_no_borra_sin_prefijo(tmp_path):
    # sin prefijo tracewell_ no se toca
    d = mk(tmp_path, name="otra")
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


def test_no_borra_con_otro_archivo(tmp_path):
    # con otro archivo además de live.pcap se conserva
    d = mk(tmp_path, files=("live.pcap", "notas.txt"))
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


def test_no_borra_solo_otro_archivo(tmp_path):
    # sin live.pcap pero con otro archivo se conserva
    d = mk(tmp_path, files=("otro.pcap",))
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


def test_no_borra_con_subcarpeta(tmp_path):
    # con subcarpeta se conserva
    d = mk(tmp_path)
    (d / "sub").mkdir()
    os.utime(d, (OLD, OLD))
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


def test_no_borra_archivo_suelto_con_prefijo(tmp_path):
    # archivo (no carpeta) llamado tracewell_x se conserva
    f = tmp_path / "tracewell_x"
    f.write_bytes(b"x")
    os.utime(f, (OLD, OLD))
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and f.exists()


def test_carpeta_vacia_vieja_se_borra(tmp_path):
    # carpeta vieja VACIA (all() sobre nada): se borra (comportamiento real)
    d = mk(tmp_path, files=())
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [d]


def test_symlink_no_se_sigue_ni_borra_destino(tmp_path):
    # symlink a carpeta vieja: ni el link ni el destino se borran
    target_root = tmp_path / "real"
    target_root.mkdir()
    target = mk(target_root, name="destino")
    root = tmp_path / "tmp"
    root.mkdir()
    link = root / "tracewell_link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("el SO no permite crear symlinks")
    assert cleanup_stale_temp_dirs(temp_root=root) == []
    assert target.exists() and (target / "live.pcap").exists()
    assert link.is_symlink()


def test_max_age_cero_borra_las_de_mtime_pasado(tmp_path):
    # max_age=0: borra las de mtime pasado, no las de mtime futuro
    viejo = mk(tmp_path, "tracewell_v")
    futuro = mk(tmp_path, "tracewell_f", old=False)
    t = time.time() + 3600
    os.utime(futuro, (t, t))
    assert cleanup_stale_temp_dirs(max_age=0, temp_root=tmp_path) == [viejo]
    assert futuro.exists()


def test_max_age_respeta_umbral(tmp_path):
    # carpeta de hace 2 h: se borra con max_age=3600 y no con 86400
    d = mk(tmp_path)
    t = time.time() - 7200
    os.utime(d, (t, t))
    assert cleanup_stale_temp_dirs(max_age=86400, temp_root=tmp_path) == []
    assert cleanup_stale_temp_dirs(max_age=3600, temp_root=tmp_path) == [d]


def test_varias_a_la_vez_y_lista_devuelta(tmp_path):
    # varias viejas: se borran todas y la lista tiene exactamente esas rutas
    ds = [mk(tmp_path, f"tracewell_{i}") for i in range(5)]
    keep = mk(tmp_path, "tracewell_keep", old=False)
    assert sorted(cleanup_stale_temp_dirs(temp_root=tmp_path)) == sorted(ds)
    assert keep.exists() and not any(d.exists() for d in ds)


def test_temp_root_inexistente(tmp_path):
    # raíz inexistente -> []
    assert cleanup_stale_temp_dirs(temp_root=tmp_path / "nada") == []


def test_temp_root_es_un_archivo(tmp_path):
    # raíz que es un archivo -> [] sin lanzar
    f = tmp_path / "f"
    f.write_bytes(b"")
    assert cleanup_stale_temp_dirs(temp_root=f) == []


def test_oserror_en_una_sigue_con_las_demas(tmp_path, monkeypatch):
    # rmtree lanza PermissionError en una: no lanza, sigue y solo devuelve las borradas
    a, b, c = (mk(tmp_path, f"tracewell_{n}") for n in "abc")
    real = shutil.rmtree

    def raro(p, *x, **k):
        if str(p).endswith("tracewell_b"):
            raise PermissionError("denegado")
        return real(p, *x, **k)

    monkeypatch.setattr(live.shutil, "rmtree", raro)
    out = cleanup_stale_temp_dirs(temp_root=tmp_path)
    assert sorted(out) == sorted([a, c]) and b.exists()


def test_oserror_en_listdir_no_lanza(tmp_path, monkeypatch):
    # os.listdir falla con OSError: se ignora y no se borra
    d = mk(tmp_path)

    def boom(p):
        raise PermissionError("x")

    monkeypatch.setattr(live.os, "listdir", boom)
    assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [] and d.exists()


@pytest.mark.parametrize("bad", [-1, -0.1, True, False, "5", None, [1], float("-inf")])
def test_max_age_invalido(bad, tmp_path):
    # max_age negativo, bool, str, None, lista -> ValueError
    with pytest.raises(ValueError):
        cleanup_stale_temp_dirs(max_age=bad, temp_root=tmp_path)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), -float("inf")])
def test_max_age_no_finito_lanza_valueerror_y_no_borra(bad, tmp_path):
    # nan/inf/-inf -> ValueError que menciona max_age, y no se borra ninguna carpeta
    vieja = mk(tmp_path, "tracewell_v")
    reciente = mk(tmp_path, "tracewell_r", old=False)
    with pytest.raises(ValueError, match="max_age"):
        cleanup_stale_temp_dirs(max_age=bad, temp_root=tmp_path)
    assert vieja.exists() and reciente.exists()


def test_resolve_out_path_usa_prefijo():
    # sin out_path crea carpeta tracewell_* y la ruta es <carpeta>/live.pcap
    path, tdir = _resolve_out_path(None)
    try:
        assert tdir.name.startswith(TEMP_PREFIX) and path == tdir / "live.pcap"
        assert tdir.is_dir()
    finally:
        shutil.rmtree(tdir, ignore_errors=True)


def test_resolve_out_path_explicito_sin_temp():
    # con out_path no hay carpeta temporal
    assert _resolve_out_path("a/b.pcap")[1] is None


def test_capturas_de_livecapture_son_limpiables(tmp_path, monkeypatch):
    # LiveCapture sin out_path crea tracewell_* en la raíz temporal
    monkeypatch.setattr(live.tempfile, "tempdir", str(tmp_path))
    cap = LiveCapture(Fake())
    try:
        assert cap.temp_dir.parent == tmp_path and cap.temp_dir.name.startswith(TEMP_PREFIX)
        cap.start()
        cap.stop()
        os.utime(cap.temp_dir, (OLD, OLD))
        assert cleanup_stale_temp_dirs(temp_root=tmp_path) == [cap.temp_dir]
        assert not cap.temp_dir.exists()
    finally:
        cap.cleanup()


def test_default_usa_gettempdir(tmp_path, monkeypatch):
    # sin temp_root usa tempfile.gettempdir() (apuntado a tmp_path, nunca el real)
    monkeypatch.setattr(live.tempfile, "gettempdir", lambda: str(tmp_path))
    d = mk(tmp_path)
    assert cleanup_stale_temp_dirs() == [d]
