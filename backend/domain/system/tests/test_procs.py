"""Tests de backend/domain/system/procs.py con psutil falso. Todo es de lectura."""
import hashlib
import json
import subprocess

import pytest

import backend.domain.system.procs as P
from backend.domain.system.procs import file_info, file_signature, list_processes, process_detail, sha256_of
from backend.domain.system.tests.fakes import FakeProcess, FakePsutil, addr, conn, patch_psutil


@pytest.fixture(autouse=True)
def sin_espera(monkeypatch):
    monkeypatch.setattr(P.time, "sleep", lambda s: None)


def setup(monkeypatch, procs=(), **kw):
    fake = FakePsutil(procs=procs, **kw)
    patch_psutil(monkeypatch, fake)
    return fake


# ------------------------------------------------------------------ list_processes

def test_omite_el_pid_0(monkeypatch):
    setup(monkeypatch, [FakeProcess(0, name="System Idle Process"), FakeProcess(4, name="a"), FakeProcess(5, name="b")])
    out = list_processes("pid")
    assert [r["pid"] for r in out["items"]] == [4, 5] and out["total"] == 2


def test_forma_de_cada_fila(monkeypatch):
    setup(monkeypatch, [FakeProcess(7, name="app", exe="/usr/bin/app", cmdline=("app", "--x", "1"), ppid=3, username="ana", rss=5000, threads=9, cpu=40.0)], ncpu=4)
    row = list_processes()["items"][0]
    assert set(row) == {"pid", "ppid", "name", "user", "cpu", "rss", "threads", "status", "started", "exe", "cmdline", "connections", "hints"}
    assert (row["pid"], row["ppid"], row["name"], row["user"], row["rss"], row["threads"]) == (7, 3, "app", "ana", 5000, 9)
    assert row["cmdline"] == "app --x 1" and row["exe"] == "/usr/bin/app"
    assert row["cpu"] == 10.0  # 40 % de un solo núcleo repartido entre 4


def test_ncpu_y_total(monkeypatch):
    setup(monkeypatch, [FakeProcess(i, name=f"p{i}") for i in range(1, 6)], ncpu=8)
    out = list_processes(limit=2)
    assert out["ncpu"] == 8 and out["total"] == 5 and len(out["items"]) == 2


def test_cpu_se_divide_por_nucleos_y_se_redondea(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, cpu=33.33)], ncpu=3)
    assert list_processes()["items"][0]["cpu"] == 11.1


def test_cpu_sin_nucleos_conocidos_no_divide_por_cero(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, cpu=50.0)], ncpu=0)
    assert list_processes()["ncpu"] == 1 and list_processes()["items"][0]["cpu"] == 50.0


@pytest.mark.parametrize("sort,expected", [
    ("ram", [3, 1, 2]), ("cpu", [2, 3, 1]), ("name", [3, 2, 1]), ("pid", [1, 2, 3]),
])
def test_ordenes(monkeypatch, sort, expected):
    setup(monkeypatch, [
        FakeProcess(1, name="Zeta", rss=100, cpu=1.0), FakeProcess(2, name="beta", rss=50, cpu=90.0), FakeProcess(3, name="Alfa", rss=999, cpu=20.0)])
    assert [r["pid"] for r in list_processes(sort)["items"]] == expected


@pytest.mark.parametrize("sort", ["", "xyz", "RAM", None, "name; drop", "../etc"])
def test_orden_invalido_cae_a_ram(monkeypatch, sort):
    setup(monkeypatch, [FakeProcess(1, rss=10), FakeProcess(2, rss=500)])
    assert [r["pid"] for r in list_processes(sort)["items"]] == [2, 1]


def test_orden_por_nombre_ignora_mayusculas_y_pone_sin_nombre_primero(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, name="b"), FakeProcess(2, no_name=True), FakeProcess(3, name="A")])
    assert [r["pid"] for r in list_processes("name")["items"]] == [2, 3, 1]


def test_orden_ram_con_valores_desconocidos_al_final(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, deny=["memory_info"]), FakeProcess(2, rss=10)])
    assert [r["pid"] for r in list_processes("ram")["items"]] == [2, 1]


@pytest.mark.parametrize("limit,expected", [(0, 1), (-5, 1), (1, 1), (3, 3), (10_000, 5)])
def test_limit_minimo_1(monkeypatch, limit, expected):
    setup(monkeypatch, [FakeProcess(i, name=f"p{i}") for i in range(1, 6)])
    assert len(list_processes("pid", limit)["items"]) == expected


def test_accessdenied_en_cada_lectura_no_rompe(monkeypatch):
    every = ["name", "exe", "cmdline", "memory_info", "cpu_percent", "ppid", "username", "num_threads", "status", "create_time"]
    setup(monkeypatch, [FakeProcess(9, deny=every)])
    row = list_processes()["items"][0]
    assert row["pid"] == 9
    for k in ("name", "user", "cpu", "rss", "threads", "status", "started", "exe", "cmdline", "ppid"):
        assert row[k] is None, k
    assert row["hints"] == [] and row["connections"] == 0


def test_nosuchprocess_en_cada_lectura_no_rompe(monkeypatch):
    every = ["name", "exe", "cmdline", "memory_info", "cpu_percent", "ppid", "username", "num_threads", "status", "create_time"]
    setup(monkeypatch, [FakeProcess(9, gone=every), FakeProcess(10)])
    assert [r["pid"] for r in list_processes("pid")["items"]] == [9, 10]


def test_un_proceso_que_muere_antes_de_leerse_se_omite(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, gone=["oneshot"]), FakeProcess(2, deny=["oneshot"]), FakeProcess(3)])
    assert [r["pid"] for r in list_processes("pid")["items"]] == [3]


def test_proceso_sin_exe(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, exe=None), FakeProcess(2, exe="")])
    for row in list_processes()["items"]:
        assert row["exe"] is None and row["hints"] == []


def test_cmdline_vacia_es_none_y_enorme_se_corta_a_400(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, cmdline=()), FakeProcess(2, cmdline=("x" * 5000, "y" * 5000))])
    rows = {r["pid"]: r for r in list_processes("pid")["items"]}
    assert rows[1]["cmdline"] is None and len(rows[2]["cmdline"]) == P.MAX_CMDLINE == 400


def test_muchos_procesos(monkeypatch):
    setup(monkeypatch, [FakeProcess(i, name=f"p{i}", rss=i) for i in range(1, 3001)])
    out = list_processes("ram", 2000)
    assert out["total"] == 3000 and len(out["items"]) == 2000 and out["items"][0]["pid"] == 3000


def test_cuenta_conexiones_por_proceso(monkeypatch):
    conns = [conn(addr("1.1.1.1", 1), addr("2.2.2.2", 2), pid=5), conn(addr("1.1.1.1", 3), addr("2.2.2.2", 4), pid=5), conn(addr("1.1.1.1", 5), None, pid=6),
             conn(addr("1.1.1.1", 7), None, pid=0), conn(addr("1.1.1.1", 8), None, pid=None)]
    setup(monkeypatch, [FakeProcess(5), FakeProcess(6), FakeProcess(7)], connections=conns)
    rows = {r["pid"]: r for r in list_processes("pid")["items"]}
    assert (rows[5]["connections"], rows[6]["connections"], rows[7]["connections"]) == (2, 1, 0)


def test_si_no_se_pueden_listar_conexiones_la_lista_sigue(monkeypatch):
    setup(monkeypatch, [FakeProcess(5)], conn_error=True)
    assert list_processes()["items"][0]["connections"] == 0


def test_las_pistas_de_ruta_llegan_a_la_fila(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, exe="/tmp/evil"), FakeProcess(2, exe="/usr/bin/ok")])
    rows = {r["pid"]: r for r in list_processes("pid")["items"]}
    assert [h["code"] for h in rows[1]["hints"]] == ["carpeta_temporal"] and rows[2]["hints"] == []


def test_se_mide_el_cpu_dos_veces_con_una_espera_entre_medio(monkeypatch):
    waits = []
    monkeypatch.setattr(P.time, "sleep", lambda s: waits.append(s))
    p = FakeProcess(1)
    setup(monkeypatch, [p])
    list_processes()
    assert waits == [P.CPU_SAMPLE_SECONDS] and p.calls.count("cpu_percent") == 2


def test_sin_procesos(monkeypatch):
    setup(monkeypatch, [])
    assert list_processes() == {"total": 0, "ncpu": 4, "items": []}


def test_salida_serializable(monkeypatch):
    setup(monkeypatch, [FakeProcess(1), FakeProcess(2, deny=["exe"])])
    json.dumps(list_processes())


# ------------------------------------------------------------------ process_detail

def test_detalle_de_proceso_inexistente_es_vacio(monkeypatch):
    setup(monkeypatch, [FakeProcess(1)])
    assert process_detail(999) == {}


def test_detalle_cuando_el_nombre_falla_se_trata_como_inexistente(monkeypatch):
    setup(monkeypatch, [FakeProcess(1, deny=["name"]), FakeProcess(2, gone=["name"])])
    assert process_detail(1) == {} and process_detail(2) == {}


def test_detalle_completo(monkeypatch):
    parent = FakeProcess(1, name="init")
    child = FakeProcess(30, name="hijo")
    p = FakeProcess(20, name="app", exe="/usr/bin/app", cmdline=("app", "-v"), username="ana", cwd="/srv", rss=10, vms=20, threads=3,
                    parent=parent, children=[child], open_files=["/a", "/b"], maps=["/lib/a.so", "/lib/b.so", "/lib/a.so"], io=(5, 6),
                    conns=[conn(addr("::ffff:10.0.0.5", 4000), addr("::ffff:8.8.8.8", 443), "ESTABLISHED")])
    setup(monkeypatch, [p, parent, child])
    d = process_detail(20)
    assert set(d) == {"pid", "name", "exe", "user", "status", "cmdline", "cwd", "started", "threads", "rss", "vms", "parent", "children", "io", "hints",
                      "open_files", "modules", "connections"}
    assert d["parent"] == {"pid": 1, "name": "init"} and d["children"] == [{"pid": 30, "name": "hijo"}]
    assert d["io"] == {"read": 5, "written": 6} and d["open_files"] == ["/a", "/b"]
    assert d["modules"] == ["/lib/a.so", "/lib/b.so"]  # sin repetir
    assert d["connections"] == [{"local": "10.0.0.5:4000", "remote": "8.8.8.8:443", "status": "ESTABLISHED", "owner": "Google"}]
    assert d["cwd"] == "/srv" and (d["rss"], d["vms"], d["threads"]) == (10, 20, 3)


def test_detalle_con_accessdenied_en_todo_no_rompe(monkeypatch):
    every = ["exe", "cmdline", "cwd", "memory_info", "io_counters", "parent", "children", "open_files", "memory_maps", "net_connections",
             "username", "status", "create_time", "num_threads", "ppid"]
    setup(monkeypatch, [FakeProcess(5, deny=every)])
    d = process_detail(5)
    assert d["pid"] == 5 and d["name"] == "prog.exe"
    for k in ("exe", "user", "status", "cmdline", "cwd", "started", "threads", "rss", "vms", "parent", "io"):
        assert d[k] is None, k
    assert d["children"] == [] and d["open_files"] == [] and d["modules"] == [] and d["connections"] == [] and d["hints"] == []


def test_detalle_con_nosuchprocess_a_mitad_no_rompe(monkeypatch):
    every = ["exe", "cmdline", "cwd", "memory_info", "io_counters", "parent", "children", "open_files", "memory_maps", "net_connections"]
    setup(monkeypatch, [FakeProcess(5, gone=every)])
    assert process_detail(5)["pid"] == 5


def test_detalle_sin_exe(monkeypatch):
    setup(monkeypatch, [FakeProcess(5, exe=None)])
    d = process_detail(5)
    assert d["exe"] is None and d["hints"] == []


def test_detalle_cmdline_enorme_a_2000(monkeypatch):
    setup(monkeypatch, [FakeProcess(5, cmdline=("a" * 9000,))])
    assert len(process_detail(5)["cmdline"]) == 2000


def test_detalle_topes_de_listas(monkeypatch):
    kids = [FakeProcess(1000 + i, name=f"k{i}") for i in range(80)]
    maps = [f"/lib/{i}.so" for i in range(500)]
    conns = [conn(addr("10.0.0.1", 1000 + i), addr("8.8.8.8", 443), "ESTABLISHED") for i in range(300)]
    setup(monkeypatch, [FakeProcess(5, children=kids, open_files=[f"/f{i}" for i in range(200)], maps=maps, conns=conns)])
    d = process_detail(5)
    assert len(d["children"]) == 50 and len(d["open_files"]) == 40 and len(d["modules"]) == 80 and len(d["connections"]) == 100


def test_detalle_modulos_sin_ruta_se_omiten(monkeypatch):
    setup(monkeypatch, [FakeProcess(5, maps=["", None, "/lib/ok.so"])])
    assert process_detail(5)["modules"] == ["/lib/ok.so"]


def test_detalle_hijos_con_nombre_ilegible(monkeypatch):
    kid = FakeProcess(7, deny=["name"])
    setup(monkeypatch, [FakeProcess(5, children=[kid])])
    assert process_detail(5)["children"] == [{"pid": 7, "name": None}]


def test_detalle_conexiones_sin_remoto_o_con_ip_rara(monkeypatch):
    conns = [conn(addr("0.0.0.0", 80), None, "LISTEN"), conn(None, None, "NONE"), conn(addr("fe80::1%12", 5), addr("not-an-ip", 6), "ESTABLISHED")]
    setup(monkeypatch, [FakeProcess(5, conns=conns)])
    out = process_detail(5)["connections"]
    assert out[0] == {"local": "0.0.0.0:80", "remote": None, "status": "LISTEN", "owner": None}
    assert out[1]["local"] is None and out[1]["remote"] is None
    assert out[2]["remote"] is None and out[2]["owner"] is None  # IP ilegible: sin remoto ni dueño


def test_detalle_sin_hash_ni_modificaciones(monkeypatch):
    p = FakeProcess(5)
    setup(monkeypatch, [p])
    process_detail(5)
    assert not set(p.calls) & {"kill", "terminate", "suspend", "resume", "nice"}


def test_detalle_serializable(monkeypatch):
    setup(monkeypatch, [FakeProcess(5, children=[FakeProcess(6)], maps=["/x"])])
    json.dumps(process_detail(5))


# ------------------------------------------------------------------ sha256_of

def test_sha256_de_un_archivo_chico_grande_y_vacio(tmp_path):
    for size in (0, 1, 1024, 1024 * 1024, 3 * 1024 * 1024 + 17):
        f = tmp_path / f"f{size}"
        data = bytes(range(256)) * (size // 256 + 1)
        f.write_bytes(data[:size])
        assert sha256_of(str(f)) == hashlib.sha256(data[:size]).hexdigest()


def test_sha256_archivo_inexistente_lanza(tmp_path):
    with pytest.raises(OSError):
        sha256_of(str(tmp_path / "no"))


# ------------------------------------------------------------------ file_info

def test_file_info_sin_exe(monkeypatch):
    setup(monkeypatch, [FakeProcess(5, exe=None), FakeProcess(6, deny=["exe"]), FakeProcess(7, exe="")])
    for pid in (5, 6, 7):
        out = file_info(pid)
        assert out["available"] is False and "administrador" in out["reason"] and "sha256" not in out


def test_file_info_proceso_inexistente(monkeypatch):
    setup(monkeypatch, [])
    assert file_info(404)["available"] is False


def test_file_info_hash_tamano_y_firma(monkeypatch, tmp_path):
    f = tmp_path / "prog.bin"
    f.write_bytes(b"hola mundo")
    setup(monkeypatch, [FakeProcess(5, exe=str(f))])
    monkeypatch.setattr(P, "IS_WINDOWS", False)
    out = file_info(5)
    assert out["available"] is True and out["path"] == str(f) and out["size"] == 10
    assert out["sha256"] == hashlib.sha256(b"hola mundo").hexdigest()
    assert out["signature"]["status"] is None and "solo está disponible en Windows" in out["signature"]["text"]


def test_file_info_archivo_borrado(monkeypatch, tmp_path):
    setup(monkeypatch, [FakeProcess(5, exe=str(tmp_path / "ya_no_esta") + " (deleted)")])
    out = file_info(5)
    assert out["available"] is True and out["sha256"] is None and out["size"] is None and "borrado" in out["hash_note"]


def test_file_info_archivo_borrado_pero_con_ese_nombre_existe(monkeypatch, tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    setup(monkeypatch, [FakeProcess(5, exe=f"{f} (deleted)")])
    out = file_info(5)
    assert out["path"].endswith("(deleted)") and out["size"] == 3 and out["sha256"] == hashlib.sha256(b"abc").hexdigest()


def test_file_info_demasiado_grande_no_se_hashea(monkeypatch, tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"x" * 100)
    monkeypatch.setattr(P, "MAX_HASH_BYTES", 50)
    setup(monkeypatch, [FakeProcess(5, exe=str(f))])
    out = file_info(5)
    assert out["size"] == 100 and out["sha256"] is None and "demasiado grande" in out["hash_note"]


def test_file_info_justo_en_el_limite_si_se_hashea(monkeypatch, tmp_path):
    f = tmp_path / "edge"
    f.write_bytes(b"x" * 50)
    monkeypatch.setattr(P, "MAX_HASH_BYTES", 50)
    setup(monkeypatch, [FakeProcess(5, exe=str(f))])
    assert file_info(5)["sha256"] == hashlib.sha256(b"x" * 50).hexdigest()


def test_file_info_si_el_hash_falla_queda_en_none(monkeypatch, tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"1")
    monkeypatch.setattr(P, "sha256_of", lambda path: (_ for _ in ()).throw(PermissionError("x")))
    setup(monkeypatch, [FakeProcess(5, exe=str(f))])
    out = file_info(5)
    assert out["available"] is True and out["sha256"] is None and out["size"] == 1


def test_file_info_la_ruta_sale_del_sistema_no_de_quien_pide(monkeypatch, tmp_path):
    """El pid es lo único que se recibe: la ruta se lee del proceso."""
    import inspect
    assert list(inspect.signature(file_info).parameters) == ["pid"]


# ------------------------------------------------------------------ file_signature

class FakeRun:
    def __init__(self, stdout="", exc=None):
        self.stdout, self.exc, self.calls = stdout, exc, []

    def __call__(self, args, **kw):
        self.calls.append((args, kw))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(args, 0, stdout=self.stdout, stderr="")


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(P, "IS_WINDOWS", True)


def test_firma_fuera_de_windows_no_lanza_nada(monkeypatch):
    monkeypatch.setattr(P, "IS_WINDOWS", False)
    run = FakeRun()
    monkeypatch.setattr(P.subprocess, "run", run)
    out = file_signature("/bin/ls")
    assert out == {"status": None, "text": "La verificación de firma digital solo está disponible en Windows.", "subject": None} and run.calls == []


@pytest.mark.parametrize("status,fragment", [
    ("Valid", "Firma válida"), ("NotSigned", "Sin firma"), ("HashMismatch", "NO coincide"), ("NotTrusted", "no confía"), ("UnknownError", "No se pudo verificar"),
])
def test_firma_estados_conocidos(windows, monkeypatch, status, fragment):
    monkeypatch.setattr(P.subprocess, "run", FakeRun(json.dumps({"status": status, "subject": "CN=Acme"})))
    out = file_signature("C:\\x.exe")
    assert out["status"] == status and fragment in out["text"] and out["subject"] == "CN=Acme"


def test_firma_estado_desconocido_se_muestra_tal_cual(windows, monkeypatch):
    monkeypatch.setattr(P.subprocess, "run", FakeRun(json.dumps({"status": "Rarisimo", "subject": ""})))
    out = file_signature("C:\\x.exe")
    assert out["status"] == "Rarisimo" and "Rarisimo" in out["text"] and out["subject"] is None


@pytest.mark.parametrize("stdout", ["", "{}", "no es json", "{broken", "   ", '{"status": null}'])
def test_firma_salida_rota_es_unknownerror(windows, monkeypatch, stdout):
    monkeypatch.setattr(P.subprocess, "run", FakeRun(stdout))
    out = file_signature("C:\\x.exe")
    assert out["status"] == "UnknownError" and "No se pudo verificar" in out["text"]


@pytest.mark.parametrize("exc", [subprocess.TimeoutExpired("powershell", 20), subprocess.SubprocessError("x"), FileNotFoundError("powershell"), OSError("x")])
def test_firma_errores_del_comando_son_unknownerror(windows, monkeypatch, exc):
    monkeypatch.setattr(P.subprocess, "run", FakeRun(exc=exc))
    assert file_signature("C:\\x.exe")["status"] == "UnknownError"


@pytest.mark.parametrize("path", [
    "C:\\a b\\x.exe", "C:\\x'; Remove-Item -Recurse C:\\ ; '.exe", 'C:\\"quoted".exe', "C:\\$(calc)\\x.exe", "C:\\`whoami`.exe", "C:\\a;b&c|d.exe",
    "C:\\ñandú\\x.exe", "\\\\server\\share\\x.exe", "C:\\x\n.exe",
])
def test_la_ruta_viaja_en_el_entorno_nunca_dentro_del_comando(windows, monkeypatch, path):
    run = FakeRun(json.dumps({"status": "Valid", "subject": "CN=x"}))
    monkeypatch.setattr(P.subprocess, "run", run)
    file_signature(path)
    args, kw = run.calls[0]
    assert kw["env"]["TW_FILE"] == path
    assert not any(path in part for part in args)  # ni entera ni dentro de otro argumento
    assert "$env:TW_FILE" in args[-1] and "-LiteralPath" in args[-1]


def test_firma_comando_de_solo_lectura_y_sin_ventana(windows, monkeypatch):
    run = FakeRun(json.dumps({"status": "Valid", "subject": "CN=x"}))
    monkeypatch.setattr(P.subprocess, "run", run)
    file_signature("C:\\x.exe")
    args, kw = run.calls[0]
    assert args[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
    assert "Get-AuthenticodeSignature" in args[-1]
    for danger in ("Remove-", "Set-", "Stop-", "Start-", "Invoke-Expression", "iex ", "Out-File", "New-"):
        assert danger not in args[-1]
    assert kw["timeout"] == 20 and kw["capture_output"] is True and kw["creationflags"] == P._NO_WINDOW and kw.get("shell") is not True


def test_firma_conserva_el_resto_del_entorno(windows, monkeypatch):
    import os
    run = FakeRun(json.dumps({"status": "Valid", "subject": "CN=x"}))
    monkeypatch.setattr(P.subprocess, "run", run)
    file_signature("C:\\x.exe")
    env = run.calls[0][1]["env"]
    assert env["PATH"] == os.environ["PATH"]
