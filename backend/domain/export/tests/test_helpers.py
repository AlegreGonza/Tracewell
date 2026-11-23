"""Tests directos de los helpers de backend/domain/export/json_export.py."""
from pathlib import Path

from backend.domain.export.json_export import _session_rows, _source_info, _stats_for
from backend.domain.pcap.reader import CaptureInfo
from backend.domain.sessions.grouper import GroupingResult, Session


def _s(proto="TCP", packets=1, size=10, sport=1000):
    return Session(proto, "10.0.0.1", sport, "10.0.0.2", 80, packets=packets, bytes=size,
                   first_ts=1.0, last_ts=3.0)


# ---------- _source_info ----------

def test_source_info_solo_basename():
    """Guarda solo el nombre del archivo, nunca la ruta completa."""
    info = CaptureInfo("pcap", 1, 65535)
    out = _source_info(Path("C:/Users/ana/capturas/trafico.pcap"), info)
    assert out == {"file": "trafico.pcap", "format": "pcap", "linktype": 1, "snaplen": 65535}


def test_source_info_ruta_posix_como_str():
    """Una ruta en texto (separador /) también se reduce al nombre."""
    assert _source_info("/home/ana/x.pcapng", None)["file"] == "x.pcapng"


def test_source_info_source_none_e_info_none():
    """Sin fuente ni info, todo es None."""
    assert _source_info(None, None) == {"file": None, "format": None, "linktype": None, "snaplen": None}


def test_source_info_snaplen_none_se_conserva():
    """pcapng no expone snaplen: queda None aunque haya info."""
    assert _source_info("a.pcapng", CaptureInfo("pcapng", 1, None))["snaplen"] is None


# ---------- _stats_for ----------

def test_stats_for_sin_filtro_usa_todo_el_resultado():
    """Con sessions=None cuenta todas las sesiones y los descartes del resultado."""
    r = GroupingResult(sessions=[_s(), _s("UDP")], non_ip=3, malformed=2)
    st = _stats_for(r, None)
    assert (st.sessions, st.non_ip, st.malformed) == (2, 3, 2)


def test_stats_for_filtrado_cuenta_solo_lo_elegido_pero_copia_truncado():
    """Las cifras son de las sesiones filtradas; truncated/untracked vienen de la captura."""
    a, b = _s(packets=5, size=50), _s("UDP", packets=1, size=7)
    r = GroupingResult(sessions=[a, b], truncated=True, untracked_packets=42, non_ip=9)
    st = _stats_for(r, [b])
    assert (st.sessions, st.packets, st.bytes) == (1, 1, 7)
    assert st.truncated is True and st.untracked_packets == 42
    assert st.non_ip == 0  # los descartes no se arrastran a un filtro


def test_stats_for_filtro_vacio_sigue_copiando_bandera():
    """Una lista filtrada vacía da 0 sesiones y mantiene la bandera de truncado."""
    r = GroupingResult(sessions=[_s()], truncated=True, untracked_packets=1)
    st = _stats_for(r, [])
    assert st.sessions == 0 and st.truncated is True and st.untracked_packets == 1


def test_stats_for_captura_completa_no_marca_truncado():
    """Si la captura no fue truncada, tampoco el reporte filtrado."""
    r = GroupingResult(sessions=[_s()])
    st = _stats_for(r, [r.sessions[0]])
    assert st.truncated is False and st.untracked_packets == 0


# ---------- _session_rows ----------

def test_session_rows_sin_filtro_ids_secuenciales():
    """Sin filtro, los ids son la posición en el análisis."""
    r = GroupingResult(sessions=[_s(sport=1), _s(sport=2)])
    rows = _session_rows(r, None)
    assert [x["id"] for x in rows] == [0, 1] and [x["src_port"] for x in rows] == [1, 2]


def test_session_rows_filtrado_conserva_ids_originales():
    """Las sesiones filtradas mantienen su id del análisis completo."""
    ss = [_s(sport=1), _s(sport=2), _s(sport=3)]
    r = GroupingResult(sessions=ss)
    rows = _session_rows(r, [ss[2], ss[0]])
    assert [(x["id"], x["src_port"]) for x in rows] == [(2, 3), (0, 1)]


def test_session_rows_sesion_ajena_usa_posicion_como_id():
    """Una sesión que no está en el resultado cae a su índice en la lista elegida."""
    r = GroupingResult(sessions=[_s(sport=1)])
    ajena = _s(sport=99)
    rows = _session_rows(r, [ajena])
    assert rows[0]["id"] == 0 and rows[0]["src_port"] == 99


def test_session_rows_lista_vacia():
    """Sin sesiones elegidas, sin filas."""
    assert _session_rows(GroupingResult(sessions=[_s()]), []) == []
    assert _session_rows(GroupingResult(), None) == []


def test_session_rows_no_expone_la_clave_interna():
    """Las filas no incluyen `key` (campo interno)."""
    s = _s()
    s.key = ("k",)
    assert "key" not in _session_rows(GroupingResult(sessions=[s]), None)[0]


# ---------- _file_name (rutas de cualquier estilo, en cualquier SO) ----------

import pytest as _pytest

from backend.domain.export.json_export import _file_name, build_report


@_pytest.mark.parametrize("src,expected", [
    (r"C:\Users\juan\Desktop\cap.pcap", "cap.pcap"),
    ("C:/Users/juan/Desktop/cap.pcap", "cap.pcap"),
    (r"C:\Users/juan\Desktop/cap.pcap", "cap.pcap"),
    ("/home/ana/cap.pcap", "cap.pcap"),
    ("cap.pcap", "cap.pcap"),
    (r"\\servidor\compartido\carpeta\cap.pcap", "cap.pcap"),
    ("//servidor/compartido/cap.pcap", "cap.pcap"),
    ("D:cap.pcap", "cap.pcap"),
    ("mi captura (1).pcap", "mi captura (1).pcap"),
    (r"C:\Users\juan\ñandú\captúra.pcap", "captúra.pcap"),
    ("", ""),
    ("C:\\Users\\juan\\carpeta\\", "carpeta"),
    ("/home/ana/carpeta/", "carpeta"),
    ("C:\\", ""),
    ("/", ""),
])
def test_file_name_cadenas(src, expected):
    assert _file_name(src) == expected


def test_file_name_none_sigue_none():
    assert _file_name(None) is None


def test_file_name_objetos_path():
    assert _file_name(Path("C:/Users/juan/cap.pcap")) == "cap.pcap"
    assert _file_name(Path("/tmp/x/cap.pcap")) == "cap.pcap"
    assert _file_name(Path("cap.pcap")) == "cap.pcap"


def test_file_name_nunca_filtra_directorios():
    for s in (r"C:\Users\juan\Desktop\cap.pcap", "/home/juan/cap.pcap", r"\\srv\sh\juan\cap.pcap"):
        out = _file_name(s)
        assert "juan" not in out and "\\" not in out and "/" not in out


def test_build_report_con_ruta_windows_solo_nombre():
    rep = build_report(r"C:\Users\juan\Desktop\cap.pcap", None, GroupingResult(sessions=[]), [])
    assert rep["source"]["file"] == "cap.pcap"
    assert "juan" not in str(rep["source"])
