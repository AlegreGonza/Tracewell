"""Tests directos de los helpers de backend/domain/analysis/analyzer.py."""
import pytest

from backend.domain.analysis.analyzer import MAX_PAGE, _check_page_args, _endpoints_dict
from backend.domain.sessions.grouper import GroupingResult, Session


class _An:
    """Análisis mínimo: _check_page_args solo mira result.sessions."""

    def __init__(self, n):
        self.result = GroupingResult(sessions=[Session("TCP", "a", 1, "b", 2) for _ in range(n)])


# ---------- _check_page_args ----------

def test_check_page_args_validos():
    """Sesión existente, offset 0 y limit en rango pasan."""
    assert _check_page_args(_An(2), 1, 0, 100) is None


@pytest.mark.parametrize("offset,limit", [(0, 1), (0, MAX_PAGE), (5000, 10)])
def test_check_page_args_bordes_validos(offset, limit):
    """limit 1 y 1000 y un offset grande son válidos."""
    assert _check_page_args(_An(1), 0, offset, limit) is None


@pytest.mark.parametrize("sid", [-1, 2, 99, True, False, 0.0, "0", None])
def test_check_page_args_sesion_inexistente_o_tipo_malo(sid):
    """Id fuera de rango, bool, float, str o None lanzan IndexError."""
    with pytest.raises(IndexError, match="no existe"):
        _check_page_args(_An(2), sid, 0, 10)


def test_check_page_args_sin_sesiones():
    """Con 0 sesiones ningún id es válido."""
    with pytest.raises(IndexError):
        _check_page_args(_An(0), 0, 0, 10)


@pytest.mark.parametrize("offset", [-1, -100])
def test_check_page_args_offset_negativo(offset):
    """Un offset negativo lanza ValueError."""
    with pytest.raises(ValueError):
        _check_page_args(_An(1), 0, offset, 10)


@pytest.mark.parametrize("limit", [0, -1, MAX_PAGE + 1, 1001])
def test_check_page_args_limit_fuera_de_rango(limit):
    """limit 0, negativo o mayor a 1000 lanza ValueError."""
    with pytest.raises(ValueError):
        _check_page_args(_An(1), 0, 0, limit)


def test_check_page_args_limit_bool_se_rechaza():
    """Un bool no es un entero válido: ValueError con el nombre del parámetro."""
    with pytest.raises(ValueError, match="limit"):
        _check_page_args(_An(1), 0, 0, True)


def test_check_page_args_limit_false_falla():
    """limit=False cae como no-entero y lanza ValueError."""
    with pytest.raises(ValueError, match="limit"):
        _check_page_args(_An(1), 0, 0, False)


@pytest.mark.parametrize("bad", [True, False, "1", None, 1.5, [1]])
def test_check_page_args_offset_no_entero(bad):
    """offset no entero real -> ValueError (nunca TypeError), con el nombre."""
    with pytest.raises(ValueError, match="offset"):
        _check_page_args(_An(1), 0, bad, 10)


@pytest.mark.parametrize("bad", [True, False, "1", None, 1.5, [1]])
def test_check_page_args_limit_no_entero(bad):
    """limit no entero real -> ValueError (nunca TypeError), con el nombre."""
    with pytest.raises(ValueError, match="limit"):
        _check_page_args(_An(1), 0, 0, bad)


def test_check_page_args_sesion_se_valida_primero():
    """Con sesión inválida y args inválidos gana IndexError."""
    with pytest.raises(IndexError):
        _check_page_args(_An(1), 5, "x", None)


# ---------- _endpoints_dict ----------

def test_endpoints_dict_none_para_no_ip():
    """Sin endpoints (paquete no IP) devuelve None."""
    assert _endpoints_dict(None) is None


def test_endpoints_dict_tcp():
    """TCP: arma el dict con IPs, puertos y nombre de protocolo."""
    assert _endpoints_dict(("10.0.0.1", 1234, "10.0.0.2", 80, 6)) == {
        "src_ip": "10.0.0.1", "src_port": 1234, "dst_ip": "10.0.0.2", "dst_port": 80, "protocol": "TCP"}


def test_endpoints_dict_icmp_sin_puertos():
    """ICMP: los puertos quedan None."""
    d = _endpoints_dict(("1.1.1.1", None, "2.2.2.2", None, 1))
    assert d["protocol"] == "ICMP" and d["src_port"] is None and d["dst_port"] is None


def test_endpoints_dict_protocolo_desconocido():
    """Un protocolo sin nombre se muestra como IP-<n>."""
    assert _endpoints_dict(("::1", None, "::2", None, 47))["protocol"] == "IP-47"
