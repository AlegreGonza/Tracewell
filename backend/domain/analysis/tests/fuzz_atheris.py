"""Harness opcional de atheris (cobertura guiada). No es parte de la suite: ver README.md."""
import sys


def one_input(data: bytes) -> None:
    """Cada entrada va a los parsers de HTTP, TLS y DNS; solo importa que no lancen."""
    from backend.domain.analysis.http import http_exchanges
    from backend.domain.analysis.names import dns_names
    from backend.domain.analysis.tls import analyze_tls

    half = len(data) // 2
    http_exchanges(data[:half], data[half:])
    analyze_tls(data[:half], data[half:])
    dns_names(data)


def main() -> None:
    import atheris  # dependencia opcional: pip install atheris

    with atheris.instrument_imports():
        import backend.domain.analysis.http  # noqa: F401
        import backend.domain.analysis.tls  # noqa: F401
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
