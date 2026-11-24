"""Harness opcional de atheris a nivel de ARCHIVO pcap/pcapng. No es parte de la suite: ver README.md."""
import sys
from pathlib import Path


def one_input(data: bytes) -> None:
    """Escribe la entrada como archivo y corre lector, agrupador, reglas e índice."""
    from backend.domain.analysis.tests import fuzz_file_support as ff

    ff.analyze_bytes(data)  # PcapError/UnsupportedLinktype se absorben; cualquier otra excepción es un hallazgo


def dump_seeds(folder: Path) -> None:
    """Deja las semillas (pcap, pcapng, demo) en `folder` para usarlas como corpus inicial."""
    from backend.domain.analysis.tests import fuzz_file_support as ff

    folder.mkdir(parents=True, exist_ok=True)
    for name, data in ff.seeds().items():
        (folder / f"{name}.bin").write_bytes(data)


def main() -> None:
    if "--dump-seeds" in sys.argv:
        dump_seeds(Path(sys.argv[sys.argv.index("--dump-seeds") + 1]))
        return
    import atheris  # dependencia opcional: pip install atheris (Linux/macOS; ver README)

    with atheris.instrument_imports():
        import backend.domain.pcap.reader  # noqa: F401
        import backend.domain.sessions.grouper  # noqa: F401
        import backend.domain.rules.engine  # noqa: F401
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    # Ejemplo: python -m backend.domain.analysis.tests.fuzz_atheris_file --dump-seeds corpus_seed
    #          python -m backend.domain.analysis.tests.fuzz_atheris_file corpus_seed -max_total_time=300
    main()
