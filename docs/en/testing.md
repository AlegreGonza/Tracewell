# Testing and quality

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Testing

Python (from the project root):

```powershell
.\.venv\Scripts\python -m pytest
```

With coverage:

```powershell
.\.venv\Scripts\python -m pytest --cov=backend --cov-report=term-missing
```

Frontend:

```bash
cd frontend
corepack pnpm test            # unit and component tests (vitest)
corepack pnpm test:e2e:install # once: downloads Chromium
corepack pnpm test:e2e         # 3 end-to-end flows against the real backend
```

The test counts change with every commit, so they are not written here: see the latest [CI run](https://github.com/AlegreGonza/Tracewell/actions/workflows/ci.yml) or measure them with `python -m pytest -q` and `corepack pnpm test`. Besides normal cases, each module covers edge cases (empty files, truncated packets, invalid IPs, out-of-range ports) and expected errors. Several modules are also fuzzed with random and mutated packets to make sure bad input never crashes the analysis.

The backend suite runs on Linux and Windows (Python 3.11 and 3.13) in GitHub Actions (`.github/workflows/ci.yml`) and can be reproduced locally in Docker with `./verificar.sh --linux`; the whole flow (ruff, bandit, pip-audit, pytest, frontend lint/test/build/audit) is described in [`docs/pruebas.md`](../pruebas.md) (Spanish). The CI also builds a CycloneDX SBOM of the pinned runtime dependencies.

**Live capture is not tested against a real network in CI.** Its tests use a simulated interface. Real-hardware validation is a manual checklist: [`docs/checklist_hardware.md`](../checklist_hardware.md) (in Spanish).

### Linters

- **Python:** `python -m ruff check backend main.py` (pyflakes rules: unused imports, undefined names). `ruff` is in the `dev` extra of `pyproject.toml`.
- **Security:** `bandit -r backend main.py -ll -c pyproject.toml` and `pip-audit --require-hashes -r requirements.lock`.
- **Frontend:** `cd frontend && corepack pnpm run lint` (ESLint, flat config in `frontend/eslint.config.js`).
- Details (including line-ending policy and security headers): [`docs/desarrollo.md`](../desarrollo.md) (in Spanish).

### Static analysis (optional)

A quality report with recommended tools (ruff, mypy, pip-audit, ESLint) and performance measurements is in [`docs/informe_calidad.md`](../informe_calidad.md) (in Spanish). Only ruff (pyflakes rules) and ESLint are configured in the project; `mypy` and `pip-audit` are not, and the report's `mypy` result predates the latest changes.

### Regenerating the demo capture

```bash
python samples/generate_demo.py
```

The file is deterministic: it produces the same `samples/demo.pcap` every time.
