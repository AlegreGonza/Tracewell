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
npm test
```

There are about 4,060 Python tests and about 1,310 frontend tests. Besides normal cases, each module covers edge cases (empty files, truncated packets, invalid IPs, out-of-range ports) and expected errors. Several modules are also fuzzed with random and mutated packets to make sure bad input never crashes the analysis.

**Live capture is not tested against a real network in CI.** Its tests use a simulated interface. Real-hardware validation is a manual checklist: [`docs/checklist_hardware.md`](../checklist_hardware.md) (in Spanish).

### Linters

- **Python:** `python -m ruff check backend main.py` (pyflakes rules: unused imports, undefined names). `ruff` is in the `dev` extra of `pyproject.toml`.
- **Frontend:** `cd frontend && npm run lint` (ESLint, flat config in `frontend/eslint.config.js`).
- Details (including line-ending policy and security headers): [`docs/desarrollo.md`](../desarrollo.md) (in Spanish).

### Static analysis (optional)

A quality report with recommended tools (ruff, mypy, pip-audit, ESLint) and performance measurements is in [`docs/informe_calidad.md`](../informe_calidad.md) (in Spanish). Only ruff (pyflakes rules) and ESLint are configured in the project; `mypy` and `pip-audit` are not, and the report's `mypy` result predates the latest changes.

### Regenerating the demo capture

```bash
python samples/generate_demo.py
```

The file is deterministic: it produces the same `samples/demo.pcap` every time.
