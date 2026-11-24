<p align="center">
  <img src="docs/assets/tracewell-portada.webp" alt="Tracewell: network traffic analysis for SOC triage" width="900">
</p>

# Tracewell

**Network traffic analysis for SOC triage.** Open a `.pcap` / `.pcapng` file (or capture live), and Tracewell groups the packets into sessions, runs YAML-defined detection rules and shows alerts with severity, MITRE ATT&CK technique and evidence in a React interface. Built as an MVP for a junior SOC analyst, with a teaching focus: every screen explains its Wireshark equivalent.

Spanish version: [`README.es.md`](README.es.md). The UI is in Spanish, and so are most `docs/` files; the English detail lives in [`docs/en/`](docs/en/README.md).

## Screenshots

*Start screen: open a file, try the demo or capture live.*

![Start screen](docs/assets/screenshot-inicio.png)

*Summary: sessions, volume, alerts, protocol distribution, risk score and top talkers.*

![Summary](docs/assets/screenshot-resumen.png)

*Case timeline: alerts, suspicious DNS, marked sessions and IOC matches in order.*

![Case timeline](docs/assets/screenshot-cronologia.png)

## Key features

- Streaming reader for `.pcap` / `.pcapng` (constant memory) and live capture (Npcap / libpcap).
- Bidirectional **sessions**, per-packet detail with hex dump, TCP conversation follow-up, flow direction.
- **Rule engine in YAML** with built-in detectors (port scan, cleartext FTP, suspicious DNS, beaconing, SYN flood, brute force, large uploads...), each alert with a MITRE ATT&CK mapping and evidence.
- **Triage tools:** notes and "reviewed" marks, IOC lists (text, CSV, STIX 2.1), host profiles, remote-access view, case timeline, "For the ticket" HTML report, Wireshark display filters.
- HTTP, TLS and DNS views; JSON / HTML / pcap export.
- Optional **read-only network support** module (ping, ARP, Wi-Fi, outage monitor, duplicate IP).
- Desktop window (pywebview) or browser mode (`--serve-only`).

Full list: [`docs/en/features.md`](docs/en/features.md).

## Quick start

Requires Python 3.11+ (Node.js only to build the interface if `frontend/dist` is missing).

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File .\instalar.ps1
.\iniciar.ps1
```

```bash
# Linux / macOS
./instalar.sh
./iniciar.sh --serve-only     # browser mode; ./iniciar.sh opens the window
```

Click **demo** on the start screen to explore `samples/demo.pcap`. Dependencies are installed from `requirements.lock` (exact versions with hashes). Manual steps and troubleshooting: [`docs/en/install.md`](docs/en/install.md), [`docs/despliegue.md`](docs/despliegue.md).

## Architecture

```
React (Vite)  <--HTTP, token-->  FastAPI  -->  controllers (state)  -->  domain (pure logic)
frontend/src                     backend/api   backend/controllers       backend/domain/
                                                                         analysis, pcap, rules,
                                                                         sessions, support, export
The pywebview window (main.py) wraps the same server
```

- `backend/api/` HTTP routes and security; `backend/controllers/` orchestration only; `backend/domain/` pure logic, one package per topic, each with its own `tests/`.
- Rules live in `rules/*.yaml`: thresholds change without touching code.

More: [`docs/en/architecture.md`](docs/en/architecture.md), [`docs/en/rules.md`](docs/en/rules.md), [`docs/en/api.md`](docs/en/api.md).

## Security

- The API is for your own machine: bound to `127.0.0.1`, a random per-start token on every `/api` route, `Host` / `Origin` checks, strict CSP and security headers.
- Traffic content is treated as hostile (rendered as text, never HTML); resources are bounded; no secrets in alerts or reports.
- Dependencies are pinned with hashes. Details: [`docs/en/security.md`](docs/en/security.md).

## Tests and quality

About 4,060 Python tests (`python -m pytest -q`) and 1,310 frontend tests (`cd frontend && npx vitest run`); linters: `ruff` and ESLint. There is no CI by design. See [`docs/en/testing.md`](docs/en/testing.md) and [`docs/informe_calidad.md`](docs/informe_calidad.md).

## Documentation

- English detail: [`docs/en/`](docs/en/README.md) (features, install, usage, architecture, rules, API, security, testing, limitations).
- Spanish: [`docs/decisiones.md`](docs/decisiones.md), [`docs/guia_didactica.md`](docs/guia_didactica.md), [`docs/despliegue.md`](docs/despliegue.md), [`docs/desarrollo.md`](docs/desarrollo.md), [`docs/guia_uso_y_pruebas.md`](docs/guia_uso_y_pruebas.md), [`docs/informe_calidad.md`](docs/informe_calidad.md).

## License

See [`LICENSE`](LICENSE).
