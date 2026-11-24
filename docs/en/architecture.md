# Architecture, layout and glossary

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## How it works

```
 .pcap / .pcapng file ─────────┐
                               ▼
 live capture (Scapy) ──► writes a .pcap ──► reader (dpkt, streaming)
                                                  │  yields one packet at a time
                              ┌───────────────────┴───────────────────┐
                              ▼                                       ▼
                    sessions (grouper)                       rules engine (YAML)
                    one summary per flow                     alerts + evidence
                              └───────────────────┬───────────────────┘
                                                  ▼
                                          analysis (orchestrator)
                                                  ▼
                              HTTP API (FastAPI) ──► React UI / JSON export
```

### Design rules

The project follows a three-layer layout, one folder per layer:

- **View** (`frontend/`): the React interface. It only shows data and calls the API.
- **Controller** (`backend/controllers/`): the use cases. They hold the current analysis, orchestrate the domain and decide what to return. They know nothing about HTTP routes.
- **API** (`backend/api/`): the FastAPI layer. Routes validate the shape of a request, call a controller and translate the result or the error to HTTP.
- **Domain** (`backend/domain/`): plain Python analysis logic (pcap reading, sessions, rules, TLS, system and network checks).

1. **`backend/domain/` never imports FastAPI or React.** It can be tested without a server and reused from a CLI or a desktop window.
2. **`backend/api/` only translates.** No analysis logic lives there.
3. **Controllers sit between them.** A route calls a controller; a controller calls the domain. (Shortcut kept on purpose: controllers raise `HTTPException` for "not found / conflict" cases instead of defining their own error types.)
4. **Tests live inside each module**, in its own `tests/` folder.
5. **Live capture is isolated** in `backend/domain/pcap/live.py`. It produces an ordinary `.pcap`, so everything downstream needs no special code. It is **never tested against a real network in CI**: tests use a simulated interface, and real validation is done by hand with [`docs/checklist_hardware.md`](../checklist_hardware.md).
6. **Minimal dependencies**, each one justified in [`docs/decisiones.md`](../decisiones.md).
7. **Small functions.** Every function does one thing, or two at most, and stays around 20 lines. A long function is split into small helpers that it calls; repeated patterns live in a single shared function.

### Why memory stays flat

Packets are read one at a time (Python generators). Only a small summary per *session* is kept in memory (~640 bytes each), never the packets themselves. Measured on synthetic captures, a 20× larger file with a similar number of sessions raised peak memory only from ~0.4 MB to ~1.2 MB. Memory grows with the number of **sessions**, so there is a cap (500,000 sessions); beyond it, new sessions are dropped and the UI shows a **partial analysis** warning.

## Project layout

```
tracewell/
├── main.py                       # desktop entry point: starts the API and opens the pywebview window
├── iniciar.ps1 / .sh             # run from source          instalar.ps1 / .sh   # first-time setup
├── backend/
│   ├── api/                      # API layer (FastAPI): translates HTTP <-> controllers
│   │   ├── app.py                # create_app(): assembles the app, nothing else
│   │   ├── server.py             # runs the API in a thread on a free 127.0.0.1 port
│   │   ├── security.py           # Host/Origin protection and security headers
│   │   ├── errors.py             # exception -> HTTP status table
│   │   ├── routes/               # one thin router per area: analysis, live, triage, insights, system, support
│   │   └── tests/
│   ├── controllers/              # use cases: current analysis, orchestration (no HTTP routing)
│   │   ├── state.py              # the one current analysis and the shared context
│   │   └── analysis.py live.py triage.py insights.py
│   └── domain/                   # pure Python. No FastAPI, no React. Each package has its own tests/
│       ├── pcap/                 # streaming reader, hexdump, layers, live capture, process sampler
│       ├── sessions/             # packets -> bidirectional sessions; filters and statistics
│       ├── analysis/             # analyzer, hosts (roles, MAC groups), DNS and name book, HTTP, TLS/JA4, explain, timeline,
│       │                         # wireshark_filter, direction, remote_access, case_timeline
│       ├── rules/                # YAML rule engine, extra detectors, IOC list
│       ├── export/               # JSON export, HTML report, pcap export
│       ├── system/               # read-only view of this machine (processes, ports, services)
│       └── support/              # read-only network checks (internet, latency, devices, Wi-Fi, outage monitor)
├── frontend/                     # View layer: React 19 + Vite + Mantine (builds to frontend/dist)
│   └── src/
│       ├── App.jsx               # shell: header, sidebar (Captures / Network support) and the screens
│       ├── tokens.css            # design tokens: 3 palettes (emerald, violet, terracotta), light and dark
│       ├── theme.js              # Mantine theme built from the chosen palette
│       ├── views/                # full screens: CapturesView (one section at a time), SupportView
│       ├── components/           # captures/ (analysis widgets), support/ (system and network), common/
│       ├── controllers/          # hooks: useLoad, useAction, usePalette
│       ├── api/                  # HTTP client (client.js)
│       └── lib/                  # formatters and help texts
├── rules/                        # YAML detection rules
├── samples/                      # demo.pcap and generate_demo.py (synthetic traffic)
├── docs/                         # decisiones.md, guia_didactica.md, checklist_hardware.md, ... (Spanish)
└── pyproject.toml, requirements*.txt, crear_zip.ps1
```

Each package under `backend/` has its own `tests/` folder; frontend tests sit next to the component they test.

## Key concepts (glossary)

**pcap / pcapng** — File formats that store captured network packets. A `.pcap` has one *global header* (format, link type, snaplen) followed by a small header plus raw bytes for every packet. `.pcapng` is the newer, block-based format. Tracewell detects the format from the file's *magic number*, not from its extension.

**Session (flow)** — A conversation between two endpoints, identified by the *5-tuple*: source IP, source port, destination IP, destination port and protocol. Sessions are **bidirectional**: the request and its reply belong to the same session, because the two endpoints are sorted when building the key. The "source" of a session is whoever sent the first packet *seen* (if the capture starts mid-conversation, that may not be the real client).

**caplen / origlen / snaplen** — `origlen` is the packet's size on the wire; `snaplen` is the limit the capturing tool was configured to keep; `caplen = min(origlen, snaplen)` is what was actually saved. If `caplen < origlen` the packet was **truncated by snaplen**: the file is healthy, but the payload is incomplete, so a rule that looks for text in it may miss something that was on the wire. Tracewell flags those packets. A file that is cut short (fewer bytes than `caplen`) is a different case: it is reported as a damaged file.

**MITRE ATT&CK** — A public knowledge base of attacker techniques. Each alert references a technique id (for example `T1046` – Network Service Discovery) so analysts can speak a common language.

**Shannon entropy** — A measure of how "random" a string looks (bits per character). Names that carry encoded data, such as DNS tunnels or algorithmically generated domains (DGA), tend to have high entropy.

**SYN scan** — A port scan that sends TCP SYN packets (connection attempts) to many ports. Normal conversations touch few ports.
