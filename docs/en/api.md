# HTTP API and JSON export

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## HTTP API

All routes are under `/api`. Errors use `{"detail": "..."}`.

**Authentication.** `main.py` generates a random token on every start. Every `/api` route requires it in the `X-Tracewell-Token` header (`401` otherwise); download links, which cannot carry headers, use a **one-time ticket** (valid 30 seconds, for that route only) that the interface requests with the header just before downloading, so the real token never appears in a URL. The desktop window receives the token directly from `main.py`; with `--serve-only` it travels in the `#token=` fragment of the printed address, which is never sent to the server. The static interface itself loads without a token.

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Liveness and version. |
| `POST /api/analyze` | Body `{"path": "..."}`. Analyzes a local file. |
| `POST /api/demo` | Analyzes `samples/demo.pcap`. |
| `GET /api/capture` | Summary of the current analysis. `409` if none is loaded. |
| `DELETE /api/capture` | Discards the current analysis (and the temp folder of a live capture). Idempotent. |
| `GET /api/sessions` | Query: `protocol`, `ip`, `port`, `limit` (1–1000, default 100), `offset`. Returns `{total, items}`. |
| `GET /api/stats` | Statistics, optionally filtered by `protocol`, `ip`, `port`. |
| `GET /api/alerts` | Optional `severity` filter. |
| `GET /api/sessions/{id}/packets` | Packets of a session, paged (`limit`, `offset`). |
| `GET /api/packets/{index}` | Packet detail with endpoints, hex dump and the decoded layers (each field with its byte range). |
| `GET /api/sessions/{id}/stream` | Rebuilt conversation of a TCP session. `422` for non-TCP sessions. |
| `GET /api/timeline` | Packets and bytes per interval (at most 120 bars). |
| `GET /api/hosts` / `GET /api/graph` | One row per IP (traffic, peers, services, alerts) and the "who talks to whom" graph. |
| `GET /api/system/overview` · `/processes` · `/processes/{pid}` · `/processes/{pid}/file` · `/ports` · `/connections` · `/services` · `/startup` | Read-only view of the local machine (works without a loaded capture). `/processes/{pid}/file` computes SHA-256 and the code signature on demand. |
| `GET /api/support/config` · `/config/raw` · `/wifi` · `/wifi/history` · `/monitor` | Read-only view of the local network state. |
| `POST /api/support/internet` · `/latency` · `/ping` · `/traceroute` · `/ports` · `/rdp` · `/time` · `/devices` · `/duplicate-ip` | Network checks that send traffic. They are `POST` on purpose: a `GET` from another web page carries no `Origin` and would slip past the origin check. Host names are validated and commands run without a shell. |
| `POST /api/support/monitor/start` · `/stop` · `/clear` | Start, stop or clear the in-memory outage monitor (it measures; it changes nothing on the machine). |
| `GET /api/dns` | DNS table (`?q=` filters by name): queries, responses, result codes, hints. |
| `GET /api/http` | Plaintext HTTP requests of the whole capture (sessions to the usual HTTP ports). |
| `GET /api/sessions/{id}/explain` | The session in plain words plus the connection steps and a `wireshark_filter`. |
| `GET /api/wireshark-filter` | Query `ip`. Display filter for an IP (`ip.addr==X` / `ipv6.addr==X`); `422` if it is not an IP. Needs no loaded capture. |
| `GET /api/hosts/by-mac` | Local-network hosts grouped by MAC address (several IPs on one MAC first, with a hint). |
| `GET /api/rules` | The loaded rules (marking those created from the interface) and a sample case for the form. |
| `POST /api/rules/preview` | Validates a rule form and returns its YAML plus, if a capture is open, how many sessions and alerts it would match. Saves nothing. |
| `POST /api/rules` | Saves the rule as `rules/<id>.yaml` (`201`). `422` if the form is invalid, `409` if the id or file already exists (existing rules are never overwritten). |
| `GET /api/remote-access` | SSH, Telnet, SMB, RDP, WinRM and VNC sessions grouped by service, with RST and SYN retries. Optional `service` (`422` if unknown). |
| `GET /api/case-timeline` | Alerts, suspicious DNS, marked sessions and IOC matches in chronological order. Optional `host` (IP) and `limit` (1–2000, default 500). |
| `GET /api/sessions/{id}/http` | HTTP exchanges of a TCP session; `/http/{n}/body` downloads the file as `.bin` (it may be malware). |
| `GET /api/sessions/{id}/tls` | JA4 fingerprint, negotiated version and server certificate (when visible). |
| `GET /api/sessions/{id}/pcap` / `GET /api/pcap` | A new `.pcap` with one session, or with the sessions matching `protocol`/`ip`/`port`. |
| `PUT /api/sessions/{id}/note` | Body `{"note": "...", "reviewed": bool}`. An empty note with `reviewed: false` removes it. Notes are kept in memory only. |
| `GET` / `POST` / `DELETE /api/iocs` | Status, load (body `{"path": "..."}`) or remove the IOC list. |
| `GET /api/report` | Single-file HTML triage report download (`?processes=true` adds the process of the listed sessions). |
| `GET /api/export` | JSON report download; accepts the same filters. |
| `GET /api/interfaces` | Lists network interfaces (needs Scapy). |
| `POST /api/live/start` | Body `{"interface": "...", "max_seconds"?, "max_packets"?}`. |
| `GET /api/live/status` | State, packet and byte counters of the live capture. |
| `POST /api/live/stop` | Stops, analyzes, and returns the result. Idempotent: calling it again returns the same result without re-analyzing. |

Status codes: `404` file or resource not found, `422` invalid pcap / unsupported link type / invalid filter, `400` path is a directory, `403` permission denied (or a disallowed origin), `409` wrong state (for example nothing loaded or a capture already running), `503` capture or driver problem.

## JSON export format

The report is a **versioned contract** (`schema_version: 1`); a test pins the exact set of keys so an accidental change fails.

| Key | Content |
|---|---|
| `schema_version` | Format version. |
| `generated_at` | ISO-8601 UTC timestamp. |
| `source` | `file` (**file name only**, never the full path), `format`, `linktype`, `snaplen`. |
| `filters` | Filters that were active when exporting. |
| `stats` | Totals, per-protocol distribution, `non_ip`, `malformed`, and the partial-analysis flags `truncated` / `untracked_packets`. |
| `sessions` | Sessions (with their original ids, even when filtered). |
| `alerts` | Alerts with severity, MITRE data and evidence. |

A filtered report still carries the partial-analysis flags of the **capture**: a filtered export of an incomplete analysis never claims to be complete.
