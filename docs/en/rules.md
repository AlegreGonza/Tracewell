# Detection rules

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Detection rules

A rule is **data** (a YAML file) and a **detector** is **code**. The YAML sets the name, severity, MITRE technique and thresholds; the detector (Python) knows how to look for the pattern. You can tune thresholds without touching code, and a file can never execute code (`yaml.safe_load`).

### Built-in rules

| Rule id | What it detects | Severity | MITRE technique |
|---|---|---|---|
| `port_scan` | One source sends pure TCP SYN packets to ≥ `min_ports` distinct ports of the same destination within `window_seconds`. One alert per source/destination pair. | high | T1046 – Network Service Discovery |
| `ftp_cleartext` | `USER` / `PASS` commands travelling unencrypted on FTP ports. **The alert never stores the password**, only its length. | medium | T1040 – Network Sniffing |
| `dns_suspicious` | DNS queries whose first label is very long, or long *and* high-entropy (typical of tunneling or DGA). | medium | T1071.004 – Application Layer Protocol: DNS |
| `beaconing` | Connection attempts (TCP SYN) or UDP datagrams to the same destination at very regular intervals (`min_events`, `min_interval_seconds`, `max_jitter`). Intervals shorter than `min_interval_seconds` (such as a 1 s keep-alive) and regular-by-design ports (DNS, NTP, mDNS...) are ignored. | medium | T1071 – Application Layer Protocol |
| `syn_flood` | At least `min_syns` pure SYN packets to one destination and port within `window_seconds`. | high | T1498 – Network Denial of Service |
| `suspicious_ports` | A connection attempt (SYN) to a port used by common attack tools or backdoors (`ports`, default 4444, 31337, 1337, 12345, 54321, 9001). Replies are ignored so an ephemeral port that happens to match does not alert. | medium | T1571 – Non-Standard Port |
| `dns_unusual_resolver` | DNS queries sent straight to a public server that is not in `allowed_resolvers` (private destinations are always considered normal). Add your ISP's or company's resolver to the list. | low | T1071.004 – Application Layer Protocol: DNS |
| `brute_force` (rule `brute_force_remote`) | At least `min_attempts` pure SYN packets from one source to the same destination on SSH (22) or RDP (3389) (`ports`) within `window_seconds`. Each login attempt opens a new connection, so many in a short time look like password guessing. It does not see whether a login failed (the traffic is encrypted). One alert per source, destination and port. | high | T1110 – Brute Force |
| `threshold` | The rule type that the **Rules** section creates: at least `min_events` events that match a filter (`protocol`, `src_ip`, `dst_ip`, `port`) within `window_seconds`. In TCP it counts connection attempts (SYN); in UDP and `any`, every packet. Counted per source/destination pair. | you choose | T1595 – Active Scanning by default |
| `large_upload` | At least `min_bytes` sent to one external destination with at least `min_ratio` times more data going out than coming in. It decides as traffic streams in, so a transfer that later balances out can still alert. | medium | T1048 – Exfiltration Over Alternative Protocol |

ARP spoofing is **not** covered: the rule engine only sees TCP/UDP packets, and ARP has no IP layer.

### Rule file format

```yaml
id: port_scan                 # lowercase letters, digits and underscore
name: Port scan
description: >
  One IP sent connection attempts (SYN) to many ports of one destination
  in a short time, a typical reconnaissance pattern.
severity: high                # low | medium | high | critical
detector: port_scan           # a detector name, see the table above
mitre:
  technique: T1046            # format T1234 or T1234.001
  name: Network Service Discovery
  tactic: Discovery
params:
  min_ports: 15               # 2..65535
  window_seconds: 60
# Optional explain-why fields (shown in the alert detail, never exported to JSON):
false_positives:              # list of non-empty texts
  - An authorized vulnerability scanner.
investigation_steps:          # list of non-empty texts
  - Confirm whether the source is an approved scanning host.
wireshark_filter: tcp.flags.syn==1 && tcp.flags.ack==0   # non-empty text
```

`GET /api/alerts` adds two extra keys to each alert: `wireshark_filter` (derived from the evidence) and, when the rule defines any of the optional fields, `guide`. The JSON export keeps its exact `schema_version: 1` shape.

### Rule validation is strict

Rules are validated when they are loaded. An unknown field (for example the typo `severty`), an out-of-range parameter, a malformed MITRE id, an unknown detector or a duplicated `id` raises an error that **names the file**. Nothing is silently ignored.

### Adding a new kind of detection

Changing thresholds only needs a YAML edit. A **new** pattern needs a new detector class (the first three live in `backend/domain/rules/engine.py`, the newer ones in `backend/domain/rules/extra_detectors.py`), registered in the `DETECTORS` table, plus its YAML file and tests.
