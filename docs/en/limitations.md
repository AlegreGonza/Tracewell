# Known limitations and roadmap

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Known limitations

These are deliberate MVP trade-offs.

- **Large captures are slower than they could be.** Analysis runs at roughly 30,000 packets per second (a 1 GB file may take one to three minutes), because every packet is decoded twice (once for sessions, once for rules). Opening the packet list of a session in a file with hundreds of thousands of packets re-reads the whole file (about 6 seconds at 500,000 packets). Both would be fixed with a single decoding pass and an offset index; neither is planned for the MVP.
- **Ethernet only** (link type 1). Packets from other link layers (for example loopback) are skipped during live capture, and files with other link types are rejected.
- **pcapng does not expose the original packet size**, so snaplen truncation cannot be flagged for pcapng files.
- **FTP detection** misses logins whose `USER`/`PASS` are split across several TCP segments.
- **DNS detection** only inspects UDP port 53.
- **Fixed thresholds** can produce false positives (for example CDN hostnames with long labels). For DNS, trusted domains can be skipped with the `ignore_suffixes` parameter in `rules/dns_suspicious.yaml` (exact domain or any subdomain; `elb.amazonaws.com` ships by default). Ignoring a domain also hides real abuse of it, so keep the list short.
- **A single analysis at a time** (single-user desktop model).
- **The desktop window has been validated on Windows** (WebView2) **and on Linux**. macOS uses another pywebview backend that has not been tried.
- **MITRE mappings** are judgment calls; review them for your environment.
- **Live capture** was validated on real Windows hardware (Npcap, administrator) and on Linux as root inside a container; the packet count matched an independent Scapy count in both. Without capture privileges the app reports a clear permission error. macOS has not been tried.
- **The Process column is best-effort and live-capture only.** The operating system is sampled once per second, so a connection shorter than that can be missed (shown as "—", meaning "could not be identified", not "no process"). Connectionless UDP is matched by local port only, which is less precise, and many Windows services appear as `svchost.exe`. `psutil` is optional: without it the column is simply not offered. The JSON export does **not** include processes unless you ask for them (`/api/export?processes=true`), because reports get shared.
- **HTTPS is not decrypted.** For TLS you get the requested site (SNI), the JA4 fingerprint, sizes and timing; the server certificate is only visible up to TLS 1.2 (TLS 1.3 encrypts it). The HTTP analyzer reads **plaintext HTTP/1.x** only (not HTTP/2) and only looks for it on the usual HTTP ports in the capture-wide table; open any session to analyze other ports.
- **JA4:** implemented by hand from the public spec. The cipher-list part was checked against a published value; the extension/signature-algorithm part follows the spec but was **not cross-checked against the reference implementation** (the verification library could not be installed in this environment). Treat it as a strong hint, not as a certified match.
- **Extracted files can be malware.** Only the SHA-256 and the real type are shown by default; downloading saves a `.bin` after a confirmation. Never open it.
- **The explanations are orientative.** They describe what the capture shows; they do not prove intent.
- **"Internal" means a private address.** Flow direction and host classification use Python's private-address check, so documentation ranges such as `203.0.113.0/24` count as internal. The real topology is not known.
- **Host roles and MAC groups are hints.** A host that does not show a role may still have it outside the capture. The MAC is read from the first packet of each session and only kept for local-network hosts (a remote host's MAC is your router's). One MAC with several IPs may be one machine (IPv4 + IPv6) or a router/NAT/bridge; a device that rotates its MAC (privacy MAC) appears as several. MACs never go into the JSON export.
- **Remote-access signals are hints.** An RST can be a closed port or a normal cut, and repeated SYNs can be packet loss rather than brute force. Retries are counted per session (same 5-tuple); a brute force that opens a new source port each time shows as many sessions instead.
- **No packaged executable.** Deployment is from source with the installer scripts. Installing Python (3.11+) is therefore required.

## Roadmap

- [x] pcap/pcapng reader with truncation and snaplen detection
- [x] Sessions, filters and statistics
- [x] YAML rule engine and the three initial rules
- [x] JSON export
- [x] HTTP API with hex dump and demo mode
- [x] Live capture (isolated, simulated-interface tests)
- [x] React interface
- [x] Desktop window with pywebview, opened with a single command (native "Browse…" file dialog included; validated on Windows and Linux)
- [x] One-command installer scripts for Windows and Linux/macOS (deployment from source)
- [x] Live capture validated on real Windows hardware and on Linux (root)
- Not planned: packaged executables (PyInstaller). The research is kept in `docs/empaquetado_futuro.md` (in Spanish) in case it is revisited.
