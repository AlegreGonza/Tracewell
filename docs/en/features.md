# Features

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Features

- Reads `.pcap` and `.pcapng` files **in streaming** (constant memory with respect to file size).
- Lists network interfaces and captures live traffic (requires administrator/root privileges; Npcap on Windows).
- **Process per session (live capture only):** a **Process** column shows which program owns each socket (for example `chrome.exe`), sampled from the operating system once per second with `psutil`. A file cannot tell which program produced a packet, so for `.pcap` files the column is not shown. Details and limits are in [Known limitations](limitations.md#known-limitations).
- Groups packets into **bidirectional sessions** by IP addresses, ports and protocol.
- Filters sessions by protocol, IP address and port.
- Statistics: packets, bytes and distribution by protocol.
- Per-packet detail with a **hex dump**.
- Rule engine driven by **YAML** files. Each alert carries a severity, a MITRE ATT&CK technique and the evidence that triggered it.
- Nine built-in rules: **port scan**, **cleartext FTP credentials**, **suspicious DNS queries**, **beaconing**, **SYN flood**, **suspicious ports**, **DNS to an unusual resolver**, **large uploads** and **brute force to SSH/RDP**. You can also **create your own alerts from the interface** (a *Rules* section: protocol, source/destination IP, port and a threshold in a time window; live YAML and a preview against the open capture before saving).
- **Triage tools:** per-session notes and a "reviewed" mark, one-click jump from an alert to its sessions, an **IOC list** (IPs, networks, domains from a local file) that flags matching sessions, and a self-contained **HTML triage report** to paste into a ticket.
- **Site name per session**, taken from the capture itself (DNS responses and the TLS SNI), with no external lookups.
- **Packet detail by layers** (Ethernet, IP, TCP/UDP/ICMP, data) with a plain-language hint for every field; hovering a field highlights its bytes in the hex dump.
- **Follow the conversation** of a TCP session (like Wireshark's *Follow TCP Stream*) and a **traffic-over-time** chart.
- **Teaching first.** Tracewell exists to lower the barrier that makes Wireshark intimidating: a **?** help button on every section with the *Wireshark equivalent*, a searchable **glossary**, a plain-language **"In simple words"** explanation of every session with a **connection diagram** (SYN → SYN+ACK → ACK → data → FIN), a guided case built on the demo, and a [Wireshark ↔ Tracewell equivalence table](../guia_didactica.md) (in Spanish).
- **Understand the capture:** a **MITRE ATT&CK map** of your alerts (only the five tactics that show up in network traffic: reconnaissance, discovery, lateral movement, command and control, exfiltration; an alert of any other tactic gets an extra column, it is never hidden), a **hosts** view with a "who talks to whom" graph (an icon per host type, and the range owner such as Google or Cloudflare from a small offline table, shown as a hint and never overriding names found in the capture), a **DNS** table (NXDOMAIN, random-looking names), a plaintext **HTTP** analyzer that extracts files and reports their **SHA-256** and real type, and **TLS** details with the **JA4** client fingerprint and the server certificate (TLS ≤ 1.2).
- **Take it with you:** download just one session (or an IP's traffic) as a new `.pcap` for Wireshark or a ticket.
- **Wireshark display filters:** a **Copy Wireshark filter** button on every session and every alert (`ip.addr`/`ipv6.addr` plus `tcp.port`/`udp.port`; for alerts it is derived from the evidence: scanned ports, DNS name, destination port, or the victim of a SYN flood). `GET /api/wireshark-filter?ip=` gives the filter for an IP.
- **Optional module, not part of the triage: Network support** (read-only helpers for the machine Tracewell runs on):
  - **Network support → System (read-only):** a separate screen, reachable from the top menu, that shows the machine Tracewell runs on: resource summary, running processes (RAM, CPU, path, parent, connections, SHA-256 and code signature on demand), open ports with who can reach them, active connections with the program that owns each one, services and startup programs. It never changes anything: there is no kill/disable button and every route is a `GET`. Windows and Linux; the Linux paths are not tested on a real Linux machine.
  - **Network support → Network (read-only):** network configuration, a layer-by-layer *Is the Internet down?* check, latency, devices on the local network (with vendor by MAC when `data/oui.csv` is provided), Wi-Fi status and disconnection history, a background **outage monitor** with a timeline, and small tools (ping, continuous ping, traceroute, port check, RDP reachability, clock offset, duplicate IP). Nothing changes the machine: when a problem is found the fix is shown as text only. Tests that reach out (Internet check, latency, clock) run only when you press their button, and they are `POST` routes, so a web page cannot trigger them with a plain link or image.
- **"For the ticket" block in the HTML report:** plain, copyable text with an executive summary, a chronological timeline of alerts and marked sessions, confirmed IOC matches, key evidence and a containment suggestion. Values from the traffic are collapsed to one line and HTML-escaped.
- **IOC import from CSV and STIX 2.1:** besides one indicator per line, a CSV/TSV with a value column (`value`, `valor`, `indicator`, `ioc`, `ip`, `domain`...) or a STIX 2.1 JSON bundle (`ipv4-addr`, `ipv6-addr`, `domain-name`, `network-traffic` indicators). The format is detected from the extension or the content, and the same validations apply (a `/0` network is rejected, misspelled IPs fail with the line or object).
- **Explain-why fields in rules:** optional `false_positives`, `investigation_steps` and `wireshark_filter` in a rule YAML, shown in the alert detail (`port_scan.yaml` is the example). They are never part of the JSON export.
- **Flow direction:** every session is labeled *Internal→External*, *External→Internal*, *Internal→Internal (lateral)* or *External→External* (and *Multicast*), client → server, correcting a reversed origin when a capture starts mid-conversation.
- **Host profile:** inferred roles per host (DNS client, web server, scan sender, top talker), using only what the capture shows, and **grouping by MAC address** (several IPs on one MAC are shown together, with a hint: dual-stack, or a router/NAT).
- **Remote access:** a section grouping SSH, Telnet, SMB, RDP, WinRM and VNC sessions by service, with RST packets and repeated SYNs (retries) highlighted. `GET /api/remote-access?service=`.
- **Case timeline:** alerts, suspicious DNS queries, marked sessions and IOC matches in one chronological thread, optionally limited to one host. It is a new view; the packets-per-interval chart is unchanged.
- Exports the analysis to JSON.
- **Demo mode** with a bundled synthetic capture (32 sessions, 3 alerts) that triggers the port scan, cleartext FTP and suspicious DNS rules.

**Out of scope for the MVP:** device discovery, asset inventory, PDF reports, code signing.
