# Using the app

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Using the app

**Analyze a file.** Type the full path of a `.pcap` or `.pcapng` file in the top bar and press *Analyze*. Opening another file replaces the current analysis.

**Demo mode.** Loads `samples/demo.pcap`: 45 synthetic packets with normal DNS/HTTP/ICMP/ARP traffic plus a port scan, an FTP login and a tunnel-like DNS query. It triggers three of the nine rules (port scan, cleartext FTP and a suspicious DNS query), so you get 3 alerts and 32 sessions to explore.

**Summary.** Sessions, packets, traffic volume, alerts, and the protocol distribution. Packets that belong to no session (ARP and similar) and damaged packets are **always shown**, even when zero, so the totals never hide traffic.

**Alerts.** One row per alert with severity (text *and* color), source → destination, and timestamp. Expand a row to see the description, the MITRE ATT&CK technique (linked to attack.mitre.org) and the **evidence** as plain text. If the rule defines them, the detail also shows **possible false positives** and **how to investigate it**, and a **Copy Wireshark filter** button copies a display filter derived from the evidence (paste it in Wireshark with the `.pcap` open to see the same packets).

**Sessions.** Filter by protocol, IP and port, then press *Filter*. Filters apply on submit, not on every keystroke. An invalid filter shows an error; it is never presented as "no results". Each session shows its **direction** (Internal→External, External→Internal, Internal→Internal (lateral), External→External, from client to server). Click a session id to open its packets and the hex dump of any packet; its detail also has **Copy Wireshark filter**.

**Live capture.** Open the *Live capture* panel, choose an interface and press *Start*. Press *Stop and analyze* when done: the captured traffic is saved to a temporary `.pcap`, then analyzed exactly like any other file. Defaults protect your disk: at most **1,000,000 packets**, **10 minutes** and **200 MB** per capture.

**Traffic over time.** A bar chart of packets (or bytes) per interval, with the peak called out in text. Spikes, silences and regular rhythms stand out.

**Jump from an alert.** Expand an alert and press *Ver las sesiones de [IP]* (see the sessions of [IP]) to filter the sessions table by that source IP.

**Site name.** When a session has a known name (from a DNS answer or the TLS server name in the capture) a **Site** column appears. It is a hint, not proof: a shared IP (CDN) can serve many names, and with encrypted DNS or ECH the name is not visible.

**Packet layers.** Selecting a packet shows its hex dump and a layer tree below it. Hover or focus a field to highlight its bytes; click to pin the highlight. Hints such as "TTL 128: typical of Windows" are indicative, not proof.

**Follow the conversation.** For a TCP session, *Ver la conversación* (view the conversation) rebuilds what each side said, in order, dropping retransmissions and marking missing bytes. With plaintext protocols (FTP, HTTP, Telnet) it shows the content as is, **passwords included**, just like Wireshark. TLS sessions are reported as encrypted.

**Triage.** In a session's detail you can write a note and mark it *reviewed*; the table shows a ✓ and a *nota* tag. Notes live only in memory for the current analysis (they are not written to disk and disappear when you open another capture). The **Indicators (IOC)** panel loads a local file and matching sessions get an **IOC** badge. Three formats are accepted and detected automatically: a text file with one IP, CIDR network or domain per line (`#` for comments); a **CSV/TSV** with a value column (`value`, `valor`, `indicator`, `ioc`, `ip`, `domain`...); or a **STIX 2.1** JSON bundle (indicators on `ipv4-addr`, `ipv6-addr`, `domain-name` and `network-traffic`). Domains are matched against the site names above.

**Hosts.** One row per IP with its traffic, peers, services and alerts, plus the "who talks to whom" graph. Each host shows inferred **roles** (DNS client, web server, scan sender, top talker), based only on what this capture shows. A second card, **Equipos por MAC** (hosts by MAC), groups local-network IPs that share a MAC address: several IPs on one MAC may be one machine (IPv4 + IPv6) or a router/NAT.

**Remote access.** Sessions to SSH (22), Telnet (23), SMB (445), RDP (3389), WinRM (5985/5986) and VNC (5900), one table per service, with who connected to whom, how many connections were reset (**RST**) and how many were **retried** (repeated SYN). Highlighted rows are worth a look, for example a rejected login attempt or brute force. They are hints: an RST can also be a closed port.

**Case timeline.** Alerts, suspicious DNS queries, the sessions you marked or annotated and IOC matches in one chronological list (UTC), to tell the story of a case from start to finish. Limit it to one host with the IP box. This is different from the *Traffic over time* chart, which only counts packets.

**Rules.** Creates a new alert without writing YAML by hand. Pick a name, a severity and a description, optionally filter by protocol, source IP or network (CIDR), destination IP or network and destination port, and set a threshold (how many events in how many seconds). The page shows the **YAML** it will write, updated as you type, and, if a capture is open, **how many sessions and alerts the rule would give on it** before you save (the open capture does not change). *Load an example* fills the form with a sample case. *Save rule* creates a new file in `rules/` with the same format as the built-in ones; **it never modifies or disables an existing rule** (an id or file that already exists is rejected) and it applies from the next capture you open.

**Leaving a capture.** With something loaded, the toolbar shows **Salir del demo** (leave the demo) or **Cerrar captura** (close capture) for any other analysis. It discards the analysis, on the server too, and returns to the start screen; the IOC list is kept, notes are dropped. In the desktop window, downloads (*Export JSON*, *Informe HTML*) open the system **Save as** dialog (pywebview cancels downloads unless `ALLOW_DOWNLOADS` is enabled, which `main.py` does).

**Table colors.** Protocols get a colored tag (TCP, UDP, ICMP), each process gets its own color dot (assigned in order of first appearance, so the first eight never share a color), rows that match an IOC are tinted red and reviewed rows are dimmed. The text is always shown: color only helps, it is never the only signal.

**Export.** *Export JSON* downloads a report of what you are currently looking at (active filters are included). *Informe HTML* downloads a single-file triage report (alerts with evidence, IOC matches, your notes and the heaviest sessions) with everything escaped and no scripts, meant for a ticket. Its **"For the ticket"** block is plain text you can select and paste into the ticket: executive summary, timeline, confirmed IOC matches, key evidence and a containment suggestion. Reports can contain sensitive data: share them carefully.

**Timestamps** are shown in **UTC**, so captures can be correlated with logs from other systems without ambiguity.
