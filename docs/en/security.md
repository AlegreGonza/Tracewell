# Security and privacy

> Part of the Tracewell detailed documentation ([index](README.md), [project README](../../README.md)).

## Security and privacy

- **The API is meant for your own machine.** `POST /api/analyze` reads a path you give it. Run it bound to `127.0.0.1` only.
- **API token.** Any program on the machine can reach `127.0.0.1`, including other users' processes (which matters when Tracewell runs as administrator to capture). So every `/api` route requires a random per-start token (at least 16 characters if you set it yourself), compared in constant time; without it, `/api/analyze` could be used to read files with the administrator's permissions. The token lives in the process memory and in the window; it is never written to disk. It protects against other local users and web pages, not against a process already running as the same user (that one can read your files anyway).
- **Probing routes are `POST`.** Ping, traceroute, port check and the other tests that send traffic are not reachable with a `GET`, because the browser sends no `Origin` on a cross-site `GET` (an `<img>` is enough) and the origin check would not stop it.
- **Protection against web pages.** The API accepts only `Host` headers `127.0.0.1` / `localhost` / `[::1]` (blocks DNS rebinding) and rejects any non-local `Origin` header with `403` (blocks cross-site requests from pages you may have open). Every response carries a Content-Security-Policy (scripts only from the app itself), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- **Paths must be regular files.** `/api/analyze` and `/api/iocs` reject Windows device names (`con`, `aux`, `nul`...) and non-files with a `400` before opening anything. Error messages never echo the content of the file you pointed at.
- **Hostile traffic is treated as text.** Evidence, names and hex dumps come from captured traffic, which may be malicious. The UI renders them as plain text and never as HTML.
- **No secrets in alerts or reports.** FTP passwords are never stored; reports contain the file name, not your folders.
- **Bounded resources.** Capture limits (packets, time, size), a cap on tracked sessions, and bounded detector state prevent a capture or an attack from exhausting memory or disk. Trade-off: with more than 100,000 distinct source/destination pairs a detector forgets the least recent ones.
- **Live capture needs elevated privileges.** Run it only on networks you are authorized to monitor.
