# Network Monitor

A connection-logging honeypot. It listens on the common service ports, plays just enough of
each real service to draw out what a connecting client is trying to do, records every detail,
and shows it live on a single-page Blazor WebAssembly dashboard.

If someone connects to port 22 and tries to log in, you see the username and password they
tried. If they hit the web port, you see the request and any credentials. Everything that
arrives on a monitored port is captured, timestamped, and stored.

> **This is a defensive tool.** It only ever *listens* and *records*. It never connects out,
> never attacks anything, and never runs anything a client sends. It grants no access: every
> login is logged and rejected.

## What it captures

| Port(s) | Service | What you get |
|--------:|---------|--------------|
| 22 | SSH | Completes a real key exchange, then logs every **username + password** tried (both `password` and `keyboard-interactive`), and public-key attempts. Always rejected. |
| 80, 8080 | HTTP | Method, path, all headers, **HTTP Basic credentials**, and login-form fields from POST bodies. |
| 443 | HTTPS | Terminates TLS with a self-signed cert (most scanners ignore cert errors), logs the SNI host, then decodes the request like HTTP. |
| 21 | FTP | `USER` / `PASS` login attempts. |
| 25 | SMTP | `AUTH LOGIN` / `AUTH PLAIN` credentials and the mail envelope. |
| 110 | POP3 | `USER` / `PASS` login attempts. |
| 143 | IMAP | `LOGIN` credentials. |
| 23 | Telnet | Username/password from the login prompt (Telnet IAC negotiation handled). |
| 6379 | Redis | `AUTH` passwords and the commands run, via the RESP protocol. |
| 445, 1433, 3306, 3389, 5432, 5900, 27017 | SMB, MSSQL, MySQL, RDP, PostgreSQL, VNC, MongoDB | Raw hex dump of whatever the client sends first (many clients leak a recognisable banner or even a username). |
| 53, 123, 161 (UDP) | DNS, NTP, SNMP | Each datagram is logged; DNS queries have the requested name decoded. |

Every connection — whatever the port — records the time, source IP and port, duration, byte
counts, a hex dump of the raw bytes, and a decoded transcript.

## Architecture

Blazor WebAssembly runs in the browser and cannot open listening sockets, so the app is two
parts in one solution:

```
┌─────────────────────────────────────────────┐
│ NetworkMonitor.Server (ASP.NET Core)          │
│  • TCP + UDP listeners on the monitored ports │
│  • Per-protocol handlers (SSH, HTTP, …)       │
│  • SQLite storage (EF Core)                   │
│  • SignalR hub for live push                  │
│  • Serves the dashboard + REST API on :8099   │
└───────────────┬───────────────────────────────┘
                │ SignalR + REST
┌───────────────┴───────────────────────────────┐
│ NetworkMonitor.Client (Blazor WebAssembly)     │
│  • Single-page live dashboard                  │
└────────────────────────────────────────────────┘
```

- `src/NetworkMonitor.Server` — listeners, protocol handlers, storage, hub, API, dashboard host.
- `src/NetworkMonitor.Client` — the single-page dashboard.
- `src/NetworkMonitor.Shared` — DTOs shared by both.
- `tests/NetworkMonitor.Tests` — unit tests (hex dump, SSH wire format + crypto, limiter, mapping).

The SSH handler implements the SSH transport (diffie-hellman-group14-sha256 key exchange, an
RSA host key, aes128/aes256-ctr, hmac-sha2-256) from the .NET base class library — enough for a
real client such as OpenSSH or paramiko to complete the handshake and send its login attempt,
which is then recorded and refused.

## Running it

### With the .NET SDK (.NET 10)

```bash
# Dashboard on http://localhost:8099 ; listeners on the configured ports.
sudo dotnet run --project src/NetworkMonitor.Server -c Release
```

`sudo` is needed because the default port list includes ports below 1024 (on Linux you can
instead grant the capability: `setcap cap_net_bind_service=+ep` on the host, or just monitor
high ports). Open **http://localhost:8099** for the dashboard.

### With Docker

```bash
docker build -t network-monitor .

# Map the dashboard and whichever honeypot ports you want reachable.
docker run --rm \
  -p 8099:8099 \
  -p 22:22 -p 80:80 -p 443:443 -p 23:23 -p 21:21 -p 6379:6379 \
  -v "$PWD/data:/data" \
  network-monitor
```

The SQLite database is written to the `/data` volume so logs survive restarts.

## The dashboard

A single page, newest connections first, updating live over SignalR:

- Per-port counters along the top (click one to filter to that port).
- Filter by source IP or free-text search over summaries and transcripts.
- A **Pause live updates** toggle.
- Click any row for the full detail: metadata, a table of any credentials offered, the decoded
  protocol transcript, and a hex dump of the raw bytes.

Rows where a credential was captured are highlighted.

## Configuration

Everything lives in `src/NetworkMonitor.Server/appsettings.json` under `Monitor`, and every key
can be overridden with an environment variable (e.g. `Monitor__DatabasePath`,
`Dashboard__Url`).

```jsonc
"Monitor": {
  "BindAddress": "0.0.0.0",
  "DatabasePath": "networkmonitor.db",
  "HistoryPageSize": 500,
  "Limits": {
    "MaxBytesPerConnection": 16384,   // cap on bytes recorded per connection
    "IdleTimeoutSeconds": 30,         // close a silent connection
    "MaxConnectionSeconds": 120,      // absolute lifetime of a connection
    "MaxConnectionsPerIp": 20,        // per-source-IP concurrency cap
    "MaxConcurrentConnections": 500   // global concurrency cap
  },
  "TcpPorts": [ { "Port": 22, "Service": "SSH", "Handler": "ssh" }, … ],
  "UdpPorts": [ { "Port": 53, "Service": "DNS" }, … ]
}
```

Change the port list, point a port at a different handler, or override a service banner right
here. Unknown services fall back to raw hex capture.

## Safety limits

Nothing a client sends is ever executed. Per-connection byte caps, idle and lifetime timeouts,
and per-IP / global connection caps protect the host from floods and from filling the disk.

## Deployment notes & limits

- **Port conflicts.** It cannot listen on a port already in use. If the host uses SSH for
  admin, move real SSH off port 22 first or you will lock yourself out — then let the monitor
  take 22.
- **Privileges.** Ports below 1024 need root (or `CAP_NET_BIND_SERVICE`) on Linux, or admin on
  Windows.
- **The dashboard shows attacker data and your watched ports.** Put it behind a firewall,
  VPN, or reverse proxy with authentication if the host is internet-facing. By default it binds
  all interfaces on :8099 with no authentication.
- **Stealth scans are invisible by design.** A listener only sees connections that complete the
  TCP handshake, so a half-open scan (`nmap -sS`) never shows up. Catching those needs raw
  packet capture (root + libpcap) and is intentionally left out of this version; the capture
  layer is pluggable so it can be added later.
- **UDP has no handshake**, so sources are trivially spoofable; treat UDP source IPs with
  suspicion.
