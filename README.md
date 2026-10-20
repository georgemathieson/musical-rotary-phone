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
- `src/NetworkMonitor.Client` — the single-page dashboard. State is managed in a Redux-style
  store (the [Blazor-State](https://github.com/TimeWarpEngineering/blazor-state) library, built on
  MediatR): a single `ConnectionsState`, actions dispatched through the mediator, and handlers as
  the reducers (see `State/`). History loads and row-detail fetches are async "effect" handlers;
  live SignalR events are dispatched as actions so every UI change flows through the store.
- `src/NetworkMonitor.Shared` — DTOs shared by both.
- `tests/NetworkMonitor.Tests` — unit tests (hex dump, SSH wire format + crypto, limiter, mapping).

The SSH handler implements the SSH transport (diffie-hellman-group14-sha256 key exchange, an
RSA host key, aes128/aes256-ctr, hmac-sha2-256) from the .NET base class library — enough for a
real client such as OpenSSH or paramiko to complete the handshake and send its login attempt,
which is then recorded and refused.

## Running it

### With the .NET SDK (.NET 10)

```bash
# macOS: no sudo needed. macOS lets normal users listen on ports below 1024.
dotnet run --project src/NetworkMonitor.Server -c Release

# Linux: ports below 1024 need root. Build as yourself, then run only the built app as root.
dotnet publish src/NetworkMonitor.Server -c Release -o out
sudo "$(command -v dotnet)" out/NetworkMonitor.Server.dll
```

Don't run the SDK itself (`dotnet run`, `dotnet build`) under `sudo`: it writes root-owned files
into your home directory that break later builds. On Linux you can also avoid root entirely with
Docker (below) or by only monitoring ports 1024 and up. Ports already used by the machine (e.g.
22 with macOS Remote Login on, 445 with File Sharing) are skipped with an error in the log.

Open **http://localhost:8099** for the dashboard and sign in (see
[Dashboard sign-in](#dashboard-sign-in)).

### With Docker

```bash
docker build -t network-monitor .

# One-off: create the password hash for the dashboard login.
docker run --rm -it network-monitor hash-password

# Map the dashboard and whichever honeypot ports you want reachable.
docker run --rm \
  -p 8099:8099 \
  -p 22:22 -p 80:80 -p 443:443 -p 23:23 -p 21:21 -p 6379:6379 \
  -e Dashboard__Username=admin \
  -e Dashboard__PasswordHash='AQAAAAIAAYagAAAAE…' \
  -v "$PWD/data:/data" \
  network-monitor
```

The SQLite database (and the keys that sign login sessions) are written to the `/data` volume
so logs and sign-ins survive restarts.

## Dashboard sign-in

The dashboard, its API (`/api/*`) and the live feed (`/hub/monitor`) all require signing in with a
username and password; the honeypot ports are not affected. Everything is denied by default —
the Blazor app files themselves are not served until you have signed in.

**Set the login.** Only a salted PBKDF2 hash of the password is stored. Generate it with:

```bash
dotnet src/NetworkMonitor.Server/bin/Release/net10.0/NetworkMonitor.Server.dll hash-password
#   or: dotnet run --project src/NetworkMonitor.Server -- hash-password
#   or: docker run --rm -it network-monitor hash-password
```

It prompts without echoing (or reads one line from stdin) and prints the hash. Put it in
`Dashboard:PasswordHash`, e.g. as the environment variable `Dashboard__PasswordHash`, and set
`Dashboard:Username` (default `admin`). Passwords must be at least 12 characters.

If no hash is configured, a random one-time password is generated at startup and written to the
log as a warning, so the dashboard is never left open — but it changes on every restart.

**What protects it**

- Cookie session: `HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS; expires after 8 hours idle.
- Anti-forgery token on the sign-in form.
- Sign-in attempts are rate-limited per IP (`Dashboard:LoginAttemptsPerMinute`, default 5), and
  failed attempts are logged with the source IP.
- `X-Frame-Options: DENY`, `nosniff`, `no-referrer`; API responses are `no-store` and the app is
  revalidated on every load, so a signed-out browser can't reopen it from cache.
- The sign-in always lands on the dashboard (no return URL), so it can't be used as an open
  redirect.

**Serve it over HTTPS.** Over plain HTTP the password and session cookie cross the network in
clear text — the app logs a warning at startup if the dashboard is on plain HTTP and reachable
off-box. Kestrel can terminate TLS itself; PEM files from Let's Encrypt work directly:

```bash
Dashboard__Url=https://0.0.0.0:8443 \
Kestrel__Certificates__Default__Path=/etc/letsencrypt/live/example.com/fullchain.pem \
Kestrel__Certificates__Default__KeyPath=/etc/letsencrypt/live/example.com/privkey.pem \
dotnet NetworkMonitor.Server.dll
```

Alternatively put it behind a TLS reverse proxy (Caddy, nginx) and bind the dashboard to
`http://127.0.0.1:8099`. Note the sign-in rate limit is per client IP, so behind a proxy it
counts every user as the proxy's address unless forwarded headers are configured.

## The dashboard

A single page, newest connections first, updating live over SignalR:

- Per-port counters along the top (click one to filter to that port).
- Filter by source IP or free-text search over summaries and transcripts.
- A **Pause live updates** toggle.
- Click any row for the full detail: metadata, a table of any credentials offered, the decoded
  protocol transcript, and a hex dump of the raw bytes.

Rows where a credential was captured are highlighted.

## Configuration

Everything lives in `src/NetworkMonitor.Server/appsettings.json` under `Monitor` and
`Dashboard`, and every key can be overridden with an environment variable (e.g.
`Monitor__DatabasePath`, `Dashboard__Url`).

```jsonc
"Dashboard": {
  "Url": "http://0.0.0.0:8099",       // https://… with a Kestrel certificate for internet use
  "Username": "admin",
  "PasswordHash": "",                 // from `hash-password`; empty = one-time password per run
  "LoginAttemptsPerMinute": 5         // per client IP
},
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
- **The dashboard shows attacker data and your watched ports.** It requires a sign-in, but
  serve it over HTTPS before exposing it to the internet (see
  [Dashboard sign-in](#dashboard-sign-in)), and keep the `/data` directory private: it holds
  the captured data and the session-signing keys (stored unencrypted).
- **Stealth scans are invisible by design.** A listener only sees connections that complete the
  TCP handshake, so a half-open scan (`nmap -sS`) never shows up. Catching those needs raw
  packet capture (root + libpcap) and is intentionally left out of this version; the capture
  layer is pluggable so it can be added later.
- **UDP has no handshake**, so sources are trivially spoofable; treat UDP source IPs with
  suspicion.

## Troubleshooting

**Every `dotnet` command fails with `System.IO.IOException: The system cannot open the device or
file specified. : 'NuGet-Migrations'`** (macOS, .NET 10.0.13 or later; the message ends with
`lstat("", ...) == -1; errno == ENOENT`). Since that security release, .NET keeps named-mutex files
in a per-user folder, which on macOS is `$TMPDIR`. If `TMPDIR` is *set but empty* in your shell,
.NET uses an empty path and fails before doing anything else. Check and fix it:

```bash
printf 'TMPDIR=[%s]\n' "$TMPDIR"                 # "TMPDIR=[]" means set but empty
export TMPDIR="$(getconf DARWIN_USER_TEMP_DIR)"  # fixes the current terminal
```

Then find the line in your shell startup files that empties it, and remove it:

```bash
grep -n TMPDIR ~/.zshenv ~/.zprofile ~/.zshrc ~/.bash_profile ~/.bashrc ~/.profile 2>/dev/null
```

If you previously ran `dotnet` with `sudo`, also hand back anything it created as root:
`sudo chown -R "$(id -un)" ~/.dotnet ~/.nuget ~/.local/share/NuGet 2>/dev/null`.
