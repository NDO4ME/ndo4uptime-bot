# NDO4Uptime – Developer and operations guide

Short user overview: [README](README.md).

- [Quick start](#quick-start) · [Configuration](#configuration)
- [Monitor types](#monitor-types) · [Webhooks](#webhooks)
- [Updating](#updating) · [Reverse proxy (Caddy)](#reverse-proxy-caddy) · [Backup and restore](#backup-and-restore) · [Reset the password](#reset-the-password)
- [Security notes](#security-notes) · [Troubleshooting](#troubleshooting)
- [Architecture](#architecture) · [Development](#development) · [CI/CD](#cicd)

## Quick start

Requirements: Docker with Compose v2.

```bash
git clone https://github.com/NDO4ME/ndo4uptime-bot.git
cd ndo4uptime-bot
docker compose up -d --build      # or: make up
```

The panel listens on `http://127.0.0.1:8589` (host side is bound to localhost only). There is no default password and no
setup page to race for: on first start a random administrator password is generated and printed **once** to the log:

```bash
docker compose logs ndo4uptime     # look for "Administrator password (shown once)"
```

Sign in with it (password only, no username) and change it under *Settings*. To choose the password yourself, set
`NDO4_ADMIN_PASSWORD` (at least 10 characters) before the first start; nothing is printed then.

Plain `docker run`:

```bash
docker run -d --name ndo4uptime --restart unless-stopped \
  -p 127.0.0.1:8589:8589 -v ndo4uptime-data:/data \
  --read-only --tmpfs /tmp:size=8m --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 384m --pids-limit 256 \
  --sysctl net.ipv4.ping_group_range="0 2147483647" \
  -e NDO4_ADMIN_PASSWORD='choose-a-long-password' \
  ghcr.io/ndo4me/ndo4uptime-bot:latest
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `NDO4_BIND` | `127.0.0.1:8589` (`0.0.0.0:8589` in the image) | Listen address inside the process/container. |
| `NDO4_DATA` | `./data` (`/data` in the image) | Directory holding the SQLite database. |
| `NDO4_PUBLIC_BIND` | `127.0.0.1:8590` (`0.0.0.0:8590` in the image) | Listener for public status pages only (no login, no admin routes). Point tunnels and reverse proxies here. |
| `NDO4_CLOUDFLARED` | `cloudflared` (`/cloudflared` in the image) | Path of the `cloudflared` binary used by the Cloudflare Tunnel switch. |
| `NDO4_TAILSCALED`, `NDO4_TAILSCALE` | `tailscaled`, `tailscale` (`/ts/…` in the image) | Paths of the Tailscale daemon and CLI used by the Tailscale switch. `NDO4_TAILSCALE_VERSION` records the bundled version so a stale updated copy never shadows a newer image. |
| `NDO4_ADMIN_PASSWORD_FILE` | – | Path of a file holding the initial password (Docker/Kubernetes secrets). Used when `NDO4_ADMIN_PASSWORD` is not set. |
| `NDO4_TAILSCALE_AUTHKEY`, `NDO4_TAILSCALE_AUTHKEY_FILE`, `NDO4_TAILSCALE_HOSTNAME` | – | Headless Tailscale setup: enables the integration and signs in on the first start. Ignored once Tailscale has been configured, so Settings always wins afterwards. Use an auth key that expires (one-time or short-lived). |
| `NDO4_RETENTION_DAYS` | `30` | How long check history is kept (1–3650). |
| `NDO4_ADMIN_PASSWORD` | random | Administrator password used only when the account is first created (min. 10 characters). Without it a random one is logged once. |
| `NDO4_COOKIE_SECURE` | `0` | Set to `1` behind an HTTPS proxy to mark the session cookie `Secure` and send `Strict-Transport-Security`. |
| `NDO4_TRUST_PROXY` | `0` | Set to `1` only behind your own reverse proxy: the right-most `X-Forwarded-For` entry becomes the client address for login rate limiting. |

## Monitor types

| Type | What it does |
|---|---|
| **HTTP(s)** | Sends the request and checks the status code against ranges such as `200-299,301`. Optional keyword in the body, custom headers (`Name: value` per line), body, redirects and TLS verification. |
| **Browser** | A pure-Rust page load with a browser-like profile. See [Browser checks](#browser-checks). It does **not** run JavaScript. |
| **TCP port** | Opens a TCP connection to host and port. |
| **Ping** | ICMP echo using unprivileged sockets (no `NET_RAW`). Needs the `net.ipv4.ping_group_range` sysctl, set in `docker-compose.yml`. |

**Proxy** (HTTP and Browser): `http://`, `https://`, `socks5://` or `socks5h://`, with optional `user:pass@`. Applies to that monitor only; without it the check connects directly and ignores `HTTP_PROXY`-style environment variables. Credentials are stored in the database and never shown back in the UI.

**Certificate expiry** (HTTPS targets): the expiry date is recorded on every check and shown on the monitor page. Set *Warn when certificate expires within (days)* to make the check fail below the threshold, which fires your webhooks. The check cannot tell you about a certificate it is not allowed to validate: with TLS verification off, expiry is still read but an already-invalid chain is accepted.

### Down confirmation (no false alarms)

A single failed check never alerts. By default a monitor must fail **3 times in a row** before it is declared down:

| Check | Monitor | Alert |
|---|---|---|
| ok | green | – |
| 1st failure | yellow `checking 1/3` | – |
| 2nd failure | yellow `checking 2/3` | – |
| 3rd failure | **red, down** | webhook `down` |
| first success | green | webhook `up` (only because a `down` was sent) |

While confirming, the monitor is re-checked every *Re-check every* seconds (default 20, never longer than its own interval) instead of waiting a full interval, so a real outage is confirmed in about a minute. One successful check resets the count, so short blips and flapping produce no notifications. Unconfirmed failures appear as yellow bars in the history and are never shown as an outage on public status pages.

Both numbers are global defaults under **Settings → Alerting** (failures 1–10, re-check 10–300 s). A monitor can override the failure count in its form (0 = use the default). Setting it to 1 alerts on the first failure.

Interval is 20 s – 24 h, timeout 1–60 s.

### Browser checks

Chromium, Servo and other full engines are deliberately not used: a real engine needs a JavaScript runtime, GPU/windowing libraries and hundreds of MB, and executing code from the monitored page would widen the attack surface of a security-focused tool. Instead the check does what a browser does *before* it runs scripts, entirely in Rust:

1. Requests the page with Chrome-like headers and a cookie jar, following redirects.
2. Parses the HTML with `html5ever` (the parser of the Servo engine, via `scraper`).
3. Requires the **keyword** in the *visible* text (script, style, head and template content are ignored) and, optionally, a **CSS selector** to match.
4. Fetches every stylesheet, script and image the page references (max 40, 8 in parallel, shared timeout, bodies are streamed and discarded) and fails if any returns a 4xx/5xx or cannot be reached.

By default only resources on the same host and port are loaded, so a monitored page cannot make the monitor contact arbitrary internal addresses; enable *Load third-party resources* when your assets live on a CDN. JavaScript-rendered content (single-page apps) is not visible to this check; use an HTTP check against the API the app calls.

## Status pages and Cloudflare Tunnel

**Groups.** Give a monitor a *Group* and the dashboard lists monitors together under it.

**Status pages.** *Status pages → New page* lets you pick any monitors and put them in groups for that page (independent from the dashboard groups). A page is served at `/s/<address>` on both listeners, updates live, and shows only monitor names, groups, state, uptime and an up/down history. Targets, URLs, error messages and configuration are never exposed. Pages can be hidden at any time.

**Custom domain.** Enter a hostname such as `status.example.com` on a page. The public listener (`NDO4_PUBLIC_BIND`, port 8590) serves the page at the root for requests whose `Host` matches; unknown hosts get 404. The admin listener never serves custom domains.

**Cloudflare Tunnel.** *Settings → Cloudflare Tunnel*:

1. In Cloudflare Zero Trust → Networks → Tunnels create a tunnel and copy its token.
2. Paste the token in Settings and press *Enable tunnel*. The panel shows `connecting` → `connected`.
3. In the tunnel's *Public hostname* tab add your hostname (or a wildcard like `*.example.com`) with service `HTTP` → `127.0.0.1:8590`, then enter the same hostname as the page's custom domain.

The image bundles a pinned, checksum-verified `cloudflared`. It runs as a supervised child process (restarted with backoff), receives the token through its environment rather than its arguments, and the token is never displayed again. Outside Docker, install `cloudflared` yourself or set `NDO4_CLOUDFLARED`. Without a tunnel, put your own reverse proxy in front of port 8590.

## Tailscale: monitor private networks

*Settings → Tailscale* lets NDO4Uptime join your tailnet and monitor devices and LANs that are not on the internet.

1. Press *Enable Tailscale*. Either paste a one-time **auth key** (Tailscale admin → Settings → Keys) or leave the field empty and open the **sign-in link** the panel shows. The key is read from a `0600` file in the tmpfs, never from a command line, is never displayed and is deleted from the database once the node is connected.
2. Add monitors as usual. In the *Network* field, **Automatic** sends tailnet addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, `*.ts.net`) through Tailscale and everything else directly. **Through Tailscale** forces it, which is what you want for LAN addresses (for example `192.168.1.10`) reached via a *subnet router* (keep *Use subnet routes* on and approve the routes in the Tailscale admin console). **Direct** never uses it.
3. HTTP, Browser and TCP checks go through the node's SOCKS5 proxy. Ping uses `tailscale ping` and therefore works for tailnet devices; ICMP cannot cross to a subnet from a userspace node, so use a TCP or HTTP check there.

**How it stays safe.** `tailscaled` runs as the unprivileged container user in userspace-networking mode: no root, no `/dev/net/tun`, no `NET_ADMIN`, and the container remains read-only with all capabilities dropped. The node is *shielded* (it accepts no inbound connections), the SOCKS proxy listens on `127.0.0.1` only, client log upload is disabled and MagicDNS never touches the container's resolver. State lives in `/data/tailscale` (mode `0700`).

**Auto-update** (on by default, switchable). One day at most between checks, only while Tailscale is enabled: the newest stable release is downloaded over HTTPS from `pkgs.tailscale.com`, verified against the SHA-256 published next to it, unpacked side by side under `/data/tailscale/bin/`, started once as a sanity check, and then activated by restarting the node. If the node does not reconnect within two minutes the previous version is restored automatically. *Check for updates* and *Update now* run the same logic on demand. The image ships a pinned, checksum-verified build, so a fresh container always starts from a known-good version.

The Tailscale feature needs a little more memory than the rest of the app; the supplied compose file allows 384 MB.

## Webhooks

Webhooks are the only alert channel. Attach them to monitors in the monitor form. They fire when a monitor is confirmed **down** (see [Down confirmation](#down-confirmation-no-false-alarms)) and on **recovery**.

```json
{
  "event": "down",
  "status": "down",
  "message": "HTTP 503 (expected 200-299)",
  "ping_ms": null,
  "failed_checks": 3,
  "confirmed_after": 3,
  "time": 1794002161,
  "monitor": { "id": 3, "name": "API", "type": "http", "target": "https://api.example.com/health" }
}
```

`event` is `down`, `up` or `test`. `failed_checks` is the number of consecutive failures that confirmed the outage and `confirmed_after` the threshold in force (both `null` for `up` and `test`). With a signing secret every request carries:

- `X-NDO4-Timestamp`: Unix time
- `X-NDO4-Signature`: `sha256=` + hex `HMAC-SHA256(secret, timestamp + "." + body)`

Verify the signature and reject old timestamps on your receiver. Redirects are not followed and the timeout is 10 s.

## Updating

```bash
git pull
docker compose up -d --build
```

The database migrates itself (`CREATE TABLE IF NOT EXISTS`). To roll back, check out the previous tag and rebuild; the volume is untouched.

## Reverse proxy (Caddy)

Use [`deploy/Caddyfile`](deploy/Caddyfile), replace the domain, and set `NDO4_COOKIE_SECURE: "1"` in `docker-compose.yml`.
Also set `NDO4_TRUST_PROXY: "1"` so login rate limiting sees the real client address (from the `X-Forwarded-For` entry your proxy appends). Only enable it when the proxy is the sole path to the panel: keep port 8589 bound to localhost and never expose it publicly, otherwise clients could spoof the header.

## Backup and restore

```bash
# backup
docker run --rm -v ndo4uptime_ndo4uptime-data:/d -v "$PWD":/b alpine tar czf /b/ndo4uptime-backup.tgz -C /d .
# restore (stack stopped)
docker run --rm -v ndo4uptime_ndo4uptime-data:/d -v "$PWD":/b alpine sh -c "cd /d && tar xzf /b/ndo4uptime-backup.tgz && chown -R 10001:10001 /d"
```

## Reset the password

```bash
echo 'a-new-long-password' | docker compose exec -T ndo4uptime /ndo4uptime reset-password
```

The password is read from stdin (never from arguments) and all sessions are signed out.

## Security notes

- No default credentials and no setup page: the first start generates a random password (or uses `NDO4_ADMIN_PASSWORD`), shown once in the log.
- Passwords: Argon2id. Sessions: random 256-bit tokens, stored hashed, 12 h sliding lifetime, `HttpOnly; SameSite=Strict` cookie.
- CSRF: per-session token on every state-changing form plus `Origin`/`Sec-Fetch-Site` validation.
- Login: single administrator, password only; 5 failures per 15 minutes per address; a dummy hash is verified when no account exists so timing does not differ.
- Headers: strict CSP (`default-src 'none'`, no inline script/style), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, `no-store`.
- Status pages are the only unauthenticated surface: separate listener, read-only, no cookies, rendered once per change and shared between viewers, capped at 256 live viewers.
- No telemetry, no external requests except the checks and webhooks you configure.
- Container: `scratch` image, UID 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges`, memory and PID limits.
- Webhook URLs and monitor headers may contain secrets; they are stored in the SQLite volume in plain text and shown redacted in lists. Protect backups accordingly.
- Monitors can target internal addresses by design (that is their job). Only administrators can create them.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Ping monitors always fail | The container needs `net.ipv4.ping_group_range` (set in the compose file). Some hosts or rootless Docker block it. |
| Cannot sign in behind a proxy | Set `NDO4_COOKIE_SECURE=1` only when the site is served over HTTPS. |
| Browser monitor fails with "resource(s) failed" | The message lists the broken asset. Fix it, or enable third-party loading if it lives on another host. |
| HTTPS monitor says "invalid peer certificate" | The target's certificate is untrusted; fix it or turn off *Verify TLS certificate* for that monitor. |
| `429` on login | Too many failures. Wait 15 minutes or restart the container. |
| Locked out | Use [Reset the password](#reset-the-password). |
| Health | `docker compose ps` shows the container health; `docker compose logs -f` for output. |

## Architecture

```
src/pages.rs    status pages: admin forms, public rendering, public live stream
src/tunnel.rs   cloudflared supervisor and the Settings panel
src/main.rs     config, routes, CLI (healthcheck, reset-password)
#   GET /events is the live stream: auth-gated SSE that pushes a re-rendered HTML fragment of the current view when data changes (max 64 streams).
src/db.rs       SQLite schema and queries (rusqlite, WAL)
src/checks.rs   HTTP / Browser (html5ever) / TCP / ping checks, proxy, certificate expiry, header and status parsing
src/sched.rs    1 s scheduler, state machine, webhook delivery
src/auth.rs     Argon2id, sessions, CSRF/origin checks, form extractor, rate limiter
src/web.rs      handlers and security-header middleware
src/view.rs     NDO4Panel layout and helpers (maud templates, compile-time escaping)
static/         NDO4Panel theme assets, embedded into the binary at build time
```

Stack: tokio, axum, maud, rusqlite (bundled SQLite), reqwest (rustls, SOCKS), scraper/html5ever, x509-parser, surge-ping, argon2.

## Development

```bash
make run     # http://127.0.0.1:8589, data in ./data
make test
make lint    # fmt --check + clippy -D warnings
make build   # release binary
```

UI follows the NDO4Panel theme: reuse the tokens and classes from `static/app.css`, no inline scripts or styles (CSP), icons only from `static/icons.svg`.

## CI/CD

- `ci.yml`: fmt, clippy, tests, `cargo audit` (RustSec advisories) and a Docker smoke test that checks the first-start password, the login page, auth enforcement and the healthcheck.
- `docker-publish.yml`: builds and publishes `ghcr.io/ndo4me/ndo4uptime-bot` on `main` and `v*` tags, with a weekly rebuild.
- Dependabot keeps Cargo, Docker and Actions dependencies current.
