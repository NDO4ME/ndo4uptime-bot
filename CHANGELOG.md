# Changelog

## 1.8.0

- **AI incident assistant (Groq).** On a confirmed DOWN (never on recovery) a model writes a neutral corporate-tone notice for status pages and a short English analysis for webhooks, sent as a follow-up `analysis` event so the DOWN alert is never delayed. Primary model `qwen/qwen3.8-27b` with automatic fallback to `openai/gpt-oss-20b`; capable models may use Groq's server-side web search, nothing runs as an agent here.
- **Private by default:** only the monitor name, check type and a scrubbed failure class go to Groq with the privacy lock on; all returned text is scrubbed again (IPs, hosts, URLs, e-mails, paths, target and port) and a status-page statement that would change is dropped. With the lock off, webhooks marked "technical details" get a detailed analysis.
- **Per monitor:** switch and a short *Notes for the assistant* field (what the system is).
- **Key handling:** `NDO4_GROQ_API_KEY` (or `_FILE`) at install, or Settings. Stored encrypted (ChaCha20-Poly1305, key file mode 0600), never shown again, replaced or removed only after re-entering the password.
- **Bounded:** daily request cap, two requests in flight, 25 s timeout, one incident = 1–3 requests.

## 1.7.5

- **Maintenance and incidents:** an outage already in progress when a maintenance window opens is closed in the incident history at that moment instead of staying "ongoing" for the whole window; if the monitor is still failing after the window it is recorded as a new incident.
- **Phones:** the dashboard monitor table becomes one card per monitor instead of scrolling sideways.
- **Cleanup:** the unused per-monitor `retries` setting is gone (confirmation is controlled by the confirmation threshold). Existing databases keep working unchanged.

## 1.7.4

- **Keyword must be absent** (HTTP and Browser): fail when text such as "error" or "maintenance" appears in the response or in the visible page text.
- **TCP banner check**: optionally send text (`\r \n \t` escapes) and require the reply, or the greeting a server sends by itself (SSH, SMTP, Redis, FTP ...), to contain a string. Works directly and through Tailscale; the failure message shows what was received.
- **Slow response limit** for every monitor type: a response slower than the limit (50 ms up to just below the timeout) counts as a failed check, goes through the normal confirmation, and keeps its measured latency on the chart.

## 1.7.3

- **TCP:** DNS is resolved separately with its own error ("name does not resolve"), IPv4 is tried before IPv6 and every address gets a share of the timeout, so one dead address no longer fails a healthy host. Latency is the TCP handshake alone, and the message names the address that answered. Errors are plain language (connection refused, unreachable, reset).
- **Ping:** up to three echo requests share the timeout and one reply is enough, so a single lost packet is not an outage ("Reply from ... after 1 lost"). Latency has sub-millisecond rounding fixed, and a missing ICMP permission now says what to configure.
- **HTTP:** failures include the status text ("HTTP 503 Service Unavailable"), and the User-Agent carries the real version.
- Tests cover open/closed ports, DNS failure, address ordering, HTTP status and keyword results, and ping.

## 1.7.2

- Dashboard: overall status banner, instant filter (search by name, group or target, plus All / Down / Up / Paused), status stripe on down and maintenance rows, paused rows dimmed, group headers with a down count. The filter survives live updates and is remembered for the session; without JavaScript the full list is shown.

## 1.7.1

- **Alert privacy lock** (Settings, on by default): webhooks carry only the monitor name, up/down and time. No IP, hostname, port, URL, error text or latency, so alerts are safe for company servers and shared channels. With the lock off, a webhook can opt in to technical details.
- **Group-bound webhooks**: a webhook can be bound to monitor groups. It then receives every monitor of those groups and nothing else, which keeps company and personal alerts fully separate in one panel. The dashboard shows which webhooks serve each group.

## 1.7.0

- **Prometheus metrics** at `/metrics` (text format 0.0.4): status, up, response time, uptime ratio, certificate expiry, muted, maintenance, open incidents and database size. Protected by a token that is stored hashed and sent as `Authorization: Bearer` (or basic auth with the token as password); failed attempts are rate limited. Optional dedicated listener via `NDO4_METRICS_BIND`, optional fixed token via `NDO4_METRICS_TOKEN`.
- **Mute** per monitor (1 h to until unmuted): the monitor stays tracked and visible but sends no webhooks; no recovery message is sent for outages that were never announced.
- **Maintenance windows** (once, daily, weekly, ...): monitors inside a window keep being checked but never alert, are not counted as down and show as "maintenance". Status pages announce windows only when the page contains an affected monitor.
- **White-label status pages**: brand name, logo upload (PNG/JPEG/WebP/GIF, 256 KB, content sniffed), accent colour, dark/light/auto theme, header links, footer text, hide attribution, noindex switch.
- **Incident history** on status pages (last 90 days, names and durations only) and on each monitor.
- **Rolling storage limits**: configurable retention, 50,000 results per monitor, a database size cap and incident cap; hourly batched deletes, oldest first. Container logs rotate (3 x 10 MB).

## 1.6.1

- Headless setup: `NDO4_TAILSCALE_AUTHKEY` / `_FILE` / `NDO4_TAILSCALE_HOSTNAME` enable Tailscale on first start; `NDO4_ADMIN_PASSWORD_FILE` supports Docker secrets.
- The documented `docker run` command sets the password, a memory limit (384 MB) and a process limit.
- The "Live" label is gone. A quiet pulsing dot shows the stream is connected (a warning pill appears only if it drops).
- Updates now feel like a stream: a hairline sweeps across the top of the window for every update, values that changed glow briefly and a new heartbeat slides into its bar. Motion respects `prefers-reduced-motion`.

## 1.6.0

- **Tailscale** in Settings: monitor private networks. Runs `tailscaled` in unprivileged userspace mode, signs in with a one-time auth key or a sign-in link, shows the device list and routes, and is shielded (no inbound) with client log upload disabled.
- New per-monitor **Network** option (Automatic / Through Tailscale / Direct). HTTP, Browser and TCP checks use the node's local SOCKS5 proxy, ping uses `tailscale ping`.
- **Automatic updates** (default on): verified download from pkgs.tailscale.com, side-by-side install, health check and automatic rollback; manual *Check* and *Update now*.
- The image bundles a pinned, checksum-verified Tailscale; compose memory limit raised to 384 MB.

## 1.5.1

- Check counters on the dashboard and monitor tiles are abbreviated (1.2K, 34M, 5.6B, 7.8T) so huge totals never break the layout; the exact figure is shown on hover.
- README leads with the one-line `docker run` of the prebuilt image.

## 1.5.0

- Secure first start: no setup page. A random administrator password is generated and logged once (or taken from `NDO4_ADMIN_PASSWORD`), so nobody can claim a fresh instance.
- `Strict-Transport-Security` is sent when `NDO4_COOKIE_SECURE=1`.
- CI: `cargo audit` job and a stricter Docker smoke test.

## 1.4.0

- Down confirmation: a monitor is declared down, and webhooks fire, only after N consecutive failed checks (default 3). The 1st and 2nd failure show yellow (`checking 1/3`), the 3rd turns red. One success resets the count. Short blips and flapping no longer notify.
- Settings → Alerting: global failure count (1–10) and fast re-check interval (10–300 s); per-monitor override replaces the old *Retries* field.
- Yellow bars for unconfirmed failures; webhook payload gains `failed_checks` and `confirmed_after`.

## 1.3.0

- Status pages: choose monitors, group them per page, publish at `/s/<address>` or on a custom domain; live updates, no refresh. Only names, groups, state and uptime are public.
- Monitor groups on the dashboard.
- Separate public listener (`NDO4_PUBLIC_BIND`, default port 8590) that serves status pages only.
- Cloudflare Tunnel switch in Settings (bundled, checksum-pinned `cloudflared`; token stored server-side and never shown back).

## 1.2.0

- Live dashboard and monitor pages: a server-sent event stream (`/events`) pushes updates the moment a check finishes; no page refresh. A "Live" indicator shows the connection state and the stream pauses while the tab is hidden.
- Password-only sign-in (single administrator, no username). Existing installs keep their password.
- New branding: logo and theme colours derived from it.

## 1.1.0

- Browser monitor rebuilt in pure Rust: HTML parsed with html5ever, visible-text keyword, CSS selector assertion and sub-resource loading (same-host by default, optional third-party).
- Per-monitor proxy (http, https, socks5, socks5h).
- TLS certificate expiry tracking with an optional failure threshold.
- `NDO4_TRUST_PROXY` for correct login rate limiting behind a reverse proxy.
- Fix: forms were rejected by real browsers because `Referrer-Policy: no-referrer` makes them send `Origin: null`; policy is now `same-origin` and the origin check falls back to `Sec-Fetch-Site`.
- Clearer errors (root cause for connection and TLS failures); database migrates existing installs automatically.

## 1.0.0

- First release: HTTP(s), Browser, TCP and ping monitors; webhook alerts; NDO4Panel theme; hardened Docker image.
