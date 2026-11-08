# Changelog
## 1.9.1
- **Notifications complete.** 29 more types: HaloPSA, Apprise API, BearSMS, CallMeBot, Flowtriq, Fluxer, Heii On-Call, Indigo, Jira Service Management, MAX, Milky, NotifyApp, OneChat, OpenWA, Pinglet, Signalgrid, SMS Gateway, SMSEagle, SMS.ir, Yunzhijia, Ooredoo, Google Sheets, AmootSMS, Aliyun SMS, **SMTP email** (implicit TLS, STARTTLS or plain, AUTH PLAIN), **Microsoft Graph email** and **Teltonika router SMS**.  Channels with several recipients or steps (Indigo, OpenWA, SMS Gateway, SMS.ir, Microsoft Graph, Teltonika, SMTP) send them in order and report the first failure. **Web Push** (RFC 8291 encryption and VAPID signing on ring; paste the browser subscription and your VAPID key pair) and **Nostr** private messages (NIP-17 gift wraps with NIP-44 encryption, signed with the audited k256 crate, sent to wss relays). Every provider of the reference catalogue is covered; 109 types in total.
- **Settings sections.** Settings shows one section at a time (General, Security, Alerts, Data, Connectivity, AI, About) with a tab bar; without JavaScript everything stays on one page.
- Timestamps in "Recent checks" and everywhere else follow the configured time zone and clock; the old sidebar styles and scripts are gone (smaller CSS and JS).
## 1.9.0
- **New top navigation.** The side menu is gone: five links (Dashboard, Status pages, Maintenance, Notifications, Settings), the primary "Add monitor" button and the account menu sit in one bar. Detail pages get a small back link instead of extra menu entries.
- **Light, dark and automatic themes.** Pick one from the account menu or Settings; it is remembered per browser and applied before the page paints. The status pages keep their own look.
- **109 notification types.** Notifications now offers, next to the signed webhook, chat (Slack, Discord, Teams, Telegram, Matrix, Mattermost, Google Chat, Rocket.Chat, LINE, Feishu, DingTalk, Signal and more), push (ntfy, Gotify, Pushover, Pushbullet, Bark and more), incident tools (PagerDuty, Opsgenie, Splunk On-Call, Grafana OnCall and more), email gateways (SendGrid, Resend, Brevo and more) and SMS/messaging providers (Twilio, Telnyx, ClickSend, WhatsApp gateways and more). Each type shows only its own fields; secrets are never shown again and stay unchanged when the field is left empty on edit. Every type is built from the same alert as the webhook, so the privacy lock still limits a message to name, state and time. SMTP is not included (the app has no mail client by design); use an email gateway.
- **Time zone and clock.** Settings → General sets the display time zone (any IANA name) and 12/24-hour clock for admin timestamps. Stored data stays in UTC.
- Settings opens with a General group; the instance panel lists the channel types.
## 1.8.9
- **Tailscale reconnects by itself after a restart or update.** While tailscaled was still loading its saved login (backend state "NoState"/"Starting"), the supervisor already started a new sign-in over it, which could leave the node disconnected until Save was pressed. It now waits for the saved login first, and a node that is still not connected after 75 seconds (and is not just waiting for a sign-in link or approval) gets a fresh tailscaled automatically. Save also restarts the connection now.
## 1.8.8
- **Admin layout made symmetrical.** Settings is now grouped under Security, Alerts, Data and metrics, Connectivity, AI and About; panels sit in equal-height pairs with their Save buttons on one line. Two-column forms (new monitor, page editor, monitor details) end at the same height. Date/time and file inputs match the other fields, stat tiles line up, and the dashboard filter bar is level again (a logo-picker style had leaked into it in 1.8.6).
## 1.8.7
- **Subnet routes work in Automatic mode.** Network → Automatic used to send only `100.x` and `*.ts.net` through Tailscale, so an address such as `10.1.2.3` behind a subnet router went out on the normal network and failed. The routes your peers advertise (and that your node accepts) are now read from the Tailscale status, and TCP/HTTP/browser checks to IP addresses inside them go through Tailscale automatically. "Never" still bypasses it. Ping to subnet addresses stays on the normal network in Automatic mode, since ICMP cannot cross a userspace node.
## 1.8.6
- **Page editor redesigned.** Logo is one panel with a single choice, upload a file or use a link, and a preview of the current logo; switching from one to the other now works (the old two-form layout required both fields). Page settings sit beside the monitor list, and Save / Cancel / View public page stay in a bar at the bottom.
- **Cleaner, cached status page source.** The document is minified (CSS, script, icon sprite), the embedded font moved to a block at the very end, and the finished page is built once and cached, including its gzip form (`Content-Encoding: gzip` for clients that accept it, `Vary: Accept-Encoding`). It is rebuilt only when the page settings, logo or live data change.
## 1.8.5
- **Status pages are always `noindex`.** Every status page response carries `X-Robots-Tag: noindex, nofollow, noarchive` and the matching robots meta tag. The per-page switch is gone; it can no longer be turned off by mistake. The admin port sends the header too.
- **Logo from a link.** The page editor can fetch a logo from a URL as well as take an upload. The image is downloaded once and stored on the server, so the public page still loads nothing from outside. The fetch accepts only public http(s) addresses on the default ports, checks every resolved address, pins the connection to it, follows no redirects, caps the size at 256 KB and checks the image type.
- **Public port refuses everything but the stream.** Apart from GET/HEAD, the only accepted request is the status page's own body-less live-stream POST on `/` or `/s/<slug>`. Any other POST, any POST with a body, PUT, PATCH and DELETE get `403`.

## 1.8.4

- **Status pages work behind "Cache Everything".** The live stream is now the page's own address asked with `POST` (a CDN never caches a POST) instead of a `GET` with an `Accept` header, which a CDN that ignores `Vary` could answer with the cached HTML. A visitor who is served a cached page gets it corrected by the first live frame, which is sent as soon as the stream opens. Tested on a custom domain behind a proxy that caches every GET for an hour and ignores origin cache headers.

## 1.8.3

- **One address per status page.** The live stream is no longer a separate `/events` path: the page's own address (`/` on a custom domain, `/s/<slug>` otherwise) returns the page normally and the live stream when asked with `Accept: text/event-stream` (read with `fetch`, no cookies). Both answers carry `Vary: Accept`. The public listener now has no `/events` or `/s/<slug>/events` route. Works through Caddy, nginx or Cloudflare Tunnel as any streaming response; for nginx keep proxy buffering off (`X-Accel-Buffering: no` is sent). The admin panel's own authenticated `/events` is unchanged.

## 1.8.2

- **Status pages are one self-contained document.** Styles, script, font, icons, logo and favicon are embedded in the page source; the only request a page makes afterwards is its live event stream (`/events`, or `/s/<slug>/events`). The public listener no longer serves `/static`, `/s/<slug>/logo` or `/s/<slug>/theme.css` at all. The page's own Content-Security-Policy allows only its inline blocks (by SHA-256 hash), `data:` images and fonts, and `connect-src 'self'`; no `unsafe-inline`, nothing from any other origin. The live script does no other request (no health probe) on public pages. Verified in a real browser: 2 requests, no CSP violations.
- **Group names fixed.** Status pages showed the monitor's own group (for example the same name on every table) instead of the group chosen under *Group on this page*. They now use the page's groups.

## 1.8.1

Full code audit; fixes:

- **Login:** the rate limit is reserved before the password is checked, so parallel guesses can no longer slip past it; Argon2 verification runs on at most two threads at once (a busy server answers 503 instead of exhausting memory); IPv6 clients are limited per /64.
- **Webhooks:** delivery retries transient failures (timeouts, connection errors, 429, 5xx) after 5 s and 20 s; permanent errors are not retried. One shared HTTP client.
- **Scheduler:** only due monitors are cloned per tick.
- **Limits:** at most 500 monitors, 50 webhooks and 50 status pages.
- **Maintenance windows:** impossible dates such as 31 February are rejected instead of silently moving to March; a repeating window must be shorter than its period (otherwise it only ran once).
- **Input hardening:** host names starting with `-` are refused and `tailscale ping` gets a `--` separator (no option injection); monitor and webhook names reject control characters; webhook fields have server-side length limits; a failed password hash can no longer store an empty hash.
- **Ping:** verified against real ICMP on the host (loopback, a public address, and an unreachable address timing out); an unavailable IPv6 route now says so instead of a raw OS error.
- **AI:** the test button has a 10 s cooldown, the analysis webhooks use the retrying delivery, and password checks share the login hardening.

## 1.8.0

- **AI incident assistant (Groq).** On a confirmed DOWN (never on recovery) a model writes a neutral corporate-tone notice for status pages and a short English analysis for webhooks, sent as a follow-up `analysis` event so the DOWN alert is never delayed. Primary model `qwen/qwen3.8-27b` with automatic fallback to `openai/gpt-oss-20b`; capable models may use Groq's server-side web search, nothing runs as an agent here.
- **Private by default:** only the monitor name, check type and a scrubbed failure class go to Groq with the privacy lock on; all returned text is scrubbed again (IPs, hosts, URLs, e-mails, paths, target and port) and a status-page statement that would change is dropped. With the lock off, webhooks marked "technical details" get a detailed analysis.
- **Per monitor:** switch and a short *Notes for the assistant* field (what the system is).
- **Key handling:** `NDO4_GROQ_API_KEY` (or `_FILE`) at install, or Settings. Stored encrypted (ChaCha20-Poly1305, key file mode 0600), never shown again, replaced or removed only after re-entering the password.
- **Bounded:** daily request cap, two requests in flight, 25 s timeout, one incident = 1–3 requests.
- **Production hardening:** own accept loop for every listener with a connection cap and a 15 s request-header deadline (slow-client protection); clean shutdown on SIGTERM (`docker stop`) with a database checkpoint; data directory created `0700`; a production checklist in DEVELOPER.md. 700 randomised requests against every POST route and malformed raw HTTP requests caused no crash or 5xx.

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
