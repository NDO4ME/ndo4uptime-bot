# Changelog

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
