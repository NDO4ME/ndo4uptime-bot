<div align="center">

<img src="docs/logo.webp" alt="NDO4Uptime" width="420">

# NDO4Uptime

**A lightweight, security-focused uptime monitor written in Rust.**<br>
One container. Small static binary. Webhook alerts. Secure by default.

[![CI](https://github.com/NDO4ME/ndo4uptime-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/NDO4ME/ndo4uptime-bot/actions/workflows/ci.yml)
[![Docker Image](https://github.com/NDO4ME/ndo4uptime-bot/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/NDO4ME/ndo4uptime-bot/actions/workflows/docker-publish.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Features](#why-ndo4uptime) · [Updating](DEVELOPER.md#updating) · [Documentation](DEVELOPER.md)

<img src="docs/dashboard.png" alt="NDO4Uptime dashboard" width="860">

</div>

## Why NDO4Uptime

| | |
|---|---|
| **Four check types** | HTTP(s), Browser, TCP port and ICMP ping. HTTP supports method, custom headers, body, expected status ranges, keyword match, redirects, TLS verification and a per-monitor proxy. [Details](DEVELOPER.md#monitor-types) |
| **Browser check without Chromium** | A pure-Rust page load: the HTML is parsed with Servo's `html5ever`, then CSS, scripts and images are fetched like a browser would. Fails on broken assets, missing text or a missing CSS selector. [How it works](DEVELOPER.md#browser-checks) |
| **Certificate expiry** | HTTPS monitors track the certificate's expiry date and can fail (and alert) before it lapses. |
| **Status pages** | Public pages for the monitors you choose, grouped your way, live without refresh, with an optional custom domain per page. Monitors can be grouped on the dashboard too. [Status pages](DEVELOPER.md#status-pages-and-cloudflare-tunnel) |
| **Cloudflare Tunnel** | Switch it on from Settings to publish status pages on your own subdomain, with no open ports. Only the public listener is exposed, never the admin panel. |
| **No false alarms** | A monitor turns yellow on the 1st and 2nd failed check and is declared down — and alerts — only on the 3rd consecutive failure. Configurable in Settings, overridable per monitor. [How it works](DEVELOPER.md#down-confirmation-no-false-alarms) |
| **Webhook alerts** | One focused channel: JSON `POST` on down and recovery, custom headers, optional HMAC-SHA256 signature and a test button. [Payload](DEVELOPER.md#webhooks) |
| **Extremely light** | Static Rust binary, SQLite storage, a `scratch` image with nothing else in it. No Node.js, no Chromium, no JavaScript engine. |
| **Secure by default** | Listens on localhost only, no default password (random one generated on first start), Argon2id passwords, CSRF protection, login rate limiting, strict CSP, read-only non-root container. [Security](DEVELOPER.md#security-notes) |
| **Clear history** | 24h / 7d / 30d uptime, response-time chart, per-check log and automatic retention. |
| **Works behind your proxy** | Ready for Caddy with automatic HTTPS, or run it locally. [Caddy setup](DEVELOPER.md#reverse-proxy-caddy) |

## Quick start

You need Docker with Compose v2.

```bash
git clone https://github.com/NDO4ME/ndo4uptime-bot.git
cd ndo4uptime-bot
docker compose up -d --build
```

Open `http://127.0.0.1:8589` and sign in with the random administrator password printed once in the log (`docker compose logs ndo4uptime`); change it under Settings. Sign-in is password-only (no username); the dashboard and monitor pages update live over a server-sent event stream, no refresh needed.
Put it behind Caddy for HTTPS with the ready-made [`deploy/Caddyfile`](deploy/Caddyfile).

## Update

```bash
git pull && docker compose up -d --build
```

Data lives in the `ndo4uptime-data` volume and is kept. See [Updating](DEVELOPER.md#updating) and [Backup and restore](DEVELOPER.md#backup-and-restore).

## Documentation

| Topic | |
|---|---|
| Installation and configuration | [Quick start](DEVELOPER.md#quick-start) · [Environment variables](DEVELOPER.md#configuration) |
| Using the panel | [Monitor types](DEVELOPER.md#monitor-types) · [Status pages and Cloudflare Tunnel](DEVELOPER.md#status-pages-and-cloudflare-tunnel) · [Webhooks](DEVELOPER.md#webhooks) |
| Operations | [Updating](DEVELOPER.md#updating) · [Caddy](DEVELOPER.md#reverse-proxy-caddy) · [Backup](DEVELOPER.md#backup-and-restore) · [Reset password](DEVELOPER.md#reset-the-password) · [Troubleshooting](DEVELOPER.md#troubleshooting) |
| Security | [Security notes](DEVELOPER.md#security-notes) · [Policy](SECURITY.md) |
| Contributing | [Architecture](DEVELOPER.md#architecture) · [Development](DEVELOPER.md#development) · [CI/CD](DEVELOPER.md#cicd) |

## License

MIT, see [LICENSE](LICENSE).
