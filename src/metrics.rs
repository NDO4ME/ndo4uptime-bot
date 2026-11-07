//! Prometheus `/metrics` (text exposition format 0.0.4) behind a bearer token.
//!
//! The app speaks plain HTTP only: put it behind a TLS proxy (Caddy) or scrape it over a private
//! network such as Tailscale. The token is stored hashed; it travels as `Authorization: Bearer`
//! (or HTTP Basic with the token as password, which every Prometheus version can send).

use crate::auth::*;
use crate::db::now;
use crate::view::*;
use crate::web::{bad_csrf, page};
use crate::{sched, App};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, request::Parts, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use maud::{html, Markup};
use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

type S = State<Arc<App>>;

static CACHE: Mutex<Option<(Instant, String)>> = Mutex::new(None);

fn esc(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => {}
            c => o.push(c),
        }
    }
    o
}

fn token_hash(app: &App) -> Option<String> {
    if let Ok(t) = std::env::var("NDO4_METRICS_TOKEN") {
        if t.trim().len() >= 16 {
            return Some(sha(t.trim()));
        }
    }
    Some(app.db.setting("metrics_token")).filter(|h| h.len() == 64)
}

fn presented(parts: &Parts) -> Option<String> {
    let h = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(t) = h.strip_prefix("Bearer ") {
        return Some(t.trim().to_string());
    }
    let b = h.strip_prefix("Basic ")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b.trim())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    Some(s.split_once(':')?.1.to_string())
}

fn render(app: &App) -> String {
    let t = now();
    let mons = app.db.monitors();
    let up24 = app.db.uptime_since(t - 86400);
    let last = app.db.last_checks();
    let mut o = String::with_capacity(512 * mons.len() + 1024);
    let fam = |o: &mut String, name: &str, help: &str, kind: &str| {
        let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} {kind}");
    };
    fam(
        &mut o,
        "ndo4uptime_build_info",
        "Build information.",
        "gauge",
    );
    let _ = writeln!(o, "ndo4uptime_build_info{{version=\"{VERSION}\"}} 1");
    let lab = |m: &crate::db::Monitor| {
        format!(
            "id=\"{}\",name=\"{}\",type=\"{}\",group=\"{}\"",
            m.id,
            esc(&m.name),
            esc(&m.kind),
            esc(&m.grp)
        )
    };
    let maint = |id: i64| app.db.in_maintenance(id).is_some();
    fam(
        &mut o,
        "ndo4uptime_monitor_status",
        "0 pending, 1 up, 2 down, 3 maintenance, 4 paused.",
        "gauge",
    );
    for m in &mons {
        let s = if !m.enabled {
            4
        } else if maint(m.id) {
            3
        } else {
            m.status
        };
        let _ = writeln!(o, "ndo4uptime_monitor_status{{{}}} {s}", lab(m));
    }
    fam(&mut o, "ndo4uptime_monitor_up", "1 when the monitor is up, 0 when confirmed down. Absent while pending, paused or in maintenance.", "gauge");
    for m in mons
        .iter()
        .filter(|m| m.enabled && m.status != 0 && !maint(m.id))
    {
        let _ = writeln!(
            o,
            "ndo4uptime_monitor_up{{{}}} {}",
            lab(m),
            i64::from(m.status == 1)
        );
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_response_time_milliseconds",
        "Response time of the latest successful check.",
        "gauge",
    );
    for m in &mons {
        if let Some((_, Some(ms))) = last.get(&m.id) {
            let _ = writeln!(
                o,
                "ndo4uptime_monitor_response_time_milliseconds{{{}}} {ms}",
                lab(m)
            );
        }
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_last_check_timestamp_seconds",
        "Unix time of the latest check.",
        "gauge",
    );
    for m in &mons {
        if let Some((ts, _)) = last.get(&m.id) {
            let _ = writeln!(
                o,
                "ndo4uptime_monitor_last_check_timestamp_seconds{{{}}} {ts}",
                lab(m)
            );
        }
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_uptime_ratio",
        "Share of successful checks over the last 24 hours (0–1).",
        "gauge",
    );
    for m in &mons {
        if let Some((n, ok)) = up24.get(&m.id).filter(|(n, _)| *n > 0) {
            let _ = writeln!(
                o,
                "ndo4uptime_monitor_uptime_ratio{{{},window=\"24h\"}} {:.6}",
                lab(m),
                *ok as f64 / *n as f64
            );
        }
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_consecutive_failures",
        "Failed checks in a row that have not yet been confirmed or cleared.",
        "gauge",
    );
    for m in &mons {
        let _ = writeln!(
            o,
            "ndo4uptime_monitor_consecutive_failures{{{}}} {}",
            lab(m),
            m.fails
        );
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_muted",
        "1 while webhooks for the monitor are muted.",
        "gauge",
    );
    for m in &mons {
        let _ = writeln!(
            o,
            "ndo4uptime_monitor_muted{{{}}} {}",
            lab(m),
            i64::from(sched::muted(m))
        );
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_maintenance",
        "1 while the monitor is inside a maintenance window.",
        "gauge",
    );
    for m in &mons {
        let _ = writeln!(
            o,
            "ndo4uptime_monitor_maintenance{{{}}} {}",
            lab(m),
            i64::from(maint(m.id))
        );
    }
    fam(
        &mut o,
        "ndo4uptime_monitor_certificate_expiry_timestamp_seconds",
        "Unix time the TLS certificate expires.",
        "gauge",
    );
    for m in mons.iter().filter(|m| m.cert_expiry > 0) {
        let _ = writeln!(
            o,
            "ndo4uptime_monitor_certificate_expiry_timestamp_seconds{{{}}} {}",
            lab(m),
            m.cert_expiry
        );
    }
    let st = app.db.storage();
    fam(
        &mut o,
        "ndo4uptime_incidents_open",
        "Outages that are currently ongoing.",
        "gauge",
    );
    let _ = writeln!(
        o,
        "ndo4uptime_incidents_open {}",
        app.db.open_incident_count()
    );
    fam(
        &mut o,
        "ndo4uptime_database_used_bytes",
        "Bytes of live data in the database.",
        "gauge",
    );
    let _ = writeln!(o, "ndo4uptime_database_used_bytes {}", st.used);
    fam(
        &mut o,
        "ndo4uptime_heartbeats",
        "Stored check results.",
        "gauge",
    );
    let _ = writeln!(o, "ndo4uptime_heartbeats {}", st.heartbeats);
    o
}

pub async fn serve(
    State(app): S,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    parts: Parts,
) -> Response {
    let Some(want) = token_hash(&app) else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    let ip = client_ip(&app, &parts, peer);
    let deny = |code: StatusCode| {
        (
            code,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"ndo4uptime\"")],
            "Unauthorized\n",
        )
            .into_response()
    };
    if rate_blocked(&app, ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts\n").into_response();
    }
    let ok =
        presented(&parts).is_some_and(|t| bool::from(sha(&t).as_bytes().ct_eq(want.as_bytes())));
    if !ok {
        rate_fail(&app, ip);
        return deny(StatusCode::UNAUTHORIZED);
    }
    let body = {
        let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        match c.as_ref() {
            Some((at, b)) if at.elapsed() < Duration::from_secs(5) => b.clone(),
            _ => {
                let b = render(&app);
                *c = Some((Instant::now(), b.clone()));
                b
            }
        }
    };
    (
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub async fn settings_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    match f.get("do") {
        "generate" => {
            let token = format!("ndo4m_{}", random_hex(24));
            app.db.set_setting("metrics_token", &sha(&token));
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
            page(crate::web::settings_page(
                &a.csrf,
                Some((
                    "ok",
                    "Metrics enabled. Copy the token now — it is shown only once.",
                )),
                None,
                &app,
                Some(&token),
            ))
        }
        "disable" => {
            app.db.set_setting("metrics_token", "");
            Redirect::to("/settings?m=metrics_off").into_response()
        }
        _ => Redirect::to("/settings").into_response(),
    }
}

pub fn panel(app: &App, csrf: &str, secret: Option<&str>) -> Markup {
    let env = std::env::var("NDO4_METRICS_TOKEN").is_ok_and(|t| t.trim().len() >= 16);
    let on = token_hash(app).is_some();
    let dedicated = app.cfg.metrics_bind.as_deref();
    html! {
        section.panel {
            header.panel-h { h2 { (ic("gauge")) "Prometheus metrics" } div.panel-tools { span class=(if on { "badge success" } else { "badge" }) { (if on { "enabled" } else { "off" }) } } }
            div.panel-b {
                @if let Some(t) = secret {
                    (msg("warn", "Copy this token now. Only its hash is stored, so it cannot be shown again.", false))
                    label.field { span.lbl { "Token" } input.mono readonly value=(t) data-select; }
                }
                p.hint { "Scrape " code { "/metrics" } " with " code { "Authorization: Bearer <token>" } " (or basic auth with the token as password)." }
                @if let Some(b) = dedicated { p.hint { "Dedicated metrics listener: " code { (b) } "." } }
                @else { p.hint { "Served on the admin port. Set " code { "NDO4_METRICS_BIND" } " (for example a Tailscale address) to expose only metrics on a separate port." } }
                p.hint { "The app speaks plain HTTP: reach it through your TLS proxy (Caddy) or over a private network such as Tailscale." }
                @if env { p.hint { "A token is also set by " code { "NDO4_METRICS_TOKEN" } "; it works alongside the one generated here." } }
            }
            div.panel-f {
                form method="post" action="/settings/metrics" { (csrf_input(csrf)) input type="hidden" name="do" value="generate";
                    button.btn.btn-primary { (ic("key")) (if on { "Regenerate token" } else { "Enable and generate token" }) } }
                @if on {
                    form method="post" action="/settings/metrics" class="js-confirm" data-confirm-title="Disable metrics" data-confirm="Scrapers using the current token will stop working." { (csrf_input(csrf)) input type="hidden" name="do" value="disable"; button.btn { (ic("stop")) "Disable" } }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_escaping() {
        assert_eq!(esc("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
