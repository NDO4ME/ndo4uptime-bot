use crate::auth::*;
use crate::db::{now, Monitor, Webhook};
use crate::view::*;
use crate::{checks, notify, sched, App};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, request::Parts, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use maud::{html, Markup};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

/// Generous ceilings that keep one instance light; a thousand checks a minute is plenty for a self-hosted monitor.
const MAX_MONITORS: usize = 500;
const MAX_WEBHOOKS: usize = 50;

type S = State<Arc<App>>;
type Q = Query<HashMap<String, String>>;

pub(crate) fn page(m: Markup) -> Response {
    Html(m.into_string()).into_response()
}
pub(crate) fn flash_of(q: &HashMap<String, String>) -> Option<(&'static str, &'static str)> {
    q.get("m").and_then(|c| flash_text(c))
}
pub(crate) fn bad_csrf() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Invalid CSRF token. Reload the page and try again.",
    )
        .into_response()
}

// ---------------------------------------------------------------- static / health
const FILES: &[(&str, &[u8], &str)] = &[
    (
        "app.css",
        include_bytes!("../static/app.css"),
        "text/css; charset=utf-8",
    ),
    (
        "ext.css",
        include_bytes!("../static/ext.css"),
        "text/css; charset=utf-8",
    ),
    (
        "nav.css",
        include_bytes!("../static/nav.css"),
        "text/css; charset=utf-8",
    ),
    (
        "admin.js",
        include_bytes!("../static/admin.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "app.js",
        include_bytes!("../static/app.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "ext.js",
        include_bytes!("../static/ext.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "boot.js",
        include_bytes!("../static/boot.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "icons.svg",
        include_bytes!("../static/icons.svg"),
        "image/svg+xml",
    ),
    (
        "logo.webp",
        include_bytes!("../static/logo.webp"),
        "image/webp",
    ),
    (
        "logo-mark.webp",
        include_bytes!("../static/logo-mark.webp"),
        "image/webp",
    ),
    (
        "favicon.webp",
        include_bytes!("../static/favicon.webp"),
        "image/webp",
    ),
    (
        "fonts/Inter-latin.woff2",
        include_bytes!("../static/fonts/Inter-latin.woff2"),
        "font/woff2",
    ),
];

pub async fn static_file(Path(p): Path<String>) -> Response {
    match FILES.iter().find(|(n, _, _)| *n == p) {
        Some((_, b, ct)) => (
            [
                (header::CONTENT_TYPE, *ct),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            *b,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
pub async fn healthz() -> &'static str {
    "ok"
}
/// Public listener gate: the only request with a method other than GET/HEAD that is accepted
/// is the status page's own live-stream POST (no body, on `/` or `/s/<slug>`). Everything else
/// that writes - any other POST, PUT, DELETE, PATCH, a POST with a body - gets 403.
pub async fn public_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use axum::http::Method;
    let p = req.uri().path();
    let stream_path = p == "/" || (p.starts_with("/s/") && !p[3..].contains('/'));
    let empty = req
        .headers()
        .get("content-length")
        .is_none_or(|v| v.as_bytes() == b"0")
        && !req.headers().contains_key("transfer-encoding");
    let ok = match *req.method() {
        Method::GET | Method::HEAD => true,
        Method::POST => stream_path && empty,
        _ => false,
    };
    if !ok {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    next.run(req).await
}

pub async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

// ---------------------------------------------------------------- login
fn login_form() -> Markup {
    html! {
        form method="post" action="/login" autocomplete="on" {
            input type="hidden" name="username" value="admin" autocomplete="username";
            label.field { span.lbl { "Password" } input type="password" name="password" autocomplete="current-password" required maxlength="256" autofocus; }
            button type="submit" class="btn btn-primary btn-block" { "Sign in" }
        }
    }
}

const LOGIN_FOOT: &str = "First start? The generated password is printed once in the server log (docker compose logs ndo4uptime). Forgot it? Run the reset command from the README on the host.";

pub async fn login_get(State(app): S, parts: Parts) -> Response {
    if let Some(t) = cookie_value(&parts) {
        if app.db.session_get(&sha(&t)).is_some_and(|(_, e)| e > now()) {
            return Redirect::to("/").into_response();
        }
    }
    page(auth_page(
        "Sign in",
        "Enter the administrator password.",
        None,
        login_form(),
        LOGIN_FOOT,
    ))
}

pub async fn login_post(
    State(app): S,
    parts: Parts,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    f: Form,
) -> Response {
    if !origin_ok(&parts) {
        return (StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response();
    }
    let ip = client_ip(&app, &parts, addr);
    if !rate_reserve(&app, ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            page(auth_page(
                "Sign in",
                "Enter the administrator password.",
                Some("Too many failed attempts. Try again in 15 minutes."),
                login_form(),
                "",
            )),
        )
            .into_response();
    }
    let p = f.get("password").to_string();
    // Always verify against a hash so timing is identical whether or not an account exists.
    let stored = app.db.first_user().map(|x| x.2);
    let known = stored.is_some();
    let hash = stored.unwrap_or_else(|| app.dummy_hash.clone());
    let Some(ok) = verify_pw(p, hash).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            page(auth_page(
                "Sign in",
                "Enter the administrator password.",
                Some("The server is busy. Try again in a moment."),
                login_form(),
                "",
            )),
        )
            .into_response();
    };
    if !(ok && known) {
        return (
            StatusCode::UNAUTHORIZED,
            page(auth_page(
                "Sign in",
                "Enter the administrator password.",
                Some("Invalid password."),
                login_form(),
                "",
            )),
        )
            .into_response();
    }
    rate_clear(&app, ip);
    let cookie = new_session(&app);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

pub async fn logout(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    app.db.session_del(&a.token_hash);
    (
        [(header::SET_COOKIE, set_cookie(&app, "", 0))],
        Redirect::to("/login"),
    )
        .into_response()
}

// ---------------------------------------------------------------- dashboard
fn beat_class(b: &crate::db::Beat) -> &'static str {
    if b.ok {
        "up"
    } else if b.soft {
        "warn"
    } else {
        "down"
    }
}

fn beat_bar(app: &App, id: i64) -> Markup {
    let mut beats = app.db.beats(id, 40);
    beats.reverse();
    let pad = 40usize.saturating_sub(beats.len());
    html! {
        div.hbar aria-hidden="true" {
            @for _ in 0..pad { i {} }
            @for b in &beats { i class=(beat_class(b)) title=(format!("{} · {}{}", fmt_ts(b.ts), b.msg, if b.soft { " (unconfirmed)" } else { "" })) {} }
        }
    }
}

fn dashboard_body(app: &App) -> Markup {
    let mons = app.db.monitors();
    let since = now() - 86400;
    // One lookup per monitor instead of one per use: this view is rebuilt on every live update.
    let in_maint: HashSet<i64> = mons
        .iter()
        .filter(|m| app.db.in_maintenance(m.id).is_some())
        .map(|m| m.id)
        .collect();
    let (mut up, mut down, mut paused, mut maint) = (0, 0, 0, 0);
    for m in &mons {
        if !m.enabled {
            paused += 1;
        } else if in_maint.contains(&m.id) {
            maint += 1;
        } else if m.status == 1 {
            up += 1;
        } else if m.status == 2 {
            down += 1;
        }
    }
    let (tot, okc) = app.db.stats_total(since);
    let avg = if tot > 0 {
        Some(okc as f64 * 100.0 / tot as f64)
    } else {
        None
    };
    let mut sorted: Vec<&Monitor> = mons.iter().collect();
    sorted.sort_by(|a, b| {
        (
            !a.grp.is_empty(),
            a.grp.to_lowercase(),
            a.name.to_lowercase(),
        )
            .cmp(&(
                !b.grp.is_empty(),
                b.grp.to_lowercase(),
                b.name.to_lowercase(),
            ))
    });
    let has_groups = mons.iter().any(|m| !m.grp.is_empty());
    let hooks = app.db.webhooks();
    let (bcls, bicon, btext) = if mons.is_empty() {
        ("info", "info", "No monitors yet".to_string())
    } else if down > 0 {
        (
            "err",
            "x-circle",
            format!("{down} monitor{} down", if down == 1 { "" } else { "s" }),
        )
    } else if up == 0 && maint > 0 {
        (
            "maint",
            "tool",
            "All monitors under maintenance".to_string(),
        )
    } else if up == 0 {
        ("info", "clock", "Waiting for the first results".to_string())
    } else {
        ("ok", "check-circle", "All systems operational".to_string())
    };
    html! {
        div class=(format!("sp-banner sp-{bcls}")) role="status" { (ic(bicon)) span { (btext) } span.sp-sub { (up) " up · " (paused) " paused" @if maint > 0 { " · " (maint) " in maintenance" } } }
        div.vitals {
            section.vital aria-label="Up" { div.vital-h { span.vital-t { (ic("check-circle")) "Up" } } div.vital-v { (up) } div.vital-s { "monitors responding" } }
            section class=(if down > 0 { "vital crit" } else { "vital" }) aria-label="Down" { div.vital-h { span.vital-t { (ic("x-circle")) "Down" } } div.vital-v { (down) } div.vital-s { "need attention" } }
            section.vital aria-label="Paused" { div.vital-h { span.vital-t { (ic("stop")) "Paused" } } div.vital-v { (paused) } div.vital-s { @if maint > 0 { (maint) " in maintenance" } @else { "not being checked" } } }
            section.vital aria-label="Uptime" { div.vital-h { span.vital-t { (ic("activity")) "Uptime · 24h" } } div.vital-v { (pct(avg)) } div.vital-s title=(format!("{} checks", grouped(tot))) { (compact(tot)) " checks" } }
        }
        section.panel {
            header.panel-h { h2 { (ic("activity")) "Monitors" } div.panel-tools { span.faint.small { (mons.len()) " total · live" } } }
            @if mons.is_empty() {
                div.empty-state { (ic("activity")) "No monitors yet. Add your first HTTP, TCP, ping or browser check." br; br; a.btn.btn-primary href="/monitors/new" { (ic("plus")) "New monitor" } }
            } @else {
                div.tbl-wrap { table.tbl.mon-tbl {
                    thead { tr { th { "Status" } th { "Monitor" } th { "Type" } th { "Last 40 checks" } th.num { "24h" } th.num { "Latency" } th {} } }
                    tbody { @for (i, m) in sorted.iter().enumerate() {
                        @if has_groups && (i == 0 || sorted[i - 1].grp != m.grp) {
                            @let n = sorted.iter().filter(|x| x.grp == m.grp).count();
                            @let u = sorted.iter().filter(|x| x.grp == m.grp && x.enabled && x.status == 1).count();
                            tr.grp-row { td colspan="7" { span.grp-n { (if m.grp.is_empty() { "Ungrouped" } else { m.grp.as_str() }) } span.faint.small { (u) " / " (n) " up" }
                                @let dn = sorted.iter().filter(|x| x.grp == m.grp && x.enabled && x.status == 2).count();
                                @if dn > 0 { span.badge.failed { (dn) " down" } }
                                @let routes: Vec<&str> = hooks.iter().filter(|h| h.enabled && h.in_group(&m.grp)).map(|h| h.name.as_str()).collect();
                                @if !routes.is_empty() { span.badge.info title="Alerts for this group go only to these webhooks" { (ic("bell")) (routes.join(", ")) } } } }
                        }
                        @let st = app.db.stats(m.id, since);
                        @let last = app.db.beats(m.id, 1);
                        @let state = if !m.enabled { "paused" } else if in_maint.contains(&m.id) { "maint" } else if m.status == 2 { "down" } else if m.status == 1 { "up" } else { "checking" };
                        tr data-state=(state) data-name=(format!("{} {} {}", m.name, m.grp, m.target).to_lowercase()) {
                            td { @if m.enabled && in_maint.contains(&m.id) { (state_badge(true, m.status, true)) } @else { (live_badge(m, app.db.threshold(m))) } @if sched::muted(m) { " " span.badge title="Muted: no webhooks" { (ic("bell-off")) } } }
                            td { div.mon-n { a href=(format!("/monitors/{}", m.id)) { (m.name) } small { (target_label(m)) } } }
                            td.nowrap { (kind_label(&m.kind)) }
                            td { (beat_bar(app, m.id)) }
                            td.num { (pct(st.pct())) }
                            td.num.nowrap { @if let Some(Some(ms)) = last.first().map(|b| b.ms) { (ms) " ms" } @else { "–" } }
                            td.actions-cell { a.btn.btn-sm.btn-ghost href=(format!("/monitors/{}", m.id)) { "Details" } }
                        }
                    } }
                } }
            }
        }
    }
}

fn live(view: &str, inner: Markup) -> Markup {
    html! { div id="live" data-live=(format!("/events?v={view}")) { (inner) } }
}

pub async fn dashboard(State(app): S, a: Auth, Query(q): Q) -> Response {
    let body = html! {
        div.toolbar.needs-js id="mon-filter" {
            label.search { (ic("search")) input type="search" id="mon-q" placeholder="Filter monitors" aria-label="Filter monitors" autocomplete="off" maxlength="80"; }
            div.seg role="group" aria-label="Status filter" {
                button type="button" class="seg-b on" data-f="all" { "All" }
                button type="button" class="seg-b" data-f="down" { "Down" }
                button type="button" class="seg-b" data-f="up" { "Up" }
                button type="button" class="seg-b" data-f="paused" { "Paused" }
            }
        }
        (live("dashboard", dashboard_body(&app)))
    };
    page(layout(
        Page {
            title: "Dashboard",
            desc: "Live status of everything you monitor.",
            active: "dashboard",
            csrf: &a.csrf,
            flash: flash_of(&q),
            parent: None,
            refresh: false,
            actions: html! {},
        },
        body,
    ))
}

fn target_label(m: &Monitor) -> String {
    if m.kind == "tcp" {
        format!("{}:{}", m.target, m.port)
    } else {
        m.target.clone()
    }
}

// ---------------------------------------------------------------- monitor detail
fn chart(beats_desc: &[crate::db::Beat]) -> Markup {
    let mut b: Vec<_> = beats_desc.iter().rev().collect();
    if b.len() > 120 {
        b = b.split_off(b.len() - 120);
    }
    let n = b.len();
    if n < 2 {
        return html! { div.empty-state { (ic("activity")) "Not enough data yet." } };
    }
    let maxms = b.iter().filter_map(|x| x.ms).max().unwrap_or(1).max(1) as f64 * 1.15;
    let step = 600.0 / (n as f64 - 1.0);
    let mut pts = Vec::new();
    for (i, x) in b.iter().enumerate() {
        if let (true, Some(ms)) = (x.ok, x.ms) {
            pts.push((i as f64 * step, 112.0 - (ms as f64 / maxms) * 100.0));
        }
    }
    let line: String = pts
        .iter()
        .map(|(x, y)| format!("{x:.1},{y:.1}"))
        .collect::<Vec<_>>()
        .join(" ");
    let area = pts
        .first()
        .zip(pts.last())
        .map(|(f, l)| format!("{:.1},112 {line} {:.1},112", f.0, l.0))
        .unwrap_or_default();
    html! {
        svg class="chart" viewBox="0 0 600 120" preserveAspectRatio="none" role="img" aria-label="Response time" {
            line.grid x1="0" y1="112" x2="600" y2="112" {}
            line.grid x1="0" y1="62" x2="600" y2="62" {}
            @if !area.is_empty() { polygon.area points=(area) {} polyline.line points=(line) vector-effect="non-scaling-stroke" {} }
            @for (i, x) in b.iter().enumerate() { @if !x.ok { rect.bad x=(format!("{:.1}", (i as f64 * step - 1.5).max(0.0))) y="0" width="3" height="112" fill-opacity="0.45" {} } }
        }
        div.chart-lbl { span { (ts(b[0].ts)) } span { "peak " (maxms as i64) " ms" } span { (ts(b[n - 1].ts)) } }
    }
}

fn monitor_body(app: &App, m: &Monitor) -> Markup {
    let id = m.id;
    let t = now();
    let (s24, s7, s30) = (
        app.db.stats(id, t - 86400),
        app.db.stats(id, t - 7 * 86400),
        app.db.stats(id, t - 30 * 86400),
    );
    let beats = app.db.beats(id, 120);
    let recent = &beats[..beats.len().min(50)];
    let linked = app.db.webhooks_for(m);
    let attached: Vec<&str> = linked.iter().map(|h| h.name.as_str()).collect();
    html! {
        div.vitals {
            section.vital { div.vital-h { span.vital-t { (ic("activity")) "Status" } } div.vital-v { (state_badge(m.enabled, m.status, m.enabled && app.db.in_maintenance(m.id).is_some())) @if sched::muted(m) { " " span.badge title=(format!("Muted until {}", if m.mute_until > now() + 5 * 365 * 86400 { "unmuted".to_string() } else { fmt_ts(m.mute_until) })) { (ic("bell-off")) "muted" } } } div.vital-s { @if m.fails > 0 && m.status != 2 { "confirming — " (m.fails) " of " (app.db.threshold(m)) " failed checks" } @else if m.changed > 0 { "since " (ago(m.changed)) } @else { "no result yet" } } }
            section.vital { div.vital-h { span.vital-t { (ic("clock")) "Uptime · 24h" } } div.vital-v { (pct(s24.pct())) } div.vital-s title=(format!("{} checks", grouped(s24.total))) { (compact(s24.total)) " checks" } }
            section.vital { div.vital-h { span.vital-t { (ic("calendar")) "Uptime · 7d / 30d" } } div.vital-v { (pct(s7.pct())) } div.vital-s { "30d " (pct(s30.pct())) } }
            section.vital { div.vital-h { span.vital-t { (ic("gauge")) "Avg response · 24h" } } div.vital-v { @if let Some(v) = s24.avg_ms { (v as i64) small { "ms" } } @else { "–" } } div.vital-s { "successful checks only" } }
        }
        div.cols.cols-main {
            div.stack {
                section.panel {
                    header.panel-h { h2 { (ic("gauge")) "Response time" } div.panel-tools { span.faint.small { "last " (beats.len()) " checks" } } }
                    div.panel-b { (chart(&beats)) }
                }
                section.panel {
                    header.panel-h { h2 { (ic("list")) "Recent checks" } }
                    div.tbl-wrap { table.tbl.recent-tbl {
                        thead { tr { th { "Time" } th { "Result" } th { "Message" } th.num { "Latency" } } }
                        tbody { @if recent.is_empty() { tr { td.empty colspan="4" { "No checks yet." } } }
                            @for b in recent { tr {
                                td.nowrap { (ts(b.ts)) }
                                td { span class=(if b.ok { "badge success" } else if b.soft { "badge warning" } else { "badge failed" }) { (if b.ok { "up" } else if b.soft { "failed" } else { "down" }) } }
                                td.break { (b.msg) }
                                td.num.nowrap { @if let Some(ms) = b.ms { (ms) " ms" } @else { "–" } }
                            } } }
                    } }
                }
            }
            div.stack {
                section.panel {
                    header.panel-h { h2 { (ic("alert")) "Incidents" } }
                    @let inc = app.db.incidents_for_monitor(id, 10);
                    @if inc.is_empty() { div.panel-b { p.hint { "No outages recorded." } } } @else {
                        div.tbl-wrap { table.tbl {
                            thead { tr { th { "Started" } th.num { "Duration" } } }
                            tbody { @for i in &inc { tr {
                                td.nowrap { (ts(i.started)) @if i.ended == 0 { " " span.badge.failed { "ongoing" } } }
                                td.num.nowrap { (dur(if i.ended == 0 { t - i.started } else { i.ended - i.started })) }
                            } @if !i.ai_text.is_empty() { tr { td colspan="2" { details { summary { (ic("zap")) " AI analysis" span.faint.small { " " (i.ai_model) } } p.ai-note { (i.ai_text) } } } } } } }
                        } }
                    }
                }
                section.panel {
                    header.panel-h { h2 { (ic("sliders")) "Configuration" } }
                    div.panel-b { dl.props {
                        dt { "Type" } dd { (kind_label(&m.kind)) }
                        @if !m.grp.is_empty() { dt { "Group" } dd { (m.grp) } }
                        dt { "Target" } dd.mono.break { (target_label(m)) }
                        @if m.kind == "http" || m.kind == "browser" {
                            dt { "Method" } dd.mono { (m.method) }
                            dt { "Expected" } dd.mono { (m.expect) }
                            @if !m.keyword.is_empty() { dt { "Keyword" } dd.mono.break { (if m.kw_not { "must be absent: " } else { "must be present: " }) (m.keyword) } }
                            dt { "Headers" } dd { (m.headers.lines().filter(|l| !l.trim().is_empty()).count()) " custom" }
                            dt { "TLS verify" } dd { (if m.verify_tls { "on" } else { "off" }) }
                            @if m.cert_expiry > 0 { dt { "Certificate" } dd { @let left = (m.cert_expiry - now()) / 86400; span class=(if left < 14 { "badge warning" } else { "badge success" }) { (left.max(0)) " days left" } " " span.faint.small { (ts(m.cert_expiry)) } } }
                            @if !m.proxy.is_empty() { dt { "Proxy" } dd.mono.break { (checks::redact_proxy(&m.proxy)) } }
                            @if m.kind == "browser" && !m.selector.is_empty() { dt { "Selector" } dd.mono.break { (m.selector) } }
                        }
                        @if m.kind == "tcp" && (!m.keyword.is_empty() || !m.body.is_empty()) { dt { "Banner check" } dd.mono.break { @if !m.body.is_empty() { "send " (m.body) } @if !m.keyword.is_empty() { " expect " (m.keyword) } } }
                        @if m.slow_ms > 0 { dt { "Slow limit" } dd { (m.slow_ms) " ms" } }
                        dt { "Interval" } dd { (m.interval) " s" }
                        dt { "Timeout" } dd { (m.timeout) " s" }
                        @if m.net != 0 || crate::tailscale::via(0, &checks::target_host(m)) { dt { "Network" } dd { @if crate::tailscale::via(m.net, &checks::target_host(m)) { "Through Tailscale" } @else { "Direct" } } }
                        dt { "Down after" } dd { (app.db.threshold(m)) " failed checks" @if m.confirm == 0 { " " span.faint.small { "(default)" } } }
                        dt { "Notifications" } dd { @if attached.is_empty() { span.faint { "none" } } @else { (attached.join(", ")) } }
                    } }
                }
            }
        }
    }
}

pub async fn monitor_get(State(app): S, a: Auth, Path(id): Path<i64>, Query(q): Q) -> Response {
    let Some(m) = app.db.monitor(id) else {
        return not_found().await;
    };
    let body = live(&format!("m{id}"), monitor_body(&app, &m));
    let actions = html! {
        form method="post" action=(format!("/monitors/{id}/check")) { (csrf_input(&a.csrf)) button.btn { (ic("refresh")) "Check now" } }
        form method="post" action=(format!("/monitors/{id}/toggle")) { (csrf_input(&a.csrf)) button.btn { (ic(if m.enabled { "stop" } else { "play" })) (if m.enabled { "Pause" } else { "Resume" }) } }
        @if sched::muted(&m) {
            form method="post" action=(format!("/monitors/{id}/unmute")) { (csrf_input(&a.csrf)) button.btn { (ic("bell")) "Unmute" } }
        } @else {
            form method="post" action=(format!("/monitors/{id}/mute")) class="mute-form" {
                (csrf_input(&a.csrf))
                select name="hours" aria-label="Mute duration" { option value="1" { "1 hour" } option value="8" { "8 hours" } option value="24" { "24 hours" } option value="168" { "7 days" } option value="0" { "Until unmuted" } }
                button.btn { (ic("bell-off")) "Mute" }
            }
        }
        a.btn href=(format!("/monitors/{id}/edit")) { (ic("edit")) "Edit" }
        form method="post" action=(format!("/monitors/{id}/delete")) class="js-confirm" data-confirm-title="Delete monitor" data-confirm=(format!("Delete \"{}\" and all of its history? This cannot be undone.", m.name)) {
            (csrf_input(&a.csrf)) button.btn.btn-danger { (ic("trash")) "Delete" }
        }
    };
    page(layout(
        Page {
            title: &m.name,
            desc: &target_label(&m),
            active: "dashboard",
            csrf: &a.csrf,
            flash: flash_of(&q),
            parent: Some(("/", "Dashboard")),
            refresh: false,
            actions,
        },
        body,
    ))
}

pub async fn monitor_action(
    State(app): S,
    a: Auth,
    Path((id, act)): Path<(i64, String)>,
    f: Form,
) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let Some(m) = app.db.monitor(id) else {
        return not_found().await;
    };
    let (code, to) = match act.as_str() {
        "toggle" => {
            app.db.set_enabled(id, !m.enabled);
            sched::run_now(&app, id);
            (
                if m.enabled { "paused" } else { "resumed" },
                format!("/monitors/{id}"),
            )
        }
        "check" => {
            sched::run_now(&app, id);
            ("checking", format!("/monitors/{id}"))
        }
        "mute" => {
            let hours = f.int("hours", 0).clamp(0, 24 * 365);
            // 0 hours means "until I unmute": far-future, but still bounded.
            let until = if hours == 0 {
                now() + 20 * 365 * 86400
            } else {
                now() + hours * 3600
            };
            app.db.set_mute(id, until);
            ("muted", format!("/monitors/{id}"))
        }
        "unmute" => {
            app.db.set_mute(id, 0);
            ("unmuted", format!("/monitors/{id}"))
        }
        "delete" => {
            app.db.delete_monitor(id);
            ("deleted", "/".into())
        }
        _ => return not_found().await,
    };
    Redirect::to(&format!("{to}?m={code}")).into_response()
}

// ---------------------------------------------------------------- monitor form
fn field_err(e: &str) -> Markup {
    msg("err", e, false)
}

fn monitor_form(
    m: &Monitor,
    hooks: &[Webhook],
    groups: &[String],
    dflt: i64,
    csrf: &str,
    err: Option<&str>,
) -> Markup {
    let action = if m.id > 0 {
        format!("/monitors/{}/edit", m.id)
    } else {
        "/monitors".to_string()
    };
    html! {
        @if let Some(e) = err { div.msgs { (field_err(e)) } }
        form method="post" action=(action) autocomplete="off" {
            (csrf_input(csrf))
            div.cols.cols-2 {
                div.stack {
                    section.panel {
                        header.panel-h { h2 { (ic("activity")) "Check" } }
                        div.panel-b {
                            label.field { span.lbl { "Name" } input name="name" value=(m.name) required maxlength="80" placeholder="Production API"; }
                            label.field { span.lbl { "Group (optional)" } input name="grp" value=(m.grp) list="mgroups" maxlength="60" placeholder="Production"; datalist id="mgroups" { @for g in groups { option value=(g) {} } } span.hint { "Monitors with the same group are listed together on the dashboard and can be grouped on status pages." } }
                            label.field { span.lbl { "Type" }
                                select name="kind" id="f-kind" {
                                    @for (v, l) in [("http", "HTTP(s)"), ("browser", "Browser (full page load)"), ("tcp", "TCP port"), ("ping", "Ping (ICMP)")] {
                                        option value=(v) selected[m.kind == v] { (l) }
                                    }
                                }
                            }
                            label.field { span.lbl { "Target" } input name="target" value=(m.target) required maxlength="2048" spellcheck="false" placeholder="https://example.com/health  ·  host or IP for TCP / ping";
                                span.hint { "URL for HTTP and Browser checks, hostname or IP for TCP and ping." } }
                            label.field data-for="tcp" { span.lbl { "Port" } input type="number" name="port" value=(m.port) min="1" max="65535"; }
                            div.row data-for="http browser" {
                                label.field { span.lbl { "Method" } select name="method" { @for v in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] { option value=(v) selected[m.method == v] { (v) } } } }
                                label.field { span.lbl { "Expected status" } input name="expect" value=(m.expect) maxlength="64" placeholder="200-299,301"; }
                            }
                            div.row data-for="http browser" {
                                label.field { span.lbl { "Keyword (optional)" } input name="keyword" value=(m.keyword) maxlength="200" placeholder="Text to look for in the response"; }
                                label.field { span.lbl { "Keyword must be" }
                                    select name="kw_not" { option value="0" selected[!m.kw_not] { "present" } option value="1" selected[m.kw_not] { "absent (e.g. \"error\", \"maintenance\")" } } }
                            }
                            div.row data-for="tcp" {
                                label.field { span.lbl { "Send (optional)" } input name="banner_send" value=(m.body) maxlength="512" spellcheck="false" placeholder="PING\\r\\n"; span.hint { "Written after connecting. " code { "\\r \\n \\t \\\\" } " are understood." } }
                                label.field { span.lbl { "Expect in reply (optional)" } input name="banner_expect" value=(m.keyword) maxlength="200" spellcheck="false" placeholder="SSH-2.0  ·  +PONG  ·  220"; span.hint { "The reply (or the greeting a server sends on its own) must contain this text." } }
                            }
                            label.field data-for="browser" { span.lbl { "CSS selector (optional)" } input name="selector" value=(m.selector) maxlength="200" spellcheck="false" placeholder="#app, main h1, .status-ok"; span.hint { "Must match at least one element in the parsed page. Keyword is matched against visible text only." } }
                        }
                    }
                    section.panel data-for="http browser" {
                        header.panel-h { h2 { (ic("code")) "Request" } }
                        div.panel-b {
                            label.field { span.lbl { "Headers" }
                                textarea name="headers" rows="5" maxlength="8192" spellcheck="false" placeholder="Authorization: Bearer …\nX-Api-Key: …" { (m.headers) }
                                span.hint { "One per line as " code { "Name: value" } ". Stored on this server; keep secrets scoped to monitoring." } }
                            label.field { span.lbl { "Body" } textarea name="body" rows="4" maxlength="65536" spellcheck="false" placeholder="Sent for POST / PUT / PATCH / DELETE" { (m.body) } }
                            label.field { span.lbl { "Proxy (optional)" } input name="proxy" value=(m.proxy) maxlength="512" spellcheck="false" autocomplete="off" placeholder="socks5://user:pass@10.0.0.2:1080"; span.hint { "http, https, socks5 or socks5h. Used for this monitor only; credentials are stored on this server." } }
            label.field { span.lbl { "Warn when certificate expires within (days)" } input type="number" name="cert_days" value=(m.cert_days) min="0" max="365"; span.hint { "0 disables. The check fails below the threshold, which triggers your notifications." } }
            label.check data-for="browser" { input type="checkbox" name="third_party" value="1" checked[m.third_party]; span { "Load third-party resources" span.hint { "By default only same-host CSS, scripts and images are loaded." } } }
                            label.check { input type="checkbox" name="follow" value="1" checked[m.follow]; span { "Follow redirects" } }
                            label.check { input type="checkbox" name="verify_tls" value="1" checked[m.verify_tls]; span { "Verify TLS certificate" span.hint { "Turn off only for self-signed internal targets." } } }
                        }
                    }
                }
                div.stack {
                    section.panel {
                        header.panel-h { h2 { (ic("clock")) "Schedule" } }
                        div.panel-b {
                            div.row {
                                label.field { span.lbl { "Interval (s)" } input type="number" name="interval" value=(m.interval) min="20" max="86400"; }
                                label.field { span.lbl { "Timeout (s)" } input type="number" name="timeout" value=(m.timeout) min="1" max="60"; }
                                label.field { span.lbl { "Failures before DOWN" } input type="number" name="confirm" value=(m.confirm) min="0" max="10"; }
                            }
                            p.hint { "A failed check turns the monitor yellow and is re-checked quickly. It is declared DOWN — and your notifications fire — only after this many consecutive failures; one success resets the count. " b { "0" } " uses the default from Settings (currently " (dflt) ")." }
                            label.field { span.lbl { "Slow response limit (ms)" } input type="number" name="slow_ms" value=(m.slow_ms) min="0" max="60000"; span.hint { "0 disables. A response slower than this counts as a failed check, so it goes through the same confirmation as an outage. Must be below the timeout." } }
                            label.check { input type="checkbox" name="ai_on" value="1" checked[m.ai_on]; span { "AI incident assistant" span.hint { "When this monitor goes DOWN and the assistant is enabled in Settings, it writes a neutral status-page statement and a short operator analysis." } } }
                            label.field { span.lbl { "Notes for the assistant" } textarea name="ai_note" rows="4" maxlength="800" placeholder="e.g. Customer portal on a single VM behind Cloudflare; database is a managed Postgres; nightly backup at 02:00." { (m.ai_note) } span.hint { "Optional short summary of the system, in any language. Used only to make the analysis specific. With the privacy lock on, IPs, hosts and URLs are stripped from it before anything leaves this server." } }
                            label.field { span.lbl { "Network" }
                                select name="net" {
                                    option value="0" selected[m.net == 0] { "Automatic" }
                                    option value="1" selected[m.net == 1] { "Through Tailscale" }
                                    option value="2" selected[m.net == 2] { "Direct" }
                                }
                                span.hint { "Automatic sends tailnet addresses (100.x.y.z, *.ts.net) through Tailscale and everything else directly. Choose Tailscale for private LAN addresses behind a subnet router; set it up under Settings → Tailscale." } }
                        }
                    }
                    section.panel {
                        header.panel-h { h2 { (ic("bell")) "Notifications" } div.panel-tools { a.btn.btn-sm.btn-ghost href="/webhooks" { "Manage" } } }
                        div.panel-b {
                            @if hooks.is_empty() { p.hint { "No notification channels yet. Add one under Notifications to get down and recovery alerts." } }
                            @for h in hooks { label.check { input type="checkbox" name="webhooks" value=(h.id) checked[m.webhooks.contains(&h.id)]; span { (h.name) @if !h.enabled { " " span.faint { "(disabled)" } } } } }
                        }
                    }
                }
            }
            div.form-actions { button type="submit" class="btn btn-primary" { (ic("check")) "Save monitor" } " " a.btn href=(if m.id > 0 { format!("/monitors/{}", m.id) } else { "/".into() }) { "Cancel" } }
        }
    }
}

fn group_names(app: &App) -> Vec<String> {
    let mut g: Vec<String> = app
        .db
        .monitors()
        .into_iter()
        .map(|m| m.grp)
        .filter(|g| !g.is_empty())
        .collect();
    g.sort_by_key(|g| g.to_lowercase());
    g.dedup();
    g
}

fn parse_monitor(f: &Form, id: i64) -> Monitor {
    let mut m = Monitor::blank();
    m.id = id;
    m.name = f.get("name").trim().to_string();
    m.grp = f.get("grp").trim().to_string();
    m.kind = f.get("kind").to_string();
    m.target = f.get("target").trim().to_string();
    m.port = f.int("port", 0);
    m.method = f.get("method").to_string();
    m.headers = f.get("headers").replace('\r', "");
    m.body = f.get("body").to_string();
    m.expect = f.get("expect").trim().to_string();
    m.kw_not = f.get("kw_not") == "1";
    m.slow_ms = f.int("slow_ms", 0);
    m.ai_on = f.has("ai_on");
    m.ai_note = f
        .get("ai_note")
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n'))
        .take(800)
        .collect::<String>()
        .trim()
        .to_string();
    if m.kind == "tcp" {
        m.body = f.get("banner_send").to_string();
        m.keyword = f.get("banner_expect").to_string();
    } else {
        m.keyword = f.get("keyword").to_string();
    }
    m.interval = f.int("interval", 60);
    m.timeout = f.int("timeout", 10);
    m.confirm = f.int("confirm", 0);
    m.net = f.int("net", 0);
    m.verify_tls = f.has("verify_tls");
    m.follow = f.has("follow");
    m.third_party = f.has("third_party");
    m.proxy = f.get("proxy").trim().to_string();
    m.selector = f.get("selector").trim().to_string();
    m.cert_days = f.int("cert_days", 0);
    m.webhooks = f
        .all("webhooks")
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if m.expect.is_empty() {
        m.expect = "200-299".into();
    }
    m
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('-') // never mistaken for a command-line option by `tailscale ping`
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

fn validate(m: &Monitor) -> Result<(), String> {
    if m.name.is_empty() || m.name.chars().count() > 80 || m.name.chars().any(char::is_control) {
        return Err("Name is required (max 80 characters).".into());
    }
    if m.grp.chars().count() > 60 || m.grp.chars().any(char::is_control) {
        return Err("Group names are limited to 60 characters.".into());
    }
    match m.kind.as_str() {
        "http" | "browser" => {
            let u = reqwest::Url::parse(&m.target)
                .map_err(|_| "Target must be a valid http:// or https:// URL.".to_string())?;
            if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
                return Err("Target must be a valid http:// or https:// URL.".into());
            }
            if !u.username().is_empty() || u.password().is_some() {
                return Err("Remove credentials from the URL and send them as a header instead (Authorization: …).".into());
            }
            if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                .contains(&m.method.as_str())
            {
                return Err("Unsupported HTTP method.".into());
            }
            if !checks::valid_status_spec(&m.expect) {
                return Err("Expected status must look like 200-299,301.".into());
            }
            checks::parse_headers(&m.headers)?;
            checks::validate_proxy(&m.proxy)?;
            if m.proxy.len() > 512 || m.selector.len() > 200 || !checks::valid_selector(&m.selector)
            {
                return Err("Proxy or CSS selector is invalid.".into());
            }
            if !(0..=365).contains(&m.cert_days) {
                return Err("Certificate warning must be between 0 and 365 days.".into());
            }
            if m.body.len() > 65536 || m.keyword.len() > 200 {
                return Err("Body or keyword is too long.".into());
            }
        }
        "tcp" => {
            if !valid_host(&m.target) {
                return Err("Enter a valid hostname or IP address.".into());
            }
            if !(1..=65535).contains(&m.port) {
                return Err("Port must be between 1 and 65535.".into());
            }
            if m.body.len() > 512 || m.keyword.len() > 200 {
                return Err("Send text (512) or expected reply (200) is too long.".into());
            }
        }
        "ping" => {
            if !valid_host(&m.target) {
                return Err("Enter a valid hostname or IP address.".into());
            }
        }
        _ => return Err("Unknown monitor type.".into()),
    }
    if !(20..=86400).contains(&m.interval) {
        return Err("Interval must be between 20 and 86400 seconds.".into());
    }
    if !(1..=60).contains(&m.timeout) || m.timeout >= m.interval {
        return Err("Timeout must be 1–60 seconds and shorter than the interval.".into());
    }
    if m.slow_ms != 0 && !(50..=60000).contains(&m.slow_ms) || m.slow_ms >= m.timeout * 1000 {
        return Err(
            "Slow response limit must be 50 ms or more and below the timeout (0 turns it off)."
                .into(),
        );
    }
    if !(0..=2).contains(&m.net) {
        return Err("Unknown network route.".into());
    }
    if !(0..=10).contains(&m.confirm) {
        return Err("Failures before DOWN must be between 0 and 10.".into());
    }
    Ok(())
}

pub async fn monitor_new(State(app): S, a: Auth) -> Response {
    let m = Monitor::blank();
    let hooks = app.db.webhooks();
    page(layout(
        Page {
            title: "New monitor",
            desc: "Add an HTTP, browser, TCP or ping check.",
            active: "new",
            csrf: &a.csrf,
            flash: None,
            parent: Some(("/", "Dashboard")),
            refresh: false,
            actions: html! {},
        },
        monitor_form(
            &m,
            &hooks,
            &group_names(&app),
            app.db.down_after(),
            &a.csrf,
            None,
        ),
    ))
}

pub async fn monitor_create(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.monitors().len() >= MAX_MONITORS {
        return Redirect::to("/?m=limit").into_response();
    }
    save_monitor(app, a, f, 0).await
}

pub async fn monitor_edit_get(State(app): S, a: Auth, Path(id): Path<i64>) -> Response {
    let Some(m) = app.db.monitor(id) else {
        return not_found().await;
    };
    let hooks = app.db.webhooks();
    let back = format!("/monitors/{id}");
    page(layout(
        Page {
            title: "Edit monitor",
            desc: &m.name,
            active: "dashboard",
            csrf: &a.csrf,
            flash: None,
            parent: Some((&back, &m.name)),
            refresh: false,
            actions: html! {},
        },
        monitor_form(
            &m,
            &hooks,
            &group_names(&app),
            app.db.down_after(),
            &a.csrf,
            None,
        ),
    ))
}

pub async fn monitor_edit_post(State(app): S, a: Auth, Path(id): Path<i64>, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.monitor(id).is_none() {
        return not_found().await;
    }
    save_monitor(app, a, f, id).await
}

async fn save_monitor(app: Arc<App>, a: Auth, f: Form, id: i64) -> Response {
    let mut m = parse_monitor(&f, id);
    let known: HashSet<i64> = app.db.webhooks().iter().map(|h| h.id).collect();
    m.webhooks.retain(|w| known.contains(w));
    if let Err(e) = validate(&m) {
        let hooks = app.db.webhooks();
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            page(layout(
                Page {
                    title: if id > 0 {
                        "Edit monitor"
                    } else {
                        "New monitor"
                    },
                    desc: "Fix the highlighted problem and save again.",
                    active: if id > 0 { "dashboard" } else { "new" },
                    csrf: &a.csrf,
                    flash: None,
                    parent: Some(("/", "Dashboard")),
                    refresh: false,
                    actions: html! {},
                },
                monitor_form(
                    &m,
                    &hooks,
                    &group_names(&app),
                    app.db.down_after(),
                    &a.csrf,
                    Some(&e),
                ),
            )),
        )
            .into_response();
    }
    let new_id = app.db.save_monitor(&m);
    sched::run_now(&app, new_id);
    Redirect::to(&format!("/monitors/{new_id}?m=saved")).into_response()
}

// ---------------------------------------------------------------- webhooks
fn webhook_form(h: &Webhook, csrf: &str, err: Option<&str>) -> Markup {
    let action = if h.id > 0 {
        format!("/webhooks/{}/edit", h.id)
    } else {
        "/webhooks".to_string()
    };
    let kind = if h.kind.is_empty() {
        "webhook"
    } else {
        h.kind.as_str()
    };
    let cfg = notify::config(&h.cfg);
    html! {
        @if let Some(e) = err { div.msgs { (field_err(e)) } }
        form method="post" action=(action) autocomplete="off" {
            (csrf_input(csrf))
            div.panel-b {
                label.field { span.lbl { "Name" } input name="name" value=(h.name) required maxlength="80" placeholder="Team alerts"; }
                label.field { span.lbl { "Type" }
                    select name="kind" id="nk" {
                        option value="webhook" selected[kind == "webhook"] { "Webhook (signed JSON)" }
                        @for cat in notify::CATS {
                            optgroup label=(cat) {
                                @for p in notify::PROVIDERS.iter().filter(|p| p.cat == *cat) {
                                    option value=(p.key) selected[kind == p.key] { (p.label) }
                                }
                            }
                        }
                    }
                }
                div.nk-pane data-kind="webhook" {
                    label.field { span.lbl { "URL" } input name="url" value=(if kind == "webhook" { h.url.as_str() } else { "" }) maxlength="2048" spellcheck="false" placeholder="https://hooks.example.com/uptime"; }
                    label.field { span.lbl { "Custom headers" } textarea name="headers" rows="3" maxlength="4096" spellcheck="false" placeholder="Authorization: Bearer …" { (h.headers) } span.hint { "One per line as " code { "Name: value" } "." } }
                    label.field { span.lbl { "Signing secret (optional)" } input name="secret" value=(h.secret) maxlength="256" spellcheck="false" autocomplete="off";
                        span.hint { "Adds " code { "X-NDO4-Signature: sha256=…" } " — HMAC-SHA256 of " code { "timestamp.body" } " using " code { "X-NDO4-Timestamp" } "." } }
                }
                @for p in notify::PROVIDERS {
                    div.nk-pane data-kind=(p.key) hidden[kind != p.key] {
                        @for f in p.fields {
                            @let id = format!("f_{}_{}", p.key, f.k);
                            @let cur = if kind == p.key { cfg.g(f.k) } else { "" };
                            label.field {
                                span.lbl { (f.label) @if !f.req { " " span.faint { "(optional)" } } }
                                @match f.kind {
                                    notify::K::Select(opts) => {
                                        select name=(id) { @for o in opts { option value=(o) selected[cur == *o] { (o) } } }
                                    }
                                    notify::K::Secret => {
                                        input name=(id) type="password" maxlength="2048" autocomplete="new-password" spellcheck="false" placeholder=(if cur.is_empty() { "" } else { "unchanged — leave empty to keep" });
                                    }
                                    _ => {
                                        input name=(id) value=(cur) maxlength="2048" spellcheck="false";
                                    }
                                }
                                @if !f.hint.is_empty() { span.hint { (f.hint) } }
                            }
                        }
                    }
                }
                label.field { span.lbl { "Only these groups (optional)" } textarea name="groups" rows="2" maxlength="600" spellcheck="false" placeholder="Company" { (h.groups) }
                    span.hint { "One monitor group per line. A bound channel receives " b { "every monitor of those groups and nothing else" } " — use it to keep company and personal alerts apart. Leave empty to use only the monitors you attach it to." } }
                label.check { input type="checkbox" name="detail" value="1" checked[h.detail]; span { "Include technical details" span.hint { "Adds target, error message and latency. Has no effect while the privacy lock in Settings is on." } } }
            }
            div.panel-f { button type="submit" class="btn btn-primary" { (ic("check")) "Save" } @if h.id > 0 { " " a.btn href="/webhooks" { "Cancel" } } }
        }
    }
}

/// `old` supplies stored secrets when a secret field is left empty on edit.
fn parse_webhook(f: &Form, id: i64, old: Option<&Webhook>) -> Webhook {
    let kind = f.get("kind").trim().to_string();
    let kind = if kind.is_empty() {
        "webhook".to_string()
    } else {
        kind
    };
    let mut w = Webhook {
        id,
        name: f.get("name").trim().to_string(),
        enabled: true,
        groups: f
            .get("groups")
            .lines()
            .map(|g| g.trim())
            .filter(|g| !g.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        detail: f.has("detail"),
        ..Default::default()
    };
    if kind == "webhook" {
        w.url = f.get("url").trim().to_string();
        w.headers = f.get("headers").replace('\r', "");
        w.secret = f.get("secret").trim().to_string();
    } else if let Some(p) = notify::provider(&kind) {
        let prev = old
            .filter(|o| o.kind == kind)
            .map(|o| notify::config(&o.cfg))
            .unwrap_or_else(|| notify::C(Default::default()));
        let mut m = std::collections::BTreeMap::new();
        for fd in p.fields {
            let mut v = f.get(&format!("f_{}_{}", p.key, fd.k)).trim().to_string();
            if v.is_empty() && fd.kind == notify::K::Secret {
                v = prev.g(fd.k).to_string();
            }
            if !v.is_empty() {
                m.insert(fd.k.to_string(), v);
            }
        }
        w.cfg = serde_json::to_string(&m).unwrap_or_default();
    }
    w.kind = kind;
    w
}

fn validate_webhook(h: &Webhook) -> Result<(), String> {
    if h.name.is_empty() || h.name.chars().count() > 80 {
        return Err("Name is required (max 80 characters).".into());
    }
    if h.name.chars().any(char::is_control) {
        return Err("Name must not contain control characters.".into());
    }
    if h.groups.len() > 600 {
        return Err("Groups list is too long.".into());
    }
    if h.kind != "webhook" {
        let p = notify::provider(&h.kind).ok_or("Unknown notification type.")?;
        return notify::validate(p, &notify::config(&h.cfg));
    }
    let u = reqwest::Url::parse(&h.url)
        .map_err(|_| "URL must be a valid http:// or https:// address.".to_string())?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err("URL must be a valid http:// or https:// address.".into());
    }
    if h.url.len() > 2048 || h.headers.len() > 4096 || h.secret.len() > 256 {
        return Err("URL, headers or secret is too long.".into());
    }
    checks::parse_headers(&h.headers)?;
    Ok(())
}

pub async fn webhooks_get(State(app): S, a: Auth, Query(q): Q) -> Response {
    let hooks = app.db.webhooks();
    let mons = app.db.monitors();
    let body = html! {
        section.panel {
            header.panel-h { h2 { (ic("bell")) "Channels" } div.panel-tools { span.faint.small { "Sent on down and recovery" } } }
            div.tbl-wrap { table.tbl {
                thead { tr { th { "Name" } th { "Type" } th { "Scope" } th { "Status" } th { "Last result" } th {} } }
                tbody { @if hooks.is_empty() { tr { td.empty colspan="6" { "No notification channels yet. Add one below." } } }
                    @for h in &hooks { tr {
                        td { strong { (h.name) } }
                        td { (channel_label(&h.kind)) @if h.kind.is_empty() || h.kind == "webhook" { " " span.faint.small.mono { (redact_url(&h.url)) } } }
                        td { @if h.group_list().is_empty() { span.faint { "attached monitors" } } @else { @for g in h.group_list() { span.badge.info { (g) } " " } } }
                        td { span class=(if h.enabled { "badge success" } else { "badge warning" }) { (if h.enabled { "enabled" } else { "disabled" }) } }
                        td { @if h.last_ts > 0 { (h.last_msg) " " span.faint.small { (ago(h.last_ts)) } } @else { span.faint { "never used" } } }
                        td.actions-cell { div.btn-group {
                            form method="post" action=(format!("/webhooks/{}/test", h.id)) { (csrf_input(&a.csrf)) button.btn.btn-sm { (ic("zap")) "Test" } }
                            form method="post" action=(format!("/webhooks/{}/toggle", h.id)) { (csrf_input(&a.csrf)) button.btn.btn-sm { (if h.enabled { "Disable" } else { "Enable" }) } }
                            a.btn.btn-sm.btn-ghost href=(format!("/webhooks/{}/edit", h.id)) { (ic("edit")) "Edit" }
                            form method="post" action=(format!("/webhooks/{}/delete", h.id)) class="js-confirm" data-confirm-title="Delete channel" data-confirm=(format!("Delete channel \"{}\"? Monitors using it will stop sending notifications to it.", h.name)) {
                                (csrf_input(&a.csrf)) button class="btn btn-sm btn-icon btn-danger" title="Delete" aria-label="Delete" { (ic("trash")) }
                            }
                        } }
                    } } }
            } }
            footer.panel-f.small.faint { (mons.len()) " monitors · attach channels to a monitor from its edit form." }
        }
        div.cols.cols-main {
            section.panel {
                header.panel-h { h2 { (ic("plus")) "Add channel" } }
                (webhook_form(&Webhook { enabled: true, ..Default::default() }, &a.csrf, None))
            }
            section.panel {
                header.panel-h { h2 { (ic("code")) "Payload" } }
                div.panel-b {
                    pre.mono { (pretty_payload(false)) }
                    p.hint { "Private payload (default): name and state only." }
                    @if !app.db.privacy_lock() { pre.mono { (pretty_payload(true)) } p.hint { "With technical details enabled on a webhook." } }
                    p.hint { code { "event" } " is " code { "down" } ", " code { "up" } " or " code { "test" } ". " code { "time" } " is a Unix timestamp." }
                }
            }
        }
    };
    page(layout(
        Page {
            title: "Notifications",
            desc: "Where alerts go: chat, push, incident tools, email gateways or your own signed webhook.",
            active: "webhooks",
            csrf: &a.csrf,
            flash: flash_of(&q),
            parent: None,
            refresh: false,
            actions: html! {},
        },
        body,
    ))
}

/// Hide query string / userinfo — webhook URLs often embed tokens.
fn channel_label(k: &str) -> &'static str {
    notify::provider(k).map_or("Webhook", |p| p.label)
}

fn redact_url(u: &str) -> String {
    match reqwest::Url::parse(u) {
        Ok(p) => {
            let mut s = format!("{}://{}", p.scheme(), p.host_str().unwrap_or(""));
            if let Some(port) = p.port() {
                s.push_str(&format!(":{port}"));
            }
            s.push_str(if p.path().len() > 1 || p.query().is_some() {
                "/…"
            } else {
                "/"
            });
            s
        }
        Err(_) => "invalid".into(),
    }
}

pub async fn webhook_create(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.webhooks().len() >= MAX_WEBHOOKS {
        return Redirect::to("/webhooks?m=limit").into_response();
    }
    let h = parse_webhook(&f, 0, None);
    if let Err(e) = validate_webhook(&h) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            page(layout(
                Page { title: "Notifications", desc: "Fix the problem and save again.", active: "webhooks", csrf: &a.csrf, flash: None, parent: None, refresh: false, actions: html! {} },
                html! { section.panel { header.panel-h { h2 { (ic("plus")) "Add channel" } } (webhook_form(&h, &a.csrf, Some(&e))) } },
            )),
        )
            .into_response();
    }
    app.db.save_webhook(&h);
    Redirect::to("/webhooks?m=saved").into_response()
}

pub async fn webhook_edit_get(State(app): S, a: Auth, Path(id): Path<i64>) -> Response {
    let Some(h) = app.db.webhook(id) else {
        return not_found().await;
    };
    page(layout(
        Page {
            title: "Edit channel",
            desc: &h.name,
            active: "webhooks",
            csrf: &a.csrf,
            flash: None,
            parent: Some(("/webhooks", "Notifications")),
            refresh: false,
            actions: html! {},
        },
        html! { section.panel { header.panel-h { h2 { (ic("edit")) "Webhook" } } (webhook_form(&h, &a.csrf, None)) } },
    ))
}

pub async fn webhook_edit_post(State(app): S, a: Auth, Path(id): Path<i64>, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.webhook(id).is_none() {
        return not_found().await;
    }
    let h = parse_webhook(&f, id, app.db.webhook(id).as_ref());
    if let Err(e) = validate_webhook(&h) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            page(layout(
                Page { title: "Edit channel", desc: "Fix the problem and save again.", active: "webhooks", csrf: &a.csrf, flash: None, parent: Some(("/webhooks", "Notifications")), refresh: false, actions: html! {} },
                html! { section.panel { header.panel-h { h2 { (ic("edit")) "Webhook" } } (webhook_form(&h, &a.csrf, Some(&e))) } },
            )),
        )
            .into_response();
    }
    app.db.save_webhook(&h);
    Redirect::to("/webhooks?m=saved").into_response()
}

pub async fn webhook_action(
    State(app): S,
    a: Auth,
    Path((id, act)): Path<(i64, String)>,
    f: Form,
) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let Some(h) = app.db.webhook(id) else {
        return not_found().await;
    };
    let code = match act.as_str() {
        "toggle" => {
            app.db.toggle_webhook(id);
            "saved"
        }
        "delete" => {
            app.db.delete_webhook(id);
            "deleted"
        }
        "test" => {
            let r = sched::send_webhook(
                &h,
                &sched::payload(
                    "test",
                    None,
                    "Test notification from NDO4Uptime",
                    Some(42),
                    None,
                    h.detail && !app.db.privacy_lock(),
                ),
            )
            .await;
            let ok = r.is_ok();
            app.db.webhook_result(id, &r.unwrap_or_else(|e| e));
            if ok {
                "test_ok"
            } else {
                "test_fail"
            }
        }
        _ => return not_found().await,
    };
    Redirect::to(&format!("/webhooks?m={code}")).into_response()
}

// ---------------------------------------------------------------- settings
fn settings_view(
    csrf: &str,
    flash: Option<(&str, &str)>,
    err: Option<&str>,
    app: &App,
    secret: Option<&str>,
) -> Markup {
    let retention = app.db.retention_days(app.cfg.retention_days);
    let st = app.db.storage();
    let cap_mb = app.db.max_db_mb();
    layout(
        Page {
            title: "Settings",
            desc: "Display, security, alerting, data and connectivity.",
            active: "settings",
            csrf,
            flash,
            parent: None,
            refresh: false,
            actions: html! {},
        },
        html! {
            (settings_tabs(false))
            div.sg id="sg-general" {
                h3.sg-t { "General" }
                div.cols.cols-2 {
                    section.panel {
                        header.panel-h { h2 { (ic("clock")) "Time zone and clock" } }
                        form method="post" action="/settings/display" {
                            (csrf_input(csrf))
                            div.panel-b {
                                label.field { span.lbl { "Time zone" } input name="tz" value=(app.db.setting("tz")) list="tz-list" maxlength="64" spellcheck="false" placeholder="Browser default (e.g. Europe/Istanbul)"; datalist id="tz-list" {}
                                    span.hint { "IANA name such as " code { "Europe/Istanbul" } " or " code { "UTC" } ". Empty uses each browser's own zone. Stored data stays in UTC." } }
                                label.field { span.lbl { "Clock" } select name="h12" { option value="0" selected[app.db.setting("h12") != "1"] { "24-hour" } option value="1" selected[app.db.setting("h12") == "1"] { "12-hour (AM/PM)" } } }
                            }
                            div.panel-f { button.btn.btn-primary { "Save" } }
                        }
                    }
                    section.panel {
                        header.panel-h { h2 { (ic("eye")) "Appearance" } }
                        div.panel-b {
                            p.hint { "The theme is remembered in this browser. Auto follows the system setting." }
                            div.btn-group {
                                button type="button" class="btn js-theme" data-theme="dark" { "Dark" }
                                button type="button" class="btn js-theme" data-theme="light" { "Light" }
                                button type="button" class="btn js-theme" data-theme="auto" { "Auto" }
                            }
                        }
                    }
                }
            }
            div.sg id="sg-security" {
                h3.sg-t { "Security" }
                div.cols.cols-2 {
                section.panel {
                    header.panel-h { h2 { (ic("key")) "Change password" } }
                    @if let Some(e) = err { div.panel-b { (msg("err", e, false)) } }
                    form method="post" action="/settings/password" {
                        (csrf_input(csrf))
                        div.panel-b {
                            label.field { span.lbl { "Current password" } input type="password" name="current" autocomplete="current-password" required maxlength="256"; }
                            label.field { span.lbl { "New password" } input type="password" name="password" autocomplete="new-password" required minlength="10" maxlength="256"; span.hint { "At least 10 characters. All other sessions are signed out." } }
                            label.field { span.lbl { "Confirm new password" } input type="password" name="confirm" autocomplete="new-password" required minlength="10" maxlength="256"; }
                        }
                        div.panel-f { button.btn.btn-primary { "Change password" } }
                    }
                }
                    section.panel {
                        header.panel-h { h2 { (ic("shield")) "Sessions" } }
                        div.panel-b { p.hint { "Sessions last 12 hours, are bound to a HttpOnly SameSite=Strict cookie and are stored hashed." } }
                        div.panel-f {
                            form method="post" action="/settings/sessions" class="js-confirm" data-confirm-title="Sign out other sessions" data-confirm="Sign out every other browser session?" {
                                (csrf_input(csrf)) button.btn { (ic("logout")) "Sign out other sessions" }
                            }
                        }
                    }
                }
            }
            div.sg id="sg-alerts" {
                h3.sg-t { "Alerts" }
                div.cols.cols-2 {
                    section.panel {
                        header.panel-h { h2 { (ic("bell")) "Alerting" } }
                        form method="post" action="/settings/alerting" {
                            (csrf_input(csrf))
                            div.panel-b {
                                div.row {
                                    label.field { span.lbl { "Failures before DOWN" } input type="number" name="down_after" value=(app.db.down_after()) min="1" max="10" required; }
                                    label.field { span.lbl { "Re-check every (s)" } input type="number" name="recheck" value=(app.db.recheck_secs()) min="10" max="300" required; }
                                }
                                p.hint { "Avoids false alarms and short blips. With the default of 3: the 1st failed check turns a monitor " b.warn-t { "yellow" } ", the 2nd stays yellow, the 3rd turns it " b.err-t { "red" } " — only then is it DOWN and notifications are sent. While confirming, the monitor is re-checked at the interval above instead of waiting for its normal one. One success resets the count. Each monitor can override the number." }
                            }
                            div.panel-f { button.btn.btn-primary { (ic("check")) "Save" } }
                        }
                    }
                    section.panel {
                        header.panel-h { h2 { (ic("shield")) "Alert privacy" } div.panel-tools { span class=(if app.db.privacy_lock() { "badge success" } else { "badge warning" }) { (if app.db.privacy_lock() { "locked" } else { "relaxed" }) } } }
                        form method="post" action="/settings/privacy" {
                            (csrf_input(csrf))
                            div.panel-b {
                                label.check { input type="checkbox" name="lock" value="1" checked[app.db.privacy_lock()]; span { "Privacy lock (recommended)" span.hint { "Notifications carry only the monitor name, up/down and time — never IP addresses, hostnames, ports, URLs, error text or latency. Safe for company servers and shared chat channels." } } }
                            }
                            div.panel-f { button.btn.btn-primary { (ic("check")) "Save" } }
                        }
                    }
                }
            }
            div.sg id="sg-data" {
                h3.sg-t { "Data and metrics" }
                div.cols.cols-2 {
                    section.panel {
                        header.panel-h { h2 { (ic("database")) "Data and storage" } div.panel-tools { span.faint.small { (mb(st.used)) " of " (cap_mb) " MB" } } }
                        form method="post" action="/settings/storage" {
                            (csrf_input(csrf))
                            div.panel-b {
                                div.row {
                                    label.field { span.lbl { "Keep history (days)" } input type="number" name="retention" value=(retention) min="1" max="3650" required; }
                                    label.field { span.lbl { "Database size cap (MB)" } input type="number" name="max_db_mb" value=(cap_mb) min="32" max="10240" required; }
                                }
                                p.hint { "Rolling window: results older than the retention period, beyond " (grouped(crate::store::HB_CAP)) " per monitor, or above the size cap are deleted oldest first, hourly, in small batches. Nothing grows without bound." }
                                dl.props {
                                    dt { "Stored checks" } dd { (grouped(st.heartbeats)) }
                                    dt { "Incidents" } dd { (grouped(st.incidents)) }
                                    dt { "Oldest check" } dd { @if st.oldest > 0 { (ts(st.oldest)) } @else { "–" } }
                                    dt { "Database" } dd { (mb(st.used)) " live · " (mb(st.file)) " on disk" }
                                }
                            }
                            div.panel-f { button.btn.btn-primary { (ic("check")) "Save" } }
                        }
                    }
                    (crate::metrics::panel(app, csrf, secret))
                }
            }
            div.sg id="sg-connect" {
                h3.sg-t { "Connectivity" }
                div.cols.cols-2 {
                    (crate::tailscale::panel(app, csrf))
                    (crate::tunnel::panel(app, csrf))
                }
            }
            div.sg id="sg-ai" {
                h3.sg-t { "AI" }
                div.cols {
                    (crate::ai::panel(app, csrf))
                }
            }
            div.sg id="sg-about" {
                h3.sg-t { "About" }
                div.cols {
                    section.panel {
                        header.panel-h { h2 { (ic("info")) "Instance" } }
                        div.panel-b { dl.props {
                            dt { "Version" } dd.mono { (VERSION) }
                            dt { "History kept" } dd { (retention) " days" }
                            dt { "Alert channel" } dd { "Webhook and 100+ service types" }
                        } }
                    }
                }
            }
        },
    )
}

pub(crate) fn settings_page(
    csrf: &str,
    flash: Option<(&str, &str)>,
    err: Option<&str>,
    app: &App,
    secret: Option<&str>,
) -> Markup {
    settings_view(csrf, flash, err, app, secret)
}

fn mb(b: i64) -> String {
    format!("{:.1} MB", b as f64 / 1_048_576.0)
}

pub async fn privacy_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    app.db
        .set_setting("alert_privacy", if f.has("lock") { "1" } else { "0" });
    Redirect::to("/settings?m=saved").into_response()
}

pub async fn storage_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let (d, m) = (f.int("retention", 0), f.int("max_db_mb", 0));
    if !(1..=3650).contains(&d) || !(32..=10240).contains(&m) {
        return Redirect::to("/settings?m=storage_bad").into_response();
    }
    app.db.set_setting("retention_days", &d.to_string());
    app.db.set_setting("max_db_mb", &m.to_string());
    Redirect::to("/settings?m=saved").into_response()
}

pub async fn settings_get(State(app): S, a: Auth, Query(q): Q) -> Response {
    page(settings_view(&a.csrf, flash_of(&q), None, &app, None))
}

pub async fn password_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let Some((uid, _, hash)) = app.db.first_user() else {
        return not_found().await;
    };
    let cur = f.get("current").to_string();
    let new = f.get("password").to_string();
    let verified = verify_pw(cur, hash).await;
    let err = if verified.is_none() {
        Some("The server is busy. Try again in a moment.")
    } else if verified != Some(true) {
        Some("Current password is incorrect.")
    } else if new.chars().count() < 10 {
        Some("New password must be at least 10 characters.")
    } else if new.len() > 1024 {
        Some("New password is too long (at most 1024 bytes).")
    } else if new != f.get("confirm") {
        Some("New passwords do not match.")
    } else {
        None
    };
    if let Some(e) = err {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            page(settings_view(&a.csrf, None, Some(e), &app, None)),
        )
            .into_response();
    }
    let h = tokio::task::spawn_blocking(move || hash_password(&new))
        .await
        .unwrap_or_default();
    if h.is_empty() {
        // Never store an empty hash: it would lock the admin out.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            page(settings_view(
                &a.csrf,
                None,
                Some("Could not change the password. Try again."),
                &app,
                None,
            )),
        )
            .into_response();
    }
    app.db.set_password(uid, &h);
    app.db.sessions_clear(Some(&a.token_hash));
    Redirect::to("/settings?m=pw_changed").into_response()
}

pub async fn sessions_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    app.db.sessions_clear(Some(&a.token_hash));
    Redirect::to("/settings?m=sessions").into_response()
}

// ---------------------------------------------------------------- security headers
pub async fn security_headers(
    State(app): S,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    // Status pages bring their own policy (hashes of their inline blocks); everything else gets this one.
    if !h.contains_key("content-security-policy") {
        set(h, "content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    }
    if app.cfg.secure_cookie {
        // Operator declared the panel is served over HTTPS (NDO4_COOKIE_SECURE=1).
        set(
            h,
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        );
    }
    set(h, "x-robots-tag", "noindex, nofollow, noarchive"); // nothing here is meant for search engines
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    );
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    if !h.contains_key(header::CACHE_CONTROL) {
        set(h, "cache-control", "no-store");
    }
    r
}

fn pretty_payload(detail: bool) -> String {
    let raw = crate::sched::payload(
        "down",
        None,
        "HTTP 503 (expected 200-299)",
        None,
        Some((3, 3)),
        detail,
    );
    serde_json::from_str::<serde_json::Value>(&raw)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(raw)
}

// ---------------------------------------------------------------- live stream (SSE)
static STREAMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const MAX_STREAMS: usize = 64;

struct StreamGuard;
impl Drop for StreamGuard {
    fn drop(&mut self) {
        STREAMS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn sse_chunk(event: &str, data: &str) -> Result<axum::body::Bytes, std::convert::Infallible> {
    Ok(axum::body::Bytes::from(format!(
        "event: {event}\ndata: {data}\n\n"
    )))
}

/// Server-sent events: pushes a fresh HTML fragment of the current view whenever data changes
/// (and at least every 10 s so relative times stay accurate). The client swaps it in place.
pub async fn events(State(app): S, a: Auth, Query(q): Q) -> Response {
    use std::hash::{Hash, Hasher};
    let view = q.get("v").cloned().unwrap_or_default();
    let mon_id = view.strip_prefix('m').and_then(|x| x.parse::<i64>().ok());
    if view != "dashboard" && mon_id.is_none() {
        return (StatusCode::BAD_REQUEST, "Unknown view").into_response();
    }
    if STREAMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= MAX_STREAMS {
        STREAMS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "Too many live streams").into_response();
    }
    let guard = StreamGuard;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut sub = app.db.1.subscribe();
    let th = a.token_hash;
    tokio::spawn(async move {
        let _guard = guard;
        let mut last = 0u64;
        loop {
            if app.db.session_get(&th).is_none_or(|(_, e)| e < now()) {
                let _ = tx.send(sse_chunk("auth", "1")).await;
                break;
            }
            let html = match mon_id {
                None => Some(dashboard_body(&app).into_string()),
                Some(id) => app
                    .db
                    .monitor(id)
                    .map(|m| monitor_body(&app, &m).into_string()),
            };
            let Some(html) = html else {
                let _ = tx.send(sse_chunk("gone", "1")).await;
                break;
            };
            let mut h = std::collections::hash_map::DefaultHasher::new();
            html.hash(&mut h);
            let hv = h.finish();
            let chunk = if hv != last {
                last = hv;
                sse_chunk("frag", &serde_json::to_string(&html).unwrap_or_default())
            } else {
                Ok(axum::body::Bytes::from_static(b": ping\n\n"))
            };
            if tx.send(chunk).await.is_err() {
                break;
            }
            tokio::select! {
                r = sub.changed() => {
                    if r.is_err() { break; }
                    // Coalesce bursts (many monitors finishing together) into one update.
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    sub.borrow_and_update();
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                _ = tx.closed() => break,
            }
        }
    });
    (
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

pub async fn tunnel_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let token = f.get("token").trim().to_string();
    if !token.is_empty() {
        if !crate::tunnel::valid_token(&token) {
            return Redirect::to("/settings?m=tunnel_bad").into_response();
        }
        app.db.set_setting("tunnel_token", &token);
    }
    let action = f.get("action");
    if matches!(action, "enable" | "save") {
        app.db.set_setting(
            "cf_auto_update",
            if f.has("auto_update") { "1" } else { "0" },
        );
    }
    let code = match action {
        "enable" | "save" => {
            if app.db.setting("tunnel_token").is_empty() {
                return Redirect::to("/settings?m=tunnel_missing").into_response();
            }
            app.db.set_setting("tunnel_enabled", "1");
            "tunnel_on"
        }
        "check" => {
            let app = app.clone();
            tokio::spawn(async move {
                let _ = crate::tunnel::check(&app).await;
            });
            return Redirect::to("/settings?m=cf_checking").into_response();
        }
        "update" => {
            let app = app.clone();
            tokio::spawn(async move { crate::tunnel::update(&app, false).await });
            return Redirect::to("/settings?m=cf_updating").into_response();
        }
        "disable" => {
            app.db.set_setting("tunnel_enabled", "0");
            "tunnel_off"
        }
        _ => "tunnel_bad",
    };
    app.tunnel_wake.notify_one();
    Redirect::to(&format!("/settings?m={code}")).into_response()
}

pub async fn tailscale_post(State(app): S, a: Auth, f: Form) -> Response {
    use crate::tailscale as ts;
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let action = f.get("action");
    if matches!(action, "enable" | "save") {
        let host = f.get("hostname").trim().to_ascii_lowercase();
        let key = f.get("authkey").trim().to_string();
        if !host.is_empty() && !ts::valid_hostname(&host) {
            return Redirect::to("/settings?m=ts_bad_name").into_response();
        }
        if !key.is_empty() && !ts::valid_key(&key) {
            return Redirect::to("/settings?m=ts_bad_key").into_response();
        }
        if !host.is_empty() {
            app.db.set_setting("ts_hostname", &host);
        }
        if !key.is_empty() {
            app.db.set_setting("ts_authkey", &key);
        }
        let flag = |b: bool| if b { "1" } else { "0" };
        app.db
            .set_setting("ts_accept_routes", flag(f.has("accept_routes")));
        app.db
            .set_setting("ts_accept_dns", flag(f.has("accept_dns")));
        app.db
            .set_setting("ts_auto_update", flag(f.has("auto_update")));
    }
    let code = match action {
        "enable" => {
            app.db.set_setting("ts_enabled", "1");
            app.ts_wake.notify_one();
            "ts_on"
        }
        "save" => {
            app.ts_wake.notify_one(); // re-apply and, if the node is stuck, reconnect now
            "ts_saved"
        }
        "disable" => {
            app.db.set_setting("ts_enabled", "0");
            app.ts_wake.notify_one();
            "ts_off"
        }
        "logout" => match ts::logout(&app).await {
            Ok(()) => "ts_loggedout",
            Err(_) => "ts_logout_fail",
        },
        "check" => {
            let app = app.clone();
            tokio::spawn(async move {
                let _ = ts::check(&app).await;
            });
            "ts_checking"
        }
        "update" => {
            let app = app.clone();
            tokio::spawn(async move { ts::update(&app, false).await });
            "ts_updating"
        }
        _ => "ts_bad_name",
    };
    Redirect::to(&format!("/settings?m={code}")).into_response()
}

pub async fn display_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let tz = f.get("tz").trim().to_string();
    let ok = tz.len() <= 64
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'));
    if !ok {
        return Redirect::to("/settings?m=alerting_bad").into_response();
    }
    let h12 = f.get("h12") == "1";
    app.db.set_setting("tz", &tz);
    app.db.set_setting("h12", if h12 { "1" } else { "0" });
    set_display(&tz, h12);
    Redirect::to("/settings?m=saved").into_response()
}

pub async fn alerting_post(State(app): S, a: Auth, f: Form) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let (n, r) = (f.int("down_after", 0), f.int("recheck", 0));
    if !(1..=10).contains(&n) || !(10..=300).contains(&r) {
        return Redirect::to("/settings?m=alerting_bad").into_response();
    }
    app.db.set_setting("down_after", &n.to_string());
    app.db.set_setting("recheck_s", &r.to_string());
    Redirect::to("/settings?m=saved").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_credentials_in_target_url() {
        let mut m = Monitor::blank();
        m.name = "x".into();
        m.target = "https://user:pass@example.com/".into();
        assert!(validate(&m).is_err());
        m.target = "https://example.com/".into();
        assert!(validate(&m).is_ok());
    }
}
