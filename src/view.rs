use maud::{html, Markup, PreEscaped, DOCTYPE};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn ic(name: &str) -> Markup {
    // `name` is always a compile-time literal at call sites.
    PreEscaped(format!(
        r#"<svg class="ic" aria-hidden="true"><use href="/static/icons.svg#{name}"></use></svg>"#
    ))
}

pub fn csrf_input(csrf: &str) -> Markup {
    html! { input type="hidden" name="csrf_token" value=(csrf); }
}

pub fn flash_text(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "saved" => ("ok", "Saved."),
        "deleted" => ("ok", "Deleted."),
        "paused" => ("ok", "Monitor paused."),
        "resumed" => ("ok", "Monitor resumed."),
        "checking" => ("ok", "Check queued — results appear within a few seconds."),
        "test_ok" => ("ok", "Test notification delivered."),
        "test_fail" => (
            "err",
            "Test notification failed. See the last result column for details.",
        ),
        "pw_changed" => ("ok", "Password changed. Other sessions were signed out."),
        "sessions" => ("ok", "All other sessions were signed out."),
        "alerting_bad" => (
            "err",
            "Failures must be 1–10 and the re-check interval 10–300 seconds.",
        ),
        "tunnel_on" => (
            "ok",
            "Cloudflare Tunnel enabled. It connects within a few seconds.",
        ),
        "tunnel_off" => ("ok", "Cloudflare Tunnel disabled."),
        "tunnel_bad" => ("err", "That does not look like a Cloudflare tunnel token."),
        "ts_on" => ("ok", "Tailscale enabled. It connects within a few seconds."),
        "ts_off" => ("ok", "Tailscale disabled."),
        "ts_saved" => ("ok", "Tailscale settings saved."),
        "ts_loggedout" => ("ok", "Signed out of Tailscale and disabled."),
        "ts_logout_fail" => ("err", "Could not sign out. Is Tailscale running?"),
        "ts_checking" => ("ok", "Checking for updates — reload in a few seconds."),
        "ts_updating" => (
            "ok",
            "Updating Tailscale in the background — reload to follow the result.",
        ),
        "ts_bad_name" => (
            "err",
            "The device name may only use lowercase letters, digits and hyphens.",
        ),
        "ts_bad_key" => (
            "err",
            "That does not look like a Tailscale auth key (tskey-…).",
        ),
        "limit" => ("err", "Too many entries."),
        "logo_bad" => ("err", "Upload a PNG, JPEG, WebP or GIF image up to 256 KB."),
        "muted" => (
            "ok",
            "Monitor muted. It is still checked and shown, but sends no webhooks.",
        ),
        "unmuted" => ("ok", "Monitor unmuted."),
        "storage_bad" => (
            "err",
            "Retention must be 1–3650 days and the size cap 32–10240 MB.",
        ),
        "metrics_on" => (
            "ok",
            "Metrics enabled. Copy the token now — it is shown only once.",
        ),
        "metrics_off" => ("ok", "Metrics disabled."),
        "tunnel_missing" => ("err", "Paste a tunnel token first."),
        _ => return None,
    })
}

pub fn msg(kind: &str, text: &str, close: bool) -> Markup {
    let icon = match kind {
        "ok" => "check-circle",
        "err" => "x-circle",
        "warn" => "alert",
        _ => "info",
    };
    html! {
        div class=(format!("msg msg-{kind}")) role=(if kind == "err" { "alert" } else { "status" }) {
            (ic(icon)) div.msg-body { (text) }
            @if close { button type="button" class="btn btn-ghost btn-icon btn-sm msg-close js-dismiss" aria-label="Dismiss" { (ic("x")) } }
        }
    }
}

fn nav_item(href: &str, icon: &str, label: &str, on: bool) -> Markup {
    html! {
        a.sb-item href=(href) data-label=(label) aria-current=[on.then_some("page")] { (ic(icon)) span { (label) } }
    }
}

pub struct Page<'a> {
    pub title: &'a str,
    pub desc: &'a str,
    pub active: &'a str,
    pub csrf: &'a str,
    pub flash: Option<(&'a str, &'a str)>,
    pub parent: Option<(&'a str, &'a str)>,
    pub actions: Markup,
    pub refresh: bool,
}

pub fn head(title: &str, csrf: &str) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="dark";
                meta name="referrer" content="same-origin";
                meta name="robots" content="noindex, nofollow";
                @if !csrf.is_empty() { meta name="csrf-token" content=(csrf); }
                title { (title) " · NDO4Uptime" }
                link rel="icon" href="/static/favicon.webp" type="image/webp";
                link rel="stylesheet" href=(format!("/static/app.css?v={VERSION}"));
                link rel="stylesheet" href=(format!("/static/ext.css?v={VERSION}"));
                script src=(format!("/static/boot.js?v={VERSION}")) {}
                script src=(format!("/static/app.js?v={VERSION}")) defer {}
                script src=(format!("/static/ext.js?v={VERSION}")) defer {}
            }
        }
    }
}

pub fn layout(p: Page, body: Markup) -> Markup {
    let a = p.active;
    html! {
        (head(p.title, p.csrf))
        body {
            a.skip href="#main" { "Skip to content" }
            div.app {
                aside.sb id="sidebar" aria-label="Sidebar" {
                    a.sb-brand href="/" aria-label="NDO4Uptime" data-label="NDO4Uptime" {
                        img.sb-logo-full src="/static/logo.webp" width="168" height="37" alt="NDO4Uptime";
                        img.sb-logo-mark src="/static/logo-mark.webp" width="36" height="21" alt="";
                    }
                    nav.sb-nav aria-label="Main" {
                        (nav_item("/", "grid", "Dashboard", a == "dashboard"))
                        div.sb-group { "Monitoring" }
                        (nav_item("/monitors/new", "plus", "New monitor", a == "new"))
                        (nav_item("/pages", "layers", "Status pages", a == "pages"))
                        (nav_item("/maintenance", "tool", "Maintenance", a == "maintenance"))
                        (nav_item("/webhooks", "bell", "Webhooks", a == "webhooks"))
                        div.sb-group { "Panel" }
                        (nav_item("/settings", "sliders", "Settings", a == "settings"))
                    }
                    div.sb-foot {
                        span.sb-ver { "v" (VERSION) }
                        button type="button" class="sb-collapse js-sb-collapse" aria-label="Collapse sidebar" title="Collapse sidebar" { (ic("chevrons-left")) }
                    }
                }
                div.scrim aria-hidden="true" {}
                div.main {
                    header.tb {
                        button type="button" class="tb-btn tb-menu js-sb-toggle" aria-label="Open menu" { (ic("menu")) }
                        nav.crumbs aria-label="Breadcrumb" {
                            @if let Some((href, label)) = p.parent { a href=(href) { (label) } span.crumb-sep { "/" } }
                            span aria-current="page" { (p.title) }
                        }
                        div.tb-right {
                            span.stream-dot id="live-pill" role="img" aria-label="Receiving live updates" title="Receiving live updates" { i {} }
                            span.conn id="conn" role="status" aria-live="polite" { i {} "Reconnecting…" }
                            details.menu {
                                summary.tb-user aria-label="Account menu" {
                                    span.tb-avatar aria-hidden="true" { "A" }
                                    span.hide-sm { "Administrator" }
                                    (ic("chevron-down"))
                                }
                                div.menu-pop {
                                    form method="post" action="/logout" {
                                        (csrf_input(p.csrf))
                                        button type="submit" class="menu-item" { (ic("logout")) "Sign out" }
                                    }
                                }
                            }
                        }
                    }
                    main.page id="main" tabindex="-1" data-autorefresh=[p.refresh.then_some("15000")] {
                        div.ph {
                            div.ph-text { h1 { (p.title) } p.ph-desc { (p.desc) } }
                            div.toolbar { (p.actions) }
                        }
                        @if let Some((k, t)) = p.flash { div.msgs { (msg(k, t, true)) } }
                        (body)
                    }
                }
            }
        }
    }
}

pub fn auth_page(title: &str, desc: &str, error: Option<&str>, form: Markup, foot: &str) -> Markup {
    html! {
        (head(title, ""))
        body {
            main.auth {
                div.auth-wrap {
                    div.auth-card {
                        div.auth-brand { img.brand-img src="/static/logo.webp" width="270" height="59" alt="NDO4Uptime"; }
                        h1 { (title) }
                        p.ph-desc { (desc) }
                        @if let Some(e) = error { (msg("err", e, false)) }
                        (form)
                        div.auth-foot { (foot) }
                    }
                    div.auth-meta { (ic("lock")) " Sessions are HttpOnly + SameSite=Strict · failed sign-ins are rate-limited" }
                }
            }
        }
    }
}

pub fn status_badge(enabled: bool, status: i64) -> Markup {
    let (c, t) = if !enabled {
        ("warning", "paused")
    } else {
        match status {
            1 => ("success", "up"),
            2 => ("failed", "down"),
            _ => ("info", "pending"),
        }
    };
    html! { span class=(format!("badge {c}")) { (t) } }
}

/// Like `status_badge`, with a blue "maintenance" state for monitors inside a maintenance window.
pub fn state_badge(enabled: bool, status: i64, maint: bool) -> Markup {
    if maint {
        html! { span class="badge maint" title="Inside a maintenance window: checks run but nothing alerts" { "maintenance" } }
    } else {
        status_badge(enabled, status)
    }
}

/// "45s", "12m", "2h 5m", "3d 4h".
pub fn dur(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86399 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h", s / 86400, s % 86400 / 3600),
    }
}

/// Admin-side status: a failing monitor that is not yet confirmed DOWN shows as yellow "n/N".
pub fn live_badge(m: &crate::db::Monitor, threshold: i64) -> Markup {
    if m.enabled && m.status != 2 && m.fails > 0 {
        html! { span class="badge warning" title="Failed check, not yet confirmed as down" { "checking " (m.fails) "/" (threshold) } }
    } else {
        status_badge(m.enabled, m.status)
    }
}

pub fn kind_label(k: &str) -> &'static str {
    match k {
        "http" => "HTTP(s)",
        "browser" => "Browser",
        "tcp" => "TCP port",
        "ping" => "Ping (ICMP)",
        _ => "?",
    }
}

pub fn ago(ts: i64) -> String {
    if ts <= 0 {
        return "never".into();
    }
    let d = (crate::db::now() - ts).max(0);
    match d {
        0..=4 => "just now".into(),
        5..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

pub fn fmt_ts(t: i64) -> String {
    let days = t.div_euclid(86400);
    let s = t.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

/// Compact count for tiles: 999, 1.2K, 34M, 5.6B, 7.8T. Never wider than ~6 characters.
pub fn compact(n: i64) -> String {
    let n = n.max(0) as f64;
    for (div, unit) in [(1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "K")] {
        if n >= div {
            let v = n / div;
            return if v < 10.0 {
                format!("{v:.1}{unit}")
            } else {
                format!("{}{unit}", v.floor() as i64)
            };
        }
    }
    format!("{}", n as i64)
}

/// Full number with thousands separators, for tooltips.
pub fn grouped(n: i64) -> String {
    let d = n.max(0).to_string();
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn pct(p: Option<f64>) -> String {
    match p {
        None => "–".into(),
        Some(v) if v >= 99.995 => "100%".into(),
        Some(v) => format!("{v:.2}%"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn compact_counts() {
        assert_eq!(super::compact(999), "999");
        assert_eq!(super::compact(1234), "1.2K");
        assert_eq!(super::compact(34_500_000), "34M");
        assert_eq!(super::compact(5_600_000_000), "5.6B");
        assert_eq!(super::grouped(1234567), "1,234,567");
    }
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_ts(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn percentages() {
        assert_eq!(pct(None), "–");
        assert_eq!(pct(Some(100.0)), "100%");
        assert_eq!(pct(Some(99.5)), "99.50%");
    }
}
