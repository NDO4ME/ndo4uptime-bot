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
        "logo_bad" => ("err", "Use a PNG, JPEG, WebP or GIF image up to 256 KB (an upload, or a public http(s) link that returns one)."),
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
        "ai_saved" => ("ok", "AI assistant settings saved."),
        "ai_key_saved" => (
            "ok",
            "Groq API key saved, encrypted. It will not be shown again.",
        ),
        "ai_key_removed" => ("ok", "Groq API key removed."),
        "ai_bad_key" => ("err", "That does not look like a Groq API key (gsk_…)."),
        "ai_bad_pw" => (
            "err",
            "Wrong password, or too many attempts. Try again in a few minutes.",
        ),
        "ai_bad_model" => (
            "err",
            "Model names may contain letters, digits and . / _ - : only.",
        ),
        "ai_key_fail" => (
            "err",
            "The key could not be stored: the data directory is not writable.",
        ),
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
        a.nl href=(href) aria-current=[on.then_some("page")] { (ic(icon)) span { (label) } }
    }
}

/// Main navigation, shared by the bar and the phone menu.
fn nav_links(a: &str) -> Markup {
    html! {
        (nav_item("/", "grid", "Dashboard", a == "dashboard"))
        (nav_item("/pages", "globe", "Pages", a == "pages" || a == "maintenance"))
        (nav_item("/settings", "sliders", "Settings", a == "settings" || a == "webhooks"))
    }
}

/// Bar shared by the two halves of the Pages area.
pub fn pages_tabs(active: &str) -> Markup {
    html! {
        nav class="stabs stabs-static" aria-label="Pages sections" {
            a href="/pages" class=(if active == "pages" { "on" } else { "" }) { "Status pages" }
            a href="/maintenance" class=(if active == "maintenance" { "on" } else { "" }) { "Maintenance" }
        }
    }
}

/// Settings section bar. On the Notifications pages every tab is a link back into Settings.
pub fn settings_tabs(away: bool) -> Markup {
    let h = |id: &str| {
        if away {
            format!("/settings#sg-{id}")
        } else {
            format!("#sg-{id}")
        }
    };
    html! {
        nav class=(if away { "stabs stabs-static" } else { "stabs" }) aria-label="Settings sections" {
            @for (id, l) in [("general", "General"), ("security", "Security"), ("alerts", "Alerts")] { a href=(h(id)) { (l) } }
            a href="/webhooks" class=(if away { "on" } else { "" }) { "Notifications" }
            @for (id, l) in [("data", "Data"), ("connect", "Connectivity"), ("ai", "AI"), ("about", "About")] { a href=(h(id)) { (l) } }
        }
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
        (PreEscaped(html_open()))
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="dark light";
                meta name="referrer" content="same-origin";
                meta name="robots" content="noindex, nofollow";
                @if !csrf.is_empty() { meta name="csrf-token" content=(csrf); }
                title { (title) " · NDO4Uptime" }
                link rel="icon" href="/static/favicon.webp" type="image/webp";
                link rel="stylesheet" href=(format!("/static/app.css?v={VERSION}"));
                link rel="stylesheet" href=(format!("/static/ext.css?v={VERSION}"));
                link rel="stylesheet" href=(format!("/static/nav.css?v={VERSION}"));
                script src=(format!("/static/boot.js?v={VERSION}")) {}
                script src=(format!("/static/app.js?v={VERSION}")) defer {}
                script src=(format!("/static/ext.js?v={VERSION}")) defer {}
                script src=(format!("/static/admin.js?v={VERSION}")) defer {}
            }
    }
}

/// The opening `<html>` tag; the document is closed by whoever appends the body (`HTML_END`).
fn html_open() -> String {
    let (tz, h12) = DISPLAY.read().unwrap_or_else(|e| e.into_inner()).clone();
    let tz: String = tz
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'))
        .collect();
    format!(
        "<html lang=\"en\" data-tz=\"{tz}\" data-h12=\"{}\">",
        u8::from(h12)
    )
}

const HTML_END: PreEscaped<&str> = PreEscaped("</html>");

pub fn layout(p: Page, body: Markup) -> Markup {
    let a = p.active;
    html! {
        (head(p.title, p.csrf))
        body {
            a.skip href="#main" { "Skip to content" }
            header.nav {
                div.nav-in {
                    a.nav-brand href="/" aria-label="NDO4Uptime" {
                        img src="/static/logo.webp" width="132" height="29" alt="NDO4Uptime";
                    }
                    nav.nav-links aria-label="Main" { (nav_links(a)) }
                    div.nav-right {
                        span.stream-dot id="live-pill" role="img" aria-label="Receiving live updates" title="Receiving live updates" { i {} }
                        span.conn id="conn" role="status" aria-live="polite" { i {} "Reconnecting…" }
                        a.btn.btn-primary.btn-sm.nav-add href="/monitors/new" { (ic("plus")) span { "Add monitor" } }
                        details.menu {
                            summary.tb-user aria-label="Account menu" {
                                span.tb-avatar aria-hidden="true" { "A" }
                                (ic("chevron-down"))
                            }
                            div.menu-pop {
                                div.menu-head { strong { "Administrator" } span.faint.small { "NDO4Uptime v" (VERSION) } }
                                div.theme-pick role="group" aria-label="Theme" {
                                    button type="button" class="js-theme" data-theme="light" { "Light" }
                                    button type="button" class="js-theme" data-theme="dark" { "Dark" }
                                    button type="button" class="js-theme" data-theme="auto" { "Auto" }
                                }
                                form method="post" action="/logout" {
                                    (csrf_input(p.csrf))
                                    button type="submit" class="menu-item" { (ic("logout")) "Sign out" }
                                }
                            }
                        }
                        details.menu.nav-mob {
                            summary.tb-btn aria-label="Menu" { (ic("menu")) }
                            div.menu-pop { (nav_links(a)) }
                        }
                    }
                }
            }
            main.page id="main" tabindex="-1" data-autorefresh=[p.refresh.then_some("15000")] {
                @if let Some((href, label)) = p.parent { a.back href=(href) { (ic("chevron-left")) (label) } }
                div.ph {
                    div.ph-text { h1 { (p.title) } @if !p.desc.is_empty() { p.ph-desc { (p.desc) } } }
                    div.toolbar { (p.actions) }
                }
                @if let Some((k, t)) = p.flash { div.msgs { (msg(k, t, true)) } }
                @if p.active == "webhooks" { (settings_tabs(true)) }
                @if matches!(p.active, "pages" | "maintenance") && p.parent.is_none() { (pages_tabs(p.active)) }
                (body)
            }
        }
        (HTML_END)
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
        (HTML_END)
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

/// Display settings applied to every admin page: IANA time zone and 12-hour clock.
static DISPLAY: std::sync::RwLock<(String, bool)> = std::sync::RwLock::new((String::new(), false));

pub fn set_display(tz: &str, h12: bool) {
    *DISPLAY.write().unwrap_or_else(|e| e.into_inner()) = (tz.to_string(), h12);
}

/// A timestamp the browser shows in the configured zone (UTC text without JavaScript).
pub fn ts(t: i64) -> Markup {
    html! { time data-ts=(t) { (fmt_ts(t)) } }
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
