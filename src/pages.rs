//! Status pages: public, read-only views of a chosen set of monitors, grouped as the owner wishes.
//!
//! Public pages deliberately expose only names, groups, state, uptime and up/down history —
//! never targets, URLs, error messages or any configuration. They are served without
//! authentication or cookies, on the admin listener at `/s/{slug}` and on a separate public
//! listener (the only one a tunnel or reverse proxy should ever point at), where a page can
//! also own a custom domain.

use crate::auth::*;
use crate::db::{now, StatusPage};
use crate::view::*;
use crate::web::{bad_csrf, flash_of, not_found, page};
use crate::App;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{html, Markup, DOCTYPE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

type S = State<Arc<App>>;
type Q = Query<HashMap<String, String>>;

// ---------------------------------------------------------------- validation
fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(40).collect()
}

fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=40).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
        && !d.split('.').all(|l| l.bytes().all(|c| c.is_ascii_digit())) // not an IPv4 address
}

fn clean_group(g: &str) -> Option<String> {
    let g = g.trim();
    (g.chars().count() <= 60 && !g.chars().any(char::is_control)).then(|| g.to_string())
}

fn parse_page(f: &Form, id: i64, valid_ids: &[i64]) -> Result<StatusPage, String> {
    let title = f.get("title").trim().to_string();
    if title.is_empty() || title.chars().count() > 80 || title.chars().any(char::is_control) {
        return Err("Title is required (max 80 characters).".into());
    }
    let mut slug = f.get("slug").trim().to_lowercase();
    if slug.is_empty() {
        slug = slugify(&title);
    }
    if !valid_slug(&slug) {
        return Err("Address may contain lowercase letters, digits and dashes (max 40).".into());
    }
    let description = f.get("description").replace('\r', "").trim().to_string();
    if description.chars().count() > 500 {
        return Err("Description is limited to 500 characters.".into());
    }
    let domain = f.get("domain").trim().trim_end_matches('.').to_lowercase();
    if !domain.is_empty() && !valid_domain(&domain) {
        return Err("Custom domain must be a hostname such as status.example.com.".into());
    }
    let mut items = Vec::new();
    for v in f.all("m") {
        let Ok(mid) = v.parse::<i64>() else { continue };
        if !valid_ids.contains(&mid) {
            continue;
        }
        let g = clean_group(f.get(&format!("g{mid}")))
            .ok_or("Group names are limited to 60 characters.")?;
        items.push((mid, g));
    }
    let brand = f.get("brand").trim().to_string();
    if brand.chars().count() > 80 || brand.chars().any(char::is_control) {
        return Err("Brand name is limited to 80 characters.".into());
    }
    let accent = f.get("accent").trim().to_lowercase();
    if !accent.is_empty() && !valid_hex(&accent) {
        return Err("Accent colour must look like #2a8fdc.".into());
    }
    let theme = match f.get("theme") {
        t @ ("light" | "auto") => t.to_string(),
        _ => "dark".to_string(),
    };
    let footer = f.get("footer").trim().to_string();
    if footer.chars().count() > 200 || footer.chars().any(char::is_control) {
        return Err("Footer text is limited to 200 characters.".into());
    }
    let links = clean_links(f.get("links"))?;
    Ok(StatusPage {
        id,
        slug,
        title,
        description,
        domain,
        enabled: f.has("enabled"),
        brand,
        accent,
        theme,
        footer,
        hide_powered: f.has("hide_powered"),
        links,
        show_history: f.has("show_history"),
        noindex: f.has("noindex"),
        logo_ts: 0,
        items,
    })
}

fn valid_hex(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// "Label | https://example.com" per line, at most four, http(s) only.
fn clean_links(text: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let bad = || "Links use the form: Label | https://example.com (max 4).".to_string();
        let (label, url) = line.split_once('|').ok_or_else(bad)?;
        let (label, url) = (label.trim(), url.trim());
        let ok = reqwest::Url::parse(url)
            .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .unwrap_or(false);
        if label.is_empty()
            || label.chars().count() > 30
            || label.chars().any(char::is_control)
            || !ok
            || url.len() > 300
        {
            return Err(bad());
        }
        out.push(format!("{label} | {url}"));
    }
    if out.len() > 4 {
        return Err("At most four links.".into());
    }
    Ok(out.join("\n"))
}

fn link_list(text: &str) -> Vec<(&str, &str)> {
    text.lines().filter_map(|l| l.split_once(" | ")).collect()
}

/// Accent colour variants for the per-page stylesheet.
fn accent_css(hex: &str, theme: &str) -> String {
    let ch = |i: usize| i64::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0);
    let (r, g, b) = (ch(1), ch(3), ch(5));
    let mix = |v: i64, to: i64, pct: i64| (v + (to - v) * pct / 100).clamp(0, 255);
    let rgb = |a: i64, b2: i64| {
        format!(
            "#{:02x}{:02x}{:02x}",
            mix(r, a, b2),
            mix(g, a, b2),
            mix(b, a, b2)
        )
    };
    // Links and badges use a text variant: darker on light surfaces so contrast holds.
    let text = match theme {
        "light" => rgb(0, 35),
        "auto" => hex.to_string(),
        _ => rgb(255, 10),
    };
    format!(
        "html.pub{{--primary:{hex};--primary-hover:{};--primary-press:{};--primary-soft:rgba({r},{g},{b},.14);--info-text:{text};}}\n",
        rgb(255, 18),
        rgb(0, 15),
    )
}

// ---------------------------------------------------------------- admin: list & form
pub async fn pages_get(State(app): S, a: Auth, Query(q): Q) -> Response {
    let pages = app.db.pages();
    let body = html! {
        section.panel {
            header.panel-h { h2 { (ic("layers")) "Status pages" } div.panel-tools { span.faint.small { (pages.len()) " total" } } }
            @if pages.is_empty() {
                div.empty-state { (ic("layers")) "No status pages yet. Publish a selection of monitors, grouped your way, on a page you can share." br; br;
                    a.btn.btn-primary href="/pages/new" { (ic("plus")) "New page" } }
            } @else {
                div.tbl-wrap { table.tbl {
                    thead { tr { th { "Status" } th { "Page" } th { "Address" } th.num { "Monitors" } th {} } }
                    tbody { @for p in &pages { tr {
                        td { span class=(if p.enabled { "badge success" } else { "badge warning" }) { (if p.enabled { "published" } else { "hidden" }) } }
                        td { div.mon-n { a href=(format!("/pages/{}/edit", p.id)) { (p.title) } small { (p.items.len()) " monitors in " (group_count(p)) " groups" } } }
                        td { div.mon-n { a.mono href=(format!("/s/{}", p.slug)) { "/s/" (p.slug) } @if !p.domain.is_empty() { small.mono { (p.domain) } } } }
                        td.num { (p.items.len()) }
                        td.actions-cell {
                            a.btn.btn-sm.btn-ghost href=(format!("/s/{}", p.slug)) target="_blank" rel="noopener" { (ic("external")) "View" }
                            a.btn.btn-sm.btn-ghost href=(format!("/pages/{}/edit", p.id)) { (ic("edit")) "Edit" }
                        }
                    } } }
                } }
            }
        }
    };
    page(layout(
        Page {
            title: "Status pages",
            desc: "Public pages that show the monitors you choose, grouped your way.",
            active: "pages",
            csrf: &a.csrf,
            flash: flash_of(&q),
            parent: None,
            refresh: false,
            actions: html! { a.btn.btn-primary href="/pages/new" { (ic("plus")) "New page" } },
        },
        body,
    ))
}

fn group_count(p: &StatusPage) -> usize {
    let mut g: Vec<&str> = p.items.iter().map(|(_, g)| g.as_str()).collect();
    g.sort_unstable();
    g.dedup();
    g.len()
}

fn page_form(app: &App, p: &StatusPage, csrf: &str, err: Option<&str>) -> Markup {
    let mons = app.db.monitors();
    let mut groups: Vec<String> = mons
        .iter()
        .map(|m| m.grp.clone())
        .chain(
            app.db
                .pages()
                .into_iter()
                .flat_map(|x| x.items.into_iter().map(|i| i.1)),
        )
        .filter(|g| !g.is_empty())
        .collect();
    groups.sort_by_key(|g| g.to_lowercase());
    groups.dedup();
    let action = if p.id > 0 {
        format!("/pages/{}/edit", p.id)
    } else {
        "/pages".to_string()
    };
    html! {
        @if let Some(e) = err { div.msgs { (msg("err", e, false)) } }
        form method="post" action=(action) autocomplete="off" {
            (csrf_input(csrf))
            div.cols.cols-main {
                div.stack {
                    section.panel {
                        header.panel-h { h2 { (ic("list")) "Monitors & groups" } }
                        @if mons.is_empty() {
                            div.panel-b { p.hint { "Create a monitor first, then add it to a page." } }
                        } @else {
                            div.tbl-wrap { table.tbl {
                                thead { tr { th { "Show" } th { "Monitor" } th { "Group on this page" } } }
                                tbody { @for m in &mons {
                                    @let cur = p.items.iter().find(|(id, _)| *id == m.id);
                                    @let on = cur.is_some();
                                    @let g = cur.map(|c| c.1.as_str()).unwrap_or(if p.id > 0 { "" } else { m.grp.as_str() });
                                    tr {
                                        td { input type="checkbox" name="m" value=(m.id) checked[on] aria-label=(format!("Show {}", m.name)); }
                                        td { div.mon-n { (m.name) small { (kind_label(&m.kind)) } } }
                                        td { input name=(format!("g{}", m.id)) value=(g) list="groups" maxlength="60" placeholder="No group" aria-label=(format!("Group for {}", m.name)); }
                                    }
                                } }
                            } }
                            datalist id="groups" { @for g in &groups { option value=(g) {} } }
                            div.panel-f { span.hint { "Monitors sharing a group name are shown together. Leave blank for no group." } }
                        }
                    }
                }
                div.stack {
                    section.panel {
                        header.panel-h { h2 { (ic("layers")) "Page" } }
                        div.panel-b {
                            label.field { span.lbl { "Title" } input name="title" value=(p.title) required maxlength="80" placeholder="Acme status"; }
                            label.field { span.lbl { "Address" } input name="slug" value=(p.slug) maxlength="40" spellcheck="false" placeholder="acme"; span.hint { "Served at " code { "/s/<address>" } ". Leave empty to derive it from the title." } }
                            label.field { span.lbl { "Description (optional)" } textarea name="description" rows="3" maxlength="500" { (p.description) } }
                            label.field { span.lbl { "Custom domain (optional)" } input name="domain" value=(p.domain) maxlength="253" spellcheck="false" placeholder="status.example.com";
                                span.hint { "Matched against the Host header on the public listener (see Settings → Cloudflare Tunnel). The page is then served at the domain root." } }
                            label.check { input type="checkbox" name="enabled" value="1" checked[p.enabled || p.id == 0]; span { "Published" span.hint { "Hidden pages answer 404." } } }
                        }
                    }
                    section.panel {
                        header.panel-h { h2 { (ic("eye")) "Appearance" } }
                        div.panel-b {
                            label.field { span.lbl { "Brand name (optional)" } input name="brand" value=(p.brand) maxlength="80" placeholder=(p.title); span.hint { "Shown as the page heading and browser title instead of the title above." } }
                            div.row {
                                label.field { span.lbl { "Theme" }
                                    select name="theme" {
                                        option value="dark" selected[p.theme != "light" && p.theme != "auto"] { "Dark" }
                                        option value="light" selected[p.theme == "light"] { "Light" }
                                        option value="auto" selected[p.theme == "auto"] { "Match the visitor's system" }
                                    } }
                                label.field { span.lbl { "Accent colour" } input name="accent" value=(p.accent) maxlength="7" spellcheck="false" placeholder="#2a8fdc" pattern="#[0-9a-fA-F]{6}"; }
                            }
                            label.field { span.lbl { "Links (optional)" } textarea name="links" rows="3" maxlength="1200" spellcheck="false" placeholder="Website | https://example.com\nSupport | https://example.com/help" { (p.links) }
                                span.hint { "Up to four, one per line as " code { "Label | https://…" } ". Shown in the page header." } }
                            label.field { span.lbl { "Footer text (optional)" } input name="footer" value=(p.footer) maxlength="200" placeholder="© Acme Inc."; }
                            label.check { input type="checkbox" name="show_history" value="1" checked[p.show_history]; span { "Show incident history" span.hint { "Lists recent outages of the monitors on this page (name, time, duration). No error details are published." } } }
                            label.check { input type="checkbox" name="hide_powered" value="1" checked[p.hide_powered]; span { "Hide “Powered by NDO4Uptime”" span.hint { "White-label: remove the attribution line." } } }
                            label.check { input type="checkbox" name="noindex" value="1" checked[p.noindex]; span { "Ask search engines not to index this page" } }
                        }
                    }
                }
            }
            div.form-actions { button type="submit" class="btn btn-primary" { (ic("check")) "Save page" } " " a.btn href="/pages" { "Cancel" } }
        }
        @if p.id > 0 {
            section.panel {
                header.panel-h { h2 { (ic("upload")) "Logo" } }
                div.panel-b {
                    @if let Some((m, b)) = app.db.page_logo(&p.slug).filter(|_| p.logo_ts > 0) { p { img.sp-logo src=(data_uri(&m, &b)) alt="Current logo"; } }
                    form method="post" action=(format!("/pages/{}/logo", p.id)) enctype="multipart/form-data" {
                        (csrf_input(csrf))
                        label.field { span.lbl { "Upload a logo" } input type="file" name="logo" accept="image/png,image/jpeg,image/webp,image/gif" required;
                            span.hint { "PNG, JPEG, WebP or GIF up to 256 KB. Also used as the page icon." } }
                        button.btn.btn-primary { (ic("upload")) "Upload" }
                    }
                }
                @if p.logo_ts > 0 {
                    div.panel-f {
                        form method="post" action=(format!("/pages/{}/logo-remove", p.id)) { (csrf_input(csrf)) button.btn { (ic("trash")) "Remove logo" } }
                    }
                }
            }
        }
    }
}

fn form_page(
    app: &App,
    a: &Auth,
    p: &StatusPage,
    title: &'static str,
    err: Option<&str>,
) -> Markup {
    layout(
        Page {
            title,
            desc: "Choose what is public and how it is grouped.",
            active: "pages",
            csrf: &a.csrf,
            flash: None,
            parent: Some(("/pages", "Status pages")),
            refresh: false,
            actions: html! {},
        },
        page_form(app, p, &a.csrf, err),
    )
}

pub async fn page_new(State(app): S, a: Auth) -> Response {
    let p = StatusPage {
        enabled: true,
        show_history: true,
        noindex: true,
        theme: "dark".into(),
        ..Default::default()
    };
    page(form_page(&app, &a, &p, "New page", None))
}

pub async fn page_edit_get(State(app): S, a: Auth, Path(id): Path<i64>) -> Response {
    let Some(p) = app.db.page(id) else {
        return not_found().await;
    };
    page(form_page(&app, &a, &p, "Edit page", None))
}

async fn save(app: Arc<App>, a: Auth, f: Form, id: i64) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    let ids: Vec<i64> = app.db.monitors().iter().map(|m| m.id).collect();
    let title = if id > 0 { "Edit page" } else { "New page" };
    let fail = |p: StatusPage, e: &str| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            page(form_page(&app, &a, &p, title, Some(e))),
        )
            .into_response()
    };
    match parse_page(&f, id, &ids) {
        Err(e) => {
            let mut p = StatusPage {
                id,
                enabled: f.has("enabled"),
                ..Default::default()
            };
            p.title = f.get("title").into();
            p.slug = f.get("slug").into();
            p.description = f.get("description").into();
            p.domain = f.get("domain").into();
            p.brand = f.get("brand").into();
            p.accent = f.get("accent").into();
            p.theme = f.get("theme").into();
            p.footer = f.get("footer").into();
            p.links = f.get("links").into();
            p.hide_powered = f.has("hide_powered");
            p.show_history = f.has("show_history");
            p.noindex = f.has("noindex");
            p.logo_ts = app.db.page(id).map_or(0, |x| x.logo_ts);
            fail(p, &e)
        }
        Ok(p) => match app.db.save_page(&p) {
            Ok(_) => Redirect::to("/pages?m=saved").into_response(),
            Err(e) => fail(p, e),
        },
    }
}

pub async fn page_create(State(app): S, a: Auth, f: Form) -> Response {
    if app.db.pages().len() >= 50 {
        return Redirect::to("/pages?m=limit").into_response();
    }
    save(app, a, f, 0).await
}
pub async fn page_edit_post(State(app): S, a: Auth, Path(id): Path<i64>, f: Form) -> Response {
    if app.db.page(id).is_none() {
        return not_found().await;
    }
    save(app, a, f, id).await
}

pub async fn page_action(
    State(app): S,
    a: Auth,
    Path((id, act)): Path<(i64, String)>,
    f: Form,
) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.page(id).is_none() {
        return not_found().await;
    }
    match act.as_str() {
        "delete" => {
            app.db.delete_page(id);
            Redirect::to("/pages?m=deleted").into_response()
        }
        "toggle" => {
            app.db.toggle_page(id);
            Redirect::to("/pages?m=saved").into_response()
        }
        "logo-remove" => {
            app.db.set_page_logo(id, None);
            Redirect::to(&format!("/pages/{id}/edit?m=saved")).into_response()
        }
        _ => not_found().await,
    }
}

// ---------------------------------------------------------------- public rendering
fn pub_bar(app: &App, mid: i64) -> Markup {
    let mut beats = app.db.beats(mid, 40);
    beats.reverse();
    let pad = 40usize.saturating_sub(beats.len());
    html! {
        div.hbar aria-hidden="true" {
            @for _ in 0..pad { i {} }
            @for b in &beats { i class=(if b.maint { "maint" } else if b.ok { "up" } else if b.soft { "warn" } else { "down" }) title=(fmt_ts(b.ts)) {} }
        }
    }
}

fn when(ts: i64) -> Markup {
    html! { time data-ts=(ts) { (fmt_ts(ts)) } }
}

/// The part of a status page that changes: banner, maintenance notices, grouped monitors, history.
fn status_body(app: &App, p: &StatusPage) -> Markup {
    let t = now();
    // Groups are the ones chosen for this page ("Group on this page"), not the monitor's own group.
    let mut groups: BTreeMap<(bool, String), (String, Vec<crate::db::Monitor>)> = BTreeMap::new();
    for (mid, g) in &p.items {
        if let Some(m) = app.db.monitor(*mid) {
            groups
                .entry((!g.is_empty(), g.to_lowercase()))
                .or_insert_with(|| (g.clone(), vec![]))
                .1
                .push(m);
        }
    }
    let all: Vec<&crate::db::Monitor> = groups
        .values()
        .flat_map(|g| g.1.iter())
        .filter(|m| m.enabled)
        .collect();
    let in_maint = |m: &crate::db::Monitor| app.db.in_maintenance(m.id).is_some();
    let maint_n = all.iter().filter(|m| in_maint(m)).count();
    let live: Vec<&&crate::db::Monitor> = all.iter().filter(|m| !in_maint(m)).collect();
    let down = live.iter().filter(|m| m.status == 2).count();
    let pending = live.iter().filter(|m| m.status == 0).count();
    let (cls, icon, text) = if all.is_empty() {
        ("info", "info", "No monitors to show")
    } else if live.is_empty() {
        ("maint", "tool", "Under maintenance")
    } else if down == live.len() {
        ("err", "x-circle", "Major outage")
    } else if down > 0 {
        ("warn", "alert", "Partial outage")
    } else if pending == live.len() {
        ("info", "clock", "Checking…")
    } else if maint_n > 0 {
        ("ok", "check-circle", "All other systems operational")
    } else {
        ("ok", "check-circle", "All systems operational")
    };
    // Public maintenance announcements, limited to windows that touch monitors on this page.
    let names = |m: &crate::store::Maint| -> Vec<String> {
        groups
            .values()
            .flat_map(|g| g.1.iter())
            .filter(|x| m.applies(x.id))
            .map(|x| x.name.clone())
            .collect()
    };
    let maints = app.db.maints();
    let notices: Vec<(&crate::store::Maint, (i64, i64), bool)> = maints
        .iter()
        .filter(|m| m.public && m.enabled)
        .filter_map(|m| {
            if m.active(t) {
                m.window(t).map(|w| (m, w, true))
            } else {
                m.upcoming(t, 7 * 86400).map(|w| (m, w, false))
            }
        })
        .filter(|(m, _, _)| !names(m).is_empty())
        .collect();
    let mids: Vec<i64> = p.items.iter().map(|i| i.0).collect();
    // AI-drafted neutral statements for monitors on this page that are down right now.
    let updates: Vec<_> = app
        .db
        .ai_updates(&mids)
        .into_iter()
        .filter(|i| {
            p.items.iter().any(|it| it.0 == i.mid) && !app.db.in_maintenance(i.mid).is_some()
        })
        .collect();
    let history = if p.show_history {
        app.db.incidents_for(&mids, t - 90 * 86400, 40)
    } else {
        vec![]
    };
    html! {
        div class=(format!("sp-banner sp-{cls}")) role="status" { (ic(icon)) span { (text) } }
        @for (m, (s, e), active) in &notices {
            div class=(if *active { "sp-notice sp-notice-on" } else { "sp-notice" }) {
                div.sp-notice-h { (ic("tool")) b { (m.title) } span class=(if *active { "badge info" } else { "badge warning" }) { (if *active { "in progress" } else { "scheduled" }) } }
                @if !m.message.is_empty() { p { (m.message) } }
                p.faint.small { (when(*s)) " – " (when(*e)) @if m.repeat_days > 0 { " · repeats " (if m.repeat_days == 1 { "daily".to_string() } else if m.repeat_days == 7 { "weekly".to_string() } else { format!("every {} days", m.repeat_days) }) } }
                p.faint.small { "Affects: " (names(m).join(", ")) }
            }
        }
        @for u in &updates {
            div class="sp-notice sp-notice-on" {
                div.sp-notice-h { (ic("alert")) b { "Incident update: " (u.name) } span.badge.failed { "investigating" } }
                p { (u.ai_public) }
                p.faint.small { "Since " (when(u.started)) " · automatically drafted, reviewed by our team" }
            }
        }
        @for ((named, _), (label, ms)) in &groups {
            @let label = if *named { label.as_str() } else { "" };
            @let gd = ms.iter().filter(|m| m.enabled && m.status == 2 && !in_maint(m)).count();
            section.panel {
                @if *named || groups.len() > 1 {
                    header.panel-h { h2 { (if *named { label } else { "Other" }) }
                        div.panel-tools { span class=(if gd == 0 { "badge success" } else { "badge failed" }) { (if gd == 0 { "operational" } else { "issues" }) } } }
                }
                div.tbl-wrap { table.tbl.sp-tbl {
                    thead { tr { th { "Status" } th { "Monitor" } th { "Last 40 checks" } th.num { "24h" } th.num { "30d" } } }
                    tbody { @for m in ms { tr {
                        td { (state_badge(m.enabled, m.status, m.enabled && in_maint(m))) }
                        td { (m.name) }
                        td { (pub_bar(app, m.id)) }
                        td.num { (pct(app.db.stats(m.id, t - 86400).pct())) }
                        td.num { (pct(app.db.stats(m.id, t - 30 * 86400).pct())) }
                    } } }
                } }
            }
        }
        @if p.show_history {
            section.panel {
                header.panel-h { h2 { (ic("clock")) "Incident history" } div.panel-tools { span.faint.small { "last 90 days" } } }
                @if history.is_empty() {
                    div.panel-b { p.hint { "No incidents in the last 90 days." } }
                } @else {
                    div.tbl-wrap { table.tbl.sp-tbl {
                        thead { tr { th { "When" } th { "Monitor" } th { "Outage" } th.num { "Duration" } } }
                        tbody { @for i in &history { tr {
                            td { (when(i.started)) }
                            td { (i.name) }
                            td { @if i.ended == 0 { span class="badge failed" { "ongoing" } } @else { span class="badge success" { "resolved" } } }
                            td.num { (dur(if i.ended == 0 { t - i.started } else { i.ended - i.started })) }
                        } } }
                    } }
                }
            }
        }
    }
}

type Cache = std::sync::Mutex<HashMap<i64, (u64, std::time::Instant, Arc<String>)>>;
static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();

/// Rendered fragment, shared by every viewer: one render per data change (or 30 s), not per request.
fn fragment(app: &App, p: &StatusPage) -> Arc<String> {
    let ver = *app.db.1.borrow();
    let mut c = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some((v, at, html)) = c.get(&p.id) {
        if *v == ver && at.elapsed().as_secs() < 30 {
            return html.clone();
        }
    }
    // Icons come from the sprite embedded in the page itself: no extra request.
    let html = Arc::new(
        status_body(app, p)
            .into_string()
            .replace("href=\"/static/icons.svg#", "href=\"#"),
    );
    c.retain(|_, (_, at, _)| at.elapsed().as_secs() < 300);
    c.insert(p.id, (ver, std::time::Instant::now(), html.clone()));
    html
}

/// Everything a status page needs, built once: the page is a single self-contained document and
/// the only request it ever makes afterwards is the live event stream.
struct PubAssets {
    css: String,
    js: String,
    sprite: String,
    favicon: String,
}

fn data_uri(mime: &str, bytes: &[u8]) -> String {
    use base64::Engine;
    format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

fn pub_assets() -> &'static PubAssets {
    static A: std::sync::OnceLock<PubAssets> = std::sync::OnceLock::new();
    A.get_or_init(|| {
        let font = data_uri(
            "font/woff2",
            include_bytes!("../static/fonts/Inter-latin.woff2"),
        );
        let app_css = include_str!("../static/app.css")
            .replace("/static/fonts/Inter-latin.woff2", &font);
        let sprite = include_str!("../static/icons.svg").replacen(
            "<svg xmlns=\"http://www.w3.org/2000/svg\">",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" class=\"sprite\" width=\"0\" height=\"0\" aria-hidden=\"true\" focusable=\"false\">",
            1,
        );
        PubAssets {
            css: format!("{app_css}\n{}", include_str!("../static/ext.css")),
            js: include_str!("../static/ext.js").to_string(),
            sprite,
            favicon: data_uri("image/webp", include_bytes!("../static/favicon.webp")),
        }
    })
}

/// CSP source for one inline block.
fn csp_hash(text: &str) -> String {
    use base64::Engine;
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(text.as_bytes()))
    )
}

/// The complete status page. Returns the document and the Content-Security-Policy that allows
/// exactly its own inline style and script blocks (by hash) and nothing from any other origin.
fn public_doc(
    p: &StatusPage,
    events: &str,
    inner: &str,
    logo: Option<(String, Vec<u8>)>,
) -> (Markup, String) {
    let a = pub_assets();
    let name = if p.brand.is_empty() {
        &p.title
    } else {
        &p.brand
    };
    let theme = match p.theme.as_str() {
        t @ ("light" | "auto") => t,
        _ => "dark",
    };
    let accent = if valid_hex(&p.accent) {
        accent_css(&p.accent, theme)
    } else {
        String::new()
    };
    let logo_uri = logo.as_ref().map(|(m, b)| data_uri(m, b));
    let icon = match (&logo_uri, p.hide_powered) {
        (Some(u), _) if u.len() <= 64 * 1024 => u.clone(),
        (_, true) | (Some(_), _) => "data:,".to_string(),
        _ => a.favicon.clone(),
    };
    let mut style_src = vec![csp_hash(&a.css)];
    if !accent.is_empty() {
        style_src.push(csp_hash(&accent));
    }
    let csp = format!(
        "default-src 'none'; script-src {}; style-src {}; img-src data:; font-src data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
        csp_hash(&a.js),
        style_src.join(" ")
    );
    let doc = html! {
        (DOCTYPE)
        html lang="en" class="pub" data-theme=(theme) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content=(match theme { "light" => "light", "auto" => "dark light", _ => "dark" });
                meta name="referrer" content="no-referrer";
                meta name="robots" content=(if p.noindex { "noindex, nofollow" } else { "index, follow" });
                title { (name) }
                link rel="icon" href=(icon);
                style { (maud::PreEscaped(&a.css)) }
                @if !accent.is_empty() { style { (maud::PreEscaped(&accent)) } }
            }
            body.pub-body {
                (maud::PreEscaped(&a.sprite))
                main.sp {
                    header.sp-head {
                        div.sp-id {
                            @if let Some(u) = &logo_uri { img.sp-logo src=(u) alt=(name); }
                            div { h1 { (name) } @if !p.description.is_empty() { p.ph-desc { (p.description) } } }
                        }
                        div.sp-side {
                            @let links = link_list(&p.links);
                            @if !links.is_empty() { nav.sp-links aria-label="Links" { @for (l, u) in links { a href=(u) target="_blank" rel="noopener noreferrer" { (l) } } } }
                            span.stream-dot id="live-pill" role="img" aria-label="Receiving live updates" title="Receiving live updates" { i {} }
                        }
                    }
                    div id="live" data-live=(events) data-public="1" { (maud::PreEscaped(inner)) }
                    footer.sp-foot {
                        @if !p.footer.is_empty() { div { (p.footer) } }
                        @if !p.hide_powered { div { "Powered by NDO4Uptime" } }
                    }
                }
                script { (maud::PreEscaped(&a.js)) }
            }
        }
    };
    (doc, csp)
}

fn host_of(h: &HeaderMap) -> String {
    h.get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.rsplit_once(':')
                .filter(|(_, p)| p.bytes().all(|c| c.is_ascii_digit()))
                .map_or(v, |x| x.0)
        })
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase()
}

fn live_page(app: &App, p: Option<StatusPage>, events: String) -> Response {
    match p.filter(|p| p.enabled) {
        Some(p) => {
            let inner = fragment(app, &p);
            let logo = if p.logo_ts > 0 {
                app.db.page_logo(&p.slug)
            } else {
                None
            };
            let (doc, csp) = public_doc(&p, &events, &inner, logo);
            let mut r = page(doc);
            if let Ok(v) = header::HeaderValue::from_str(&csp) {
                r.headers_mut().insert("content-security-policy", v);
            }
            r
        }
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// `/` on the public listener: the page that owns the request's Host.
pub async fn by_host(State(app): S, h: HeaderMap) -> Response {
    live_page(&app, app.db.page_by_domain(&host_of(&h)), "/events".into())
}
pub async fn by_slug(State(app): S, Path(slug): Path<String>) -> Response {
    live_page(
        &app,
        app.db.page_by_slug(&slug),
        format!("/s/{slug}/events"),
    )
}

// ---------------------------------------------------------------- public live stream
static PUB_STREAMS: AtomicUsize = AtomicUsize::new(0);
const MAX_PUB_STREAMS: usize = 256;

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        PUB_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}

fn chunk(event: &str, data: &str) -> Result<Bytes, std::convert::Infallible> {
    Ok(Bytes::from(format!("event: {event}\ndata: {data}\n\n")))
}

fn stream(app: Arc<App>, p: Option<StatusPage>) -> Response {
    let Some(p) = p.filter(|p| p.enabled) else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    if PUB_STREAMS.fetch_add(1, Ordering::Relaxed) >= MAX_PUB_STREAMS {
        PUB_STREAMS.fetch_sub(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "Too many viewers").into_response();
    }
    let guard = Guard;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut sub = app.db.1.subscribe();
    let id = p.id;
    tokio::spawn(async move {
        let _guard = guard;
        let mut last = 0u64;
        loop {
            let Some(p) = app.db.page(id).filter(|p| p.enabled) else {
                let _ = tx.send(chunk("gone", "1")).await;
                break;
            };
            let html = fragment(&app, &p);
            let mut h = std::collections::hash_map::DefaultHasher::new();
            html.hash(&mut h);
            let hv = h.finish();
            let c = if hv != last {
                last = hv;
                chunk("frag", &serde_json::to_string(&*html).unwrap_or_default())
            } else {
                Ok(Bytes::from_static(b": ping\n\n"))
            };
            if tx.send(c).await.is_err() {
                break;
            }
            tokio::select! {
                r = sub.changed() => {
                    if r.is_err() { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    sub.borrow_and_update();
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => {}
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
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

pub async fn events_by_host(State(app): S, h: HeaderMap) -> Response {
    let p = app.db.page_by_domain(&host_of(&h));
    stream(app, p)
}
pub async fn events_by_slug(State(app): S, Path(slug): Path<String>) -> Response {
    let p = app.db.page_by_slug(&slug);
    stream(app, p)
}

// ---------------------------------------------------------------- logo and theme
fn sniff_image(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub async fn logo_post(
    State(app): S,
    a: Auth,
    Path(id): Path<i64>,
    mut mp: axum::extract::Multipart,
) -> Response {
    use subtle::ConstantTimeEq;
    if app.db.page(id).is_none() {
        return not_found().await;
    }
    let (mut csrf, mut data) = (String::new(), Vec::new());
    while let Ok(Some(field)) = mp.next_field().await {
        match field.name() {
            Some("csrf_token") => csrf = field.text().await.unwrap_or_default(),
            Some("logo") => data = field.bytes().await.map(|b| b.to_vec()).unwrap_or_default(),
            _ => {}
        }
    }
    if !bool::from(csrf.as_bytes().ct_eq(a.csrf.as_bytes())) {
        return bad_csrf();
    }
    let back = format!("/pages/{id}/edit");
    if data.is_empty() || data.len() > 256 * 1024 {
        return Redirect::to(&format!("{back}?m=logo_bad")).into_response();
    }
    let Some(mime) = sniff_image(&data) else {
        return Redirect::to(&format!("{back}?m=logo_bad")).into_response();
    };
    app.db.set_page_logo(id, Some((mime, &data)));
    Redirect::to(&format!("{back}?m=saved")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slugify("Acme  Status!"), "acme-status");
        assert!(valid_slug("acme-1") && !valid_slug("-x") && !valid_slug("A") && !valid_slug(""));
    }

    #[test]
    fn domains() {
        assert!(valid_domain("status.example.com"));
        assert!(!valid_domain("localhost") && !valid_domain("a..b") && !valid_domain("10.0.0.1"));
        assert!(!valid_domain("exa_mple.com") && !valid_domain("-a.com"));
    }

    #[test]
    fn branding_inputs() {
        assert!(
            valid_hex("#2a8fdc")
                && !valid_hex("2a8fdc")
                && !valid_hex("#12345")
                && !valid_hex("#gggggg")
        );
        assert_eq!(
            clean_links("Site | https://a.example\n\nHelp|http://b.example/x").unwrap(),
            "Site | https://a.example\nHelp | http://b.example/x"
        );
        assert!(clean_links("no separator").is_err());
        assert!(clean_links("X | javascript:alert(1)").is_err());
        assert!(clean_links(
            "1|https://a.b\n2|https://a.b\n3|https://a.b\n4|https://a.b\n5|https://a.b"
        )
        .is_err());
        assert!(accent_css("#2a8fdc", "dark").contains("--primary:#2a8fdc"));
    }

    #[test]
    fn image_sniffing() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nxxxx"), Some("image/png"));
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_image(b"<svg onload=alert(1)>"), None);
        assert_eq!(sniff_image(b"GIF89a.."), Some("image/gif"));
    }

    #[test]
    fn status_page_is_self_contained() {
        let p = StatusPage {
            title: "T".into(),
            accent: "#e0a32e".into(),
            ..Default::default()
        };
        let logo = Some(("image/png".to_string(), b"\x89PNG\r\n\x1a\n".to_vec()));
        let (doc, csp) = public_doc(&p, "/events", "<p>x</p>", logo);
        let html = doc.into_string();
        // Nothing may be fetched from any path: no linked styles, scripts, images or fonts.
        for bad in [
            "src=\"/",
            "href=\"/",
            "url(\"/",
            "url(/",
            "<link rel=\"stylesheet",
            "<script src",
        ] {
            assert!(!html.contains(bad), "found {bad}");
        }
        assert!(html.contains("data-live=\"/events\""));
        assert!(csp.contains("default-src 'none'") && csp.contains("connect-src 'self'"));
        assert!(!csp.contains("unsafe-inline") && !csp.contains("'self'; style"));
    }

    #[test]
    fn hosts() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "Status.Example.com:8590".parse().unwrap());
        assert_eq!(host_of(&h), "status.example.com");
    }
}
