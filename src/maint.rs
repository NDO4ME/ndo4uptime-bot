//! Maintenance windows: admin pages. Times are entered and shown in UTC; public pages localise
//! them in the visitor's browser.

use crate::auth::*;
use crate::db::now;
use crate::store::Maint;
use crate::view::*;
use crate::web::{bad_csrf, flash_of, page};
use crate::App;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use maud::{html, Markup};
use std::collections::HashMap;
use std::sync::Arc;

type S = State<Arc<App>>;
type Q = Query<HashMap<String, String>>;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `YYYY-MM-DDTHH:MM` (a datetime-local value, read as UTC) to epoch seconds.
pub fn parse_local(s: &str) -> Option<i64> {
    let s = s.trim();
    let (d, t) = s.split_once(['T', ' '])?;
    let mut dp = d.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (dp.next()??, dp.next()??, dp.next()??);
    let mut tp = t.split(':').map(|x| x.parse::<i64>().ok());
    let (h, mi) = (tp.next()??, tp.next()??);
    if !(2000..=2100).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&h)
        || !(0..60).contains(&mi)
    {
        return None;
    }
    let days = days_from_civil(y, m, day);
    // Reject dates that do not exist (31 February would silently become 3 March).
    if civil_day(days) != day {
        return None;
    }
    Some(days * 86400 + h * 3600 + mi * 60)
}

/// Day of month for a day count since 1970-01-01.
fn civil_day(z: i64) -> i64 {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    doy - (153 * mp + 2) / 5 + 1
}

fn local_value(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    let s = fmt_ts(ts); // "YYYY-MM-DD HH:MM:SS UTC"
    format!("{}T{}", &s[..10], &s[11..16])
}

fn repeat_label(d: i64) -> String {
    match d {
        0 => "once".into(),
        1 => "daily".into(),
        7 => "weekly".into(),
        n => format!("every {n} days"),
    }
}

fn parse(f: &Form, id: i64) -> (Maint, Option<&'static str>) {
    let mut m = Maint {
        id,
        title: f.get("title").trim().to_string(),
        message: f.get("message").trim().to_string(),
        start: parse_local(f.get("start")).unwrap_or(0),
        end: parse_local(f.get("end")).unwrap_or(0),
        repeat_days: f.int("repeat", 0).clamp(0, 365),
        all: f.has("all"),
        public: f.has("public"),
        enabled: f.has("enabled"),
        mons: f
            .all("mons")
            .iter()
            .filter_map(|v| v.parse().ok())
            .collect(),
    };
    m.mons.truncate(500);
    let err = if m.title.is_empty()
        || m.title.chars().count() > 80
        || m.title.chars().any(char::is_control)
    {
        "Give the window a title of up to 80 characters."
    } else if m.message.chars().count() > 300 {
        "The message is limited to 300 characters."
    } else if m.start == 0 || m.end == 0 {
        "Start and end must be set (YYYY-MM-DD HH:MM, UTC)."
    } else if m.end <= m.start {
        "The end must be after the start."
    } else if m.end - m.start > 14 * 86400 {
        "A window can last at most 14 days."
    } else if m.repeat_days > 0 && m.end - m.start >= m.repeat_days * 86400 {
        "A repeating window must be shorter than its repeat period."
    } else if !m.all && m.mons.is_empty() {
        "Pick at least one monitor, or choose all monitors."
    } else {
        return (m, None);
    };
    (m, Some(err))
}

fn form(app: &App, m: &Maint, csrf: &str, title: &str, err: Option<&str>) -> Markup {
    let mons = app.db.monitors();
    let action = if m.id == 0 {
        "/maintenance".to_string()
    } else {
        format!("/maintenance/{}/edit", m.id)
    };
    layout(
        Page {
            title,
            desc: "Checks keep running, but nothing alerts while a window is open.",
            active: "maintenance",
            csrf,
            flash: None,
            parent: Some(("/maintenance", "Maintenance")),
            refresh: false,
            actions: html! {},
        },
        html! {
            form method="post" action=(action) {
                (csrf_input(csrf))
                section.panel {
                    header.panel-h { h2 { (ic("tool")) "Window" } }
                    div.panel-b {
                        @if let Some(e) = err { (msg("err", e, false)) }
                        label.field { span.lbl { "Title" } input name="title" value=(m.title) required maxlength="80" placeholder="Database upgrade"; }
                        label.field { span.lbl { "Message (optional)" } textarea name="message" rows="2" maxlength="300" placeholder="Shown on status pages while the window is announced." { (m.message) } }
                        div.row {
                            label.field { span.lbl { "Start (UTC)" } input type="datetime-local" name="start" value=(local_value(m.start)) required; }
                            label.field { span.lbl { "End (UTC)" } input type="datetime-local" name="end" value=(local_value(m.end)) required; }
                            label.field { span.lbl { "Repeat" }
                                select name="repeat" {
                                    option value="0" selected[m.repeat_days == 0] { "Once" }
                                    option value="1" selected[m.repeat_days == 1] { "Daily" }
                                    option value="7" selected[m.repeat_days == 7] { "Weekly" }
                                    option value="14" selected[m.repeat_days == 14] { "Every 14 days" }
                                    option value="30" selected[m.repeat_days == 30] { "Every 30 days" }
                                }
                            }
                        }
                        label.check { input type="checkbox" name="public" value="1" checked[m.public || m.id == 0]; span { "Announce on status pages" span.hint { "Shown only on pages that include an affected monitor, from 7 days ahead." } } }
                        label.check { input type="checkbox" name="enabled" value="1" checked[m.enabled || m.id == 0]; span { "Enabled" } }
                    }
                }
                section.panel {
                    header.panel-h { h2 { (ic("activity")) "Affected monitors" } }
                    div.panel-b {
                        label.check { input type="checkbox" name="all" value="1" checked[m.all]; span { "All monitors" span.hint { "Includes monitors added later." } } }
                        @if mons.is_empty() { p.hint { "No monitors yet." } }
                        @for x in &mons {
                            label.check { input type="checkbox" name="mons" value=(x.id) checked[m.mons.contains(&x.id)]; span { (x.name) @if !x.grp.is_empty() { " " span.faint.small { (x.grp) } } } }
                        }
                    }
                }
                div.form-actions { button type="submit" class="btn btn-primary" { (ic("check")) "Save window" } " " a.btn href="/maintenance" { "Cancel" } }
            }
        },
    )
}

pub async fn list(State(app): S, a: Auth, Query(q): Q) -> Response {
    let t = now();
    let list = app.db.maints();
    page(layout(
        Page {
            title: "Maintenance",
            desc: "Planned downtime: monitors keep being checked but stay quiet.",
            active: "maintenance",
            csrf: &a.csrf,
            flash: flash_of(&q),
            parent: None,
            refresh: false,
            actions: html! { a.btn.btn-primary href="/maintenance/new" { (ic("plus")) "New window" } },
        },
        html! {
            section.panel {
                header.panel-h { h2 { (ic("tool")) "Windows" } }
                @if list.is_empty() {
                    div.empty-state { (ic("tool")) "No maintenance windows. While one is open, its monitors do not alert and are shown as under maintenance." }
                } @else {
                    div.tbl-wrap { table.tbl {
                        thead { tr { th { "State" } th { "Title" } th { "When" } th { "Repeat" } th { "Applies to" } th {} } }
                        tbody { @for m in list.iter() {
                            @let w = m.window(t);
                            tr {
                                td { @if !m.enabled { span.badge { "disabled" } } @else if m.active(t) { span.badge.info { "active" } } @else if w.is_some() { span.badge.warning { "scheduled" } } @else { span.badge { "finished" } } }
                                td { (m.title) }
                                td.nowrap { @if let Some((s, e)) = w { (ts(s)) " → " (ts(e)) } @else { (ts(m.start)) } }
                                td { (repeat_label(m.repeat_days)) }
                                td { @if m.all { "all monitors" } @else { (m.mons.len()) " monitor(s)" } }
                                td.actions-cell {
                                    a.btn.btn-sm href=(format!("/maintenance/{}/edit", m.id)) { "Edit" } " "
                                    form method="post" action=(format!("/maintenance/{}/toggle", m.id)) { (csrf_input(&a.csrf)) button.btn.btn-sm { (if m.enabled { "Disable" } else { "Enable" }) } } " "
                                    form method="post" action=(format!("/maintenance/{}/delete", m.id)) class="js-confirm" data-confirm-title="Delete window" data-confirm=(format!("Delete \"{}\"?", m.title)) { (csrf_input(&a.csrf)) button.btn.btn-sm.btn-danger { (ic("trash")) } }
                                }
                            }
                        } }
                    } }
                }
            }
        },
    ))
}

pub async fn new(State(app): S, a: Auth) -> Response {
    let t = now() / 3600 * 3600 + 3600;
    let m = Maint {
        start: t,
        end: t + 3600,
        public: true,
        enabled: true,
        ..Default::default()
    };
    page(form(&app, &m, &a.csrf, "New maintenance window", None))
}

pub async fn create(State(app): S, a: Auth, f: Form) -> Response {
    save(app, a, f, 0).await
}

pub async fn edit_get(State(app): S, a: Auth, Path(id): Path<i64>) -> Response {
    match app.db.maint(id) {
        Some(m) => page(form(&app, &m, &a.csrf, "Edit maintenance window", None)),
        None => crate::web::not_found().await,
    }
}

pub async fn edit_post(State(app): S, a: Auth, Path(id): Path<i64>, f: Form) -> Response {
    if app.db.maint(id).is_none() {
        return crate::web::not_found().await;
    }
    save(app, a, f, id).await
}

async fn save(app: Arc<App>, a: Auth, f: Form, id: i64) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.maints().len() >= 200 && id == 0 {
        return Redirect::to("/maintenance?m=limit").into_response();
    }
    match parse(&f, id) {
        (m, None) => {
            app.db.save_maint(&m);
            Redirect::to("/maintenance?m=saved").into_response()
        }
        (m, Some(e)) => page(form(
            &app,
            &m,
            &a.csrf,
            if id == 0 {
                "New maintenance window"
            } else {
                "Edit maintenance window"
            },
            Some(e),
        )),
    }
}

pub async fn action(
    State(app): S,
    a: Auth,
    Path((id, act)): Path<(i64, String)>,
    f: Form,
) -> Response {
    if !f.csrf_ok(&a) {
        return bad_csrf();
    }
    if app.db.maint(id).is_none() {
        return crate::web::not_found().await;
    }
    match act.as_str() {
        "toggle" => app.db.toggle_maint(id),
        "delete" => app.db.delete_maint(id),
        _ => return crate::web::not_found().await,
    }
    Redirect::to("/maintenance?m=saved").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_parsing() {
        assert_eq!(parse_local("1970-01-02T00:00"), None); // out of the accepted range
        assert_eq!(parse_local("2024-03-01T12:30"), Some(1709296200));
        assert_eq!(local_value(1709296200), "2024-03-01T12:30");
        assert_eq!(parse_local("2024-13-01T00:00"), None);
        assert_eq!(parse_local("garbage"), None);
        assert_eq!(parse_local("2025-02-31T10:00"), None);
        assert_eq!(parse_local("2024-02-29T10:00"), Some(1709200800));
        assert_eq!(parse_local("2025-04-31T10:00"), None);
    }
}
