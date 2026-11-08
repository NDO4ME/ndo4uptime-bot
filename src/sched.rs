use crate::db::{now, Monitor, Webhook};
use crate::{checks, App};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[derive(Default)]
pub struct Sched {
    next: HashMap<i64, Instant>,
    running: HashSet<i64>,
}
pub type Shared = Mutex<Sched>;

pub fn run_now(app: &App, id: i64) {
    let mut s = app.sched.lock().unwrap_or_else(|e| e.into_inner());
    s.next.remove(&id);
}

pub async fn run(app: Arc<App>) {
    let sem = Arc::new(Semaphore::new(32));
    let mut last_gc = Instant::now() - Duration::from_secs(3600);
    // The monitor list is re-read only when something changed (or every 15 s), not every second.
    let mut changes = app.db.1.subscribe();
    let mut monitors: Vec<Monitor> = Vec::new();
    let mut loaded = Instant::now() - Duration::from_secs(60);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if changes.has_changed().unwrap_or(true) || loaded.elapsed() > Duration::from_secs(15) {
            changes.borrow_and_update();
            monitors = app.db.monitors();
            loaded = Instant::now();
        }
        let ids: HashSet<i64> = monitors.iter().map(|m| m.id).collect();
        app.sched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next
            .retain(|k, _| ids.contains(k));
        for m in monitors.iter().filter(|m| m.enabled) {
            let due = {
                let mut s = app.sched.lock().unwrap_or_else(|e| e.into_inner());
                let due = s.next.get(&m.id).is_none_or(|t| Instant::now() >= *t);
                if due && !s.running.contains(&m.id) {
                    s.running.insert(m.id);
                    s.next.insert(
                        m.id,
                        Instant::now() + Duration::from_secs(m.interval as u64),
                    );
                    true
                } else {
                    false
                }
            };
            if !due {
                continue;
            }
            let (app2, sem2, m) = (app.clone(), sem.clone(), m.clone());
            tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                let id = m.id;
                let retry_in = check_once(&app2, m).await;
                let mut s = app2.sched.lock().unwrap_or_else(|e| e.into_inner());
                s.running.remove(&id);
                if let Some(d) = retry_in {
                    s.next.insert(id, Instant::now() + d);
                }
            });
        }
        if last_gc.elapsed() > Duration::from_secs(3600) {
            last_gc = Instant::now();
            let app2 = app.clone();
            drop(tokio::task::spawn_blocking(move || {
                app2.db.enforce_limits(
                    app2.db.retention_days(app2.cfg.retention_days),
                    app2.db.max_db_mb() * 1024 * 1024,
                );
                app2.db.sessions_gc();
            }));
        }
    }
}

/// What one check result does to a monitor. Pure, so the alerting rules are unit-tested.
#[derive(Debug, PartialEq)]
pub struct Step {
    pub status: i64,
    pub fails: i64,
    /// Webhook event to fire, if any.
    pub event: Option<&'static str>,
    /// A failure that is not yet confirmed as DOWN (shown yellow, no alert).
    pub soft: bool,
}

/// A monitor goes DOWN — and alerts — only after `threshold` consecutive failed checks;
/// anything shorter is a yellow "confirming" state that never notifies. A single success
/// resets the count. Recovery is announced only if a DOWN alert was actually raised.
pub fn decide(prev_status: i64, prev_fails: i64, ok: bool, threshold: i64) -> Step {
    if ok {
        return Step {
            status: 1,
            fails: 0,
            event: (prev_status == 2).then_some("up"),
            soft: false,
        };
    }
    let fails = prev_fails + 1;
    if prev_status == 2 || fails >= threshold {
        Step {
            status: 2,
            fails,
            event: (prev_status != 2).then_some("down"),
            soft: false,
        }
    } else {
        Step {
            status: prev_status,
            fails,
            event: None,
            soft: true,
        }
    }
}

/// Runs a check, stores the heartbeat, updates state and fires webhooks on confirmed transitions.
/// Returns a shorter delay while a failure is still being confirmed.
async fn check_once(app: &Arc<App>, m: Monitor) -> Option<Duration> {
    // Re-read: the monitor may have been edited/deleted while queued.
    let m = app.db.monitor(m.id).filter(|x| x.enabled).unwrap_or(m);
    let mut res = checks::run(&m).await;
    if let Ok((_, _, Some(exp))) = &res {
        app.db.set_cert(m.id, *exp);
        let left = (*exp - now()) / 86400;
        if m.cert_days > 0 && left < m.cert_days {
            res = Err(format!(
                "Certificate expires in {} day(s) (threshold {})",
                left.max(0),
                m.cert_days
            ));
        }
    }
    let mut slow_ms = None; // keep the measured latency on the chart even when it fails the limit
    if let Ok((ms, _, _)) = &res {
        if m.slow_ms > 0 && *ms > m.slow_ms {
            slow_ms = Some(*ms);
            res = Err(format!("Slow response: {ms} ms (limit {} ms)", m.slow_ms));
        }
    }
    let (ok, ms, msg) = match &res {
        Ok((ms, msg, _)) => (true, Some(*ms), msg.clone()),
        Err(e) => (false, slow_ms, e.clone()),
    };
    let cur = app.db.monitor(m.id)?;
    if !cur.enabled {
        app.db.add_beat(m.id, ok, 0, ms, &msg);
        return None;
    }
    // Under maintenance the check still runs and is recorded, but it can neither change the
    // monitor's state, open an incident nor alert anyone, and it never counts as downtime.
    if app.db.in_maintenance(m.id).is_some() {
        // An outage already in progress stops counting once the window opens; it is reopened
        // below if the monitor is still failing when the window ends.
        if cur.status == 2 {
            app.db.close_incident(m.id);
        }
        app.db.add_beat(m.id, ok, 2, ms, &msg);
        return None;
    }
    let threshold = app.db.threshold(&cur);
    let step = decide(cur.status, cur.fails, ok, threshold);
    app.db.add_beat(m.id, ok, i64::from(step.soft), ms, &msg);
    if step.status != cur.status {
        app.db.set_state(m.id, step.status, step.fails, Some(now()));
    } else if step.fails != cur.fails {
        app.db.set_state(m.id, step.status, step.fails, None);
    }
    if step.status == 2 && step.event.is_none() {
        app.db.open_incident(m.id);
    }
    match step.event {
        Some("down") => {
            app.db.open_incident(m.id);
            // A muted monitor is tracked visually (and in the incident history) but sends nothing.
            let alert = !muted(&cur);
            if alert {
                app.db.set_alerted(m.id, true);
                notify(app, &cur, "down", &msg, ms, (step.fails, threshold));
            }
            crate::ai::on_down(app, &cur, &msg, ms, (step.fails, threshold), alert);
        }
        Some(event) => {
            app.db.close_incident(m.id);
            if cur.alerted {
                app.db.set_alerted(m.id, false);
                if !muted(&cur) {
                    notify(app, &cur, event, &msg, ms, (step.fails, threshold));
                }
            }
        }
        None => {}
    }
    step.soft
        .then(|| Duration::from_secs((cur.interval.min(app.db.recheck_secs())) as u64))
}

/// True while a monitor's alerts are silenced (muted until a time, or for good).
pub fn muted(m: &Monitor) -> bool {
    m.mute_until > now()
}

fn notify(
    app: &Arc<App>,
    m: &Monitor,
    event: &'static str,
    msg: &str,
    ms: Option<i64>,
    checks: (i64, i64),
) {
    let hooks = app.db.webhooks_for(m);
    if hooks.is_empty() {
        return;
    }
    let lock = app.db.privacy_lock();
    for h in hooks {
        let app = app.clone();
        let p = payload(event, Some(m), msg, ms, Some(checks), h.detail && !lock);
        tokio::spawn(async move { deliver(&app, &h, &p).await });
    }
}

/// `checks` = (consecutive failed checks, threshold that confirmed them).
pub fn payload(
    event: &str,
    m: Option<&Monitor>,
    msg: &str,
    ms: Option<i64>,
    checks: Option<(i64, i64)>,
    detail: bool,
) -> String {
    if !detail {
        // Private by default: monitor name and state only. No target, IP, port, error text or timings.
        let name = m.map_or("Test monitor", |m| m.name.as_str());
        return json!({
            "event": event,
            "status": if event == "down" { "down" } else { "up" },
            "time": now(),
            "monitor": {"name": name},
        })
        .to_string();
    }
    let mon = match m {
        Some(m) => {
            json!({"id": m.id, "name": m.name, "type": m.kind, "target": if m.kind == "tcp" { format!("{}:{}", m.target, m.port) } else { m.target.clone() }})
        }
        None => {
            json!({"id": 0, "name": "Test monitor", "type": "http", "target": "https://example.com"})
        }
    };
    json!({
        "event": event,
        "status": if event == "down" { "down" } else { "up" },
        "message": msg,
        "ping_ms": ms,
        "failed_checks": checks.map(|c| c.0),
        "confirmed_after": checks.map(|c| c.1),
        "time": now(),
        "monitor": mon,
    })
    .to_string()
}

fn hook_client() -> &'static reqwest::Client {
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("NDO4Uptime/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default()
    })
}

/// Worth another attempt: network trouble, a timeout, 408, 429 or a 5xx. A 4xx means the
/// receiver rejected the request itself, and repeating it will not help.
fn retryable(err: &str) -> bool {
    match err
        .strip_prefix("HTTP ")
        .and_then(|c| c.parse::<u16>().ok())
    {
        Some(code) => code == 408 || code == 429 || code >= 500,
        None => matches!(err, "Timed out" | "Connection failed" | "Request failed"),
    }
}

/// Delivers an alert and keeps trying for about a minute (now, +5 s, +25 s) so a short outage
/// of the receiver does not swallow a DOWN alert. The last result is shown on the Webhooks page.
pub async fn deliver(app: &App, h: &Webhook, body: &str) {
    let mut last = Err("not sent".to_string());
    for (i, wait) in [0u64, 5, 20].into_iter().enumerate() {
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        last = send_webhook(h, body).await;
        match &last {
            Ok(_) => break,
            Err(e) if !retryable(e) => break,
            Err(_) if i == 2 => break,
            Err(_) => {}
        }
    }
    app.db.webhook_result(h.id, &last.unwrap_or_else(|e| e));
}

/// Sends one alert over the channel's type. Returns a short result ("HTTP 200") or an error text.
pub async fn send_webhook(h: &Webhook, body: &str) -> Result<String, String> {
    if h.kind.is_empty() || h.kind == "webhook" {
        return send_plain(h, body).await;
    }
    let client = hook_client();
    if let Some(r) = crate::mail::send(&h.kind, &h.cfg, body, client).await {
        return r;
    }
    let mut last = String::new();
    for r in crate::notify::build_all(&h.kind, &h.cfg, body)? {
        last = send_req(client, r).await?;
    }
    Ok(last)
}

async fn send_req(client: &reqwest::Client, r: crate::notify::Req) -> Result<String, String> {
    let mut rq = match r.method {
        "GET" => client.get(&r.url),
        "PUT" => client.put(&r.url),
        _ => client.post(&r.url),
    };
    for (k, v) in &r.headers {
        rq = rq.header(k.as_str(), v.as_str());
    }
    if let Some((u, p)) = &r.basic {
        rq = rq.basic_auth(u, Some(p));
    }
    rq = match r.body {
        crate::notify::Body::None => rq,
        crate::notify::Body::Json(v) => rq
            .header("content-type", "application/json")
            .body(v.to_string()),
        crate::notify::Body::Text(t) => rq
            .header("content-type", "text/plain; charset=utf-8")
            .body(t),
        crate::notify::Body::Form(f) => {
            let enc = f
                .iter()
                .map(|(k, v)| format!("{}={}", crate::notify::enc(k), crate::notify::enc(v)))
                .collect::<Vec<_>>()
                .join("&");
            rq.header("content-type", "application/x-www-form-urlencoded")
                .body(enc)
        }
    };
    match rq.send().await {
        Ok(r) if r.status().is_success() => Ok(format!("HTTP {}", r.status().as_u16())),
        Ok(r) => Err(format!("HTTP {}", r.status().as_u16())),
        Err(e) => Err(if e.is_timeout() {
            "Timed out".into()
        } else if e.is_connect() {
            "Connection failed".into()
        } else {
            "Request failed".into()
        }),
    }
}

async fn send_plain(h: &Webhook, body: &str) -> Result<String, String> {
    let client = hook_client();
    let ts = now().to_string();
    let mut req = client
        .post(&h.url)
        .header("content-type", "application/json")
        .header("x-ndo4-timestamp", &ts)
        .headers(checks::parse_headers(&h.headers)?);
    if !h.secret.is_empty() {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(h.secret.as_bytes()).map_err(|e| e.to_string())?;
        mac.update(ts.as_bytes());
        mac.update(b".");
        mac.update(body.as_bytes());
        req = req.header(
            "x-ndo4-signature",
            format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
        );
    }
    match req.body(body.to_string()).send().await {
        Ok(r) if r.status().is_success() => Ok(format!("HTTP {}", r.status().as_u16())),
        Ok(r) => Err(format!("HTTP {}", r.status().as_u16())),
        Err(e) => Err(if e.is_timeout() {
            "Timed out".into()
        } else if e.is_connect() {
            "Connection failed".into()
        } else {
            "Request failed".into()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_payload_leaks_nothing() {
        let mut m = Monitor::blank();
        m.name = "Mail relay".into();
        m.kind = "tcp".into();
        m.target = "10.1.2.3".into();
        m.port = 2525;
        let p = payload(
            "down",
            Some(&m),
            "Connection refused 10.1.2.3:2525",
            Some(9),
            Some((3, 3)),
            false,
        );
        assert!(p.contains("Mail relay") && p.contains("\"down\""));
        for secret in [
            "10.1.2.3", "2525", "refused", "tcp", "ping_ms", "message", "target",
        ] {
            assert!(!p.contains(secret), "leaked {secret}");
        }
        let d = payload("down", Some(&m), "x", None, None, true);
        assert!(d.contains("10.1.2.3:2525"));
    }

    #[test]
    fn delivery_retry_rules() {
        for e in [
            "Timed out",
            "Connection failed",
            "Request failed",
            "HTTP 503",
            "HTTP 429",
            "HTTP 408",
        ] {
            assert!(retryable(e), "{e}");
        }
        for e in [
            "HTTP 400",
            "HTTP 404",
            "HTTP 401",
            "Invalid header name \"x\".",
            "At most 20 headers are allowed.",
        ] {
            assert!(!retryable(e), "{e}");
        }
    }

    #[test]
    fn group_binding() {
        let w = Webhook {
            groups: "Company\n prod ".into(),
            ..Default::default()
        };
        assert!(
            w.in_group("company")
                && w.in_group("PROD")
                && !w.in_group("Personal")
                && !w.in_group("")
        );
    }

    /// Feeds a result sequence through `decide`, returning (status, event, soft) per step.
    fn run(results: &[bool], threshold: i64) -> Vec<(i64, Option<&'static str>, bool)> {
        let (mut status, mut fails) = (1, 0);
        results
            .iter()
            .map(|ok| {
                let s = decide(status, fails, *ok, threshold);
                status = s.status;
                fails = s.fails;
                (s.status, s.event, s.soft)
            })
            .collect()
    }

    #[test]
    fn three_failures_confirm_down() {
        let r = run(&[false, false, false], 3);
        assert_eq!(r[0], (1, None, true)); // yellow
        assert_eq!(r[1], (1, None, true)); // yellow
        assert_eq!(r[2], (2, Some("down"), false)); // red + alert
    }

    #[test]
    fn short_blips_never_alert() {
        let r = run(&[false, false, true, false, true], 3);
        assert!(r.iter().all(|(_, e, _)| e.is_none()));
        assert!(r.iter().all(|(s, _, _)| *s == 1));
    }

    #[test]
    fn alerts_once_then_announces_recovery() {
        let r = run(&[false, false, false, false, false, true, true], 3);
        let events: Vec<_> = r.iter().filter_map(|x| x.1).collect();
        assert_eq!(events, ["down", "up"]);
    }

    #[test]
    fn threshold_one_alerts_immediately() {
        assert_eq!(run(&[false], 1)[0], (2, Some("down"), false));
    }

    #[test]
    fn pending_monitor_needs_confirmation_too() {
        let s = decide(0, 0, false, 3);
        assert_eq!((s.status, s.event, s.soft), (0, None, true));
        assert_eq!(decide(0, 0, true, 3).event, None); // first success: up, no recovery alert
    }

    #[test]
    fn raising_the_threshold_does_not_flap_a_down_monitor() {
        let s = decide(2, 3, false, 5);
        assert_eq!((s.status, s.event, s.soft), (2, None, false));
    }
}
