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
    let mut last_gc = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let monitors = app.db.monitors();
        let ids: HashSet<i64> = monitors.iter().map(|m| m.id).collect();
        for m in monitors.into_iter().filter(|m| m.enabled) {
            let due = {
                let mut s = app.sched.lock().unwrap_or_else(|e| e.into_inner());
                s.next.retain(|k, _| ids.contains(k));
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
            let app2 = app.clone();
            let sem2 = sem.clone();
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
            app.db.prune(app.cfg.retention_days);
            app.db.sessions_gc();
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
    let (ok, ms, msg) = match &res {
        Ok((ms, msg, _)) => (true, Some(*ms), msg.clone()),
        Err(e) => (false, None, e.clone()),
    };
    let cur = app.db.monitor(m.id)?;
    if !cur.enabled {
        app.db.add_beat(m.id, ok, false, ms, &msg);
        return None;
    }
    let threshold = app.db.threshold(&cur);
    let step = decide(cur.status, cur.fails, ok, threshold);
    app.db.add_beat(m.id, ok, step.soft, ms, &msg);
    if step.status != cur.status {
        app.db.set_state(m.id, step.status, step.fails, Some(now()));
    } else if step.fails != cur.fails {
        app.db.set_state(m.id, step.status, step.fails, None);
    }
    if let Some(event) = step.event {
        notify(app, &cur, event, &msg, ms, (step.fails, threshold));
    }
    step.soft
        .then(|| Duration::from_secs((cur.interval.min(app.db.recheck_secs())) as u64))
}

fn notify(
    app: &Arc<App>,
    m: &Monitor,
    event: &'static str,
    msg: &str,
    ms: Option<i64>,
    checks: (i64, i64),
) {
    let hooks = app.db.webhooks_for(m.id);
    if hooks.is_empty() {
        return;
    }
    let payload = payload(event, Some(m), msg, ms, Some(checks));
    for h in hooks {
        let app = app.clone();
        let p = payload.clone();
        tokio::spawn(async move {
            let r = send_webhook(&h, &p).await;
            app.db.webhook_result(h.id, &r.unwrap_or_else(|e| e));
        });
    }
}

/// `checks` = (consecutive failed checks, threshold that confirmed them).
pub fn payload(
    event: &str,
    m: Option<&Monitor>,
    msg: &str,
    ms: Option<i64>,
    checks: Option<(i64, i64)>,
) -> String {
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

/// Sends the payload. Returns a short human-readable result ("HTTP 200") or an error text.
pub async fn send_webhook(h: &Webhook, body: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("NDO4Uptime/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
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
