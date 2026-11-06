//! Optional Cloudflare Tunnel: supervises a `cloudflared` child process that publishes the
//! *public* status-page listener (never the admin panel) under hostnames you route to it in
//! Cloudflare. Configured from Settings; the token is stored in the database, passed to the
//! child through its environment (not argv) and never rendered back.

use crate::view::*;
use crate::App;
use maud::{html, Markup};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Clone, Default)]
pub struct State {
    /// stopped | starting | running | error
    pub status: &'static str,
    pub detail: String,
}
pub type Shared = Mutex<State>;

fn set(app: &App, status: &'static str, detail: impl Into<String>) {
    *app.tunnel.lock().unwrap_or_else(|e| e.into_inner()) = State {
        status,
        detail: detail.into(),
    };
}

pub fn valid_token(t: &str) -> bool {
    (20..=4096).contains(&t.len())
        && t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-=+/.".contains(&c))
}

/// Sleeps, but wakes early when the settings change.
async fn pause(app: &App, secs: u64) {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        _ = app.tunnel_wake.notified() => {}
    }
}

pub async fn run(app: Arc<App>) {
    let mut backoff = 3u64;
    loop {
        let token = app.db.setting("tunnel_token");
        if app.db.setting("tunnel_enabled") != "1" || token.is_empty() {
            set(&app, "stopped", "");
            app.tunnel_wake.notified().await;
            backoff = 3;
            continue;
        }
        set(&app, "starting", "");
        let mut cmd = Command::new(&app.cfg.cloudflared);
        cmd.args(["--no-autoupdate", "tunnel", "run"])
            .env_clear()
            .env("TUNNEL_TOKEN", &token)
            .env("HOME", "/tmp")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let msg = if e.kind() == std::io::ErrorKind::NotFound {
                    "cloudflared binary not found (the Docker image bundles it; set NDO4_CLOUDFLARED otherwise)".to_string()
                } else {
                    format!("could not start cloudflared: {e}")
                };
                set(&app, "error", msg);
                pause(&app, 60).await;
                continue;
            }
        };
        let mut lines = BufReader::new(child.stderr.take().expect("piped")).lines();
        let mut reached = false;
        let mut last_err = String::new();
        loop {
            tokio::select! {
                l = lines.next_line() => match l {
                    Ok(Some(line)) => {
                        let line = line.replace(&token, "•••");
                        if line.contains("Registered tunnel connection") {
                            reached = true;
                            backoff = 3;
                            set(&app, "running", "");
                        } else if line.contains(" ERR ") || line.contains("not valid") {
                            last_err = line.chars().take(240).collect();
                            if !reached { set(&app, "starting", last_err.clone()); }
                        }
                    }
                    _ => break,
                },
                _ = app.tunnel_wake.notified() => {
                    let _ = child.kill().await;
                    backoff = 0;
                    break;
                }
            }
        }
        let _ = child.kill().await;
        if backoff == 0 {
            backoff = 3;
            continue; // settings changed: re-read them immediately
        }
        set(
            &app,
            "error",
            if last_err.is_empty() {
                "cloudflared exited".into()
            } else {
                last_err
            },
        );
        pause(&app, backoff).await;
        backoff = (backoff * 2).min(120);
    }
}

pub fn panel(app: &App, csrf: &str) -> Markup {
    let st = app.tunnel.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let enabled = app.db.setting("tunnel_enabled") == "1";
    let has_token = !app.db.setting("tunnel_token").is_empty();
    let port = app
        .cfg
        .public_bind
        .rsplit(':')
        .next()
        .unwrap_or("8590")
        .to_string();
    let (cls, label) = match st.status {
        "running" => ("success", "connected"),
        "starting" => ("info", "connecting"),
        "error" => ("failed", "error"),
        _ => ("warning", "off"),
    };
    html! {
        section.panel {
            header.panel-h { h2 { (ic("cloud")) "Cloudflare Tunnel" } div.panel-tools { span class=(format!("badge {cls}")) { (label) } } }
            form method="post" action="/settings/tunnel" autocomplete="off" {
                (csrf_input(csrf))
                div.panel-b {
                    @if !st.detail.is_empty() { (msg(if st.status == "error" { "err" } else { "warn" }, &st.detail, false)) }
                    label.field { span.lbl { "Tunnel token" }
                        input type="password" name="token" maxlength="4096" spellcheck="false" autocomplete="off"
                            placeholder=(if has_token { "•••••••• saved — leave empty to keep" } else { "eyJhIjoi…" });
                        span.hint { "Stored on this server and never shown again. Create it under Cloudflare Zero Trust → Networks → Tunnels." } }
                    ol.hint {
                        li { "In the tunnel's " b { "Public hostname" } " tab add a hostname, e.g. " code { "status.example.com" } " — or a wildcard such as " code { "*.example.com" } " to attach any subdomain to a page later." }
                        li { "Set the service to " code { "HTTP" } " → " code { "127.0.0.1:" (port) } "." }
                        li { "Enter the same hostname as a page's " b { "custom domain" } "." }
                    }
                    p.hint { "Only the public status-page listener is exposed. The admin panel is never reachable through the tunnel." }
                }
                div.panel-f {
                    @if enabled {
                        button.btn.btn-primary name="action" value="save" { (ic("check")) "Save & reconnect" } " "
                        button.btn name="action" value="disable" { (ic("power")) "Disable" }
                    } @else {
                        button.btn.btn-primary name="action" value="enable" { (ic("power")) "Enable tunnel" }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn tokens() {
        assert!(super::valid_token("eyJhIjoiZmFrZWZha2VmYWtlZmFrZSJ9"));
        assert!(
            !super::valid_token("short") && !super::valid_token("has space has space has space")
        );
    }
}
