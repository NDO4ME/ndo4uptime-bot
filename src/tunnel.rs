//! Optional Cloudflare Tunnel: supervises a `cloudflared` child process that publishes the
//! *public* status-page listener (never the admin panel) under hostnames you route to it in
//! Cloudflare. Configured from Settings; the token is stored in the database, passed to the
//! child through its environment (not argv) and never rendered back.
//!
//! Updates (on by default, like Tailscale): the newest stable release is looked up on GitHub
//! (`cloudflare/cloudflared`), downloaded over HTTPS from that repository only, and checked against
//! two independent SHA-256 values (the digest GitHub computed for the asset and the checksum
//! the maintainers print in the release notes; they must agree when both exist). The new binary
//! must start and report the expected version before it is switched on; if the tunnel does not
//! reconnect within two minutes the previous version is restored. Files live under the data
//! volume; the version baked into the image is used until a newer one is installed.

use crate::tailscale::{arch, ver};
use crate::view::*;
use crate::App;
use maud::{html, Markup};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

const API: &str = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest";
const DOWNLOADS: &str = "https://github.com/cloudflare/cloudflared/releases/download/";
const MAX_DOWNLOAD: u64 = 120 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct Upd {
    pub latest: String,
    pub checked: i64,
    pub busy: bool,
    pub last: String,
    pub last_ok: bool,
}

#[derive(Clone, Default)]
pub struct State {
    /// stopped | starting | running | error
    pub status: &'static str,
    pub detail: String,
    pub upd: Upd,
}
pub type Shared = Mutex<State>;

fn set(app: &App, status: &'static str, detail: impl Into<String>) {
    let mut s = app.tunnel.lock().unwrap_or_else(|e| e.into_inner());
    *s = State {
        status,
        detail: detail.into(),
        upd: std::mem::take(&mut s.upd),
    };
}

fn upd_state(app: &App, f: impl FnOnce(&mut State)) {
    f(&mut app.tunnel.lock().unwrap_or_else(|e| e.into_inner()));
}

fn on(app: &App) -> bool {
    app.db.setting("cf_auto_update") != "0"
}

fn root(app: &App) -> PathBuf {
    Path::new(&app.cfg.data).join("cloudflared").join("bin")
}

/// The binary to run: an updated copy under the data volume wins unless the image ships a newer one.
fn bin(app: &App) -> String {
    let cur = root(app).join("current");
    let installed = std::fs::read_link(&cur)
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
    if let Some(v) = installed {
        let exe = cur.join("cloudflared");
        let newer = app.cfg.cf_baked.is_empty() || ver(&v) >= ver(&app.cfg.cf_baked);
        if newer && exe.is_file() {
            return exe.to_string_lossy().into_owned();
        }
    }
    app.cfg.cloudflared.clone()
}

fn current_version(app: &App) -> String {
    if bin(app).starts_with(&app.cfg.data) {
        return std::fs::read_link(root(app).join("current"))
            .ok()
            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
    }
    app.cfg.cf_baked.clone()
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
        let mut cmd = Command::new(bin(&app));
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

// ------------------------------------------------------------------ updates
fn http() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(300))
        .user_agent(format!("NDO4Uptime/{VERSION}"))
        .build()
        .map_err(|e| e.to_string())
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Picks version and checksum out of GitHub's release JSON. Pure, so it is unit-tested.
/// The checksum must be a SHA-256 for our asset; when GitHub's own digest and the checksum
/// printed in the release notes are both present they have to agree.
fn parse_release(v: &Value, arch: &str) -> Result<(String, String), String> {
    let bad = || "unexpected release data".to_string();
    if v["draft"].as_bool().unwrap_or(true) || v["prerelease"].as_bool().unwrap_or(true) {
        return Err(bad());
    }
    let tag = v["tag_name"].as_str().ok_or_else(bad)?.to_string();
    if ver(&tag) == (0, 0, 0)
        || tag.len() > 20
        || !tag.bytes().all(|c| c.is_ascii_digit() || c == b'.')
    {
        return Err(bad());
    }
    let name = format!("cloudflared-linux-{arch}");
    let digest = v["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(&name)))
        .and_then(|x| x["digest"].as_str())
        .and_then(|d| d.strip_prefix("sha256:"))
        .map(str::to_ascii_lowercase)
        .filter(|d| is_sha256(d));
    let prefix = format!("{name}: ");
    let notes = v["body"]
        .as_str()
        .unwrap_or("")
        .lines()
        .find_map(|l| l.trim().strip_prefix(prefix.as_str()))
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| is_sha256(h));
    match (digest, notes) {
        (Some(a), Some(b)) if a != b => Err("the two published checksums disagree".into()),
        (Some(a), _) => Ok((tag, a)),
        (None, Some(b)) => Ok((tag, b)),
        (None, None) => Err("no published checksum found".into()),
    }
}

async fn latest() -> Result<(String, String), String> {
    let body = http()?
        .get(API)
        .header("accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| "could not reach GitHub".to_string())?
        .text()
        .await
        .map_err(|_| "unexpected release data".to_string())?;
    let v: Value =
        serde_json::from_str(&body).map_err(|_| "unexpected release data".to_string())?;
    parse_release(&v, arch())
}

/// Looks up the newest stable release and records it.
pub async fn check(app: &App) -> Result<String, String> {
    let r = latest().await;
    upd_state(app, |s| {
        s.upd.checked = crate::db::now();
        match &r {
            Ok((v, _)) => s.upd.latest = v.clone(),
            Err(e) => {
                s.upd.last = format!("Update check failed: {e}");
                s.upd.last_ok = false;
            }
        }
    });
    r.map(|(v, _)| v)
}

async fn download(url: &str, dest: &Path, want: &str) -> Result<(), String> {
    let mut resp = http()?
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| "download failed".to_string())?;
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o755)
        .open(dest)
        .await
        .map_err(|_| "cannot write the download".to_string())?;
    let (mut h, mut n) = (Sha256::new(), 0u64);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| "download interrupted".to_string())?
    {
        n += chunk.len() as u64;
        if n > MAX_DOWNLOAD {
            return Err("download is unexpectedly large".into());
        }
        h.update(&chunk);
        f.write_all(&chunk)
            .await
            .map_err(|_| "cannot write the download".to_string())?;
    }
    f.flush()
        .await
        .map_err(|_| "cannot write the download".to_string())?;
    if hex::encode(h.finalize()) != want {
        return Err("checksum mismatch, download discarded".into());
    }
    Ok(())
}

fn point_current(bin_dir: &Path, target: Option<&str>) -> std::io::Result<()> {
    let cur = bin_dir.join("current");
    match target {
        Some(t) => {
            let tmp = bin_dir.join("current.new");
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(t, &tmp)?;
            std::fs::rename(&tmp, &cur)
        }
        None => std::fs::remove_file(&cur),
    }
}

async fn install(app: &App, version: &str, want: &str) -> Result<(), String> {
    let dir = root(app);
    std::fs::create_dir_all(&dir).map_err(|_| "cannot create the install directory".to_string())?;
    let stage = dir.join(format!("{version}.tmp"));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)
        .map_err(|_| "cannot create the install directory".to_string())?;
    let exe = stage.join("cloudflared");
    let res = async {
        let url = format!("{DOWNLOADS}{version}/cloudflared-linux-{}", arch());
        download(&url, &exe, want).await?;
        let out = timeout(
            Duration::from_secs(10),
            Command::new(&exe)
                .arg("--version")
                .env_clear()
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| "the new cloudflared does not start".to_string())?
        .map_err(|_| "the new cloudflared does not start".to_string())?;
        if !String::from_utf8_lossy(&out.stdout).contains(version) {
            return Err("the new cloudflared reports an unexpected version".into());
        }
        let dest = dir.join(version);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::rename(&stage, &dest).map_err(|_| "cannot install the new version".to_string())
    }
    .await;
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&stage);
    }
    res
}

fn prune(app: &App, keep: &[&str]) {
    let Ok(rd) = std::fs::read_dir(root(app)) else {
        return;
    };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n != "current" && !keep.contains(&n.as_str()) && e.path().is_dir() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn record(app: &App, ok: bool, msg: String) {
    upd_state(app, |s| {
        s.upd.busy = false;
        s.upd.last = msg;
        s.upd.last_ok = ok;
    });
}

fn running(app: &App) -> bool {
    app.tunnel
        .lock()
        .map(|s| s.status == "running")
        .unwrap_or(false)
}

/// Installs the newest release, restarts the tunnel and rolls back if it does not reconnect.
pub async fn update(app: &App, auto: bool) {
    let claimed = app
        .tunnel
        .lock()
        .map(|mut s| !std::mem::replace(&mut s.upd.busy, true))
        .unwrap_or(false);
    if !claimed {
        return;
    }
    let (version, want) = match latest().await {
        Ok(x) => x,
        Err(e) => return record(app, false, format!("Update check failed: {e}")),
    };
    upd_state(app, |s| {
        s.upd.latest = version.clone();
        s.upd.checked = crate::db::now();
    });
    let cur = current_version(app);
    if !cur.is_empty() && ver(&version) <= ver(&cur) {
        return record(app, true, format!("Already up to date ({cur})."));
    }
    let tag = if auto { "Automatic update" } else { "Update" };
    if let Err(e) = install(app, &version, &want).await {
        return record(app, false, format!("{tag} to {version} failed: {e}"));
    }
    let dir = root(app);
    let prev = std::fs::read_link(dir.join("current"))
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
    if point_current(&dir, Some(&version)).is_err() {
        return record(
            app,
            false,
            format!("{tag} to {version} failed: cannot switch versions."),
        );
    }
    if app.db.setting("tunnel_enabled") != "1" {
        prune(app, &[&version]);
        return record(
            app,
            true,
            format!("{tag}: {version} installed; it starts with the next connection."),
        );
    }
    let was_up = running(app);
    app.tunnel_wake.notify_one(); // restart cloudflared on the new binary
    if was_up {
        let deadline = Instant::now() + Duration::from_secs(120);
        tokio::time::sleep(Duration::from_secs(8)).await;
        while !running(app) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        if !running(app) {
            let _ = point_current(&dir, prev.as_deref());
            app.tunnel_wake.notify_one();
            prune(app, &[prev.as_deref().unwrap_or("")]);
            return record(
                app,
                false,
                format!("{tag} to {version} was rolled back: the tunnel did not reconnect."),
            );
        }
    }
    prune(app, &[&version, prev.as_deref().unwrap_or("")]);
    record(
        app,
        true,
        format!(
            "{tag}: {} → {version}.",
            if cur.is_empty() { "previous" } else { &cur }
        ),
    );
}

/// Background auto-updater: a first look ten minutes after start, then once a day. Runs only
/// while the tunnel is enabled and the automatic-update switch is on (default).
pub async fn updater(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(600)).await;
    loop {
        if app.db.setting("tunnel_enabled") == "1" && on(&app) {
            update(&app, true).await;
        }
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    }
}

pub fn panel(app: &App, csrf: &str) -> Markup {
    let st = app.tunnel.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let enabled = app.db.setting("tunnel_enabled") == "1";
    let has_token = !app.db.setting("tunnel_token").is_empty();
    let current = current_version(app);
    let upd_avail =
        !st.upd.latest.is_empty() && !current.is_empty() && ver(&st.upd.latest) > ver(&current);
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
                    label.check { input type="checkbox" name="auto_update" value="1" checked[on(app)]; span { "Update cloudflared automatically" span.hint { "Downloads verified releases from GitHub once a day (checked against two published SHA-256 values) and rolls back if the tunnel does not reconnect." } } }
                    dl.props {
                        dt { "Installed" } dd.mono { @if current.is_empty() { "–" } @else { (current) } }
                        dt { "Latest" } dd { @if st.upd.latest.is_empty() { span.faint { "not checked" } } @else { span.mono { (st.upd.latest) } @if upd_avail { " " span class="badge info" { "update available" } } } @if st.upd.checked > 0 { " " span.faint.small { "checked " (ago(st.upd.checked)) } } }
                        @if !st.upd.last.is_empty() { dt { "Last update" } dd { span class=(if st.upd.last_ok { "ok-t" } else { "err-t" }) { (st.upd.last) } } }
                    }
                }
                div.panel-f {
                    @if enabled {
                        button.btn.btn-primary name="action" value="save" { (ic("check")) "Save & reconnect" } " "
                        button.btn name="action" value="disable" { (ic("power")) "Disable" } " "
                    } @else {
                        button.btn.btn-primary name="action" value="enable" { (ic("power")) "Enable tunnel" } " "
                    }
                    button.btn name="action" value="check" { (ic("refresh")) "Check for updates" }
                    @if upd_avail { " " button.btn name="action" value="update" { (ic("download")) "Update now" } }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn rel(digest: Option<&str>, notes: &str) -> serde_json::Value {
        let mut asset = json!({"name": "cloudflared-linux-amd64"});
        if let Some(d) = digest {
            asset["digest"] = json!(d);
        }
        json!({"tag_name": "2026.11.0", "draft": false, "prerelease": false,
               "assets": [asset], "body": notes})
    }

    #[test]
    fn release_checksums() {
        let h = "a".repeat(64);
        let o = "b".repeat(64);
        let notes = format!("### SHA256 Checksums:\ncloudflared-linux-amd64: {h}\n");
        // both agree
        let r = rel(Some(&format!("sha256:{h}")), &notes);
        assert_eq!(
            super::parse_release(&r, "amd64").unwrap(),
            ("2026.11.0".into(), h.clone())
        );
        // either alone is enough
        assert!(super::parse_release(&rel(None, &notes), "amd64").is_ok());
        assert!(super::parse_release(&rel(Some(&format!("sha256:{h}")), ""), "amd64").is_ok());
        // disagreement, nothing, junk, wrong arch, prerelease
        assert!(super::parse_release(&rel(Some(&format!("sha256:{o}")), &notes), "amd64").is_err());
        assert!(super::parse_release(&rel(None, ""), "amd64").is_err());
        assert!(super::parse_release(&rel(Some("sha256:zz"), ""), "amd64").is_err());
        assert!(super::parse_release(&rel(Some(&format!("sha256:{h}")), &notes), "arm64").is_err());
        let mut p = rel(Some(&format!("sha256:{h}")), &notes);
        p["prerelease"] = json!(true);
        assert!(super::parse_release(&p, "amd64").is_err());
        let mut t = rel(Some(&format!("sha256:{h}")), &notes);
        t["tag_name"] = json!("../../evil");
        assert!(super::parse_release(&t, "amd64").is_err());
    }

    #[test]
    fn tokens() {
        assert!(super::valid_token("eyJhIjoiZmFrZWZha2VmYWtlZmFrZSJ9"));
        assert!(
            !super::valid_token("short") && !super::valid_token("has space has space has space")
        );
    }
}
