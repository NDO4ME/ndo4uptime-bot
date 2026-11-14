//! Optional Tailscale integration, so private services (tailnet devices and LANs behind a subnet
//! router) can be monitored like any public one.
//!
//! * `tailscaled` runs in **userspace-networking** mode as an unprivileged child process: no
//!   `/dev/net/tun`, no `NET_ADMIN`, no root, and the read-only container stays read-only.
//! * It exposes a SOCKS5 proxy on `127.0.0.1:1055` only; monitors that need the tailnet dial
//!   through it (HTTP and Browser via the HTTP client, TCP via a minimal SOCKS5 client, ping via
//!   `tailscale ping`).
//! * The node is **shielded** (no inbound connections) and never uploads client logs.
//! * Sign in with a one-time auth key or an interactive login link. The key is read from a
//!   0600 file in the tmpfs (never from argv), is removed from the database once connected, and
//!   is never rendered back.
//! * Auto-update (on by default): the client is fetched from `pkgs.tailscale.com`, verified
//!   against the published SHA-256, installed side by side, health-checked after the restart and
//!   rolled back automatically if the node does not come back.

use crate::view::*;
use crate::App;
use maud::{html, Markup};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::timeout;

pub const SOCKS: &str = "127.0.0.1:1055";
const SOCK_PATH: &str = "/tmp/tailscaled.sock";
const KEY_PATH: &str = "/tmp/ndo4-ts-authkey";
const RELEASES: &str = "https://pkgs.tailscale.com/stable/";
const MAX_DOWNLOAD: u64 = 160 * 1024 * 1024;
const MAX_BINARY: u64 = 200 * 1024 * 1024;
const DEFAULT_HOST: &str = "ndo4uptime";

static UP: AtomicBool = AtomicBool::new(false);
/// Set when the installed tailscaled rejects `--encrypt-state` (a daemon from before TPM sealing).
static NO_ENCRYPT_FLAG: AtomicBool = AtomicBool::new(false);
static CLI: Mutex<String> = Mutex::new(String::new());

/// True while the node is connected to the tailnet (set by the supervisor).
pub fn is_up() -> bool {
    UP.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------ shared state
#[derive(Clone, Default)]
pub struct Peer {
    pub name: String,
    pub ip: String,
    pub online: bool,
    pub os: String,
    pub routes: Vec<String>,
}

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
    /// off | starting | login | approval | connected | error
    pub phase: &'static str,
    pub detail: String,
    pub auth_url: String,
    pub version: String,
    pub me: String,
    pub ips: Vec<String>,
    pub tailnet: String,
    pub peers: Vec<Peer>,
    pub health: Vec<String>,
    pub upd: Upd,
}
pub type Shared = Mutex<State>;

fn upd_state(app: &App, f: impl FnOnce(&mut State)) {
    f(&mut app.ts.lock().unwrap_or_else(|e| e.into_inner()));
}

fn set_phase(app: &App, phase: &'static str, detail: impl Into<String>) {
    upd_state(app, |s| {
        s.phase = phase;
        s.detail = detail.into();
        if phase == "off" || phase == "error" {
            *s = State {
                phase,
                detail: std::mem::take(&mut s.detail),
                upd: std::mem::take(&mut s.upd),
                ..Default::default()
            };
        }
    });
    UP.store(phase == "connected", Ordering::Relaxed);
}

// ------------------------------------------------------------------ validation
pub fn valid_key(k: &str) -> bool {
    k.starts_with("tskey-")
        && (12..=300).contains(&k.len())
        && k.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn valid_hostname(h: &str) -> bool {
    (1..=63).contains(&h.len())
        && !h.starts_with('-')
        && !h.ends_with('-')
        && h.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Tailnet addresses: 100.64.0.0/10, fd7a:115c:a1e0::/48 and MagicDNS names under `.ts.net`.
pub fn is_tailnet(host: &str) -> bool {
    let h = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if h.ends_with(".ts.net") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        Ok(IpAddr::V6(a)) => a.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
        Err(_) => false,
    }
}

/// Subnets that tailnet peers route for us (e.g. 10.0.0.0/8), refreshed with every status poll.
static ROUTES: Mutex<Vec<(IpAddr, u8)>> = Mutex::new(Vec::new());

fn parse_cidr(c: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = c.split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let p: u8 = p.parse().ok().filter(|p| *p <= max)?;
    Some((ip, p))
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    let (a, b): (u128, u128) = match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b)),
        _ => return false,
    };
    let width = if ip.is_ipv4() { 32 } else { 128 };
    let shift = width - bits as u32;
    shift >= width || (a >> shift) == (b >> shift)
}

/// True when `host` is an address inside a subnet one of our tailnet peers routes.
fn in_routes(host: &str) -> bool {
    let Ok(ip) = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
    else {
        return false;
    };
    ROUTES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(n, b)| in_cidr(ip, *n, *b))
}

/// Whether a monitor's traffic should go through Tailscale: 0 automatic (tailnet addresses and
/// addresses inside subnets a peer routes), 1 always, 2 never.
pub fn via(net: i64, host: &str) -> bool {
    match net {
        1 => true,
        2 => false,
        _ => is_tailnet(host) || (is_up() && in_routes(host)),
    }
}

/// Same for ping: ICMP cannot cross a userspace node into a subnet, so automatic mode keeps
/// subnet addresses on the normal network and only tailnet devices use `tailscale ping`.
pub fn via_ping(net: i64, host: &str) -> bool {
    match net {
        1 => true,
        2 => false,
        _ => is_tailnet(host),
    }
}

fn ver(s: &str) -> (u32, u32, u32) {
    let mut it = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

// ------------------------------------------------------------------ settings
fn on(app: &App, key: &str) -> bool {
    app.db.setting(key) != "0"
}
fn enabled(app: &App) -> bool {
    app.db.setting("ts_enabled") == "1"
}
fn hostname(app: &App) -> String {
    let h = app.db.setting("ts_hostname");
    if valid_hostname(&h) {
        h
    } else {
        DEFAULT_HOST.into()
    }
}
fn prefs_key(app: &App) -> String {
    format!(
        "{}|{}|{}",
        hostname(app),
        on(app, "ts_accept_routes"),
        on(app, "ts_accept_dns")
    )
}

// ------------------------------------------------------------------ binaries
fn root(app: &App) -> PathBuf {
    Path::new(&app.cfg.data).join("tailscale")
}

/// (tailscaled, tailscale). An updated copy under the data volume wins unless the image
/// itself ships something newer.
fn bins(app: &App) -> (String, String) {
    let cur = root(app).join("bin").join("current");
    let installed = std::fs::read_link(&cur)
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
    if let Some(v) = installed {
        let newer = app.cfg.ts_baked.is_empty() || ver(&v) >= ver(&app.cfg.ts_baked);
        let (d, c) = (cur.join("tailscaled"), cur.join("tailscale"));
        if newer && d.is_file() && c.is_file() {
            return (
                d.to_string_lossy().into_owned(),
                c.to_string_lossy().into_owned(),
            );
        }
    }
    (app.cfg.tailscaled.clone(), app.cfg.tailscale.clone())
}

fn remember_cli(path: &str) {
    *CLI.lock().unwrap_or_else(|e| e.into_inner()) = path.to_string();
}
fn cli_path() -> String {
    CLI.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn clean_cmd(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.env_clear()
        .env("HOME", "/tmp")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    c
}

/// Runs `tailscale --socket=… <args>`; returns stdout, or the trimmed output on failure.
async fn cli(app: &App, args: &[&str], secs: u64) -> Result<String, String> {
    let (_, bin) = bins(app);
    let mut c = clean_cmd(&bin);
    c.arg(format!("--socket={SOCK_PATH}")).args(args);
    match timeout(Duration::from_secs(secs), c.output()).await {
        Err(_) => Err("timed out".into()),
        Ok(Err(e)) => Err(format!("cannot run tailscale: {}", e.kind())),
        Ok(Ok(o)) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(Ok(o)) => {
            let text = if o.stderr.is_empty() {
                &o.stdout
            } else {
                &o.stderr
            };
            Err(clip(&String::from_utf8_lossy(text), 240))
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    s.trim()
        .lines()
        .next_back()
        .unwrap_or("")
        .chars()
        .take(n)
        .collect()
}

fn flag(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

// ------------------------------------------------------------------ status
struct Snap {
    backend: String,
    auth_url: String,
}

fn snapshot(app: &App, v: &Value) -> Snap {
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let strs = |x: &Value| -> Vec<String> {
        x.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|i| i.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    // Subnets reachable through peers: what they are primary for, plus any non-host prefix we
    // were allowed to send them. Exit-node defaults (/0) and tailnet addresses are not subnets.
    let mut nets: Vec<(IpAddr, u8)> = Vec::new();
    if on(app, "ts_accept_routes") {
        if let Some(m) = v["Peer"].as_object() {
            for p in m.values() {
                for c in strs(&p["PrimaryRoutes"])
                    .into_iter()
                    .chain(strs(&p["AllowedIPs"]))
                {
                    if let Some((ip, b)) = parse_cidr(&c) {
                        let host = b == if ip.is_ipv4() { 32 } else { 128 };
                        if b > 0 && !host && !is_tailnet(&ip.to_string()) && nets.len() < 256 {
                            nets.push((ip, b));
                        }
                    }
                }
            }
        }
    }
    *ROUTES.lock().unwrap_or_else(|e| e.into_inner()) = nets;
    let mut peers: Vec<Peer> = v["Peer"]
        .as_object()
        .map(|m| {
            m.values()
                .map(|p| Peer {
                    name: {
                        let h = s(&p["HostName"]);
                        if h.is_empty() {
                            s(&p["DNSName"]).trim_end_matches('.').to_string()
                        } else {
                            h
                        }
                    },
                    ip: strs(&p["TailscaleIPs"])
                        .into_iter()
                        .next()
                        .unwrap_or_default(),
                    online: p["Online"].as_bool().unwrap_or(false),
                    os: s(&p["OS"]),
                    routes: strs(&p["PrimaryRoutes"]),
                })
                .collect()
        })
        .unwrap_or_default();
    peers.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    peers.truncate(200);
    let snap = Snap {
        backend: s(&v["BackendState"]),
        auth_url: s(&v["AuthURL"]),
    };
    upd_state(app, |st| {
        st.version = s(&v["Version"]);
        st.me = s(&v["Self"]["HostName"]);
        st.ips = strs(&v["TailscaleIPs"]);
        st.tailnet = s(&v["CurrentTailnet"]["Name"]);
        st.health = strs(&v["Health"]).into_iter().take(5).collect();
        st.peers = peers;
    });
    snap
}

// ------------------------------------------------------------------ supervisor
async fn pause(app: &App, secs: u64) {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        _ = app.ts_wake.notified() => {}
    }
}

fn write_key(key: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(KEY_PATH)?;
    f.write_all(key.as_bytes())
}

fn up_args(app: &App) -> Vec<String> {
    vec![
        "up".into(),
        "--reset".into(),
        format!("--hostname={}", hostname(app)),
        format!("--accept-routes={}", flag(on(app, "ts_accept_routes"))),
        format!("--accept-dns={}", flag(on(app, "ts_accept_dns"))),
        "--shields-up=true".into(),
    ]
}

const STATE_FILE: &str = "tailscaled.state";
const SEALED_NOTE: &str = "The saved Tailscale login was sealed to a TPM that is no longer available. It was set aside (tailscaled.state.tpm-sealed.bak) and this node needs to sign in again.";

/// True for a state file that tailscaled encrypted with the machine's TPM.
fn is_tpm_sealed(path: &Path) -> bool {
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"tpmseal:"
}

/// Moves an unreadable state file next to itself so a fresh login can start; nothing is deleted.
fn set_aside(path: &Path) -> bool {
    set_aside_as(path, "tpm-sealed")
}

fn set_aside_as(path: &Path, tag: &str) -> bool {
    let dest = path.with_file_name(format!("{STATE_FILE}.{tag}.bak"));
    let ok = std::fs::rename(path, dest).is_ok();
    if ok {
        eprintln!("Tailscale: the saved login is sealed to a TPM that is not available; set it aside, signing in again.");
    }
    ok
}

/// Which tailscaled stderr lines are worth showing as the reason for an exit. The plain
/// "TPM: error opening" probe note is printed on every start of a healthy node without a TPM.
fn failure_line(l: &str) -> bool {
    let low = l.to_ascii_lowercase();
    if low.contains("tpm: error opening") && !low.contains("unseal") && !low.contains("fatal") {
        return false;
    }
    low.contains("fatal")
        || low.contains("error")
        || low.contains("panic")
        || low.contains("unseal")
        || low.contains("not defined")
}

const UNREADABLE_NOTE: &str = "tailscaled kept stopping right after it started, so the saved login was set aside (tailscaled.state.unreadable.bak) and this node needs to sign in again.";

pub async fn run(app: Arc<App>) {
    let mut backoff = 3u64;
    // Consecutive daemon exits within seconds of starting: a saved state that cannot be used.
    let mut quick_exits = 0u32;
    loop {
        if !enabled(&app) {
            set_phase(&app, "off", "");
            app.ts_wake.notified().await;
            backoff = 3;
            continue;
        }
        set_phase(&app, "starting", "");
        let (daemon, cli_bin) = bins(&app);
        remember_cli(&cli_bin);
        let state_dir = root(&app).join("state");
        if std::fs::create_dir_all(&state_dir).is_err() {
            set_phase(&app, "error", "cannot create the Tailscale state directory");
            pause(&app, 60).await;
            continue;
        }
        let _ = std::fs::set_permissions(
            root(&app),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        );
        let state_file = state_dir.join(STATE_FILE);
        if is_tpm_sealed(&state_file) && !Path::new("/dev/tpmrm0").exists() {
            // Sealed by an earlier tailscaled while a TPM was present; without it nothing can
            // read the login, so keep the file aside and sign in again instead of failing forever.
            if set_aside(&state_file) {
                set_phase(&app, "starting", SEALED_NOTE);
            }
        }
        let _ = std::fs::remove_file(SOCK_PATH);
        let mut cmd = clean_cmd(&daemon);
        cmd.args([
            "--tun=userspace-networking",
            &format!("--socks5-server={SOCKS}"),
            &format!("--statedir={}", state_dir.display()),
            &format!("--socket={SOCK_PATH}"),
        ])
        // Recent tailscaled seals its state to the machine's TPM whenever one is present. The
        // login would then be unreadable after a reboot, a VM or host change, or whenever the
        // device is not passed to the container, so the state stays an ordinary 0600 file.
        // (Very old daemons do not know the flag; that is detected below and it is left out.)
        .args((!NO_ENCRYPT_FLAG.load(Ordering::Relaxed)).then_some("--encrypt-state=false"))
        .env("TS_NO_LOGS_NO_SUPPORT", "true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let msg = if e.kind() == std::io::ErrorKind::NotFound {
                    "tailscaled binary not found (the Docker image bundles it; set NDO4_TAILSCALED otherwise)".to_string()
                } else {
                    format!("could not start tailscaled: {e}")
                };
                set_phase(&app, "error", msg);
                pause(&app, 60).await;
                continue;
            }
        };
        let last_line = Arc::new(Mutex::new(String::new()));
        // The newest stderr line of any kind, used when nothing looked like an error: a daemon
        // that exits on its own should still say why instead of a bare "exited".
        let any_line = Arc::new(Mutex::new(String::new()));
        if let Some(err) = child.stderr.take() {
            let keep = last_line.clone();
            let any = any_line.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let short: String = l.chars().take(240).collect();
                    if failure_line(&l) {
                        *keep.lock().unwrap_or_else(|e| e.into_inner()) = short.clone();
                    }
                    if !l.trim().is_empty() {
                        *any.lock().unwrap_or_else(|e| e.into_inner()) = short;
                    }
                }
            });
        }
        let started = Instant::now();
        let mut login: Option<Child> = None;
        let mut applied = String::new();
        let mut key_retry = Instant::now();
        let mut stuck_since: Option<Instant> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(4));
        let restart = loop {
            tokio::select! {
                _ = tick.tick() => {
                    drive(&app, &mut login, &mut applied, &mut key_retry, started).await;
                    if is_up() { backoff = 3; }
                    // Self-heal: a node that has not come up on its own (and is not simply
                    // waiting for someone to open the sign-in link) gets a fresh daemon.
                    if is_up() {
                        stuck_since = None;
                    } else if !waiting_for_user(&app) {
                        let since = *stuck_since.get_or_insert_with(Instant::now);
                        if since.elapsed() > Duration::from_secs(75) { break true; }
                    } else {
                        stuck_since = None;
                    }
                }
                _ = child.wait() => break false,
                _ = app.ts_wake.notified() => break true,
            }
        };
        drop(login);
        let _ = child.kill().await;
        UP.store(false, Ordering::Relaxed);
        if restart {
            backoff = 3;
            continue; // settings or binary changed: start over immediately
        }
        let mut why = last_line.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if why.is_empty() {
            why = any_line.lock().unwrap_or_else(|e| e.into_inner()).clone();
        }
        let low = why.to_ascii_lowercase();
        if !NO_ENCRYPT_FLAG.load(Ordering::Relaxed)
            && low.contains("encrypt-state")
            && (low.contains("not defined") || low.contains("unknown flag"))
        {
            // An older tailscaled that does not know the flag: start it without.
            NO_ENCRYPT_FLAG.store(true, Ordering::Relaxed);
            backoff = 3;
            continue;
        }
        if why.to_ascii_lowercase().contains("tpm")
            && is_tpm_sealed(&state_file)
            && set_aside(&state_file)
        {
            // The saved login cannot be unsealed (TPM missing or replaced): start clean right away.
            set_phase(&app, "starting", SEALED_NOTE);
            backoff = 3;
            continue;
        }
        if started.elapsed() < Duration::from_secs(30) {
            quick_exits += 1;
        } else {
            quick_exits = 0;
        }
        if quick_exits >= 3 && state_file.exists() && set_aside_as(&state_file, "unreadable") {
            // Whatever the reason, a login that makes the daemon die at once will never recover
            // by itself; keep it aside (nothing is deleted) and start clean.
            quick_exits = 0;
            set_phase(&app, "starting", UNREADABLE_NOTE);
            backoff = 3;
            continue;
        }
        set_phase(
            &app,
            "error",
            if why.is_empty() {
                "tailscaled exited".into()
            } else {
                why
            },
        );
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 3;
        }
        pause(&app, backoff).await;
        backoff = (backoff * 2).min(120);
    }
}

/// One supervision step: read status, log in when needed, apply preferences.
/// True while the node legitimately waits for a person: a sign-in link or an admin approval.
fn waiting_for_user(app: &App) -> bool {
    app.ts
        .lock()
        .map(|s| matches!(s.phase, "login" | "approval"))
        .unwrap_or(false)
}

async fn drive(
    app: &App,
    login: &mut Option<Child>,
    applied: &mut String,
    key_retry: &mut Instant,
    started: Instant,
) {
    let raw = match cli(app, &["status", "--json"], 8).await {
        Ok(t) => t,
        Err(_) => {
            set_phase(app, "starting", "");
            return;
        }
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    let snap = snapshot(app, &v);
    if let Some(c) = login.as_mut() {
        if matches!(c.try_wait(), Ok(Some(_))) {
            *login = None;
        }
    }
    match snap.backend.as_str() {
        "Running" => {
            *login = None;
            set_phase(app, "connected", "");
            if !app.db.setting("ts_authkey").is_empty() {
                app.db.set_setting("ts_authkey", ""); // one-time use: do not keep it
            }
            let want = prefs_key(app);
            if *applied != want {
                let args = [
                    "set".to_string(),
                    format!("--hostname={}", hostname(app)),
                    format!("--accept-routes={}", flag(on(app, "ts_accept_routes"))),
                    format!("--accept-dns={}", flag(on(app, "ts_accept_dns"))),
                    "--shields-up=true".to_string(),
                ];
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                match cli(app, &refs, 20).await {
                    Ok(_) => *applied = want,
                    Err(e) => set_phase(app, "connected", format!("could not apply settings: {e}")),
                }
            }
        }
        "NeedsMachineAuth" => set_phase(
            app,
            "approval",
            "Approve this device in the Tailscale admin console (Machines).",
        ),
        "NoState" | "Starting" if started.elapsed() < Duration::from_secs(12) => {
            // tailscaled is still loading its saved login: do not start a new one over it.
            set_phase(app, "starting", "");
        }
        "NeedsLogin" | "Stopped" | "NoState" | "Starting" => {
            let key = app.db.setting("ts_authkey");
            if !key.is_empty() && Instant::now() >= *key_retry {
                set_phase(app, "starting", "Signing in with the auth key…");
                let _ = write_key(&key);
                let mut args = up_args(app);
                args.push(format!("--auth-key=file:{KEY_PATH}"));
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                let res = cli(app, &refs, 60).await;
                let _ = std::fs::remove_file(KEY_PATH);
                if let Err(e) = res {
                    *key_retry = Instant::now() + Duration::from_secs(90);
                    set_phase(app, "login", format!("Auth key rejected: {e}"));
                }
                return;
            }
            if key.is_empty() && login.is_none() {
                let (_, bin) = bins(app);
                let mut c = clean_cmd(&bin);
                c.arg(format!("--socket={SOCK_PATH}"))
                    .args(up_args(app))
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                *login = c.spawn().ok();
            }
            let url = snap.auth_url;
            if url.starts_with("https://") && !url.contains(char::is_whitespace) {
                upd_state(app, |s| {
                    s.phase = "login";
                    s.auth_url = url;
                    if !s.detail.starts_with("Auth key") {
                        s.detail.clear();
                    }
                });
            } else if app.ts.lock().map(|s| s.phase != "login").unwrap_or(true) {
                set_phase(app, "starting", "Waiting for the sign-in link…");
            }
            UP.store(false, Ordering::Relaxed);
        }
        _ => set_phase(app, "starting", ""),
    }
}

/// Signs the node out of the tailnet and disables the integration.
pub async fn logout(app: &App) -> Result<(), String> {
    cli(app, &["logout"], 20).await?;
    app.db.set_setting("ts_enabled", "0");
    app.ts_wake.notify_one();
    Ok(())
}

// ------------------------------------------------------------------ routing for checks
/// Opens a TCP connection to `host:port` through the Tailscale SOCKS5 proxy.
pub async fn socks_connect(host: &str, port: u16) -> Result<TcpStream, String> {
    if !is_up() {
        return Err("Tailscale is not connected".into());
    }
    socks_connect_via(SOCKS, host, port).await
}

async fn socks_connect_via(proxy: &str, host: &str, port: u16) -> Result<TcpStream, String> {
    let io = |_e: std::io::Error| "Tailscale proxy unavailable".to_string();
    let mut s = TcpStream::connect(proxy).await.map_err(io)?;
    s.write_all(&[5, 1, 0]).await.map_err(io)?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await.map_err(io)?;
    if hello != [5, 0] {
        return Err("Tailscale proxy refused the handshake".into());
    }
    let mut req = vec![5u8, 1, 0];
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Err(_) => {
            if host.is_empty() || host.len() > 255 {
                return Err("Invalid host name".into());
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    if head[1] != 0 {
        return Err(match head[1] {
            2 => "Not allowed by the tailnet policy",
            3 => "Network unreachable through Tailscale",
            4 => "Host unreachable through Tailscale",
            5 => "Connection refused",
            6 => "Timed out",
            _ => "Tailscale proxy error",
        }
        .into());
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io)?;
            l[0] as usize + 2
        }
        _ => return Err("Tailscale proxy error".into()),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.map_err(io)?;
    Ok(s)
}

/// `tailscale ping` for a tailnet device; ICMP cannot cross a userspace node to a subnet.
pub async fn ping(host: &str, secs: u64) -> Result<(i64, String), String> {
    if !is_up() {
        return Err("Tailscale is not connected".into());
    }
    if !is_tailnet(host) && host.parse::<IpAddr>().is_ok() {
        return Err(
            "Ping cannot reach subnet addresses through Tailscale; use a TCP or HTTP check".into(),
        );
    }
    let bin = cli_path();
    if bin.is_empty() {
        return Err("Tailscale is not ready".into());
    }
    let mut c = clean_cmd(&bin);
    c.arg(format!("--socket={SOCK_PATH}")).args([
        "ping",
        "--c=1",
        &format!("--timeout={secs}s"),
        "--",
        host,
    ]);
    let out = match timeout(Duration::from_secs(secs + 3), c.output()).await {
        Err(_) => return Err("Timed out".into()),
        Ok(Err(_)) => return Err("Tailscale is not ready".into()),
        Ok(Ok(o)) => o,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    match parse_pong(&text) {
        Some(r) if out.status.success() => Ok(r),
        _ => Err("No reply from the device".into()),
    }
}

fn parse_pong(text: &str) -> Option<(i64, String)> {
    let line = text.lines().find(|l| l.starts_with("pong from"))?;
    let ms = line.rsplit(" in ").next()?.trim().strip_suffix("ms")?;
    let rtt = ms.parse::<f64>().ok()?;
    let via = line
        .split(" via ")
        .nth(1)
        .and_then(|r| r.split(" in ").next())
        .unwrap_or("tailnet");
    Some((
        (rtt.round() as i64).max(1),
        format!("Reply via {}", via.chars().take(60).collect::<String>()),
    ))
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

async fn latest() -> Result<(String, String), String> {
    let body = http()?
        .get(format!("{RELEASES}?mode=json"))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| "could not reach pkgs.tailscale.com".to_string())?
        .text()
        .await
        .map_err(|_| "unexpected release data".to_string())?;
    let v: Value =
        serde_json::from_str(&body).map_err(|_| "unexpected release data".to_string())?;
    let version = v["TarballsVersion"].as_str().unwrap_or("").to_string();
    let file = v["Tarballs"][arch()].as_str().unwrap_or("").to_string();
    let safe = |s: &str| {
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    };
    if ver(&version) == (0, 0, 0) || file.is_empty() || !safe(&file) || !safe(&version) {
        return Err("unexpected release data".into());
    }
    Ok((version, file))
}

fn current_version(app: &App) -> String {
    let running = app.ts.lock().map(|s| s.version.clone()).unwrap_or_default();
    if !running.is_empty() {
        return running;
    }
    let (_, bin) = bins(app);
    if bin.starts_with(&app.cfg.data) {
        return std::fs::read_link(root(app).join("bin").join("current"))
            .ok()
            .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
    }
    app.cfg.ts_baked.clone()
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
    let mut f = tokio::fs::File::create(dest)
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

fn extract(tgz: &Path, out: &Path, top: &str) -> Result<(), String> {
    let file = std::fs::File::open(tgz).map_err(|e| e.to_string())?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut found = 0;
    for entry in ar.entries().map_err(|e| e.to_string())? {
        let mut e = entry.map_err(|e| e.to_string())?;
        let path = e.path().map_err(|e| e.to_string())?.into_owned();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if parent != top
            || !matches!(name.as_str(), "tailscale" | "tailscaled")
            || !e.header().entry_type().is_file()
        {
            continue;
        }
        let mut w = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o755)
            .open(out.join(&name))
            .map_err(|e| e.to_string())?;
        std::io::copy(&mut (&mut e).take(MAX_BINARY), &mut w).map_err(|e| e.to_string())?;
        found += 1;
    }
    if found == 2 {
        Ok(())
    } else {
        Err("archive does not contain tailscale and tailscaled".into())
    }
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

async fn install(app: &App, version: &str, file: &str) -> Result<(), String> {
    let bin_dir = root(app).join("bin");
    std::fs::create_dir_all(&bin_dir)
        .map_err(|_| "cannot create the install directory".to_string())?;
    let tgz = bin_dir.join("download.tgz");
    let url = format!("{RELEASES}{file}");
    let want = http()?
        .get(format!("{url}.sha256"))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| "could not fetch the published checksum".to_string())?
        .text()
        .await
        .map_err(|_| "could not read the published checksum".to_string())?;
    let want = want
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if want.len() != 64 || !want.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("published checksum is malformed".into());
    }
    let res = async {
        download(&url, &tgz, &want).await?;
        let (stage, top) = (
            bin_dir.join(format!("{version}.tmp")),
            file.trim_end_matches(".tgz").to_string(),
        );
        let _ = std::fs::remove_dir_all(&stage);
        let (t, s) = (tgz.clone(), stage.clone());
        tokio::task::spawn_blocking(move || extract(&t, &s, &top))
            .await
            .map_err(|_| "extraction failed".to_string())??;
        let out = timeout(
            Duration::from_secs(10),
            clean_cmd(&stage.join("tailscaled").to_string_lossy())
                .arg("--version")
                .output(),
        )
        .await
        .map_err(|_| "new tailscaled does not start".to_string())?
        .map_err(|_| "new tailscaled does not start".to_string())?;
        if !String::from_utf8_lossy(&out.stdout).contains(version) {
            return Err("new tailscaled reports an unexpected version".into());
        }
        let dest = bin_dir.join(version);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::rename(&stage, &dest).map_err(|_| "cannot install the new version".to_string())
    }
    .await;
    let _ = std::fs::remove_file(&tgz);
    res
}

fn prune(app: &App, keep: &[&str]) {
    let Ok(rd) = std::fs::read_dir(root(app).join("bin")) else {
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

/// Installs the newest release, restarts the node and rolls back if it does not come back.
pub async fn update(app: &App, auto: bool) {
    let claimed = app
        .ts
        .lock()
        .map(|mut s| !std::mem::replace(&mut s.upd.busy, true))
        .unwrap_or(false);
    if !claimed {
        return;
    }
    let (version, file) = match latest().await {
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
    if let Err(e) = install(app, &version, &file).await {
        return record(app, false, format!("{tag} to {version} failed: {e}"));
    }
    let bin_dir = root(app).join("bin");
    let prev = std::fs::read_link(bin_dir.join("current"))
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()));
    if point_current(&bin_dir, Some(&version)).is_err() {
        return record(
            app,
            false,
            format!("{tag} to {version} failed: cannot switch versions."),
        );
    }
    if !enabled(app) {
        prune(app, &[&version]);
        return record(
            app,
            true,
            format!("{tag}: {version} installed; it starts with the next connection."),
        );
    }
    let was_up = is_up();
    app.ts_wake.notify_one(); // restart tailscaled on the new binary
    if was_up {
        let deadline = Instant::now() + Duration::from_secs(120);
        tokio::time::sleep(Duration::from_secs(8)).await;
        while !is_up() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        if !is_up() {
            let _ = point_current(&bin_dir, prev.as_deref());
            app.ts_wake.notify_one();
            prune(app, &[prev.as_deref().unwrap_or("")]);
            return record(
                app,
                false,
                format!("{tag} to {version} was rolled back: the node did not reconnect."),
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

/// Background auto-updater: a first look shortly after start, then once a day. Runs only when
/// the integration is enabled and the automatic-update switch is on (default).
pub async fn updater(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(300)).await;
    loop {
        if enabled(&app) && on(&app, "ts_auto_update") {
            update(&app, true).await;
        }
        tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    }
}

// ------------------------------------------------------------------ settings panel
fn ago_or(ts: i64) -> String {
    if ts > 0 {
        ago(ts)
    } else {
        "never".into()
    }
}

pub fn panel(app: &App, csrf: &str) -> Markup {
    let st = app.ts.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let is_on = enabled(app);
    let has_key = !app.db.setting("ts_authkey").is_empty();
    let (cls, label) = match st.phase {
        "connected" => ("success", "connected"),
        "starting" => ("info", "connecting"),
        "login" => ("warning", "sign-in required"),
        "approval" => ("warning", "awaiting approval"),
        "error" => ("failed", "error"),
        _ => ("warning", "off"),
    };
    let current = current_version(app);
    let upd_avail =
        !st.upd.latest.is_empty() && !current.is_empty() && ver(&st.upd.latest) > ver(&current);
    let online = st.peers.iter().filter(|p| p.online).count();
    let refresh = matches!(st.phase, "starting" | "approval").then_some("5000");
    html! {
        section.panel data-autorefresh=[refresh] {
            header.panel-h { h2 { (ic("link")) "Tailscale" } div.panel-tools { span class=(format!("badge {cls}")) { (label) } } }
            form method="post" action="/settings/tailscale" autocomplete="off" {
                (csrf_input(csrf))
                div.panel-b {
                    p.hint { "Monitor private services — tailnet devices and networks behind a subnet router — from this container. Runs in userspace mode: no root, no TUN device, no extra privileges; the node accepts no inbound connections." }
                    @if !st.detail.is_empty() { (msg(if st.phase == "error" { "err" } else { "warn" }, &st.detail, false)) }
                    @if st.phase == "login" && !st.auth_url.is_empty() {
                        (msg("info", "Open the sign-in link to add this device to your tailnet, then reload this page.", false))
                        p { a.btn.btn-primary href=(st.auth_url) target="_blank" rel="noopener noreferrer" { (ic("external")) "Authorise this device" } }
                    }
                    @if st.phase == "connected" {
                        dl.props {
                            dt { "Device" } dd { (st.me) @if let Some(ip) = st.ips.first() { " " span.mono.faint { (ip) } } }
                            @if !st.tailnet.is_empty() { dt { "Tailnet" } dd { (st.tailnet) } }
                            dt { "Devices" } dd { (online) " online of " (st.peers.len()) }
                            dt { "Client" } dd.mono { (ver_label(&st.version)) }
                        }
                        @for h in &st.health { (msg("warn", h, false)) }
                    }
                    @if !is_on || st.phase == "login" || st.phase == "starting" {
                        label.field { span.lbl { "Auth key (optional)" }
                            input type="password" name="authkey" maxlength="300" spellcheck="false" autocomplete="off"
                                placeholder=(if has_key { "•••••••• saved — used for the next sign-in" } else { "tskey-auth-…" });
                            span.hint { "Create a one-time key under Tailscale admin → Settings → Keys. Leave empty to sign in with a link instead. The key is never shown again and is removed once connected." } }
                    }
                    label.field { span.lbl { "Device name" } input name="hostname" value=(hostname(app)) maxlength="63" spellcheck="false" autocomplete="off" pattern="[a-z0-9]([a-z0-9\\-]*[a-z0-9])?"; }
                    label.check { input type="checkbox" name="accept_routes" value="1" checked[on(app, "ts_accept_routes")]; span { "Use subnet routes" span.hint { "Reach LAN ranges advertised by your subnet routers." } } }
                    label.check { input type="checkbox" name="accept_dns" value="1" checked[on(app, "ts_accept_dns")]; span { "Resolve MagicDNS names" span.hint { "Lets monitors use names such as " code { "nas.tailnet.ts.net" } ". Only the Tailscale proxy uses them; the container's own DNS is untouched." } } }
                    label.check { input type="checkbox" name="auto_update" value="1" checked[on(app, "ts_auto_update")]; span { "Update Tailscale automatically" span.hint { "Downloads verified releases from pkgs.tailscale.com once a day and rolls back if the node does not reconnect." } } }
                    dl.props {
                        dt { "Installed" } dd.mono { @if current.is_empty() { "–" } @else { (ver_label(&current)) } }
                        dt { "Latest" } dd { @if st.upd.latest.is_empty() { span.faint { "not checked" } } @else { span.mono { (st.upd.latest) } @if upd_avail { " " span class="badge info" { "update available" } } } " " span.faint.small { "checked " (ago_or(st.upd.checked)) } }
                        @if !st.upd.last.is_empty() { dt { "Last update" } dd { span class=(if st.upd.last_ok { "ok-t" } else { "err-t" }) { (st.upd.last) } } }
                    }
                    p.hint { "In monitors, " b { "Network → Automatic" } " sends tailnet addresses (" code { "100.x.y.z" } ", " code { "*.ts.net" } ") and IP addresses inside subnets your peers route (e.g. " code { "10.0.0.0/8" } ") through Tailscale. Ping checks to subnet addresses are not possible; use TCP or HTTP. Choose " b { "Tailscale" } " to force it, e.g. for a LAN hostname." }
                }
                div.panel-f {
                    @if is_on {
                        button.btn.btn-primary name="action" value="save" { (ic("check")) "Save" } " "
                        button.btn name="action" value="disable" { (ic("power")) "Disable" } " "
                    } @else {
                        button.btn.btn-primary name="action" value="enable" { (ic("power")) "Enable Tailscale" } " "
                    }
                    button.btn name="action" value="check" { (ic("refresh")) "Check for updates" }
                    @if upd_avail { " " button.btn name="action" value="update" { (ic("download")) "Update now" } }
                }
            }
            @if is_on && st.phase == "connected" {
                div.panel-b {
                    h3.sub { "Devices" }
                    div.tbl-wrap { table.tbl {
                        thead { tr { th {} th { "Name" } th { "Address" } th { "Routes" } } }
                        tbody { @for p in st.peers.iter().take(50) { tr {
                            td { span class=(if p.online { "dot success" } else { "dot" }) {} }
                            td { (p.name) @if !p.os.is_empty() { " " span.faint.small { (p.os) } } }
                            td.mono { (p.ip) }
                            td.mono.small { @if p.routes.is_empty() { span.faint { "–" } } @else { (p.routes.join(", ")) } }
                        } } }
                    } }
                }
                div.panel-f {
                    form method="post" action="/settings/tailscale" class="js-confirm" data-confirm-title="Sign out of Tailscale" data-confirm="Remove this device from your tailnet? Monitors that use Tailscale will fail until you sign in again." {
                        (csrf_input(csrf)) input type="hidden" name="action" value="logout";
                        button.btn.btn-danger { (ic("logout")) "Sign out & disable" }
                    }
                }
            }
        }
    }
}

fn ver_label(v: &str) -> String {
    let (a, b, c) = ver(v);
    if (a, b, c) == (0, 0, 0) {
        "–".into()
    } else {
        format!("{a}.{b}.{c}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_probe_note_is_not_a_failure() {
        assert!(!failure_line(
            "TPM: error opening: stat /dev/tpmrm0: no such file or directory"
        ));
        assert!(failure_line("failed unseal encryption key with TPM: TPM: error opening: stat /dev/tpmrm0: no such file or directory"));
        assert!(failure_line("tailscaled: fatal: cannot load state"));
        assert!(failure_line(
            "flag provided but not defined: -encrypt-state"
        ));
        assert!(!failure_line("wgengine: Reconfig: configuring router"));
    }

    #[test]
    fn sealed_state_is_detected_and_set_aside() {
        let d = std::env::temp_dir().join(format!("ndo4-ts-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join(STATE_FILE);
        std::fs::write(&f, b"{\"_machinekey\":\"x\"}").unwrap();
        assert!(!is_tpm_sealed(&f));
        std::fs::write(&f, b"tpmseal:abcdef").unwrap();
        assert!(is_tpm_sealed(&f));
        assert!(set_aside(&f));
        assert!(!f.exists() && d.join("tailscaled.state.tpm-sealed.bak").exists());
        assert!(!is_tpm_sealed(&f));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn subnet_matching() {
        let (n, b) = parse_cidr("10.0.0.0/8").unwrap();
        assert!(in_cidr("10.200.1.2".parse().unwrap(), n, b));
        assert!(!in_cidr("11.0.0.1".parse().unwrap(), n, b));
        let (n, b) = parse_cidr("192.168.1.0/24").unwrap();
        assert!(in_cidr("192.168.1.77".parse().unwrap(), n, b));
        assert!(!in_cidr("192.168.2.1".parse().unwrap(), n, b));
        assert!(parse_cidr("10.0.0.0/33").is_none() && parse_cidr("x").is_none());
        // Automatic mode picks up a routed subnet once a peer advertises it.
        *ROUTES.lock().unwrap() = vec![parse_cidr("10.0.0.0/8").unwrap()];
        assert!(in_routes("10.1.2.3") && !in_routes("172.16.0.1") && !in_routes("example.com"));
        *ROUTES.lock().unwrap() = Vec::new();
    }

    #[test]
    fn addresses() {
        assert!(
            is_tailnet("100.101.102.103")
                && is_tailnet("100.64.0.1")
                && is_tailnet("100.127.255.254")
        );
        assert!(
            !is_tailnet("100.63.0.1") && !is_tailnet("100.128.0.1") && !is_tailnet("192.168.1.10")
        );
        assert!(is_tailnet("nas.tail1234.ts.net") && is_tailnet("NAS.TS.NET"));
        assert!(is_tailnet("fd7a:115c:a1e0::1") && !is_tailnet("fd00::1"));
        assert!(!is_tailnet("example.com"));
        assert!(via(0, "100.100.100.1") && !via(0, "10.0.0.1"));
        assert!(via(1, "10.0.0.1") && !via(2, "100.100.100.1"));
    }

    #[test]
    fn input_rules() {
        assert!(valid_key(
            "tskey-auth-kABCDEF1234-abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(
            !valid_key("tskey-")
                && !valid_key("auth-abcdefghijklmnop")
                && !valid_key("tskey-bad key value")
        );
        assert!(valid_hostname("ndo4uptime") && valid_hostname("a"));
        assert!(
            !valid_hostname("-x")
                && !valid_hostname("Upper")
                && !valid_hostname("a_b")
                && !valid_hostname("")
        );
        assert!(ver("1.104.5") > ver("1.98.12") && ver("1.104.5-t123-gabc") == (1, 104, 5));
    }

    #[test]
    fn pong() {
        let (ms, via) = parse_pong("pong from nas (100.64.0.2) via DERP(fra) in 23ms\n").unwrap();
        assert_eq!(ms, 23);
        assert!(via.contains("DERP"));
        assert!(parse_pong("ping \"x\" timed out").is_none());
    }

    #[test]
    fn status_json() {
        let app_less = serde_json::json!({"BackendState":"Running","Version":"1.104.5-tabc-gdef",
            "Self":{"HostName":"ndo"},"TailscaleIPs":["100.64.0.9"],
            "Peer":{"k1":{"HostName":"nas","Online":true,"TailscaleIPs":["100.64.0.2"],"PrimaryRoutes":["192.168.1.0/24"]}}});
        assert_eq!(app_less["Peer"]["k1"]["PrimaryRoutes"][0], "192.168.1.0/24");
        assert_eq!(ver_label("1.104.5-tabc-gdef"), "1.104.5");
    }

    #[tokio::test]
    async fn socks_handshake() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 3];
            s.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 5];
            s.read_exact(&mut h).await.unwrap();
            assert_eq!(&h[..4], &[5, 1, 0, 3]);
            let mut rest = vec![0u8; h[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..h[4] as usize], b"nas.ts.net");
            assert_eq!(&rest[h[4] as usize..], &443u16.to_be_bytes());
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        assert!(socks_connect_via(&addr, "nas.ts.net", 443).await.is_ok());

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 3];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let e = socks_connect_via(&addr, "100.64.0.2", 22)
            .await
            .unwrap_err();
        assert_eq!(e, "Connection refused");
    }
}
