mod ai;
mod auth;
mod checks;
mod db;
mod maint;
mod metrics;
mod pages;
mod sched;
mod serve;
mod store;
mod tailscale;
mod tunnel;
mod view;
mod web;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{middleware, Router};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub struct Config {
    pub bind: String,
    pub public_bind: String,
    pub cloudflared: String,
    pub tailscaled: String,
    pub tailscale: String,
    pub ts_baked: String,
    pub data: String,
    pub secure_cookie: bool,
    pub trust_proxy: bool,
    pub retention_days: i64,
    pub metrics_bind: Option<String>,
}

pub struct App {
    pub db: db::Db,
    pub cfg: Config,
    pub sched: sched::Shared,
    pub limiter: Mutex<HashMap<IpAddr, (u32, i64)>>,
    pub dummy_hash: String,
    pub tunnel: tunnel::Shared,
    pub tunnel_wake: tokio::sync::Notify,
    pub ts: tailscale::Shared,
    pub ts_wake: tokio::sync::Notify,
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| d.to_string())
}

fn config() -> Config {
    Config {
        bind: env("NDO4_BIND", "127.0.0.1:8589"),
        public_bind: env("NDO4_PUBLIC_BIND", "127.0.0.1:8590"),
        cloudflared: env("NDO4_CLOUDFLARED", "cloudflared"),
        tailscaled: env("NDO4_TAILSCALED", "tailscaled"),
        tailscale: env("NDO4_TAILSCALE", "tailscale"),
        ts_baked: env("NDO4_TAILSCALE_VERSION", ""),
        data: env("NDO4_DATA", "./data"),
        trust_proxy: matches!(env("NDO4_TRUST_PROXY", "0").as_str(), "1" | "true"),
        secure_cookie: matches!(env("NDO4_COOKIE_SECURE", "0").as_str(), "1" | "true"),
        metrics_bind: std::env::var("NDO4_METRICS_BIND")
            .ok()
            .filter(|v| !v.trim().is_empty()),
        retention_days: env("NDO4_RETENTION_DAYS", "30")
            .parse()
            .unwrap_or(30)
            .clamp(1, 3650),
    }
}

/// `ndo4uptime healthcheck` — used by the Docker HEALTHCHECK (image has no curl).
async fn healthcheck(bind: &str) -> i32 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = bind.rsplit(':').next().unwrap_or("8589");
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .ok()?;
        s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await
            .ok()?;
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.ok()?;
        buf.starts_with("HTTP/1.0 200")
            .then_some(())
            .or_else(|| buf.starts_with("HTTP/1.1 200").then_some(()))
    };
    match tokio::time::timeout(std::time::Duration::from_secs(3), fut).await {
        Ok(Some(())) => 0,
        _ => 1,
    }
}

/// Optional headless setup for Tailscale: `NDO4_TAILSCALE_AUTHKEY` (or `_FILE`) and
/// `NDO4_TAILSCALE_HOSTNAME`. Applied only while the integration has never been configured, so a
/// later change in Settings is never overridden by the environment.
fn seed_tailscale(db: &db::Db) {
    if !db.setting("ts_enabled").is_empty() {
        return;
    }
    let key = std::env::var("NDO4_TAILSCALE_AUTHKEY")
        .ok()
        .or_else(|| {
            std::fs::read_to_string(std::env::var("NDO4_TAILSCALE_AUTHKEY_FILE").ok()?).ok()
        })
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    let Some(key) = key else { return };
    if !tailscale::valid_key(&key) {
        eprintln!("NDO4_TAILSCALE_AUTHKEY is not a valid Tailscale auth key (tskey-…); ignored.");
        return;
    }
    if let Ok(h) = std::env::var("NDO4_TAILSCALE_HOSTNAME") {
        let h = h.trim().to_ascii_lowercase();
        if tailscale::valid_hostname(&h) {
            db.set_setting("ts_hostname", &h);
        }
    }
    db.set_setting("ts_authkey", &key);
    db.set_setting("ts_enabled", "1");
    println!("Tailscale enabled from the environment; it signs in with the provided auth key.");
}

/// First start: there is no setup page to race for. The administrator account is created with
/// `NDO4_ADMIN_PASSWORD` if set, otherwise with a random password printed once to the log.
fn bootstrap_admin(db: &db::Db) {
    if db.user_count() > 0 {
        return;
    }
    // NDO4_ADMIN_PASSWORD, or NDO4_ADMIN_PASSWORD_FILE (Docker/Kubernetes secrets).
    let from_env = std::env::var("NDO4_ADMIN_PASSWORD")
        .ok()
        .or_else(|| {
            let f = std::env::var("NDO4_ADMIN_PASSWORD_FILE").ok()?;
            std::fs::read_to_string(f).ok()
        })
        .map(|p| p.trim_end_matches(['\r', '\n']).to_string())
        .filter(|p| !p.is_empty());
    if from_env.as_ref().is_some_and(|p| p.chars().count() < 10) {
        eprintln!("NDO4_ADMIN_PASSWORD must be at least 10 characters; a random password is generated instead.");
    }
    let (pw, show) = match from_env.filter(|p| p.chars().count() >= 10) {
        Some(p) => (p, false),
        None => {
            let r = auth::random_hex(12);
            (
                format!("{}-{}-{}-{}", &r[0..6], &r[6..12], &r[12..18], &r[18..24]),
                true,
            )
        }
    };
    let hash = auth::hash_password(&pw);
    if hash.is_empty() || !db.create_user("admin", &hash) {
        eprintln!("cannot create the administrator account");
        std::process::exit(1);
    }
    if show {
        println!("================================================================");
        println!(" NDO4Uptime first start. Administrator password (shown once):");
        println!();
        println!("     {pw}");
        println!();
        println!(" Sign in at the web interface, then change it under Settings.");
        println!(" Lost it later? ndo4uptime reset-password (see the README).");
        println!("================================================================");
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let cfg = config();
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "healthcheck" {
        std::process::exit(healthcheck(&cfg.bind).await);
    }

    std::fs::create_dir_all(&cfg.data).expect("cannot create data dir");
    // The data directory holds the database, the encryption key and session hashes: owner only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&cfg.data, std::fs::Permissions::from_mode(0o700));
    }
    let db = db::Db::open(&format!("{}/ndo4uptime.db", cfg.data)).expect("cannot open database");
    ai::announce();

    if arg == "reset-password" {
        // Reads the new password from stdin so it never lands in shell history or `ps`.
        let mut pw = String::new();
        std::io::stdin().read_line(&mut pw).ok();
        let pw = pw.trim_end_matches(['\r', '\n']);
        if pw.chars().count() < 10 {
            eprintln!("Password must be at least 10 characters.");
            std::process::exit(2);
        }
        match db.first_user() {
            Some((id, _, _)) => {
                db.set_password(id, &auth::hash_password(pw));
                db.sessions_clear(None);
                println!("Password updated; all sessions were signed out.");
            }
            None => {
                eprintln!("No account exists yet. Start the server once; it creates the administrator account.");
                std::process::exit(1);
            }
        }
        return;
    }

    bootstrap_admin(&db);
    seed_tailscale(&db);

    let app = Arc::new(App {
        db,
        sched: Mutex::new(Default::default()),
        limiter: Mutex::new(HashMap::new()),
        dummy_hash: auth::hash_password(&auth::random_hex(16)),
        tunnel: Default::default(),
        tunnel_wake: tokio::sync::Notify::new(),
        ts: Default::default(),
        ts_wake: tokio::sync::Notify::new(),
        cfg,
    });
    app.db.sessions_gc();
    tokio::spawn(sched::run(app.clone()));
    tokio::spawn(tunnel::run(app.clone()));
    tokio::spawn(tailscale::run(app.clone()));
    tokio::spawn(tailscale::updater(app.clone()));

    let router = Router::new()
        .route("/", get(web::dashboard))
        .route("/healthz", get(web::healthz))
        .route("/static/{*path}", get(web::static_file))
        .route("/login", get(web::login_get).post(web::login_post))
        .route("/logout", post(web::logout))
        .route("/events", get(web::events))
        .route("/monitors", post(web::monitor_create))
        .route("/monitors/new", get(web::monitor_new))
        .route("/monitors/{id}", get(web::monitor_get))
        .route(
            "/monitors/{id}/edit",
            get(web::monitor_edit_get).post(web::monitor_edit_post),
        )
        .route("/monitors/{id}/{act}", post(web::monitor_action))
        .route(
            "/webhooks",
            get(web::webhooks_get).post(web::webhook_create),
        )
        .route(
            "/webhooks/{id}/edit",
            get(web::webhook_edit_get).post(web::webhook_edit_post),
        )
        .route("/webhooks/{id}/{act}", post(web::webhook_action))
        .route("/settings", get(web::settings_get))
        .route("/settings/password", post(web::password_post))
        .route("/settings/sessions", post(web::sessions_post))
        .route("/settings/tunnel", post(web::tunnel_post))
        .route("/settings/tailscale", post(web::tailscale_post))
        .route("/settings/alerting", post(web::alerting_post))
        .route("/maintenance", get(maint::list).post(maint::create))
        .route("/maintenance/new", get(maint::new))
        .route(
            "/maintenance/{id}/edit",
            get(maint::edit_get).post(maint::edit_post),
        )
        .route("/maintenance/{id}/{act}", post(maint::action))
        .route("/metrics", get(metrics::serve))
        .route("/settings/ai", post(ai::settings_post))
        .route("/settings/metrics", post(metrics::settings_post))
        .route("/settings/storage", post(web::storage_post))
        .route("/settings/privacy", post(web::privacy_post))
        .route("/pages", get(pages::pages_get).post(pages::page_create))
        .route("/pages/new", get(pages::page_new))
        .route(
            "/pages/{id}/edit",
            get(pages::page_edit_get).post(pages::page_edit_post),
        )
        .route(
            "/pages/{id}/logo",
            post(pages::logo_post).layer(DefaultBodyLimit::max(300 * 1024)),
        )
        .route("/pages/{id}/{act}", post(pages::page_action))
        .route("/s/{slug}", get(pages::by_slug).post(pages::stream_by_slug))
        .fallback(web::not_found)
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            web::security_headers,
        ))
        .with_state(app.clone());

    // Public listener: status pages only. This — never the admin port — is what a tunnel or
    // reverse proxy should point at. It has no login, no cookies and no admin routes.
    let public = Router::new()
        .route("/", get(pages::by_host).post(pages::stream_by_host))
        .route("/s/{slug}", get(pages::by_slug).post(pages::stream_by_slug))
        .route("/healthz", get(web::healthz))
        .fallback(web::not_found)
        .layer(middleware::from_fn_with_state(
            app.clone(),
            web::security_headers,
        ))
        .with_state(app.clone());
    match tokio::net::TcpListener::bind(&app.cfg.public_bind).await {
        Ok(l) => {
            println!("Public status pages on http://{}", app.cfg.public_bind);
            tokio::spawn(async move {
                serve::run(l, public, 1024).await;
            });
        }
        Err(e) => eprintln!(
            "public listener disabled (cannot bind {}): {e}",
            app.cfg.public_bind
        ),
    }

    // Optional metrics-only listener (for example on a Tailscale address): /metrics and nothing else.
    if let Some(addr) = app.cfg.metrics_bind.clone() {
        let r = Router::new()
            .route("/metrics", get(metrics::serve))
            .route("/healthz", get(web::healthz))
            .fallback(web::not_found)
            .with_state(app.clone());
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                println!("Prometheus metrics on http://{addr}/metrics");
                tokio::spawn(async move {
                    serve::run(l, r, 128).await;
                });
            }
            Err(e) => eprintln!("metrics listener disabled (cannot bind {addr}): {e}"),
        }
    }

    let listener = tokio::net::TcpListener::bind(&app.cfg.bind)
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot bind {}: {e}", app.cfg.bind);
            std::process::exit(1)
        });
    println!(
        "NDO4Uptime {} listening on http://{}",
        view::VERSION,
        app.cfg.bind
    );
    tokio::select! {
        () = serve::run(listener, router, 256) => {}
        () = serve::shutdown_signal() => {}
    }
    // Fold the WAL into the main database file so a plain copy of it is complete.
    app.db.checkpoint();
    println!("NDO4Uptime stopped");
}
