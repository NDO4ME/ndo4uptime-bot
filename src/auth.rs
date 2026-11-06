use crate::db::now;
use crate::App;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::{header, request::Parts, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub const COOKIE: &str = "ndo4_session";
pub const SESSION_TTL: i64 = 12 * 3600;

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn hash_password(pw: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

pub fn cookie_value(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

pub fn set_cookie(app: &App, token: &str, max_age: i64) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if app.cfg.secure_cookie {
            "; Secure"
        } else {
            ""
        }
    )
}

/// Creates a session and returns (cookie header value).
pub fn new_session(app: &App) -> String {
    let token = random_hex(32);
    app.db
        .session_add(&sha(&token), &random_hex(24), now() + SESSION_TTL);
    set_cookie(app, &token, SESSION_TTL)
}

fn same_origin(parts: &Parts) -> bool {
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(o) = parts
        .headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        // Browsers send "null" when the referrer policy hides the origin; Sec-Fetch-Site decides then.
        if o != "null" {
            let oh = o.split_once("://").map(|x| x.1).unwrap_or(o);
            return oh == host;
        }
    }
    matches!(
        parts
            .headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok()),
        None | Some("same-origin") | Some("none")
    )
}

/// Origin check for unauthenticated state-changing requests (login).
pub fn origin_ok(parts: &Parts) -> bool {
    parts.method == Method::GET || parts.method == Method::HEAD || same_origin(parts)
}

/// Client address for rate limiting. Behind a trusted reverse proxy (NDO4_TRUST_PROXY=1) the
/// right-most X-Forwarded-For entry — the one our own proxy appended — is used; otherwise the socket peer.
pub fn client_ip(app: &App, parts: &Parts, peer: std::net::SocketAddr) -> IpAddr {
    if app.cfg.trust_proxy {
        if let Some(ip) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

pub struct Auth {
    pub csrf: String,
    pub token_hash: String,
}

impl FromRequestParts<Arc<App>> for Auth {
    type Rejection = Response;
    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Response> {
        let _ = app;
        let to_login = || Redirect::to("/login").into_response();
        let Some(tok) = cookie_value(parts) else {
            return Err(to_login());
        };
        let th = sha(&tok);
        let Some((csrf, exp)) = app.db.session_get(&th) else {
            return Err(to_login());
        };
        let t = now();
        if exp < t {
            app.db.session_del(&th);
            return Err(to_login());
        }
        if !origin_ok(parts) {
            return Err((StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response());
        }
        if exp - t < SESSION_TTL - 600 {
            app.db.session_touch(&th, t + SESSION_TTL);
        }
        Ok(Auth {
            csrf,
            token_hash: th,
        })
    }
}

/// url-encoded form body with repeated keys preserved.
pub struct Form(pub Vec<(String, String)>);

impl Form {
    pub fn get(&self, k: &str) -> &str {
        self.0
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }
    pub fn all(&self, k: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    pub fn has(&self, k: &str) -> bool {
        self.0.iter().any(|(a, _)| a == k)
    }
    pub fn int(&self, k: &str, default: i64) -> i64 {
        self.get(k).trim().parse().unwrap_or(default)
    }
    pub fn csrf_ok(&self, a: &Auth) -> bool {
        self.get("csrf_token")
            .as_bytes()
            .ct_eq(a.csrf.as_bytes())
            .into()
    }
}

impl FromRequest<Arc<App>> for Form {
    type Rejection = Response;
    async fn from_request(req: Request, st: &Arc<App>) -> Result<Self, Response> {
        let b = Bytes::from_request(req, st)
            .await
            .map_err(|e| e.into_response())?;
        Ok(Form(
            form_urlencoded::parse(&b)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        ))
    }
}

// ---- login rate limiting: 5 failures / 15 min per address
const WINDOW: i64 = 900;
const MAX_FAILS: u32 = 5;

pub fn rate_blocked(app: &App, ip: IpAddr) -> bool {
    let mut m = app.limiter.lock().unwrap_or_else(|e| e.into_inner());
    let t = now();
    m.retain(|_, (_, first)| t - *first < WINDOW);
    m.get(&ip).is_some_and(|(n, _)| *n >= MAX_FAILS)
}
pub fn rate_fail(app: &App, ip: IpAddr) {
    let mut m = app.limiter.lock().unwrap_or_else(|e| e.into_inner());
    let e = m.entry(ip).or_insert((0, now()));
    e.0 += 1;
}
pub fn rate_clear(app: &App, ip: IpAddr) {
    app.limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&ip);
}
