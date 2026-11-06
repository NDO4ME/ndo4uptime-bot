use crate::db::Monitor;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// (latency ms, message, TLS certificate notAfter as Unix time if the target is HTTPS)
pub type CheckResult = Result<(i64, String, Option<i64>), String>;

const BROWSER_UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_RESOURCES: usize = 40;
const RESOURCE_PARALLEL: usize = 8;

pub async fn run(m: &Monitor) -> CheckResult {
    match m.kind.as_str() {
        "tcp" => tcp(m).await,
        "ping" => ping(m).await,
        "browser" => http(m, true).await,
        _ => http(m, false).await,
    }
}

/// Parses "Name: value" lines into a HeaderMap. Used for validation and sending.
pub fn parse_headers(text: &str) -> Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    let mut n = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        n += 1;
        if n > 20 {
            return Err("At most 20 headers are allowed.".into());
        }
        let (k, v) = line.split_once(':').ok_or_else(|| {
            format!(
                "Header line \"{}\" must look like Name: value.",
                cut(line, 40)
            )
        })?;
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .map_err(|_| format!("Invalid header name \"{}\".", cut(k.trim(), 40)))?;
        let val = HeaderValue::from_str(v.trim())
            .map_err(|_| format!("Invalid value for header {}.", name))?;
        map.append(name, val);
    }
    Ok(map)
}

/// Validates a proxy URL (http, https, socks5, socks5h; optional user:pass@).
pub fn validate_proxy(p: &str) -> Result<(), String> {
    if p.is_empty() {
        return Ok(());
    }
    let u = reqwest::Url::parse(p)
        .map_err(|_| "Proxy must look like http://host:port or socks5://host:port.".to_string())?;
    if !matches!(u.scheme(), "http" | "https" | "socks5" | "socks5h") || u.host_str().is_none() {
        return Err("Proxy scheme must be http, https, socks5 or socks5h.".into());
    }
    reqwest::Proxy::all(p).map_err(|_| "Invalid proxy address.".to_string())?;
    Ok(())
}

/// Proxy URL without credentials, safe to display.
pub fn redact_proxy(p: &str) -> String {
    match reqwest::Url::parse(p) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => String::new(),
    }
}

pub fn valid_selector(s: &str) -> bool {
    s.is_empty() || Selector::parse(s).is_ok()
}

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// "200-299,301" -> matcher
pub fn status_ok(spec: &str, code: u16) -> bool {
    spec.split(',').any(|p| {
        let p = p.trim();
        match p.split_once('-') {
            Some((a, b)) => matches!((a.trim().parse::<u16>(), b.trim().parse::<u16>()), (Ok(a), Ok(b)) if code >= a && code <= b),
            None => p.parse::<u16>().map(|c| c == code).unwrap_or(false),
        }
    })
}

pub fn valid_status_spec(spec: &str) -> bool {
    !spec.trim().is_empty()
        && spec.split(',').all(|p| {
            let p = p.trim();
            let ok = |s: &str| {
                s.trim()
                    .parse::<u16>()
                    .map(|c| (100..=599).contains(&c))
                    .unwrap_or(false)
            };
            match p.split_once('-') {
                Some((a, b)) => ok(a) && ok(b),
                None => ok(p),
            }
        })
}

fn build_client(m: &Monitor, browser: bool) -> Result<reqwest::Client, String> {
    let mut cb = reqwest::Client::builder()
        .tls_info(true)
        .timeout(Duration::from_secs(m.timeout as u64))
        .danger_accept_invalid_certs(!m.verify_tls)
        .redirect(if m.follow {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(if browser {
            BROWSER_UA
        } else {
            "NDO4Uptime/1.0"
        });
    if browser {
        cb = cb.cookie_store(true);
    }
    if m.proxy.is_empty() {
        cb = cb.no_proxy(); // never inherit proxy settings from the environment implicitly
    } else {
        cb = cb.proxy(reqwest::Proxy::all(&m.proxy).map_err(|_| "Invalid proxy".to_string())?);
    }
    cb.build().map_err(|e| e.to_string())
}

async fn http(m: &Monitor, browser: bool) -> CheckResult {
    let client = build_client(m, browser)?;
    let method =
        reqwest::Method::from_bytes(m.method.as_bytes()).map_err(|_| "Bad method".to_string())?;

    let mut headers = HeaderMap::new();
    if browser {
        for (k, v) in [
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
            ("accept-language", "en-US,en;q=0.9"),
            ("upgrade-insecure-requests", "1"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-site", "none"),
            ("sec-fetch-user", "?1"),
        ] {
            headers.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
    }
    let custom = parse_headers(&m.headers)?;
    for name in custom.keys() {
        headers.remove(name); // user supplied headers override defaults
    }
    for (k, v) in custom.iter() {
        headers.append(k.clone(), v.clone());
    }

    let mut req = client.request(method.clone(), &m.target).headers(headers);
    if !m.body.is_empty() && method != reqwest::Method::GET && method != reqwest::Method::HEAD {
        req = req.body(m.body.clone());
    }

    let start = Instant::now();
    let mut resp = req.send().await.map_err(describe)?;
    let code = resp.status().as_u16();
    let final_url = resp.url().clone();
    let is_html = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("html"));
    let need_body = browser || !m.keyword.is_empty();
    let mut body = Vec::new();
    if need_body && method != reqwest::Method::HEAD {
        while let Some(chunk) = resp.chunk().await.map_err(describe)? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                break;
            }
        }
    }
    let cert = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|t| t.peer_certificate())
        .and_then(|der| x509_parser::parse_x509_certificate(der).ok())
        .map(|(_, c)| c.validity().not_after.timestamp());
    if !status_ok(&m.expect, code) {
        return Err(format!("HTTP {} (expected {})", code, m.expect));
    }
    let text = String::from_utf8_lossy(&body).into_owned();

    if browser && is_html {
        browser_page(m, &client, &final_url, &text, start).await?;
    } else if !m.keyword.is_empty() && !text.contains(&m.keyword) {
        return Err(format!("HTTP {} but keyword not found", code));
    }
    let ms = start.elapsed().as_millis() as i64;
    Ok((ms, format!("HTTP {}", code), cert))
}

/// DOM work is synchronous: the parsed tree is not `Send`, so it never lives across an `.await`.
struct PageInfo {
    visible_text: String,
    selector_hit: bool,
    resources: Vec<reqwest::Url>,
}

fn analyze(html: &str, base: &reqwest::Url, selector: &str, third_party: bool) -> PageInfo {
    let doc = Html::parse_document(html);
    // Visible text: everything except script/style/noscript/template/head contents.
    let mut visible_text = String::new();
    for node in doc.tree.nodes() {
        if let scraper::Node::Text(t) = node.value() {
            let hidden = node.ancestors().any(|a| {
                matches!(
                    a.value().as_element().map(|e| e.name()),
                    Some("script" | "style" | "noscript" | "template" | "head" | "title")
                )
            });
            if !hidden {
                visible_text.push_str(t);
                visible_text.push(' ');
            }
        }
    }
    let selector_hit = if selector.is_empty() {
        true
    } else {
        Selector::parse(selector)
            .map(|s| doc.select(&s).next().is_some())
            .unwrap_or(false)
    };

    // Sub-resources a browser would load for rendering: CSS, scripts, images.
    let mut seen = HashSet::new();
    let mut resources = Vec::new();
    let mut add = |raw: &str| {
        if resources.len() >= MAX_RESOURCES {
            return;
        }
        if let Ok(u) = base.join(raw.trim()) {
            if !matches!(u.scheme(), "http" | "https") {
                return;
            }
            if !third_party
                && (u.host_str() != base.host_str()
                    || u.port_or_known_default() != base.port_or_known_default())
            {
                return;
            }
            let mut key = u.clone();
            key.set_fragment(None);
            if seen.insert(key.to_string()) {
                resources.push(key);
            }
        }
    };
    if let Ok(sel) = Selector::parse(r#"link[rel~="stylesheet"][href], script[src], img[src]"#) {
        for el in doc.select(&sel) {
            let v = el.value();
            let attr = if v.name() == "link" { "href" } else { "src" };
            if let Some(u) = v.attr(attr) {
                add(u);
            }
        }
    }
    PageInfo {
        visible_text,
        selector_hit,
        resources,
    }
}

async fn browser_page(
    m: &Monitor,
    client: &reqwest::Client,
    base: &reqwest::Url,
    html: &str,
    start: Instant,
) -> Result<(), String> {
    let info = analyze(html, base, &m.selector, m.third_party);
    if !m.keyword.is_empty() && !info.visible_text.contains(&m.keyword) {
        return Err("Page loaded but keyword not found in visible text".into());
    }
    if !info.selector_hit {
        return Err(format!(
            "Page loaded but selector \"{}\" matched nothing",
            cut(&m.selector, 60)
        ));
    }

    // Load sub-resources like a browser would, with bounded concurrency and a shared deadline.
    let budget = Duration::from_secs(m.timeout as u64).saturating_sub(start.elapsed());
    let sem = Arc::new(Semaphore::new(RESOURCE_PARALLEL));
    let mut set = JoinSet::new();
    for url in info.resources {
        let (c, sem) = (client.clone(), sem.clone());
        set.spawn(async move {
            let _p = sem.acquire().await;
            let shown = format!("{}{}", url.host_str().unwrap_or(""), url.path());
            let r = async {
                let mut resp = c
                    .get(url)
                    .header("sec-fetch-site", "same-origin")
                    .send()
                    .await
                    .map_err(|_| "unreachable".to_string())?;
                let st = resp.status();
                let mut n = 0usize;
                while let Some(ch) = resp.chunk().await.map_err(|_| "read error".to_string())? {
                    n += ch.len();
                    if n > MAX_BODY {
                        break; // enough: the resource exists and is serving data
                    }
                }
                if st.is_client_error() || st.is_server_error() {
                    Err(format!("HTTP {}", st.as_u16()))
                } else {
                    Ok(())
                }
            };
            (
                shown,
                timeout(budget.max(Duration::from_secs(1)), r)
                    .await
                    .unwrap_or(Err("timed out".into())),
            )
        });
    }
    let mut broken = Vec::new();
    while let Some(Ok((url, res))) = set.join_next().await {
        if let Err(e) = res {
            broken.push(format!("{} ({e})", cut(&url, 60)));
        }
    }
    if !broken.is_empty() {
        broken.sort();
        let more = broken.len().saturating_sub(3);
        let mut msg = format!(
            "{} resource(s) failed: {}",
            broken.len(),
            broken
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        if more > 0 {
            msg.push_str(&format!(" +{more} more"));
        }
        return Err(msg);
    }
    Ok(())
}

fn describe(e: reqwest::Error) -> String {
    let e = e.without_url();
    if e.is_timeout() {
        return "Timed out".into();
    }
    if e.is_redirect() {
        return "Too many redirects".into();
    }
    // Root cause (refused, DNS failure, invalid certificate, ...) is what an operator needs.
    let mut root = String::new();
    let mut src = std::error::Error::source(&e);
    while let Some(x) = src {
        root = x.to_string();
        src = x.source();
    }
    let head = if e.is_connect() {
        "Connection failed"
    } else {
        "Request failed"
    };
    if root.is_empty() {
        head.into()
    } else {
        cut(&format!("{head}: {root}"), 200)
    }
}

async fn tcp(m: &Monitor) -> CheckResult {
    let start = Instant::now();
    let d = Duration::from_secs(m.timeout as u64);
    match timeout(d, TcpStream::connect((m.target.as_str(), m.port as u16))).await {
        Err(_) => Err("Timed out".into()),
        Ok(Err(e)) => Err(format!("Connection failed: {}", e.kind())),
        Ok(Ok(_)) => Ok((
            start.elapsed().as_millis() as i64,
            format!("Port {} open", m.port),
            None,
        )),
    }
}

async fn ping(m: &Monitor) -> CheckResult {
    let d = Duration::from_secs(m.timeout as u64);
    let ip = match timeout(d, lookup_host((m.target.as_str(), 0))).await {
        Err(_) => return Err("DNS timed out".into()),
        Ok(Err(_)) => return Err("DNS lookup failed".into()),
        Ok(Ok(mut it)) => it.next().ok_or("DNS lookup failed")?.ip(),
    };
    match timeout(d, surge_ping::ping(ip, &[0u8; 32])).await {
        Err(_) => Err("Timed out".into()),
        Ok(Err(e)) => Err(format!("Ping failed: {}", cut(&e.to_string(), 120))),
        Ok(Ok((_, rtt))) => Ok((
            rtt.as_millis().max(1) as i64,
            format!("Reply from {}", ip),
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_ranges() {
        assert!(status_ok("200-299", 204));
        assert!(status_ok("200-299,301", 301));
        assert!(!status_ok("200-299", 500));
        assert!(!status_ok("abc", 200));
    }

    #[test]
    fn status_spec_validation() {
        assert!(valid_status_spec("200-299,301"));
        assert!(!valid_status_spec(""));
        assert!(!valid_status_spec("99"));
        assert!(!valid_status_spec("200-"));
    }

    #[test]
    fn header_parsing() {
        assert_eq!(parse_headers("A: 1\n\nB: two").unwrap().len(), 2);
        assert!(parse_headers("no-colon").is_err());
        assert!(parse_headers("bad name: x").is_err());
        let many: String = (0..21).map(|i| format!("X-{i}: v\n")).collect();
        assert!(parse_headers(&many).is_err());
    }

    #[test]
    fn proxy_validation() {
        assert!(validate_proxy("").is_ok());
        assert!(validate_proxy("http://10.0.0.1:3128").is_ok());
        assert!(validate_proxy("socks5://u:p@127.0.0.1:1080").is_ok());
        assert!(validate_proxy("ftp://x").is_err());
        assert!(validate_proxy("not a url").is_err());
        assert_eq!(
            redact_proxy("socks5://u:p@127.0.0.1:1080"),
            "socks5://127.0.0.1:1080"
        );
    }

    #[test]
    fn browser_analysis() {
        let base = reqwest::Url::parse("https://example.com/a/").unwrap();
        let html = r#"<html><head><title>T</title><link rel="stylesheet" href="/s.css"><script src="app.js"></script></head>
            <body><h1 id="x">Hello</h1><script>var secret="hidden";</script><img src="https://cdn.other.net/i.png"></body></html>"#;
        let p = analyze(html, &base, "#x", false);
        assert!(p.visible_text.contains("Hello") && !p.visible_text.contains("hidden"));
        assert!(p.selector_hit);
        let urls: Vec<_> = p.resources.iter().map(|u| u.as_str()).collect();
        assert_eq!(
            urls,
            ["https://example.com/s.css", "https://example.com/a/app.js"]
        );
        assert_eq!(analyze(html, &base, "", true).resources.len(), 3);
        assert!(!analyze(html, &base, ".nope", false).selector_hit);
        assert!(valid_selector("div > a.b") && !valid_selector("div >> ["));
    }
}
