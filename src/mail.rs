//! Channels that need more than one HTTP request: a small SMTP client (implicit TLS, STARTTLS
//! or plain), Microsoft Graph mail (token, then send) and a Teltonika router (login, then SMS).

use crate::notify::{config, message, C, M};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const STEP: Duration = Duration::from_secs(15);

pub async fn send(
    kind: &str,
    raw: &str,
    body: &str,
    client: &reqwest::Client,
) -> Option<Result<String, String>> {
    let (c, m) = (config(raw), message(body));
    Some(match kind {
        "smtp" => smtp(&c, &m).await,
        "microsoft-graph" => graph(&c, &m, client).await,
        "teltonika" => teltonika(&c, &m).await,
        "nostr" => crate::nostr::send(&c, &m).await,
        _ => return None,
    })
}

fn addrs(s: &str) -> Vec<String> {
    s.split([',', ';', '\n'])
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

/// Mail addresses go into protocol lines, so anything that could end a line or a command is out.
fn clean_addr(a: &str) -> Result<&str, String> {
    if a.len() > 254
        || !a.contains('@')
        || a.chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '<' | '>' | '"'))
    {
        return Err(format!("Invalid address: {a}"));
    }
    Ok(a)
}

fn subject(s: &str) -> String {
    if s.is_ascii() {
        s.to_string()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(s)
        )
    }
}

pub fn connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

struct Conn<S> {
    r: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    async fn reply(&mut self) -> Result<(u16, String), String> {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            let n = timeout(STEP, self.r.read_line(&mut line))
                .await
                .map_err(|_| "SMTP server timed out".to_string())?
                .map_err(|_| "SMTP connection failed".to_string())?;
            if n == 0 || text.len() > 8192 {
                return Err("SMTP server closed the connection".into());
            }
            let code = line
                .get(..3)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
            let last = line.as_bytes().get(3) != Some(&b'-');
            text.push_str(line.trim_end());
            text.push('\n');
            if last {
                return Ok((code, text));
            }
        }
    }
    async fn cmd(&mut self, line: &str, want: u16) -> Result<String, String> {
        timeout(
            STEP,
            self.r.get_mut().write_all(format!("{line}\r\n").as_bytes()),
        )
        .await
        .map_err(|_| "SMTP server timed out".to_string())?
        .map_err(|_| "SMTP connection failed".to_string())?;
        let (code, text) = self.reply().await?;
        if code / 100 != want / 100 {
            return Err(format!("SMTP {}", text.lines().next().unwrap_or("error")));
        }
        Ok(text)
    }
}

async fn smtp(c: &C, m: &M) -> Result<String, String> {
    let host = c.g("host");
    let security = c.g("security");
    let port: u16 = if c.g("port").is_empty() {
        match security {
            "tls" => 465,
            "none" => 25,
            _ => 587,
        }
    } else {
        c.g("port").parse().map_err(|_| "Port must be a number")?
    };
    let from = clean_addr(c.g("from"))?;
    let mut rcpt = vec![];
    for a in addrs(c.g("to"))
        .into_iter()
        .chain(addrs(c.g("cc")))
        .chain(addrs(c.g("bcc")))
    {
        clean_addr(&a)?;
        rcpt.push(a);
    }
    if rcpt.is_empty() || rcpt.len() > 20 {
        return Err("Give between 1 and 20 recipients.".into());
    }
    if host.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err("Invalid server name.".into());
    }
    let tcp = timeout(STEP, TcpStream::connect((host, port)))
        .await
        .map_err(|_| "Connection timed out".to_string())?
        .map_err(|_| "Connection failed".to_string())?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "Invalid server name.".to_string())?;
    let tls = connector();
    let ehlo = "EHLO ndo4uptime";

    let mut msg = String::new();
    msg.push_str(&format!("From: <{from}>\r\n"));
    msg.push_str(&format!("To: {}\r\n", addrs(c.g("to")).join(", ")));
    if !c.g("cc").is_empty() {
        msg.push_str(&format!("Cc: {}\r\n", addrs(c.g("cc")).join(", ")));
    }
    msg.push_str(&format!("Subject: {}\r\n", subject(&m.title)));
    msg.push_str("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
    for l in m.text.lines() {
        if l.starts_with('.') {
            msg.push('.');
        }
        msg.push_str(l);
        msg.push_str("\r\n");
    }
    msg.push('.');

    async fn dialog<S: AsyncRead + AsyncWrite + Unpin>(
        cn: &mut Conn<S>,
        c: &C,
        from: &str,
        rcpt: &[String],
        msg: &str,
        ehlo: &str,
        greeting: bool,
    ) -> Result<(), String> {
        if greeting {
            let (code, text) = cn.reply().await?;
            if code / 100 != 2 {
                return Err(format!("SMTP {}", text.lines().next().unwrap_or("error")));
            }
        }
        cn.cmd(ehlo, 250).await?;
        if !c.g("user").is_empty() {
            let tok = base64::engine::general_purpose::STANDARD.encode(format!(
                "\0{}\0{}",
                c.g("user"),
                c.g("pass")
            ));
            cn.cmd(&format!("AUTH PLAIN {tok}"), 235).await?;
        }
        cn.cmd(&format!("MAIL FROM:<{from}>"), 250).await?;
        for r in rcpt {
            cn.cmd(&format!("RCPT TO:<{r}>"), 250).await?;
        }
        cn.cmd("DATA", 354).await?;
        cn.cmd(msg, 250).await?;
        let _ = cn.cmd("QUIT", 221).await;
        Ok(())
    }

    match security {
        "tls" => {
            let s = timeout(STEP, tls.connect(name, tcp))
                .await
                .map_err(|_| "TLS handshake timed out".to_string())?
                .map_err(|_| {
                    "TLS handshake failed (check the server name and certificate)".to_string()
                })?;
            let mut cn = Conn {
                r: BufReader::new(s),
            };
            dialog(&mut cn, c, from, &rcpt, &msg, ehlo, true).await?;
        }
        "none" => {
            let mut cn = Conn {
                r: BufReader::new(tcp),
            };
            dialog(&mut cn, c, from, &rcpt, &msg, ehlo, true).await?;
        }
        _ => {
            let mut cn = Conn {
                r: BufReader::new(tcp),
            };
            let (code, text) = cn.reply().await?;
            if code / 100 != 2 {
                return Err(format!("SMTP {}", text.lines().next().unwrap_or("error")));
            }
            cn.cmd(ehlo, 250).await?;
            cn.cmd("STARTTLS", 220).await?;
            let tcp = cn.r.into_inner();
            let s = timeout(STEP, tls.connect(name, tcp))
                .await
                .map_err(|_| "TLS handshake timed out".to_string())?
                .map_err(|_| {
                    "TLS handshake failed (check the server name and certificate)".to_string()
                })?;
            let mut cn = Conn {
                r: BufReader::new(s),
            };
            dialog(&mut cn, c, from, &rcpt, &msg, ehlo, false).await?;
        }
    }
    Ok("Mail accepted".into())
}

async fn graph(c: &C, m: &M, client: &reqwest::Client) -> Result<String, String> {
    let recipients = |s: &str| -> Result<Vec<Value>, String> {
        addrs(s)
            .iter()
            .map(|a| clean_addr(a).map(|a| json!({"emailAddress": {"address": a}})))
            .collect()
    };
    let (to, cc, bcc) = (
        recipients(c.g("to"))?,
        recipients(c.g("cc"))?,
        recipients(c.g("bcc"))?,
    );
    if to.len() + cc.len() + bcc.len() == 0 {
        return Err("At least one recipient is required.".into());
    }
    let tok = client
        .post(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            crate::notify::enc(c.g("tenant"))
        ))
        .form(&[
            ("client_id", c.g("client")),
            ("client_secret", c.g("secret")),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .map_err(|_| "Sign-in request failed".to_string())?;
    if !tok.status().is_success() {
        return Err(format!("Sign-in rejected (HTTP {})", tok.status().as_u16()));
    }
    let tok = read(tok).await?;
    let access = tok["access_token"]
        .as_str()
        .ok_or("No access token received")?;
    let r = client
        .post(format!(
            "https://graph.microsoft.com/v1.0/users/{}/sendMail",
            crate::notify::enc(c.g("mailbox"))
        ))
        .bearer_auth(access)
        .body_json(json!({"message": {
            "subject": m.title,
            "body": {"contentType": "Text", "content": m.text},
            "toRecipients": to, "ccRecipients": cc, "bccRecipients": bcc},
            "saveToSentItems": false}))
        .send()
        .await
        .map_err(|_| "Request failed".to_string())?;
    if r.status().is_success() {
        Ok(format!("HTTP {}", r.status().as_u16()))
    } else {
        Err(format!("HTTP {}", r.status().as_u16()))
    }
}

async fn teltonika(c: &C, m: &M) -> Result<String, String> {
    let u = reqwest::Url::parse(c.g("url")).map_err(|_| "Invalid router URL".to_string())?;
    let base = u.origin().ascii_serialization();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(c.g("tls") == "skip")
        .build()
        .map_err(|_| "Client error".to_string())?;
    let l = client
        .post(format!("{base}/api/login"))
        .body_json(json!({"username": c.g("user"), "password": c.g("pass")}))
        .send()
        .await
        .map_err(|_| "Router unreachable".to_string())?;
    let l = read(l).await?;
    if l["success"] != true {
        return Err("Router login failed".into());
    }
    let token = l["data"]["token"].as_str().ok_or("No token received")?;
    let text: String = m.text.chars().take(159).collect();
    let r = client
        .post(format!("{base}/api/messages/actions/send"))
        .bearer_auth(token)
        .body_json(json!({"data": {"modem": c.g("modem"), "number": c.g("to"), "message": text}}))
        .send()
        .await
        .map_err(|_| "Request failed".to_string())?;
    let r = read(r).await?;
    if r["success"] == true {
        Ok("SMS queued".into())
    } else {
        Err("Router refused the message".into())
    }
}

trait BodyJson {
    fn body_json(self, v: Value) -> Self;
}
impl BodyJson for reqwest::RequestBuilder {
    fn body_json(self, v: Value) -> Self {
        self.header("content-type", "application/json")
            .body(v.to_string())
    }
}

async fn read(r: reqwest::Response) -> Result<Value, String> {
    let b = r
        .bytes()
        .await
        .map_err(|_| "Unreadable answer".to_string())?;
    serde_json::from_slice(&b[..b.len().min(1 << 20)]).map_err(|_| "Unreadable answer".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn smtp_dialogue_with_a_plain_server() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut log = String::new();
            s.write_all(b"220 hi\r\n").await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut data = false;
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                log.push_str(&chunk);
                if data {
                    if chunk.ends_with("\r\n.\r\n") {
                        data = false;
                        s.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let up = chunk.to_uppercase();
                let r: &[u8] = if up.starts_with("EHLO") {
                    b"250-x\r\n250 AUTH PLAIN\r\n"
                } else if up.starts_with("AUTH") {
                    b"235 ok\r\n"
                } else if up.starts_with("DATA") {
                    data = true;
                    b"354 go\r\n"
                } else if up.starts_with("QUIT") {
                    b"221 bye\r\n"
                } else {
                    b"250 ok\r\n"
                };
                s.write_all(r).await.unwrap();
                if up.starts_with("QUIT") {
                    break;
                }
            }
            log
        });
        let c = C([
            ("host", "127.0.0.1"),
            ("port", &port.to_string()),
            ("security", "none"),
            ("user", "u"),
            ("pass", "p"),
            ("from", "a@example.com"),
            ("to", "b@example.com, c@example.com"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect());
        let body = crate::sched::payload("down", None, "x", None, None, false);
        smtp(&c, &message(&body)).await.unwrap();
        let log = srv.await.unwrap();
        assert!(log.contains("MAIL FROM:<a@example.com>"));
        assert!(log.contains("RCPT TO:<c@example.com>"));
        assert!(log.contains("Subject: "));
    }

    #[test]
    fn addresses_cannot_carry_commands() {
        assert!(clean_addr("a@b.c").is_ok());
        assert!(clean_addr("a@b.c>\r\nRCPT TO:<x@y.z").is_err());
        assert!(clean_addr("nobody").is_err());
    }
}
