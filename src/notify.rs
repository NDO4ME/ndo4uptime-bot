//! Notification channels. A channel is a generic webhook or one of the providers below; each
//! provider is data (its fields) plus one function that turns a message into one HTTP request.
//! Every provider builds its message from the same alert payload as the webhook, so the privacy
//! lock applies unchanged: with it on, a message carries only the monitor name, state and time.

use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq)]
pub enum K {
    Text,
    Secret,
    Url,
    Select(&'static [&'static str]),
}

pub struct F {
    pub k: &'static str,
    pub label: &'static str,
    pub kind: K,
    pub req: bool,
    pub hint: &'static str,
}

const fn f(k: &'static str, label: &'static str, kind: K, req: bool) -> F {
    F {
        k,
        label,
        kind,
        req,
        hint: "",
    }
}
const fn t(k: &'static str, label: &'static str) -> F {
    f(k, label, K::Text, true)
}
const fn o(k: &'static str, label: &'static str) -> F {
    f(k, label, K::Text, false)
}
const fn s(k: &'static str, label: &'static str) -> F {
    f(k, label, K::Secret, true)
}
const fn u(k: &'static str, label: &'static str) -> F {
    f(k, label, K::Url, true)
}
const fn ou(k: &'static str, label: &'static str) -> F {
    f(k, label, K::Url, false)
}
const fn sel(k: &'static str, label: &'static str, opts: &'static [&'static str]) -> F {
    f(k, label, K::Select(opts), true)
}
const fn h(mut x: F, hint: &'static str) -> F {
    x.hint = hint;
    x
}

/// Settings of one channel.
pub struct C(pub HashMap<String, String>);
impl C {
    pub fn g(&self, k: &str) -> &str {
        self.0.get(k).map_or("", |v| v.trim())
    }
    fn or<'a>(&'a self, k: &str, d: &'a str) -> &'a str {
        let v = self.g(k);
        if v.is_empty() {
            d
        } else {
            v
        }
    }
    fn base(&self, k: &str, d: &str) -> String {
        self.or(k, d).trim_end_matches('/').to_string()
    }
}

/// One alert, ready to be phrased by a provider.
pub struct M {
    pub up: bool,
    pub test: bool,
    pub time: i64,
    pub name: String,
    /// "name is DOWN"
    pub title: String,
    /// title plus time (and details when the webhook allows them)
    pub text: String,
}

pub enum Body {
    None,
    Json(Value),
    Form(Vec<(String, String)>),
    Text(String),
}

pub struct Req {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Body,
    pub basic: Option<(String, String)>,
}

fn req(method: &'static str, url: String, body: Body) -> Req {
    Req {
        method,
        url,
        headers: vec![],
        body,
        basic: None,
    }
}
fn post(url: &str, v: Value) -> Result<Req, String> {
    Ok(req("POST", url.to_string(), Body::Json(v)))
}
fn form(url: &str, v: &[(&str, &str)]) -> Result<Req, String> {
    Ok(req(
        "POST",
        url.to_string(),
        Body::Form(
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        ),
    ))
}
fn with_h(mut r: Req, k: &str, v: String) -> Req {
    r.headers.push((k.to_string(), v));
    r
}
fn bearer(r: Req, tok: &str) -> Req {
    with_h(r, "authorization", format!("Bearer {tok}"))
}
fn basic(mut r: Req, u: &str, p: &str) -> Req {
    r.basic = Some((u.to_string(), p.to_string()));
    r
}

/// Percent-encodes everything but unreserved characters.
pub fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}
fn q(base: &str, params: &[(&str, &str)]) -> String {
    let mut u = base.to_string();
    for (i, (k, v)) in params.iter().enumerate() {
        u.push(if i == 0 && !base.contains('?') {
            '?'
        } else {
            '&'
        });
        u.push_str(&format!("{}={}", enc(k), enc(v)));
    }
    u
}
fn hmac_b64(key: &[u8], data: &[u8]) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes())
}
fn dedup(m: &M) -> String {
    format!("ndo4uptime-{}", enc(&m.name))
}
fn list(s: &str) -> Vec<String> {
    s.split([',', '\n', ';'])
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

pub struct P {
    pub key: &'static str,
    pub label: &'static str,
    pub cat: &'static str,
    pub fields: &'static [F],
    pub build: fn(&C, &M) -> Result<Req, String>,
}

pub const CATS: &[&str] = &[
    "Chat",
    "Push",
    "Incident management",
    "Email",
    "SMS and messaging",
];

macro_rules! p {
    ($key:expr, $label:expr, $cat:expr, [$($fld:expr),* $(,)?], $b:expr) => {
        P { key: $key, label: $label, cat: $cat, fields: &[$($fld),*], build: $b }
    };
}

const PRIORITY: &[&str] = &["min", "low", "default", "high", "max"];

pub static PROVIDERS: &[P] = &[
    // ------------------------------------------------------------ chat
    p!(
        "slack",
        "Slack",
        "Chat",
        [
            u("url", "Webhook URL"),
            o("channel", "Channel override"),
            o("username", "Bot name")
        ],
        |c, m| post(
            c.g("url"),
            json!({"text": m.text, "channel": c.g("channel"), "username": c.or("username", "NDO4Uptime")})
        )
    ),
    p!(
        "discord",
        "Discord",
        "Chat",
        [u("url", "Webhook URL"), o("username", "Bot name")],
        |c, m| post(
            c.g("url"),
            json!({"username": c.or("username", "NDO4Uptime"), "content": m.text})
        )
    ),
    p!(
        "teams",
        "Microsoft Teams",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": m.title, "themeColor": if m.up { "2fb344" } else { "d63939" }, "title": m.title, "text": m.text})
        )
    ),
    p!(
        "google-chat",
        "Google Chat",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(c.g("url"), json!({"text": m.text}))
    ),
    p!(
        "mattermost",
        "Mattermost",
        "Chat",
        [
            u("url", "Webhook URL"),
            o("channel", "Channel override"),
            o("username", "Bot name")
        ],
        |c, m| post(
            c.g("url"),
            json!({"text": m.text, "channel": c.g("channel"), "username": c.or("username", "NDO4Uptime")})
        )
    ),
    p!(
        "rocket-chat",
        "Rocket.Chat",
        "Chat",
        [
            u("url", "Webhook URL"),
            o("channel", "Channel override"),
            o("username", "Bot name")
        ],
        |c, m| post(
            c.g("url"),
            json!({"text": m.text, "channel": c.g("channel"), "username": c.or("username", "NDO4Uptime")})
        )
    ),
    p!(
        "pumble",
        "Pumble",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(c.g("url"), json!({"text": m.text}))
    ),
    p!(
        "zoho-cliq",
        "Zoho Cliq",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(c.g("url"), json!({"text": m.text}))
    ),
    p!(
        "stackfield",
        "Stackfield",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(c.g("url"), json!({"Title": m.title, "Text": m.text}))
    ),
    p!(
        "feishu",
        "Feishu / Lark",
        "Chat",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"msg_type": "text", "content": {"text": m.text}})
        )
    ),
    p!(
        "dingtalk",
        "DingTalk",
        "Chat",
        [
            u("url", "Webhook URL"),
            f("secret", "Signing secret", K::Secret, false)
        ],
        |c, m| {
            let mut url = c.g("url").to_string();
            if !c.g("secret").is_empty() {
                let ts = crate::db::now() * 1000;
                let sig = hmac_b64(
                    c.g("secret").as_bytes(),
                    format!("{ts}\n{}", c.g("secret")).as_bytes(),
                );
                url = q(&url, &[("timestamp", &ts.to_string()), ("sign", &sig)]);
            }
            post(
                &url,
                json!({"msgtype": "text", "text": {"content": m.text}}),
            )
        }
    ),
    p!(
        "wecom",
        "WeCom",
        "Chat",
        [s("key", "Bot key")],
        |c, m| post(
            &q(
                "https://qyapi.weixin.qq.com/cgi-bin/webhook/send",
                &[("key", c.g("key"))]
            ),
            json!({"msgtype": "text", "text": {"content": m.text}})
        )
    ),
    p!(
        "telegram",
        "Telegram",
        "Chat",
        [
            s("token", "Bot token"),
            t("chat", "Chat ID"),
            o("thread", "Topic (thread) ID"),
            ou("server", "API server (default https://api.telegram.org)"),
            sel("silent", "Notification sound", &["on", "silent"])
        ],
        |c, m| {
            let mut v = json!({"chat_id": c.g("chat"), "text": m.text, "disable_notification": c.g("silent") == "silent"});
            if !c.g("thread").is_empty() {
                v["message_thread_id"] = json!(c.g("thread").parse::<i64>().unwrap_or(0));
            }
            post(
                &format!(
                    "{}/bot{}/sendMessage",
                    c.base("server", "https://api.telegram.org"),
                    c.g("token")
                ),
                v,
            )
        }
    ),
    p!(
        "bale",
        "Bale",
        "Chat",
        [s("token", "Bot token"), t("chat", "Chat ID")],
        |c, m| post(
            &format!("https://tapi.bale.ai/bot{}/sendMessage", c.g("token")),
            json!({"chat_id": c.g("chat"), "text": m.text})
        )
    ),
    p!(
        "line",
        "LINE",
        "Chat",
        [
            s("token", "Channel access token"),
            t("to", "User or group ID")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api.line.me/v2/bot/message/push".into(),
                Body::Json(
                    json!({"to": c.g("to"), "messages": [{"type": "text", "text": m.text}]})
                )
            ),
            c.g("token")
        ))
    ),
    p!(
        "matrix",
        "Matrix",
        "Chat",
        [
            u("server", "Homeserver URL"),
            s("token", "Access token"),
            t("room", "Room ID")
        ],
        |c, m| {
            let url = format!(
                "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
                c.base("server", ""),
                enc(c.g("room")),
                crate::db::now_ms()
            );
            Ok(bearer(
                req(
                    "PUT",
                    url,
                    Body::Json(json!({"msgtype": "m.text", "body": m.text})),
                ),
                c.g("token"),
            ))
        }
    ),
    p!(
        "nextcloud-talk",
        "Nextcloud Talk",
        "Chat",
        [
            u("host", "Server URL"),
            t("conversation", "Conversation token"),
            s("secret", "Bot secret")
        ],
        |c, m| {
            let random = format!("{:x}{:x}", crate::db::now_ms(), std::process::id());
            let mut mac = Hmac::<Sha256>::new_from_slice(c.g("secret").as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(random.as_bytes());
            mac.update(m.text.as_bytes());
            let r = req(
                "POST",
                format!(
                    "{}/ocs/v2.php/apps/spreed/api/v1/bot/{}/message",
                    c.base("host", ""),
                    enc(c.g("conversation"))
                ),
                Body::Json(json!({"message": m.text})),
            );
            Ok(with_h(
                with_h(
                    with_h(r, "x-nextcloud-talk-bot-random", random),
                    "x-nextcloud-talk-bot-signature",
                    hex::encode(mac.finalize().into_bytes()),
                ),
                "ocs-apirequest",
                "true".into(),
            ))
        }
    ),
    p!(
        "kook",
        "KOOK",
        "Chat",
        [s("token", "Bot token"), t("target", "Channel ID")],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://www.kookapp.cn/api/v3/message/create".into(),
                Body::Json(json!({"target_id": c.g("target"), "content": m.text, "type": 1}))
            ),
            "authorization",
            format!("Bot {}", c.g("token"))
        ))
    ),
    p!(
        "vk-teams",
        "VK Teams",
        "Chat",
        [
            s("token", "Bot token"),
            t("chat", "Chat ID"),
            ou("server", "API server (default https://myteam.mail.ru)")
        ],
        |c, m| Ok(req(
            "GET",
            q(
                &format!(
                    "{}/bot/v1/messages/sendText",
                    c.base("server", "https://myteam.mail.ru")
                ),
                &[
                    ("token", c.g("token")),
                    ("chatId", c.g("chat")),
                    ("text", &m.text)
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "vk",
        "VK",
        "Chat",
        [s("token", "Access token"), t("user", "User or chat ID")],
        |c, m| form(
            "https://api.vk.ru/method/messages.send",
            &[
                ("access_token", c.g("token")),
                ("user_id", c.g("user")),
                ("random_id", &crate::db::now_ms().to_string()),
                ("message", &m.text),
                ("v", "5.131")
            ]
        )
    ),
    p!(
        "onebot",
        "OneBot",
        "Chat",
        [
            u("server", "HTTP address"),
            f("token", "Access token", K::Secret, false),
            sel("type", "Target", &["private", "group"]),
            t("target", "User or group ID")
        ],
        |c, m| {
            let (path, key) = if c.g("type") == "group" {
                ("send_group_msg", "group_id")
            } else {
                ("send_private_msg", "user_id")
            };
            let id = c
                .g("target")
                .parse::<i64>()
                .map_err(|_| "Target ID must be a number")?;
            let r = req(
                "POST",
                format!("{}/{path}", c.base("server", "")),
                Body::Json(json!({key: id, "message": m.text})),
            );
            Ok(if c.g("token").is_empty() {
                r
            } else {
                bearer(r, c.g("token"))
            })
        }
    ),
    p!(
        "home-assistant",
        "Home Assistant",
        "Chat",
        [
            u("url", "Instance URL"),
            s("token", "Long-lived access token"),
            h(
                o("service", "Notify service"),
                "e.g. mobile_app_phone (default notify)"
            )
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                format!(
                    "{}/api/services/notify/{}",
                    c.base("url", ""),
                    enc(c.or("service", "notify"))
                ),
                Body::Json(json!({"title": m.title, "message": m.text}))
            ),
            c.g("token")
        ))
    ),
    p!(
        "signal",
        "Signal (REST gateway)",
        "Chat",
        [
            u("url", "Gateway URL"),
            t("number", "Sender number"),
            h(t("to", "Recipients"), "Comma separated")
        ],
        |c, m| post(
            &format!("{}/v2/send", c.base("url", "")),
            json!({"message": m.text, "number": c.g("number"), "recipients": list(c.g("to"))})
        )
    ),
    p!(
        "threema",
        "Threema Gateway",
        "Chat",
        [
            t("from", "Gateway ID"),
            t("to", "Recipient ID"),
            s("secret", "API secret")
        ],
        |c, m| form(
            "https://msgapi.threema.ch/send_simple",
            &[
                ("from", c.g("from")),
                ("to", c.g("to")),
                ("secret", c.g("secret")),
                ("text", &m.text)
            ]
        )
    ),
    // ------------------------------------------------------------ push
    p!(
        "ntfy",
        "ntfy",
        "Push",
        [
            ou("server", "Server (default https://ntfy.sh)"),
            t("topic", "Topic"),
            sel("priority", "Priority", PRIORITY),
            sel("auth", "Authentication", &["none", "basic", "token"]),
            o("user", "Username"),
            f("secret", "Password or token", K::Secret, false)
        ],
        |c, m| {
            let pri = match c.or("priority", "default") {
                "min" => "1",
                "low" => "2",
                "high" => "4",
                "max" => "5",
                _ => "3",
            };
            let mut r = req(
                "POST",
                format!(
                    "{}/{}",
                    c.base("server", "https://ntfy.sh"),
                    enc(c.g("topic"))
                ),
                Body::Text(m.text.clone()),
            );
            r = with_h(with_h(r, "title", m.title.clone()), "priority", pri.into());
            r = with_h(
                r,
                "tags",
                if m.up {
                    "white_check_mark"
                } else {
                    "rotating_light"
                }
                .into(),
            );
            Ok(match c.g("auth") {
                "basic" => basic(r, c.g("user"), c.g("secret")),
                "token" => bearer(r, c.g("secret")),
                _ => r,
            })
        }
    ),
    p!(
        "gotify",
        "Gotify",
        "Push",
        [
            u("url", "Server URL"),
            s("token", "Application token"),
            sel("priority", "Priority", &["1", "3", "5", "8", "10"])
        ],
        |c, m| post(
            &q(
                &format!("{}/message", c.base("url", "")),
                &[("token", c.g("token"))]
            ),
            json!({"title": m.title, "message": m.text, "priority": c.or("priority", "5").parse::<i64>().unwrap_or(5)})
        )
    ),
    p!(
        "pushover",
        "Pushover",
        "Push",
        [
            s("token", "Application token"),
            s("user", "User key"),
            o("device", "Device"),
            sel("priority", "Priority", &["-1", "0", "1"])
        ],
        |c, m| form(
            "https://api.pushover.net/1/messages.json",
            &[
                ("token", c.g("token")),
                ("user", c.g("user")),
                ("device", c.g("device")),
                ("title", &m.title),
                ("message", &m.text),
                ("priority", c.or("priority", "0"))
            ]
        )
    ),
    p!(
        "pushbullet",
        "Pushbullet",
        "Push",
        [s("token", "Access token")],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://api.pushbullet.com/v2/pushes".into(),
                Body::Json(json!({"type": "note", "title": m.title, "body": m.text}))
            ),
            "access-token",
            c.g("token").into()
        ))
    ),
    p!(
        "bark",
        "Bark",
        "Push",
        [
            u("url", "Endpoint (https://api.day.app/KEY)"),
            o("group", "Group"),
            o("sound", "Sound")
        ],
        |c, m| Ok(req(
            "GET",
            q(
                &format!("{}/{}/{}", c.base("url", ""), enc(&m.title), enc(&m.text)),
                &[
                    ("group", c.or("group", "NDO4Uptime")),
                    ("sound", c.g("sound"))
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "pushy",
        "Pushy",
        "Push",
        [s("key", "API key"), s("device", "Device token")],
        |c, m| post(
            &q("https://api.pushy.me/push", &[("api_key", c.g("key"))]),
            json!({"to": c.g("device"), "data": {"message": m.text}, "notification": {"title": m.title, "body": m.text}})
        )
    ),
    p!(
        "gorush",
        "Gorush",
        "Push",
        [
            u("url", "Server URL"),
            s("device", "Device token"),
            sel("platform", "Platform", &["ios", "android", "huawei"])
        ],
        |c, m| post(
            &format!("{}/api/push", c.base("url", "")),
            json!({"notifications": [{"tokens": [c.g("device")], "platform": match c.g("platform") { "android" => 2, "huawei" => 3, _ => 1 }, "title": m.title, "message": m.text}]})
        )
    ),
    p!(
        "techulus-push",
        "Techulus Push",
        "Push",
        [s("key", "API key")],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://push.techulus.com/api/v1/notify".into(),
                Body::Json(json!({"title": m.title, "body": m.text}))
            ),
            "x-api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "lunasea",
        "LunaSea",
        "Push",
        [
            sel("target", "Target", &["user", "device"]),
            t("id", "User or device ID")
        ],
        |c, m| post(
            &format!(
                "https://notify.lunasea.app/v1/custom/{}/{}",
                if c.g("target") == "device" {
                    "device"
                } else {
                    "user"
                },
                enc(c.g("id"))
            ),
            json!({"title": m.title, "body": m.text})
        )
    ),
    p!(
        "notifery",
        "Notifery",
        "Push",
        [s("key", "API key"), o("group", "Group")],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://api.notifery.com/event".into(),
                Body::Json(
                    json!({"title": m.title, "message": m.text, "group": c.or("group", "NDO4Uptime")})
                )
            ),
            "x-api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "pushdeer",
        "PushDeer",
        "Push",
        [
            s("key", "Push key"),
            ou("server", "Server (default https://api2.pushdeer.com)")
        ],
        |c, m| form(
            &format!(
                "{}/message/push",
                c.base("server", "https://api2.pushdeer.com")
            ),
            &[
                ("pushkey", c.g("key")),
                ("text", &m.title),
                ("desp", &m.text),
                ("type", "text")
            ]
        )
    ),
    p!(
        "pushplus",
        "PushPlus",
        "Push",
        [s("token", "Send key")],
        |c, m| post(
            "https://www.pushplus.plus/send",
            json!({"token": c.g("token"), "title": m.title, "content": m.text})
        )
    ),
    p!(
        "serverchan",
        "ServerChan",
        "Push",
        [s("key", "Send key")],
        |c, m| form(
            &format!("https://sctapi.ftqq.com/{}.send", enc(c.g("key"))),
            &[("title", &m.title), ("desp", &m.text)]
        )
    ),
    p!(
        "spugpush",
        "SpugPush",
        "Push",
        [s("key", "Template key")],
        |c, m| post(
            &format!("https://push.spug.cc/send/{}", enc(c.g("key"))),
            json!({"title": m.title, "content": m.text})
        )
    ),
    p!("wxpusher", "WxPusher", "Push", [s("spt", "SPT")], |c, m| {
        post(
            "https://wxpusher.zjiecode.com/api/send/message/simple-push",
            json!({"content": m.text, "summary": m.title, "spt": c.g("spt")}),
        )
    }),
    p!(
        "wpush",
        "WPush",
        "Push",
        [s("key", "API key"), o("channel", "Channel")],
        |c, m| post(
            "https://api.wpush.cn/api/v1/send",
            json!({"apikey": c.g("key"), "title": m.title, "content": m.text, "channel": c.or("channel", "wechat")})
        )
    ),
    // ------------------------------------------------------------ incident management
    p!(
        "pagerduty",
        "PagerDuty",
        "Incident management",
        [s("key", "Integration key")],
        |c, m| post(
            "https://events.pagerduty.com/v2/enqueue",
            json!({"routing_key": c.g("key"), "event_action": if m.up { "resolve" } else { "trigger" }, "dedup_key": dedup(m), "payload": {"summary": m.title, "source": "NDO4Uptime", "severity": "critical"}})
        )
    ),
    p!(
        "opsgenie",
        "Opsgenie",
        "Incident management",
        [
            s("key", "API key"),
            sel("region", "Region", &["us", "eu"]),
            sel("priority", "Priority", &["P1", "P2", "P3", "P4", "P5"])
        ],
        |c, m| {
            let host = if c.g("region") == "eu" {
                "api.eu.opsgenie.com"
            } else {
                "api.opsgenie.com"
            };
            let r = if m.up {
                req(
                    "POST",
                    format!(
                        "https://{host}/v2/alerts/{}/close?identifierType=alias",
                        dedup(m)
                    ),
                    Body::Json(json!({"note": m.text, "source": "NDO4Uptime"})),
                )
            } else {
                req(
                    "POST",
                    format!("https://{host}/v2/alerts"),
                    Body::Json(
                        json!({"message": m.title, "alias": dedup(m), "description": m.text, "priority": c.or("priority", "P3"), "source": "NDO4Uptime"}),
                    ),
                )
            };
            Ok(with_h(
                r,
                "authorization",
                format!("GenieKey {}", c.g("key")),
            ))
        }
    ),
    p!(
        "pagertree",
        "PagerTree",
        "Incident management",
        [
            u("url", "Integration URL"),
            sel("urgency", "Urgency", &["low", "medium", "high", "critical"])
        ],
        |c, m| post(
            c.g("url"),
            json!({"event_type": if m.up { "resolve" } else { "create" }, "id": dedup(m), "title": m.title, "description": m.text, "urgency": c.or("urgency", "high")})
        )
    ),
    p!(
        "grafana-oncall",
        "Grafana OnCall",
        "Incident management",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"alert_uid": dedup(m), "title": m.title, "message": m.text, "state": if m.up { "ok" } else { "alerting" }})
        )
    ),
    p!(
        "alerta",
        "Alerta",
        "Incident management",
        [
            u("url", "API endpoint"),
            s("key", "API key"),
            t("environment", "Environment")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                c.g("url").into(),
                Body::Json(
                    json!({"environment": c.g("environment"), "severity": if m.up { "ok" } else { "critical" }, "resource": m.name, "event": "NDO4Uptime", "text": m.text, "service": ["NDO4Uptime"]})
                )
            ),
            "authorization",
            format!("Key {}", c.g("key"))
        ))
    ),
    p!(
        "alertnow",
        "AlertNow",
        "Incident management",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"summary": m.text, "status": if m.up { "OK" } else { "CRITICAL" }, "service": m.name})
        )
    ),
    p!(
        "splunk-oncall",
        "Splunk On-Call",
        "Incident management",
        [u("url", "REST endpoint URL")],
        |c, m| post(
            c.g("url"),
            json!({"message_type": if m.up { "RECOVERY" } else { "CRITICAL" }, "entity_id": dedup(m), "entity_display_name": m.name, "state_message": m.text})
        )
    ),
    p!(
        "squadcast",
        "Squadcast",
        "Incident management",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"message": m.title, "description": m.text, "status": if m.up { "resolve" } else { "trigger" }, "event_id": dedup(m)})
        )
    ),
    p!(
        "goalert",
        "GoAlert",
        "Incident management",
        [u("url", "Server URL"), s("token", "Integration token")],
        |c, m| post(
            &q(
                &format!("{}/api/v2/generic/incoming", c.base("url", "")),
                &[("token", c.g("token"))]
            ),
            json!({"summary": m.title, "details": m.text, "action": if m.up { "close" } else { "trigger" }, "dedup": dedup(m)})
        )
    ),
    p!(
        "flashduty",
        "Flashduty",
        "Incident management",
        [s("key", "Integration key")],
        |c, m| post(
            &q(
                "https://api.flashcat.cloud/event/push/alert/standard",
                &[("integration_key", c.g("key"))]
            ),
            json!({"title_rule": "$title", "event_status": if m.up { "Ok" } else { "Critical" }, "alert_key": dedup(m), "title": m.title, "description": m.text})
        )
    ),
    p!(
        "signl4",
        "SIGNL4",
        "Incident management",
        [u("url", "Webhook URL")],
        |c, m| post(
            c.g("url"),
            json!({"title": m.title, "message": m.text, "X-S4-ExternalID": dedup(m), "X-S4-Status": if m.up { "resolved" } else { "new" }, "X-S4-SourceSystem": "NDO4Uptime"})
        )
    ),
    p!(
        "keep",
        "Keep",
        "Incident management",
        [u("url", "Webhook URL"), s("key", "API key")],
        |c, m| Ok(with_h(
            req(
                "POST",
                c.g("url").into(),
                Body::Json(
                    json!({"name": m.title, "message": m.text, "status": if m.up { "resolved" } else { "firing" }, "source": ["NDO4Uptime"]})
                )
            ),
            "x-api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "clickup",
        "ClickUp Chat",
        "Incident management",
        [
            t("workspace", "Workspace ID"),
            t("channel", "Channel ID"),
            s("token", "API token")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                format!(
                    "https://api.clickup.com/api/v3/workspaces/{}/chat/channels/{}/messages",
                    enc(c.g("workspace")),
                    enc(c.g("channel"))
                ),
                Body::Json(json!({"type": "message", "content": m.text}))
            ),
            "authorization",
            c.g("token").into()
        ))
    ),
    p!(
        "bitrix24",
        "Bitrix24",
        "Incident management",
        [u("url", "Webhook URL"), t("user", "User ID")],
        |c, m| Ok(req(
            "GET",
            q(
                &format!("{}/im.notify.system.add.json", c.base("url", "")),
                &[("USER_ID", c.g("user")), ("MESSAGE", &m.text)]
            ),
            Body::None
        ))
    ),
    // ------------------------------------------------------------ email
    p!(
        "sendgrid",
        "SendGrid",
        "Email",
        [
            s("key", "API key"),
            t("from", "From address"),
            t("to", "To address"),
            o("subject", "Subject")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api.sendgrid.com/v3/mail/send".into(),
                Body::Json(
                    json!({"personalizations": [{"to": list(c.g("to")).iter().map(|a| json!({"email": a})).collect::<Vec<_>>()}], "from": {"email": c.g("from")}, "subject": c.or("subject", &m.title), "content": [{"type": "text/plain", "value": m.text}]})
                )
            ),
            c.g("key")
        ))
    ),
    p!(
        "resend",
        "Resend",
        "Email",
        [
            s("key", "API key"),
            t("from", "From address"),
            t("to", "To address"),
            o("subject", "Subject")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api.resend.com/emails".into(),
                Body::Json(
                    json!({"from": c.g("from"), "to": list(c.g("to")), "subject": c.or("subject", &m.title), "text": m.text})
                )
            ),
            c.g("key")
        ))
    ),
    p!(
        "brevo",
        "Brevo",
        "Email",
        [
            s("key", "API key"),
            t("from", "From address"),
            t("to", "To address"),
            o("subject", "Subject")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://api.brevo.com/v3/smtp/email".into(),
                Body::Json(
                    json!({"sender": {"email": c.g("from")}, "to": list(c.g("to")).iter().map(|a| json!({"email": a})).collect::<Vec<_>>(), "subject": c.or("subject", &m.title), "textContent": m.text})
                )
            ),
            "api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "turbosmtp",
        "TurboSMTP",
        "Email",
        [
            t("consumer_key", "Consumer key"),
            s("consumer_secret", "Consumer secret"),
            t("from", "From address"),
            t("to", "To address"),
            o("subject", "Subject")
        ],
        |c, m| Ok(with_h(
            with_h(
                req(
                    "POST",
                    "https://api.turbo-smtp.com/api/v2/mail/send".into(),
                    Body::Json(
                        json!({"from": c.g("from"), "to": c.g("to"), "subject": c.or("subject", &m.title), "content": m.text})
                    )
                ),
                "consumerkey",
                c.g("consumer_key").into()
            ),
            "consumersecret",
            c.g("consumer_secret").into()
        ))
    ),
    // ------------------------------------------------------------ SMS and messaging
    p!(
        "twilio",
        "Twilio",
        "SMS and messaging",
        [
            t("sid", "Account SID"),
            s("token", "Auth token"),
            t("from", "From number"),
            t("to", "To number"),
            o("api_key", "API key SID (optional)")
        ],
        |c, m| {
            let user = c.or("api_key", c.g("sid"));
            Ok(basic(
                req(
                    "POST",
                    format!(
                        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
                        enc(c.g("sid"))
                    ),
                    Body::Form(vec![
                        ("To".into(), c.g("to").into()),
                        ("From".into(), c.g("from").into()),
                        ("Body".into(), m.text.clone()),
                    ]),
                ),
                user,
                c.g("token"),
            ))
        }
    ),
    p!(
        "telnyx",
        "Telnyx",
        "SMS and messaging",
        [
            s("key", "API key"),
            t("from", "From number"),
            t("to", "To number")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api.telnyx.com/v2/messages".into(),
                Body::Json(json!({"from": c.g("from"), "to": c.g("to"), "text": m.text}))
            ),
            c.g("key")
        ))
    ),
    p!(
        "plivo",
        "Plivo",
        "SMS and messaging",
        [
            t("id", "Auth ID"),
            s("token", "Auth token"),
            t("from", "From number"),
            t("to", "To number")
        ],
        |c, m| Ok(basic(
            req(
                "POST",
                format!(
                    "https://api.plivo.com/v1/Account/{}/Message/",
                    enc(c.g("id"))
                ),
                Body::Json(json!({"src": c.g("from"), "dst": c.g("to"), "text": m.text}))
            ),
            c.g("id"),
            c.g("token")
        ))
    ),
    p!(
        "46elks",
        "46elks",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("secret", "Password"),
            t("from", "From"),
            t("to", "To number")
        ],
        |c, m| Ok(basic(
            req(
                "POST",
                "https://api.46elks.com/a1/sms".into(),
                Body::Form(vec![
                    ("from".into(), c.g("from").into()),
                    ("to".into(), c.g("to").into()),
                    ("message".into(), m.text.clone())
                ])
            ),
            c.g("user"),
            c.g("secret")
        ))
    ),
    p!(
        "clicksend",
        "ClickSend",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("key", "API key"),
            o("from", "Sender"),
            t("to", "To number")
        ],
        |c, m| Ok(basic(
            req(
                "POST",
                "https://rest.clicksend.com/v3/sms/send".into(),
                Body::Json(
                    json!({"messages": [{"body": m.text, "to": c.g("to"), "source": "ndo4uptime", "from": c.g("from")}]})
                )
            ),
            c.g("user"),
            c.g("key")
        ))
    ),
    p!(
        "sevenio",
        "seven.io",
        "SMS and messaging",
        [
            s("key", "API key"),
            t("from", "Sender"),
            t("to", "To number")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://gateway.seven.io/api/sms".into(),
                Body::Json(json!({"to": c.g("to"), "from": c.g("from"), "text": m.text}))
            ),
            "x-api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "octopush",
        "Octopush",
        "SMS and messaging",
        [
            t("login", "API login"),
            s("key", "API key"),
            t("to", "To number"),
            t("sender", "Sender name")
        ],
        |c, m| Ok(with_h(
            with_h(
                req(
                    "POST",
                    "https://api.octopush.com/v1/public/sms-campaign/send".into(),
                    Body::Json(
                        json!({"recipients": [{"phone_number": c.g("to")}], "text": m.text, "type": "sms_premium", "purpose": "alert", "sender": c.g("sender")})
                    )
                ),
                "api-login",
                c.g("login").into()
            ),
            "api-key",
            c.g("key").into()
        ))
    ),
    p!(
        "freemobile",
        "Free Mobile",
        "SMS and messaging",
        [t("user", "User"), s("pass", "Password")],
        |c, m| Ok(req(
            "GET",
            q(
                "https://smsapi.free-mobile.fr/sendmsg",
                &[
                    ("user", c.g("user")),
                    ("pass", c.g("pass")),
                    ("msg", &m.text)
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "cellsynt",
        "Cellsynt",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("pass", "Password"),
            t("to", "Destination (00 + number)"),
            t("from", "Originator")
        ],
        |c, m| Ok(req(
            "GET",
            q(
                "https://se-1.cellsynt.net/sms.php",
                &[
                    ("username", c.g("user")),
                    ("password", c.g("pass")),
                    ("destination", c.g("to")),
                    ("text", &m.text),
                    ("originatortype", "alpha"),
                    ("originator", c.g("from"))
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "smsc",
        "SMSC.kz",
        "SMS and messaging",
        [t("login", "Login"), s("pass", "Password"), t("to", "Phone")],
        |c, m| Ok(req(
            "GET",
            q(
                "https://smsc.kz/sys/send.php",
                &[
                    ("login", c.g("login")),
                    ("psw", c.g("pass")),
                    ("phones", c.g("to")),
                    ("mes", &m.text)
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "smsmanager",
        "SMS Manager",
        "SMS and messaging",
        [s("key", "API key"), t("to", "Phone")],
        |c, m| Ok(req(
            "GET",
            q(
                "https://http-api.smsmanager.cz/Send",
                &[
                    ("apikey", c.g("key")),
                    ("number", c.g("to")),
                    ("message", &m.text)
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "egosms",
        "EgoSMS",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("pass", "Password"),
            t("to", "Number"),
            t("from", "Sender")
        ],
        |c, m| Ok(req(
            "GET",
            q(
                "https://www.egosms.co/api/v1/plain/",
                &[
                    ("username", c.g("user")),
                    ("password", c.g("pass")),
                    ("number", c.g("to")),
                    ("message", &m.text),
                    ("sender", c.g("from"))
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "gtx-messaging",
        "GTX Messaging",
        "SMS and messaging",
        [s("key", "API key"), t("from", "Sender"), t("to", "Number")],
        |c, m| Ok(req(
            "GET",
            q(
                &format!(
                    "https://rest.gtx-messaging.net/smsc/sendsms/{}/json",
                    enc(c.g("key"))
                ),
                &[("from", c.g("from")), ("to", c.g("to")), ("text", &m.text)]
            ),
            Body::None
        ))
    ),
    p!(
        "serwersms",
        "SerwerSMS",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("pass", "Password"),
            t("to", "Phone"),
            o("from", "Sender")
        ],
        |c, m| post(
            "https://api2.serwersms.pl/messages/send_sms",
            json!({"username": c.g("user"), "password": c.g("pass"), "phone": c.g("to"), "text": m.text, "sender": c.g("from")})
        )
    ),
    p!(
        "smspartner",
        "SMS Partner",
        "SMS and messaging",
        [s("key", "API key"), t("to", "Phone"), o("from", "Sender")],
        |c, m| post(
            "https://api.smspartner.fr/v1/send",
            json!({"apiKey": c.g("key"), "phoneNumbers": c.g("to"), "message": m.text, "sender": c.g("from")})
        )
    ),
    p!(
        "smsplanet",
        "SMS Planet",
        "SMS and messaging",
        [
            s("token", "API token"),
            t("from", "Sender"),
            t("to", "Phone")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api2.smsplanet.pl/sms".into(),
                Body::Form(vec![
                    ("from".into(), c.g("from").into()),
                    ("to".into(), c.g("to").into()),
                    ("msg".into(), m.text.clone())
                ])
            ),
            c.g("token")
        ))
    ),
    p!(
        "promosms",
        "PromoSMS",
        "SMS and messaging",
        [
            t("login", "Login"),
            s("pass", "Password"),
            t("to", "Phone"),
            t("from", "Sender")
        ],
        |c, m| Ok(basic(
            req(
                "POST",
                "https://promosms.com/api/rest/v3_2/sms".into(),
                Body::Json(
                    json!({"recipients": [c.g("to")], "type": 1, "sender": c.g("from"), "text": m.text})
                )
            ),
            c.g("login"),
            c.g("pass")
        ))
    ),
    p!(
        "whapi",
        "WHAPI (WhatsApp)",
        "SMS and messaging",
        [s("token", "API token"), t("to", "Chat or phone")],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://gate.whapi.cloud/messages/text".into(),
                Body::Json(json!({"to": c.g("to"), "body": m.text}))
            ),
            c.g("token")
        ))
    ),
    p!(
        "waha",
        "WAHA (WhatsApp)",
        "SMS and messaging",
        [
            u("url", "WAHA URL"),
            f("key", "API key", K::Secret, false),
            t("chat", "Chat ID"),
            o("session", "Session")
        ],
        |c, m| {
            let r = req(
                "POST",
                format!("{}/api/sendText", c.base("url", "")),
                Body::Json(
                    json!({"chatId": c.g("chat"), "text": m.text, "session": c.or("session", "default")}),
                ),
            );
            Ok(if c.g("key").is_empty() {
                r
            } else {
                with_h(r, "x-api-key", c.g("key").into())
            })
        }
    ),
    p!(
        "evolution",
        "Evolution API (WhatsApp)",
        "SMS and messaging",
        [
            u("url", "Server URL"),
            s("key", "API key"),
            t("instance", "Instance"),
            t("to", "Number")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                format!(
                    "{}/message/sendText/{}",
                    c.base("url", ""),
                    enc(c.g("instance"))
                ),
                Body::Json(json!({"number": c.g("to"), "text": m.text}))
            ),
            "apikey",
            c.g("key").into()
        ))
    ),
    p!(
        "onesender",
        "OneSender",
        "SMS and messaging",
        [
            u("url", "API URL"),
            s("token", "API token"),
            t("to", "Recipient")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                c.g("url").into(),
                Body::Json(
                    json!({"to": c.g("to"), "type": "text", "recipient_type": "individual", "text": {"body": m.text}})
                )
            ),
            c.g("token")
        ))
    ),
    p!(
        "360messenger",
        "360messenger",
        "SMS and messaging",
        [s("token", "API token"), t("to", "Phone number")],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://api.360messenger.com/v2/sendMessage".into(),
                Body::Form(vec![
                    ("phonenumber".into(), c.g("to").into()),
                    ("text".into(), m.text.clone())
                ])
            ),
            c.g("token")
        ))
    ),
    // ------------------------------------------------------------ added providers
    p!(
        "halopsa",
        "HaloPSA",
        "Incident management",
        [
            u("url", "Webhook URL"),
            o("user", "Username"),
            f("pass", "Password", K::Secret, false)
        ],
        |c, m| {
            let r = req(
                "POST",
                c.g("url").into(),
                Body::Json(json!({
                "title": "NDO4Uptime alert",
                "status": if m.test { "NOTIFICATION" } else if m.up { "UP" } else { "DOWN" },
                "monitor": m.name, "message": m.text, "timestamp": utc(m.time)})),
            );
            Ok(if !c.g("user").is_empty() && !c.g("pass").is_empty() {
                basic(r, c.g("user"), c.g("pass"))
            } else {
                r
            })
        }
    ),
    p!(
        "apprise",
        "Apprise API",
        "Push",
        [u("url", "Apprise API URL"), t("key", "Configuration key")],
        |c, m| post(
            &format!("{}/notify/{}", c.base("url", ""), enc(c.g("key"))),
            json!({"title": m.title, "body": m.text, "type": if m.test { "info" } else if m.up { "success" } else { "failure" }})
        )
    ),
    p!(
        "bearsms",
        "BearSMS",
        "SMS and messaging",
        [
            t("user", "Username"),
            s("hash", "Hash key"),
            t("to", "Phone number"),
            o("from", "Sender ID")
        ],
        |c, m| {
            let uni = if m.text.is_ascii() { "0" } else { "1" };
            let mut p = vec![
                ("app", "ws"),
                ("u", c.g("user")),
                ("h", c.g("hash")),
                ("op", "pv"),
                ("to", c.g("to")),
                ("msg", m.text.as_str()),
                ("unicode", uni),
            ];
            if !c.g("from").is_empty() {
                p.push(("from", c.g("from")));
            }
            Ok(req(
                "GET",
                q("https://app.bearsms.com/index.php", &p),
                Body::None,
            ))
        }
    ),
    p!(
        "callmebot",
        "CallMeBot",
        "Chat",
        [u("url", "Endpoint URL")],
        |c, m| Ok(req("GET", q(c.g("url"), &[("text", &m.text)]), Body::None))
    ),
    p!(
        "flowtriq",
        "Flowtriq",
        "Incident management",
        [
            u("url", "Webhook URL"),
            f("key", "API key", K::Secret, false)
        ],
        |c, m| {
            let r = req(
                "POST",
                c.g("url").into(),
                Body::Json(json!({
                "event": if m.test { "test" } else if m.up { "up" } else { "down" },
                "monitor": m.name, "message": m.text, "time": m.time})),
            );
            Ok(if c.g("key").is_empty() {
                r
            } else {
                with_h(r, "x-api-key", c.g("key").into())
            })
        }
    ),
    p!(
        "fluxer",
        "Fluxer",
        "Chat",
        [u("url", "Webhook URL"), o("username", "Bot name")],
        |c, m| post(
            c.g("url"),
            json!({"username": c.or("username", "NDO4Uptime"), "content": m.text})
        )
    ),
    p!(
        "heii-oncall",
        "Heii On-Call",
        "Incident management",
        [t("trigger", "Trigger ID"), s("key", "API key")],
        |c, m| Ok(bearer(
            req(
                "POST",
                format!(
                    "https://heiioncall.com/triggers/{}/{}",
                    enc(c.g("trigger")),
                    if m.up && !m.test { "resolve" } else { "alert" }
                ),
                Body::Json(
                    json!({"msg": m.text, "monitor": m.name, "status": if m.up { "up" } else { "down" }})
                )
            ),
            c.g("key")
        ))
    ),
    p!(
        "indigo",
        "Indigo",
        "Push",
        [
            u("url", "Server URL"),
            s("key", "API key"),
            o("variable", "Variable ID"),
            o("group", "Action group ID")
        ],
        |c, m| first(indigo(c, m))
    ),
    p!(
        "jira-service-management",
        "Jira Service Management",
        "Incident management",
        [
            t("cloud", "Cloud ID"),
            t("email", "Account email"),
            s("token", "API token"),
            sel("priority", "Priority", &["1", "2", "3", "4", "5"])
        ],
        |c, m| {
            let base = format!(
                "https://api.atlassian.com/jsm/ops/api/{}/v1",
                enc(c.g("cloud"))
            );
            let r = if m.up && !m.test {
                req(
                    "POST",
                    format!("{base}/alerts/{}/close?identifierType=alias", enc(&m.name)),
                    Body::Json(json!({"source": "NDO4Uptime"})),
                )
            } else {
                req(
                    "POST",
                    format!("{base}/alerts"),
                    Body::Json(json!({
                    "message": m.title, "alias": m.name, "description": m.text, "source": "NDO4Uptime",
                    "priority": if m.test { "P5".to_string() } else { format!("P{}", c.or("priority", "3")) }, "tags": ["NDO4Uptime"]})),
                )
            };
            Ok(basic(r, c.g("email"), c.g("token")))
        }
    ),
    p!(
        "max",
        "MAX",
        "Chat",
        [
            s("token", "Bot token"),
            t("chat", "Chat ID"),
            ou("server", "API server (default https://platform-api.max.ru)")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                q(
                    &format!(
                        "{}/messages",
                        c.base("server", "https://platform-api.max.ru")
                    ),
                    &[("chat_id", c.g("chat"))]
                ),
                Body::Json(json!({"text": m.text}))
            ),
            "authorization",
            c.g("token").into()
        ))
    ),
    p!(
        "milky",
        "Milky",
        "Chat",
        [
            u("url", "Server address"),
            s("token", "Access token"),
            sel("type", "Message type", &["private", "group"]),
            t("to", "Receiver ID")
        ],
        |c, m| {
            let group = c.g("type") == "group";
            let id = c
                .g("to")
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::from(c.g("to")));
            let mut body = json!({"message": [{"type": "text", "data": {"text": m.text}}]});
            body[if group { "group_id" } else { "user_id" }] = id;
            let url = format!(
                "{}/api/{}",
                c.base("url", ""),
                if group {
                    "send_group_message"
                } else {
                    "send_private_message"
                }
            );
            Ok(bearer(req("POST", url, Body::Json(body)), c.g("token")))
        }
    ),
    p!(
        "notifyapp",
        "NotifyApp",
        "Push",
        [
            s("token", "Token"),
            t("device", "Device ID"),
            ou("icon", "Icon URL")
        ],
        |c, m| {
            let mut b =
                json!({"text": m.text, "title": m.title, "timeSensitive": !m.up && !m.test});
            if !c.g("icon").is_empty() {
                b["iconUrl"] = c.g("icon").into();
            }
            post(
                &q(
                    &format!(
                        "https://push.getnotifyapp.com/notify-json/{}",
                        enc(c.g("device"))
                    ),
                    &[("token", c.g("token"))],
                ),
                b,
            )
        }
    ),
    p!(
        "onechat",
        "OneChat",
        "Chat",
        [
            s("token", "Access token"),
            t("to", "Receiver ID"),
            t("bot", "Bot ID")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                "https://chat-api.one.th/message/api/v1/push_message".into(),
                Body::Json(
                    json!({"to": c.g("to"), "bot_id": c.g("bot"), "type": "text", "message": m.text})
                )
            ),
            c.g("token")
        ))
    ),
    p!(
        "openwa",
        "OpenWA (WhatsApp)",
        "SMS and messaging",
        [
            u("url", "API URL"),
            s("key", "API key"),
            t("session", "Session"),
            t("chat", "Chat IDs (comma separated)")
        ],
        |c, m| first(openwa(c, m))
    ),
    p!(
        "pinglet",
        "Pinglet",
        "Push",
        [u("url", "Publish URL"), s("key", "API key")],
        |c, m| Ok(bearer(
            req(
                "POST",
                c.base("url", ""),
                Body::Json(
                    json!({"title": m.title, "message": m.text, "status": if m.up { "up" } else { "down" }})
                )
            ),
            c.g("key")
        ))
    ),
    p!(
        "signalgrid",
        "Signalgrid",
        "Push",
        [s("key", "Client key"), t("channel", "Channel")],
        |c, m| form(
            "https://api.signalgrid.co/v1/push",
            &[
                ("client_key", c.g("key")),
                ("channel", c.g("channel")),
                ("title", &m.title),
                ("body", &m.text),
                (
                    "type",
                    if m.test {
                        "INFO"
                    } else if m.up {
                        "SUCCESS"
                    } else {
                        "CRIT"
                    }
                ),
                ("critical", "false")
            ]
        )
    ),
    p!(
        "sms-gateway",
        "SMS Gateway",
        "SMS and messaging",
        [
            u("url", "Gateway URL"),
            s("key", "API key"),
            t("to", "Recipients (comma separated)")
        ],
        |c, m| first(sms_gateway(c, m))
    ),
    p!(
        "smseagle",
        "SMSEagle",
        "SMS and messaging",
        [
            u("url", "Server URL"),
            s("token", "Access token"),
            t("to", "Recipient number")
        ],
        |c, m| Ok(req(
            "GET",
            q(
                &format!("{}/http_api/send_sms", c.base("url", "")),
                &[
                    ("access_token", c.g("token")),
                    ("to", c.g("to")),
                    ("message", &m.text),
                    ("unicode", if m.text.is_ascii() { "0" } else { "1" }),
                    ("highpriority", "0")
                ]
            ),
            Body::None
        ))
    ),
    p!(
        "smsir",
        "SMS.ir",
        "SMS and messaging",
        [
            s("key", "API key"),
            t("to", "Mobile numbers (comma separated)"),
            t("template", "Template ID")
        ],
        |c, m| first(smsir(c, m))
    ),
    p!(
        "yzj",
        "Yunzhijia",
        "Chat",
        [u("url", "Webhook URL"), s("token", "Token")],
        |c, m| post(
            &q(c.g("url"), &[("yzjtype", "0"), ("yzjtoken", c.g("token"))]),
            json!({"content": m.text})
        )
    ),
    p!(
        "ooredoo",
        "Ooredoo SMS",
        "SMS and messaging",
        [
            ou("server", "Server URL (default Ooredoo Maldives)"),
            t("user", "Username"),
            s("key", "Access key"),
            s("token", "Bearer token"),
            t("to", "Recipients (comma separated)")
        ],
        |c, m| Ok(bearer(
            req(
                "POST",
                c.or("server", "https://o-papi1-lb01.ooredoo.mv/bulk_sms/v2")
                    .into(),
                Body::Form(vec![
                    ("username".into(), c.g("user").into()),
                    (
                        "access_key".into(),
                        base64::engine::general_purpose::STANDARD.encode(c.g("key"))
                    ),
                    ("message".into(), m.text.clone()),
                    ("batch".into(), list(c.g("to")).join(" "))
                ])
            ),
            c.g("token")
        ))
    ),
    p!(
        "google-sheets",
        "Google Sheets (webhook)",
        "Incident management",
        [u("url", "Apps Script web app URL")],
        |c, m| post(
            c.g("url"),
            json!({"timestamp": utc(m.time), "status": if m.test { "TEST" } else if m.up { "UP" } else { "DOWN" }, "monitorName": m.name, "message": m.text})
        )
    ),
    p!(
        "amootsms",
        "AmootSMS",
        "SMS and messaging",
        [
            s("token", "API token"),
            t("line", "Line number"),
            t("to", "Mobile numbers (comma separated)")
        ],
        |c, m| Ok(with_h(
            req(
                "POST",
                "https://portal.amootsms.com/rest/SendSimple".into(),
                Body::Form(vec![
                    (
                        "SendDateTime".into(),
                        utc(m.time + 12_600).trim_end_matches(" UTC").to_string()
                    ),
                    ("SMSMessageText".into(), m.text.clone()),
                    ("LineNumber".into(), c.g("line").into()),
                    ("Mobiles".into(), list(c.g("to")).join(","))
                ])
            ),
            "authorization",
            c.g("token").into()
        ))
    ),
    p!(
        "aliyun-sms",
        "Aliyun SMS",
        "SMS and messaging",
        [
            t("key", "Access key ID"),
            s("secret", "Access key secret"),
            t("sign", "Sign name"),
            t("template", "Template code"),
            t("to", "Phone numbers (comma separated)")
        ],
        |c, m| {
            let state = if m.test {
                "TEST"
            } else if m.up {
                "UP"
            } else {
                "DOWN"
            };
            let nonce = format!("{:x}", rand::random::<u64>());
            let ts = utc(m.time).replace(' ', "T").replace("TUTC", "Z");
            let tp = json!({"name": m.name, "time": utc(m.time), "status": state}).to_string();
            let mut p: Vec<(String, String)> = vec![
                ("PhoneNumbers".into(), list(c.g("to")).join(",")),
                ("TemplateCode".into(), c.g("template").into()),
                ("SignName".into(), c.g("sign").into()),
                ("TemplateParam".into(), tp),
                ("AccessKeyId".into(), c.g("key").into()),
                ("Format".into(), "JSON".into()),
                ("SignatureMethod".into(), "HMAC-SHA1".into()),
                ("SignatureVersion".into(), "1.0".into()),
                ("SignatureNonce".into(), nonce),
                ("Timestamp".into(), ts),
                ("Action".into(), "SendSms".into()),
                ("Version".into(), "2017-05-25".into()),
            ];
            p.sort();
            let canon = p
                .iter()
                .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
                .collect::<Vec<_>>()
                .join("&");
            let to_sign = format!("POST&{}&{}", enc("/"), enc(&canon));
            let key = ring::hmac::Key::new(
                ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                format!("{}&", c.g("secret")).as_bytes(),
            );
            let sig = base64::engine::general_purpose::STANDARD
                .encode(ring::hmac::sign(&key, to_sign.as_bytes()).as_ref());
            p.push(("Signature".into(), sig));
            Ok(req(
                "POST",
                "https://dysmsapi.aliyuncs.com/".into(),
                Body::Form(p),
            ))
        }
    ),
    // ----- these three talk to their server in several steps; see mail.rs
    p!(
        "smtp",
        "SMTP email",
        "Email",
        [
            t("host", "Server"),
            o("port", "Port (default by security)"),
            sel("security", "Security", &["starttls", "tls", "none"]),
            o("user", "Username"),
            f("pass", "Password", K::Secret, false),
            t("from", "From address"),
            t("to", "To (comma separated)"),
            o("cc", "Cc"),
            o("bcc", "Bcc")
        ],
        |_, _| Err(SPECIAL_MSG.into())
    ),
    p!(
        "microsoft-graph",
        "Microsoft Graph email",
        "Email",
        [
            t("tenant", "Tenant ID"),
            t("client", "Client ID"),
            s("secret", "Client secret"),
            t("mailbox", "Sender mailbox"),
            t("to", "To (comma separated)"),
            o("cc", "Cc"),
            o("bcc", "Bcc")
        ],
        |_, _| Err(SPECIAL_MSG.into())
    ),
    p!(
        "teltonika",
        "Teltonika router SMS",
        "SMS and messaging",
        [
            u("url", "Router URL"),
            t("user", "Username"),
            s("pass", "Password"),
            t("modem", "Modem ID (e.g. 1-1)"),
            t("to", "Phone number"),
            sel("tls", "Certificate check", &["verify", "skip"])
        ],
        |_, _| Err(SPECIAL_MSG.into())
    ),
];

pub fn provider(key: &str) -> Option<&'static P> {
    PROVIDERS.iter().find(|p| p.key == key)
}

/// Settings may only name http(s) addresses; secrets and text are length-limited.
pub fn validate(p: &P, c: &C) -> Result<(), String> {
    for f in p.fields {
        let v = c.g(f.k);
        if v.len() > 2048 || v.chars().any(char::is_control) {
            return Err(format!(
                "{} is too long or has control characters.",
                f.label
            ));
        }
        if f.req && v.is_empty() {
            return Err(format!("{} is required.", f.label));
        }
        if let K::Select(opts) = f.kind {
            if !v.is_empty() && !opts.contains(&v) {
                return Err(format!("{}: unknown choice.", f.label));
            }
        }
        if f.kind == K::Url && !v.is_empty() {
            let ok = reqwest::Url::parse(v)
                .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
                .unwrap_or(false);
            if !ok {
                return Err(format!(
                    "{} must be an http:// or https:// address.",
                    f.label
                ));
            }
        }
    }
    Ok(())
}

/// Turns the alert payload (as sent to webhooks) into a message.
pub fn message(body: &str) -> M {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let event = v["event"].as_str().unwrap_or("down");
    let name = v["monitor"]["name"]
        .as_str()
        .unwrap_or("Monitor")
        .to_string();
    let time = v["time"].as_i64().unwrap_or_else(crate::db::now);
    let up = event != "down";
    let test = event == "test";
    let title = if test {
        "NDO4Uptime test notification".to_string()
    } else {
        format!("{name} is {}", if up { "UP" } else { "DOWN" })
    };
    let mut text = format!("{title}\n{}", utc(time));
    if let Some(t) = v["monitor"]["target"].as_str() {
        text.push_str(&format!("\nTarget: {t}"));
    }
    if let Some(m) = v["message"].as_str().filter(|m| !m.is_empty()) {
        text.push_str(&format!("\n{m}"));
    }
    if let Some(ms) = v["ping_ms"].as_i64() {
        text.push_str(&format!("\nResponse: {ms} ms"));
    }
    M {
        up,
        test,
        time,
        name,
        title,
        text,
    }
}

fn utc(ts: i64) -> String {
    let (d, s) = (ts.div_euclid(86400), ts.rem_euclid(86400));
    let z = d + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

pub fn config(raw: &str) -> C {
    let v: HashMap<String, String> = serde_json::from_str(raw).unwrap_or_default();
    C(v)
}

const SPECIAL_MSG: &str = "handled by the multi-step sender";

fn first(v: Result<Vec<Req>, String>) -> Result<Req, String> {
    v?.into_iter()
        .next()
        .ok_or_else(|| "nothing to send".to_string())
}
fn indigo(c: &C, m: &M) -> Result<Vec<Req>, String> {
    let url = format!("{}/v2/api/command", c.base("url", ""));
    let mut v = vec![];
    if let Ok(id) = c.g("variable").parse::<i64>() {
        v.push(json!({"id": "ndo4uptime", "message": "indigo.variable.updateValue", "objectId": id, "parameters": {"value": m.text}}));
    }
    if let Ok(id) = c.g("group").parse::<i64>() {
        v.push(
            json!({"id": "ndo4uptime", "message": "indigo.actionGroup.execute", "objectId": id}),
        );
    }
    if v.is_empty() {
        return Err("Set a variable ID, an action group ID, or both.".into());
    }
    Ok(v.into_iter()
        .map(|b| bearer(req("POST", url.clone(), Body::Json(b)), c.g("key")))
        .collect())
}
fn openwa(c: &C, m: &M) -> Result<Vec<Req>, String> {
    let url = format!(
        "{}/api/sessions/{}/messages/send-text",
        c.base("url", ""),
        enc(c.g("session"))
    );
    let ids = list(c.g("chat"));
    if ids.is_empty() {
        return Err("No chat ID given.".into());
    }
    Ok(ids
        .iter()
        .take(10)
        .map(|id| {
            with_h(
                req(
                    "POST",
                    url.clone(),
                    Body::Json(json!({"chatId": id, "text": m.text})),
                ),
                "x-api-key",
                c.g("key").into(),
            )
        })
        .collect())
}
fn sms_gateway(c: &C, m: &M) -> Result<Vec<Req>, String> {
    let url = format!("{}/api/v1/sms/send", c.base("url", ""));
    let to = list(c.g("to"));
    if to.is_empty() {
        return Err("No recipient given.".into());
    }
    Ok(to
        .iter()
        .take(10)
        .map(|n| {
            with_h(
                req(
                    "POST",
                    url.clone(),
                    Body::Json(json!({"to": n, "body": m.text})),
                ),
                "x-api-key",
                c.g("key").into(),
            )
        })
        .collect())
}
fn smsir(c: &C, m: &M) -> Result<Vec<Req>, String> {
    let to = list(c.g("to"));
    if to.is_empty() {
        return Err("No recipient given.".into());
    }
    // the service accepts at most 20 characters of text per template value
    let mut text: String = m.title.chars().filter(|ch| !ch.is_whitespace()).collect();
    text.truncate(text.char_indices().nth(20).map_or(text.len(), |(i, _)| i));
    Ok(to
        .iter()
        .take(10)
        .map(|n| {
            let n = if n.len() == 11 && n.starts_with("09") {
                &n[1..]
            } else {
                n.as_str()
            };
            with_h(
                req(
                    "POST",
                    "https://api.sms.ir/v1/send/verify".into(),
                    Body::Json(json!({
            "mobile": n, "templateId": c.g("template").parse::<i64>().unwrap_or(0),
            "parameters": [{"name": "alert", "value": text}]})),
                ),
                "x-api-key",
                c.g("key").into(),
            )
        })
        .collect())
}

/// Every request a channel needs for one message, in order.
pub fn build_all(kind: &str, raw: &str, body: &str) -> Result<Vec<Req>, String> {
    let p = provider(kind).ok_or("Unknown notification type")?;
    let (c, m) = (config(raw), message(body));
    match kind {
        "indigo" => indigo(&c, &m),
        "openwa" => openwa(&c, &m),
        "sms-gateway" => sms_gateway(&c, &m),
        "smsir" => smsir(&c, &m),
        _ => Ok(vec![(p.build)(&c, &m)?]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECIAL: &[&str] = &["smtp", "microsoft-graph", "teltonika"];

    fn sample(k: &str) -> C {
        let p = provider(k).unwrap();
        C(p.fields
            .iter()
            .map(|f| {
                let v = match f.kind {
                    K::Url => "https://example.com/hook".to_string(),
                    K::Select(o) => o[0].to_string(),
                    _ => "1234".to_string(),
                };
                (f.k.to_string(), v)
            })
            .collect())
    }

    #[test]
    fn every_provider_builds_a_request() {
        let body = crate::sched::payload("down", None, "x", None, None, false);
        let m = message(&body);
        let mut keys = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert!(keys.insert(p.key), "duplicate {}", p.key);
            assert!(CATS.contains(&p.cat), "{}", p.key);
            let c = sample(p.key);
            validate(p, &c).unwrap_or_else(|e| panic!("{}: {e}", p.key));
            if SPECIAL.contains(&p.key) {
                continue;
            }
            let r = (p.build)(&c, &m).unwrap_or_else(|e| panic!("{}: {e}", p.key));
            assert!(
                r.url.starts_with("https://") || r.url.starts_with("http://"),
                "{} {}",
                p.key,
                r.url
            );
            assert!(reqwest::Url::parse(&r.url).is_ok(), "{} {}", p.key, r.url);
        }
        assert!(PROVIDERS.len() >= 100);
    }

    #[test]
    fn private_message_has_no_technical_detail() {
        let body = crate::sched::payload(
            "down",
            None,
            "Connection refused 10.1.2.3:2525",
            Some(9),
            None,
            false,
        );
        let m = message(&body);
        assert!(m.text.contains("is DOWN") && m.text.contains("UTC"));
        for leak in ["10.1.2.3", "2525", "example.com", "Response"] {
            assert!(!m.text.contains(leak), "{leak}");
        }
    }

    #[test]
    fn encoding_and_time() {
        assert_eq!(enc("a b/ç"), "a%20b%2F%C3%A7");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_794_032_688), "2026-11-07 06:24:48 UTC");
    }
}
