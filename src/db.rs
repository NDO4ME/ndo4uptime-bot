use rusqlite::{params, Connection, OptionalExtension, Row};
use std::sync::Mutex;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Runs a query and returns its rows; a database error yields an empty list instead of a panic
/// (the release profile aborts on panic, so request handlers must never unwrap).
fn rows<T, P: rusqlite::Params>(
    c: &Connection,
    sql: &str,
    p: P,
    f: impl FnMut(&Row) -> rusqlite::Result<T>,
) -> Vec<T> {
    (|| -> rusqlite::Result<Vec<T>> { Ok(c.prepare(sql)?.query_map(p, f)?.flatten().collect()) })()
        .unwrap_or_default()
}

pub struct Db(Mutex<Connection>, pub tokio::sync::watch::Sender<u64>);

#[derive(Clone, Debug)]
pub struct Monitor {
    pub id: i64,
    pub name: String,
    pub kind: String, // http | browser | tcp | ping
    pub target: String,
    pub port: i64,
    pub method: String,
    pub headers: String,
    pub body: String,
    pub expect: String,
    pub keyword: String,
    pub interval: i64,
    pub timeout: i64,
    pub retries: i64,
    pub verify_tls: bool,
    pub follow: bool,
    pub enabled: bool,
    pub status: i64, // 0 pending, 1 up, 2 down
    pub fails: i64,
    pub changed: i64,
    pub cert_days: i64,
    pub proxy: String,
    pub selector: String,
    pub third_party: bool,
    pub cert_expiry: i64,
    pub grp: String,
    /// Consecutive failures before the monitor is DOWN; 0 = use the global default from Settings.
    pub confirm: i64,
    /// Network route: 0 automatic (tailnet addresses use Tailscale), 1 always Tailscale, 2 direct.
    pub net: i64,
    pub webhooks: Vec<i64>,
}

impl Monitor {
    pub fn blank() -> Self {
        Monitor {
            id: 0,
            name: String::new(),
            kind: "http".into(),
            target: String::new(),
            port: 443,
            method: "GET".into(),
            headers: String::new(),
            body: String::new(),
            expect: "200-299".into(),
            keyword: String::new(),
            interval: 60,
            timeout: 10,
            retries: 1,
            verify_tls: true,
            follow: true,
            enabled: true,
            status: 0,
            fails: 0,
            changed: 0,
            cert_days: 0,
            proxy: String::new(),
            selector: String::new(),
            third_party: false,
            cert_expiry: 0,
            grp: String::new(),
            confirm: 0,
            net: 0,
            webhooks: vec![],
        }
    }
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Monitor {
            id: r.get(0)?,
            name: r.get(1)?,
            kind: r.get(2)?,
            target: r.get(3)?,
            port: r.get(4)?,
            method: r.get(5)?,
            headers: r.get(6)?,
            body: r.get(7)?,
            expect: r.get(8)?,
            keyword: r.get(9)?,
            interval: r.get(10)?,
            timeout: r.get(11)?,
            retries: r.get(12)?,
            verify_tls: r.get(13)?,
            follow: r.get(14)?,
            enabled: r.get(15)?,
            status: r.get(16)?,
            fails: r.get(17)?,
            changed: r.get(18)?,
            cert_days: r.get(19)?,
            cert_expiry: r.get(20)?,
            proxy: r.get(21)?,
            selector: r.get(22)?,
            third_party: r.get(23)?,
            grp: r.get(24)?,
            confirm: r.get(25)?,
            net: r.get(26)?,
            webhooks: vec![],
        })
    }
}

const MCOLS: &str = "id,name,kind,target,port,method,headers,body,expect,keyword,interval_s,timeout_s,retries,verify_tls,follow,enabled,status,fails,changed,cert_days,cert_expiry,proxy,selector,third_party,grp,confirm,net";

#[derive(Clone, Debug, Default)]
pub struct StatusPage {
    pub id: i64,
    pub slug: String,
    pub title: String,
    pub description: String,
    pub domain: String,
    pub enabled: bool,
    /// (monitor id, group name)
    pub items: Vec<(i64, String)>,
}

#[derive(Clone, Debug)]
pub struct Webhook {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub headers: String,
    pub secret: String,
    pub enabled: bool,
    pub last_ts: i64,
    pub last_msg: String,
}

impl Webhook {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Webhook {
            id: r.get(0)?,
            name: r.get(1)?,
            url: r.get(2)?,
            headers: r.get(3)?,
            secret: r.get(4)?,
            enabled: r.get(5)?,
            last_ts: r.get(6)?,
            last_msg: r.get(7)?,
        })
    }
}
const WCOLS: &str = "id,name,url,headers,secret,enabled,last_ts,last_msg";

#[derive(Clone, Debug)]
pub struct Beat {
    pub ts: i64,
    pub ok: bool,
    /// A failure that is not yet confirmed as DOWN.
    pub soft: bool,
    pub ms: Option<i64>,
    pub msg: String,
}

#[derive(Default, Clone, Copy)]
pub struct Stats {
    pub total: i64,
    pub ok: i64,
    pub avg_ms: Option<f64>,
}
impl Stats {
    pub fn pct(&self) -> Option<f64> {
        if self.total == 0 {
            None
        } else {
            Some(self.ok as f64 * 100.0 / self.total as f64)
        }
    }
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Db> {
        let c = Connection::open(path)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, hash TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS monitors(
               id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL,
               port INTEGER NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT 'GET', headers TEXT NOT NULL DEFAULT '',
               body TEXT NOT NULL DEFAULT '', expect TEXT NOT NULL DEFAULT '200-299', keyword TEXT NOT NULL DEFAULT '',
               interval_s INTEGER NOT NULL DEFAULT 60, timeout_s INTEGER NOT NULL DEFAULT 10, retries INTEGER NOT NULL DEFAULT 1,
               verify_tls INTEGER NOT NULL DEFAULT 1, follow INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
               status INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, changed INTEGER NOT NULL DEFAULT 0,
               created INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS heartbeats(
               id INTEGER PRIMARY KEY, mid INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
               ts INTEGER NOT NULL, ok INTEGER NOT NULL, ms INTEGER, msg TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS hb_mid_ts ON heartbeats(mid, ts);
             CREATE TABLE IF NOT EXISTS webhooks(
               id INTEGER PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, headers TEXT NOT NULL DEFAULT '',
               secret TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
               last_ts INTEGER NOT NULL DEFAULT 0, last_msg TEXT NOT NULL DEFAULT '');
             CREATE TABLE IF NOT EXISTS monitor_webhooks(
               mid INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
               wid INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE, PRIMARY KEY(mid, wid));
             CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pages(
               id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
               domain TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
             CREATE UNIQUE INDEX IF NOT EXISTS pages_domain ON pages(domain) WHERE domain<>'';
             CREATE TABLE IF NOT EXISTS page_monitors(
               pid INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
               mid INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
               grp TEXT NOT NULL DEFAULT '', PRIMARY KEY(pid, mid));",
        )?;
        for (table, col, ddl) in [
            (
                "heartbeats",
                "soft",
                "ALTER TABLE heartbeats ADD COLUMN soft INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "monitors",
                "confirm",
                "ALTER TABLE monitors ADD COLUMN confirm INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "monitors",
                "proxy",
                "ALTER TABLE monitors ADD COLUMN proxy TEXT NOT NULL DEFAULT ''",
            ),
            (
                "monitors",
                "selector",
                "ALTER TABLE monitors ADD COLUMN selector TEXT NOT NULL DEFAULT ''",
            ),
            (
                "monitors",
                "third_party",
                "ALTER TABLE monitors ADD COLUMN third_party INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "monitors",
                "cert_days",
                "ALTER TABLE monitors ADD COLUMN cert_days INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "monitors",
                "net",
                "ALTER TABLE monitors ADD COLUMN net INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "monitors",
                "grp",
                "ALTER TABLE monitors ADD COLUMN grp TEXT NOT NULL DEFAULT ''",
            ),
            (
                "monitors",
                "cert_expiry",
                "ALTER TABLE monitors ADD COLUMN cert_expiry INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            let has: bool = c
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name=?2",
                    [table, col],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n > 0)?;
            if !has {
                c.execute_batch(ddl)?;
            }
        }
        Ok(Db(Mutex::new(c), tokio::sync::watch::channel(0).0))
    }

    /// Runs a mutation and wakes every live stream so viewers see it immediately.
    fn write<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        let r = self.with(f);
        self.1.send_modify(|v| *v = v.wrapping_add(1));
        r
    }

    pub fn with<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        let g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&g)
    }

    // ---- users / sessions
    pub fn user_count(&self) -> i64 {
        self.with(|c| {
            c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
                .unwrap_or(0)
        })
    }
    pub fn first_user(&self) -> Option<(i64, String, String)> {
        self.with(|c| {
            c.query_row(
                "SELECT id,username,hash FROM users ORDER BY id LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()
            .flatten()
        })
    }
    pub fn create_user(&self, name: &str, hash: &str) -> bool {
        self.with(|c| {
            c.execute(
                "INSERT INTO users(username,hash) VALUES(?1,?2)",
                params![name, hash],
            )
            .is_ok()
        })
    }
    pub fn set_password(&self, id: i64, hash: &str) {
        self.with(|c| {
            let _ = c.execute("UPDATE users SET hash=?1 WHERE id=?2", params![hash, id]);
        })
    }
    pub fn session_add(&self, token_hash: &str, csrf: &str, expires: i64) {
        self.with(|c| {
            let _ = c.execute(
                "INSERT INTO sessions(token,csrf,expires) VALUES(?1,?2,?3)",
                params![token_hash, csrf, expires],
            );
        })
    }
    pub fn session_get(&self, token_hash: &str) -> Option<(String, i64)> {
        self.with(|c| {
            c.query_row(
                "SELECT csrf,expires FROM sessions WHERE token=?1",
                [token_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten()
        })
    }
    pub fn session_touch(&self, token_hash: &str, expires: i64) {
        self.with(|c| {
            let _ = c.execute(
                "UPDATE sessions SET expires=?1 WHERE token=?2",
                params![expires, token_hash],
            );
        })
    }
    pub fn session_del(&self, token_hash: &str) {
        self.with(|c| {
            let _ = c.execute("DELETE FROM sessions WHERE token=?1", [token_hash]);
        })
    }
    pub fn sessions_clear(&self, except: Option<&str>) {
        self.with(|c| {
            let _ = c.execute(
                "DELETE FROM sessions WHERE token<>?1",
                [except.unwrap_or("")],
            );
        })
    }
    pub fn sessions_gc(&self) {
        self.with(|c| {
            let _ = c.execute("DELETE FROM sessions WHERE expires<?1", [now()]);
        })
    }

    // ---- monitors
    pub fn monitors(&self) -> Vec<Monitor> {
        self.with(|c| {
            rows(
                c,
                &format!("SELECT {MCOLS} FROM monitors ORDER BY name COLLATE NOCASE"),
                [],
                Monitor::from_row,
            )
        })
    }
    pub fn monitor(&self, id: i64) -> Option<Monitor> {
        self.with(|c| {
            let mut m = c
                .query_row(
                    &format!("SELECT {MCOLS} FROM monitors WHERE id=?1"),
                    [id],
                    Monitor::from_row,
                )
                .optional()
                .ok()
                .flatten()?;
            let mut s = c
                .prepare("SELECT wid FROM monitor_webhooks WHERE mid=?1")
                .ok()?;
            m.webhooks = s.query_map([id], |r| r.get(0)).ok()?.flatten().collect();
            Some(m)
        })
    }
    pub fn save_monitor(&self, m: &Monitor) -> i64 {
        self.write(|c| {
            let id = if m.id > 0 {
                let _ = c.execute(
                    "UPDATE monitors SET name=?1,kind=?2,target=?3,port=?4,method=?5,headers=?6,body=?7,expect=?8,keyword=?9,
                     interval_s=?10,timeout_s=?11,retries=?12,verify_tls=?13,follow=?14,cert_days=?15,proxy=?16,selector=?17,third_party=?18,grp=?19,confirm=?20,net=?21,status=0,fails=0 WHERE id=?22",
                    params![m.name, m.kind, m.target, m.port, m.method, m.headers, m.body, m.expect, m.keyword,
                            m.interval, m.timeout, m.retries, m.verify_tls, m.follow, m.cert_days, m.proxy, m.selector, m.third_party, m.grp, m.confirm, m.net, m.id],
                );
                m.id
            } else {
                let _ = c.execute(
                    "INSERT INTO monitors(name,kind,target,port,method,headers,body,expect,keyword,interval_s,timeout_s,retries,verify_tls,follow,cert_days,proxy,selector,third_party,grp,confirm,net,created)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
                    params![m.name, m.kind, m.target, m.port, m.method, m.headers, m.body, m.expect, m.keyword,
                            m.interval, m.timeout, m.retries, m.verify_tls, m.follow, m.cert_days, m.proxy, m.selector, m.third_party, m.grp, m.confirm, m.net, now()],
                );
                c.last_insert_rowid()
            };
            let _ = c.execute("DELETE FROM monitor_webhooks WHERE mid=?1", [id]);
            for w in &m.webhooks {
                let _ = c.execute("INSERT OR IGNORE INTO monitor_webhooks(mid,wid) VALUES(?1,?2)", params![id, w]);
            }
            id
        })
    }
    pub fn delete_monitor(&self, id: i64) {
        self.write(|c| {
            let _ = c.execute("DELETE FROM monitors WHERE id=?1", [id]);
        })
    }
    pub fn set_enabled(&self, id: i64, on: bool) {
        self.write(|c| {
            let _ = c.execute(
                "UPDATE monitors SET enabled=?1,status=0,fails=0 WHERE id=?2",
                params![on, id],
            );
        })
    }
    pub fn set_state(&self, id: i64, status: i64, fails: i64, changed: Option<i64>) {
        self.write(|c| {
            let _ = match changed {
                Some(t) => c.execute(
                    "UPDATE monitors SET status=?1,fails=?2,changed=?3 WHERE id=?4",
                    params![status, fails, t, id],
                ),
                None => c.execute(
                    "UPDATE monitors SET status=?1,fails=?2 WHERE id=?3",
                    params![status, fails, id],
                ),
            };
        })
    }

    pub fn set_cert(&self, id: i64, expiry: i64) {
        self.write(|c| {
            let _ = c.execute(
                "UPDATE monitors SET cert_expiry=?1 WHERE id=?2",
                params![expiry, id],
            );
        })
    }

    // ---- heartbeats
    pub fn add_beat(&self, mid: i64, ok: bool, soft: bool, ms: Option<i64>, msg: &str) {
        self.write(|c| {
            let _ = c.execute(
                "INSERT INTO heartbeats(mid,ts,ok,ms,msg,soft) VALUES(?1,?2,?3,?4,?5,?6)",
                params![mid, now(), ok, ms, msg, soft],
            );
        })
    }
    pub fn beats(&self, mid: i64, limit: i64) -> Vec<Beat> {
        self.with(|c| {
            rows(
                c,
                "SELECT ts,ok,ms,msg,soft FROM heartbeats WHERE mid=?1 ORDER BY ts DESC, id DESC LIMIT ?2",
                params![mid, limit],
                |r| Ok(Beat { ts: r.get(0)?, ok: r.get(1)?, ms: r.get(2)?, msg: r.get(3)?, soft: r.get(4)? }),
            )
        })
    }
    pub fn stats(&self, mid: i64, since: i64) -> Stats {
        self.with(|c| {
            c.query_row(
                "SELECT COUNT(*),COALESCE(SUM(ok),0),AVG(CASE WHEN ok=1 THEN ms END) FROM heartbeats WHERE mid=?1 AND ts>=?2",
                params![mid, since],
                |r| Ok(Stats { total: r.get(0)?, ok: r.get(1)?, avg_ms: r.get(2)? }),
            )
            .unwrap_or_default()
        })
    }
    pub fn prune(&self, days: i64) {
        self.with(|c| {
            let _ = c.execute("DELETE FROM heartbeats WHERE ts<?1", [now() - days * 86400]);
        })
    }

    // ---- webhooks
    pub fn webhooks(&self) -> Vec<Webhook> {
        self.with(|c| {
            rows(
                c,
                &format!("SELECT {WCOLS} FROM webhooks ORDER BY name COLLATE NOCASE"),
                [],
                Webhook::from_row,
            )
        })
    }
    pub fn webhook(&self, id: i64) -> Option<Webhook> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {WCOLS} FROM webhooks WHERE id=?1"),
                [id],
                Webhook::from_row,
            )
            .optional()
            .ok()
            .flatten()
        })
    }
    pub fn webhooks_for(&self, mid: i64) -> Vec<Webhook> {
        self.with(|c| {
            rows(
                c,
                &format!("SELECT {WCOLS} FROM webhooks WHERE enabled=1 AND id IN (SELECT wid FROM monitor_webhooks WHERE mid=?1)"),
                [mid],
                Webhook::from_row,
            )
        })
    }
    pub fn save_webhook(&self, w: &Webhook) -> i64 {
        self.with(|c| {
            if w.id > 0 {
                let _ = c.execute(
                    "UPDATE webhooks SET name=?1,url=?2,headers=?3,secret=?4 WHERE id=?5",
                    params![w.name, w.url, w.headers, w.secret, w.id],
                );
                w.id
            } else {
                let _ = c.execute(
                    "INSERT INTO webhooks(name,url,headers,secret) VALUES(?1,?2,?3,?4)",
                    params![w.name, w.url, w.headers, w.secret],
                );
                c.last_insert_rowid()
            }
        })
    }
    pub fn delete_webhook(&self, id: i64) {
        self.with(|c| {
            let _ = c.execute("DELETE FROM webhooks WHERE id=?1", [id]);
        })
    }
    pub fn toggle_webhook(&self, id: i64) {
        self.with(|c| {
            let _ = c.execute("UPDATE webhooks SET enabled=1-enabled WHERE id=?1", [id]);
        })
    }
    pub fn webhook_result(&self, id: i64, msg: &str) {
        self.with(|c| {
            let _ = c.execute(
                "UPDATE webhooks SET last_ts=?1,last_msg=?2 WHERE id=?3",
                params![now(), msg, id],
            );
        })
    }

    // ---- settings (key/value)
    pub fn setting(&self, k: &str) -> String {
        self.with(|c| {
            c.query_row("SELECT v FROM settings WHERE k=?1", [k], |r| r.get(0))
                .unwrap_or_default()
        })
    }
    pub fn set_setting(&self, k: &str, v: &str) {
        self.write(|c| {
            let _ = c.execute(
                "INSERT INTO settings(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                params![k, v],
            );
        })
    }

    /// Global default: consecutive failed checks before a monitor is declared DOWN (1–10).
    pub fn down_after(&self) -> i64 {
        self.setting("down_after").parse().unwrap_or(3).clamp(1, 10)
    }
    /// Seconds between re-checks while a failure is being confirmed (10–300).
    pub fn recheck_secs(&self) -> i64 {
        self.setting("recheck_s")
            .parse()
            .unwrap_or(20)
            .clamp(10, 300)
    }
    /// Effective threshold for one monitor.
    pub fn threshold(&self, m: &Monitor) -> i64 {
        if m.confirm > 0 {
            m.confirm.min(10)
        } else {
            self.down_after()
        }
    }

    // ---- status pages
    fn page_row(c: &Connection, where_: &str, arg: &str) -> Option<StatusPage> {
        let mut p = c
            .query_row(
                &format!(
                    "SELECT id,slug,title,description,domain,enabled FROM pages WHERE {where_}"
                ),
                [arg],
                |r| {
                    Ok(StatusPage {
                        id: r.get(0)?,
                        slug: r.get(1)?,
                        title: r.get(2)?,
                        description: r.get(3)?,
                        domain: r.get(4)?,
                        enabled: r.get(5)?,
                        items: vec![],
                    })
                },
            )
            .optional()
            .ok()
            .flatten()?;
        let mut s = c
            .prepare(
                "SELECT mid,grp FROM page_monitors WHERE pid=?1 ORDER BY grp COLLATE NOCASE, mid",
            )
            .ok()?;
        p.items = s
            .query_map([p.id], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok()?
            .flatten()
            .collect();
        Some(p)
    }
    pub fn pages(&self) -> Vec<StatusPage> {
        self.with(|c| {
            let ids: Vec<String> = c
                .prepare("SELECT id FROM pages ORDER BY title COLLATE NOCASE")
                .and_then(|mut s| {
                    s.query_map([], |r| r.get::<_, i64>(0).map(|i| i.to_string()))?
                        .collect()
                })
                .unwrap_or_default();
            ids.iter()
                .filter_map(|i| Self::page_row(c, "id=?1", i))
                .collect()
        })
    }
    pub fn page(&self, id: i64) -> Option<StatusPage> {
        self.with(|c| Self::page_row(c, "id=?1", &id.to_string()))
    }
    pub fn page_by_slug(&self, slug: &str) -> Option<StatusPage> {
        self.with(|c| Self::page_row(c, "slug=?1", slug))
    }
    pub fn page_by_domain(&self, domain: &str) -> Option<StatusPage> {
        if domain.is_empty() {
            return None;
        }
        self.with(|c| Self::page_row(c, "domain=?1", domain))
    }
    /// Err carries a user-facing message (slug or domain already used).
    pub fn save_page(&self, p: &StatusPage) -> Result<i64, &'static str> {
        self.write(|c| {
            let dup = |sql: &str, v: &str| -> bool {
                c.query_row(sql, params![v, p.id], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0
            };
            if dup("SELECT COUNT(*) FROM pages WHERE slug=?1 AND id<>?2", &p.slug) {
                return Err("That address (slug) is already used by another page.");
            }
            if !p.domain.is_empty() && dup("SELECT COUNT(*) FROM pages WHERE domain=?1 AND id<>?2", &p.domain) {
                return Err("That custom domain is already used by another page.");
            }
            let id = if p.id > 0 {
                c.execute(
                    "UPDATE pages SET slug=?1,title=?2,description=?3,domain=?4,enabled=?5 WHERE id=?6",
                    params![p.slug, p.title, p.description, p.domain, p.enabled, p.id],
                )
                .map_err(|_| "Could not save the page.")?;
                p.id
            } else {
                c.execute(
                    "INSERT INTO pages(slug,title,description,domain,enabled,created) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![p.slug, p.title, p.description, p.domain, p.enabled, now()],
                )
                .map_err(|_| "Could not save the page.")?;
                c.last_insert_rowid()
            };
            let _ = c.execute("DELETE FROM page_monitors WHERE pid=?1", [id]);
            for (mid, g) in &p.items {
                let _ = c.execute(
                    "INSERT OR IGNORE INTO page_monitors(pid,mid,grp) VALUES(?1,?2,?3)",
                    params![id, mid, g],
                );
            }
            Ok(id)
        })
    }
    pub fn delete_page(&self, id: i64) {
        self.write(|c| {
            let _ = c.execute("DELETE FROM pages WHERE id=?1", [id]);
        })
    }
    pub fn toggle_page(&self, id: i64) {
        self.write(|c| {
            let _ = c.execute("UPDATE pages SET enabled=1-enabled WHERE id=?1", [id]);
        })
    }
}
