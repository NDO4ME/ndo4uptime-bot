//! Data access for maintenance windows, incident history, storage limits and metrics queries.

use crate::db::{now, Db};
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hard ceiling on stored heartbeats per monitor, whatever the retention period says.
pub const HB_CAP: i64 = 50_000;
pub const INCIDENT_KEEP_DAYS: i64 = 365;
pub const INCIDENT_CAP: i64 = 5_000;

// ------------------------------------------------------------------ maintenance windows
#[derive(Clone, Debug, Default)]
pub struct Maint {
    pub id: i64,
    pub title: String,
    pub message: String,
    pub start: i64,
    pub end: i64,
    /// 0 = once, otherwise repeats every N days (1 = daily, 7 = weekly).
    pub repeat_days: i64,
    pub all: bool,
    /// Announce on status pages that include an affected monitor.
    pub public: bool,
    pub enabled: bool,
    pub mons: Vec<i64>,
}

impl Maint {
    /// The occurrence that is running now or is the next to run: `(start, end)`.
    pub fn window(&self, t: i64) -> Option<(i64, i64)> {
        if self.end <= self.start {
            return None;
        }
        let dur = self.end - self.start;
        if self.repeat_days <= 0 {
            return (t < self.end).then_some((self.start, self.end));
        }
        let period = self.repeat_days * 86400;
        if dur >= period || t < self.start {
            return (t < self.start).then_some((self.start, self.end));
        }
        let s = self.start + (t - self.start) / period * period;
        Some(if t < s + dur {
            (s, s + dur)
        } else {
            (s + period, s + period + dur)
        })
    }
    pub fn active(&self, t: i64) -> bool {
        self.enabled && self.window(t).is_some_and(|(s, e)| s <= t && t < e)
    }
    /// Next occurrence starting within `within` seconds.
    pub fn upcoming(&self, t: i64, within: i64) -> Option<(i64, i64)> {
        if !self.enabled {
            return None;
        }
        self.window(t).filter(|(s, _)| *s > t && *s - t <= within)
    }
    pub fn applies(&self, mid: i64) -> bool {
        self.all || self.mons.contains(&mid)
    }
}

static MAINT_CACHE: Mutex<Option<(Instant, Arc<Vec<Maint>>)>> = Mutex::new(None);

fn invalidate() {
    *MAINT_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

// ------------------------------------------------------------------ incidents
#[derive(Clone, Debug)]
pub struct Incident {
    pub mid: i64,
    pub name: String,
    pub started: i64,
    /// 0 while ongoing.
    pub ended: i64,
    /// AI-written texts: neutral status-page statement, operator analysis, and the model that wrote them.
    pub ai_public: String,
    pub ai_text: String,
    pub ai_model: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Storage {
    pub used: i64,
    pub file: i64,
    pub heartbeats: i64,
    pub incidents: i64,
    pub oldest: i64,
}

impl Db {
    // ---- maintenance
    fn load_maints(&self) -> Vec<Maint> {
        self.with(|c| {
            let Ok(mut s) = c.prepare(
                "SELECT id,title,message,start_ts,end_ts,repeat_days,all_mons,public,enabled FROM maint ORDER BY start_ts DESC",
            ) else {
                return vec![];
            };
            let mut list: Vec<Maint> = s
                .query_map([], |r| {
                    Ok(Maint {
                        id: r.get(0)?,
                        title: r.get(1)?,
                        message: r.get(2)?,
                        start: r.get(3)?,
                        end: r.get(4)?,
                        repeat_days: r.get(5)?,
                        all: r.get(6)?,
                        public: r.get(7)?,
                        enabled: r.get(8)?,
                        mons: vec![],
                    })
                })
                .map(|it| it.flatten().collect())
                .unwrap_or_default();
            if let Ok(mut q) = c.prepare("SELECT mid FROM maint_monitors WHERE maint_id=?1") {
                for m in &mut list {
                    m.mons = q
                        .query_map([m.id], |r| r.get(0))
                        .map(|it| it.flatten().collect())
                        .unwrap_or_default();
                }
            }
            list
        })
    }
    /// Cached for a few seconds: the scheduler and every live render ask for it.
    pub fn maints(&self) -> Arc<Vec<Maint>> {
        let mut g = MAINT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, v)) = g.as_ref() {
            if at.elapsed() < Duration::from_secs(5) {
                return v.clone();
            }
        }
        let v = Arc::new(self.load_maints());
        *g = Some((Instant::now(), v.clone()));
        v
    }
    pub fn maint(&self, id: i64) -> Option<Maint> {
        self.load_maints().into_iter().find(|m| m.id == id)
    }
    /// The window that currently silences a monitor, if any.
    pub fn in_maintenance(&self, mid: i64) -> Option<Maint> {
        let t = now();
        self.maints()
            .iter()
            .find(|m| m.active(t) && m.applies(mid))
            .cloned()
    }
    pub fn save_maint(&self, m: &Maint) -> i64 {
        let id = self.write(|c| {
            let tx = c.unchecked_transaction().ok();
            let c = tx.as_deref().unwrap_or(c);
            let id = if m.id > 0 {
                let _ = c.execute(
                    "UPDATE maint SET title=?1,message=?2,start_ts=?3,end_ts=?4,repeat_days=?5,all_mons=?6,public=?7,enabled=?8 WHERE id=?9",
                    params![m.title, m.message, m.start, m.end, m.repeat_days, m.all, m.public, m.enabled, m.id],
                );
                m.id
            } else {
                let _ = c.execute(
                    "INSERT INTO maint(title,message,start_ts,end_ts,repeat_days,all_mons,public,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![m.title, m.message, m.start, m.end, m.repeat_days, m.all, m.public, m.enabled],
                );
                c.last_insert_rowid()
            };
            let _ = c.execute("DELETE FROM maint_monitors WHERE maint_id=?1", [id]);
            for mid in &m.mons {
                let _ = c.execute(
                    "INSERT OR IGNORE INTO maint_monitors(maint_id,mid) VALUES(?1,?2)",
                    params![id, mid],
                );
            }
            if let Some(tx) = tx {
                let _ = tx.commit();
            }
            id
        });
        invalidate();
        id
    }
    pub fn delete_maint(&self, id: i64) {
        self.write(|c| {
            let _ = c.execute("DELETE FROM maint WHERE id=?1", [id]);
        });
        invalidate();
    }
    pub fn toggle_maint(&self, id: i64) {
        self.write(|c| {
            let _ = c.execute("UPDATE maint SET enabled=1-enabled WHERE id=?1", [id]);
        });
        invalidate();
    }

    // ---- mute
    pub fn set_mute(&self, id: i64, until: i64) {
        self.write(|c| {
            let _ = c.execute(
                "UPDATE monitors SET mute_until=?1 WHERE id=?2",
                params![until, id],
            );
        })
    }
    pub fn set_alerted(&self, id: i64, v: bool) {
        self.with(|c| {
            let _ = c.execute("UPDATE monitors SET alerted=?1 WHERE id=?2", params![v, id]);
        })
    }

    // ---- incidents
    pub fn open_incident(&self, mid: i64) {
        self.write(|c| {
            let open: i64 = c
                .query_row(
                    "SELECT COUNT(*) FROM incidents WHERE mid=?1 AND ended=0",
                    [mid],
                    |r| r.get(0),
                )
                .unwrap_or(1);
            if open == 0 {
                let _ = c.execute(
                    "INSERT INTO incidents(mid,started,ended) VALUES(?1,?2,0)",
                    params![mid, now()],
                );
            }
        })
    }
    pub fn close_incident(&self, mid: i64) {
        self.write(|c| {
            let _ = c.execute(
                "UPDATE incidents SET ended=?1 WHERE mid=?2 AND ended=0",
                params![now(), mid],
            );
        })
    }
    fn incident_rows(&self, sql: &str, p: impl rusqlite::Params) -> Vec<Incident> {
        self.with(|c| {
            let Ok(mut s) = c.prepare(sql) else {
                return vec![];
            };
            s.query_map(p, |r| {
                Ok(Incident {
                    mid: r.get(0)?,
                    name: r.get(1)?,
                    started: r.get(2)?,
                    ended: r.get(3)?,
                    ai_public: r.get(4)?,
                    ai_text: r.get(5)?,
                    ai_model: r.get(6)?,
                })
            })
            .map(|it| it.flatten().collect())
            .unwrap_or_default()
        })
    }
    pub fn incidents_for_monitor(&self, mid: i64, limit: i64) -> Vec<Incident> {
        self.incident_rows(
            "SELECT i.mid,m.name,i.started,i.ended,i.ai_public,i.ai_text,i.ai_model FROM incidents i JOIN monitors m ON m.id=i.mid
             WHERE i.mid=?1 ORDER BY i.started DESC LIMIT ?2",
            params![mid, limit],
        )
    }
    /// Ongoing first, then newest first. Only the given monitors; ids are integers, never text.
    pub fn incidents_for(&self, mids: &[i64], since: i64, limit: i64) -> Vec<Incident> {
        if mids.is_empty() {
            return vec![];
        }
        let list = mids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.incident_rows(
            &format!(
                "SELECT i.mid,m.name,i.started,i.ended,i.ai_public,i.ai_text,i.ai_model FROM incidents i JOIN monitors m ON m.id=i.mid
                 WHERE i.mid IN ({list}) AND (i.ended=0 OR i.started>=?1)
                 ORDER BY (i.ended=0) DESC, i.started DESC LIMIT ?2"
            ),
            params![since, limit],
        )
    }
    /// Attaches AI text to the monitor's ongoing incident (no-op when it already ended).
    pub fn set_incident_ai(&self, mid: i64, public: Option<&str>, text: Option<&str>, model: &str) {
        self.write(|c| {
            if let Some(t) = public {
                let _ = c.execute(
                    "UPDATE incidents SET ai_public=?1, ai_model=?2 WHERE mid=?3 AND ended=0",
                    params![t, model, mid],
                );
            }
            if let Some(t) = text {
                let _ = c.execute(
                    "UPDATE incidents SET ai_text=?1, ai_model=?2 WHERE mid=?3 AND ended=0",
                    params![t, model, mid],
                );
            }
        })
    }
    /// Ongoing incidents that carry a public statement, for the given monitors (status pages).
    pub fn ai_updates(&self, mids: &[i64]) -> Vec<Incident> {
        if mids.is_empty() {
            return vec![];
        }
        let list = mids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.incident_rows(
            &format!(
                "SELECT i.mid,m.name,i.started,i.ended,i.ai_public,i.ai_text,i.ai_model FROM incidents i JOIN monitors m ON m.id=i.mid
                 WHERE i.mid IN ({list}) AND i.ended=0 AND i.ai_public<>'' AND m.enabled=1 ORDER BY i.started"
            ),
            [],
        )
    }
    pub fn open_incident_count(&self) -> i64 {
        self.with(|c| {
            c.query_row("SELECT COUNT(*) FROM incidents WHERE ended=0", [], |r| {
                r.get(0)
            })
            .unwrap_or(0)
        })
    }

    // ---- storage limits
    pub fn retention_days(&self, env_default: i64) -> i64 {
        self.setting("retention_days")
            .parse()
            .unwrap_or(env_default)
            .clamp(1, 3650)
    }
    pub fn max_db_mb(&self) -> i64 {
        self.setting("max_db_mb")
            .parse()
            .unwrap_or(256)
            .clamp(32, 10240)
    }
    pub fn storage(&self) -> Storage {
        self.with(|c| {
            let pragma = |p: &str| -> i64 {
                c.query_row(&format!("PRAGMA {p}"), [], |r| r.get(0))
                    .unwrap_or(0)
            };
            let (pages, free, size) = (
                pragma("page_count"),
                pragma("freelist_count"),
                pragma("page_size"),
            );
            let one = |sql: &str| -> i64 { c.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
            Storage {
                used: (pages - free).max(0) * size,
                file: pages * size,
                heartbeats: one("SELECT COUNT(*) FROM heartbeats"),
                incidents: one("SELECT COUNT(*) FROM incidents"),
                oldest: c
                    .query_row("SELECT MIN(ts) FROM heartbeats", [], |r| {
                        r.get::<_, Option<i64>>(0)
                    })
                    .ok()
                    .flatten()
                    .unwrap_or(0),
            }
        })
    }

    /// Deletes in small batches so live checks and viewers are never blocked for long.
    fn delete_batches(&self, sql: &str, args: impl rusqlite::Params + Copy) -> usize {
        let mut total = 0;
        loop {
            let n = self.with(|c| c.execute(sql, args).unwrap_or(0));
            total += n;
            if n < 5000 {
                return total;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The rolling-window housekeeper: age limit, per-monitor cap, then a global size cap that
    /// drops the oldest data first. Newest data always overwrites oldest.
    pub fn enforce_limits(&self, days: i64, max_bytes: i64) {
        self.delete_batches(
            "DELETE FROM heartbeats WHERE id IN (SELECT id FROM heartbeats WHERE ts<?1 LIMIT 5000)",
            params![now() - days * 86400],
        );
        let mids: Vec<i64> = self.with(|c| {
            c.prepare("SELECT DISTINCT mid FROM heartbeats")
                .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
                .unwrap_or_default()
        });
        for mid in mids {
            self.delete_batches(
                "DELETE FROM heartbeats WHERE id IN (SELECT id FROM heartbeats WHERE mid=?1 ORDER BY id DESC LIMIT 5000 OFFSET ?2)",
                params![mid, HB_CAP],
            );
        }
        for _ in 0..30 {
            let s = self.storage();
            if s.used <= max_bytes || s.heartbeats == 0 {
                break;
            }
            let n = (s.heartbeats / 10).clamp(1000, 50_000);
            self.with(|c| {
                let _ = c.execute(
                    "DELETE FROM heartbeats WHERE id IN (SELECT id FROM heartbeats ORDER BY id LIMIT ?1)",
                    [n],
                );
            });
            std::thread::sleep(Duration::from_millis(25));
        }
        self.with(|c| {
            let _ = c.execute(
                "DELETE FROM incidents WHERE ended>0 AND ended<?1",
                [now() - INCIDENT_KEEP_DAYS * 86400],
            );
            let _ = c.execute(
                "DELETE FROM incidents WHERE id IN (SELECT id FROM incidents ORDER BY started DESC LIMIT -1 OFFSET ?1)",
                [INCIDENT_CAP],
            );
            let _ = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;");
        });
    }

    // ---- metrics
    /// monitor id -> (checks, successful checks) since `since`, maintenance and unconfirmed checks excluded.
    pub fn uptime_since(&self, since: i64) -> HashMap<i64, (i64, i64)> {
        self.with(|c| {
            let Ok(mut s) = c.prepare(
                "SELECT mid,COUNT(*),COALESCE(SUM(ok),0) FROM heartbeats WHERE ts>=?1 AND soft<2 GROUP BY mid",
            ) else {
                return HashMap::new();
            };
            s.query_map([since], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))
                .map(|it| it.flatten().collect())
                .unwrap_or_default()
        })
    }
    /// monitor id -> (timestamp, response time ms) of the latest check.
    pub fn last_checks(&self) -> HashMap<i64, (i64, Option<i64>)> {
        self.with(|c| {
            let Ok(mut s) = c.prepare(
                "SELECT mid,ts,ms FROM heartbeats WHERE id IN (SELECT MAX(id) FROM heartbeats GROUP BY mid)",
            ) else {
                return HashMap::new();
            };
            s.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))
                .map(|it| it.flatten().collect())
                .unwrap_or_default()
        })
    }

    // ---- status page assets
    pub fn page_logo(&self, slug: &str) -> Option<(String, Vec<u8>)> {
        self.with(|c| {
            c.query_row(
                "SELECT logo_mime,logo FROM pages WHERE slug=?1 AND logo IS NOT NULL",
                [slug],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten()
        })
    }
    pub fn set_page_logo(&self, id: i64, logo: Option<(&str, &[u8])>) {
        self.write(|c| {
            let _ = match logo {
                Some((mime, data)) => c.execute(
                    "UPDATE pages SET logo_mime=?1,logo=?2,logo_ts=?3 WHERE id=?4",
                    params![mime, data, now(), id],
                ),
                None => c.execute(
                    "UPDATE pages SET logo_mime='',logo=NULL,logo_ts=0 WHERE id=?1",
                    [id],
                ),
            };
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(start: i64, end: i64, repeat: i64) -> Maint {
        Maint {
            start,
            end,
            repeat_days: repeat,
            enabled: true,
            all: true,
            ..Default::default()
        }
    }

    #[test]
    fn one_off_window() {
        let w = m(1000, 2000, 0);
        assert!(!w.active(999) && w.active(1000) && w.active(1999) && !w.active(2000));
        assert_eq!(w.window(500), Some((1000, 2000)));
        assert_eq!(w.window(2500), None);
        assert_eq!(w.upcoming(500, 600), Some((1000, 2000)));
        assert_eq!(w.upcoming(500, 100), None);
    }

    #[test]
    fn repeating_window() {
        let day = 86400;
        let w = m(10 * day, 10 * day + 3600, 1);
        assert!(w.active(10 * day + 10) && w.active(13 * day + 3599));
        assert!(!w.active(13 * day + 3600) && !w.active(12 * day + 5000));
        assert_eq!(w.window(13 * day + 4000), Some((14 * day, 14 * day + 3600)));
        let weekly = m(0, 7200, 7);
        assert!(weekly.active(14 * day + 100) && !weekly.active(15 * day));
    }

    #[test]
    fn disabled_never_applies() {
        let mut w = m(0, 100, 0);
        w.enabled = false;
        assert!(!w.active(10) && w.upcoming(0, 50).is_none());
        w.enabled = true;
        w.all = false;
        w.mons = vec![3];
        assert!(w.applies(3) && !w.applies(4));
    }
}
