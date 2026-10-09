//! Persistent cache (SQLite, WAL).
//!
//! The registry owns all state in memory; this store is only written in
//! debounced batches (and on shutdown), never on every heartbeat. Records are
//! JSON documents so the schema can evolve without migrations; a record that
//! fails to decode is skipped with a warning instead of failing startup.
//! A corrupt database file is moved aside and replaced with a fresh one.

use lablink_core::model::HistoryEvent;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: i64 = 1;

/// Rows loaded at startup.
#[derive(Debug, Default)]
pub struct Loaded {
    pub devices: Vec<(String, String)>,
    pub discovered: Vec<(String, String)>,
    pub events: Vec<HistoryEvent>,
    /// `meta` rows other than the schema version (site mode, signatures).
    pub meta: Vec<(String, String)>,
}

/// One debounced write.
#[derive(Debug, Default)]
pub struct Batch {
    pub devices: Vec<(String, String)>,
    pub discovered: Vec<(String, String)>,
    pub removed_discovered: Vec<String>,
    /// Device rows to delete (written under an old key before sites).
    pub removed_devices: Vec<String>,
    /// `meta` rows to upsert.
    pub meta: Vec<(String, String)>,
    pub events: Vec<HistoryEvent>,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
            && self.discovered.is_empty()
            && self.removed_discovered.is_empty()
            && self.removed_devices.is_empty()
            && self.meta.is_empty()
            && self.events.is_empty()
    }
}

pub struct Store {
    conn: Connection,
    retention: u32,
    path: PathBuf,
}

/// What happened while opening the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenNote {
    Fresh,
    Existing,
    /// The old file was unreadable and was moved to the given path.
    RecoveredFromCorruption(PathBuf, String),
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=2000;
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS devices (name TEXT PRIMARY KEY, data TEXT NOT NULL, updated_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS discovered (ip TEXT PRIMARY KEY, data TEXT NOT NULL, updated_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS events (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             ts_ms INTEGER NOT NULL, device TEXT, kind TEXT NOT NULL, message TEXT NOT NULL);
         CREATE INDEX IF NOT EXISTS events_device ON events(device, id);",
    )?;
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if v.is_none() {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
    }
    Ok(())
}

fn check(conn: &Connection) -> Result<(), String> {
    let r: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if r != "ok" {
        return Err(format!("quick_check: {r}"));
    }
    init_schema(conn).map_err(|e| e.to_string())?;
    let v: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    match v.parse::<i64>() {
        Ok(n) if n <= SCHEMA_VERSION => Ok(()),
        _ => Err(format!("unsupported cache schema version {v}")),
    }
}

impl Store {
    /// Open (or create) the cache, recovering from corruption.
    pub fn open(path: &Path, retention: u32) -> Result<(Self, OpenNote), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        let existed = path.exists();
        let attempt = Connection::open(path)
            .map_err(|e| e.to_string())
            .and_then(|c| check(&c).map(|_| c));
        match attempt {
            Ok(conn) => Ok((
                Self {
                    conn,
                    retention,
                    path: path.to_path_buf(),
                },
                if existed {
                    OpenNote::Existing
                } else {
                    OpenNote::Fresh
                },
            )),
            Err(reason) => {
                let ts = lablink_core::time::now_ms();
                let aside = path.with_extension(format!("db.corrupt-{ts}"));
                std::fs::rename(path, &aside)
                    .map_err(|e| format!("cannot move corrupt cache aside: {e}"))?;
                for suffix in ["-wal", "-shm"] {
                    let side = PathBuf::from(format!("{}{suffix}", path.display()));
                    let _ = std::fs::remove_file(side);
                }
                let conn = Connection::open(path).map_err(|e| e.to_string())?;
                init_schema(&conn).map_err(|e| e.to_string())?;
                Ok((
                    Self {
                        conn,
                        retention,
                        path: path.to_path_buf(),
                    },
                    OpenNote::RecoveredFromCorruption(aside, reason),
                ))
            }
        }
    }

    /// Cheap size/memory statistics, for attributing growth during soaks.
    pub fn stats(&self) -> Vec<(&'static str, u64)> {
        let count = |sql: &str| -> u64 {
            self.conn
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                .max(0) as u64
        };
        let file = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let wal = PathBuf::from(format!("{}-wal", self.path.display()));
        // SAFETY: sqlite3_memory_used takes no arguments and only reads a counter.
        let mem = unsafe { rusqlite::ffi::sqlite3_memory_used() }.max(0) as u64;
        vec![
            ("sqlite_event_rows", count("SELECT COUNT(*) FROM events")),
            (
                "sqlite_discovered_rows",
                count("SELECT COUNT(*) FROM discovered"),
            ),
            ("sqlite_device_rows", count("SELECT COUNT(*) FROM devices")),
            ("sqlite_page_count", count("PRAGMA page_count")),
            ("sqlite_page_size", count("PRAGMA page_size")),
            ("sqlite_db_file_bytes", file(&self.path)),
            ("sqlite_wal_file_bytes", file(&wal)),
            ("sqlite_memory_used_bytes", mem),
        ]
    }

    /// Load everything needed to restore the registry.
    pub fn load(&self, recent_events: u32) -> Result<Loaded, String> {
        let e = |e: rusqlite::Error| e.to_string();
        let mut out = Loaded::default();
        let mut s = self
            .conn
            .prepare("SELECT name, data FROM devices ORDER BY name")
            .map_err(e)?;
        out.devices = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(e)?
            .filter_map(Result::ok)
            .collect();
        let mut s = self
            .conn
            .prepare("SELECT key, value FROM meta WHERE key <> 'schema_version'")
            .map_err(e)?;
        out.meta = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(e)?
            .filter_map(Result::ok)
            .collect();
        let mut s = self
            .conn
            .prepare("SELECT ip, data FROM discovered")
            .map_err(e)?;
        out.discovered = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(e)?
            .filter_map(Result::ok)
            .collect();
        let mut s = self
            .conn
            .prepare("SELECT ts_ms, device, kind, message FROM (SELECT * FROM events ORDER BY id DESC LIMIT ?1) ORDER BY id ASC")
            .map_err(e)?;
        out.events = s
            .query_map(params![recent_events], |r| {
                Ok(HistoryEvent {
                    ts_ms: r.get::<_, i64>(0)? as u64,
                    device: r.get(1)?,
                    kind: r.get(2)?,
                    message: r.get(3)?,
                })
            })
            .map_err(e)?
            .filter_map(Result::ok)
            .collect();
        Ok(out)
    }

    /// Write one batch in a single transaction and enforce event retention.
    pub fn save(&mut self, b: &Batch) -> Result<(), String> {
        if b.is_empty() {
            return Ok(());
        }
        let e = |e: rusqlite::Error| e.to_string();
        let now = lablink_core::time::now_ms() as i64;
        let tx = self.conn.transaction().map_err(e)?;
        for (name, data) in &b.devices {
            tx.execute(
                "INSERT INTO devices(name, data, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name) DO UPDATE SET data=excluded.data, updated_ms=excluded.updated_ms",
                params![name, data, now],
            )
            .map_err(e)?;
        }
        for (ip, data) in &b.discovered {
            tx.execute(
                "INSERT INTO discovered(ip, data, updated_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT(ip) DO UPDATE SET data=excluded.data, updated_ms=excluded.updated_ms",
                params![ip, data, now],
            )
            .map_err(e)?;
        }
        for ip in &b.removed_discovered {
            tx.execute("DELETE FROM discovered WHERE ip=?1", params![ip])
                .map_err(e)?;
        }
        for name in &b.removed_devices {
            tx.execute("DELETE FROM devices WHERE name=?1", params![name])
                .map_err(e)?;
        }
        for (k, v) in &b.meta {
            if k == "schema_version" {
                continue;
            }
            tx.execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![k, v],
            )
            .map_err(e)?;
        }
        for ev in &b.events {
            tx.execute(
                "INSERT INTO events(ts_ms, device, kind, message) VALUES (?1, ?2, ?3, ?4)",
                params![ev.ts_ms as i64, ev.device, ev.kind, ev.message],
            )
            .map_err(e)?;
        }
        if !b.events.is_empty() {
            tx.execute(
                "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?1",
                params![self.retention as i64],
            )
            .map_err(e)?;
        }
        tx.commit().map_err(e)
    }

    /// History query straight from disk (for limits beyond the in-memory ring).
    pub fn history(&self, device: Option<&str>, limit: u32) -> Result<Vec<HistoryEvent>, String> {
        let e = |e: rusqlite::Error| e.to_string();
        let map = |r: &rusqlite::Row<'_>| {
            Ok(HistoryEvent {
                ts_ms: r.get::<_, i64>(0)? as u64,
                device: r.get(1)?,
                kind: r.get(2)?,
                message: r.get(3)?,
            })
        };
        let mut v: Vec<HistoryEvent> = match device {
            Some(d) => {
                // Events from before sites name the device without its site.
                let legacy = d.split_once('/').map_or(d, |(_, n)| n);
                let mut s = self
                    .conn
                    .prepare("SELECT ts_ms, device, kind, message FROM events WHERE device IN (?1, ?2) ORDER BY id DESC LIMIT ?3")
                    .map_err(e)?;
                let rows = s.query_map(params![d, legacy, limit], map).map_err(e)?;
                rows.filter_map(Result::ok).collect()
            }
            None => {
                let mut s = self
                    .conn
                    .prepare(
                        "SELECT ts_ms, device, kind, message FROM events ORDER BY id DESC LIMIT ?1",
                    )
                    .map_err(e)?;
                let rows = s.query_map(params![limit], map).map_err(e)?;
                rows.filter_map(Result::ok).collect()
            }
        };
        v.reverse();
        Ok(v)
    }

    pub fn event_count(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap_or(-1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(i: u64) -> HistoryEvent {
        HistoryEvent {
            ts_ms: i,
            device: Some("jetson-a".into()),
            kind: "k".into(),
            message: format!("m{i}"),
        }
    }

    #[test]
    fn stats_are_sane_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        let (mut s, _) = Store::open(&p, 100).unwrap();
        s.save(&Batch {
            devices: vec![("jetson-a".into(), "{\"a\":1}".into())],
            discovered: vec![("192.168.10.9".into(), "{}".into())],
            events: vec![ev(1), ev(2)],
            ..Default::default()
        })
        .unwrap();
        let m: std::collections::BTreeMap<_, _> = s.stats().into_iter().collect();
        assert_eq!(m["sqlite_event_rows"], 2);
        assert_eq!(m["sqlite_discovered_rows"], 1);
        assert_eq!(m["sqlite_device_rows"], 1);
        assert!(m["sqlite_page_count"] > 0 && m["sqlite_page_size"] >= 512);
        assert!(m["sqlite_db_file_bytes"] + m["sqlite_wal_file_bytes"] > 0);
        assert!(m["sqlite_memory_used_bytes"] > 0);
    }

    #[test]
    fn roundtrip_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        {
            let (mut s, note) = Store::open(&p, 100).unwrap();
            assert_eq!(note, OpenNote::Fresh);
            s.save(&Batch {
                devices: vec![("jetson-a".into(), "{\"a\":1}".into())],
                discovered: vec![("192.168.10.9".into(), "{}".into())],
                events: vec![ev(1), ev(2)],
                ..Default::default()
            })
            .unwrap();
        }
        let (s, note) = Store::open(&p, 100).unwrap();
        assert_eq!(note, OpenNote::Existing);
        let l = s.load(10).unwrap();
        assert_eq!(
            l.devices,
            vec![("jetson-a".to_string(), "{\"a\":1}".to_string())]
        );
        assert_eq!(l.discovered.len(), 1);
        assert_eq!(
            l.events.iter().map(|e| e.ts_ms).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        std::fs::write(
            &p,
            b"this is definitely not an sqlite database, just garbage bytes......",
        )
        .unwrap();
        let (s, note) = Store::open(&p, 100).unwrap();
        match note {
            OpenNote::RecoveredFromCorruption(aside, _) => assert!(aside.exists()),
            n => panic!("{n:?}"),
        }
        assert!(s.load(10).unwrap().devices.is_empty());
    }

    #[test]
    fn truncated_database_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        {
            let (mut s, _) = Store::open(&p, 100).unwrap();
            s.save(&Batch {
                devices: vec![("a".into(), "{}".into())],
                ..Default::default()
            })
            .unwrap();
            s.conn
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let bytes = std::fs::read(&p).unwrap();
        std::fs::write(&p, &bytes[..bytes.len() / 3]).unwrap();
        let (s, _) = Store::open(&p, 100).unwrap();
        // Either recovered (moved aside) or readable; never a startup failure.
        let _ = s.load(10).unwrap();
    }

    #[test]
    fn retention_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = Store::open(&dir.path().join("c.db"), 5).unwrap();
        for i in 0..4 {
            s.save(&Batch {
                events: (0..3).map(|j| ev(i * 3 + j)).collect(),
                ..Default::default()
            })
            .unwrap();
        }
        assert_eq!(s.event_count(), 5);
        let h = s.history(Some("jetson-a"), 3).unwrap();
        assert_eq!(
            h.iter().map(|e| e.ts_ms).collect::<Vec<_>>(),
            vec![9, 10, 11]
        );
    }
}
