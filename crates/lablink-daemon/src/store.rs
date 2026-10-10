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
    /// Positive corruption evidence caused the old file to be quarantined.
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

enum OpenFailure {
    Corrupt(String),
    Other(String),
}

impl From<rusqlite::Error> for OpenFailure {
    fn from(e: rusqlite::Error) -> Self {
        match &e {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.extended_code & 0xff,
                    rusqlite::ffi::SQLITE_CORRUPT | rusqlite::ffi::SQLITE_NOTADB
                ) =>
            {
                Self::Corrupt(e.to_string())
            }
            _ => Self::Other(e.to_string()),
        }
    }
}

/// Check an existing version before any schema or journal-mode writes.
fn check_version(conn: &Connection) -> Result<(), OpenFailure> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
        [],
        |r| r.get(0),
    )?;
    if !has_meta {
        return Ok(());
    }
    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(v) = version {
        if !matches!(v.parse::<i64>(), Ok(n) if n <= SCHEMA_VERSION) {
            return Err(OpenFailure::Other(format!(
                "unsupported cache schema version {v}"
            )));
        }
    }
    Ok(())
}

fn check(conn: &Connection) -> Result<(), OpenFailure> {
    let r: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if r != "ok" {
        return Err(OpenFailure::Corrupt(format!("quick_check: {r}")));
    }
    check_version(conn)
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

struct JournalSnapshot {
    original: PathBuf,
    suffix: &'static str,
    file: tempfile::NamedTempFile,
    len: u64,
}

/// SQLite may delete journals even when opening a corrupt database fails.
/// Copy them first to private files, bounded by the initial length and using
/// streaming IO, never allocating a journal-sized buffer.
fn snapshot_journals(path: &Path, dir: &Path) -> Result<Vec<JournalSnapshot>, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if let Some(why) = lablink_core::paths::writable_by_others(dir) {
        return Err(format!("refusing cache directory: {why}"));
    }
    let mut snapshots = Vec::new();
    for suffix in ["-wal", "-shm"] {
        let original = suffixed(path, suffix);
        let checked = match std::fs::symlink_metadata(&original) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot check cache journal: {e}")),
        };
        // SAFETY: getuid is infallible.
        if !checked.is_file() || checked.uid() != unsafe { libc::getuid() } {
            return Err("refusing cache journal: must be a regular file owned by you".into());
        }
        if let Some(why) = lablink_core::paths::writable_by_others(&original) {
            return Err(format!("refusing cache journal: {why}"));
        }
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&original)
            .map_err(|e| format!("cannot snapshot cache journal: {e}"))?;
        let opened = source.metadata().map_err(|e| e.to_string())?;
        if !opened.is_file() || (opened.dev(), opened.ino()) != (checked.dev(), checked.ino()) {
            return Err("cache journal changed while being checked".into());
        }
        let mut file = tempfile::Builder::new()
            .prefix(".lablink-journal-")
            .tempfile_in(dir)
            .map_err(|e| format!("cannot stage cache journal: {e}"))?;
        let len = opened.len();
        let copied = std::io::copy(&mut source.take(len), file.as_file_mut())
            .map_err(|e| format!("cannot snapshot cache journal: {e}"))?;
        if copied != len {
            return Err("cache journal changed while being copied".into());
        }
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        snapshots.push(JournalSnapshot {
            original,
            suffix,
            file,
            len,
        });
    }
    Ok(snapshots)
}

fn copy_snapshot(snapshot: &JournalSnapshot, destination: &Path) -> Result<(), String> {
    use std::io::{Read, Seek};
    let dir = destination.parent().unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".lablink-journal-")
        .tempfile_in(dir)
        .map_err(|e| e.to_string())?;
    let mut source = snapshot
        .file
        .as_file()
        .try_clone()
        .map_err(|e| e.to_string())?;
    source.rewind().map_err(|e| e.to_string())?;
    let copied = std::io::copy(&mut source.take(snapshot.len), file.as_file_mut())
        .map_err(|e| e.to_string())?;
    if copied != snapshot.len {
        return Err("incomplete cache journal snapshot".into());
    }
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(destination)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Stage every journal before moving the DB. A persistent guard prevents a
/// later startup from treating an interrupted/failed recovery as a fresh DB.
fn recover(
    path: &Path,
    dir: &Path,
    snapshots: Vec<JournalSnapshot>,
) -> Result<(Connection, PathBuf), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let name = path.file_name().ok_or("cache path has no file name")?;
    let mut prefix = name.to_os_string();
    prefix.push(".corrupt-");
    let quarantine = tempfile::Builder::new()
        .prefix(&prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(dir)
        .map_err(|e| format!("cannot stage corrupt cache: {e}"))?;
    let aside = quarantine.path().join(name);
    let guard = suffixed(path, ".recovery-pending");
    let guard_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&guard)
        .map_err(|e| format!("cannot guard corrupt cache recovery: {e}"))?;
    guard_file.sync_all().map_err(|e| e.to_string())?;
    let mut moved = false;
    let mut fresh_started = false;
    let attempt = (|| {
        for snapshot in &snapshots {
            copy_snapshot(snapshot, &suffixed(&aside, snapshot.suffix))?;
        }
        std::fs::rename(path, &aside)
            .map_err(|e| format!("cannot move corrupt cache aside: {e}"))?;
        moved = true;
        for suffix in ["-wal", "-shm"] {
            match std::fs::remove_file(suffixed(path, suffix)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("cannot remove quarantined journal: {e}")),
            }
        }
        fresh_started = true;
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        init_schema(&conn).map_err(|e| e.to_string())?;
        Ok(conn)
    })();
    match attempt {
        Ok(conn) => {
            let _kept = quarantine.keep();
            std::fs::remove_file(&guard).map_err(|e| {
                format!("cache recovered, but recovery guard could not be cleared: {e}")
            })?;
            Ok((conn, aside))
        }
        Err(reason) => {
            let rollback = (|| {
                if fresh_started {
                    for suffix in ["", "-wal", "-shm"] {
                        match std::fs::remove_file(suffixed(path, suffix)) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                }
                if moved {
                    // Never overwrite a file that appeared during rollback.
                    std::fs::hard_link(&aside, path).map_err(|e| e.to_string())?;
                    std::fs::remove_file(&aside).map_err(|e| e.to_string())?;
                }
                for snapshot in &snapshots {
                    match std::fs::symlink_metadata(&snapshot.original) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            copy_snapshot(snapshot, &snapshot.original)?
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                std::fs::remove_file(&guard).map_err(|e| e.to_string())?;
                Ok::<(), String>(())
            })();
            match rollback {
                Ok(()) => Err(format!("{reason}; recovery was rolled back")),
                Err(error) => {
                    let kept = quarantine.keep();
                    // Snapshots have already been copied into this directory.
                    Err(format!("{reason}; rollback failed: {error}; recovery is blocked by {}; evidence kept in {}", guard.display(), kept.display()))
                }
            }
        }
    }
}

impl Store {
    /// Open (or create) the cache, recovering from corruption.
    pub fn open(path: &Path, retention: u32) -> Result<(Self, OpenNote), String> {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let guard = suffixed(path, ".recovery-pending");
        match std::fs::symlink_metadata(&guard) {
            Ok(_) => {
                return Err(format!(
                    "cache recovery is incomplete; inspect {} before restarting",
                    guard.display()
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot check cache recovery guard: {e}")),
        }
        let snapshots = snapshot_journals(path, dir)?;
        let existed = path.exists();
        let attempt = (|| {
            if existed {
                // Read-only validation cannot initialize old tables or checkpoint
                // a future-format database while refusing its version.
                let reader = Connection::open_with_flags(
                    path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                reader.busy_timeout(std::time::Duration::from_secs(2))?;
                check(&reader)?;
            }
            let conn = Connection::open(path)?;
            conn.busy_timeout(std::time::Duration::from_secs(2))?;
            check_version(&conn)?;
            init_schema(&conn)?;
            Ok::<Connection, OpenFailure>(conn)
        })();
        match attempt {
            Ok(conn) => Ok((Self { conn, retention, path: path.to_path_buf() },
                if existed { OpenNote::Existing } else { OpenNote::Fresh })),
            Err(OpenFailure::Other(reason)) => Err(format!(
                "cannot open cache {}: {reason}; existing cache and trust pins were not quarantined", path.display()
            )),
            Err(OpenFailure::Corrupt(reason)) => {
                let (conn, aside) = recover(path, dir, snapshots)?;
                Ok((Self { conn, retention, path: path.to_path_buf() }, OpenNote::RecoveredFromCorruption(aside, reason)))
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
    fn journal_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        name.into()
    }

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
    fn a_locked_cache_is_not_corruption_and_keeps_pins() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        let (mut s, _) = Store::open(&p, 100).unwrap();
        s.save(&Batch {
            devices: vec![("test/device".into(), "pinned identity".into())],
            ..Default::default()
        })
        .unwrap();
        s.conn
            .execute_batch("PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE;")
            .unwrap();
        let before = std::fs::read(&p).unwrap();
        assert!(
            Store::open(&p, 100).is_err(),
            "a lock must never reset the cache"
        );
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        s.conn.execute_batch("ROLLBACK").unwrap();
        drop(s);
        let (s, note) = Store::open(&p, 100).unwrap();
        assert_eq!(note, OpenNote::Existing);
        assert_eq!(s.load(10).unwrap().devices[0].1, "pinned identity");
    }

    #[test]
    fn a_future_minimal_schema_is_refused_without_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO meta VALUES('schema_version','999'); CREATE TABLE future_pins(key TEXT);").unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        assert!(Store::open(&path, 100).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let conn = Connection::open(&path).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 2);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_sidecars_are_saved_before_sqlite_can_delete_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let original = b"a synthetic corrupt database, not an SQLite file";
        std::fs::write(&path, original).unwrap();
        let wal = b"synthetic WAL bytes to retain";
        let shm = b"synthetic SHM bytes to retain";
        std::fs::write(journal_path(&path, "-wal"), wal).unwrap();
        std::fs::write(journal_path(&path, "-shm"), shm).unwrap();
        let (store, note) = Store::open(&path, 100).unwrap();
        let OpenNote::RecoveredFromCorruption(aside, _) = note else {
            panic!("not recovered");
        };
        assert_eq!(std::fs::read(&aside).unwrap(), original);
        assert_eq!(std::fs::read(journal_path(&aside, "-wal")).unwrap(), wal);
        assert_eq!(std::fs::read(journal_path(&aside, "-shm")).unwrap(), shm);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(aside.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(journal_path(&aside, "-wal"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(store.load(10).unwrap().devices.is_empty());
        assert!(!journal_path(&path, ".recovery-pending").exists());
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|f| f
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".lablink-journal-")));
    }

    #[test]
    fn an_interrupted_recovery_never_becomes_a_fresh_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        std::fs::write(
            journal_path(&path, ".recovery-pending"),
            "recovery interrupted",
        )
        .unwrap();
        let error = Store::open(&path, 100).err().unwrap();
        assert!(error.contains("recovery is incomplete"));
        assert!(!path.exists());
    }

    #[test]
    fn a_newer_schema_is_not_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.db");
        let (s, _) = Store::open(&p, 100).unwrap();
        s.conn
            .execute("UPDATE meta SET value='999' WHERE key='schema_version'", [])
            .unwrap();
        drop(s);
        let before = std::fs::read(&p).unwrap();
        assert!(Store::open(&p, 100).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|p| p
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("corrupt")));
    }

    #[test]
    fn only_positive_sqlite_corruption_allows_recovery() {
        for code in [
            rusqlite::ffi::SQLITE_BUSY,
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_CANTOPEN,
            rusqlite::ffi::SQLITE_IOERR,
            rusqlite::ffi::SQLITE_READONLY,
            rusqlite::ffi::SQLITE_PERM,
        ] {
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(
                matches!(OpenFailure::from(e), OpenFailure::Other(_)),
                "code {code}"
            );
        }
        for code in [rusqlite::ffi::SQLITE_CORRUPT, rusqlite::ffi::SQLITE_NOTADB] {
            let e = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
            assert!(matches!(OpenFailure::from(e), OpenFailure::Corrupt(_)));
        }
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
