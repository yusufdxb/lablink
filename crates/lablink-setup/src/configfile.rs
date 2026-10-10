//! Writing `config.yaml` safely: validate first, keep a backup of the
//! previous file, replace atomically.

use lablink_core::config::{Config, ConfigError};
use std::io::Write;
use std::path::{Path, PathBuf};

const HEADER: &str = "\
# LabLink configuration.
#
# Hand edits are welcome: LabLink validates this file before using it
# (`lablink check-config`). When LabLink itself rewrites it (lablink init,
# the GUI settings, lablink import) comments are not kept, and the previous
# version is saved next to it as config.yaml.bak-<UTC time>.
# Restart the daemon after editing: systemctl --user restart lablinkd
";

/// `YYYYMMDD-HHMMSS` (UTC) for a Unix time in milliseconds.
pub fn utc_stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The text LabLink writes for `cfg`.
pub fn render(cfg: &Config) -> String {
    format!("{HEADER}\n{}", cfg.to_yaml())
}

/// Validate `cfg`, back up the current file (if any) and replace it
/// atomically. Returns the backup path.
pub fn write(path: &Path, cfg: &Config) -> Result<Option<PathBuf>, String> {
    let _lock = lock(path)?;
    write_locked(path, cfg)
}

/// Serialize a load-modify-write operation across all LabLink processes.
/// The closure runs against the latest file, while the lock is held.
pub fn update<F>(path: &Path, edit: F) -> Result<Option<PathBuf>, String>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    let _lock = lock(path)?;
    let mut cfg = load_or_default(path)?;
    edit(&mut cfg)?;
    write_locked(path, &cfg)
}

fn lock(path: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot create config directory: {e}"))?;
    if let Some(why) = lablink_core::paths::writable_by_others(dir) {
        return Err(format!("refusing config directory: {why}"));
    }
    let lock_path = dir.join(format!(
        ".{}.lock",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| format!("cannot open config lock: {e}"))?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    // SAFETY: getuid has no preconditions.
    if !m.is_file() || m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0 {
        return Err("refusing config lock: must be your private regular file".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        // SAFETY: f owns a valid descriptor for the whole lock lifetime.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(f);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock || std::time::Instant::now() >= deadline {
            return Err(format!("cannot acquire config lock: {e}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Backups kept next to the configuration; older ones are deleted.
const KEEP_BACKUPS: usize = 20;

/// Delete all but the newest `KEEP_BACKUPS` regular files named
/// `<prefix>...`. Names start with a UTC time, so they sort by age. Best
/// effort: a backup that cannot be listed or removed is left in place.
fn prune_backups(dir: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut backups: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.starts_with(prefix).then(|| (name, e.path()))
        })
        .collect();
    if backups.len() <= KEEP_BACKUPS {
        return;
    }
    backups.sort();
    for (_, old) in &backups[..backups.len() - KEEP_BACKUPS] {
        let _ = std::fs::remove_file(old);
    }
}

fn write_locked(path: &Path, cfg: &Config) -> Result<Option<PathBuf>, String> {
    cfg.validate().map_err(|e| e.to_string())?;
    let text = render(cfg);
    // The written text must parse back to the same configuration.
    match Config::parse(&text, &path.display().to_string()) {
        Ok(back) if &back == cfg => {}
        Ok(_) => {
            return Err("internal error: the written configuration does not round-trip".into())
        }
        Err(e) => return Err(format!("internal error: {e}")),
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let backup = if path.exists() {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.yaml");
        let name = format!(
            "{}.bak-{}-{}-{}-{}",
            file_name,
            utc_stamp(lablink_core::time::now_ms()),
            lablink_core::time::now_ms(),
            std::process::id(),
            NEXT_BACKUP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        // A fresh private file (never follow or reuse whatever is at that
        // name, never inherit a looser mode from the original).
        let current =
            std::fs::read(path).map_err(|e| format!("cannot back up {}: {e}", path.display()))?;
        let mut n = 0;
        let b = loop {
            use std::os::unix::fs::OpenOptionsExt;
            let b = dir.join(if n == 0 {
                name.clone()
            } else {
                format!("{name}-{n}")
            });
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&b)
            {
                Ok(mut f) => {
                    f.write_all(&current)
                        .and_then(|_| f.sync_all())
                        .map_err(|e| format!("cannot write {}: {e}", b.display()))?;
                    break b;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 100 => n += 1,
                Err(e) => return Err(format!("cannot write {}: {e}", b.display())),
            }
        };
        prune_backups(dir, &format!("{}.bak-", file_name));
        Some(b)
    } else {
        None
    };
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.yaml"),
        std::process::id()
    ));
    // A fresh file only (never follow or reuse whatever is at that name);
    // private, because the file lists your devices and usernames.
    let _ = std::fs::remove_file(&tmp);
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?
    };
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", path.display())
    })?;
    Ok(backup)
}

static NEXT_BACKUP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Load the config for editing: a missing file is an empty config.
pub fn load_or_default(path: &Path) -> Result<Config, String> {
    match Config::load(path) {
        Ok(c) => Ok(c),
        Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(Config::default())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(utc_stamp(0), "19700101-000000");
        assert_eq!(utc_stamp(1_728_496_800_000), "20241009-180000");
        assert_eq!(utc_stamp(951_782_400_000), "20000229-000000");
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let other = dir.path().join("notes.bak-keep");
        std::fs::write(&other, "not a LabLink backup").unwrap();
        let cfg = Config::default();
        for _ in 0..KEEP_BACKUPS + 5 {
            write(&path, &cfg).unwrap();
        }
        let backups = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                let n = e.as_ref().unwrap().file_name();
                n.to_string_lossy().starts_with("config.yaml.bak-")
            })
            .count();
        assert_eq!(backups, KEEP_BACKUPS);
        assert!(other.exists());
    }

    #[test]
    fn write_validates_backs_up_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.yaml");
        let mut cfg = Config::default();
        let mut site = lablink_core::config::SiteConfig::new("site-alpha", "Site Alpha");
        site.networks.push(lablink_core::config::NetworkConfig::new(
            "lab",
            "192.168.50.0/24",
            true,
        ));
        cfg.sites.push(site);
        assert_eq!(write(&path, &cfg).unwrap(), None);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# LabLink configuration."));
        assert_eq!(Config::load(&path).unwrap(), cfg);
        // A second write keeps a backup of the first.
        cfg.daemon.check_interval_s = 7;
        let b = write(&path, &cfg).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&b).unwrap(), text);
        assert_eq!(Config::load(&path).unwrap().daemon.check_interval_s, 7);
        // Invalid configs are refused and nothing changes.
        let before = std::fs::read_to_string(&path).unwrap();
        cfg.sites[0].networks[0].cidr = "8.8.8.0/24".into();
        assert!(write(&path, &cfg).unwrap_err().contains("public"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(
            load_or_default(&dir.path().join("none.yaml")).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn config_is_private_and_a_planted_temp_symlink_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lablink").join("config.yaml");
        write(&path, &Config::default()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let tmp = path
            .parent()
            .unwrap()
            .join(format!(".config.yaml.tmp-{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        write(&path, &Config::default()).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        // Backups are fresh 0600 files even when the config was loosened by
        // hand, and a second backup in the same second gets its own name.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let b1 = write(&path, &Config::default()).unwrap().unwrap();
        let b2 = write(&path, &Config::default()).unwrap().unwrap();
        assert_ne!(b1, b2);
        assert_eq!((mode(&b1), mode(&b2)), (0o600, 0o600));
    }
}
