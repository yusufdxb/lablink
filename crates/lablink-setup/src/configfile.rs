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
        let name = format!(
            "{}.bak-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("config.yaml"),
            utc_stamp(lablink_core::time::now_ms())
        );
        let b = dir.join(name);
        std::fs::copy(path, &b).map_err(|e| format!("cannot back up {}: {e}", path.display()))?;
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
    }
}
