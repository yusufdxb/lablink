//! Default filesystem locations (XDG-style, per user, no root required).

use std::path::PathBuf;

use std::path::Path;

/// A directory from the environment, if it is absolute. Empty and relative
/// values are ignored, as the XDG base directory specification requires:
/// they would make LabLink read its configuration and pins from whatever
/// directory it was started in.
fn env_dir(var: &str) -> Option<PathBuf> {
    absolute(std::env::var_os(var))
}

fn absolute(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|p| p.is_absolute())
}

/// `$HOME`, else the home directory in the password database. Never a shared
/// directory like /tmp, where another user could plant a configuration or
/// pins; with no home at all, a path that does not exist, so nothing is read
/// and the daemon cannot start.
pub fn home() -> PathBuf {
    home_from(std::env::var_os("HOME"))
}

fn home_from(value: Option<std::ffi::OsString>) -> PathBuf {
    absolute(value)
        .or_else(passwd_home)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

fn passwd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: every pointer is valid for the call and `buf.len()` is its
    // size; on success the strings in `pw` point into `buf`.
    let rc = unsafe { libc::getpwuid_r(uid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`, still alive.
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()))).filter(|p| p.is_absolute())
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Why another user could have written or replaced `path`, if one could.
/// OpenSSH's rule for its own files, applied to the whole path: the file and
/// every directory above it must belong to this user or root, and none may be
/// writable by every user, except directories with the sticky bit (like
/// /tmp), where only a file's owner can replace it. Group-writable is
/// accepted: with per-user groups (umask 002) that group is the user alone.
/// A path that does not exist is not judged here.
pub fn writable_by_others(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let real = path.canonicalize().ok()?;
    let me = uid();
    let mut at = Some(real.as_path());
    while let Some(p) = at {
        let Ok(m) = std::fs::metadata(p) else {
            return Some(format!("cannot check {}", p.display()));
        };
        if m.uid() != me && m.uid() != 0 {
            return Some(format!(
                "{} belongs to another user (uid {})",
                p.display(),
                m.uid()
            ));
        }
        if m.mode() & 0o002 != 0 && !(m.is_dir() && m.mode() & 0o1000 != 0) {
            return Some(format!("{} is writable by every user", p.display()));
        }
        at = p.parent();
    }
    None
}

/// `$LABLINK_CONFIG`, else `$XDG_CONFIG_HOME/lablink/config.yaml`. Relative
/// values of either are ignored.
pub fn default_config_path() -> PathBuf {
    if let Some(p) = env_dir("LABLINK_CONFIG") {
        return p;
    }
    env_dir("XDG_CONFIG_HOME")
        .unwrap_or_else(|| home().join(".config"))
        .join("lablink")
        .join("config.yaml")
}

/// `$LABLINK_STATE_DIR`, else `$XDG_STATE_HOME/lablink` (cache DB,
/// known_hosts). Relative values of either are ignored.
pub fn default_state_dir() -> PathBuf {
    if let Some(p) = env_dir("LABLINK_STATE_DIR") {
        return p;
    }
    env_dir("XDG_STATE_HOME")
        .unwrap_or_else(|| home().join(".local").join("state"))
        .join("lablink")
}

/// `$LABLINK_SOCKET`, else `$XDG_RUNTIME_DIR/lablink/lablinkd.sock`,
/// else `/tmp/lablink-<uid>/lablinkd.sock`. Relative values are ignored.
pub fn default_socket_path() -> PathBuf {
    if let Some(p) = env_dir("LABLINK_SOCKET") {
        return p;
    }
    match env_dir("XDG_RUNTIME_DIR") {
        Some(d) => d.join("lablink").join("lablinkd.sock"),
        None => PathBuf::from(format!("/tmp/lablink-{}", uid())).join("lablinkd.sock"),
    }
}

/// The OpenSSH known_hosts file LabLink maintains for pinned identities.
pub fn known_hosts_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("known_hosts")
}

/// The SQLite cache database.
pub fn cache_db_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("cache.db")
}

/// The user's own known_hosts file (read-only for LabLink).
pub fn user_known_hosts() -> PathBuf {
    home().join(".ssh").join("known_hosts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Without a usable `$HOME`, LabLink's files are looked up in the home
    /// directory from the password database, never in /tmp (where another
    /// user could plant a configuration naming the ssh program) and never
    /// relative to the current directory.
    #[test]
    fn a_missing_or_relative_home_is_never_a_shared_or_relative_directory() {
        let real = passwd_home().expect("this user has a home directory");
        assert!(real.is_absolute());
        for v in [None, Some(""), Some("."), Some("relative/home")] {
            let h = home_from(v.map(Into::into));
            assert_eq!(h, real, "HOME={v:?}");
            assert!(!h.starts_with("/tmp"), "HOME={v:?} gave {}", h.display());
        }
        assert_eq!(home_from(Some("/srv/me".into())), PathBuf::from("/srv/me"));
        assert_eq!(absolute(Some("".into())), None);
        assert_eq!(absolute(Some("state".into())), None);
        assert_eq!(
            absolute(Some("/x/state".into())),
            Some(PathBuf::from("/x/state"))
        );
    }

    #[test]
    fn files_other_users_could_change_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("config.yaml");
        std::fs::write(&f, "").unwrap();
        chmod(&f, 0o600);
        assert_eq!(writable_by_others(&f), None);
        // umask 002 with a per-user group: group-writable is the user alone.
        chmod(&f, 0o664);
        assert_eq!(writable_by_others(&f), None);
        chmod(&f, 0o666);
        assert!(writable_by_others(&f)
            .unwrap()
            .contains("writable by every user"));
        chmod(&f, 0o600);
        // A directory anyone can write to lets them replace the file...
        chmod(dir.path(), 0o777);
        assert!(writable_by_others(&f)
            .unwrap()
            .contains("writable by every user"));
        // ...unless it is sticky, like /tmp: only the owner can replace it.
        chmod(dir.path(), 0o1777);
        assert_eq!(writable_by_others(&f), None);
        chmod(dir.path(), 0o700);
        // Through a symlink, the real location is judged.
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(writable_by_others(&link), None);
        chmod(&f, 0o646);
        assert!(writable_by_others(&link).is_some());
        // Files owned by root (here /etc/passwd) are trusted like your own.
        assert_eq!(writable_by_others(Path::new("/etc/passwd")), None);
        assert_eq!(writable_by_others(&dir.path().join("missing")), None);
    }
}
