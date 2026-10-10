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
    let (_, dir) = passwd_entry()?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&dir))).filter(|p| p.is_absolute())
}

/// This user's name and home directory from the password database.
fn passwd_entry() -> Option<(Vec<u8>, Vec<u8>)> {
    // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: every pointer is valid for the call and `buf.len()` is its
    // size; on success the strings in `pw` point into `buf`.
    let rc = unsafe { libc::getpwuid_r(uid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pw.pw_name.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: both are NUL-terminated strings inside `buf`, still alive.
    let (name, dir) = unsafe {
        (
            std::ffi::CStr::from_ptr(pw.pw_name),
            std::ffi::CStr::from_ptr(pw.pw_dir),
        )
    };
    Some((name.to_bytes().to_vec(), dir.to_bytes().to_vec()))
}

/// Whether `gid` is this user's private group, the group a umask of 002 is
/// meant for: the user's primary group, named like the user (`pam_umask`
/// usergroups), with no other members listed.
fn is_private_group(gid: u32) -> bool {
    // SAFETY: getgid has no preconditions and cannot fail.
    if gid != unsafe { libc::getgid() } {
        return false;
    }
    let Some((user, _)) = passwd_entry() else {
        return false;
    };
    // SAFETY: an all-zero group is a valid value for getgrgid_r to fill.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 64 * 1024];
    // SAFETY: as for getpwuid_r above.
    let rc = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || gr.gr_name.is_null() {
        return false;
    }
    // SAFETY: gr_name is a NUL-terminated string inside `buf`.
    if unsafe { std::ffi::CStr::from_ptr(gr.gr_name) }.to_bytes() != user.as_slice() {
        return false;
    }
    // gr_mem is a NULL-terminated array of NUL-terminated strings in `buf`.
    let mut i = 0;
    while !gr.gr_mem.is_null() {
        // SAFETY: reading entries up to and including the terminating NULL.
        let m = unsafe { *gr.gr_mem.add(i) };
        if m.is_null() {
            break;
        }
        // SAFETY: a NUL-terminated string inside `buf`.
        if unsafe { std::ffi::CStr::from_ptr(m) }.to_bytes() != user.as_slice() {
            return false;
        }
        i += 1;
    }
    true
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Why another user could have written or replaced `path`, if one could.
/// The file and every directory above it must belong to this user or root,
/// and none may be writable by everyone (directories with the sticky bit,
/// like /tmp, excepted: only a file's owner can replace a file there) or by
/// a group, unless that group is the user's own private group (see
/// `is_private_group`), so files and directories created with a umask of
/// 002 stay usable. A shared group such as
/// `lab` is refused, as OpenSSH refuses a group-writable config. A
/// symbolic link on the way that belongs to another user is refused too, as
/// its owner could point it elsewhere after this check. A path that does not
/// exist is not judged here; one that cannot be checked is refused.
pub fn writable_by_others(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let me = uid();
    let ours = |uid: u32| uid == me || uid == 0;
    let real = match path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("cannot check {}: {e}", path.display())),
    };
    let given = std::env::current_dir()
        .map(|d| d.join(path))
        .unwrap_or_else(|_| path.to_path_buf());
    for p in given.ancestors() {
        if let Ok(m) = std::fs::symlink_metadata(p) {
            if m.file_type().is_symlink() && !ours(m.uid()) {
                return Some(format!(
                    "{} is a link that belongs to another user (uid {})",
                    p.display(),
                    m.uid()
                ));
            }
        }
    }
    let mut at = Some(real.as_path());
    while let Some(p) = at {
        let m = match std::fs::metadata(p) {
            Ok(m) => m,
            Err(e) => return Some(format!("cannot check {}: {e}", p.display())),
        };
        if !ours(m.uid()) {
            return Some(format!(
                "{} belongs to another user (uid {})",
                p.display(),
                m.uid()
            ));
        }
        let sticky = m.is_dir() && m.mode() & 0o1000 != 0;
        if m.mode() & 0o002 != 0 && !sticky {
            return Some(format!(
                "{} is writable by every user (chmod o-w)",
                p.display()
            ));
        }
        if m.mode() & 0o020 != 0 && !sticky && !is_private_group(m.gid()) {
            return Some(format!(
                "{} is writable by group {} (chmod g-w)",
                p.display(),
                m.gid()
            ));
        }
        at = p.parent();
    }
    None
}

/// The path settings in the environment that are set but ignored because
/// they are not absolute, for a warning.
pub fn ignored_relative_settings() -> Vec<&'static str> {
    [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "LABLINK_CONFIG",
        "LABLINK_STATE_DIR",
        "LABLINK_SOCKET",
    ]
    .into_iter()
    .filter(|v| std::env::var_os(v).is_some_and(|x| !Path::new(&x).is_absolute()))
    .collect()
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

    /// A supplementary group of this user that is not its private group.
    fn shared_group() -> Option<u32> {
        let mut groups = vec![0 as libc::gid_t; 256];
        // SAFETY: the buffer holds `groups.len()` entries.
        let n = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
        groups.truncate(n.max(0) as usize);
        groups.into_iter().find(|&g| !is_private_group(g) && g != 0)
    }

    #[test]
    fn files_other_users_could_change_are_named() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("config.yaml");
        std::fs::write(&f, "").unwrap();
        chmod(&f, 0o600);
        assert_eq!(writable_by_others(&f), None);
        chmod(&f, 0o666);
        let why = writable_by_others(&f).unwrap_or_default();
        assert!(why.contains("writable by every user"), "{why}");
        // Group-writable: fine for the user's own private group (umask 002),
        // refused for a group other users are in.
        chmod(&f, 0o664);
        // SAFETY: getgid has no preconditions.
        let private = is_private_group(unsafe { libc::getgid() });
        assert_eq!(writable_by_others(&f).is_none(), private);
        if let Some(g) = shared_group() {
            std::os::unix::fs::chown(&f, None, Some(g)).unwrap();
            let why = writable_by_others(&f).unwrap_or_default();
            assert!(why.contains(&format!("writable by group {g}")), "{why}");
            chmod(&f, 0o644);
            assert_eq!(writable_by_others(&f), None);
            // The same for a directory above the file.
            std::os::unix::fs::chown(dir.path(), None, Some(g)).unwrap();
            chmod(dir.path(), 0o770);
            assert!(writable_by_others(&f).is_some());
            chmod(dir.path(), 0o750);
            assert_eq!(writable_by_others(&f), None);
        }
        chmod(&f, 0o600);
        chmod(dir.path(), 0o700);
        // A directory anyone can write to lets them replace the file...
        chmod(dir.path(), 0o777);
        let why = writable_by_others(&f).unwrap_or_default();
        assert!(why.contains("writable by every user"), "{why}");
        // ...unless it is sticky, like /tmp: only the owner can replace it.
        chmod(dir.path(), 0o1777);
        assert_eq!(writable_by_others(&f), None);
        chmod(dir.path(), 0o700);
        // Through a symlink of ours, the real location is judged.
        let link = dir.path().join("link.yaml");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(writable_by_others(&link), None);
        chmod(&f, 0o646);
        assert!(writable_by_others(&link).is_some());
        chmod(&f, 0o600);
        // Files owned by root (here /etc/passwd) are trusted like your own.
        assert_eq!(writable_by_others(Path::new("/etc/passwd")), None);
        assert_eq!(writable_by_others(&dir.path().join("missing")), None);
        // Anything that cannot be checked is not trusted.
        chmod(dir.path(), 0o000);
        let blocked = writable_by_others(&f);
        chmod(dir.path(), 0o700);
        if uid() != 0 {
            assert!(blocked.unwrap_or_default().contains("cannot check"));
        }
    }
}
