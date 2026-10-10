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
    let account = passwd_entry()?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&account.dir))).filter(|p| p.is_absolute())
}

/// This user's entry in the password database.
struct Account {
    name: Vec<u8>,
    dir: Vec<u8>,
    /// The primary group: what files are created with, whatever group the
    /// process happens to run as (`newgrp`, `sg`, a service's `Group=`).
    gid: u32,
}

fn passwd_entry() -> Option<Account> {
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
    Some(Account {
        name: name.to_bytes().to_vec(),
        dir: dir.to_bytes().to_vec(),
        gid: pw.pw_gid,
    })
}

/// How long the answer of [`private_group`] is reused. Each lookup can be a
/// round trip to a directory server (LDAP, Active Directory), and the answer
/// is needed for every group-writable directory on every probe; group
/// membership changes need root, and are seen within this time.
const PRIVATE_GROUP_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// This user's private group, the group a umask of 002 is meant for, if it
/// has one: the primary group from the password database, named like the
/// user (`pam_umask` usergroups), with no other members listed, no other
/// account in /etc/passwd having it as primary group and no other line of
/// /etc/group using its number. Only when every account and group is local:
/// /etc/nsswitch.conf must list nothing but `files` and `systemd` for
/// `passwd` and `group`, because accounts of a directory service (LDAP,
/// SSSD, NIS, winbind, extrausers) cannot be listed, so one of them could
/// share the group unseen. Looked up at most once per [`PRIVATE_GROUP_TTL`];
/// any lookup failure means no private group.
fn private_group() -> Option<u32> {
    use std::sync::Mutex;
    use std::time::Instant;
    static CACHE: Mutex<Option<(Instant, Option<u32>)>> = Mutex::new(None);
    // Holding the lock during the lookup makes concurrent callers wait for
    // one lookup instead of each starting their own.
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, gid)) = *cache {
        if at.elapsed() < PRIVATE_GROUP_TTL {
            return gid;
        }
    }
    let gid = lookup_private_group();
    *cache = Some((Instant::now(), gid));
    gid
}

fn lookup_private_group() -> Option<u32> {
    let account = passwd_entry()?;
    let gid = account.gid;
    let user = account.name.as_slice();
    // SAFETY: an all-zero group is a valid value for getgrgid_r to fill.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 64 * 1024];
    // SAFETY: as for getpwuid_r above. A group too large for `buf` (ERANGE)
    // is no private group.
    let rc = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || gr.gr_name.is_null() {
        return None;
    }
    // SAFETY: gr_name is a NUL-terminated string inside `buf`.
    if unsafe { std::ffi::CStr::from_ptr(gr.gr_name) }.to_bytes() != user {
        return None;
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
        if unsafe { std::ffi::CStr::from_ptr(m) }.to_bytes() != user {
            return None;
        }
        i += 1;
    }
    // Another account whose primary group this is can write the files too,
    // without being listed as a member, and so can the members of another
    // group with the same number. Only local files can be searched (a
    // directory server often refuses to list its accounts), so a private
    // group exists only where every account and group comes from them.
    let nsswitch = std::fs::read("/etc/nsswitch.conf").ok()?;
    if !accounts_are_local(&nsswitch, b"passwd") || !accounts_are_local(&nsswitch, b"group") {
        return None;
    }
    let passwd = std::fs::read("/etc/passwd").ok()?;
    if others_with_primary_group(&passwd, user, gid) {
        return None;
    }
    let group = std::fs::read("/etc/group").ok()?;
    if other_groups_with_gid(&group, user, gid) {
        return None;
    }
    Some(gid)
}

/// Whether /etc/nsswitch.conf (`conf`) takes `database` (`passwd`, `group`)
/// only from sources whose accounts this host lists itself: `files`
/// (/etc/passwd, /etc/group) and `systemd` (accounts root defines through
/// systemd). A missing or repeated line, `compat` (NIS `+` entries) and any
/// other service (`ldap`, `sss`, `nis`, `winbind`, `extrausers`, ...) are
/// not local.
fn accounts_are_local(conf: &[u8], database: &[u8]) -> bool {
    let mut lines = conf.split(|&b| b == b'\n').filter_map(|line| {
        let line = line.split(|&b| b == b'#').next().unwrap_or_default();
        let colon = line.iter().position(|&b| b == b':')?;
        (line[..colon].trim_ascii() == database).then(|| &line[colon + 1..])
    });
    let (Some(sources), None) = (lines.next(), lines.next()) else {
        return false;
    };
    // Actions such as `[NOTFOUND=return]` sit between brackets.
    let mut depth = 0usize;
    let mut words = Vec::new();
    let mut word = Vec::new();
    for &b in sources {
        match b {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            _ if depth > 0 => {}
            b if b.is_ascii_whitespace() => words.push(std::mem::take(&mut word)),
            b => word.push(b),
        }
    }
    words.push(word);
    words.retain(|w| !w.is_empty());
    !words.is_empty()
        && words
            .iter()
            .all(|w| w.as_slice() == b"files" || w.as_slice() == b"systemd")
}

/// Whether a line of `group` (the /etc/group format) with number `gid` is
/// named other than `user` or lists a member other than `user`.
fn other_groups_with_gid(group: &[u8], user: &[u8], gid: u32) -> bool {
    group.split(|&b| b == b'\n').any(|line| {
        let mut f = line.split(|&b| b == b':');
        let (Some(name), Some(_), Some(g), members) = (f.next(), f.next(), f.next(), f.next())
        else {
            return false;
        };
        if std::str::from_utf8(g).ok().and_then(|g| g.parse().ok()) != Some(gid) {
            return false;
        }
        name != user
            || members
                .unwrap_or_default()
                .split(|&b| b == b',')
                .any(|m| !m.is_empty() && m != user)
    })
}

/// Whether a line of `passwd` (the /etc/passwd format) other than `user`'s
/// has `gid` as its primary group.
fn others_with_primary_group(passwd: &[u8], user: &[u8], gid: u32) -> bool {
    passwd.split(|&b| b == b'\n').any(|line| {
        let mut f = line.split(|&b| b == b':');
        let (Some(name), Some(_), Some(_), Some(g)) = (f.next(), f.next(), f.next(), f.next())
        else {
            return false;
        };
        name != user && std::str::from_utf8(g).ok().and_then(|g| g.parse().ok()) == Some(gid)
    })
}

/// Whether `gid` is this user's private group (see [`private_group`]).
fn is_private_group(gid: u32) -> bool {
    private_group() == Some(gid)
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Most symbolic links followed while checking one path (the kernel's limit).
const MAX_LINKS: u32 = 40;

/// Whether the POSIX access ACL of `p` (if it has one) lets a user other
/// than this one or root, or a group other than the private group, write
/// it. With an ACL, the group bits of the mode are only the ACL's mask, so
/// they do not show who the named entries are. No ACL, or a filesystem
/// without ACLs, means no such writer; any other failure to read it is an
/// error.
fn acl_lets_others_write(p: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = c"system.posix_acl_access";
    let get = |buf: &mut [u8]| {
        // SAFETY: both strings are NUL-terminated and `buf` is valid for
        // `buf.len()` bytes (a zero length only asks for the size).
        let n = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    };
    let none = |e: &std::io::Error| {
        matches!(
            e.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
        )
    };
    let size = match get(&mut []) {
        Ok(n) => n,
        Err(e) if none(&e) => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut acl = vec![0u8; size];
    let n = match get(&mut acl) {
        Ok(n) => n,
        Err(e) if none(&e) => return Ok(false),
        Err(e) => return Err(e),
    };
    let unreadable =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable access ACL");
    // A size larger than the buffer means the ACL changed between the calls.
    let acl = acl.get(..n).ok_or_else(unreadable)?;
    acl_writers(acl, uid(), private_group()).ok_or_else(unreadable)
}

/// Whether the access ACL `acl` (the kernel's `system.posix_acl_access`
/// format: a little-endian version 2, then 8-byte tag, permissions and id
/// entries) gives write to a user other than `me` or root or a group other
/// than `private`. `None` if it is not in that format.
fn acl_writers(acl: &[u8], me: u32, private: Option<u32>) -> Option<bool> {
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP: u16 = 0x08;
    const ACL_WRITE: u16 = 0x02;
    let (version, entries) = acl.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*version) != 2 || entries.len() % 8 != 0 {
        return None;
    }
    Some(entries.as_chunks::<8>().0.iter().any(|e| {
        let tag = u16::from_le_bytes([e[0], e[1]]);
        let write = u16::from_le_bytes([e[2], e[3]]) & ACL_WRITE != 0;
        let id = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        write
            && match tag {
                ACL_USER => id != me && id != 0,
                ACL_GROUP => Some(id) != private,
                _ => false,
            }
    }))
}

/// Why another user could have written or replaced `path`, if one could
/// (see [`trusted_metadata`]).
pub fn writable_by_others(path: &Path) -> Option<String> {
    trusted_metadata(path).err()
}

/// The metadata of what `path` leads to, if no other user could have
/// written or replaced it, else why one could.
///
/// The path is resolved one component at a time from `/`, as the kernel
/// does, and everything met on the way is judged: every directory entered
/// and the final file or directory must belong to this user or root and be
/// writable by neither everyone (directories with the sticky bit, like /tmp,
/// excepted: only a file's owner can replace a file there) nor a group,
/// unless that group is the user's own private group (see [`private_group`]),
/// so files and directories created with a umask of 002 stay usable. A
/// shared group such as `lab` is refused, as OpenSSH refuses a
/// group-writable config, and so is a group-writable file or directory whose
/// POSIX access ACL lets another user or group write it. Every symbolic link met, including those inside
/// the targets of other links, must belong to this user or root, as its
/// owner could point it elsewhere at any time.
///
/// Judging from `/` down means that once a path passes, no other user can
/// change where it leads: each step's owner and permissions keep them from
/// replacing the next. A path that does not exist, or that cannot be
/// resolved to a file (such as `/dev/stdin` on a pipe), is refused.
pub fn trusted_metadata(path: &Path) -> Result<std::fs::Metadata, String> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    let me = uid();
    let ours = |uid: u32| uid == me || uid == 0;
    let cannot = |p: &Path, why: &dyn std::fmt::Display| {
        if p == path {
            format!("cannot check {}: {why}", path.display())
        } else {
            format!("cannot check {}: {}: {why}", path.display(), p.display())
        }
    };
    let judge = |p: &Path, m: &std::fs::Metadata| -> Result<(), String> {
        if !ours(m.uid()) {
            return Err(format!(
                "{} belongs to another user (uid {})",
                p.display(),
                m.uid()
            ));
        }
        let sticky = m.is_dir() && m.mode() & 0o1000 != 0;
        if m.mode() & 0o002 != 0 && !sticky {
            return Err(format!(
                "{} is writable by every user (chmod o-w)",
                p.display()
            ));
        }
        if m.mode() & 0o020 != 0 && !sticky {
            if !is_private_group(m.gid()) {
                return Err(format!(
                    "{} is writable by group {} (chmod g-w)",
                    p.display(),
                    m.gid()
                ));
            }
            // The group bits are an ACL's mask if it has one: the named
            // users and groups it lists may write too.
            match acl_lets_others_write(p) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(format!(
                        "{} has an ACL that lets another user or group write it (chmod g-w, or setfacl -b)",
                        p.display()
                    ))
                }
                Err(e) => return Err(cannot(p, &e)),
            }
        }
        Ok(())
    };
    if path.as_os_str().is_empty() {
        return Err(cannot(path, &"empty path"));
    }
    // A relative path starts at the current directory, which the kernel
    // reports without links.
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| cannot(path, &e))?
            .join(path)
    };
    // Components still to walk, the next one last. `.` stands for a
    // trailing `/` or `/.`, which `components` drops but the kernel reads as
    // "this must be a directory".
    let mut todo: Vec<std::ffi::OsString> = Vec::new();
    let push = |todo: &mut Vec<std::ffi::OsString>, p: &Path| {
        use std::os::unix::ffi::OsStrExt;
        let b = p.as_os_str().as_bytes();
        if b.ends_with(b"/") || b.ends_with(b"/.") || b == b"." {
            todo.push(".".into());
        }
        for c in p.components().rev() {
            match c {
                Component::Normal(n) => todo.push(n.to_os_string()),
                Component::ParentDir => todo.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    };
    push(&mut todo, &full);
    // `at` never holds a link: it is where the walk stands, every directory
    // above it already judged.
    let mut at = PathBuf::from("/");
    let mut meta = std::fs::symlink_metadata(&at).map_err(|e| cannot(&at, &e))?;
    judge(&at, &meta)?;
    let mut links = 0;
    while let Some(name) = todo.pop() {
        if !meta.is_dir() {
            return Err(cannot(&at, &"not a directory"));
        }
        if name == "." {
            continue;
        }
        if name == ".." {
            at.pop();
            meta = std::fs::symlink_metadata(&at).map_err(|e| cannot(&at, &e))?;
            continue;
        }
        let next = at.join(&name);
        let m = std::fs::symlink_metadata(&next).map_err(|e| cannot(&next, &e))?;
        if m.file_type().is_symlink() {
            if !ours(m.uid()) {
                return Err(format!(
                    "{} is a link that belongs to another user (uid {})",
                    next.display(),
                    m.uid()
                ));
            }
            links += 1;
            if links > MAX_LINKS {
                return Err(cannot(path, &"too many levels of symbolic links"));
            }
            let target = std::fs::read_link(&next).map_err(|e| cannot(&next, &e))?;
            // The kernel resolves an empty target to nothing (ENOENT).
            if target.as_os_str().is_empty() {
                return Err(cannot(&next, &"empty link target"));
            }
            if target.is_absolute() {
                at = PathBuf::from("/");
                meta = std::fs::symlink_metadata(&at).map_err(|e| cannot(&at, &e))?;
            }
            push(&mut todo, &target);
            continue;
        }
        judge(&next, &m)?;
        at = next;
        meta = m;
    }
    Ok(meta)
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
/// else `<state_dir>/run/lablinkd.sock`. The fallback stays in the user's
/// private state tree so another user cannot squat on a predictable /tmp
/// directory. Relative environment values are ignored.
pub fn default_socket_path() -> PathBuf {
    if let Some(p) = env_dir("LABLINK_SOCKET") {
        return p;
    }
    match env_dir("XDG_RUNTIME_DIR") {
        Some(d) => d.join("lablink").join("lablinkd.sock"),
        None => default_state_dir().join("run").join("lablinkd.sock"),
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
        // refused for a group other users are in. New files get the primary
        // group from the password database.
        chmod(&f, 0o664);
        let primary = passwd_entry().unwrap().gid;
        let private = is_private_group(primary);
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
        // Anything that cannot be checked is not trusted, a missing path
        // included: every caller has just seen it exist.
        let missing = writable_by_others(&dir.path().join("missing")).unwrap_or_default();
        assert!(missing.contains("cannot check"), "{missing}");
        chmod(dir.path(), 0o000);
        let blocked = writable_by_others(&f);
        chmod(dir.path(), 0o700);
        if uid() != 0 {
            assert!(blocked.unwrap_or_default().contains("cannot check"));
        }
    }

    #[test]
    fn the_socket_fallback_stays_in_the_private_state_tree() {
        if std::env::var_os("LABLINK_TEST_PRIVATE_SOCKET_FALLBACK").is_some() {
            assert_eq!(
                default_socket_path(),
                default_state_dir().join("run/lablinkd.sock")
            );
            assert!(!default_socket_path().starts_with("/tmp"));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "paths::tests::the_socket_fallback_stays_in_the_private_state_tree",
                "--nocapture",
            ])
            .env("LABLINK_TEST_PRIVATE_SOCKET_FALLBACK", "1")
            .env("LABLINK_STATE_DIR", "/fixture/private-state")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("LABLINK_SOCKET")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_foreign_owned_link_is_refused_even_when_its_target_is_trusted() {
        if uid() != 0 {
            eprintln!("SKIP: foreign link ownership requires root in a disposable container");
            return;
        }
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o700);
        let target = dir.path().join("trusted.yaml");
        std::fs::write(&target, "trusted").unwrap();
        chmod(&target, 0o600);
        let link = dir.path().join("foreign-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(trusted_metadata(&link).is_ok());
        let path = std::ffi::CString::new(link.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; lchown changes only this test link.
        assert_eq!(unsafe { libc::lchown(path.as_ptr(), 65534, 65534) }, 0);
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().uid(), 65534);
        assert!(trusted_metadata(&target).is_ok());
        let outer = dir.path().join("our-link");
        std::os::unix::fs::symlink(&link, &outer).unwrap();
        for path in [&link, &outer] {
            let why = writable_by_others(path).unwrap_or_default();
            assert!(why.contains("link that belongs to another user"), "{why}");
        }
        assert_eq!(std::fs::read_to_string(target).unwrap(), "trusted");
    }

    #[test]
    fn a_real_shared_group_cannot_write_a_trusted_file_or_ancestor() {
        if uid() != 0 {
            eprintln!("SKIP: shared group fixture requires root in a disposable container");
            return;
        }
        let group = 65534;
        assert!(!is_private_group(group));
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o700);
        let file = dir.path().join("config.yaml");
        std::fs::write(&file, "trusted").unwrap();
        std::os::unix::fs::chown(&file, None, Some(group)).unwrap();
        chmod(&file, 0o660);
        let why = writable_by_others(&file).unwrap_or_default();
        assert!(why.contains("writable by group 65534"), "{why}");
        chmod(&file, 0o640);
        assert!(trusted_metadata(&file).is_ok());
        std::os::unix::fs::chown(dir.path(), None, Some(group)).unwrap();
        chmod(dir.path(), 0o770);
        let why = writable_by_others(&file).unwrap_or_default();
        assert!(why.contains("writable by group 65534"), "{why}");
        chmod(dir.path(), 0o750);
        assert!(trusted_metadata(&file).is_ok());
    }

    #[test]
    fn acl_read_errors_fail_closed() {
        if uid() != 0 {
            eprintln!("SKIP: ACL error fixture requires root in a disposable container");
            return;
        }
        if std::env::var_os("LABLINK_TEST_ACL_QUERY_DENIED").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "paths::tests::acl_read_errors_fail_closed",
                    "--nocapture",
                ])
                .env("LABLINK_TEST_ACL_QUERY_DENIED", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            return;
        }
        // Only this child test process is sandboxed. Make the kernel deny
        // lgetxattr so the real trusted_metadata path sees an ACL query error.
        let Some(group) = private_group() else {
            eprintln!("SKIP: ACL error fixture needs a private account group");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o700);
        let file = dir.path().join("config.yaml");
        std::fs::write(&file, "trusted").unwrap();
        std::os::unix::fs::chown(&file, None, Some(group)).unwrap();
        chmod(&file, 0o660);
        assert!(trusted_metadata(&file).is_ok());
        let filter = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_lgetxattr as u32,
            },
            libc::sock_filter {
                code: libc::BPF_RET as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: libc::BPF_RET as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut _,
        };
        // SAFETY: the BPF program is valid for the calls, affects only this
        // child, and denies one syscall without altering Rust memory safety.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let why = writable_by_others(&file).unwrap_or_default();
        assert!(
            why.contains("cannot check") && why.contains("Operation not permitted"),
            "{why}"
        );
        println!("ACL query returned kernel EPERM and trusted_metadata refused: {why}");
    }

    /// Links met while following other links are judged too, and so is
    /// every directory the walk passes through, not only those above the
    /// final file.
    #[test]
    fn every_link_and_directory_on_the_way_is_judged() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        chmod(d, 0o700);
        let f = d.join("config.yaml");
        std::fs::write(&f, "").unwrap();
        chmod(&f, 0o600);
        // A directory anyone can write to, holding a link of ours to the
        // file: anyone could replace that link.
        let open = d.join("open");
        std::fs::create_dir(&open).unwrap();
        chmod(&open, 0o777);
        std::os::unix::fs::symlink(&f, open.join("inner")).unwrap();
        // Our own link, in our own directory, to the link in `open`.
        let outer = d.join("outer");
        std::os::unix::fs::symlink(open.join("inner"), &outer).unwrap();
        let why = writable_by_others(&outer).unwrap_or_default();
        assert!(why.contains("/open is writable by every user"), "{why}");
        // The same through a relative target and `..`.
        let rel = d.join("rel");
        std::os::unix::fs::symlink("open/../open/inner", &rel).unwrap();
        assert!(writable_by_others(&rel).is_some());
        chmod(&open, 0o700);
        assert_eq!(writable_by_others(&outer), None);
        assert_eq!(writable_by_others(&rel), None);
        // The result is what the path leads to.
        let m = trusted_metadata(&outer).unwrap();
        assert!(m.is_file());
        // Loops and dangling links cannot be checked.
        std::os::unix::fs::symlink(d.join("loop-b"), d.join("loop-a")).unwrap();
        std::os::unix::fs::symlink(d.join("loop-a"), d.join("loop-b")).unwrap();
        let why = writable_by_others(&d.join("loop-a")).unwrap_or_default();
        assert!(why.contains("too many levels"), "{why}");
        std::os::unix::fs::symlink(d.join("gone"), d.join("dangling")).unwrap();
        assert!(writable_by_others(&d.join("dangling")).is_some());
        // A file is not a directory to walk through.
        let why = writable_by_others(&f.join("x")).unwrap_or_default();
        assert!(why.contains("not a directory"), "{why}");
    }

    /// Paths the kernel refuses are refused too: the walk never approves a
    /// path that leads nowhere.
    #[test]
    fn what_the_kernel_would_not_open_is_not_approved() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        chmod(d, 0o700);
        let f = d.join("config.yaml");
        std::fs::write(&f, "").unwrap();
        chmod(&f, 0o600);
        let s = |p: &Path| p.to_str().unwrap().to_string();
        assert!(writable_by_others(Path::new("")).is_some(), "empty path");
        for p in [
            format!("{}/", s(&f)),
            format!("{}/.", s(&f)),
            format!("{}/..", s(&f)),
        ] {
            assert!(std::fs::metadata(&p).is_err(), "{p}");
            let why = writable_by_others(Path::new(&p)).unwrap_or_default();
            assert!(why.contains("not a directory"), "{p}: {why}");
        }
        std::os::unix::fs::symlink(format!("{}/", s(&f)), d.join("slash")).unwrap();
        assert!(writable_by_others(&d.join("slash")).is_some());
        // A directory, or a link to one, may end in `/` or `/.`.
        std::os::unix::fs::symlink(d, d.join("here")).unwrap();
        for p in [
            format!("{}/", s(d)),
            format!("{}/.", s(d)),
            format!("{}/here/", s(d)),
        ] {
            assert_eq!(writable_by_others(Path::new(&p)), None, "{p}");
        }
    }

    /// With a POSIX ACL the group bits are only the ACL's mask: the users
    /// and groups it names are judged too.
    #[test]
    fn an_acl_that_lets_another_user_write_is_refused() {
        let acl = |entries: &[(u16, u16, u32)]| {
            let mut b = 2u32.to_le_bytes().to_vec();
            for &(tag, perm, id) in entries {
                b.extend(tag.to_le_bytes());
                b.extend(perm.to_le_bytes());
                b.extend(id.to_le_bytes());
            }
            b
        };
        let base = [
            (0x01, 6, u32::MAX),
            (0x04, 6, u32::MAX),
            (0x10, 6, u32::MAX),
            (0x20, 4, u32::MAX),
        ];
        let with = |e: (u16, u16, u32)| {
            let mut v = base.to_vec();
            v.insert(1, e);
            acl(&v)
        };
        let me = 1000;
        let private = Some(1000);
        assert_eq!(acl_writers(&acl(&base), me, private), Some(false));
        assert_eq!(
            acl_writers(&with((0x02, 6, 2000)), me, private),
            Some(true),
            "user:2000:rw"
        );
        assert_eq!(
            acl_writers(&with((0x02, 4, 2000)), me, private),
            Some(false),
            "user:2000:r"
        );
        assert_eq!(
            acl_writers(&with((0x02, 6, me)), me, private),
            Some(false),
            "user:me:rw"
        );
        assert_eq!(
            acl_writers(&with((0x02, 6, 0)), me, private),
            Some(false),
            "user:root:rw"
        );
        assert_eq!(
            acl_writers(&with((0x08, 2, 3000)), me, private),
            Some(true),
            "group:3000:w"
        );
        assert_eq!(
            acl_writers(&with((0x08, 6, 1000)), me, private),
            Some(false),
            "group:private:rw"
        );
        assert_eq!(
            acl_writers(&with((0x08, 6, 1000)), me, None),
            Some(true),
            "no private group"
        );
        assert_eq!(acl_writers(&[2, 0, 0], me, private), None, "short");
        assert_eq!(
            acl_writers(&acl(&base)[..9], me, private),
            None,
            "cut entry"
        );
        let mut v1 = acl(&base);
        v1[0] = 1;
        assert_eq!(acl_writers(&v1, me, private), None, "version 1");

        // On a real file, where the setfacl tool and ACLs are available.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("config.yaml");
        std::fs::write(&f, "").unwrap();
        chmod(dir.path(), 0o700);
        chmod(&f, 0o600);
        let setfacl = |args: &[&str]| {
            std::process::Command::new("setfacl")
                .args(args)
                .arg(&f)
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        };
        if !setfacl(&["-m", "u:65534:rw"]) {
            eprintln!("setfacl unavailable here: real-file ACL case skipped");
            return;
        }
        let why = writable_by_others(&f).unwrap_or_default();
        assert!(
            why.contains("writable by group") || why.contains("has an ACL"),
            "{why}"
        );
        assert!(setfacl(&["-m", "u:65534:r"]));
        assert!(setfacl(&["-m", "m::r"]));
        assert_eq!(writable_by_others(&f), None, "read-only grant, mask r");
        assert!(setfacl(&["-b"]));
        assert_eq!(writable_by_others(&f), None);
    }

    /// A path that does not lead to a file, like a pipe's /proc fd link (what
    /// `/dev/stdin` is when input is piped), is refused.
    #[test]
    fn a_pipe_is_not_a_path_that_can_be_checked() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` has room for the two descriptors pipe returns.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let p = PathBuf::from(format!("/proc/self/fd/{}", fds[0]));
        let why = writable_by_others(&p);
        // SAFETY: closing the two descriptors this test opened.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert!(why.unwrap_or_default().contains("cannot check"));
    }

    /// The private group is the primary group from the password database,
    /// never the group the process runs as; another local account with it as
    /// primary group makes it shared.
    #[test]
    fn the_private_group_is_the_primary_group_of_the_account() {
        let account = passwd_entry().expect("this user has a password entry");
        if let Some(g) = private_group() {
            assert_eq!(g, account.gid);
        }
        let passwd = b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n\
            bob:x:1001:1001::/home/bob:/bin/sh\n+@netgroup::::::\n";
        assert!(!others_with_primary_group(passwd, b"alice", 1000));
        assert!(others_with_primary_group(passwd, b"alice", 1001));
        assert!(others_with_primary_group(passwd, b"carol", 1000));
        assert!(!others_with_primary_group(b"", b"alice", 1000));
    }

    #[test]
    fn a_group_a_directory_service_could_share_is_not_private() {
        let local = b"# comment\npasswd:         files systemd\ngroup:          files [SUCCESS=merge] systemd\nhosts: files dns\n";
        assert!(accounts_are_local(local, b"passwd"));
        assert!(accounts_are_local(local, b"group"));
        for conf in [
            &b"passwd: files ldap\ngroup: files ldap\n"[..],
            b"passwd: files sss systemd\ngroup: files sss systemd\n",
            b"passwd: compat\ngroup: compat\n",
            b"passwd: files extrausers\ngroup: files extrausers\n",
            b"passwd: files [NOTFOUND=continue] nis\ngroup: nis files\n",
            b"passwd: files\npasswd: ldap\ngroup: files\n",
            b"group: files\n",
            b"passwd:\ngroup: files\n",
            b"",
        ] {
            assert!(
                !accounts_are_local(conf, b"passwd") || !accounts_are_local(conf, b"group"),
                "{}",
                String::from_utf8_lossy(conf)
            );
        }
        let group = b"root:x:0:\nalice:x:1000:\nlab:x:3000:alice,mallory\n";
        assert!(!other_groups_with_gid(group, b"alice", 1000));
        assert!(!other_groups_with_gid(
            b"alice:x:1000:alice\n",
            b"alice",
            1000
        ));
        assert!(other_groups_with_gid(
            b"alice:x:1000:mallory\n",
            b"alice",
            1000
        ));
        // `groupadd -o`: a second group with the same number.
        assert!(other_groups_with_gid(
            b"alice:x:1000:\nshadow2:x:1000:mallory\n",
            b"alice",
            1000
        ));
        assert!(other_groups_with_gid(
            b"alice:x:1000:\nempty:x:1000:\n",
            b"alice",
            1000
        ));
    }
}
