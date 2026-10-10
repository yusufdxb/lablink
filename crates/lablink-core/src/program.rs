//! Starting other programs (OpenSSH tools, systemctl, terminals) by name.
//!
//! A bare name is looked up only in trusted absolute `$PATH` directories. Empty and
//! relative entries (`PATH=:/usr/bin`, `.`) mean the current directory, which
//! may be a cloned repository with its own `ssh`; that `ssh` would receive the
//! pinned identity's address and the password typed for `copy-id`. Children
//! get the same `$PATH` without those entries, so programs they start by name
//! (a ProxyCommand's `ssh`, the `ssh` inside `ssh-copy-id`) cannot be taken
//! from the current directory either.

use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What `execvp` searches when `$PATH` is unset.
const DEFAULT_PATH: &str = "/bin:/usr/bin";

/// `$PATH` with only absolute directories that other users cannot replace or
/// write. Children also use this path when starting helpers of their own.
pub fn search_path() -> OsString {
    trusted_dirs(&absolute_dirs(std::env::var_os("PATH")))
}

fn trusted_dirs(path: &OsString) -> OsString {
    std::env::join_paths(std::env::split_paths(path).filter(|d| {
        d.is_absolute()
            && crate::paths::trusted_metadata(d).is_ok_and(|m| {
                // A sticky shared directory protects an already checked file, but
                // children searching it by name could choose another user's file.
                m.is_dir()
                    && !(m.permissions().mode() & 0o1000 != 0
                        && m.permissions().mode() & 0o022 != 0)
            })
    }))
    .unwrap_or_default()
}

fn absolute_dirs(path: Option<OsString>) -> OsString {
    let path = path.unwrap_or_else(|| DEFAULT_PATH.into());
    let dirs = std::env::split_paths(&path).filter(|d| d.is_absolute());
    std::env::join_paths(dirs).unwrap_or_default()
}

fn executable(p: &Path) -> bool {
    trusted_executable(p).is_ok()
}

/// An absolute executable whose file, links and parent directories are trusted.
pub fn trusted_executable(p: &Path) -> io::Result<PathBuf> {
    if !p.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "program path must be absolute",
        ));
    }
    let m = crate::paths::trusted_metadata(p)
        .map_err(|why| io::Error::new(io::ErrorKind::PermissionDenied, why))?;
    if !m.is_file() || m.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "program is not an executable file",
        ));
    }
    Ok(p.to_path_buf())
}

/// The program `name` runs: a path as given (configured program paths are
/// absolute), else the first executable `name` in an absolute `$PATH`
/// directory.
pub fn find(name: &str) -> io::Result<PathBuf> {
    find_in(name, &search_path())
}

fn find_in(name: &str, path: &OsString) -> io::Result<PathBuf> {
    if name.contains('/') {
        return trusted_executable(Path::new(name));
    }
    if !name.is_empty() {
        if let Some(p) = std::env::split_paths(path)
            .map(|d| d.join(name))
            .find(|p| executable(p))
        {
            return Ok(p);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("'{name}' is not a trusted executable in any absolute $PATH directory"),
    ))
}

/// A [`Command`] for `name`, resolved by [`find`], whose `$PATH` keeps only
/// absolute directories.
pub fn command(name: &str) -> io::Result<Command> {
    let path = search_path();
    let mut c = Command::new(find_in(name, &path)?);
    c.env("PATH", path);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// An `ssh` in the current directory is never run, whatever relative
    /// entries `$PATH` has; the next absolute directory's `ssh` is.
    #[test]
    fn relative_path_entries_never_select_a_program() {
        let cwd = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        fake(cwd.path(), "ssh");
        let real = fake(bin.path(), "ssh");
        let abs = bin.path().display().to_string();
        let rel = cwd
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        for raw in [
            format!(":{abs}"),
            format!(".:{abs}"),
            format!("{abs}:"),
            format!("{rel}:{abs}"),
            format!("::.:{abs}:."),
        ] {
            let p = absolute_dirs(Some(raw.clone().into()));
            assert_eq!(p, OsString::from(&abs), "PATH={raw}");
            assert_eq!(find_in("ssh", &p).unwrap(), real, "PATH={raw}");
        }
        assert!(find_in("ssh", &absolute_dirs(Some(".:".into()))).is_err());
        assert_eq!(absolute_dirs(None), OsString::from(DEFAULT_PATH));
        assert!(find_in("/nonexistent/ssh", &OsString::new()).is_err());
        assert!(find_in("./ssh", &OsString::new()).is_err());
        assert!(find_in("", &OsString::from(abs)).is_err());
    }

    /// Only executable regular files count, as for `execvp`.
    #[test]
    fn non_executables_and_directories_are_skipped() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("ssh"), "").unwrap();
        std::fs::create_dir(a.path().join("ssh-keygen")).unwrap();
        let real = fake(b.path(), "ssh");
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        assert_eq!(find_in("ssh", &path).unwrap(), real);
        assert!(find_in("ssh-keygen", &path).is_err());
    }

    #[test]
    fn writable_helpers_and_parent_directories_are_skipped() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let bad = fake(a.path(), "ssh");
        let good = fake(b.path(), "ssh");
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert_eq!(find_in("ssh", &path).unwrap(), good);
        assert!(trusted_executable(&bad).is_err());
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(a.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(find_in("ssh", &path).unwrap(), good);
        assert_eq!(trusted_dirs(&path), b.path().as_os_str());
        let sticky = tempfile::tempdir().unwrap();
        std::fs::set_permissions(sticky.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(trusted_dirs(&sticky.path().as_os_str().to_os_string()).is_empty());
        if unsafe { libc::geteuid() } == 0 {
            std::fs::set_permissions(a.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let p = std::ffi::CString::new(bad.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(p.as_ptr(), 65534, 65534) }, 0);
            assert_eq!(find_in("ssh", &path).unwrap(), good);
        }
    }
}
