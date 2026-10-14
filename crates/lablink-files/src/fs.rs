use crate::{
    check_cancel, remote_join, validate_name, validate_path, Entry, Error, Kind, Listing, Result,
};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use russh_sftp::{
    client::{error::Error as SftpError, RawSftpSession},
    protocol::{FileAttributes, StatusCode},
};
use std::{
    collections::BTreeSet,
    path::{Component, Path},
    time::UNIX_EPOCH,
};
use tokio_util::sync::CancellationToken;

pub const MAX_ENTRIES: usize = 50_000;
pub const MAX_DEPTH: usize = 128;

/// Explicitly chosen browser roots may resolve OS aliases (e.g. macOS /var).
/// All child operations use directory capabilities and no-follow traversal.
pub fn local_root(path: &Path) -> Result<(Dir, String)> {
    let path = std::fs::canonicalize(path)?;
    let expected = std::fs::metadata(&path)?;
    let text = path
        .to_str()
        .ok_or_else(|| Error::Refused("Non-UTF-8 paths are unsupported".into()))?
        .to_owned();
    validate_path(&text)?;
    // Canonicalization may resolve explicit OS aliases. Once it returns, no
    // component may be followed as a symlink while acquiring the capability.
    let slash = Dir::open_ambient_dir("/", ambient_authority())?;
    let dir = local_child_dir(
        &slash,
        path.strip_prefix("/")
            .map_err(|_| Error::Refused("Absolute local root required".into()))?,
    )?;
    use cap_std::fs::MetadataExt;
    use std::os::unix::fs::MetadataExt as StdMetadataExt;
    let actual = dir.dir_metadata()?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(Error::Refused("Local root changed while opening".into()));
    }
    Ok((dir, text))
}
pub fn local_child_dir(root: &Dir, relative: &Path) -> Result<Dir> {
    let mut dir = root.try_clone()?;
    for part in relative.components() {
        match part {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| Error::Refused("Non-UTF-8 filenames are unsupported".into()))?;
                validate_name(name)?;
                dir = dir.open_dir_nofollow(name)?;
            }
            Component::CurDir => (),
            _ => return Err(Error::Refused("Path traversal refused".into())),
        }
    }
    Ok(dir)
}
pub fn local_open(root: &Dir, name: &str, create: bool) -> Result<cap_std::fs::File> {
    use cap_std::fs::OpenOptionsExt;
    validate_name(name)?;
    let mut options = OpenOptions::new();
    options.custom_flags(libc::O_NONBLOCK);
    options.follow(FollowSymlinks::No);
    if create {
        options.read(true).write(true).create_new(true).mode(0o600);
    } else {
        options.read(true);
    }
    let file = root.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Refused(
            "Only regular files can be transferred".into(),
        ));
    }
    Ok(file)
}
pub fn local_listing(path: &Path) -> Result<Listing> {
    let (dir, path) = local_root(path)?;
    let mut entries = Vec::new();
    for entry in dir.entries()? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::Refused("Non-UTF-8 filenames are unsupported".into()))?;
        validate_name(&name)?;
        let m = dir.symlink_metadata(&name)?;
        let kind = if m.is_symlink() {
            Kind::Symlink
        } else if m.is_dir() {
            Kind::Directory
        } else if m.is_file() {
            Kind::File
        } else {
            Kind::Other
        };
        entries.push(Entry {
            name,
            kind,
            size: Some(m.len()),
            modified: m
                .modified()
                .ok()
                .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
        });
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Refused(
                "Directory exceeds 50,000-entry safety limit".into(),
            ));
        }
    }
    Ok(Listing { path, entries })
}
pub fn local_mkdir(path: &Path, name: &str) -> Result<()> {
    validate_name(name)?;
    let (dir, _) = local_root(path)?;
    dir.create_dir(name)?;
    Ok(())
}
pub fn local_rename(path: &Path, old: &str, new: &str) -> Result<()> {
    validate_name(old)?;
    validate_name(new)?;
    let (dir, _) = local_root(path)?;
    // Atomic no-clobber rename, including directories (Linux and macOS).
    rename_noreplace(&dir, old, new)
}
pub fn rename_noreplace(dir: &Dir, old: &str, new: &str) -> Result<()> {
    rename_between_noreplace(dir, old, dir, new)
}
#[cfg(target_os = "linux")]
pub fn rename_between_noreplace(from: &Dir, old: &str, to: &Dir, new: &str) -> Result<()> {
    validate_name(old)?;
    validate_name(new)?;
    use std::{ffi::CString, os::fd::AsRawFd};
    let old = CString::new(old).map_err(|_| Error::Refused("Invalid filename".into()))?;
    let new = CString::new(new).map_err(|_| Error::Refused("Invalid filename".into()))?;
    // SAFETY: live directory descriptor and NUL-terminated single components.
    let result = unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            old.as_ptr(),
            to.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
pub fn rename_between_noreplace(from: &Dir, old: &str, to: &Dir, new: &str) -> Result<()> {
    validate_name(old)?;
    validate_name(new)?;
    use std::{ffi::CString, os::fd::AsRawFd};
    let old = CString::new(old).map_err(|_| Error::Refused("Invalid filename".into()))?;
    let new = CString::new(new).map_err(|_| Error::Refused("Invalid filename".into()))?;
    // SAFETY: live directory descriptor and NUL-terminated single components.
    let result = unsafe {
        libc::renameatx_np(
            from.as_raw_fd(),
            old.as_ptr(),
            to.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub fn remote_kind(attrs: &FileAttributes) -> Kind {
    // Compare the type mask exactly; russh's is_* helpers use bit containment.
    match attrs.permissions.unwrap_or(0) & 0o170000 {
        0o040000 => Kind::Directory,
        0o100000 => Kind::File,
        0o120000 => Kind::Symlink,
        _ => Kind::Other,
    }
}
pub fn status_is(error: &SftpError, code: StatusCode) -> bool {
    matches!(error, SftpError::Status(s) if s.status_code == code)
}
pub async fn remote_metadata(sftp: &RawSftpSession, path: &str) -> Result<Option<FileAttributes>> {
    match sftp.lstat(path).await {
        Ok(a) => Ok(Some(a.attrs)),
        Err(e) if status_is(&e, StatusCode::NoSuchFile) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
/// Check every ancestor rather than just the final path. SFTP v3 has no
/// openat/O_NOFOLLOW; this cannot remove races caused by concurrent server writers.
pub async fn remote_dir(sftp: &RawSftpSession, path: &str) -> Result<String> {
    validate_path(path)?;
    let absolute = if path == "." {
        sftp.realpath(".")
            .await?
            .files
            .into_iter()
            .next()
            .ok_or_else(|| Error::Refused("Server returned no home directory".into()))?
            .filename
    } else if path.starts_with('/') {
        normalize_remote(path)?
    } else {
        return Err(Error::Refused("Enter an absolute remote path".into()));
    };
    let mut prefix = String::from("/");
    for name in absolute.split('/').filter(|s| !s.is_empty()) {
        prefix = remote_join(&prefix, name)?;
        let attrs = sftp.lstat(&prefix).await?.attrs;
        if remote_kind(&attrs) != Kind::Directory {
            return Err(Error::Refused(
                "Remote directory contains a symlink or is not a folder".into(),
            ));
        }
    }
    let canonical = sftp
        .realpath(absolute.clone())
        .await?
        .files
        .into_iter()
        .next()
        .ok_or_else(|| Error::Refused("Server returned no canonical path".into()))?
        .filename;
    validate_path(&canonical)?;
    if normalize_remote(&canonical)? != absolute {
        return Err(Error::Refused(
            "Remote path changed during validation".into(),
        ));
    }
    Ok(absolute)
}
pub fn normalize_remote(path: &str) -> Result<String> {
    validate_path(path)?;
    if !path.starts_with('/') {
        return Err(Error::Refused("Absolute remote path required".into()));
    }
    let mut parts = Vec::new();
    for name in path.split('/') {
        match name {
            "" | "." => (),
            ".." => {
                parts.pop();
            }
            _ => {
                validate_name(name)?;
                parts.push(name);
            }
        }
    }
    Ok(format!("/{}", parts.join("/")))
}
pub async fn remote_listing(
    sftp: &RawSftpSession,
    path: &str,
    cancel: &CancellationToken,
) -> Result<Listing> {
    let path = remote_dir(sftp, path).await?;
    let handle = sftp.opendir(path.clone()).await?.handle;
    let result = async {
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            check_cancel(cancel)?;
            let batch = match sftp.readdir(handle.clone()).await {
                Ok(batch) => batch,
                Err(e) if status_is(&e, StatusCode::Eof) => break,
                Err(e) => return Err(e.into()),
            };
            if batch.files.is_empty() {
                return Err(Error::Refused(
                    "Server returned an empty directory packet without EOF".into(),
                ));
            }
            for file in batch.files {
                if file.filename == "." || file.filename == ".." {
                    continue;
                }
                validate_name(&file.filename)?;
                if !names.insert(file.filename.clone()) {
                    return Err(Error::Refused(
                        "Server returned duplicate directory names".into(),
                    ));
                }
                entries.push(Entry {
                    name: file.filename,
                    kind: remote_kind(&file.attrs),
                    size: file.attrs.size,
                    modified: file.attrs.mtime.map(u64::from),
                });
                if entries.len() > MAX_ENTRIES {
                    return Err(Error::Refused(
                        "Directory exceeds 50,000-entry safety limit".into(),
                    ));
                }
            }
        }
        Ok(Listing { path, entries })
    }
    .await;
    let close = sftp.close(handle).await;
    match result {
        Ok(listing) => {
            close?;
            Ok(listing)
        }
        Err(e) => Err(e),
    }
}
pub async fn remote_mkdir(sftp: &RawSftpSession, path: &str, name: &str) -> Result<()> {
    let parent = remote_dir(sftp, path).await?;
    sftp.mkdir(
        remote_join(&parent, name)?,
        FileAttributes {
            permissions: Some(0o700),
            ..FileAttributes::empty()
        },
    )
    .await?;
    Ok(())
}
pub async fn remote_rename(_sftp: &RawSftpSession, path: &str, old: &str, new: &str) -> Result<()> {
    validate_path(path)?;
    validate_name(old)?;
    validate_name(new)?;
    // Standard SFTP rename may use stat+rename, or link+unlink without
    // conditional source deletion. Neither proves ownership under path races.
    Err(Error::Refused(
        "Remote rename refused: the server cannot guarantee safe rename under concurrent writers"
            .into(),
    ))
}

/// Reserved, UUID-shaped transient namespace. Skip when planning copies; a
/// matching name never grants deletion authority or proves ownership.
pub fn is_staging_name(name: &str) -> bool {
    name.strip_prefix(".lablink-transfer-")
        .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
}
