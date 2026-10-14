//! Local ownership and publication. All operations are on pinned capabilities.
//! Private namespace + inode identity prevent accidental cleanup of substitutes.
//! Hostile same-UID actors can bypass permissions/advisory locks; see review.
use crate::{fs, validate_name, Error, Result};
use cap_fs_ext::DirExt;
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, File, Metadata, MetadataExt};
use std::os::fd::{AsRawFd, FromRawFd};

pub struct LocalLease {
    _directory: Dir,
}
impl LocalLease {
    pub fn acquire(parent: &Dir) -> Result<Self> {
        // A fresh open description is required: dup would share a flock lease.
        // cap-std directory capabilities may be O_PATH descriptors on Linux.
        // Open a real, fresh description for flock; dup/O_PATH are unsuitable.
        // SAFETY: live directory descriptor and a constant single dot component.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new descriptor; transfer ownership once.
        let directory = Dir::from_std_file(unsafe { std::fs::File::from_raw_fd(fd) });
        // SAFETY: live private descriptor; no blocking lock request.
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Refused("Destination directory is busy or does not support safe locking; retry after the other writer finishes".into()));
        }
        Ok(Self {
            _directory: directory,
        })
    }
}

pub struct LocalStage {
    parent: Dir,
    directory: Dir,
    directory_identity: Metadata,
    name: String,
    pub file: File,
}
impl LocalStage {
    pub fn create(parent: &Dir) -> Result<Self> {
        Self::create_named(
            parent,
            format!(".lablink-transfer-{}", uuid::Uuid::new_v4()),
        )
    }
    /// Explicit names are used by deterministic ownership tests. Still exclusive.
    pub fn create_named(parent: &Dir, name: String) -> Result<Self> {
        validate_name(&name)?;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(&name, &builder)?;
        let expected = parent.symlink_metadata(&name)?;
        let directory = parent.open_dir_nofollow(&name)?;
        let directory_identity = directory.dir_metadata()?;
        if !same_inode(&expected, &directory_identity) {
            return Err(Error::Refused(
                "Staging directory substituted while opening; retained".into(),
            ));
        }
        // A failure here retains the directory; no unproven name-based cleanup.
        let file = fs::local_open(&directory, "payload", true)?;
        Ok(Self {
            parent: parent.try_clone()?,
            directory,
            directory_identity,
            name,
            file,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn verify(&self) -> Result<()> {
        let entry = self.directory.symlink_metadata("payload")?;
        if !entry.is_file() || !same_inode(&entry, &self.file.metadata()?) {
            return Err(Error::Refused(
                "Local staging payload substituted; retained without deleting it".into(),
            ));
        }
        let entry = self.parent.symlink_metadata(&self.name)?;
        if !entry.is_dir() || !same_inode(&entry, &self.directory_identity) {
            return Err(Error::Refused(
                "Local staging directory substituted; publication refused".into(),
            ));
        }
        Ok(())
    }
    pub fn publish(&self, destination: &Dir, name: &str) -> Result<()> {
        self.verify()?;
        fs::rename_between_noreplace(&self.directory, "payload", destination, name)
    }
}
impl Drop for LocalStage {
    fn drop(&mut self) {
        // Never recurse, never scan prefixes, and never unlink an unproven entry.
        if let Ok(entry) = self.directory.symlink_metadata("payload") {
            if entry.is_file() && self.file.metadata().is_ok_and(|m| same_inode(&entry, &m)) {
                let _ = self.directory.remove_file("payload");
            }
        }
        if self
            .parent
            .symlink_metadata(&self.name)
            .is_ok_and(|m| m.is_dir() && same_inode(&m, &self.directory_identity))
        {
            let _ = self.parent.remove_dir(&self.name); // refuses non-empty directories
        }
    }
}
pub fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
