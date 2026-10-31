//! SFTP transport, capability-scoped filesystem operations and bounded workers.
//! Rendering and native dialogs belong to the GUI, never to this crate.
pub mod fs;
pub mod preferences;
pub mod staging;
pub mod transfer;
pub mod transport;
pub mod worker;

use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Refused(String),
    #[error("Transfer cancelled")]
    Cancelled,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("SFTP: {0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
}

impl Error {
    /// Actionable UI errors without rendering arbitrary remote status messages.
    pub fn user_message(&self) -> String {
        use russh_sftp::{client::error::Error as SftpError, protocol::StatusCode};
        let hint = match self {
            Self::Io(error) => match error.raw_os_error() {
                Some(libc::ENOSPC | libc::EDQUOT) => Some("Local storage is full or its quota is exhausted. Free space, inspect the destination, then retry."),
                Some(libc::EACCES | libc::EPERM | libc::EROFS) => Some("Local filesystem permission denied or read-only. Choose a writable destination and check source read permissions."),
                _ => None,
            },
            Self::Sftp(SftpError::Status(status)) => Some(match status.status_code {
                StatusCode::PermissionDenied => "Remote filesystem permission denied. Check source read and destination write permissions for the authenticated SSH user.",
                StatusCode::NoSuchFile => "Remote item no longer exists. Refresh the folder and select it again.",
                StatusCode::NoConnection | StatusCode::ConnectionLost => "Remote connection interrupted. Reconnect, inspect the destination, then retry.",
                StatusCode::OpUnsupported => "The server does not support a required SFTP operation. Use an OpenSSH SFTP server with the required sync and hardlink extensions.",
                StatusCode::Failure => "Remote filesystem operation failed. Check permissions, free space, quota, and server logs. Inspect the destination before retrying.",
                _ => "The server returned an unexpected SFTP status. Inspect the destination and check the server logs before retrying.",
            }),
            Self::Sftp(SftpError::Timeout) => Some("SFTP response timed out. Check connectivity, reconnect, and inspect the destination before retrying."),
            Self::Sftp(SftpError::IO(_)) => Some("SFTP connection or I/O failed. Check connectivity and server availability; inspect the destination before retrying."),
            Self::Sftp(_) => Some("Unexpected SFTP server response. Check server compatibility and logs; inspect the destination before retrying."),
            _ => None,
        };
        hint.map(str::to_owned).unwrap_or_else(|| self.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Directory,
    File,
    Symlink,
    Other,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Directory => "Folder",
            Self::File => "File",
            Self::Symlink => "Symlink",
            Self::Other => "Special",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: Option<u64>,
    pub modified: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictAction {
    Skip,
    Replace,
    KeepBoth,
}
#[derive(Clone, Debug)]
pub struct Job {
    pub id: u64,
    pub device: String,
    pub direction: Direction,
    pub local: PathBuf,
    pub remote: String,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Publication {
    #[default]
    NotRequested,
    Requested,
    Confirmed,
    Uncertain,
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub bytes: u64,
    pub total: u64,
    pub files_done: usize,
    pub files_total: usize,
    pub skipped: usize,
    pub bytes_per_second: f64,
    pub phase: String,
    pub current: Option<String>,
    pub publication: Publication,
}
#[derive(Clone, Debug)]
pub struct Outcome {
    pub progress: Progress,
}

pub fn check_cancel(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// A server's directory names are data, never paths or shell text.
/// Reject control characters too: they can spoof rows and error messages.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.chars().any(|c| c.is_control() || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        || name.len() > 255
    {
        Err(Error::Refused(
            "Unsafe or unsupported directory entry name".into(),
        ))
    } else {
        Ok(())
    }
}
pub fn remote_join(parent: &str, name: &str) -> Result<String> {
    validate_name(name)?;
    let path = format!("{}/{}", parent.trim_end_matches('/'), name);
    validate_path(&path)?;
    Ok(path)
}
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        Err(Error::Refused("Invalid or unsupported path".into()))
    } else {
        Ok(())
    }
}

/// Parent of an absolute SFTP path, including a file directly in /.
pub fn remote_parent(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((parent, _)) => parent,
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    #[test]
    fn filesystem_guidance_uses_status_not_untrusted_server_text() {
        let error = Error::Sftp(russh_sftp::client::error::Error::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: russh_sftp::protocol::StatusCode::PermissionDenied,
                error_message: "server\u{202e} spoofed instructions".into(),
                language_tag: String::new(),
            },
        ));
        assert!(error.user_message().contains("permission denied"));
        assert!(!error.user_message().contains("spoofed"));
        assert!(Error::Io(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .user_message()
            .contains("full"));
    }
}
