//! Blocking IPC client used by the CLI and the GUI. No async runtime needed.

use crate::protocol::{ApiError, Request, Response, MAX_RESPONSE_BYTES};
use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Errors talking to the daemon.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The daemon is not running or the socket is not accessible.
    #[error("lablinkd is not reachable at {path}: {source}")]
    Unavailable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The daemon answered with something unexpected, or timed out.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The daemon returned an error.
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// Accept only a daemon running as `own` (pure, for tests).
fn check_peer(path: &Path, peer: Option<u32>, own: u32) -> Result<(), ClientError> {
    match peer {
        Some(uid) if uid == own => Ok(()),
        Some(uid) => Err(ClientError::Protocol(format!(
            "refusing to talk to {}: it is served by uid {uid}, not by this user",
            path.display()
        ))),
        None => Err(ClientError::Protocol(format!(
            "cannot verify who serves {}",
            path.display()
        ))),
    }
}

fn own_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// UID of the process at the other end of a connected Unix socket.
fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid fd, and `cred`/`len` describe a writable ucred.
        let rc = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: valid fd and out-pointers.
        let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }
}

/// A connection factory for the daemon socket.
#[derive(Debug, Clone)]
pub struct Client {
    path: PathBuf,
    timeout: Duration,
}

impl Client {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            timeout: Duration::from_secs(15),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    /// Send one request and return the raw `result` value.
    pub fn call(&self, req: &Request) -> Result<serde_json::Value, ClientError> {
        let stream =
            UnixStream::connect(&self.path).map_err(|source| ClientError::Unavailable {
                path: self.path.display().to_string(),
                source,
            })?;
        // The daemon decides which ssh binary and options the CLI runs, so
        // only a daemon running as this user is believed. Without this, a
        // process of another user listening at the socket path (possible
        // when the fallback /tmp location is used) could make the CLI
        // execute programs of its choosing.
        check_peer(&self.path, peer_uid(&stream), own_uid())?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let mut line = serde_json::to_vec(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        line.push(b'\n');
        (&stream)
            .write_all(&line)
            .map_err(|e| ClientError::Protocol(format!("write: {e}")))?;

        let mut reader = BufReader::new((&stream).take(MAX_RESPONSE_BYTES as u64 + 1));
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ClientError::Protocol(
                format!("no response from lablinkd within {:?}", self.timeout),
            ),
            _ => ClientError::Protocol(format!("read: {e}")),
        })?;
        if n == 0 {
            return Err(ClientError::Protocol("daemon closed the connection".into()));
        }
        if n > MAX_RESPONSE_BYTES {
            return Err(ClientError::Protocol("response too large".into()));
        }
        let resp: Response = serde_json::from_str(buf.trim_end())
            .map_err(|e| ClientError::Protocol(format!("bad response: {e}")))?;
        match (resp.ok, resp.result, resp.error) {
            (true, Some(v), _) => Ok(v),
            (true, None, _) => Ok(serde_json::Value::Null),
            (false, _, Some(e)) => Err(ClientError::Api(e)),
            (false, _, None) => Err(ClientError::Protocol(
                "error response without details".into(),
            )),
        }
    }

    /// Send one request and decode the result into `T`.
    pub fn call_typed<T: DeserializeOwned>(&self, req: &Request) -> Result<T, ClientError> {
        let v = self.call(req)?;
        serde_json::from_value(v)
            .map_err(|e| ClientError::Protocol(format!("unexpected result shape: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_daemon_of_this_user_is_believed() {
        let p = Path::new("/tmp/lablink-1000/lablinkd.sock");
        assert!(check_peer(p, Some(1000), 1000).is_ok());
        let e = check_peer(p, Some(1001), 1000).unwrap_err().to_string();
        assert!(e.contains("served by uid 1001"), "{e}");
        assert!(check_peer(p, None, 1000).is_err());
    }

    #[test]
    fn peer_uid_of_a_local_socket_is_ours() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let c = UnixStream::connect(&sock).unwrap();
        let _ = l.accept().unwrap();
        assert_eq!(peer_uid(&c), Some(own_uid()));
    }
}
