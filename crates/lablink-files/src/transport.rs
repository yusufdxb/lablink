//! OpenSSH owns SSH. russh-sftp only parses the SFTP v3 stream on its pipes.
use crate::{Error, Result};
use lablink_core::{
    client::Client,
    model::{IdentityState, ResolveResult},
    protocol::Request,
};
use lablink_ssh::{build_args, Mode, Target};
use russh_sftp::client::{Config, RawSftpSession};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::{
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct IdentityGuard {
    socket: PathBuf,
    device: String,
    target: Target,
    trust: Vec<u8>,
    refusal: Arc<Mutex<Option<String>>>,
}
impl IdentityGuard {
    pub fn resolve(socket: &Path, device: &str) -> Result<Self> {
        let client = Client::new(socket).with_timeout(Duration::from_secs(3));
        let ping: serde_json::Value = client
            .call_typed(&Request::Ping)
            .map_err(|e| Error::Refused(format!("Files daemon compatibility check failed: {e}")))?;
        if lablink_core::daemon_build_status(&ping) == "different"
            || ping["files_protocol_version"].as_u64()
                != Some(lablink_core::protocol::FILES_PROTOCOL_VERSION as u64)
        {
            return Err(Error::Refused("Files requires a matching LabLink daemon version and Files protocol. Start the matching feature daemon with an isolated development socket and select that socket for this GUI.".into()));
        }
        let r: ResolveResult = client.call_typed(&Request::ResolveFiles {
                device: device.into(),
            })
            .map_err(|e| match &e {
                lablink_core::client::ClientError::Api(api) if api.code == lablink_core::protocol::ErrorCode::BadRequest =>
                    Error::Refused("Files requires a matching LabLink daemon version. Start the matching feature daemon with an isolated development socket and select that socket for this GUI.".into()),
                _ => Error::Refused(format!("Files resolution refused: {e}")),
            })?;
        if r.identity != IdentityState::Verified
            || r.host_key_alias.is_none()
            || r.known_hosts_file.is_none()
        {
            return Err(Error::Refused(
                "Files requires a verified, pinned identity".into(),
            ));
        }
        if r.id.is_empty() || !r.id.contains('/') {
            return Err(Error::Refused(
                "Files daemon returned an invalid site-aware device identity".into(),
            ));
        }
        let target = Target::from_resolve(&r).map_err(Error::Refused)?;
        let trust = trust_digest(&target)?;
        Ok(Self {
            socket: socket.into(),
            device: r.id,
            target,
            trust,
            refusal: Arc::new(Mutex::new(None)),
        })
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn check(&self) -> Result<()> {
        let mut refusal = self.refusal.lock().unwrap();
        if let Some(message) = &*refusal {
            return Err(Error::Refused(message.clone()));
        }
        let result = Self::resolve(&self.socket, &self.device).and_then(|current| {
            if self.target != current.target || self.trust != current.trust {
                return Err(Error::Refused(
                    "Device route or trust changed; reconnect and review the transfer".into(),
                ));
            }
            Ok(())
        });
        if let Err(error) = &result {
            *refusal = Some(error.to_string());
        }
        result
    }
}
fn trust_digest(target: &Target) -> Result<Vec<u8>> {
    let path = target
        .known_hosts_file
        .as_ref()
        .ok_or_else(|| Error::Refused("Missing pinned host keys".into()))?;
    // Hash the complete private trust file, including gateway pins. Never log it.
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > 4 * 1024 * 1024 {
        return Err(Error::Refused("Trust file exceeds safety limit".into()));
    }
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut data)?;
    if data.len() > 4 * 1024 * 1024 {
        return Err(Error::Refused("Trust file exceeds safety limit".into()));
    }
    Ok(Sha256::digest(&data).to_vec())
}

struct Pipes {
    input: ChildStdin,
    output: ChildStdout,
}
impl AsyncRead for Pipes {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.output).poll_read(cx, buf)
    }
}
impl AsyncWrite for Pipes {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.input).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.input).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.input).poll_shutdown(cx)
    }
}

/// Session diagnostics, never an ownership capability or permission to delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteStageState {
    CreationUnconfirmed,
    Created,
    PublicationRequested,
    Published,
    PublicationUncertain,
}
impl RemoteStageState {
    pub fn diagnostic(self) -> &'static str {
        match self {
            Self::CreationUnconfirmed => "Remote staging creation unconfirmed; path may be absent or unrelated. No cleanup attempted; never delete by name or prefix.",
            Self::Created => "Remote staging creation acknowledged; partial or verified data may remain. No ownership-safe SFTP cleanup primitive; no cleanup attempted.",
            Self::PublicationRequested | Self::PublicationUncertain => "Remote publication outcome uncertain; staging and destination may remain. Inspect both before retrying; no cleanup attempted.",
            Self::Published => "Remote publication acknowledged; staging hardlink retained. It may alias the published file; no ownership-safe SFTP cleanup primitive; no cleanup attempted.",
        }
    }
}
#[derive(Clone, Debug)]
pub struct RemoteStage {
    pub path: String,
    pub state: RemoteStageState,
}

pub struct Connection {
    pub sftp: RawSftpSession,
    child: Child,
    diagnostic: Arc<Mutex<Vec<u8>>>,
    stderr_task: tokio::task::JoinHandle<()>,
    pub hardlink: bool,
    pub fsync: bool,
    staging: Mutex<Vec<RemoteStage>>,
}
impl Connection {
    pub async fn connect(target: &Target, cancel: &CancellationToken) -> Result<Self> {
        if target.host_key_alias.is_none() || target.known_hosts_file.is_none() {
            return Err(Error::Refused("Files requires pinned host keys".into()));
        }
        let mut command = Command::from(lablink_core::program::command(&target.binary)?);
        command
            .args(build_args(target, &Mode::Sftp, &[]))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Kill the whole private process group, including a gateway ProxyCommand.
        command.as_std_mut().process_group(0);
        let mut child = command.spawn()?;
        let pipes = Pipes {
            input: child.stdin.take().unwrap(),
            output: child.stdout.take().unwrap(),
        };
        let mut stderr = child.stderr.take().unwrap();
        let diagnostic = Arc::new(Mutex::new(Vec::new()));
        let captured = diagnostic.clone();
        let stderr_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = stderr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut data = captured.lock().unwrap();
                let take = n.min(8192usize.saturating_sub(data.len()));
                data.extend_from_slice(&buf[..take]);
            }
        });
        let sftp = RawSftpSession::new_with_config(
            pipes,
            Config {
                max_packet_len: 256 * 1024,
                max_concurrent_reads: 1,
                max_concurrent_writes: 1,
                request_timeout_secs: 10,
                ..Config::default()
            },
        );
        let mut connection = Self {
            sftp,
            child,
            diagnostic,
            stderr_task,
            hardlink: false,
            fsync: false,
            staging: Mutex::new(Vec::new()),
        };
        let init = tokio::select! {
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            result = tokio::time::timeout(Duration::from_secs(target.connect_timeout_s.saturating_add(12)), connection.sftp.init()) => result,
        };
        match init {
            Ok(Ok(version)) if version.version == 3 => {
                connection.hardlink = version
                    .extensions
                    .get("hardlink@openssh.com")
                    .is_some_and(|v| v == "1");
                connection.fsync = version
                    .extensions
                    .get("fsync@openssh.com")
                    .is_some_and(|v| v == "1");
                Ok(connection)
            }
            _ => Err(connection.connection_error()),
        }
    }
    pub fn process_id(&self) -> Option<u32> {
        self.child.id()
    }
    /// Close the private SSH transport immediately. Existing requests fail.
    pub fn abort(&self) {
        let _ = self.sftp.close_session();
        if let Some(pid) = self.child.id() {
            // SAFETY: only the process group created for this connection.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
    /// SFTP v3 cannot prove inode ownership for pathname deletion. Retain even
    /// acknowledged creations; never unlink a staging candidate by name.
    pub async fn cleanup(&self) { /* Deliberately no remote REMOVE requests. */
    }
    /// Record before OPEN is sent: a lost reply cannot prove creation failed.
    pub(crate) fn plan_stage(&self, path: &str) {
        self.staging.lock().unwrap().push(RemoteStage {
            path: path.into(),
            state: RemoteStageState::CreationUnconfirmed,
        });
    }
    pub(crate) fn stage_state(&self, path: &str, state: RemoteStageState) {
        if let Some(stage) = self
            .staging
            .lock()
            .unwrap()
            .iter_mut()
            .find(|s| s.path == path)
        {
            stage.state = state;
        }
    }
    pub fn stage_diagnostics(&self) -> Vec<RemoteStage> {
        self.staging.lock().unwrap().clone()
    }
    pub fn retained_stages(&self) -> Vec<String> {
        self.staging
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.state != RemoteStageState::CreationUnconfirmed)
            .map(|s| s.path.clone())
            .collect()
    }
    fn connection_error(&self) -> Error {
        let data = self.diagnostic.lock().unwrap();
        let text = String::from_utf8_lossy(&data).to_lowercase();
        // Classify locally; never display arbitrary ssh output/config/credentials.
        let msg = if text.contains("host key verification failed")
            || text.contains("host identification has changed")
        {
            "SSH host-key verification failed. Connection refused; review LabLink identity."
        } else if text.contains("subsystem request failed") {
            "Unsupported server: SFTP subsystem is unavailable. Ask the server administrator to enable SFTP."
        } else if text.contains("permission denied") {
            "SSH authentication failed. Configure the existing OpenSSH key or agent; Files cannot prompt for passwords."
        } else {
            "SFTP connection failed or timed out. Check device connectivity, authentication, and SFTP availability."
        };
        Error::Refused(msg.into())
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.abort();
        let _ = self.child.start_kill();
        // Reap promptly even when the current-thread runtime is about to end.
        // This runs only on background workers, never on the GUI thread.
        for _ in 0..100 {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        self.stderr_task.abort();
    }
}

/// Revalidate throughout long copies, including conflict waits and stalled I/O.
pub async fn guarded<T>(
    guard: Option<IdentityGuard>,
    cancel: &CancellationToken,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::pin!(operation);
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            _ = interval.tick(), if guard.is_some() => {
                let copy = guard.clone().unwrap();
                let check = tokio::task::spawn_blocking(move || copy.check());
                tokio::select! {
                    _ = cancel.cancelled() => return Err(Error::Cancelled),
                    result = check => result.map_err(|_| Error::Refused("Identity monitor stopped".into()))??,
                }
                // A valid but slow daemon can take longer than the period.
                // With biased select, accumulated interval ticks would keep
                // winning and prevent the transfer future from being polled.
                // Preserve refusal/cancellation precedence, then allow useful
                // work until the next check rather than catching up ticks.
                interval.reset();
            },
            result = &mut operation => return result,
        }
    }
}
