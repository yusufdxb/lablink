//! Running OpenSSH tools with timeouts, output capture and exit-code fidelity.

use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Per-stream capture limit; output beyond this is discarded and flagged.
pub const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// What to do with the child's stdout/stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Capture both streams into memory.
    Capture,
    /// Inherit the parent's streams (live output for humans).
    Inherit,
}

/// Result of a finished (or killed) child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit code if the process exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub duration: Duration,
}

pub(crate) fn reader<R: Read + Send + 'static>(
    r: Option<R>,
) -> Option<std::thread::JoinHandle<(Vec<u8>, bool)>> {
    let mut r = r?;
    Some(std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_CAPTURE_BYTES.saturating_sub(out.len());
                    if n > room {
                        truncated = true;
                    }
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        (out, truncated)
    }))
}

fn kill(pid: u32, group: bool, sig: i32) {
    let target = if group { -(pid as i32) } else { pid as i32 };
    // SAFETY: sending a signal has no memory-safety preconditions.
    unsafe {
        libc::kill(target, sig);
    }
}

/// Run `binary args...` with a timeout. With `own_group`, the child runs in a
/// new process group so a timeout kills ssh and anything it spawned (do not
/// use for commands that must read a password from the controlling terminal).
pub fn run_captured(
    binary: &str,
    args: &[String],
    timeout: Duration,
    output: OutputMode,
    own_group: bool,
) -> std::io::Result<ExecOutput> {
    let mut cmd = lablink_core::program::command(binary)?;
    cmd.args(args);
    match output {
        OutputMode::Capture => {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        OutputMode::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }
    if own_group {
        cmd.process_group(0);
    }
    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let out_h = reader(child.stdout.take());
    let err_h = reader(child.stderr.take());

    let deadline = start + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            kill(pid, own_group, libc::SIGTERM);
            let grace = Instant::now() + Duration::from_millis(500);
            loop {
                if child.try_wait()?.is_some() {
                    break;
                }
                if Instant::now() >= grace {
                    kill(pid, own_group, libc::SIGKILL);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            break child.wait()?;
        }
        // Short sleep while the child runs; the poll stops when it exits.
        std::thread::sleep((deadline - now).min(Duration::from_millis(10)));
    };
    let duration = start.elapsed();

    let join = |h: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>| -> (Vec<u8>, bool) {
        let Some(h) = h else {
            return (Vec::new(), false);
        };
        // A grandchild holding the pipe open must not hang us forever.
        let limit = Instant::now() + Duration::from_secs(1);
        while !h.is_finished() && Instant::now() < limit {
            std::thread::sleep(Duration::from_millis(5));
        }
        if h.is_finished() {
            h.join().unwrap_or_default()
        } else {
            (Vec::new(), true)
        }
    };
    let (stdout, stdout_truncated) = join(out_h);
    let (stderr, stderr_truncated) = join(err_h);
    Ok(ExecOutput {
        exit_code: status.code(),
        signal: status.signal(),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
        duration,
    })
}

/// Why an ssh invocation failed, from its stderr (exit status 255).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshFailure {
    /// The server rejected authentication. `password_only` when the server
    /// offers nothing LabLink can use non-interactively.
    AuthFailed {
        password_only: bool,
    },
    /// The presented host key differs from the known one.
    HostKeyChanged,
    /// No known host key (first contact, or unpinned under BatchMode).
    HostKeyUnknown,
    ConnectionRefused,
    Timeout,
    NoRoute,
    ResolveFailed,
    Other(String),
}

impl SshFailure {
    pub fn describe(&self) -> String {
        match self {
            SshFailure::AuthFailed { password_only: true } => {
                "server only accepts password authentication; LabLink never stores passwords (install a key, or open a ControlMaster session with `lablink ssh`)".into()
            }
            SshFailure::AuthFailed { password_only: false } => "authentication failed (keys/agent rejected)".into(),
            SshFailure::HostKeyChanged => "host key verification failed: key CHANGED".into(),
            SshFailure::HostKeyUnknown => "host key verification failed: key not known".into(),
            SshFailure::ConnectionRefused => "connection refused".into(),
            SshFailure::Timeout => "connection timed out".into(),
            SshFailure::NoRoute => "no route to host".into(),
            SshFailure::ResolveFailed => "could not resolve host".into(),
            SshFailure::Other(s) => s.clone(),
        }
    }

    /// The safest next step for `device`, in one sentence.
    pub fn advice(&self, device: &str) -> String {
        match self {
            SshFailure::AuthFailed { .. } => format!(
                "the device is reachable but did not accept your SSH key: install it with `lablink copy-id {device}` (you type the password once; LabLink never stores it), or set the right user with `lablink set {device} --user NAME`"
            ),
            SshFailure::HostKeyChanged => format!(
                "SECURITY STOP: do not connect. Check the host key on the device's console; only if it legitimately changed run `lablink trust {device} --replace`"
            ),
            SshFailure::HostKeyUnknown => format!(
                "the host key is not trusted yet: compare and pin it with `lablink trust {device}`"
            ),
            SshFailure::ConnectionRefused => format!(
                "the SSH server is not running on {device} (on the device: `sudo systemctl enable --now ssh`)"
            ),
            SshFailure::Timeout | SshFailure::NoRoute => format!(
                "{device} did not answer; check power and network, then `lablink status {device}`"
            ),
            SshFailure::ResolveFailed | SshFailure::Other(_) => {
                format!("see `lablink status {device}` for what LabLink currently knows")
            }
        }
    }
}

/// Result of a host-key possession check ([`crate::Mode::KeyProof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProof {
    /// The host completed the key exchange with the pinned key.
    Proven,
    /// The host presented another key, or could not sign with the pinned one.
    Refused(String),
    /// No answer either way (timeout, refused, network): try again later.
    Inconclusive(String),
}

/// Text OpenSSH prints when the server ended the connection or sent text of
/// its own (OpenSSH before 9.0 prints disconnect reasons and algorithm
/// offers with newlines unescaped, so a server can forge whole lines).
const SERVER_TEXT_MARKERS: &[&str] = &[
    "Received disconnect",
    "Disconnected from",
    "Connection closed",
    "Connection reset",
    "kex_exchange_identification",
    "banner",
    "protocol version",
    "Protocol major versions",
    "Unable to negotiate",
    "Their offer",
];

/// Explain a [`crate::Mode::KeyProof`] run that did not prove possession
/// (see [`crate::prove_host_key`]), from ssh's stderr at `LogLevel=INFO`.
/// Never returns [`KeyProof::Proven`]: possession is decided only from the
/// bytes ssh sent, never from text. Server text is not trusted to explain
/// anything either: any sign of it makes the result inconclusive.
pub(crate) fn classify_unproven(stderr: &str, timed_out: bool) -> KeyProof {
    if timed_out {
        return KeyProof::Inconclusive("timed out".into());
    }
    if let Some(m) = SERVER_TEXT_MARKERS.iter().find(|m| stderr.contains(*m)) {
        return KeyProof::Inconclusive(format!("the server closed the connection ({m})"));
    }
    if stderr.contains("incorrect signature")
        || stderr.contains("signature verification failed")
        || stderr.contains("error in libcrypto")
    {
        return KeyProof::Refused("it could not sign with the pinned key".into());
    }
    match classify_ssh_failure(stderr) {
        SshFailure::HostKeyChanged => {
            KeyProof::Refused("it presented a different key of a pinned type".into())
        }
        // No key of the offered type is pinned: says nothing about the
        // device (the scan comparison catches contradicting keys).
        SshFailure::HostKeyUnknown => {
            KeyProof::Inconclusive("the host offered no key of a pinned type".into())
        }
        SshFailure::AuthFailed { .. } => {
            KeyProof::Inconclusive("authentication output without a completed key exchange".into())
        }
        f => KeyProof::Inconclusive(f.describe()),
    }
}

/// Classify an ssh client failure from its stderr.
pub fn classify_ssh_failure(stderr: &str) -> SshFailure {
    let s = stderr;
    if let Some(i) = s.find("Permission denied") {
        let methods = s[i..]
            .split_once('(')
            .and_then(|(_, r)| r.split_once(')'))
            .map(|(m, _)| m.to_string())
            .unwrap_or_default();
        let password_only = !methods.is_empty()
            && methods
                .split(',')
                .all(|m| matches!(m.trim(), "password" | "keyboard-interactive"));
        return SshFailure::AuthFailed { password_only };
    }
    if s.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || s.contains("Host key for") && s.contains("has changed")
    {
        return SshFailure::HostKeyChanged;
    }
    if s.contains("Host key verification failed")
        || s.contains("No ED25519 host key is known")
        || s.contains("host key is known for")
    {
        return SshFailure::HostKeyUnknown;
    }
    if s.contains("Connection refused") {
        return SshFailure::ConnectionRefused;
    }
    if s.contains("timed out") {
        return SshFailure::Timeout;
    }
    if s.contains("No route to host") || s.contains("Network is unreachable") {
        return SshFailure::NoRoute;
    }
    if s.contains("Could not resolve hostname") {
        return SshFailure::ResolveFailed;
    }
    let last = s
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("ssh failed")
        .trim();
    SshFailure::Other(last.chars().take(300).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, timeout_ms: u64) -> ExecOutput {
        run_captured(
            "/bin/sh",
            &["-c".into(), script.into()],
            Duration::from_millis(timeout_ms),
            OutputMode::Capture,
            true,
        )
        .unwrap()
    }

    #[test]
    fn exit_code_preserved() {
        for code in [0, 1, 3, 42, 255] {
            assert_eq!(sh(&format!("exit {code}"), 5000).exit_code, Some(code));
        }
    }

    #[test]
    fn stdout_and_stderr_separate() {
        let o = sh("echo out; echo err >&2; exit 7", 5000);
        assert_eq!(o.stdout, b"out\n");
        assert_eq!(o.stderr, b"err\n");
        assert_eq!(o.exit_code, Some(7));
        assert!(!o.timed_out);
    }

    #[test]
    fn timeout_kills_whole_group() {
        let start = Instant::now();
        // The background sleep would keep the pipe open if not killed with the group.
        let o = sh("sleep 30 & sleep 30", 300);
        assert!(o.timed_out);
        assert_eq!(o.exit_code, None);
        assert_eq!(o.signal, Some(libc::SIGTERM));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn large_output_truncated_not_oom() {
        let o = sh("head -c 20000000 /dev/zero", 20_000);
        assert!(o.stdout_truncated);
        assert_eq!(o.stdout.len(), MAX_CAPTURE_BYTES);
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify_ssh_failure("ops@192.168.10.70: Permission denied (password)."),
            SshFailure::AuthFailed {
                password_only: true
            }
        );
        assert_eq!(
            classify_ssh_failure("x@y: Permission denied (publickey,password)."),
            SshFailure::AuthFailed {
                password_only: false
            }
        );
        assert_eq!(
            classify_ssh_failure("@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed."),
            SshFailure::HostKeyChanged
        );
        assert_eq!(
            classify_ssh_failure("Host key verification failed."),
            SshFailure::HostKeyUnknown
        );
        assert_eq!(
            classify_ssh_failure("ssh: connect to host 1.2.3.4 port 22: Connection refused"),
            SshFailure::ConnectionRefused
        );
        assert_eq!(
            classify_ssh_failure("ssh: connect to host 1.2.3.4 port 22: Connection timed out"),
            SshFailure::Timeout
        );
        assert_eq!(
            classify_ssh_failure("ssh: connect to host 1.2.3.4 port 22: No route to host"),
            SshFailure::NoRoute
        );
        assert!(
            matches!(classify_ssh_failure("weird\n"), SshFailure::Other(ref s) if s == "weird")
        );
    }
    #[test]
    fn text_never_proves_possession() {
        use super::{classify_unproven, KeyProof};
        let p = |err: &str| classify_unproven(err, false);
        // Even OpenSSH's own denial line: without the NEWKEYS that a real
        // key exchange sends first, it can only be server text.
        for forged in [
            "ops@192.168.10.70: Permission denied (publickey,password).\n",
            "Received disconnect from 10.0.0.9 port 22:2: x\nops@192.168.10.70: Permission denied (publickey).\n",
            "Unable to negotiate with 192.168.10.70 port 22: no matching key exchange method found. Their offer: x\nops@192.168.10.70: Permission denied (publickey).\n",
            "Disconnected from 10.0.0.9 port 22\nkex_exchange_identification: Connection closed by remote host\n",
            "Connection closed by 10.0.0.9 port 22\n",
            "Received disconnect from 10.0.0.9 port 22:2: Host key verification failed.\n",
            "",
        ] {
            assert!(matches!(p(forged), KeyProof::Inconclusive(_)), "{forged:?}");
        }
        assert!(matches!(
            p("ssh_dispatch_run_fatal: Connection to UNKNOWN port 65535: incorrect signature\n"),
            KeyProof::Refused(_)
        ));
        assert!(matches!(
            p("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.\n"),
            KeyProof::Refused(_)
        ));
        // Nothing of a pinned type offered (another algorithm list, an
        // empty pin file): not a verdict about the device.
        assert!(matches!(
            p("No ED25519 host key is known for lablink.s.dev and you have requested strict checking.\nHost key verification failed.\n"),
            KeyProof::Inconclusive(_)
        ));
        assert!(matches!(
            classify_unproven("", true),
            KeyProof::Inconclusive(_)
        ));
    }
}
