//! Running OpenSSH tools with timeouts, output capture and exit-code fidelity.

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};
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
    /// Live stdin/stdout/stderr, retaining stderr for failure advice.
    InheritAndCaptureStderr,
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
    reader_with_tee(r, false)
}

fn reader_with_tee<R: Read + Send + 'static>(
    r: Option<R>,
    tee_stderr: bool,
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
                    if tee_stderr {
                        let _ = std::io::stderr().lock().write_all(&buf[..n]);
                    }
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

static SIGNAL_RUN: Mutex<()> = Mutex::new(());
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn interrupted(sig: libc::c_int) {
    // Only an atomic operation in the signal handler. Cleanup happens in
    // the polling thread, which still owns the child's unreaped PID.
    let _ = INTERRUPTED.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
}

struct SignalHandlers {
    previous: [(i32, libc::sigaction); 2],
    _lock: MutexGuard<'static, ()>,
}

impl SignalHandlers {
    fn install() -> std::io::Result<Self> {
        let lock = SIGNAL_RUN.lock().unwrap_or_else(|e| e.into_inner());
        INTERRUPTED.store(0, Ordering::SeqCst);
        // SAFETY: zero is a valid initial sigaction; initialize its mask
        // and give sigaction valid pointers to saved/replacement actions.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupted as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous = [
                (libc::SIGINT, std::mem::zeroed()),
                (libc::SIGTERM, std::mem::zeroed()),
            ];
            for i in 0..previous.len() {
                if libc::sigaction(previous[i].0, &action, &mut previous[i].1) != 0 {
                    let error = std::io::Error::last_os_error();
                    for (sig, saved) in previous.iter().take(i) {
                        libc::sigaction(*sig, saved, std::ptr::null_mut());
                    }
                    return Err(error);
                }
            }
            Ok(Self {
                previous,
                _lock: lock,
            })
        }
    }
}

impl Drop for SignalHandlers {
    fn drop(&mut self) {
        for (sig, action) in &self.previous {
            // SAFETY: these are the exact actions saved at installation.
            unsafe {
                libc::sigaction(*sig, action, std::ptr::null_mut());
            }
        }
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
    run_inner(binary, args, timeout, output, own_group, false)
}

/// Run a foreground CLI command and forward SIGINT/SIGTERM to its child.
/// Temporary handlers are restored before returning. Background daemon
/// checks use `run_captured`, since signal dispositions are process-wide.
pub fn run_captured_interruptible(
    binary: &str,
    args: &[String],
    timeout: Duration,
    output: OutputMode,
    own_group: bool,
) -> std::io::Result<ExecOutput> {
    run_inner(binary, args, timeout, output, own_group, true)
}

fn run_inner(
    binary: &str,
    args: &[String],
    timeout: Duration,
    output: OutputMode,
    own_group: bool,
    interruptible: bool,
) -> std::io::Result<ExecOutput> {
    let _signals = interruptible.then(SignalHandlers::install).transpose()?;
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
        OutputMode::InheritAndCaptureStderr => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::piped());
        }
    }
    if own_group {
        cmd.process_group(0);
    }
    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let out_h = reader(child.stdout.take());
    let err_h = reader_with_tee(
        child.stderr.take(),
        output == OutputMode::InheritAndCaptureStderr,
    );

    let deadline = start + timeout;
    let mut timed_out = false;
    let mut signal = None;
    let status = loop {
        let now = Instant::now();
        let received = if interruptible {
            INTERRUPTED.load(Ordering::SeqCst)
        } else {
            0
        };
        if received == 0 {
            if let Some(s) = child.try_wait()? {
                // A foreground child may exit on the same terminal signal
                // before our next poll. Preserve the caller's signal status.
                if interruptible {
                    let received = INTERRUPTED.load(Ordering::SeqCst);
                    signal = (received != 0).then_some(received);
                }
                break s;
            }
        }
        if received != 0 || now >= deadline {
            timed_out = received == 0;
            signal = (received != 0).then_some(received);
            kill(pid, own_group, signal.unwrap_or(libc::SIGTERM));
            // Keep the leader unreaped through cleanup, so its PID cannot
            // be reused while a surviving descendant still holds a pipe.
            std::thread::sleep(Duration::from_millis(500));
            kill(pid, own_group, libc::SIGKILL);
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
    if interruptible && signal.is_none() {
        // A signal can also arrive while draining the bounded captures,
        // after the child has exited. It still determines the CLI's status.
        let received = INTERRUPTED.load(Ordering::SeqCst);
        signal = (received != 0).then_some(received);
    }
    Ok(ExecOutput {
        exit_code: if signal.is_some() {
            None
        } else {
            status.code()
        },
        signal: signal.or_else(|| status.signal()),
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
