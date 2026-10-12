//! The only door to the operating system. Everything else in this crate
//! takes a `&dyn System`, so the hotspot logic is tested against a scripted
//! fake and never needs a radio, root or NetworkManager.
//!
//! Programs are started by name through `lablink_core::program::command`
//! (trusted `$PATH` directories only), with structured arguments (no shell)
//! and `LC_ALL=C` so their output is parseable. A secret is only ever passed
//! on stdin; programs that echo stdin get `discard_stdout`, so the secret
//! never comes back into LabLink, and their stderr is scrubbed of it.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The operating system family, for capability reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Macos,
    Other,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Other
        }
    }
}

/// One program run.
#[derive(Debug, Clone)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
    /// Written to the program's stdin, then stdin is closed. The only way a
    /// secret leaves LabLink.
    pub stdin: Option<String>,
    /// The secret inside `stdin`, scrubbed from anything the program
    /// prints back.
    pub secret: Option<String>,
    /// Send stdout to /dev/null (for programs that echo their input).
    pub discard_stdout: bool,
    pub timeout: Duration,
}

impl Cmd {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            stdin: None,
            secret: None,
            discard_stdout: false,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// `program arg arg ...`, for messages and the fake. Never contains a
    /// secret, because secrets never go into arguments.
    pub fn line(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }

    pub fn success(stdout: &str) -> Self {
        Self {
            code: Some(0),
            stdout: stdout.into(),
            ..Self::default()
        }
    }

    pub fn failure(code: i32, stderr: &str) -> Self {
        Self {
            code: Some(code),
            stderr: stderr.into(),
            ..Self::default()
        }
    }

    /// The first useful line of stderr (or stdout), for an error message.
    pub fn reason(&self) -> String {
        if self.timed_out {
            return "timed out".into();
        }
        let pick = |s: &str| {
            s.lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map(str::to_string)
        };
        pick(&self.stderr)
            .or_else(|| pick(&self.stdout))
            .unwrap_or_else(|| match self.code {
                Some(c) => format!("exit status {c}"),
                None => "killed by a signal".into(),
            })
    }
}

pub trait System: Send + Sync {
    fn os(&self) -> Os;
    fn run(&self, cmd: &Cmd) -> io::Result<Output>;
    fn read_file(&self, path: &Path) -> Option<String>;
    /// File names in a directory (`NotFound` when it does not exist).
    fn list_dir(&self, path: &Path) -> io::Result<Vec<String>>;
    fn env(&self, key: &str) -> Option<String>;
    /// Cryptographically secure random bytes.
    fn random(&self, buf: &mut [u8]) -> io::Result<()>;
    /// Whether stdin and stdout are a terminal (for confirmations).
    fn interactive(&self) -> bool;
    /// The login name of the user running LabLink, if it is a plain name.
    fn username(&self) -> Option<String>;
}

/// Replace every occurrence of `secret` in `text`.
pub fn redact(text: &str, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() => text.replace(s, "<redacted>"),
        _ => text.to_string(),
    }
}

/// The real operating system.
pub struct RealSystem;

/// Debug builds only: end-to-end tests of the binary point `/proc` reads
/// (`LABLINK_TEST_PROC_ROOT`) and `/etc` reads (`LABLINK_TEST_ETC_ROOT`) at
/// fixture directories, so this machine's own connections (an SSH session
/// into the build host) and configuration cannot change their outcome.
/// Release builds always read the real paths.
fn fixture_path(path: &Path) -> std::path::PathBuf {
    #[cfg(debug_assertions)]
    for (var, prefix) in [
        ("LABLINK_TEST_PROC_ROOT", "/proc"),
        ("LABLINK_TEST_ETC_ROOT", "/etc"),
    ] {
        if let (Some(root), Ok(rest)) = (std::env::var_os(var), path.strip_prefix(prefix)) {
            return Path::new(&root).join(rest);
        }
    }
    path.to_path_buf()
}

impl System for RealSystem {
    fn os(&self) -> Os {
        Os::current()
    }

    fn run(&self, c: &Cmd) -> io::Result<Output> {
        let mut cmd = lablink_core::program::command(&c.program)?;
        cmd.args(&c.args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(if c.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(if c.discard_stdout {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        if let (Some(text), Some(mut stdin)) = (c.stdin.clone(), child.stdin.take()) {
            // A thread, so a program that does not read cannot block us
            // past the timeout. Dropping `stdin` closes it.
            std::thread::spawn(move || {
                let _ = stdin.write_all(text.as_bytes());
            });
        }
        let read = |pipe: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut p) = pipe {
                    let _ = p.by_ref().take(1 << 20).read_to_end(&mut buf);
                }
                String::from_utf8_lossy(&buf).into_owned()
            })
        };
        let out_h = read(
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );
        let err_h = read(
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        );
        let deadline = Instant::now() + c.timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break Some(s);
            }
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = redact(&out_h.join().unwrap_or_default(), c.secret.as_deref());
        let stderr = redact(&err_h.join().unwrap_or_default(), c.secret.as_deref());
        Ok(Output {
            code: status.and_then(|s| s.code()),
            stdout,
            stderr,
            timed_out,
        })
    }

    fn read_file(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(fixture_path(path)).ok()
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<String>> {
        let mut v = Vec::new();
        for e in std::fs::read_dir(fixture_path(path))? {
            v.push(e?.file_name().to_string_lossy().into_owned());
        }
        v.sort();
        Ok(v)
    }

    fn env(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn random(&self, buf: &mut [u8]) -> io::Result<()> {
        std::fs::File::open("/dev/urandom")?.read_exact(buf)
    }

    fn interactive(&self) -> bool {
        use std::io::IsTerminal;
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }

    fn username(&self) -> Option<String> {
        lablink_core::paths::username()
    }
}

/// A scripted system for tests: commands are answered by the first rule
/// whose prefix matches `Cmd::line()`; every run is recorded with its
/// stdin, so tests can prove a secret went to stdin and never to argv.
#[derive(Default)]
pub struct FakeSystem {
    pub os_family: Option<Os>,
    rules: Mutex<Vec<(String, Output)>>,
    once: Mutex<Vec<(String, Output)>>,
    files: Mutex<HashMap<PathBuf, String>>,
    vars: Mutex<HashMap<String, String>>,
    calls: Mutex<Vec<Cmd>>,
    counter: Mutex<u8>,
    pub tty: bool,
    pub user: Option<String>,
}

impl FakeSystem {
    pub fn new() -> Self {
        Self {
            os_family: Some(Os::Linux),
            user: Some("tester".into()),
            ..Self::default()
        }
    }

    /// Answer commands starting with `prefix`. Later rules for the same
    /// prefix take precedence (so a test can change the world).
    pub fn on(&self, prefix: &str, out: Output) {
        self.rules
            .lock()
            .unwrap()
            .insert(0, (prefix.to_string(), out));
    }

    pub fn ok(&self, prefix: &str, stdout: &str) {
        self.on(prefix, Output::success(stdout));
    }

    /// Answer only the next command starting with `prefix`, ahead of the
    /// standing rules (so a test can change the world between two calls).
    pub fn once(&self, prefix: &str, stdout: &str) {
        self.once
            .lock()
            .unwrap()
            .push((prefix.to_string(), Output::success(stdout)));
    }

    pub fn file(&self, path: &str, text: &str) {
        self.files.lock().unwrap().insert(path.into(), text.into());
    }

    pub fn set_env(&self, key: &str, value: &str) {
        self.vars.lock().unwrap().insert(key.into(), value.into());
    }

    pub fn clear_env(&self, key: &str) {
        self.vars.lock().unwrap().remove(key);
    }

    pub fn calls(&self) -> Vec<Cmd> {
        self.calls.lock().unwrap().clone()
    }

    pub fn lines(&self) -> Vec<String> {
        self.calls().iter().map(Cmd::line).collect()
    }
}

impl System for FakeSystem {
    fn os(&self) -> Os {
        self.os_family.unwrap_or(Os::Linux)
    }

    fn run(&self, c: &Cmd) -> io::Result<Output> {
        self.calls.lock().unwrap().push(c.clone());
        let line = c.line();
        let once = {
            let mut once = self.once.lock().unwrap();
            once.iter()
                .position(|(p, _)| line.starts_with(p.as_str()))
                .map(|i| once.remove(i))
        };
        let rules = self.rules.lock().unwrap();
        match once.or_else(|| {
            rules
                .iter()
                .find(|(p, _)| line.starts_with(p.as_str()))
                .cloned()
        }) {
            Some((_, out)) => {
                let mut out = out;
                if c.discard_stdout {
                    out.stdout.clear();
                }
                out.stdout = redact(&out.stdout, c.secret.as_deref());
                out.stderr = redact(&out.stderr, c.secret.as_deref());
                Ok(out)
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("not scripted: {line}"),
            )),
        }
    }

    fn read_file(&self, path: &Path) -> Option<String> {
        self.files.lock().unwrap().get(path).cloned()
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<String>> {
        let mut v: Vec<String> = self
            .files
            .lock()
            .unwrap()
            .keys()
            .filter(|p| p.parent() == Some(path))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        if v.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such directory"));
        }
        v.sort();
        Ok(v)
    }

    fn env(&self, key: &str) -> Option<String> {
        self.vars.lock().unwrap().get(key).cloned()
    }

    fn random(&self, buf: &mut [u8]) -> io::Result<()> {
        let mut c = self.counter.lock().unwrap();
        for b in buf {
            *c = c.wrapping_mul(31).wrapping_add(7);
            *b = *c;
        }
        Ok(())
    }

    fn interactive(&self) -> bool {
        self.tty
    }

    fn username(&self) -> Option<String> {
        self.user.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_runs_capture_time_out_and_scrub_the_secret() {
        let s = RealSystem;
        let out = s
            .run(&Cmd::new("sh", &["-c", "echo hi; echo oops >&2"]))
            .unwrap();
        assert!(out.ok());
        assert_eq!(out.stdout.trim(), "hi");
        assert_eq!(out.stderr.trim(), "oops");

        // A program that echoes its input: stdout discarded.
        let mut c = Cmd::new("sh", &["-c", "cat"]);
        c.stdin = Some("set psk TOPSECRET\nquit\n".into());
        c.secret = Some("TOPSECRET".into());
        c.discard_stdout = true;
        let out = s.run(&c).unwrap();
        assert!(out.ok() && out.stdout.is_empty(), "stdout discarded");

        // An error message quoting the input: the secret is scrubbed.
        let mut c = Cmd::new(
            "sh",
            &["-c", "read l; echo \"Error: bad value in: $l\" >&2; exit 1"],
        );
        c.stdin = Some("set psk TOPSECRET\n".into());
        c.secret = Some("TOPSECRET".into());
        let out = s.run(&c).unwrap();
        assert_eq!(out.stderr.trim(), "Error: bad value in: set psk <redacted>");

        let out = s
            .run(&Cmd::new("sleep", &["5"]).timeout(Duration::from_millis(200)))
            .unwrap();
        assert!(out.timed_out && !out.ok());
        assert_eq!(out.reason(), "timed out");
    }

    #[test]
    fn programs_run_under_the_c_locale() {
        let out = RealSystem
            .run(&Cmd::new("sh", &["-c", "echo $LC_ALL"]))
            .unwrap();
        assert_eq!(out.stdout.trim(), "C");
    }

    #[test]
    fn fake_records_and_answers_by_prefix() {
        let f = FakeSystem::new();
        f.ok("nmcli -t", "a");
        f.ok("nmcli -t -f X", "b");
        assert_eq!(
            f.run(&Cmd::new("nmcli", &["-t", "-f", "X"]))
                .unwrap()
                .stdout,
            "b"
        );
        assert_eq!(
            f.run(&Cmd::new("nmcli", &["-t", "-f", "Y"]))
                .unwrap()
                .stdout,
            "a"
        );
        assert!(f.run(&Cmd::new("ip", &[])).is_err());
        assert_eq!(f.lines().len(), 3);
    }
}
