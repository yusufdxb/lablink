//! Signals are delivered to isolated test subprocesses, never the test runner.
use lablink_ssh::{run_captured_interruptible, OutputMode};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn signal_runner_child() {
    let Some(dir) = std::env::var_os("LABLINK_SIGNAL_CHILD") else {
        return;
    };
    let out = run_captured_interruptible(
        "/bin/sh",
        &[
            "-c".into(),
            "trap '' INT TERM; sleep 30 & echo \"$$ $!\" > \"$1\"; wait".into(),
            "child".into(),
            Path::new(&dir).join("pids").display().to_string(),
        ],
        Duration::from_secs(10),
        OutputMode::Capture,
        true,
    )
    .unwrap();
    assert!(!out.timed_out);
    assert!(out.duration < Duration::from_secs(5));
    std::process::exit(128 + out.signal.expect("signal forwarded"));
}

fn live(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(") ")
            .is_some_and(|(_, fields)| !fields.starts_with('Z'))
    })
}

#[test]
fn signals_to_parent_kill_the_owned_group_and_preserve_status() {
    for sig in [libc::SIGINT, libc::SIGTERM] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "signal_runner_child", "--nocapture"])
            .env("LABLINK_SIGNAL_CHILD", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let marker = dir.path().join("pids");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let pids = std::fs::read_to_string(marker)
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);
        assert!(pids.iter().all(|pid| live(*pid)));
        // SAFETY: signal only the isolated subprocess, whose PID we own.
        assert_eq!(unsafe { libc::kill(child.id() as i32, sig) }, 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("signal cleanup hung");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(128 + sig));
        for pid in pids {
            assert!(!live(pid), "orphan process {pid}");
        }
    }
}

extern "C" fn previous_handler(_: libc::c_int) {}

#[test]
fn restore_runner_child() {
    if std::env::var_os("LABLINK_RESTORE_CHILD").is_none() {
        return;
    }
    // SAFETY: this is an isolated subprocess; sigaction pointers are valid.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = previous_handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        for sig in [libc::SIGINT, libc::SIGTERM] {
            assert_eq!(libc::sigaction(sig, &action, std::ptr::null_mut()), 0);
        }
        for binary in ["/bin/true", "/does/not/exist"] {
            let _ = run_captured_interruptible(
                binary,
                &[],
                Duration::from_secs(1),
                OutputMode::Capture,
                true,
            );
            for sig in [libc::SIGINT, libc::SIGTERM] {
                let mut restored: libc::sigaction = std::mem::zeroed();
                assert_eq!(libc::sigaction(sig, std::ptr::null(), &mut restored), 0);
                assert_eq!(restored.sa_sigaction, action.sa_sigaction);
                assert_eq!(restored.sa_flags & libc::SA_RESTART, libc::SA_RESTART);
            }
        }
    }
    let out = run_captured_interruptible(
        "/bin/sh",
        &["-c".into(), "echo live-out; echo live-err >&2".into()],
        Duration::from_secs(1),
        OutputMode::InheritAndCaptureStderr,
        true,
    )
    .unwrap();
    assert_eq!(out.stderr, b"live-err\n");
    assert!(out.stdout.is_empty());
}

#[test]
fn previous_handlers_are_restored_and_live_stderr_is_captured() {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "restore_runner_child", "--nocapture"])
        .env("LABLINK_RESTORE_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("live-out"));
    assert_eq!(out.stderr, b"live-err\n");
}
