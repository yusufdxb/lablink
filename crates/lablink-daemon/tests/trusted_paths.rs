//! [localhost] lablinkd refuses a state directory (the pins) or a
//! configuration (the programs it runs) that another user could have written.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Run lablinkd; if it is still running after `secs`, stop it (it accepted
/// the paths) and return None.
fn daemon(root: &Path, args: &[&str], secs: u64) -> Option<Output> {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lablinkd"))
        .args(["--no-netlink", "--no-mdns", "--no-startup-discovery"])
        .arg("--socket")
        .arg(root.join("run/lablinkd.sock"))
        .args(args)
        .env("LABLINK_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if c.try_wait().unwrap().is_some() {
            return Some(c.wait_with_output().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = c.kill();
    let _ = c.wait();
    None
}

#[test]
fn a_state_dir_others_can_rearrange_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    chmod(&cfg, 0o600);
    let shared = t.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    // Anyone could rename `lablink` away and put their own pins there.
    chmod(&shared, 0o777);
    let state = shared.join("lablink");
    let cfg_s = cfg.to_str().unwrap();
    let out = daemon(
        t.path(),
        &["--config", cfg_s, "--state-dir", state.to_str().unwrap()],
        10,
    )
    .expect("lablinkd must refuse the state dir");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("writable by every user"), "{err}");
    assert!(!state.join("known_hosts").exists());

    // A sticky shared directory is fine (only the owner can replace a
    // file there), and so is a private one: the daemon starts.
    chmod(&shared, 0o1777);
    assert!(daemon(
        t.path(),
        &["--config", cfg_s, "--state-dir", state.to_str().unwrap()],
        2
    )
    .is_none());
}

#[test]
fn a_configuration_others_can_change_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("config.yaml");
    std::fs::write(&cfg, "ssh:\n  binary: /bin/true\n").unwrap();
    chmod(&cfg, 0o666);
    let out = daemon(
        t.path(),
        &["--config", cfg.to_str().unwrap(), "--check-config"],
        10,
    )
    .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("refusing a configuration other users can change"),
        "{err}"
    );
    // Owner-only and world-readable files are fine.
    chmod(&cfg, 0o644);
    let out = daemon(
        t.path(),
        &["--config", cfg.to_str().unwrap(), "--check-config"],
        10,
    )
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_shared_state_dir_is_refused_without_chmod_or_trusting_its_contents() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    chmod(&cfg, 0o600);
    let state = t.path().join("state");
    std::fs::create_dir(&state).unwrap();
    chmod(&state, 0o777);
    let planted = state.join("cache.db");
    std::fs::write(&planted, "untrusted pins").unwrap();
    let out = daemon(
        t.path(),
        &[
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ],
        5,
    )
    .expect("shared state must be refused");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("mode 0700"));
    assert_eq!(
        std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o777
    );
    assert_eq!(std::fs::read_to_string(planted).unwrap(), "untrusted pins");
}

#[test]
fn a_link_to_a_cache_in_a_private_state_dir_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    chmod(&cfg, 0o600);
    let state = t.path().join("state");
    std::fs::create_dir(&state).unwrap();
    chmod(&state, 0o700);
    let victim = t.path().join("victim");
    std::fs::write(&victim, "do not overwrite").unwrap();
    std::os::unix::fs::symlink(&victim, state.join("cache.db")).unwrap();
    let out = daemon(
        t.path(),
        &[
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ],
        5,
    )
    .expect("linked cache must be refused");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("regular file owned by you"));
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "do not overwrite");
}

#[test]
fn a_hard_linked_journal_in_a_private_state_dir_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let cfg = t.path().join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    chmod(&cfg, 0o600);
    let state = t.path().join("state");
    std::fs::create_dir(&state).unwrap();
    chmod(&state, 0o700);
    let victim = t.path().join("victim");
    std::fs::write(&victim, "do not truncate").unwrap();
    std::fs::hard_link(&victim, state.join("cache.db-wal")).unwrap();
    let out = daemon(
        t.path(),
        &[
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ],
        5,
    )
    .expect("hard-linked journal must be refused");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no other links"));
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "do not truncate");
}

/// A configuration that cannot be resolved to a file, here `/dev/stdin` on a
/// pipe, is refused rather than read unchecked.
#[test]
fn a_configuration_on_a_pipe_is_refused() {
    use std::io::Write;
    let t = tempfile::tempdir().unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_lablinkd"))
        .args(["--no-netlink", "--no-mdns", "--no-startup-discovery"])
        .arg("--socket")
        .arg(t.path().join("run/lablinkd.sock"))
        .args(["--config", "/dev/stdin", "--check-config"])
        .env("LABLINK_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A valid configuration, so only the path decides.
    let _ = c
        .stdin
        .take()
        .unwrap()
        .write_all(b"ssh:\n  binary: /bin/true\n");
    let out = c.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("refusing the configuration: cannot check /dev/stdin"),
        "{err}"
    );
}

fn private_state(t: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let cfg = t.join("config.yaml");
    std::fs::write(&cfg, "").unwrap();
    chmod(&cfg, 0o600);
    let state = t.join("state");
    std::fs::create_dir(&state).unwrap();
    chmod(&state, 0o700);
    (cfg, state)
}

/// 0.3.x created the lock with the umask's mode (0664 under umask 002); on a
/// host whose group cannot be proven private (nsswitch lists `sss`) every
/// later release refused to start. The lock holds no data: it is tightened.
#[test]
fn a_lock_file_others_could_write_is_tightened_not_refused() {
    let t = tempfile::tempdir().unwrap();
    let (cfg, state) = private_state(t.path());
    let lock = state.join("lablinkd.lock");
    std::fs::write(&lock, "").unwrap();
    chmod(&lock, 0o666);
    let out = daemon(
        t.path(),
        &[
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ],
        3,
    );
    assert!(out.is_none(), "daemon must start: {out:?}");
    let mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_new_lock_file_is_private_whatever_the_umask() {
    use std::os::unix::process::CommandExt;
    let t = tempfile::tempdir().unwrap();
    let (cfg, state) = private_state(t.path());
    let mut c = Command::new(env!("CARGO_BIN_EXE_lablinkd"));
    c.args([
        "--no-netlink",
        "--no-mdns",
        "--no-startup-discovery",
        "--socket",
    ])
    .arg(t.path().join("run/lablinkd.sock"))
    .args([
        "--config",
        cfg.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
    ])
    .env("LABLINK_LOG", "warn")
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    // SAFETY: umask is async-signal-safe and has no preconditions.
    unsafe {
        c.pre_exec(|| {
            libc::umask(0o002);
            Ok(())
        });
    }
    let mut child = c.spawn().unwrap();
    let lock = state.join("lablinkd.lock");
    let end = Instant::now() + Duration::from_secs(5);
    while !lock.exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let mode = std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_linked_lock_file_is_still_refused() {
    let t = tempfile::tempdir().unwrap();
    let (cfg, state) = private_state(t.path());
    let victim = t.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    chmod(&victim, 0o644);
    std::os::unix::fs::symlink(&victim, state.join("lablinkd.lock")).unwrap();
    let out = daemon(
        t.path(),
        &[
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
        ],
        5,
    )
    .expect("linked lock must be refused");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("regular file owned by you"));
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
