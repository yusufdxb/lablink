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
