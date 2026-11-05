//! [localhost] Startup is only reported once the daemon answers: the real
//! `lablinkd` binary, started the way a service would start it, judged by
//! `lablink_setup::service::wait_ready` (what `lablink init`, the desktop
//! app's Start button and `lablink install-service` use). The process here
//! stands in for systemd's view of the unit; systemd itself is not involved.

use lablink_core::client::Client;
use lablink_core::protocol::Request;
use lablink_setup::service::{wait_ready, READY_TIMEOUT};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CONFIG: &str = "sites:\n  - id: lab\n    name: Lab\n    networks:\n      - name: lan\n        cidr: 192.168.77.0/24\n        active_scan: false\n    devices:\n      - name: jetson\n        hostnames: [jetson.local]\n";

struct Home {
    _t: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    socket: PathBuf,
}

fn home() -> Home {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().to_path_buf();
    let config = root.join("config.yaml");
    std::fs::write(&config, CONFIG).unwrap();
    chmod(&config, 0o600);
    Home {
        config,
        state: root.join("state").join("lablink"),
        socket: root.join("run").join("lablink").join("lablinkd.sock"),
        root,
        _t: t,
    }
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn start(h: &Home) -> Child {
    Command::new(env!("CARGO_BIN_EXE_lablinkd"))
        .args([
            "--no-netlink",
            "--no-mdns",
            "--no-startup-discovery",
            "--no-color",
        ])
        .arg("--config")
        .arg(&h.config)
        .arg("--state-dir")
        .arg(&h.state)
        .arg("--socket")
        .arg(&h.socket)
        .env("LABLINK_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// systemd's view of the process: it exited, with this status.
fn exited(c: &mut Child) -> Option<String> {
    c.try_wait()
        .unwrap()
        .map(|s| format!("lablinkd exited with {s}"))
}

/// The daemon's last message (what the journal would hold).
fn last_message(c: &mut Child) -> Vec<String> {
    use std::io::Read;
    if c.try_wait().unwrap().is_none() {
        return vec![];
    }
    let mut s = String::new();
    c.stderr.take().unwrap().read_to_string(&mut s).unwrap();
    s.lines()
        .last()
        .map(|l| vec![format!("its last message: {l}")])
        .unwrap_or_default()
}

fn ready(h: &Home, c: &mut Child) -> Result<String, String> {
    let c = std::cell::RefCell::new(c);
    wait_ready(
        &h.socket,
        READY_TIMEOUT,
        || exited(&mut c.borrow_mut()),
        || last_message(&mut c.borrow_mut()),
    )
}

fn stop(mut c: Child) {
    // SAFETY: kill with a valid pid of our own child.
    unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
    let end = Instant::now() + Duration::from_secs(15);
    while c.try_wait().unwrap().is_none() {
        assert!(Instant::now() < end, "lablinkd did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn status_json(h: &Home) -> String {
    Client::new(&h.socket)
        .call(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .unwrap()
        .to_string()
}

fn history_len(h: &Home) -> usize {
    let v = Client::new(&h.socket)
        .call(&Request::History {
            device: None,
            limit: 500,
        })
        .unwrap();
    v.as_array()
        .or_else(|| v["events"].as_array())
        .map(|a| a.len())
        .unwrap_or_else(|| panic!("unexpected history reply: {v}"))
}

#[test]
fn first_start_is_reported_once_the_daemon_answers() {
    let h = home();
    let mut c = start(&h);
    let ok = ready(&h, &mut c).expect("a fresh daemon must answer");
    assert!(ok.contains(env!("CARGO_PKG_VERSION")), "{ok}");
    assert!(ok.contains(&h.socket.display().to_string()), "{ok}");
    assert!(status_json(&h).contains("jetson"));
    assert_eq!(mode(&h.state), 0o700);
    stop(c);
}

#[test]
fn a_daemon_that_exits_at_once_fails_fast_with_its_own_reason() {
    let h = home();
    // A state directory any user could have written is still refused.
    std::fs::create_dir_all(&h.state).unwrap();
    chmod(&h.state, 0o777);
    let mut c = start(&h);
    let t0 = Instant::now();
    let err = ready(&h, &mut c).expect_err("must not read as started");
    assert!(
        t0.elapsed() < READY_TIMEOUT / 2,
        "an exit is seen at once, not after the timeout: {:?}",
        t0.elapsed()
    );
    assert!(err.contains("exited"), "{err}");
    assert!(
        err.contains("mode 0700"),
        "the daemon's reason is shown: {err}"
    );
    assert!(err.contains("chmod 700"), "the fix is named: {err}");
    assert_eq!(mode(&h.state), 0o777, "a shared directory is not touched");
}

#[test]
fn a_daemon_that_never_creates_its_socket_times_out_with_the_path() {
    let h = home();
    // Alive but never listening (hung before bind).
    let mut c = Command::new("sleep").arg("30").spawn().unwrap();
    let err = wait_ready(
        &h.socket,
        Duration::from_millis(800),
        || exited(&mut c),
        || vec!["service active (running, pid 1)".into()],
    )
    .expect_err("no socket, no success");
    let _ = c.kill();
    let _ = c.wait();
    assert!(err.contains("did not answer on"), "{err}");
    assert!(err.contains(&h.socket.display().to_string()), "{err}");
    assert!(err.contains("service active"), "{err}");
}

#[test]
fn a_daemon_on_another_socket_is_not_mistaken_for_ours() {
    let h = home();
    let mut c = start(&h);
    ready(&h, &mut c).unwrap();
    let elsewhere = h.root.join("other-runtime").join("lablinkd.sock");
    let err = wait_ready(&elsewhere, Duration::from_millis(500), || None, Vec::new)
        .expect_err("nothing serves this path");
    assert!(err.contains(&elsewhere.display().to_string()), "{err}");
    stop(c);
}

/// LabLink 0.4.2's desktop app created the state directory 0775 under
/// umask 002 (Files preferences) before the daemon ever ran, and every
/// later start failed. A directory only this user could have written is
/// tightened; the cache, pins and history in it survive.
#[test]
fn a_state_dir_only_you_could_write_is_tightened_and_keeps_its_contents() {
    let h = home();
    let mut c = start(&h);
    ready(&h, &mut c).unwrap();
    let events = history_len(&h);
    stop(c);
    // The pinned known_hosts lablinkd keeps (regenerated from the cache).
    let pins = h.state.join("known_hosts");
    let config_before = std::fs::read(&h.config).unwrap();
    let pins_before = std::fs::read(&pins).unwrap();
    // 0755: nobody else can write it, whatever the group.
    chmod(&h.state, 0o755);
    let mut c = start(&h);
    let ok = ready(&h, &mut c);
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(mode(&h.state), 0o700);
    assert!(status_json(&h).contains("jetson"));
    assert!(history_len(&h) > events, "history kept and extended");
    stop(c);
    assert_eq!(std::fs::read(&h.config).unwrap(), config_before);
    assert_eq!(std::fs::read(&pins).unwrap(), pins_before);
}

/// A sticky directory passes the path check (only an owner can replace a
/// file there) but anyone could have created files in it: refused,
/// untouched, whatever its group.
#[test]
fn a_sticky_shared_state_dir_is_refused_not_tightened() {
    for m in [0o1777, 0o1775] {
        let h = home();
        std::fs::create_dir_all(&h.state).unwrap();
        chmod(&h.state, m);
        let mut c = start(&h);
        let err = ready(&h, &mut c).expect_err("a sticky shared dir must be refused");
        assert!(err.contains("chmod 700"), "{m:o}: {err}");
        let now = std::fs::metadata(&h.state).unwrap().permissions().mode() & 0o7777;
        assert_eq!(now, m, "left untouched");
    }
}

/// 0775 with the user's own group: tightened where the group is provably
/// private (local accounts only), refused with the fix where it is not
/// (an `sss`/LDAP host). Either way the daemon says which.
#[test]
fn a_group_writable_state_dir_is_tightened_only_for_a_private_group() {
    let h = home();
    std::fs::create_dir_all(&h.state).unwrap();
    chmod(&h.state, 0o775);
    let private = lablink_core::paths::writable_by_others(&h.state).is_none();
    let mut c = start(&h);
    let r = ready(&h, &mut c);
    if private {
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(mode(&h.state), 0o700);
        stop(c);
    } else {
        let err = r.expect_err("a group other users share must be refused");
        assert!(err.contains("chmod 700"), "{err}");
        assert_eq!(mode(&h.state), 0o775);
    }
}

/// A start that fails leaves the configuration and the cache as they were;
/// after the cause is fixed a restart serves the same devices.
#[test]
fn recovery_after_a_failed_start_keeps_config_and_devices() {
    let h = home();
    let mut c = start(&h);
    ready(&h, &mut c).unwrap();
    stop(c);
    let db = h.state.join("cache.db");
    let db_len = std::fs::metadata(&db).unwrap().len();
    // Break it: a configuration the daemon refuses.
    std::fs::write(&h.config, format!("{CONFIG}bogus_key: 1\n")).unwrap();
    let broken = std::fs::read(&h.config).unwrap();
    let mut c = start(&h);
    let err = ready(&h, &mut c).expect_err("invalid config");
    assert!(err.contains("exited"), "{err}");
    assert!(
        err.contains("bogus_key") || err.contains("unknown field"),
        "{err}"
    );
    assert_eq!(
        std::fs::read(&h.config).unwrap(),
        broken,
        "config not rewritten"
    );
    assert!(
        std::fs::metadata(&db).unwrap().len() >= db_len,
        "cache kept"
    );
    // Fixed: the next start answers with the same device.
    std::fs::write(&h.config, CONFIG).unwrap();
    let mut c = start(&h);
    ready(&h, &mut c).unwrap();
    assert!(status_json(&h).contains("jetson"));
    stop(c);
}
