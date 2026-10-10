//! [integration, simulated] Complete daemons run in-process against a
//! simulated network (`lablink_daemon::testing::FakeNet`) and are queried over
//! their real Unix socket. No real network access.

use lablink_core::model::*;
use lablink_core::protocol::{DeviceChanges, ErrorCode, Request};
use lablink_daemon::probe::AuthOutcome;
use lablink_daemon::testing::{
    fake_key, fast_config, fast_config_with, FakeHost, FakeNet, PortMode, TestDaemon,
};
use std::time::{Duration, Instant};

const JETSON_A_MAC: &str = "02:4c:4c:00:00:01";

fn status(d: &TestDaemon, name: &str) -> DeviceStatus {
    let r: StatusReport = d
        .client()
        .call_typed(&Request::Status {
            device: Some(name.into()),
            site: None,
            all: false,
        })
        .unwrap();
    r.devices.into_iter().next().unwrap()
}

fn wait_for(
    d: &TestDaemon,
    name: &str,
    secs: u64,
    what: &str,
    pred: impl Fn(&DeviceStatus) -> bool,
) -> DeviceStatus {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let s = status(d, name);
        if pred(&s) {
            return s;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {name}: {what}; last status: {s:#?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn history(d: &TestDaemon, name: &str) -> Vec<HistoryEvent> {
    let v = d
        .client()
        .call(&Request::History {
            device: Some(name.into()),
            limit: 500,
        })
        .unwrap();
    serde_json::from_value(v["events"].clone()).unwrap()
}

fn kinds(evs: &[HistoryEvent]) -> Vec<&str> {
    evs.iter().map(|e| e.kind.as_str()).collect()
}

fn jetson_cfg(extra: &str) -> String {
    let fp = fake_key("jetson-a").fingerprint;
    format!(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    hostnames: [robot-host]\n    host_key_fingerprints: [\"{fp}\"]\n{extra}"
    )
}

fn lab_with_jetson(ip: &str) -> std::sync::Arc<FakeNet> {
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        ip,
        FakeHost::ssh_host(vec![fake_key("jetson-a")], JETSON_A_MAC),
    );
    net.with(|w| {
        w.resolve
            .insert("robot-host".into(), vec![ip.parse().unwrap()])
    });
    net
}

#[test]
fn device_located_verified_and_green() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), true).unwrap();
    let s = wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    assert_eq!(s.ip.as_deref(), Some("10.9.0.31"));
    assert_eq!(s.identity, IdentityState::Verified);
    assert_eq!(s.ssh_auth, AuthState::Ok);
    assert_eq!(s.network_name.as_deref(), Some("lab"));
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "jetson-a".into(),
        })
        .unwrap();
    assert_eq!(r.ip, "10.9.0.31");
    assert_eq!(
        r.host_key_alias.as_deref(),
        Some("lablink.default.jetson-a")
    );
    let kh = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
    assert!(kh.contains(&format!(
        "lablink.default.jetson-a ssh-ed25519 {}",
        fake_key("jetson-a").public_key.unwrap()
    )));
    d.stop().unwrap();
}

#[test]
fn ip_change_is_followed_by_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    // Hostname resolution would reveal the move too; disable it to prove the
    // host key alone re-identifies the device.
    net.with(|w| w.resolve.clear());
    let cfg = fast_config(
        &jetson_cfg("    expected_ips: [10.9.0.31]\n")
            .replace("hostnames: [robot-host]", "hostnames: []"),
    );
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // DHCP renumbers jetson-a and its MAC is not visible (no ARP evidence):
    // only an active scan followed by a host-key scan can find it.
    net.move_host("10.9.0.31", "10.9.0.44");
    net.host("10.9.0.44", |h| h.mac = None);
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    assert!(
        net.calls().iter().any(|c| c == "keyscan 10.9.0.44"),
        "the new address must be key-scanned"
    );
    let s = wait_for(&d, "jetson-a", 15, "moved and green", |s| {
        s.ip.as_deref() == Some("10.9.0.44") && s.color == Color::Green
    });
    assert_eq!(s.identity, IdentityState::Verified);
    let h = history(&d, "jetson-a");
    assert!(
        h.iter().any(|e| e.kind == "ip_changed"
            && e.message.contains("10.9.0.44")
            && e.message.contains("fingerprint")),
        "{h:#?}"
    );
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "jetson-a".into(),
        })
        .unwrap();
    assert_eq!(r.ip, "10.9.0.44");
    d.stop().unwrap();
}

/// A host replaying jetson-a's public key (it answers ssh-keyscan with it
/// but cannot sign) is never GREEN: the possession proof fails and the
/// device is a security stop; nothing is ever run against it.
#[test]
fn replayed_host_key_fails_the_possession_proof() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.host("10.9.0.31", |h| h.holds_keys = false);
    let cfg = fast_config(&jetson_cfg("    expected_ips: [10.9.0.31]\n"));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    let s = wait_for(&d, "jetson-a", 15, "mismatch", |s| {
        s.identity == IdentityState::Mismatch
    });
    assert_eq!(s.color, Color::Red);
    assert!(
        s.reasons.iter().any(|r| r.contains("replaying")),
        "{:?}",
        s.reasons
    );
    assert!(!kinds(&history(&d, "jetson-a")).contains(&"identity_verified"));
    // The genuine host (holds its key) is verified at the same address.
    let dir2 = tempfile::tempdir().unwrap();
    let net2 = lab_with_jetson("10.9.0.31");
    let cfg2 = fast_config(&jetson_cfg("    expected_ips: [10.9.0.31]\n"));
    let d2 = TestDaemon::start(cfg2, net2, dir2.path().into(), true).unwrap();
    wait_for(&d2, "jetson-a", 15, "green", |s| s.color == Color::Green);
}

#[test]
fn host_key_mismatch_is_red_and_never_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let cfg = fast_config(&jetson_cfg("    expected_ips: [10.9.0.31]\n"));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // Reinstall (or impersonation): same static IP and MAC, new host key.
    net.host("10.9.0.31", |h| h.keys = vec![fake_key("impostor")]);
    // Force an identity re-check by cycling the SSH port.
    net.host("10.9.0.31", |h| h.port = PortMode::Refused);
    wait_for(&d, "jetson-a", 15, "port closed", |s| {
        s.ssh_port == PortState::Closed
    });
    net.host("10.9.0.31", |h| h.port = PortMode::Open);
    let s = wait_for(&d, "jetson-a", 15, "mismatch", |s| {
        s.identity == IdentityState::Mismatch
    });
    assert_eq!(s.color, Color::Red);
    assert!(s.reasons[0].contains("SECURITY"), "{:?}", s.reasons);
    let err = d
        .client()
        .call(&Request::Resolve {
            device: "jetson-a".into(),
        })
        .unwrap_err();
    match err {
        lablink_core::client::ClientError::Api(e) => {
            assert_eq!(e.code, ErrorCode::IdentityMismatch)
        }
        e => panic!("{e:?}"),
    }
    // Pins are unchanged and the event is recorded once.
    let h = history(&d, "jetson-a");
    assert_eq!(
        kinds(&h)
            .iter()
            .filter(|k| **k == "identity_mismatch")
            .count(),
        1,
        "{h:#?}"
    );
    let kh = std::fs::read_to_string(dir.path().join("known_hosts")).unwrap();
    assert!(!kh.contains(&fake_key("impostor").public_key.unwrap()));
    // `trust` without --replace refuses; config pins can't be replaced at runtime.
    let fp = vec![fake_key("impostor").fingerprint];
    let e = d
        .client()
        .call(&Request::Trust {
            device: "jetson-a".into(),
            confirm: Some(fp.clone()),
            replace: false,
        })
        .unwrap_err();
    assert!(
        matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::IdentityMismatch),
        "{e:?}"
    );
    let e = d
        .client()
        .call(&Request::Trust {
            device: "jetson-a".into(),
            confirm: Some(fp),
            replace: true,
        })
        .unwrap_err();
    assert!(
        matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::Refused),
        "{e:?}"
    );
    d.stop().unwrap();
}

/// Final qualification WSC2-F2, F3: a MISMATCH is kept across a restart,
/// and clears (without a restart) once the genuine machine proves the
/// pinned key again; meanwhile the device is not key-scanned at every check.
#[test]
fn mismatch_survives_restart_and_clears_when_the_pin_is_proven_again() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let cfg = fast_config(&jetson_cfg("    expected_ips: [10.9.0.31]\n"));
    let d = TestDaemon::start(cfg.clone(), net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    let cycle_port = |d: &TestDaemon| {
        net.host("10.9.0.31", |h| h.port = PortMode::Refused);
        wait_for(d, "jetson-a", 15, "port closed", |s| {
            s.ssh_port == PortState::Closed
        });
        net.host("10.9.0.31", |h| h.port = PortMode::Open);
    };
    net.host("10.9.0.31", |h| h.keys = vec![fake_key("impostor")]);
    cycle_port(&d);
    wait_for(&d, "jetson-a", 15, "mismatch", |s| {
        s.identity == IdentityState::Mismatch
    });
    d.stop().unwrap();
    // Restart with the impostor gone: still a security stop, with its reason.
    net.host("10.9.0.31", |h| h.up = false);
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let s = status(&d, "jetson-a");
    assert_eq!(s.identity, IdentityState::Mismatch, "{s:#?}");
    assert!(s.reasons.iter().any(|r| r.contains("SECURITY")), "{s:#?}");
    assert!(d
        .client()
        .call(&Request::Resolve {
            device: "jetson-a".into()
        })
        .is_err());
    // The genuine machine returns with the pinned key.
    net.host("10.9.0.31", |h| {
        h.up = true;
        h.keys = vec![fake_key("jetson-a")];
    });
    let s = wait_for(&d, "jetson-a", 20, "verified again", |s| {
        s.identity == IdentityState::Verified
    });
    assert_ne!(s.color, Color::Red);
    let m0: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
    std::thread::sleep(Duration::from_secs(4));
    let m1: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
    assert!(
        m1.counters["keyscans"] - m0.counters["keyscans"] <= 1,
        "{} keyscans in 4 s",
        m1.counters["keyscans"] - m0.counters["keyscans"]
    );
    d.stop().unwrap();
}

/// Final qualification WSC2-F4: a new link-layer address at the device's
/// address takes the verified label away until the pin is proven again.
#[test]
fn new_mac_at_the_address_is_not_shown_verified_until_proven() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let cfg = fast_config(&jetson_cfg("    expected_ips: [10.9.0.31]\n"));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // Another machine (new MAC) that shows no host keys at all.
    net.host("10.9.0.31", |h| {
        h.mac = Some("02:4c:4c:00:00:99".into());
        h.keys = vec![];
    });
    wait_for(&d, "jetson-a", 20, "not verified", |s| {
        s.identity != IdentityState::Verified
    });
    d.stop().unwrap();
}

#[test]
fn intermittent_packet_loss_never_goes_offline() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // Every other round fails (50% loss in a pattern hysteresis must absorb).
    net.host("10.9.0.31", |h| h.script = [false, true].repeat(5).into());
    let deadline = Instant::now() + Duration::from_secs(12);
    while net.with(|w| !w.hosts[&"10.9.0.31".parse().unwrap()].script.is_empty()) {
        let s = status(&d, "jetson-a");
        assert_ne!(s.network, NetworkState::Offline);
        assert_ne!(
            s.network,
            NetworkState::Degraded,
            "single drops must not degrade"
        );
        assert!(Instant::now() < deadline, "script not consumed");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!kinds(&history(&d, "jetson-a")).contains(&"network_offline"));
    d.stop().unwrap();
}

#[test]
fn unavailable_device_goes_red_after_threshold_then_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    net.host("10.9.0.31", |h| h.up = false);
    let s = wait_for(&d, "jetson-a", 15, "degraded", |s| {
        s.network == NetworkState::Degraded
    });
    assert_eq!(s.color, Color::Yellow);
    let s = wait_for(&d, "jetson-a", 20, "offline", |s| {
        s.network == NetworkState::Offline
    });
    assert_eq!(s.color, Color::Red);
    assert_eq!(s.latency_ms, None);
    net.host("10.9.0.31", |h| h.up = true);
    wait_for(&d, "jetson-a", 20, "recovered", |s| s.color == Color::Green);
    let k = kinds(&history(&d, "jetson-a"))
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let pos = |x: &str| {
        k.iter()
            .position(|e| e == x)
            .unwrap_or_else(|| panic!("{x} missing from {k:?}"))
    };
    assert!(pos("network_degraded") < pos("network_offline"));
    assert!(k.iter().rposition(|e| e == "network_online").unwrap() > pos("network_offline"));
    d.stop().unwrap();
}

#[test]
fn ssh_port_opens_and_closes() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.host("10.9.0.31", |h| h.port = PortMode::Refused);
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    let s = wait_for(&d, "jetson-a", 15, "closed", |s| {
        s.ssh_port == PortState::Closed
    });
    assert_eq!(s.color, Color::Yellow);
    assert_eq!(
        s.network,
        NetworkState::Online,
        "refused proves the host is up"
    );
    net.host("10.9.0.31", |h| h.port = PortMode::Open);
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    net.host("10.9.0.31", |h| h.port = PortMode::Timeout);
    let s = wait_for(&d, "jetson-a", 15, "filtered", |s| {
        s.ssh_port == PortState::Filtered
    });
    assert_eq!(s.network, NetworkState::Online, "ICMP still answers");
    let h = history(&d, "jetson-a");
    assert!(h
        .iter()
        .any(|e| e.message.contains("TCP/22 became reachable")));
    assert!(h.iter().any(|e| e.message.contains("TCP/22 not answering")));
    d.stop().unwrap();
}

#[test]
fn history_records_transitions_not_heartbeats() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    let n0 = history(&d, "jetson-a").len();
    std::thread::sleep(Duration::from_secs(4)); // ~4 more successful checks
    let n1 = history(&d, "jetson-a").len();
    assert_eq!(
        n0,
        n1,
        "steady state must not add history: {:#?}",
        history(&d, "jetson-a")
    );
    let m: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
    assert!(m.counters["device_checks"] >= 4);
    d.stop().unwrap();
}

#[test]
fn restart_restores_identity_and_history_from_cache() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let cfg = fast_config(&jetson_cfg(""));
    let d = TestDaemon::start(cfg.clone(), net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    d.stop().unwrap();
    // Device unreachable during the second run: the cache must still know it.
    net.host("10.9.0.31", |h| h.up = false);
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let detail: DeviceDetail = d
        .client()
        .call_typed(&Request::Inspect {
            device: "jetson-a".into(),
        })
        .unwrap();
    assert_eq!(detail.status.ip.as_deref(), Some("10.9.0.31"));
    assert!(detail.status.last_seen_ms.is_some());
    assert!(detail.macs.contains(&JETSON_A_MAC.to_string()));
    assert!(detail
        .pinned_keys
        .iter()
        .any(|k| k.fingerprint == fake_key("jetson-a").fingerprint
            && k.source.as_deref() == Some("config")));
    let k = kinds(&history(&d, "jetson-a"))
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    assert!(k.contains(&"identity_verified".to_string()), "{k:?}");
    let all: serde_json::Value = d
        .client()
        .call(&Request::History {
            device: None,
            limit: 100,
        })
        .unwrap();
    let sys: Vec<String> = all["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(sys.iter().filter(|k| *k == "daemon_started").count() >= 2);
    assert!(sys.contains(&"daemon_stopped".to_string()));
    // Previously seen device that stays unreachable becomes RED (expected but unavailable).
    wait_for(&d, "jetson-a", 20, "red", |s| s.color == Color::Red);
    d.stop().unwrap();
}

#[test]
fn corrupt_cache_is_recovered() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cache.db"), vec![0x42u8; 8192]).unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    let all: serde_json::Value = d
        .client()
        .call(&Request::History {
            device: None,
            limit: 50,
        })
        .unwrap();
    assert!(all["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "cache_recovered"));
    assert!(std::fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("corrupt")));
    d.stop().unwrap();
}

#[test]
fn graceful_shutdown_flushes_and_removes_socket() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    let sock = d.socket.clone();
    let t = Instant::now();
    d.stop().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        t.elapsed()
    );
    assert!(!sock.exists(), "socket must be removed");
    let (store, _) = lablink_daemon::store::Store::open(&dir.path().join("cache.db"), 100).unwrap();
    let l = store.load(100).unwrap();
    assert!(l.devices.iter().any(|(n, _)| n == "default/jetson-a"));
    assert_eq!(l.events.last().unwrap().kind, "daemon_stopped");
}

#[test]
fn second_daemon_on_same_state_dir_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        false,
    )
    .unwrap();
    let e = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), false)
        .err()
        .unwrap();
    assert!(e.contains("another lablinkd"), "{e}");
    d.stop().unwrap();
}

#[test]
fn no_runaway_task_creation() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    for i in 0..5 {
        net.add(
            &format!("10.9.0.{}", 100 + i),
            FakeHost::ssh_host(
                vec![fake_key(&format!("h{i}"))],
                &format!("aa:00:00:00:00:{i:02x}"),
            ),
        );
    }
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    let m0: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
    let mut peak = 0;
    for round in 0..6 {
        // Churn: flap the device, run discovery, hammer the socket.
        net.host("10.9.0.31", |h| h.up = round % 2 == 0);
        let _: DiscoverReport = d
            .client()
            .call_typed(&Request::Discover { scan_cidr: None })
            .unwrap();
        for _ in 0..20 {
            let _ = d
                .client()
                .call(&Request::Status {
                    device: None,
                    site: None,
                    all: true,
                })
                .unwrap();
        }
        let m: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
        peak = peak.max(m.tokio_alive_tasks);
    }
    std::thread::sleep(Duration::from_millis(500));
    let m1: MetricsReport = d.client().call_typed(&Request::Metrics).unwrap();
    // Long-lived: ipc, coordinator, persist, one monitor; plus this request's handler.
    assert!(
        m0.tokio_alive_tasks <= 8,
        "baseline {}",
        m0.tokio_alive_tasks
    );
    assert!(
        m1.tokio_alive_tasks <= m0.tokio_alive_tasks + 1,
        "tasks grew {} -> {}",
        m0.tokio_alive_tasks,
        m1.tokio_alive_tasks
    );
    // During scans: bounded by scan_concurrency (32) + baseline, never by range size.
    assert!(peak <= m0.tokio_alive_tasks + 40, "peak {peak}");
    assert!(
        m1.open_fds.unwrap() <= m0.open_fds.unwrap() + 4,
        "fds {:?} -> {:?}",
        m0.open_fds,
        m1.open_fds
    );
    d.stop().unwrap();
}

#[test]
fn active_scans_only_touch_allowlisted_attached_networks() {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24", "172.20.0.2/16"]);
    let cfg = fast_config(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\n  - name: away\n    cidr: 10.50.0.0/24\n    active_scan: true\n  - name: campus\n    cidr: 172.20.0.0/16\n",
    );
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let rep: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let by = |n: &str| {
        rep.stages
            .iter()
            .find(|s| s.stage == n)
            .unwrap_or_else(|| panic!("{n}: {:#?}", rep.stages))
            .clone()
    };
    assert_eq!(by("active_scan:default/lab").result, "ok");
    assert_eq!(by("active_scan:default/away").result, "skipped");
    assert!(by("active_scan:default/away")
        .detail
        .contains("not directly attached"));
    assert!(
        !rep.stages
            .iter()
            .any(|s| s.stage == "active_scan:default/campus"),
        "passive network must not be scanned"
    );
    let calls = net.calls();
    assert!(!calls.is_empty());
    for c in &calls {
        let ip = c.split(' ').nth(1).unwrap();
        assert!(
            ip.starts_with("10.9.0."),
            "probe outside allowlisted attached network: {c}"
        );
    }
    assert_eq!(calls.iter().filter(|c| c.starts_with("icmp")).count(), 254);
    // One-time scans: refused when huge, public, or not attached.
    for bad in [
        "10.0.0.0/8",
        "8.8.8.0/24",
        "10.77.0.0/24",
        "172.20.0.0/16",
        "nonsense",
    ] {
        let e = d
            .client()
            .call(&Request::Discover {
                scan_cidr: Some(bad.into()),
            })
            .unwrap_err();
        assert!(
            matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::Refused),
            "{bad}: {e:?}"
        );
    }
    let before = net.calls().len();
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover {
            scan_cidr: Some("172.20.5.0/24".into()),
        })
        .unwrap();
    let after = net.calls();
    assert!(
        after[before..]
            .iter()
            .any(|c| c.starts_with("icmp 172.20.5.")),
        "one-time scan of an attached subrange runs"
    );
    let h: serde_json::Value = d
        .client()
        .call(&Request::History {
            device: None,
            limit: 100,
        })
        .unwrap();
    let refused = h["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "scan_refused")
        .count();
    assert_eq!(refused, 5);
    d.stop().unwrap();
}

#[test]
fn reassigned_ip_moves_to_the_device_whose_key_it_presents() {
    let dir = tempfile::tempdir().unwrap();
    let xfp = fake_key("jetson-b").fingerprint;
    let net = lab_with_jetson("10.9.0.31");
    net.add(
        "10.9.0.45",
        FakeHost::ssh_host(vec![fake_key("jetson-b")], "aa:bb:cc:00:00:45"),
    );
    let cfg = fast_config(&jetson_cfg(&format!(
        "  - name: jetson-b\n    host_key_fingerprints: [\"{xfp}\"]\n    expected_ips: [10.9.0.45]\n"
    )));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-b", 15, "green", |s| s.color == Color::Green);
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // jetson-b powers off; DHCP gives its address to jetson-a.
    net.with(|w| {
        w.hosts.remove(&"10.9.0.45".parse().unwrap());
        w.resolve.clear();
    });
    net.move_host("10.9.0.31", "10.9.0.45");
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let o = wait_for(&d, "jetson-a", 20, "jetson-a at .45", |s| {
        s.ip.as_deref() == Some("10.9.0.45") && s.identity == IdentityState::Verified
    });
    assert_eq!(o.color, Color::Green);
    let x = status(&d, "jetson-b");
    assert_ne!(
        x.identity,
        IdentityState::Mismatch,
        "reuse by a known device is not an attack on jetson-b"
    );
    assert_ne!(x.ip.as_deref(), Some("10.9.0.45"));
    d.stop().unwrap();
}

#[test]
fn unknown_host_at_old_dhcp_address_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.with(|w| w.resolve.clear());
    let cfg = fast_config(&jetson_cfg("").replace("hostnames: [robot-host]", "hostnames: []"));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    // jetson-a leaves; a laptop with a different key (and MAC) gets its address.
    net.with(|w| {
        let h = w.hosts.get_mut(&"10.9.0.31".parse().unwrap()).unwrap();
        h.keys = vec![fake_key("laptop")];
        h.mac = Some("cc:cc:cc:00:00:01".into());
        h.port = PortMode::Refused;
    });
    // The kernel would report the new link-layer address via rtnetlink; the
    // simulated network only exposes it through a snapshot.
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    wait_for(&d, "jetson-a", 15, "port closed", |s| {
        s.ssh_port == PortState::Closed
    });
    net.host("10.9.0.31", |h| h.port = PortMode::Open);
    let s = wait_for(&d, "jetson-a", 15, "released", |s| {
        s.ip.is_none() || s.ip.as_deref() != Some("10.9.0.31")
    });
    assert_ne!(s.identity, IdentityState::Mismatch);
    let disc: serde_json::Value = d.client().call(&Request::Discovered).unwrap();
    assert!(
        disc["discovered"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["ip"] == "10.9.0.31"),
        "{disc:#}"
    );
    d.stop().unwrap();
}

#[test]
fn password_only_server_is_yellow_with_reason() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.host("10.9.0.31", |h| {
        h.auth = AuthOutcome::Rejected {
            password_only: true,
            detail: "server only accepts password authentication".into(),
        }
    });
    let d = TestDaemon::start(fast_config(&jetson_cfg("")), net, dir.path().into(), true).unwrap();
    let s = wait_for(&d, "jetson-a", 15, "auth failed", |s| {
        s.ssh_auth == AuthState::Failed
    });
    assert_eq!(s.color, Color::Yellow);
    assert!(
        s.reasons.iter().any(|r| r.contains("password")),
        "{:?}",
        s.reasons
    );
    d.stop().unwrap();
}

#[test]
fn unpinned_device_trusted_from_user_known_hosts_or_explicit_trust() {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.50",
        FakeHost::ssh_host(vec![fake_key("a")], "aa:00:00:00:00:50"),
    );
    net.add(
        "10.9.0.51",
        FakeHost::ssh_host(vec![fake_key("b")], "aa:00:00:00:00:51"),
    );
    net.with(|w| w.user_known = vec![fake_key("a")]);
    let cfg = fast_config("devices:\n  - name: known\n    expected_ips: [10.9.0.50]\n  - name: fresh\n    expected_ips: [10.9.0.51]\n");
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "known", 15, "verified via known_hosts", |s| {
        s.identity == IdentityState::Verified
    });
    let s = wait_for(&d, "fresh", 15, "unverified", |s| {
        s.identity == IdentityState::Unverified
    });
    assert_eq!(s.color, Color::Yellow);
    // Unpinned: resolve works but without LabLink's alias (OpenSSH policy applies).
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "fresh".into(),
        })
        .unwrap();
    assert!(r.host_key_alias.is_none());
    // Trust flow: preview, then confirm exactly what was shown.
    let p: TrustReport = d
        .client()
        .call_typed(&Request::Trust {
            device: "fresh".into(),
            confirm: None,
            replace: false,
        })
        .unwrap();
    assert_eq!(p.action, "preview");
    // Key changes between preview and confirm: refuse.
    net.host("10.9.0.51", |h| h.keys = vec![fake_key("b2")]);
    let confirm: Vec<String> = p.scanned.iter().map(|k| k.fingerprint.clone()).collect();
    let e = d
        .client()
        .call(&Request::Trust {
            device: "fresh".into(),
            confirm: Some(confirm.clone()),
            replace: false,
        })
        .unwrap_err();
    assert!(
        matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::Conflict),
        "{e:?}"
    );
    net.host("10.9.0.51", |h| h.keys = vec![fake_key("b")]);
    let t: TrustReport = d
        .client()
        .call_typed(&Request::Trust {
            device: "fresh".into(),
            confirm: Some(confirm),
            replace: false,
        })
        .unwrap();
    assert_eq!(t.action, "pinned");
    let s = wait_for(&d, "fresh", 15, "verified and green", |s| {
        s.color == Color::Green
    });
    assert_eq!(s.identity, IdentityState::Verified);
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "fresh".into(),
        })
        .unwrap();
    assert_eq!(r.host_key_alias.as_deref(), Some("lablink.default.fresh"));
    d.stop().unwrap();
}

#[test]
fn adopt_discovered_host_and_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.77",
        FakeHost::ssh_host(vec![fake_key("new")], "aa:00:00:00:00:77"),
    );
    let cfg =
        fast_config("networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\n");
    let d = TestDaemon::start(cfg, net, dir.path().into(), false).unwrap();
    let rep: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let h = rep
        .discovered
        .iter()
        .find(|h| h.ip == "10.9.0.77")
        .expect("found by scan");
    assert_eq!(h.ssh_port, PortState::Open);
    assert_eq!(h.fingerprints, vec![fake_key("new").fingerprint]);
    let s: DeviceStatus = d
        .client()
        .call_typed(&Request::Adopt {
            site: None,
            ip: "10.9.0.77".into(),
            name: "rig".into(),
            label: None,
            username: None,
            profile: None,
            ssh: None,
        })
        .unwrap();
    assert_eq!(s.ip.as_deref(), Some("10.9.0.77"));
    wait_for(&d, "rig", 15, "online", |s| {
        s.network == NetworkState::Online
    });
    let s: DeviceStatus = d
        .client()
        .call_typed(&Request::Set {
            device: "rig".into(),
            changes: DeviceChanges {
                label: Some("Test Rig".into()),
                username: Some("lab".into()),
                monitoring: Some(false),
                ..Default::default()
            },
        })
        .unwrap();
    assert_eq!(s.label.as_deref(), Some("Test Rig"));
    assert_eq!(s.username.as_deref(), Some("lab"));
    assert_eq!(s.color, Color::Gray);
    let e = d
        .client()
        .call(&Request::Set {
            device: "rig".into(),
            changes: DeviceChanges {
                username: Some("-oProxyCommand=x".into()),
                ..Default::default()
            },
        })
        .unwrap_err();
    assert!(
        matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::BadRequest)
    );
    d.stop().unwrap();
}

#[test]
fn malformed_and_oversized_requests_are_rejected() {
    use std::io::{BufRead, BufReader, Write};
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    let d = TestDaemon::start(fast_config(""), net, dir.path().into(), false).unwrap();
    let mut s = std::os::unix::net::UnixStream::connect(&d.socket).unwrap();
    s.write_all(b"{not json}\n").unwrap();
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap();
    assert!(line.contains("\"bad_request\""), "{line}");
    let mut s = std::os::unix::net::UnixStream::connect(&d.socket).unwrap();
    let big = vec![b'x'; 70 * 1024];
    let _ = s.write_all(&big);
    let _ = s.write_all(b"\n");
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap();
    assert!(line.contains("too large"), "{line}");
    let e = d
        .client()
        .call(&Request::Status {
            device: Some("nope".into()),
            site: None,
            all: false,
        })
        .unwrap_err();
    assert!(
        matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::DeviceNotFound)
    );
    let mode = std::fs::metadata(&d.socket).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.permissions().mode() & 0o777, 0o600);
    d.stop().unwrap();
}

/// [simulated soak] Churn for LABLINK_SOAK_SECS (default 60): devices appear
/// and disappear, change IP, SSH ports flap, discovery runs. Asserts that
/// tasks, file descriptors and memory stay bounded, and prints samples.
/// Run: cargo test -p lablink-daemon --release --test daemon soak -- --ignored --nocapture
#[test]
#[ignore = "soak test; run explicitly with --ignored"]
fn soak_churn_resources_bounded() {
    let secs: u64 = std::env::var("LABLINK_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let env_u64 = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    };
    let step_ms = env_u64("LABLINK_SOAK_STEP_MS", 1500);
    let sample_s = env_u64("LABLINK_SOAK_SAMPLE_S", 10);
    let retention: Option<u64> = std::env::var("LABLINK_SOAK_RETENTION")
        .ok()
        .and_then(|s| s.parse().ok());
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    let mut yaml = String::from(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\ndevices:\n",
    );
    for i in 0..5 {
        let k = fake_key(&format!("dev{i}"));
        net.add(
            &format!("10.9.0.{}", 10 + i),
            FakeHost::ssh_host(vec![k.clone()], &format!("aa:00:00:00:01:{i:02x}")),
        );
        yaml.push_str(&format!("  - name: dev{i}\n    usernames: [u]\n    host_key_fingerprints: [\"{}\"]\n    expected_ips: [10.9.0.{}]\n", k.fingerprint, 10 + i));
    }
    net.record_calls
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let cfg = match retention {
        Some(n) => fast_config_with(&format!("  history_retention: {n}\n"), &yaml),
        None => fast_config(&yaml),
    };
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    for i in 0..5 {
        wait_for(&d, &format!("dev{i}"), 20, "green", |s| {
            s.color == Color::Green
        });
    }
    let metrics = || -> MetricsReport { d.client().call_typed(&Request::Metrics).unwrap() };
    let m0 = metrics();
    println!("t_s,tasks,fds,rss_kib,cpu_ms,device_checks,history_events,heap_in_use_bytes,heap_arena_bytes,sqlite_memory_used_bytes,sqlite_event_rows,sqlite_db_file_bytes,sqlite_wal_file_bytes,ring_events,discovered_hosts,ambiguity_notes,address_records_total");
    let start = Instant::now();
    let mut step = 0u64;
    let mut moved = [false; 5];
    let mut last_sample = Instant::now() - Duration::from_secs(60);
    let mut max_tasks = 0;
    while start.elapsed() < Duration::from_secs(secs) {
        let i = (step % 5) as usize;
        let base = format!("10.9.0.{}", 10 + i);
        let alt = format!("10.9.0.{}", 100 + i);
        let cur = if moved[i] { alt.clone() } else { base.clone() };
        match step % 4 {
            0 => net.host(&cur, |h| h.up = !h.up),
            1 => net.host(&cur, |h| {
                h.port = if h.port == PortMode::Open {
                    PortMode::Refused
                } else {
                    PortMode::Open
                }
            }),
            2 => {
                net.host(&cur, |h| {
                    h.up = true;
                    h.port = PortMode::Open;
                });
                let to = if moved[i] { &base } else { &alt };
                net.move_host(&cur, to);
                moved[i] = !moved[i];
            }
            _ => {
                let _: DiscoverReport = d
                    .client()
                    .call_typed(&Request::Discover { scan_cidr: None })
                    .unwrap();
            }
        }
        step += 1;
        std::thread::sleep(Duration::from_millis(step_ms));
        let m = metrics();
        max_tasks = max_tasks.max(m.tokio_alive_tasks);
        if last_sample.elapsed() >= Duration::from_secs(sample_s) {
            last_sample = Instant::now();
            let c = |k: &str| m.counters.get(k).copied().unwrap_or(0);
            println!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                start.elapsed().as_secs(),
                m.tokio_alive_tasks,
                m.open_fds.unwrap_or(0),
                m.rss_kib.unwrap_or(0),
                m.cpu_user_ms.unwrap_or(0) + m.cpu_system_ms.unwrap_or(0),
                m.counters["device_checks"],
                m.counters["history_events"],
                c("heap_in_use_bytes"),
                c("heap_arena_bytes"),
                c("sqlite_memory_used_bytes"),
                c("sqlite_event_rows"),
                c("sqlite_db_file_bytes"),
                c("sqlite_wal_file_bytes"),
                c("ring_events"),
                c("discovered_hosts"),
                c("ambiguity_notes"),
                c("address_records_total")
            );
        }
    }
    // Let in-flight work settle, then compare against the baseline.
    for (i, was_moved) in moved.iter().enumerate() {
        let cur = if *was_moved {
            format!("10.9.0.{}", 100 + i)
        } else {
            format!("10.9.0.{}", 10 + i)
        };
        net.host(&cur, |h| {
            h.up = true;
            h.port = PortMode::Open;
        });
    }
    std::thread::sleep(Duration::from_secs(3));
    let m1 = metrics();
    println!("baseline tasks={} fds={:?} rss={:?}; end tasks={} fds={:?} rss={:?}; peak tasks={max_tasks}; steps={step}",
        m0.tokio_alive_tasks, m0.open_fds, m0.rss_kib, m1.tokio_alive_tasks, m1.open_fds, m1.rss_kib);
    assert!(
        m1.tokio_alive_tasks <= m0.tokio_alive_tasks + 1,
        "task leak"
    );
    assert!(m1.open_fds.unwrap() <= m0.open_fds.unwrap() + 4, "fd leak");
    assert!(
        m1.rss_kib.unwrap() < m0.rss_kib.unwrap() + 8 * 1024,
        "RSS grew by more than 8 MiB"
    );
    // Every device must still converge to GREEN at its final address.
    for i in 0..5 {
        wait_for(&d, &format!("dev{i}"), 30, "green after churn", |s| {
            s.color == Color::Green
        });
    }
    d.stop().unwrap();
}

#[test]
fn service_checks_report_per_service_and_only_run_on_verified_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.host("10.9.0.31", |h| {
        h.commands.insert("disk-check".into(), 1);
    });
    net.add(
        "10.9.0.60",
        FakeHost::ssh_host(vec![fake_key("unpinned")], "aa:00:00:00:00:60"),
    );
    let svc = "    services:\n      - name: ros2\n        command: ros2-check\n        interval_s: 10\n        timeout_s: 5\n      - name: disk\n        command: disk-check\n        interval_s: 10\n        timeout_s: 5\n";
    let cfg = fast_config(&format!(
        "{}{svc}  - name: stranger\n    expected_ips: [10.9.0.60]\n{svc}",
        jetson_cfg("")
    ));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    let s = wait_for(&d, "jetson-a", 15, "services checked", |s| {
        s.services.iter().all(|x| x.state != ServiceState::Unknown)
    });
    assert_eq!(
        s.color,
        Color::Green,
        "service results do not change the connectivity color"
    );
    let by = |n: &str| s.services.iter().find(|x| x.name == n).unwrap().clone();
    assert_eq!(by("ros2").state, ServiceState::Ok);
    assert_eq!(by("disk").state, ServiceState::Degraded);
    assert!(history(&d, "jetson-a")
        .iter()
        .any(|e| e.kind == "service" && e.message.contains("disk")));
    // The unpinned host is never sent a command.
    let st = wait_for(&d, "stranger", 15, "unverified", |s| {
        s.identity == IdentityState::Unverified
    });
    assert!(st.services.iter().all(|x| x.state == ServiceState::Unknown));
    assert!(
        !net.calls().iter().any(|c| c == "exec 10.9.0.60"),
        "service checks must not run on unverified hosts"
    );
    d.stop().unwrap();
}

#[test]
fn device_behind_gateway_is_checked_through_it_never_directly() {
    // The robot (192.168.50.161) sits on the robot's internal network behind
    // jetson-a. This host is only on the lab network (10.9.0.0/24).
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.add(
        "192.168.50.161",
        FakeHost {
            port: PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "aa:00:00:00:01:61")
        },
    );
    net.add(
        "192.168.50.20",
        FakeHost::ssh_host(vec![fake_key("payload")], "aa:00:00:00:01:20"),
    );
    let cfg = fast_config(&jetson_cfg(
        "  - name: robot-a\n    ssh: false\n    via: jetson-a\n    expected_ips: [192.168.50.161]\n  - name: payload\n    via: jetson-a\n    usernames: [ops]\n    expected_ips: [192.168.50.20]\n",
    ));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait_for(&d, "jetson-a", 15, "gateway green", |s| {
        s.color == Color::Green
    });
    let s = wait_for(&d, "robot-a", 20, "robot-a green via jetson-a", |s| {
        s.color == Color::Green
    });
    assert_eq!(s.via.as_deref(), Some("jetson-a"));
    assert_eq!(s.network, NetworkState::Online);
    assert_eq!(s.ip.as_deref(), Some("192.168.50.161"));
    // An SSH device behind the gateway: identity via ssh-keyscan on the gateway.
    let p = wait_for(&d, "payload", 20, "payload port open", |s| {
        s.ssh_port == PortState::Open
    });
    assert_eq!(p.via.as_deref(), Some("jetson-a"));
    let calls = net.calls();
    for c in &calls {
        assert!(
            !(c.ends_with(" 192.168.50.161") || c.ends_with(" 192.168.50.20"))
                || c.starts_with("via-ping"),
            "direct probe of a device behind the gateway: {c}"
        );
    }
    assert!(
        calls.iter().any(|c| c == "exec 10.9.0.31"),
        "checks run on the gateway"
    );
    // Its host key was scanned through the gateway; pin it with trust (which
    // also scans through the gateway), then resolve tunnels via the gateway.
    wait_for(&d, "payload", 20, "payload unpinned", |s| {
        s.identity == IdentityState::Unverified
    });
    let preview: TrustReport = d
        .client()
        .call_typed(&Request::Trust {
            device: "payload".into(),
            confirm: None,
            replace: false,
        })
        .unwrap();
    assert_eq!(preview.scanned.len(), 1);
    let confirm = vec![fake_key("payload").fingerprint];
    let t: TrustReport = d
        .client()
        .call_typed(&Request::Trust {
            device: "payload".into(),
            confirm: Some(confirm),
            replace: false,
        })
        .unwrap();
    assert_eq!(t.action, "pinned");
    let calls = net.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.ends_with(" 192.168.50.20") && !c.starts_with("via-ping")),
        "trust must not scan directly: {calls:?}"
    );
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "payload".into(),
        })
        .unwrap();
    assert_eq!(r.host_key_alias.as_deref(), Some("lablink.default.payload"));
    let pc = r
        .proxy_command
        .expect("proxy command for a device behind a gateway");
    assert!(
        pc.contains("HostName=10.9.0.31")
            && pc.contains("HostKeyAlias=lablink.default.jetson-a")
            && pc.contains("-W %h:%p"),
        "{pc}"
    );
    assert!(
        !pc.contains("BatchMode=yes"),
        "interactive use may prompt for the gateway"
    );
    // Gateway goes away: the device becomes GRAY with the reason, not RED.
    net.host("10.9.0.31", |h| h.up = false);
    let s = wait_for(&d, "robot-a", 30, "robot-a gray", |s| {
        s.color == Color::Gray
    });
    assert!(
        s.reasons.iter().any(|r| r.contains("gateway 'jetson-a'")),
        "{:?}",
        s.reasons
    );
    assert!(history(&d, "robot-a")
        .iter()
        .any(|e| e.kind == "via_unavailable"));
    d.stop().unwrap();
}

#[test]
fn device_behind_gateway_is_probed_directly_when_attached() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.with(|w| w.local.push("192.168.50.10/24".parse().unwrap()));
    net.add(
        "192.168.50.161",
        FakeHost {
            port: PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "aa:00:00:00:01:61")
        },
    );
    let cfg = fast_config(&jetson_cfg(
        "  - name: robot-a\n    ssh: false\n    via: jetson-a\n    expected_ips: [192.168.50.161]\n",
    ));
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    let s = wait_for(&d, "robot-a", 20, "robot-a green", |s| {
        s.color == Color::Green
    });
    assert_eq!(
        s.via, None,
        "on the cable network the gateway is not needed"
    );
    assert!(net.calls().iter().any(|c| c == "icmp 192.168.50.161"));
    d.stop().unwrap();
}

/// Regression: the login check must recover once the server accepts the key
/// (e.g. after enabling PubkeyAuthentication and restarting sshd), not stay
/// stuck on a cached "password only" failure until the periodic interval.
#[test]
fn login_check_recovers_when_server_starts_accepting_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let net = lab_with_jetson("10.9.0.31");
    net.host("10.9.0.31", |h| {
        h.auth = AuthOutcome::Rejected {
            password_only: true,
            detail: "server only accepts password authentication; LabLink never stores passwords"
                .into(),
        }
    });
    // auth_check_interval_s is 30 s in the fast config: recovery must not wait for it.
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    let s = wait_for(&d, "jetson-a", 15, "auth failed", |s| {
        s.ssh_auth == AuthState::Failed
    });
    assert_eq!(s.color, Color::Yellow);
    assert!(
        s.reasons.iter().any(|r| r.contains("password")),
        "{:?}",
        s.reasons
    );

    // Server fixed: key accepted. sshd restarts (port briefly refuses).
    net.host("10.9.0.31", |h| {
        h.auth = AuthOutcome::Ok {
            hostname: Some("jetson-a-host".into()),
        };
        h.port = PortMode::Refused;
    });
    wait_for(&d, "jetson-a", 15, "port closed", |s| {
        s.ssh_port == PortState::Closed
    });
    net.host("10.9.0.31", |h| h.port = PortMode::Open);
    let s = wait_for(&d, "jetson-a", 15, "green after key accepted", |s| {
        s.color == Color::Green
    });
    assert_eq!(s.ssh_auth, AuthState::Ok);
    assert!(s.reasons.is_empty(), "stale reasons: {:?}", s.reasons);
    let detail: DeviceDetail = d
        .client()
        .call_typed(&Request::Inspect {
            device: "jetson-a".into(),
        })
        .unwrap();
    assert!(
        detail
            .last_error
            .as_deref()
            .is_none_or(|e| !e.contains("password")),
        "stale login error kept: {:?}",
        detail.last_error
    );
    assert!(detail
        .learned_hostnames
        .contains(&"jetson-a-host".to_string()));
    let k = kinds(&history(&d, "jetson-a"))
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let failed = k
        .iter()
        .position(|x| x == "auth_failed")
        .expect("auth_failed recorded");
    let ok = k
        .iter()
        .rposition(|x| x == "auth_ok")
        .expect("auth_ok recorded");
    assert!(ok > failed, "{k:?}");
    d.stop().unwrap();
}

#[test]
fn adopt_with_profile_network_only_and_login_recheck() {
    use lablink_core::profile::{Capability, Profile};
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.77",
        FakeHost::ssh_host(vec![fake_key("box")], "aa:00:00:00:00:77"),
    );
    let mut robot = FakeHost::ssh_host(vec![], "aa:00:00:00:00:88");
    robot.port = PortMode::Refused;
    net.add("10.9.0.88", robot);
    let cfg = fast_config(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\ndevices:\n  - name: gw\n    expected_ips: [10.9.0.99]\n",
    );
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    // A Jetson with label and user, adopted in one request; nothing pinned.
    let s: DeviceStatus = d
        .client()
        .call_typed(&Request::Adopt {
            site: None,
            ip: "10.9.0.77".into(),
            name: "box".into(),
            label: Some("Bench Jetson".into()),
            username: Some("ops".into()),
            profile: Some("jetson".into()),
            ssh: None,
        })
        .unwrap();
    assert_eq!(s.label.as_deref(), Some("Bench Jetson"));
    assert_eq!(s.username.as_deref(), Some("ops"));
    assert_eq!(s.profile, Some(Profile::Jetson));
    assert_eq!(
        s.capabilities,
        [
            Capability::Network,
            Capability::Ssh,
            Capability::Gpu,
            Capability::Jetson
        ]
    );
    let detail: DeviceDetail = d
        .client()
        .call_typed(&Request::Inspect {
            device: "box".into(),
        })
        .unwrap();
    assert!(detail.pinned_keys.is_empty(), "adopting never pins");
    assert_eq!(detail.overrides.profile, Some(Profile::Jetson));
    // A robot without SSH: network-only, never YELLOW for a closed port.
    let s: DeviceStatus = d
        .client()
        .call_typed(&Request::Adopt {
            site: None,
            ip: "10.9.0.88".into(),
            name: "robot".into(),
            label: None,
            username: None,
            profile: Some("network_only".into()),
            ssh: None,
        })
        .unwrap();
    assert_eq!(s.ssh_port, PortState::Disabled);
    assert_eq!(s.capabilities, [Capability::Network]);
    let s = wait_for(&d, "robot", 15, "green", |s| s.color == Color::Green);
    assert_eq!(s.ssh_auth, AuthState::Disabled);
    // Unknown profiles and SSH changes on configured devices are refused.
    for (dev, changes) in [
        (
            "box",
            DeviceChanges {
                profile: Some("toaster".into()),
                ..Default::default()
            },
        ),
        (
            "gw",
            DeviceChanges {
                ssh: Some(false),
                ..Default::default()
            },
        ),
        (
            "gw",
            DeviceChanges {
                profile: Some("network_only".into()),
                ..Default::default()
            },
        ),
    ] {
        let e = d
            .client()
            .call(&Request::Set {
                device: dev.into(),
                changes,
            })
            .unwrap_err();
        assert!(
            matches!(e, lablink_core::client::ClientError::Api(ref a) if a.code == ErrorCode::BadRequest),
            "{dev}: {e}"
        );
    }
    // Pin the Jetson, let its login fail, then a recheck picks up the fix.
    net.host("10.9.0.77", |h| {
        h.auth = AuthOutcome::Rejected {
            password_only: false,
            detail: "denied".into(),
        }
    });
    let t: TrustReport = d
        .client()
        .call_typed(&Request::Trust {
            device: "box".into(),
            confirm: Some(vec![fake_key("box").fingerprint]),
            replace: false,
        })
        .unwrap();
    assert_eq!(t.action, "pinned");
    wait_for(&d, "box", 15, "auth failed", |s| {
        s.ssh_auth == AuthState::Failed
    });
    net.host("10.9.0.77", |h| h.auth = AuthOutcome::Ok { hostname: None });
    let _: DeviceStatus = d
        .client()
        .call_typed(&Request::Set {
            device: "box".into(),
            changes: DeviceChanges {
                recheck: true,
                ..Default::default()
            },
        })
        .unwrap();
    // Far sooner than the 300 s auth_check_interval.
    let s = wait_for(&d, "box", 10, "green after recheck", |s| {
        s.color == Color::Green
    });
    assert_eq!(s.identity, IdentityState::Verified);
    // Survives a restart: profile and network-only setting are persisted.
    d.stop().unwrap();
    let d = TestDaemon::start(
        fast_config(
            "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\n    active_scan: true\ndevices:\n  - name: gw\n    expected_ips: [10.9.0.99]\n",
        ),
        net,
        dir.path().into(),
        false,
    )
    .unwrap();
    assert_eq!(status(&d, "robot").ssh_port, PortState::Disabled);
    assert_eq!(status(&d, "box").profile, Some(Profile::Jetson));
    d.stop().unwrap();
}

#[test]
fn changed_key_seen_by_the_login_check_is_reverified_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("jetson-a")], JETSON_A_MAC),
    );
    // identity_check_interval_s is 30 in the fast config: anything well under
    // that proves the login check triggered the re-verification.
    let d = TestDaemon::start(
        fast_config(&jetson_cfg("")),
        net.clone(),
        dir.path().into(),
        true,
    )
    .unwrap();
    wait_for(&d, "jetson-a", 15, "green", |s| s.color == Color::Green);
    net.host("10.9.0.31", |h| {
        h.keys = vec![fake_key("impostor")];
        h.auth = AuthOutcome::HostKeyChanged;
    });
    let t0 = Instant::now();
    let _: DeviceStatus = d
        .client()
        .call_typed(&Request::Set {
            device: "jetson-a".into(),
            changes: DeviceChanges {
                recheck: true,
                ..Default::default()
            },
        })
        .unwrap();
    let s = wait_for(&d, "jetson-a", 10, "mismatch", |s| {
        s.identity == IdentityState::Mismatch
    });
    assert!(t0.elapsed() < Duration::from_secs(10));
    assert_eq!(s.color, Color::Red);
    let e = lablink_core::explain::explain(&s).unwrap();
    assert!(e.security_stop, "{e:?}");
    d.stop().unwrap();
}
