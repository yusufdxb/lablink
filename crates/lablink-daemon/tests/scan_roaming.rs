//! Complete daemon regression: an IP's previous-site memo cannot suppress
//! identification at a new site that reuses the same subnet.
use lablink_core::model::{DiscoverReport, IdentityState};
use lablink_core::protocol::Request;
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, PortMode, TestDaemon};

#[test]
fn a_reused_ip_is_keyscanned_again_immediately_after_roaming() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let net = FakeNet::new(&["10.9.0.2/29"]);
    net.add(
        "10.9.0.1",
        FakeHost {
            port: PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "02:00:00:00:00:a1")
        },
    );
    net.with(|w| w.gateways.push("10.9.0.1".parse().unwrap()));
    net.add(
        "10.9.0.3",
        FakeHost::ssh_host(vec![fake_key("unknown-lab-host")], "02:00:00:00:a0:03"),
    );
    let key = fake_key("club-pc");
    let cfg = fast_config(&format!("sites:\n  - id: lab\n    name: Lab\n    networks:\n      - name: lan\n        cidr: 10.9.0.0/29\n        gateway_mac: 02:00:00:00:00:a1\n        active_scan: true\n  - id: club\n    name: Club\n    networks:\n      - name: lan\n        cidr: 10.9.0.0/29\n        gateway_mac: 02:00:00:00:00:b1\n        active_scan: true\n    devices:\n      - name: pc\n        host_key_fingerprints: [\"{}\"]\n", key.fingerprint));
    let daemon = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let _: DiscoverReport = daemon
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let scans = || {
        net.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.as_str() == "keyscan 10.9.0.3")
            .count()
    };
    let before = scans();
    assert!(before > 0, "initial site must actually populate the memo");
    net.host("10.9.0.1", |h| h.mac = Some("02:00:00:00:00:b1".into()));
    net.host("10.9.0.3", |h| {
        h.keys = vec![key.clone()];
        h.mac = Some("02:00:00:00:b0:03".into());
    });
    let report: DiscoverReport = daemon
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    assert!(
        scans() > before,
        "the previous site's ten-minute memo suppressed identification"
    );
    let pc = report.devices.iter().find(|d| d.id == "club/pc").unwrap();
    assert_eq!(pc.identity, IdentityState::Verified, "{pc:?}");
    assert_eq!(pc.ip.as_deref(), Some("10.9.0.3"));
    daemon.stop().unwrap();
}
