//! [integration, simulated] The Field Network (a roaming site): it is an
//! overlay that never parks the site you are at, and pinned devices of AWAY
//! sites that join it are recognized by their host key alone, keep their
//! home site and never appear twice. Hotspot clients claiming a device's
//! name or MAC never move, verify or condemn it. Complete daemons on a
//! simulated network; nothing touches the real network.

use lablink_core::model::*;
use lablink_core::protocol::Request;
use lablink_core::site::{SiteState, SitesReport};
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, TestDaemon};
use std::time::{Duration, Instant};

fn status(d: &TestDaemon, id: &str) -> DeviceStatus {
    let r: StatusReport = d
        .client()
        .call_typed(&Request::Status {
            device: Some(id.into()),
            site: None,
            all: false,
        })
        .unwrap();
    r.devices.into_iter().next().unwrap()
}

fn all(d: &TestDaemon) -> Vec<DeviceStatus> {
    let r: StatusReport = d
        .client()
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .unwrap();
    r.devices
}

fn site_state(d: &TestDaemon, id: &str) -> SiteState {
    let r: SitesReport = d.client().call_typed(&Request::Sites).unwrap();
    r.sites.iter().find(|s| s.id == id).unwrap().state
}

fn discover(d: &TestDaemon) {
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
}

fn discovered_ips(d: &TestDaemon) -> Vec<String> {
    let v: serde_json::Value = d.client().call(&Request::Discovered).unwrap();
    v["discovered"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h["ip"].as_str().map(str::to_string))
        .collect()
}

fn wait<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

const ORIN_MAC: &str = "02:00:00:00:a0:31";

/// Home (10.9.0.0/24, attached), a lab (10.20.30.0/24, not attached) and a
/// Field Network (10.77.0.0/24, attached once the hotspot is up). The orin
/// is pinned at the lab; `sensor` is a lab device without SSH; `robot` is
/// reached through the orin.
fn world() -> (std::sync::Arc<FakeNet>, lablink_core::Config) {
    let net = FakeNet::new(&["10.20.30.2/24"]);
    net.add(
        "10.20.30.31",
        FakeHost::ssh_host(vec![fake_key("orin")], ORIN_MAC),
    );
    let fp = fake_key("orin").fingerprint;
    let cfg = fast_config(&format!(
        "sites:\n  - id: home\n    name: Home\n    networks:\n      - name: lan\n        cidr: 10.9.0.0/24\n        active_scan: true\n    devices:\n      - name: desktop\n        ssh: false\n        expected_ips: [10.9.0.5]\n  - id: lab\n    name: Lab\n    networks:\n      - name: lab\n        cidr: 10.20.30.0/24\n        active_scan: true\n    devices:\n      - name: orin\n        usernames: [ops]\n        hostnames: [orin]\n        macs: [\"{ORIN_MAC}\"]\n        expected_ips: [10.20.30.31]\n        host_key_fingerprints: [\"{fp}\"]\n      - name: sensor\n        ssh: false\n        expected_ips: [10.20.30.40]\n      - name: robot\n        ssh: false\n        via: orin\n        expected_ips: [192.168.123.161]\n  - id: field-network\n    name: Field Network\n    roaming: true\n    networks:\n      - name: hotspot\n        cidr: 10.77.0.0/24\n        active_scan: true\n        interface: wlan0\n"
    ));
    (net, cfg)
}

/// Leave the lab and bring up the hotspot: the orin joins it at a new
/// address.
fn go_to_the_field(net: &FakeNet) {
    net.with(|w| w.local = vec!["10.77.0.1/24".parse().unwrap()]);
    net.move_host("10.20.30.31", "10.77.0.23");
}

#[test]
fn pinned_device_visits_the_field_network_without_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let (net, cfg) = world();
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    // At the lab first: verified, so its pin holds the public key.
    wait("orin green at the lab", 20, || {
        (status(&d, "lab/orin").color == Color::Green).then_some(())
    });
    assert_eq!(site_state(&d, "field-network"), SiteState::Away);
    let before = all(&d).len();

    go_to_the_field(&net);
    discover(&d);
    wait("field network active", 20, || {
        (site_state(&d, "field-network") == SiteState::Active
            && site_state(&d, "lab") == SiteState::Away)
            .then_some(())
    });
    let field_calls_from = net.calls().len();
    discover(&d);
    let s = wait("orin green on the field network", 30, || {
        let s = status(&d, "lab/orin");
        (s.color == Color::Green && s.ip.as_deref() == Some("10.77.0.23")).then_some(s)
    });
    assert_eq!(s.site, "lab", "keeps its home site");
    assert_eq!(s.visiting.as_deref(), Some("field-network"));
    assert_eq!(s.identity, IdentityState::Verified);
    assert_eq!(s.network_name.as_deref(), Some("hotspot"));
    let r: ResolveResult = d
        .client()
        .call_typed(&Request::Resolve {
            device: "orin".into(),
            batch: true,
        })
        .unwrap();
    assert_eq!(r.ip, "10.77.0.23");
    assert!(!r.site_away);

    // Same records: no duplicate, nothing adopted.
    let devices = all(&d);
    assert_eq!(devices.len(), before);
    assert_eq!(devices.iter().filter(|x| x.name == "orin").count(), 1);
    assert!(
        !discovered_ips(&d).contains(&"10.77.0.23".to_string()),
        "the orin is not listed as an unknown host"
    );

    // The robot behind the orin visits with it; the lab device without a
    // pin does not, and stays AWAY.
    let robot = status(&d, "lab/robot");
    assert_eq!(robot.visiting.as_deref(), Some("field-network"));
    let sensor = status(&d, "lab/sensor");
    assert_eq!(sensor.visiting, None);
    assert_eq!(sensor.site_state, SiteState::Away);
    assert_eq!(sensor.color, Color::Gray);
    assert!(
        !net.calls()[field_calls_from..]
            .iter()
            .any(|c| c.contains(" 10.20.30.")),
        "home-site addresses are never probed while visiting: {:?}",
        &net.calls()[field_calls_from..]
    );

    // A sighting on the Field Network is never evidence for the lab.
    assert_eq!(site_state(&d, "lab"), SiteState::Away);

    // Hotspot down, back at the lab: the orin is home again.
    net.with(|w| w.local = vec!["10.20.30.2/24".parse().unwrap()]);
    net.move_host("10.77.0.23", "10.20.30.31");
    discover(&d); // the simulated network sends no netlink events
    wait("back at the lab", 30, || {
        let s = status(&d, "lab/orin");
        (site_state(&d, "field-network") == SiteState::Away
            && s.color == Color::Green
            && s.ip.as_deref() == Some("10.20.30.31")
            && s.visiting.is_none())
        .then_some(())
    });
    d.stop().unwrap();
}

#[test]
fn hotspot_clients_claiming_a_name_or_mac_never_move_or_condemn_a_visitor() {
    let dir = tempfile::tempdir().unwrap();
    let (net, cfg) = world();
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait("orin green at the lab", 20, || {
        (status(&d, "lab/orin").color == Color::Green).then_some(())
    });
    // In the field the orin is switched off; a rogue client takes its MAC
    // and offers a different key.
    net.with(|w| w.local = vec!["10.77.0.1/24".parse().unwrap()]);
    net.host("10.20.30.31", |h| h.up = false);
    net.add(
        "10.77.0.66",
        FakeHost::ssh_host(vec![fake_key("rogue")], ORIN_MAC),
    );
    discover(&d);
    wait("field network active", 20, || {
        (site_state(&d, "field-network") == SiteState::Active).then_some(())
    });
    for _ in 0..3 {
        discover(&d);
    }
    std::thread::sleep(Duration::from_secs(3));
    let s = status(&d, "lab/orin");
    assert_ne!(s.ip.as_deref(), Some("10.77.0.66"), "a MAC never places it");
    assert_ne!(
        s.identity,
        IdentityState::Mismatch,
        "only its pinned key speaks for a visitor: {s:?}"
    );
    assert_ne!(s.color, Color::Green);
    assert!(discovered_ips(&d).contains(&"10.77.0.66".to_string()));

    // A client replaying the orin's public key without holding it is the
    // same security stop as at home: RED, never verified, never GREEN.
    let mut replay = FakeHost::ssh_host(vec![fake_key("orin")], "02:00:00:00:66:67");
    replay.holds_keys = false;
    net.add("10.77.0.67", replay);
    discover(&d);
    let s = wait("replay refused", 20, || {
        let s = status(&d, "lab/orin");
        (s.identity == IdentityState::Mismatch).then_some(s)
    });
    assert_eq!(s.color, Color::Red);
    let r: Result<ResolveResult, _> = d.client().call_typed(&Request::Resolve {
        device: "orin".into(),
        batch: true,
    });
    assert!(r.is_err(), "no SSH to a device in a security stop");
    d.stop().unwrap();
}
