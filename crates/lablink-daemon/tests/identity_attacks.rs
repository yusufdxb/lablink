//! [unit, simulated] Identity attacks from the LAN, driven through the
//! registry's public API (no daemon, no network). The scenarios are the
//! proofs of concept from the 0.3.1 adversarial review: each failed before
//! the fix it guards.

use lablink_core::config::Config;
use lablink_core::identity::{HostKey, Observation};
use lablink_core::model::{IdentityState, PortState};
use lablink_daemon::registry::{ProbeReport, Registry, UserKnown};
use lablink_daemon::testing::fake_key;
use lablink_discovery::{Interface, NeighState, Neighbor, Snapshot};
use lablink_ssh::KeyProof;
use std::net::IpAddr;
use std::time::Duration;

const CONFIG: &str = "sites:\n  - id: lab\n    name: Lab\n    networks:\n      - name: lan\n        cidr: 192.168.1.0/24\n    devices:\n      - name: jetson\n        hostnames: [jetson.local]\n";
const REAL: &str = "192.168.1.20";
const EVIL: &str = "192.168.1.66";
const SQUAT: &str = "192.168.1.30";
const REAL_MAC: &str = "aa:aa:aa:aa:aa:20";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn up(at: &str, port: PortState) -> ProbeReport {
    ProbeReport {
        ip: ip(at),
        up: true,
        port: Some(port),
        rtt: Some(Duration::from_millis(2)),
        method: "icmp",
        detail: None,
        icmp_answered: Some(true),
    }
}

fn down(at: &str) -> ProbeReport {
    ProbeReport {
        ip: ip(at),
        up: false,
        port: None,
        rtt: None,
        method: "none",
        detail: Some("ICMP echo timed out".into()),
        icmp_answered: Some(false),
    }
}

fn mdns(at: &str) -> Observation {
    Observation {
        ip: Some(ip(at)),
        mac: None,
        names: vec!["jetson.local.".into()],
        host_keys: vec![],
    }
}

fn registry(dir: &tempfile::TempDir, now: u64) -> Registry {
    let cfg = Config::parse(CONFIG, "test").unwrap();
    let mut r = Registry::new(cfg, dir.path().join("known_hosts"));
    let snap = Snapshot {
        interfaces: vec![Interface {
            index: 2,
            name: "eth0".into(),
            up: true,
            loopback: false,
            mac: None,
            addrs: vec!["192.168.1.10/24".parse().unwrap()],
        }],
        neighbors: [
            (REAL, REAL_MAC),
            (EVIL, "bb:bb:bb:bb:bb:66"),
            (SQUAT, "cc:cc:cc:cc:cc:30"),
        ]
        .iter()
        .map(|(i, m)| Neighbor {
            ip: ip(i),
            mac: Some(m.to_string()),
            ifindex: 2,
            state: NeighState::Reachable,
        })
        .collect(),
        gateways: vec![],
        ssids: vec![],
    };
    for (o, s) in r.set_snapshot(snap) {
        r.observe(&o, &s, None, now);
    }
    r.refresh_sites(now);
    r
}

/// jetson located at REAL, its key pinned with `lablink trust`, verified.
fn pinned(dir: &tempfile::TempDir, k: &HostKey, now: u64) -> Registry {
    let mut r = registry(dir, now);
    r.apply_probe("lab/jetson", &up(REAL, PortState::Open), now);
    let none = UserKnown::default();
    r.apply_keys("lab/jetson", ip(REAL), Ok(vec![k.clone()]), &none, now);
    r.trust(
        "lab/jetson",
        ip(REAL),
        std::slice::from_ref(k),
        std::slice::from_ref(&k.fingerprint),
        false,
        now,
    )
    .expect("trust");
    r.apply_keys("lab/jetson", ip(REAL), Ok(vec![k.clone()]), &none, now + 1);
    r.apply_key_proof("lab/jetson", ip(REAL), &KeyProof::Proven, now + 1);
    assert_eq!(
        r.device("lab/jetson").unwrap().identity,
        IdentityState::Verified
    );
    r
}

/// The monitor's identity check at `at`: key scan, then possession proof.
fn check_identity(r: &mut Registry, at: &str, keys: Vec<HostKey>, proof: KeyProof, now: u64) {
    r.apply_probe("lab/jetson", &up(at, PortState::Open), now);
    r.apply_keys("lab/jetson", ip(at), Ok(keys), &UserKnown::default(), now);
    r.apply_key_proof("lab/jetson", ip(at), &proof, now);
}

fn has_event(r: &Registry, kind: &str) -> bool {
    r.history(None, 1000)
        .unwrap_or_default()
        .iter()
        .any(|e| e.kind == kind)
}

/// A forged mDNS answer after one missed ping must not move a pinned,
/// verified device (it used to, silently, and `lablink resolve` then printed
/// the attacker's address).
#[test]
fn forged_mdns_cannot_move_a_verified_pinned_device() {
    let dir = tempfile::tempdir().unwrap();
    let k = fake_key("jetson-real");
    let mut now = 1_000_000;
    let mut r = pinned(&dir, &k, now);
    now += 5_000;
    r.apply_probe("lab/jetson", &down(REAL), now);
    r.observe(&mdns(EVIL), "mdns", None, now + 1);
    assert_eq!(r.resolve("jetson").unwrap().ip, REAL);
    assert_eq!(
        r.device("lab/jetson").unwrap().identity,
        IdentityState::Verified
    );
}

/// Once the device is offline a name sighting may move it (that is how
/// devices are found again), but a key that contradicts the pin at an
/// address claimed by name is a security stop, not "address reused".
#[test]
fn contradicting_key_at_a_name_claimed_address_is_a_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let k = fake_key("jetson-real");
    let evil = fake_key("attacker");
    let mut now = 1_000_000;
    let mut r = pinned(&dir, &k, now);
    for _ in 0..4 {
        now += 5_000;
        r.apply_probe("lab/jetson", &down(REAL), now);
    }
    r.observe(&mdns(EVIL), "mdns", None, now + 1);
    assert_eq!(
        r.device("lab/jetson").unwrap().rec.current_ip,
        Some(ip(EVIL))
    );
    r.apply_probe("lab/jetson", &up(EVIL, PortState::Open), now + 2);
    r.apply_keys(
        "lab/jetson",
        ip(EVIL),
        Ok(vec![evil]),
        &UserKnown::default(),
        now + 3,
    );
    assert_eq!(
        r.device("lab/jetson").unwrap().identity,
        IdentityState::Mismatch
    );
    assert!(has_event(&r, "identity_mismatch"));
    assert!(r.resolve("jetson").is_err(), "a MISMATCH is never resolved");
    // The real device presenting its pinned key heals it.
    let real = Observation {
        ip: Some(ip(REAL)),
        mac: Some(REAL_MAC.into()),
        names: vec![],
        host_keys: vec![k.clone()],
    };
    r.observe(&real, "keyscan", None, now + 10);
    assert_eq!(
        r.device("lab/jetson").unwrap().rec.current_ip,
        Some(ip(REAL))
    );
    check_identity(&mut r, REAL, vec![k], KeyProof::Proven, now + 11);
    let res = r.resolve("jetson").unwrap();
    assert_eq!(
        (res.ip.as_str(), res.identity),
        (REAL, IdentityState::Verified)
    );
}

/// A stranger answering ping at an old address (fail-over) is displaced as
/// soon as the real device is seen presenting its pinned key.
#[test]
fn key_verified_sighting_displaces_a_squatter() {
    let dir = tempfile::tempdir().unwrap();
    let k = fake_key("jetson-real");
    let mut now = 1_000_000;
    let mut r = pinned(&dir, &k, now);
    let old = Observation {
        ip: Some(ip(SQUAT)),
        mac: Some(REAL_MAC.into()),
        names: vec![],
        host_keys: vec![],
    };
    r.observe(&old, "neighbor", None, now);
    for _ in 0..3 {
        now += 5_000;
        r.apply_probe("lab/jetson", &down(REAL), now);
    }
    let squatter = Observation {
        ip: Some(ip(SQUAT)),
        mac: Some("cc:cc:cc:cc:cc:30".into()),
        names: vec![],
        host_keys: vec![],
    };
    r.observe(&squatter, "failover", Some("lab/jetson"), now);
    r.apply_probe("lab/jetson", &up(SQUAT, PortState::Closed), now);
    now += 5_000;
    let real = Observation {
        ip: Some(ip(REAL)),
        mac: Some(REAL_MAC.into()),
        names: vec![],
        host_keys: vec![k.clone()],
    };
    r.observe(&real, "keyscan", None, now);
    assert_eq!(
        r.device("lab/jetson").unwrap().rec.current_ip,
        Some(ip(REAL))
    );
    check_identity(&mut r, REAL, vec![k], KeyProof::Proven, now + 1);
    let res = r.resolve("jetson").unwrap();
    assert_eq!(
        (res.ip.as_str(), res.identity),
        (REAL, IdentityState::Verified)
    );
}

/// A machine replaying a device's public host key (keyscan only asks for
/// public keys) never makes the device Verified, never teaches LabLink its
/// MAC, and is a security stop once it fails the possession proof.
#[test]
fn replayed_public_key_is_never_verified() {
    let k = fake_key("jetson-real");
    let evil_mac = "bb:bb:bb:bb:bb:66";
    let replay = Observation {
        ip: Some(ip(EVIL)),
        mac: Some(evil_mac.into()),
        names: vec![],
        host_keys: vec![k.clone()],
    };
    for (proof, want) in [
        (
            KeyProof::Refused("the host could not sign with the pinned key".into()),
            IdentityState::Mismatch,
        ),
        (
            KeyProof::Inconclusive("connection closed".into()),
            IdentityState::Unverified,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut now = 1_000_000;
        let mut r = pinned(&dir, &k, now);
        for _ in 0..4 {
            now += 5_000;
            r.apply_probe("lab/jetson", &down(REAL), now);
        }
        // A scan sees the pinned key at EVIL: the device moves there to be
        // checked, but the sighting alone verifies nothing and learns no MAC.
        r.observe(&replay, "keyscan", None, now + 1);
        let d = r.device("lab/jetson").unwrap();
        assert_eq!(d.rec.current_ip, Some(ip(EVIL)));
        assert_ne!(d.identity, IdentityState::Verified);
        check_identity(&mut r, EVIL, vec![k.clone()], proof, now + 2);
        let d = r.device("lab/jetson").unwrap();
        assert_eq!(d.identity, want);
        assert!(!d.rec.learned_macs.contains(evil_mac));
        if want == IdentityState::Mismatch {
            assert!(r.resolve("jetson").is_err());
        } else {
            // No retry storm: the next key check waits for the periodic one.
            assert!(r.follow_up("lab/jetson", now + 3).keyscan.is_none());
        }
    }
}

/// An unpinned device pointed at a neighbour by a forged mDNS answer must not
/// import the neighbour's key from an IP-keyed ~/.ssh/known_hosts entry.
#[test]
fn forged_mdns_cannot_import_an_ip_keyed_known_hosts_entry() {
    let dir = tempfile::tempdir().unwrap();
    let neighbour = fake_key("lab-pc-once-trusted-by-ip");
    let now = 5_000_000;
    let mut r = registry(&dir, now);
    r.observe(&mdns(EVIL), "mdns", None, now);
    r.apply_probe("lab/jetson", &up(EVIL, PortState::Open), now);
    let uk = UserKnown {
        by_name: vec![],
        by_ip: vec![neighbour.clone()],
    };
    r.apply_keys("lab/jetson", ip(EVIL), Ok(vec![neighbour]), &uk, now + 10);
    assert_ne!(
        r.device("lab/jetson").unwrap().identity,
        IdentityState::Verified
    );
    assert!(r.pinned_view("lab/jetson").is_empty());
    assert!(!has_event(&r, "key_pinned"));
}

/// One device MAC of another site (a carried laptop, or a forged MAC) on
/// this link must not make that site ACTIVE, park the site whose subnet is
/// attached, and send bare names there.
#[test]
fn a_foreign_device_mac_cannot_flip_the_site() {
    let cfg = Config::parse(
        "sites:\n  - id: alpha\n    name: Alpha\n    networks:\n      - name: lan\n        cidr: 10.10.0.0/24\n    devices:\n      - name: jetson\n        hostnames: [jetson.local]\n  - id: beta\n    name: Beta\n    networks:\n      - name: lan\n        cidr: 10.20.0.0/24\n    devices:\n      - name: jetson\n      - name: laptop\n        macs: [02:00:00:00:00:bb]\n",
        "test",
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut r = Registry::new(cfg, dir.path().join("known_hosts"));
    let snap = Snapshot {
        interfaces: vec![Interface {
            index: 2,
            name: "eth0".into(),
            up: true,
            loopback: false,
            mac: None,
            addrs: vec!["10.10.0.5/24".parse().unwrap()],
        }],
        neighbors: vec![Neighbor {
            ip: ip("10.10.0.6"),
            mac: Some("02:00:00:00:00:bb".into()),
            ifindex: 2,
            state: NeighState::Reachable,
        }],
        gateways: vec![],
        ssids: vec![],
    };
    let now = 1_000;
    for (o, s) in r.set_snapshot(snap) {
        r.observe(&o, &s, None, now);
    }
    r.refresh_sites(now);
    let beta = r.decision("beta").unwrap();
    assert!(!beta.confident(), "{beta:?}");
    let alpha = r.decision("alpha").unwrap();
    assert_ne!(
        alpha.state,
        lablink_core::site::SiteState::Away,
        "{alpha:?}"
    );
    assert_ne!(r.resolve_ref("jetson").ok().as_deref(), Some("beta/jetson"));
}

/// A forged mDNS answer cannot send LabLink's probes to the Internet, and a
/// host name with control characters is never learned.
#[test]
fn name_answers_cannot_point_outside_the_lab_or_inject_names() {
    let dir = tempfile::tempdir().unwrap();
    let now = 1_000;
    let mut r = registry(&dir, now);
    r.observe(&mdns("198.51.100.7"), "mdns", None, now);
    assert_eq!(r.device("lab/jetson").unwrap().rec.current_ip, None);
    let hostile = Observation {
        ip: Some(ip("192.168.1.77")),
        mac: None,
        names: vec!["evil\u{1b}[2J.local".into()],
        host_keys: vec![],
    };
    r.observe(&hostile, "neighbor", None, now);
    let shown = r.discovered_view(now);
    assert!(shown
        .iter()
        .all(|h| h.hostname.as_deref().is_none_or(|n| !n.contains('\u{1b}'))));
}
