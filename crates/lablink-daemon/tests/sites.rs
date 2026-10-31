//! [integration, simulated] Sites: AWAY semantics, automatic detection,
//! manual override, ambiguous names, scan restriction and the migration of
//! a single-site cache. Complete daemons on a simulated network; nothing
//! touches the real network.

use lablink_core::client::ClientError;
use lablink_core::model::*;
use lablink_core::protocol::{ErrorCode, Request};
use lablink_core::site::{Confidence, SiteMode, SiteState, SitesReport};
use lablink_daemon::registry::{DeviceRecord, PinnedKey};
use lablink_daemon::store::{Batch, Store};
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

fn sites(d: &TestDaemon) -> SitesReport {
    d.client().call_typed(&Request::Sites).unwrap()
}

fn site<'a>(r: &'a SitesReport, id: &str) -> &'a lablink_core::site::SiteStatus {
    r.sites.iter().find(|s| s.id == id).unwrap()
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

fn resolve(d: &TestDaemon, name: &str) -> Result<ResolveResult, ClientError> {
    d.client().call_typed(&Request::Resolve {
        device: name.into(),
        batch: false,
    })
}

/// Site Alpha (attached, 10.9.0.0/24) and Site Beta (10.20.30.0/24, not
/// attached). Both have a device called `jetson`.
fn two_sites() -> (std::sync::Arc<FakeNet>, lablink_core::Config) {
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("alpha-jetson")], "02:00:00:00:a0:31"),
    );
    let fa = fake_key("alpha-jetson").fingerprint;
    let fb = fake_key("beta-jetson").fingerprint;
    let cfg = fast_config(&format!(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n        active_scan: true\n    devices:\n      - name: jetson\n        usernames: [ops]\n        expected_ips: [10.9.0.31]\n        host_key_fingerprints: [\"{fa}\"]\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: club\n        cidr: 10.20.30.0/24\n        active_scan: true\n    devices:\n      - name: jetson\n        usernames: [ops]\n        expected_ips: [10.20.30.31]\n        host_key_fingerprints: [\"{fb}\"]\n      - name: robot-a\n        ssh: false\n        expected_ips: [10.20.30.40]\n"
    ));
    (net, cfg)
}

#[test]
fn away_site_is_gray_never_probed_never_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let (net, cfg) = two_sites();
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    wait("site-alpha/jetson green", 20, || {
        (status(&d, "site-alpha/jetson").color == Color::Green).then_some(())
    });
    let r = sites(&d);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Active);
    assert_eq!(site(&r, "site-alpha").confidence, Confidence::High);
    assert_eq!(site(&r, "site-beta").state, SiteState::Away);
    assert!(
        site(&r, "site-beta").scan.is_some(),
        "no scanning while away"
    );

    // Beta's devices are AWAY: gray, explained, not failures.
    for id in ["site-beta/jetson", "site-beta/robot-a"] {
        let s = status(&d, id);
        assert_eq!(s.site_state, SiteState::Away, "{id}");
        assert_eq!(s.color, Color::Gray, "{id}");
        assert!(s.reasons[0].contains("away"), "{:?}", s.reasons);
        let e = lablink_core::explain::explain(&s).unwrap();
        assert_eq!(e.headline, "Site is away");
    }
    // Default scope: only the site you are at.
    let all: StatusReport = d
        .client()
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: false,
        })
        .unwrap();
    assert!(all.devices.iter().all(|x| x.site == "site-alpha"));
    let beta: StatusReport = d
        .client()
        .call_typed(&Request::Status {
            device: None,
            site: Some("site-beta".into()),
            all: false,
        })
        .unwrap();
    assert_eq!(beta.devices.len(), 2);

    // A user-requested discovery scans Alpha's network only.
    let rep: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let st = |n: &str| rep.stages.iter().find(|s| s.stage == n).unwrap();
    assert_eq!(st("active_scan:site-alpha/lab").result, "ok");
    assert_eq!(st("active_scan:site-beta/club").result, "skipped");
    assert!(st("active_scan:site-beta/club").detail.contains("away"));
    std::thread::sleep(Duration::from_millis(1500));
    let calls = net.calls();
    assert!(
        !calls.iter().any(|c| c.contains(" 10.20.30.")),
        "an AWAY site's addresses were touched: {:?}",
        calls
            .iter()
            .filter(|c| c.contains("10.20.30."))
            .collect::<Vec<_>>()
    );

    // `jetson` exists at both sites; Alpha is confirmed by its host key, so
    // the bare name means Alpha's, and the result says so.
    let r = resolve(&d, "jetson").unwrap();
    assert_eq!(r.id, "site-alpha/jetson");
    assert!(r.shared_name);
    assert_eq!(resolve(&d, "site-alpha/jetson").unwrap().ip, "10.9.0.31");
    d.stop().unwrap();
}

#[test]
fn manual_override_switches_what_is_probed_and_back_to_auto() {
    let dir = tempfile::tempdir().unwrap();
    let (net, cfg) = two_sites();
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    wait("alpha green", 20, || {
        (status(&d, "site-alpha/jetson").color == Color::Green).then_some(())
    });
    let r: SitesReport = d
        .client()
        .call_typed(&Request::SetSiteMode {
            site: Some("site-beta".into()),
        })
        .unwrap();
    assert_eq!(r.mode, SiteMode::Manual("site-beta".into()));
    assert_eq!(site(&r, "site-beta").state, SiteState::Active);
    assert_eq!(site(&r, "site-beta").confidence, Confidence::Manual);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Away);
    // Alpha's device is parked: gray, no longer probed.
    let s = status(&d, "site-alpha/jetson");
    assert_eq!((s.color, s.site_state), (Color::Gray, SiteState::Away));
    std::thread::sleep(Duration::from_millis(500));
    let before = net
        .calls()
        .iter()
        .filter(|c| c.ends_with(" 10.9.0.31"))
        .count();
    // Beta's devices are checked now (here they are unreachable).
    wait("beta probed", 10, || {
        net.calls()
            .iter()
            .any(|c| c.ends_with(" 10.20.30.31"))
            .then_some(())
    });
    std::thread::sleep(Duration::from_secs(3));
    let after = net
        .calls()
        .iter()
        .filter(|c| c.ends_with(" 10.9.0.31"))
        .count();
    assert_eq!(before, after, "an AWAY device was probed after the switch");
    // The bare name now means Beta's device (manual choice is confident).
    assert_eq!(status(&d, "jetson").id, "site-beta/jetson");
    // Persisted across a restart.
    d.stop().unwrap();
    let (net2, cfg2) = two_sites();
    let d = TestDaemon::start(cfg2, net2, dir.path().into(), false).unwrap();
    assert_eq!(sites(&d).mode, SiteMode::Manual("site-beta".into()));
    // Back to automatic detection.
    let r: SitesReport = d
        .client()
        .call_typed(&Request::SetSiteMode { site: None })
        .unwrap();
    assert_eq!(r.mode, SiteMode::Auto);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Active);
    let e = d
        .client()
        .call(&Request::SetSiteMode {
            site: Some("site-gamma".into()),
        })
        .unwrap_err();
    assert!(matches!(e, ClientError::Api(a) if a.code == ErrorCode::DeviceNotFound));
    d.stop().unwrap();
}

#[test]
fn ambiguous_name_is_refused_until_one_site_is_confident() {
    // Both sites use 10.9.0.0/24 and nothing tells them apart: both stay
    // UNKNOWN (no device answers), nothing is scanned, and `jetson` is
    // ambiguous.
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    let cfg = fast_config(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n        active_scan: true\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.31]\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n        active_scan: true\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.32]\n",
    );
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), true).unwrap();
    let r = sites(&d);
    assert!(
        r.sites.iter().all(|s| s.state == SiteState::Unknown),
        "{r:?}"
    );
    match resolve(&d, "jetson").unwrap_err() {
        ClientError::Api(a) => {
            assert_eq!(a.code, ErrorCode::Ambiguous);
            assert_eq!(a.code.exit_code(), lablink_core::exit::AMBIGUOUS);
            let ids: Vec<&str> = a.candidates.iter().map(|c| c.id.as_str()).collect();
            assert_eq!(ids, ["site-alpha/jetson", "site-beta/jetson"]);
            assert_eq!(
                a.ambiguity_text("ssh").unwrap(),
                "Ambiguous device 'jetson':\n\nSite Alpha / jetson\nSite Beta / jetson\n\nUse:\n  lablink ssh site-alpha/jetson\n  lablink ssh site-beta/jetson\n"
            );
        }
        e => panic!("{e:?}"),
    }
    // The status of a bare ambiguous name is refused too; site/name works.
    assert!(d
        .client()
        .call(&Request::Status {
            device: Some("jetson".into()),
            site: None,
            all: false
        })
        .is_err());
    // Unreachable at an unconfirmed site: gray, not red.
    let s = wait("offline at unconfirmed site", 20, || {
        let s = status(&d, "site-alpha/jetson");
        (s.network == NetworkState::Offline || s.discovery == DiscoveryState::NeverSeen)
            .then_some(s)
    });
    assert_ne!(s.color, Color::Red, "{s:?}");
    // No active scan of a contested subnet.
    let rep: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    assert!(rep
        .stages
        .iter()
        .filter(|s| s.stage.starts_with("active_scan:"))
        .all(|s| s.result == "skipped"));
    let swept: Vec<String> = net
        .calls()
        .into_iter()
        .filter(|c| !c.ends_with(" 10.9.0.31") && !c.ends_with(" 10.9.0.32"))
        .collect();
    assert!(
        swept.is_empty(),
        "no sweep of the contested subnet: {swept:?}"
    );
    // Choosing a site by hand makes the bare name unambiguous.
    let _: SitesReport = d
        .client()
        .call_typed(&Request::SetSiteMode {
            site: Some("site-beta".into()),
        })
        .unwrap();
    let e = resolve(&d, "jetson").unwrap_err().to_string();
    assert!(
        e.contains("site-beta/jetson") || e.contains("no known current address"),
        "{e}"
    );
    let st = status(&d, "jetson");
    assert_eq!(st.id, "site-beta/jetson");
    d.stop().unwrap();
}

#[test]
fn gateway_mac_and_host_keys_pick_the_right_same_subnet_site() {
    // Same subnet at both sites; each recorded its gateway's MAC.
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.1",
        FakeHost {
            port: lablink_daemon::testing::PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "02:00:00:00:00:b1")
        },
    );
    net.with(|w| w.gateways.push("10.9.0.1".parse().unwrap()));
    let cfg = fast_config(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n        gateway_mac: 02:00:00:00:00:a1\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n        gateway_mac: 02:00:00:00:00:b1\n",
    );
    let d = TestDaemon::start(cfg, net.clone(), dir.path().into(), false).unwrap();
    let r = sites(&d);
    assert_eq!(site(&r, "site-beta").state, SiteState::Active, "{r:?}");
    assert_eq!(site(&r, "site-beta").confidence, Confidence::Medium);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Away);
    assert!(site(&r, "site-alpha")
        .evidence
        .iter()
        .any(|e| e.kind == "gateway_mac_differs"));
    // Moving to the other place (the gateway answers with Alpha's MAC).
    net.host("10.9.0.1", |h| h.mac = Some("02:00:00:00:00:a1".into()));
    let _: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let r = sites(&d);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Active, "{r:?}");
    assert_eq!(site(&r, "site-beta").state, SiteState::Away);
    // A third place reusing the subnet: neither site, nothing scanned there.
    net.host("10.9.0.1", |h| h.mac = Some("02:00:00:00:00:c1".into()));
    let rep: DiscoverReport = d
        .client()
        .call_typed(&Request::Discover { scan_cidr: None })
        .unwrap();
    let r = sites(&d);
    assert!(r.sites.iter().all(|s| s.state == SiteState::Away), "{r:?}");
    assert!(rep.devices.is_empty());
    d.stop().unwrap();
}

#[test]
fn host_key_of_a_known_device_settles_a_tie_and_teaches_the_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.32",
        FakeHost::ssh_host(vec![fake_key("beta-jetson")], "02:00:00:00:b0:32"),
    );
    net.add(
        "10.9.0.1",
        FakeHost {
            port: lablink_daemon::testing::PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "02:00:00:00:00:b1")
        },
    );
    net.with(|w| w.gateways.push("10.9.0.1".parse().unwrap()));
    let fb = fake_key("beta-jetson").fingerprint;
    let cfg = fast_config(&format!(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.31]\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.32]\n        host_key_fingerprints: [\"{fb}\"]\n"
    ));
    let d = TestDaemon::start(cfg.clone(), net.clone(), dir.path().into(), false).unwrap();
    let r = wait("beta confirmed by host key", 20, || {
        let r = sites(&d);
        (site(&r, "site-beta").confidence == Confidence::High).then_some(r)
    });
    assert_eq!(site(&r, "site-beta").state, SiteState::Active);
    assert_eq!(site(&r, "site-alpha").state, SiteState::Away);
    assert!(site(&r, "site-beta")
        .evidence
        .iter()
        .any(|e| e.kind == "host_key"));
    // The gateway signature was learned and survives a restart: the next
    // visit is recognized before any device answers.
    d.stop().unwrap();
    net.host("10.9.0.32", |h| h.up = false);
    let d = TestDaemon::start(cfg, net, dir.path().into(), false).unwrap();
    let r = sites(&d);
    assert_eq!(site(&r, "site-beta").state, SiteState::Active, "{r:?}");
    assert_eq!(site(&r, "site-beta").confidence, Confidence::Medium);
    d.stop().unwrap();
}

#[test]
fn single_site_cache_is_migrated_to_site_ids() {
    let dir = tempfile::tempdir().unwrap();
    let k = fake_key("jetson-a");
    // A cache written before sites: rows keyed by bare names.
    {
        let (mut store, _) = Store::open(&dir.path().join("cache.db"), 1000).unwrap();
        let rec = DeviceRecord {
            name: "jetson-a".into(),
            pinned: vec![PinnedKey {
                key_type: k.key_type.clone(),
                fingerprint: k.fingerprint.clone(),
                public_key: k.public_key.clone(),
                source: "trust".into(),
                pinned_at_ms: 1,
            }],
            ..Default::default()
        };
        let adopted = DeviceRecord {
            name: "bench".into(),
            adopted: true,
            ..Default::default()
        };
        store
            .save(&Batch {
                devices: vec![
                    ("jetson-a".into(), serde_json::to_string(&rec).unwrap()),
                    ("bench".into(), serde_json::to_string(&adopted).unwrap()),
                ],
                events: vec![HistoryEvent {
                    ts_ms: 1,
                    device: Some("jetson-a".into()),
                    kind: "key_pinned".into(),
                    message: "pinned before sites existed".into(),
                }],
                ..Default::default()
            })
            .unwrap();
    }
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![k.clone()], "02:00:00:00:a0:31"),
    );
    // A single-site (legacy layout) config without the pin: it came from
    // `lablink trust` and lives in the cache.
    let cfg = fast_config(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n",
    );
    let d = TestDaemon::start(cfg, net, dir.path().into(), false).unwrap();
    let s = wait("verified from the migrated pin", 20, || {
        let s = status(&d, "jetson-a");
        (s.identity == IdentityState::Verified).then_some(s)
    });
    assert_eq!(s.id, "default/jetson-a");
    assert_eq!(s.site, "default");
    assert_eq!(
        status(&d, "bench").id,
        "default/bench",
        "adopted device kept"
    );
    let v = d
        .client()
        .call(&Request::History {
            device: Some("jetson-a".into()),
            limit: 100,
        })
        .unwrap();
    let evs: Vec<HistoryEvent> = serde_json::from_value(v["events"].clone()).unwrap();
    assert!(
        evs.iter()
            .any(|e| e.message == "pinned before sites existed"),
        "{evs:?}"
    );
    d.stop().unwrap();
    let (store, _) = Store::open(&dir.path().join("cache.db"), 1000).unwrap();
    let rows: Vec<String> = store
        .load(10)
        .unwrap()
        .devices
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(rows, ["default/bench", "default/jetson-a"]);
}

#[test]
fn onboarding_identity_is_scoped_persisted_and_does_not_change_pins() {
    use lablink_core::protocol::DeviceChanges;
    let dir = tempfile::tempdir().unwrap();
    let (net, cfg) = two_sites();
    let d = TestDaemon::start(cfg.clone(), net.clone(), dir.path().into(), false).unwrap();
    wait("alpha green", 20, || {
        (status(&d, "site-alpha/jetson").color == Color::Green).then_some(())
    });
    let before = resolve(&d, "site-alpha/jetson").unwrap();
    d.client()
        .call(&Request::Set {
            device: "site-alpha/jetson".into(),
            changes: DeviceChanges {
                identity_file: Some("/tmp/lablink-test-key".into()),
                recheck: true,
                ..Default::default()
            },
        })
        .unwrap();
    let after = resolve(&d, "site-alpha/jetson").unwrap();
    assert_eq!(
        after.ssh_options.get("IdentityFile").map(String::as_str),
        Some("/tmp/lablink-test-key")
    );
    assert_eq!(after.host_key_alias, before.host_key_alias);
    assert_eq!(after.known_hosts_file, before.known_hosts_file);
    // Even a failed update must leave the previous choice and pins intact.
    for hostile in [
        "relative",
        "-i/key",
        "/tmp/$(id)",
        "/tmp/a%h",
        "/tmp/a b",
        "/tmp/a\nb",
    ] {
        assert!(d
            .client()
            .call(&Request::Set {
                device: "site-alpha/jetson".into(),
                changes: DeviceChanges {
                    identity_file: Some(hostile.into()),
                    ..Default::default()
                }
            })
            .is_err());
    }
    assert_eq!(
        resolve(&d, "site-alpha/jetson").unwrap().ssh_options,
        after.ssh_options
    );
    let beta: lablink_core::model::DeviceDetail = d
        .client()
        .call_typed(&Request::Inspect {
            device: "site-beta/jetson".into(),
        })
        .unwrap();
    assert_eq!(beta.status.site, "site-beta");
    d.stop().unwrap();
    let d = TestDaemon::start(cfg, net, dir.path().into(), false).unwrap();
    wait("restored identity", 20, || {
        resolve(&d, "site-alpha/jetson").ok()
    });
    assert_eq!(
        resolve(&d, "site-alpha/jetson")
            .unwrap()
            .ssh_options
            .get("IdentityFile"),
        after.ssh_options.get("IdentityFile")
    );
    assert_eq!(
        resolve(&d, "site-alpha/jetson").unwrap().host_key_alias,
        before.host_key_alias
    );
    d.stop().unwrap();
}
