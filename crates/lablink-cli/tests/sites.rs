//! [integration, simulated] The `lablink` binary with two sites: `sites`,
//! `site`, `site use`, scoped `status`, ambiguous names (exit 8) and the
//! site config commands. A real daemon runs in-process on a simulated
//! network; HOME and every XDG directory point at a temporary directory.

use lablink_core::exit;
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, TestDaemon};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

struct Env {
    dir: tempfile::TempDir,
    daemon: TestDaemon,
}

/// Site Alpha is attached (10.9.0.0/24); Site Beta (10.20.30.0/24) is not.
/// Both have a `jetson`; only Alpha's answers.
fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("alpha-jetson")], "02:00:00:00:a0:31"),
    );
    let fa = fake_key("alpha-jetson").fingerprint;
    let cfg = fast_config(&format!(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n    devices:\n      - name: jetson\n        usernames: [ops]\n        expected_ips: [10.9.0.31]\n        host_key_fingerprints: [\"{fa}\"]\n      - name: gpu-workstation\n        expected_ips: [10.9.0.50]\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: club\n        cidr: 10.20.30.0/24\n    devices:\n      - name: jetson\n        expected_ips: [10.20.30.31]\n      - name: robot-a\n        ssh: false\n        expected_ips: [10.20.30.40]\n"
    ));
    let daemon = TestDaemon::start(cfg, net, dir.path().join("state"), false).unwrap();
    let e = Env { dir, daemon };
    let deadline = Instant::now() + Duration::from_secs(20);
    while code(&lablink(&e, &["status", "site-alpha/jetson"])) != exit::OK {
        assert!(Instant::now() < deadline, "site-alpha/jetson never GREEN");
        std::thread::sleep(Duration::from_millis(150));
    }
    e
}

fn lablink(e: &Env, args: &[&str]) -> Output {
    let home = e.dir.path().join("home");
    let _ = std::fs::create_dir_all(&home);
    Command::new(env!("CARGO_BIN_EXE_lablink"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env_remove("LABLINK_CONFIG")
        .env("LABLINK_SOCKET", &e.daemon.socket)
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn sites_status_scopes_and_away_semantics() {
    let e = setup();
    let o = lablink(&e, &["sites"]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    let t = out(&o);
    assert!(t.lines().next().unwrap().starts_with("SITE"), "{t}");
    assert!(
        t.contains("Site Alpha") && t.contains("ACTIVE") && t.contains("high"),
        "{t}"
    );
    assert!(t.contains("Site Beta") && t.contains("AWAY"), "{t}");
    assert!(t.contains("mode: auto"), "{t}");

    let v: Value = serde_json::from_str(&out(&lablink(&e, &["sites", "--json"]))).unwrap();
    assert_eq!(v["mode"]["mode"], "auto");
    assert_eq!(v["sites"][1]["state"], "away");

    let o = lablink(&e, &["site"]);
    let t = out(&o);
    assert!(
        t.starts_with("Site Alpha  ACTIVE  (confidence: high"),
        "{t}"
    );
    assert!(t.contains("host key"), "evidence is shown: {t}");
    assert!(t.contains("Away: Site Beta (site-beta)"), "{t}");
    let v: Value = serde_json::from_str(&out(&lablink(&e, &["site", "--json"]))).unwrap();
    assert_eq!(v["active"]["id"], "site-alpha");

    // Default `status`: the current site, then the other sites summarized.
    let t = out(&lablink(&e, &["status"]));
    assert!(t.starts_with("Site Alpha  ACTIVE"), "{t}");
    assert!(t.contains("\njetson "), "{t}");
    assert!(
        !t.contains("robot-a"),
        "AWAY devices are not listed by default: {t}"
    );
    assert!(t.contains("Other sites\n  Site Beta"), "{t}");
    assert!(t.contains("2 (not checked)"), "{t}");
    // --all lists both jetsons by site/name, AWAY devices as AWAY.
    let t = out(&lablink(&e, &["status", "--all"]));
    assert!(
        t.contains("site-alpha/jetson") && t.contains("site-beta/jetson"),
        "{t}"
    );
    assert!(
        t.lines()
            .any(|l| l.starts_with("robot-a ") && l.contains("AWAY")),
        "{t}"
    );
    let t = out(&lablink(&e, &["status", "--site", "site-beta"]));
    assert!(t.starts_with("Site Beta  AWAY"), "{t}");
    // An AWAY device is GRAY (exit 12), never RED (11).
    let o = lablink(&e, &["status", "site-beta/robot-a"]);
    assert_eq!(code(&o), exit::STATUS_GRAY, "{}", out(&o));
    assert!(out(&o).contains("Site is away"), "{}", out(&o));
    // ssh to an AWAY site's device is refused before ssh runs (its last
    // address may belong to another machine here); --force overrides.
    let o = lablink(&e, &["exec", "site-beta/jetson", "true"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE, "{}", err(&o));
    assert!(err(&o).contains("which is AWAY"), "{}", err(&o));
    // resolve: the address of an AWAY device is not handed out either (exit 5
    // like ssh/exec), unless --force; the daemon refuses one it has no
    // address for.
    let o = lablink(&e, &["resolve", "site-beta/jetson"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE, "{}", err(&o));
    // Doctor with --all: AWAY devices are listed but never fail the run.
    let o = lablink(&e, &["doctor", "--all", "--json", "site-beta/robot-a"]);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["devices"][0]["away"], true, "{v}");
    assert_eq!(code(&o), exit::OK, "{}", out(&o));
}

#[test]
fn bare_name_uses_the_confident_site_and_site_slash_name_always_works() {
    let e = setup();
    // Alpha is confirmed by a host key: the bare name means Alpha's jetson,
    // and the JSON result says which one was used.
    let o = lablink(&e, &["exec", "jetson", "true", "--json"]);
    let v: Value = serde_json::from_str(&out(&o)).unwrap_or_default();
    assert_eq!(v["id"], "site-alpha/jetson", "{} {}", out(&o), err(&o));
    let o = lablink(&e, &["status", "site-gamma/jetson"]);
    assert_eq!(code(&o), exit::DEVICE_NOT_FOUND, "{}", err(&o));
    assert!(err(&o).contains("unknown site 'site-gamma'"), "{}", err(&o));
    let o = lablink(&e, &["status", "site-beta/jetson", "--json"]);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["devices"][0]["id"], "site-beta/jetson");
}

#[test]
fn ambiguous_name_message_and_exit_code() {
    // Both sites on the same subnet and nothing answers: neither site is
    // confident, so `ssh jetson` must not guess.
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    let cfg = fast_config(
        "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.31]\n  - id: site-beta\n    name: Site Beta\n    networks:\n      - name: lab\n        cidr: 10.9.0.0/24\n    devices:\n      - name: jetson\n        expected_ips: [10.9.0.32]\n",
    );
    let daemon = TestDaemon::start(cfg, net, dir.path().join("state"), false).unwrap();
    let e = Env { dir, daemon };
    let o = lablink(&e, &["ssh", "jetson"]);
    assert_eq!(code(&o), exit::AMBIGUOUS, "{}", err(&o));
    assert_eq!(
        err(&o),
        "Ambiguous device 'jetson':\n\nSite Alpha / jetson\nSite Beta / jetson\n\nUse:\n  lablink ssh site-alpha/jetson\n  lablink ssh site-beta/jetson\n"
    );
    let o = lablink(&e, &["status", "jetson", "--json"]);
    assert_eq!(code(&o), exit::AMBIGUOUS);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["error"]["code"], "ambiguous");
    assert_eq!(v["error"]["candidates"][1]["id"], "site-beta/jetson");
    // Choosing the site by hand resolves it; `auto` goes back.
    let o = lablink(&e, &["site", "use", "site-beta"]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    let v: Value =
        serde_json::from_str(&out(&lablink(&e, &["status", "jetson", "--json"]))).unwrap();
    assert_eq!(v["devices"][0]["id"], "site-beta/jetson");
    assert!(out(&lablink(&e, &["site", "use", "auto"])).contains("mode: auto"));
    assert_eq!(code(&lablink(&e, &["ssh", "jetson"])), exit::AMBIGUOUS);
}

#[test]
fn site_add_and_rename_write_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.yaml");
    std::fs::write(
        &cfg,
        "networks:\n  - name: lab\n    cidr: 192.168.50.0/24\ndevices:\n  - name: jetson-a\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_lablink"))
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("cfg"))
            .env("LABLINK_SOCKET", "/nonexistent/lablink/test.sock")
            .output()
            .unwrap()
    };
    let p = cfg.to_str().unwrap();
    let o = run(&[
        "site",
        "add",
        "Makerspace",
        "--scan",
        "10.20.30.0/24",
        "--config",
        p,
    ]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    assert!(
        out(&o).contains("added site 'Makerspace' (makerspace)"),
        "{}",
        out(&o)
    );
    let c = lablink_core::Config::load(Path::new(p)).unwrap();
    assert_eq!(
        c.sites.len(),
        2,
        "the single-site file became site 'default' plus the new one"
    );
    assert_eq!(c.sites[0].id, "default");
    assert_eq!(c.sites[1].networks[0].cidr, "10.20.30.0/24");
    assert!(c.sites[1].networks[0].active_scan);
    let o = run(&["site", "add", "makerspace", "--config", p]);
    assert_ne!(code(&o), exit::OK, "duplicate name");
    let o = run(&[
        "site",
        "add",
        "Public",
        "--scan",
        "8.8.8.0/24",
        "--config",
        p,
    ]);
    assert_eq!(code(&o), exit::USAGE, "{}", err(&o));
    let o = run(&["site", "rename", "default", "Home Lab", "--config", p]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    let c = lablink_core::Config::load(Path::new(p)).unwrap();
    assert_eq!(
        (c.sites[0].id.as_str(), c.sites[0].name.as_str()),
        ("default", "Home Lab")
    );
    let o = run(&["check-config", p]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    assert!(out(&o).contains("2 sites"), "{}", out(&o));
}

/// A file from LabLink 0.1.x (single-site layout with a `wake:` section)
/// is accepted, and rewriting it in the `sites:` layout keeps the section.
#[test]
fn site_add_keeps_the_wake_section_of_a_0_1_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.yaml");
    std::fs::write(
        &cfg,
        "networks:\n  - name: wired_wake\n    cidr: 192.0.2.0/24\n    active_scan: false\ndevices:\n  - name: orin\n    usernames: [ops]\nchecks:\n  ws:\n    - disk\nwake:\n  ws:\n    mac: \"02:00:00:35:7b:ca\"\n    network: wired_wake\n    interface: \"eno1\"\n    port: 9\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_lablink"))
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("cfg"))
            .env("LABLINK_SOCKET", "/nonexistent/lablink/test.sock")
            .output()
            .unwrap()
    };
    let p = cfg.to_str().unwrap();
    let o = run(&["check-config", p]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    assert!(
        out(&o).contains("wake ws") && out(&o).contains("does not send Wake-on-LAN"),
        "{}",
        out(&o)
    );
    let before = lablink_core::Config::load(Path::new(p)).unwrap();
    let o = run(&["site", "add", "Makerspace", "--config", p]);
    assert_eq!(code(&o), exit::OK, "{}", err(&o));
    let text = std::fs::read_to_string(&cfg).unwrap();
    assert!(text.contains("sites:") && text.contains("wake:"), "{text}");
    let after = lablink_core::Config::load(Path::new(p)).unwrap();
    assert_eq!(after.wake, before.wake);
    assert_eq!(after.wake["ws"].mac, "02:00:00:35:7b:ca");
    assert_eq!(after.wake["ws"].interface, "eno1");
    assert_eq!(after.sites[0].networks, before.sites[0].networks);
    assert_eq!(after.sites[0].devices, before.sites[0].devices);
    assert_eq!(after.sites[0].checks, before.sites[0].checks);
}
