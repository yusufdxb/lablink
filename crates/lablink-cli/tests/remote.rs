//! [integration, simulated + loopback] Remote access through the `lablink`
//! binary. The LAN is a real daemon on a simulated network (or no daemon at
//! all); the tailnet address is a real TCP listener on a loopback address;
//! `ssh`, `ssh-keyscan` and `tailscale` are scripts that record what they
//! were asked and answer from files. No traffic leaves the machine.

use lablink_core::exit;
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, PortMode, TestDaemon};
use serde_json::Value;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const FAKE_SSH: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$FAKE_DIR/ssh-args"
case " $* " in
  *" -T "*) for last; do :; done; exec /bin/sh -c "$last" ;;
  *) exit 0 ;;
esac
"#;

/// Answers with the key lines stored for the scanned address.
const FAKE_KEYSCAN: &str = r#"#!/bin/sh
for last; do :; done
echo "$last" >> "$FAKE_DIR/keyscan-log"
[ -f "$FAKE_DIR/keys-$last" ] && cat "$FAKE_DIR/keys-$last"
exit 0
"#;

/// Prints the stored status document; stderr carries secrets on purpose.
const FAKE_TAILSCALE: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE_DIR/tailscale-log"
echo "To authenticate, visit: https://login.tailscale.com/a/LEAKURL123 tskey-auth-kLEAK1CNTRL-LeakSecretValue99" >&2
[ -f "$FAKE_DIR/ts-sleep" ] && sleep 30
cat "$FAKE_DIR/ts.json"
"#;

/// Strings that must never appear in any output or state file.
const SECRETS: &[&str] = &[
    "LEAKURL123",
    "login.tailscale.com",
    "LeakSecretValue99",
    "tskey-auth",
    "owner@example.com",
    "LEAKKEY",
];

const TS_IP: &str = "127.0.0.2";
const LAN_IP: &str = "127.0.0.3";

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn ts_running(tailnet: &str, peer_ip: &str) -> String {
    format!(
        r#"{{"BackendState":"Running","AuthURL":"https://login.tailscale.com/a/LEAKURL123",
        "CurrentTailnet":{{"Name":"owner@example.com","MagicDNSSuffix":"{tailnet}"}},
        "Self":{{"ID":"nSELF","DNSName":"laptop.{tailnet}.","TailscaleIPs":["100.64.0.1"],"Online":true,"PublicKey":"nodekey:LEAKKEY"}},
        "Peer":{{"nodekey:LEAKKEY":{{"ID":"nBOX","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":["{peer_ip}"],"Online":true}}}},
        "User":{{"1":{{"LoginName":"owner@example.com"}}}}}}"#
    )
}

struct Env {
    dir: tempfile::TempDir,
    daemon: Option<TestDaemon>,
    net: Option<std::sync::Arc<FakeNet>>,
    port: u16,
    _listeners: Vec<TcpListener>,
    config: PathBuf,
    state: PathBuf,
    path: String,
}

/// A free port that can be bound on both loopback addresses.
fn bind_pair() -> (u16, Vec<TcpListener>) {
    for _ in 0..50 {
        let a = TcpListener::bind(format!("{TS_IP}:0")).unwrap();
        let port = a.local_addr().unwrap().port();
        if let Ok(b) = TcpListener::bind(format!("{LAN_IP}:{port}")) {
            return (port, vec![a, b]);
        }
    }
    panic!("no common free port");
}

/// `devices` is appended under `devices:`; `{port}`, `{ssh}`, `{keyscan}`
/// and `{fp}` are substituted. With `daemon`, a daemon serves the same file.
fn setup(devices: &str, daemon: bool, with_tailscale: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let ssh = script(dir.path(), "fake-ssh", FAKE_SSH);
    let keyscan = script(dir.path(), "fake-keyscan", FAKE_KEYSCAN);
    if with_tailscale {
        script(&bin, "tailscale", FAKE_TAILSCALE);
    }
    let (port, listeners) = bind_pair();
    let fp = fake_key("box").fingerprint;
    let devices = devices
        .replace("{port}", &port.to_string())
        .replace("{fp}", &fp);
    let yaml = format!(
        "ssh:\n  binary: {}\n  keyscan_binary: {}\nnetworks:\n  - name: lab\n    cidr: 10.9.0.0/24\ndevices:\n{devices}",
        ssh.display(),
        keyscan.display()
    );
    let config = dir.path().join("config.yaml");
    std::fs::write(&config, &yaml).unwrap();
    let state = dir.path().join("cli-state");
    let (daemon, net) = if daemon {
        let net = FakeNet::new(&["10.9.0.2/24"]);
        net.add(
            "10.9.0.31",
            FakeHost::ssh_host(vec![fake_key("box")], "02:4c:4c:00:00:01"),
        );
        let d = TestDaemon::start(
            fast_config(&yaml),
            net.clone(),
            dir.path().join("dstate"),
            true,
        )
        .unwrap();
        (Some(d), Some(net))
    } else {
        (None, None)
    };
    // Only our bin directory and the basics: a real tailscale is never run.
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let e = Env {
        dir,
        daemon,
        net,
        port,
        _listeners: listeners,
        config,
        state,
        path,
    };
    e.keys(TS_IP, &[fake_key("box")]);
    e.keys(LAN_IP, &[fake_key("box")]);
    e.ts(&ts_running("tail-ex.ts.net", TS_IP));
    e
}

impl Env {
    fn keys(&self, ip: &str, keys: &[lablink_core::identity::HostKey]) {
        let text: String = keys
            .iter()
            .map(|k| format!("{ip} {} {}\n", k.key_type, k.public_key.as_ref().unwrap()))
            .collect();
        std::fs::write(self.dir.path().join(format!("keys-{ip}")), text).unwrap();
    }
    fn ts(&self, json: &str) {
        std::fs::write(self.dir.path().join("ts.json"), json).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_lablink"));
        c.args(args)
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", self.dir.path())
            .env("NO_COLOR", "1")
            .env("LABLINK_CONFIG", &self.config)
            .env("LABLINK_STATE_DIR", &self.state)
            .env("FAKE_DIR", self.dir.path())
            .env(
                "LABLINK_SOCKET",
                self.daemon
                    .as_ref()
                    .map(|d| d.socket.clone())
                    .unwrap_or_else(|| self.dir.path().join("no-daemon.sock")),
            );
        c.output().unwrap()
    }
    fn ssh_args(&self) -> Option<Vec<String>> {
        std::fs::read_to_string(self.dir.path().join("ssh-args"))
            .ok()
            .map(|t| t.lines().map(String::from).collect())
    }
    fn clear(&self) {
        for f in ["ssh-args", "tailscale-log", "keyscan-log"] {
            let _ = std::fs::remove_file(self.dir.path().join(f));
        }
    }
    fn log(&self, f: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(f)).unwrap_or_default()
    }
    fn wait_color(&self, dev: &str, color: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let o = self.run(&["status", dev, "--json"]);
            if json(&o)["devices"][0]["color"] == color {
                return;
            }
            assert!(Instant::now() < deadline, "{dev} never became {color}");
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    fn lan_down(&self) {
        self.net
            .as_ref()
            .unwrap()
            .host("10.9.0.31", |h| h.up = false);
        self.wait_color("box", "red");
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}): {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn opt(args: &[String], k: &str) -> Option<String> {
    args.iter()
        .find_map(|a| a.strip_prefix(&format!("{k}=")).map(String::from))
}

fn remote_dev(name: &str, extra: &str) -> String {
    format!(
        "  - name: {name}\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n    ssh_port: {{port}}\n    host_key_fingerprints: [\"{{fp}}\"]\n{extra}    remote:\n      tailscale:\n        address: box.tail-ex.ts.net\n        tailnet: tail-ex.ts.net\n        node_id: nBOX\n"
    )
}

#[test]
fn lan_success_is_the_unchanged_daemon_path() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    let o = e.run(&["exec", "box", "echo hi", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let j = json(&o);
    assert_eq!(
        (j["transport"].as_str(), j["ip"].as_str()),
        (Some("lan"), Some("10.9.0.31"))
    );
    let a = e.ssh_args().unwrap();
    assert_eq!(opt(&a, "HostName").as_deref(), Some("10.9.0.31"));
    let kh = opt(&a, "UserKnownHostsFile").unwrap();
    assert!(
        kh.starts_with(&*e.dir.path().join("dstate").to_string_lossy()),
        "daemon pins: {kh}"
    );
    assert_eq!(
        e.log("tailscale-log"),
        "",
        "Tailscale is not consulted while the LAN works"
    );
}

#[test]
fn lan_down_falls_back_to_verified_tailscale() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    e.lan_down();
    let o = e.run(&["exec", "box", "echo hi", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let j = json(&o);
    assert_eq!(j["transport"], "tailscale");
    assert_eq!(j["ip"], TS_IP);
    assert_eq!(j["stdout"], "hi\n");
    assert_eq!(j["identity_pinned"], true);
    let a = e.ssh_args().unwrap();
    assert_eq!(opt(&a, "HostName").as_deref(), Some(TS_IP));
    assert_eq!(opt(&a, "Port"), Some(e.port.to_string()));
    assert_eq!(
        opt(&a, "HostKeyAlias").as_deref(),
        Some("lablink.default.box")
    );
    assert_eq!(opt(&a, "StrictHostKeyChecking").as_deref(), Some("yes"));
    assert_eq!(
        opt(&a, "GlobalKnownHostsFile").as_deref(),
        Some("/dev/null")
    );
    assert_eq!(opt(&a, "UpdateHostKeys").as_deref(), Some("no"));
    assert!(!a
        .iter()
        .any(|x| x.contains("StrictHostKeyChecking=no") || x.contains("accept-new")));
    let kh = PathBuf::from(opt(&a, "UserKnownHostsFile").unwrap());
    assert_eq!(kh, e.state.join("remote/default.box.known_hosts"));
    let pins = std::fs::read_to_string(&kh).unwrap();
    let k = fake_key("box");
    assert_eq!(
        pins.lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>(),
        [format!(
            "lablink.default.box ssh-ed25519 {}",
            k.public_key.unwrap()
        )]
    );
    assert_eq!(
        std::fs::metadata(&kh).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The daemon's own pins are untouched by the fallback.
    let d = std::fs::read_to_string(e.dir.path().join("dstate/known_hosts")).unwrap();
    assert!(d.contains("lablink.default.box"));
    // Interactive ssh says which path it took.
    e.clear();
    let o = e.run(&["ssh", "box"]);
    assert_eq!(code(&o), 0);
    assert!(
        text(&o).contains(&format!("box -> ops@{TS_IP}:{} via tailscale", e.port)),
        "{}",
        text(&o)
    );
    // --transport lan keeps the old behaviour.
    let o = e.run(&["exec", "box", "true", "--transport", "lan"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
}

#[test]
fn both_unavailable_names_each_reason() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    e.lan_down();
    // Nothing listens on the tailnet address any more.
    e.ts(&ts_running("tail-ex.ts.net", "127.0.0.4"));
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE, "{}", text(&o));
    let j = json(&o);
    assert_eq!(j["error"]["code"], "ssh_refused");
    assert!(j["error"]["message"]
        .as_str()
        .unwrap()
        .contains("tailscale box.tail-ex.ts.net (127.0.0.4)"));
    assert!(e.ssh_args().is_none());
}

#[test]
fn identity_mismatch_on_the_lan_never_falls_back() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    e.net.as_ref().unwrap().host("10.9.0.31", |h| {
        h.keys = vec![fake_key("impostor")];
        h.port = PortMode::Refused;
    });
    e.wait_color("box", "yellow");
    e.net
        .as_ref()
        .unwrap()
        .host("10.9.0.31", |h| h.port = PortMode::Open);
    e.wait_color("box", "red");
    for args in [
        &["exec", "box", "true"][..],
        &["ssh", "box"],
        &["exec", "box", "true", "--transport", "tailscale"],
        &["exec", "box", "true", "--force"],
    ] {
        let o = e.run(args);
        assert_eq!(code(&o), exit::IDENTITY_MISMATCH, "{args:?}: {}", text(&o));
    }
    assert!(e.ssh_args().is_none(), "ssh never ran");
    assert_eq!(e.log("tailscale-log"), "", "no fallback was attempted");
}

#[test]
fn tailscale_mitm_unauthenticated_and_wrong_tailnet() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    e.lan_down();

    // Something else answers on the tailnet address.
    e.keys(TS_IP, &[fake_key("mitm")]);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::IDENTITY_MISMATCH, "{}", text(&o));
    assert_eq!(json(&o)["error"]["code"], "host_key_mismatch");
    assert!(json(&o)["error"]["message"]
        .as_str()
        .unwrap()
        .contains(&fake_key("mitm").fingerprint));
    let o = e.run(&["ssh", "box"]);
    assert_eq!(code(&o), exit::IDENTITY_MISMATCH);
    assert!(e.ssh_args().is_none());
    assert!(
        !e.state.join("remote/default.box.known_hosts").exists(),
        "nothing pinned from a mismatch"
    );
    e.keys(TS_IP, &[fake_key("box")]);

    e.clear();
    e.ts(r#"{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/LEAKURL123"}"#);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    assert_eq!(json(&o)["error"]["code"], "tailscale_unauthenticated");
    assert!(
        !e.log("keyscan-log").contains(TS_IP),
        "nothing sent while logged out"
    );

    e.ts(r#"{"BackendState":"Stopped"}"#);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(json(&o)["error"]["code"], "tailscale_stopped");

    e.ts(&ts_running("tail-other.ts.net", TS_IP));
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::REFUSED, "{}", text(&o));
    assert_eq!(json(&o)["error"]["code"], "tailnet_mismatch");

    // The device was replaced in the tailnet: same name, other node.
    e.ts(&ts_running("tail-ex.ts.net", TS_IP).replace("\"ID\":\"nBOX\"", "\"ID\":\"nNEW\""));
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::REFUSED);
    assert_eq!(json(&o)["error"]["code"], "tailscale_peer_mismatch");

    e.ts(&ts_running("tail-ex.ts.net", TS_IP)
        .replace("box.tail-ex", "other.tail-ex")
        .replace("nBOX", "nOTHER"));
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    assert_eq!(json(&o)["error"]["code"], "tailscale_peer_not_found");
    assert!(e.ssh_args().is_none());
}

#[test]
fn devices_without_remote_behave_exactly_as_before() {
    let e = setup(
        "  - name: box\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n    host_key_fingerprints: [\"{fp}\"]\n",
        true,
        true,
    );
    e.wait_color("box", "green");
    e.lan_down();
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    assert_eq!(json(&o)["error"]["code"], "unreachable");
    let o = e.run(&["exec", "box", "true", "--transport", "tailscale"]);
    assert_eq!(code(&o), exit::USAGE);
    assert_eq!(e.log("tailscale-log"), "");
    // And without a daemon: exit 3 as before.
    drop(e);
    let e = setup(
        "  - name: box\n    expected_ips: [10.9.0.31]\n",
        false,
        true,
    );
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DAEMON_UNAVAILABLE);
    assert_eq!(json(&o)["error"]["code"], "daemon_unavailable");
}

fn standalone_dev() -> String {
    format!(
        "  - name: box\n    usernames: [ops]\n    expected_ips: [{LAN_IP}]\n    ssh_port: {{port}}\n    host_key_fingerprints: [\"{{fp}}\"]\n    remote:\n      tailscale:\n        address: box.tail-ex.ts.net\n        tailnet: tail-ex.ts.net\n        node_id: nBOX\n"
    )
}

#[test]
fn without_a_daemon_lan_first_then_tailscale() {
    // The client situation on macOS (no lablinkd) or with the daemon stopped.
    let e = setup(&standalone_dev(), false, true);
    let o = e.run(&["exec", "box", "echo hi", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert_eq!(
        (json(&o)["transport"].as_str(), json(&o)["ip"].as_str()),
        (Some("lan"), Some(LAN_IP))
    );
    assert_eq!(e.log("tailscale-log"), "");
    let a = e.ssh_args().unwrap();
    assert_eq!(
        opt(&a, "HostKeyAlias").as_deref(),
        Some("lablink.default.box")
    );
    assert_eq!(opt(&a, "StrictHostKeyChecking").as_deref(), Some("yes"));

    // LAN address now answers with another machine's key: SECURITY STOP,
    // even though the tailnet path would work.
    e.clear();
    e.keys(LAN_IP, &[fake_key("neighbour")]);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::IDENTITY_MISMATCH, "{}", text(&o));
    assert_eq!(e.log("tailscale-log"), "", "no fallback past a mismatch");
    // The user can deliberately choose the tailnet.
    let o = e.run(&["exec", "box", "true", "--json", "--transport", "tailscale"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert_eq!(json(&o)["transport"], "tailscale");

    // LAN address silent/not SSH: falls back.
    e.clear();
    std::fs::remove_file(e.dir.path().join(format!("keys-{LAN_IP}"))).unwrap();
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert_eq!(json(&o)["transport"], "tailscale");
    assert_eq!(
        opt(&e.ssh_args().unwrap(), "HostName").as_deref(),
        Some(TS_IP)
    );
}

#[test]
fn cross_site_names_are_never_guessed() {
    let yaml_sites = |tailnet_b: &str| {
        format!(
            "sites:\n  - id: careslab\n    name: CARES Lab\n    devices:\n      - name: box\n        expected_ips: [{LAN_IP}]\n        ssh_port: {{port}}\n        host_key_fingerprints: [\"{{fp}}\"]\n        remote:\n          tailscale:\n            address: box.tail-ex.ts.net\n            tailnet: tail-ex.ts.net\n  - id: club\n    name: Robotics Club\n    devices:\n      - name: box\n        ssh_port: {{port}}\n        host_key_fingerprints: [\"{{fp}}\"]\n        remote:\n          tailscale:\n            address: box.{tailnet_b}\n            tailnet: {tailnet_b}\n"
        )
    };
    let e = setup("", false, true);
    let port = e.port.to_string();
    let fp = fake_key("box").fingerprint;
    let ssh = e.dir.path().join("fake-ssh");
    let ks = e.dir.path().join("fake-keyscan");
    std::fs::write(
        &e.config,
        format!(
            "ssh:\n  binary: {}\n  keyscan_binary: {}\n{}",
            ssh.display(),
            ks.display(),
            yaml_sites("tail-club.ts.net")
                .replace("{port}", &port)
                .replace("{fp}", &fp)
        ),
    )
    .unwrap();
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::AMBIGUOUS, "{}", text(&o));
    assert_eq!(json(&o)["error"]["candidates"].as_array().unwrap().len(), 2);
    // The club device lives in another tailnet than this client's.
    let o = e.run(&["exec", "club/box", "true", "--json"]);
    assert_eq!(code(&o), exit::REFUSED, "{}", text(&o));
    assert_eq!(json(&o)["error"]["code"], "tailnet_mismatch");
    let o = e.run(&["exec", "careslab/box", "true", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let a = e.ssh_args().unwrap();
    assert_eq!(
        opt(&a, "HostKeyAlias").as_deref(),
        Some("lablink.careslab.box")
    );
}

#[test]
fn missing_slow_or_broken_tailscale_cli() {
    // A Mac whose GUI-managed Tailscale has no CLI on PATH: the configured
    // Tailscale IP is used and the pinned host key is still required.
    if ["/usr/bin/tailscale", "/usr/local/bin/tailscale"]
        .iter()
        .any(|p| Path::new(p).exists())
    {
        eprintln!("skipped: a real Tailscale CLI is installed on this machine");
        return;
    }
    let with_node = standalone_dev()
        .replace(
            &format!("expected_ips: [{LAN_IP}]"),
            "expected_ips: [127.0.0.5]",
        )
        .replace(
            "address: box.tail-ex.ts.net",
            &format!("address: \"{TS_IP}\""),
        );
    // node_id configured: it cannot be checked, so the tailnet is not used.
    let e = setup(&with_node, false, false);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE, "{}", text(&o));
    assert_eq!(json(&o)["error"]["code"], "tailscale_missing");
    assert!(e.ssh_args().is_none());
    // Without node_id: host key only, and LabLink says so.
    let dev = with_node.replace("        node_id: nBOX\n", "");
    let e = setup(&dev, false, false);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let j = json(&o);
    assert_eq!(j["transport"], "tailscale");
    assert!(
        j["notes"][0].as_str().unwrap().contains("not checked"),
        "{j}"
    );
    e.keys(TS_IP, &[fake_key("mitm")]);
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::IDENTITY_MISMATCH, "{}", text(&o));

    // A MagicDNS name that does not resolve: DNS failure, distinctly.
    let e = setup(
        &standalone_dev()
            .replace(&format!("[{LAN_IP}]"), "[127.0.0.5]")
            .replace("        node_id: nBOX\n", ""),
        false,
        false,
    );
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    assert_eq!(json(&o)["error"]["code"], "dns_failure");

    // A hanging CLI is killed after its timeout; malformed output is not trusted.
    let e = setup(&dev, false, true);
    std::fs::write(e.dir.path().join("ts-sleep"), "").unwrap();
    let t = Instant::now();
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert!(json(&o)["notes"][0].as_str().unwrap().contains("timed out"));
    std::fs::remove_file(e.dir.path().join("ts-sleep")).unwrap();
    e.ts("{\"BackendState\": \"Running\", \"Peer\": {");
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), 0);
    assert!(json(&o)["notes"][0]
        .as_str()
        .unwrap()
        .contains("not valid JSON"));
}

#[test]
fn device_without_an_address_uses_the_daemons_choice() {
    // The daemon has never seen the device (no current address): resolve
    // says unreachable, and the device it meant (inspect) is used.
    let e = setup(
        &remote_dev("box", "").replace("10.9.0.31", "10.9.0.77"),
        true,
        true,
    );
    let r = e.run(&["resolve", "box", "--json"]);
    assert_eq!(
        code(&r),
        exit::DEVICE_UNREACHABLE,
        "the daemon has no address"
    );
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert_eq!(json(&o)["transport"], "tailscale");
}

#[test]
fn shared_names_without_remote_keep_their_exit_codes() {
    // Two sites with a `box` and no remote access anywhere: no daemon is
    // exit 3 exactly as before (not "ambiguous").
    let e = setup("", false, true);
    std::fs::write(
        &e.config,
        "sites:\n  - id: a\n    name: A\n    devices:\n      - name: box\n  - id: b\n    name: B\n    devices:\n      - name: box\n",
    )
    .unwrap();
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(code(&o), exit::DAEMON_UNAVAILABLE, "{}", text(&o));
    let o = e.run(&["ssh", "box"]);
    assert_eq!(code(&o), exit::DAEMON_UNAVAILABLE);
}

#[test]
fn remote_status_reports_every_path_without_logging_in() {
    let e = setup(&remote_dev("box", ""), true, true);
    e.wait_color("box", "green");
    let o = e.run(&["remote", "status", "box", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let j = json(&o);
    assert_eq!(j["daemon"]["lan"], "online");
    assert_eq!(j["would_use"]["transport"], "lan");
    assert_eq!(j["tailscale"]["state"], "running");
    assert_eq!(j["tailscale"]["tailnet"], "tail-ex.ts.net");
    assert_eq!(j["attempts"][0]["transport"], "tailscale");
    assert_eq!(j["attempts"][0]["result"], "ok");
    assert!(e.ssh_args().is_none(), "status never runs ssh");
    e.lan_down();
    let j = json(&e.run(&["remote", "status", "box", "--json"]));
    assert_eq!(j["would_use"]["transport"], "tailscale");
    let o = e.run(&["remote", "status"]);
    assert!(
        text(&o).contains("default/box: tailscale box.tail-ex.ts.net"),
        "{}",
        text(&o)
    );
    e.keys(TS_IP, &[fake_key("mitm")]);
    let o = e.run(&["remote", "status", "box"]);
    assert_eq!(code(&o), exit::IDENTITY_MISMATCH);
    assert!(text(&o).contains("SECURITY STOP"), "{}", text(&o));
}

#[test]
fn no_credentials_reach_output_state_or_bundles() {
    let e = setup(&standalone_dev(), false, true);
    std::fs::remove_file(e.dir.path().join(format!("keys-{LAN_IP}"))).unwrap();
    let mut out = String::new();
    for args in [
        &["exec", "box", "true", "--json"][..],
        &["exec", "box", "true"],
        &["ssh", "box"],
        &["remote", "status"],
        &["remote", "status", "--json"],
        &["remote", "status", "box"],
        &["remote", "status", "box", "--json"],
        &["remote", "setup"],
        &["remote", "setup", "--json"],
    ] {
        let o = e.run(args);
        assert!(code(&o) == 0, "{args:?}: {}", text(&o));
        out.push_str(&text(&o));
    }
    // Error paths too.
    e.ts(r#"{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/LEAKURL123","User":{"1":{"LoginName":"owner@example.com"}}}"#);
    let o = e.run(&["exec", "box", "true", "--json", "--transport", "tailscale"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    out.push_str(&text(&o));
    out.push_str(&text(&e.run(&["remote", "status", "box", "--json"])));
    let bdir = e.dir.path().join("bundles");
    std::fs::create_dir(&bdir).unwrap();
    let o = e.run(&[
        "support-bundle",
        "--output-dir",
        bdir.to_str().unwrap(),
        "--no-doctor",
    ]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    out.push_str(&text(&o));
    let x = e.dir.path().join("x");
    std::fs::create_dir(&x).unwrap();
    let tarball = std::fs::read_dir(&bdir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&x)
        .status()
        .unwrap()
        .success());
    let mut files = vec![];
    for d in [&e.state, &x] {
        collect(d, &mut files);
    }
    assert!(!files.is_empty());
    for f in files {
        out.push_str(&String::from_utf8_lossy(&std::fs::read(f).unwrap()));
    }
    for s in SECRETS {
        assert!(!out.contains(s), "{s} leaked into output/state/bundle");
    }
}

fn collect(d: &Path, v: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                collect(&p, v);
            } else {
                v.push(p);
            }
        }
    }
}

#[test]
fn remote_setup_changes_nothing() {
    let e = setup(&standalone_dev(), false, true);
    let files = || {
        let mut v = vec![];
        collect(e.dir.path(), &mut v);
        v.retain(|p| !p.ends_with("tailscale-log"));
        v.sort();
        v
    };
    let before = files();
    let o = e.run(&["remote", "setup", "--json"]);
    assert_eq!(code(&o), 0, "{}", text(&o));
    let j = json(&o);
    assert_eq!(j["tailscale"]["self_node_id"], "nSELF");
    let snippet = j["client_config_snippet"].as_str().unwrap();
    assert!(snippet.contains("node_id: nSELF"), "{snippet}");
    assert!(snippet.contains("tailnet: tail-ex.ts.net"), "{snippet}");
    assert!(
        snippet.contains("address: laptop.tail-ex.ts.net"),
        "{snippet}"
    );
    // Whatever keys this machine has are listed with real fingerprints.
    for k in j["host_keys"].as_array().unwrap() {
        assert!(lablink_core::config::valid_fingerprint(
            k["fingerprint"].as_str().unwrap()
        ));
    }
    assert!(j["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s.as_str().unwrap().contains("never forward port 22")));
    assert_eq!(before, files(), "setup wrote no files");
    assert_eq!(
        e.log("tailscale-log").trim(),
        "status --json",
        "only `status --json` is ever run"
    );
}
