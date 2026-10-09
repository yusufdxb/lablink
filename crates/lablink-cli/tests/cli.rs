//! [integration, simulated + localhost] End-to-end tests of the `lablink`
//! binary: a real daemon runs in-process on a simulated network, the CLI runs
//! as a subprocess, and `ssh` is replaced by a shell script that executes the
//! "remote" command locally and records its arguments.

use lablink_core::exit;
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, PortMode, TestDaemon};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const FAKE_SSH: &str = r#"#!/bin/sh
# Fake OpenSSH client for tests: record argv, then run the "remote" command locally.
printf '%s\n' "$@" > "$FAKE_SSH_ARGS"
case " $* " in
  *" -T "*) for last; do :; done; exec /bin/sh -c "$last" ;;
  *) exit 0 ;;
esac
"#;

struct Env {
    _dir: tempfile::TempDir,
    daemon: TestDaemon,
    net: std::sync::Arc<FakeNet>,
    args_file: PathBuf,
}

fn setup(extra_devices: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("fake-ssh");
    std::fs::write(&ssh, FAKE_SSH).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("jetson-a")], "02:4c:4c:00:00:01"),
    );
    let fp = fake_key("jetson-a").fingerprint;
    let cfg = fast_config(&format!(
        "ssh:\n  binary: {}\nnetworks:\n  - name: lab\n    cidr: 10.9.0.0/24\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n    host_key_fingerprints: [\"{fp}\"]\n{extra_devices}",
        ssh.display()
    ));
    let state = dir.path().join("state");
    let daemon = TestDaemon::start(cfg, net.clone(), state, true).unwrap();
    let args_file = dir.path().join("ssh-args");
    Env {
        _dir: dir,
        daemon,
        net,
        args_file,
    }
}

fn lablink(env: Option<&Env>, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lablink"));
    // Never read the developer's own config file.
    c.args(args)
        .env("NO_COLOR", "1")
        .env("LABLINK_CONFIG", "/nonexistent/lablink/config.yaml");
    match env {
        Some(e) => {
            c.env("LABLINK_SOCKET", &e.daemon.socket)
                .env("FAKE_SSH_ARGS", &e.args_file);
        }
        None => {
            c.env("LABLINK_SOCKET", "/nonexistent/lablink/test.sock");
        }
    }
    c.output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&o.stdout)))
}

fn wait_color(e: &Env, dev: &str, color: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let o = lablink(Some(e), &["status", dev, "--json"]);
        if json(&o)["devices"][0]["color"] == color {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{dev} never became {color}: {}",
            String::from_utf8_lossy(&o.stdout)
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn recorded_args(e: &Env) -> Vec<String> {
    std::fs::read_to_string(&e.args_file)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn daemon_unavailable_is_exit_3_with_json_error() {
    for args in [
        &["status"][..],
        &["status", "jetson-a"],
        &["exec", "jetson-a", "true"],
        &["ssh", "jetson-a"],
        &["discover"],
    ] {
        let o = lablink(None, args);
        assert_eq!(code(&o), exit::DAEMON_UNAVAILABLE, "{args:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("lablinkd is not running"));
    }
    let o = lablink(None, &["status", "--json"]);
    let v = json(&o);
    assert_eq!(v["status"], "lablink_error");
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["error"]["code"], "daemon_unavailable");
}

#[test]
fn status_json_schema_is_stable() {
    let e = setup("  - name: never\n    expected_ips: [10.9.0.99]\n");
    wait_color(&e, "jetson-a", "green");
    let v = json(&lablink(Some(&e), &["status", "--json"]));
    assert_eq!(v["schema_version"], 1);
    assert!(
        v["daemon"]["version"].is_string()
            && v["daemon"]["pid"].is_u64()
            && v["daemon"]["uptime_s"].is_u64()
    );
    let expected: std::collections::BTreeSet<&str> = [
        "name",
        "label",
        "color",
        "ip",
        "discovery",
        "network",
        "ssh_port",
        "ssh_auth",
        "identity",
        "latency_ms",
        "last_seen_ms",
        "username",
        "interface",
        "network_name",
        "via",
        "monitoring",
        "reasons",
        "services",
        // Added in 0.3.0 (additive).
        "profile",
        "capabilities",
        "id",
        "site",
        "site_name",
        "site_state",
    ]
    .into_iter()
    .collect();
    let allowed = |k: &str, v: &str| -> bool {
        match k {
            "color" => ["green", "yellow", "red", "gray"].contains(&v),
            "network" => ["unknown", "online", "degraded", "offline"].contains(&v),
            "ssh_port" => ["unknown", "open", "closed", "filtered", "disabled"].contains(&v),
            "ssh_auth" => ["unknown", "ok", "failed", "unavailable", "disabled"].contains(&v),
            "identity" => ["unknown", "unverified", "verified", "mismatch"].contains(&v),
            "discovery" => ["never_seen", "located", "searching"].contains(&v),
            "site_state" => ["active", "away", "unknown"].contains(&v),
            _ => true,
        }
    };
    for d in v["devices"].as_array().unwrap() {
        let keys: std::collections::BTreeSet<&str> =
            d.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, expected);
        for k in [
            "color",
            "network",
            "ssh_port",
            "ssh_auth",
            "identity",
            "discovery",
            "site_state",
        ] {
            assert!(allowed(k, d[k].as_str().unwrap()), "{k}={}", d[k]);
        }
        assert!(d["reasons"].is_array() && d["monitoring"].is_boolean());
        assert!(d["latency_ms"].is_null() || d["latency_ms"].is_u64());
        assert!(d["last_seen_ms"].is_null() || d["last_seen_ms"].is_u64());
    }
    let jetson_a = &v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "jetson-a")
        .unwrap();
    assert_eq!(jetson_a["ip"], "10.9.0.31");
    assert_eq!(jetson_a["identity"], "verified");
    assert_eq!(jetson_a["ssh_auth"], "ok");
    // Human output has the documented header.
    let h = String::from_utf8(lablink(Some(&e), &["status"]).stdout).unwrap();
    assert!(h.starts_with("DEVICE    STATE"), "{h}");
    assert!(h.contains("jetson-a  GREEN  10.9.0.31"), "{h}");
}

#[test]
fn status_exit_codes_follow_color() {
    let e = setup("  - name: never\n    expected_ips: [10.9.0.99]\n  - name: closed\n    expected_ips: [10.9.0.40]\n");
    e.net.add(
        "10.9.0.40",
        FakeHost {
            port: PortMode::Refused,
            ..FakeHost::ssh_host(vec![], "aa:00:00:00:00:40")
        },
    );
    wait_color(&e, "jetson-a", "green");
    wait_color(&e, "closed", "yellow");
    assert_eq!(code(&lablink(Some(&e), &["status", "jetson-a"])), exit::OK);
    assert_eq!(
        code(&lablink(Some(&e), &["status", "closed"])),
        exit::STATUS_YELLOW
    );
    assert_eq!(
        code(&lablink(Some(&e), &["status", "never"])),
        exit::STATUS_GRAY
    );
    assert_eq!(
        code(&lablink(Some(&e), &["status", "nope"])),
        exit::DEVICE_NOT_FOUND
    );
    assert_eq!(
        code(&lablink(Some(&e), &["status"])),
        exit::OK,
        "fleet status succeeds whatever the colors"
    );
    e.net.host("10.9.0.31", |h| h.up = false);
    wait_color(&e, "jetson-a", "red");
    assert_eq!(
        code(&lablink(Some(&e), &["status", "jetson-a"])),
        exit::STATUS_RED
    );
}

#[test]
fn exec_preserves_exit_code_output_and_pins_host_key() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    let o = lablink(
        Some(&e),
        &["exec", "jetson-a", "echo out; echo err >&2; exit 42"],
    );
    assert_eq!(code(&o), 42);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "out\n");
    assert_eq!(String::from_utf8_lossy(&o.stderr), "err\n");
    let a = recorded_args(&e);
    for want in [
        "HostName=10.9.0.31",
        "HostKeyAlias=lablink.default.jetson-a",
        "StrictHostKeyChecking=yes",
        "BatchMode=yes",
        "UpdateHostKeys=no",
        "-T",
        "-n",
    ] {
        assert!(a.contains(&want.to_string()), "{want} missing from {a:?}");
    }
    let kh = a
        .iter()
        .find(|x| x.starts_with("UserKnownHostsFile="))
        .unwrap();
    assert!(
        Path::new(kh.trim_start_matches("UserKnownHostsFile=")).exists(),
        "known_hosts must exist before ssh runs"
    );
    let l = a.iter().position(|x| x == "-l").unwrap();
    assert_eq!(a[l + 1], "ops");
    assert_eq!(
        &a[a.len() - 3..],
        &[
            "--".to_string(),
            "jetson-a".into(),
            "echo out; echo err >&2; exit 42".into()
        ]
    );

    let v = json(&lablink(
        Some(&e),
        &["exec", "jetson-a", "printf hi; exit 3", "--json"],
    ));
    assert_eq!(v["status"], "remote_error");
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["stdout"], "hi");
    assert_eq!(v["identity_pinned"], true);
    let v = json(&lablink(Some(&e), &["exec", "jetson-a", "true", "--json"]));
    assert_eq!(v["status"], "ok");
    assert_eq!(v["exit_code"], 0);
}

#[test]
fn exec_timeout_is_124_and_kills_the_command() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    let t = Instant::now();
    let o = lablink(
        Some(&e),
        &["exec", "jetson-a", "sleep 30", "--timeout", "1", "--json"],
    );
    assert_eq!(code(&o), exit::EXEC_TIMEOUT);
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    let v = json(&o);
    assert_eq!(v["status"], "timeout");
    assert_eq!(v["timed_out"], true);
}

#[test]
fn ssh_uses_interactive_mode_with_pinned_identity() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    let o = lablink(
        Some(&e),
        &["ssh", "jetson-a", "--", "-o", "StrictHostKeyChecking=no"],
    );
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr)
        .contains("jetson-a -> ops@10.9.0.31:22 (host key pinned by LabLink)"));
    let a = recorded_args(&e);
    assert!(!a.contains(&"BatchMode=yes".to_string()));
    let strict = a
        .iter()
        .position(|x| x == "StrictHostKeyChecking=yes")
        .unwrap();
    let weak = a
        .iter()
        .position(|x| x == "StrictHostKeyChecking=no")
        .unwrap();
    assert!(
        strict < weak,
        "user extras cannot weaken host-key checking: {a:?}"
    );
    assert_eq!(a.last().unwrap(), "jetson-a");
}

#[test]
fn offline_and_mismatch_are_refused_before_ssh_runs() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    e.net.host("10.9.0.31", |h| h.up = false);
    wait_color(&e, "jetson-a", "red");
    let o = lablink(Some(&e), &["exec", "jetson-a", "true", "--json"]);
    assert_eq!(code(&o), exit::DEVICE_UNREACHABLE);
    assert_eq!(json(&o)["error"]["code"], "unreachable");
    assert!(!e.args_file.exists(), "ssh must not have been started");
    let o = lablink(Some(&e), &["exec", "jetson-a", "true", "--force"]);
    assert_eq!(code(&o), 0, "--force runs anyway");

    // Host key changes at the static IP: mismatch, RED, refused with exit 6.
    e.net.host("10.9.0.31", |h| {
        h.up = true;
        h.keys = vec![fake_key("impostor")];
        h.port = PortMode::Refused;
    });
    wait_color(&e, "jetson-a", "yellow");
    e.net.host("10.9.0.31", |h| h.port = PortMode::Open);
    wait_color(&e, "jetson-a", "red");
    std::fs::remove_file(&e.args_file).unwrap();
    for args in [
        &["exec", "jetson-a", "true"][..],
        &["ssh", "jetson-a"],
        &["exec", "jetson-a", "true", "--force"],
    ] {
        let o = lablink(Some(&e), args);
        assert_eq!(
            code(&o),
            exit::IDENTITY_MISMATCH,
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert!(
        !e.args_file.exists(),
        "ssh must never run against a mismatched identity"
    );
}

#[test]
fn discover_refusals_and_resolve() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    let o = lablink(
        Some(&e),
        &["discover", "--scan-cidr", "10.0.0.0/8", "--json"],
    );
    assert_eq!(code(&o), exit::REFUSED);
    assert!(json(&o)["error"]["message"]
        .as_str()
        .unwrap()
        .contains("scan limit"));
    let o = lablink(Some(&e), &["discover", "--json"]);
    assert_eq!(code(&o), 0);
    assert!(json(&o)["stages"].as_array().unwrap().len() >= 5);
    let o = lablink(Some(&e), &["resolve", "jetson-a"]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "10.9.0.31\n");
}

#[test]
fn trust_requires_confirmation_when_not_interactive() {
    let e = setup("  - name: fresh\n    expected_ips: [10.9.0.51]\n");
    e.net.add(
        "10.9.0.51",
        FakeHost::ssh_host(vec![fake_key("fresh")], "aa:00:00:00:00:51"),
    );
    wait_color(&e, "fresh", "yellow");
    let o = lablink(Some(&e), &["trust", "fresh"]);
    assert_eq!(code(&o), exit::REFUSED);
    assert!(String::from_utf8_lossy(&o.stdout).contains(&fake_key("fresh").fingerprint));
    let o = lablink(Some(&e), &["trust", "fresh", "--yes", "--json"]);
    assert_eq!(code(&o), 0);
    assert_eq!(json(&o)["action"], "pinned");
    wait_color(&e, "fresh", "green");
}

#[test]
fn check_config_reports_errors_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.yaml");
    std::fs::write(
        &p,
        "networks:\n  - name: everything\n    cidr: 10.0.0.0/8\n    active_scan: true\n",
    )
    .unwrap();
    let o = lablink(None, &["check-config", p.to_str().unwrap()]);
    assert_eq!(code(&o), exit::USAGE);
    assert!(String::from_utf8_lossy(&o.stderr).contains("above the scan limit"));
    std::fs::write(&p, "devices:\n  - name: ok\n").unwrap();
    assert_eq!(
        code(&lablink(None, &["check-config", p.to_str().unwrap()])),
        0
    );
}

#[test]
fn doctor_runs_read_only_checks_through_the_exec_path() {
    let e = setup("");
    wait_color(&e, "jetson-a", "green");
    let cfg = e._dir.path().join("doctor.yaml");
    // The fake ssh runs the remote script locally: `disk` passes, `jetson_gpu`
    // fails because this machine is not a Jetson.
    std::fs::write(
        &cfg,
        "checks:\n  jetson-a:\n    - disk: { warn_pct: 100, fail_pct: 100 }\n    - jetson_gpu\n",
    )
    .unwrap();
    let c = cfg.to_str().unwrap();
    let o = lablink(Some(&e), &["doctor", "--json", "--config", c]);
    assert_eq!(
        code(&o),
        exit::STATUS_RED,
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v = json(&o);
    assert_eq!(v["verdict"], "not_ready");
    let d = &v["devices"][0];
    assert_eq!(
        (d["name"].as_str(), d["color"].as_str()),
        (Some("jetson-a"), Some("red"))
    );
    let ids: Vec<&str> = d["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["ssh", "disk", "jetson_gpu"]);
    let st = |i: usize| d["checks"][i]["status"].as_str().unwrap().to_string();
    assert_eq!(
        (st(0).as_str(), st(1).as_str(), st(2).as_str()),
        ("ok", "ok", "fail")
    );
    assert!(d["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("host key pinned"));
    assert!(d["checks"][1]["detail"]
        .as_str()
        .unwrap()
        .ends_with("% used"));
    assert!(d["checks"][2]["detail"]
        .as_str()
        .unwrap()
        .contains("not a Jetson"));
    // One batch session, same argument shape as `lablink exec`.
    let args = recorded_args(&e);
    assert!(args.iter().any(|a| a == "BatchMode=yes"));
    assert!(args.iter().any(|a| a == "-T"));
    assert!(args.iter().any(|a| a.starts_with("sh -c ")), "{args:?}");

    std::fs::write(
        &cfg,
        "checks:\n  jetson-a:\n    - disk: { warn_pct: 100, fail_pct: 100 }\n",
    )
    .unwrap();
    let o = lablink(Some(&e), &["doctor", "jetson-a", "--config", c]);
    assert_eq!(code(&o), exit::OK, "{}", String::from_utf8_lossy(&o.stdout));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.starts_with("LAB READY\n\njetson-a"), "{text}");
    assert!(text.contains("  SSH        OK\n  Disk       OK "), "{text}");
    // Unknown device and a bad config.
    let o = lablink(Some(&e), &["doctor", "nosuch", "--config", c]);
    assert_eq!(code(&o), exit::DEVICE_NOT_FOUND);
    std::fs::write(
        &cfg,
        "checks:\n  jetson-a:\n    - disk: { path: \"/a/../b\" }\n",
    )
    .unwrap();
    let o = lablink(Some(&e), &["doctor", "--config", c]);
    assert_eq!(code(&o), exit::USAGE);
    assert_eq!(code(&lablink(None, &["doctor"])), exit::DAEMON_UNAVAILABLE);
}
