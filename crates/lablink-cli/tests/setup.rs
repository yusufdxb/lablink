//! [integration, simulated + localhost] First-run setup and the portability
//! commands, run as the real `lablink` binary with HOME and every XDG
//! directory pointed at a temporary directory. `--no-service` is used
//! throughout: tests never touch the user's systemd.

use lablink_core::exit;
use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, TestDaemon};
use serde_json::Value;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A fresh user: empty home, no config, no state.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn config(&self) -> PathBuf {
        self.path().join(".config/lablink/config.yaml")
    }
    fn cmd(&self, socket: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_lablink"));
        c.args(args)
            .env_remove("LABLINK_CONFIG")
            .env_remove("LABLINK_STATE_DIR")
            .env("HOME", self.path())
            .env("XDG_CONFIG_HOME", self.path().join(".config"))
            .env("XDG_DATA_HOME", self.path().join(".local/share"))
            .env("XDG_STATE_HOME", self.path().join(".local/state"))
            .env("LABLINK_SOCKET", socket)
            .env("NO_COLOR", "1")
            .current_dir(self.path());
        c
    }
    fn run(&self, socket: &Path, args: &[&str]) -> Output {
        self.cmd(socket, args).output().unwrap()
    }
    fn run_with_input(&self, socket: &Path, args: &[&str], input: &str) -> Output {
        let mut child = self
            .cmd(socket, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const NO_DAEMON: &str = "/nonexistent/lablink/test.sock";

#[test]
fn init_from_empty_directories() {
    let h = Home::new();
    let sock = Path::new(NO_DAEMON);
    assert!(!h.config().exists());
    let o = h.run(
        sock,
        &[
            "init",
            "--yes",
            "--no-service",
            "--scan",
            "10.9.0.0/24",
            "--network",
            "campus=10.20.0.0/16",
        ],
    );
    let t = text(&o);
    assert_eq!(code(&o), exit::OK, "{t}");
    assert!(t.contains("config      done"), "{t}");
    assert!(t.contains("service     skipped"), "{t}");
    assert!(t.contains("completion  done"), "{t}");
    assert!(
        t.contains("Site -> Discover -> Adopt -> Trust -> Connect"),
        "{t}"
    );
    let cfg = lablink_core::Config::load(&h.config()).unwrap();
    assert_eq!(cfg.sites.len(), 1);
    assert_eq!(
        cfg.sites[0].id, "default",
        "-y without --site uses the default site"
    );
    let nets = &cfg.sites[0].networks;
    assert_eq!(nets.len(), 2);
    assert!(nets[0].active_scan && nets[0].cidr == "10.9.0.0/24");
    assert!(!nets[1].active_scan && nets[1].name == "campus");
    assert!(h
        .path()
        .join(".local/share/bash-completion/completions/lablink")
        .is_file());
    // The written file passes the same validation the daemon uses.
    let o = h.run(sock, &["check-config"]);
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    // Running again keeps the config.
    let o = h.run(sock, &["init", "--yes", "--no-service", "--no-completions"]);
    assert!(text(&o).contains("kept the existing"), "{}", text(&o));
    assert_eq!(lablink_core::Config::load(&h.config()).unwrap(), cfg);
    // Active scanning of a public or oversized range is refused up front.
    for bad in ["8.8.8.0/24", "10.0.0.0/16"] {
        let o = h.run(
            sock,
            &["init", "--yes", "--no-service", "--force", "--scan", bad],
        );
        assert_eq!(code(&o), exit::USAGE, "{bad}: {}", text(&o));
    }
    assert_eq!(lablink_core::Config::load(&h.config()).unwrap(), cfg);
}

#[test]
fn init_never_selects_networks_by_itself() {
    let h = Home::new();
    let o = h.run(
        Path::new(NO_DAEMON),
        &["init", "--yes", "--no-service", "--no-completions"],
    );
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    let cfg = lablink_core::Config::load(&h.config()).unwrap();
    assert_eq!(cfg.network_count(), 0, "{cfg:?}");
}

#[test]
fn init_interactive_answers_from_stdin() {
    let h = Home::new();
    // Networks given on the command line, so the site name, service and
    // completion questions are asked: a site name, "n" (no service), "y"
    // (completion). The test HOME never reaches the real systemd user
    // manager either way (see service::systemd_available).
    let o = h.run_with_input(
        Path::new(NO_DAEMON),
        &["init", "--scan", "lab=10.9.0.0/24"],
        "Site Alpha\nn\ny\n",
    );
    let t = text(&o);
    assert_eq!(code(&o), exit::OK, "{t}");
    assert!(
        t.contains("LabLink only looks at networks you choose"),
        "{t}"
    );
    assert!(
        t.contains("Install and start the background service"),
        "{t}"
    );
    assert!(t.contains("service     skipped"), "{t}");
    assert!(t.contains("completion  done"), "{t}");
    let cfg = lablink_core::Config::load(&h.config()).unwrap();
    assert_eq!(
        (cfg.sites[0].id.as_str(), cfg.sites[0].name.as_str()),
        ("site-alpha", "Site Alpha")
    );
    // Keep the existing config on a second run ("y"), then decline service/completion.
    let o = h.run_with_input(Path::new(NO_DAEMON), &["init"], "y\nn\nn\n");
    assert!(text(&o).contains("kept the existing"), "{}", text(&o));
}

fn daemon_env(home: &Home) -> (TestDaemon, std::sync::Arc<FakeNet>, PathBuf) {
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("jetson-a")], "02:4c:4c:00:00:01"),
    );
    net.add(
        "10.9.0.77",
        FakeHost::ssh_host(vec![fake_key("bench")], "aa:00:00:00:00:77"),
    );
    let fp = fake_key("jetson-a").fingerprint;
    let yaml = format!(
        "networks:\n  - name: lab_net\n    cidr: 10.9.0.0/24\n    active_scan: true\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n    host_key_fingerprints: [\"{fp}\"]\n"
    );
    std::fs::create_dir_all(home.config().parent().unwrap()).unwrap();
    std::fs::write(home.config(), &yaml).unwrap();
    let d = TestDaemon::start(
        fast_config(&yaml),
        net.clone(),
        home.path().join("state"),
        true,
    )
    .unwrap();
    let sock = d.socket.clone();
    (d, net, sock)
}

fn wait_json(h: &Home, sock: &Path, args: &[&str], pred: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let o = h.run(sock, args);
        let v: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
        if pred(&v) {
            return v;
        }
        assert!(Instant::now() < deadline, "timeout: {}", text(&o));
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[test]
fn version_reports_cli_and_daemon() {
    let h = Home::new();
    let o = h.run(Path::new(NO_DAEMON), &["version"]);
    assert_eq!(code(&o), exit::OK);
    let t = text(&o);
    assert!(
        t.starts_with(&format!("lablink {}", lablink_core::VERSION)),
        "{t}"
    );
    assert!(t.contains("lablinkd not running"), "{t}");
    let (d, _net, sock) = daemon_env(&h);
    let o = h.run(&sock, &["version", "--json"]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["version"], lablink_core::VERSION);
    assert_eq!(v["daemon"]["version"], lablink_core::VERSION);
    assert!(v["daemon"].as_object().unwrap().contains_key("git_sha"));
    assert_eq!(v["daemon"]["git_sha"].as_str(), lablink_core::GIT_SHA);
    assert!(matches!(
        v["daemon_build"].as_str(),
        Some("same" | "unknown")
    ));
    assert_eq!(v["protocol_version"], 1);
    d.stop().unwrap();
}

#[test]
fn version_warns_when_an_older_daemon_is_running() {
    use std::io::{BufRead, BufReader};
    let h = Home::new();
    let socket = h.path().join("version.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("ping"));
        stream.write_all(b"{\"ok\":true,\"result\":{\"version\":\"0.2.0\",\"protocol_version\":1,\"pid\":123,\"uptime_s\":0}}\n").unwrap();
    });
    let out = h.run(&socket, &["version"]);
    server.join().unwrap();
    assert_eq!(code(&out), exit::OK);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("client and daemon builds differ"), "{text}");
    assert!(text.contains("Restart lablinkd"));
}

#[test]
fn daemon_commands_warn_when_the_running_daemon_is_an_older_build() {
    use std::io::{BufRead, BufReader};
    let h = Home::new();
    let socket = h.path().join("old.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("ping"));
        stream.write_all(b"{\"ok\":true,\"result\":{\"version\":\"0.3.0\",\"protocol_version\":1,\"pid\":123,\"uptime_s\":0}}\n").unwrap();
    });
    let out = h.run(&socket, &["status", "--json"]);
    server.join().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("running lablinkd is 0.3.0"), "{err}");
    assert!(err.contains("systemctl --user restart lablinkd"), "{err}");
    // The warning never lands on stdout, which carries the JSON.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("WARNING"));
}

/// A fake 0.3.0 daemon that answers exactly one request (the ping). Any
/// second request would find the socket closed (exit 3), so exit 7 proves
/// the command was refused before it asked the daemon to do anything.
fn old_daemon_refuses(args: &[&str]) {
    use std::io::{BufRead, BufReader};
    let h = Home::new();
    let socket = h.path().join("old.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("ping"));
        stream.write_all(b"{\"ok\":true,\"result\":{\"version\":\"0.3.0\",\"protocol_version\":1,\"pid\":123,\"uptime_s\":0}}\n").unwrap();
    });
    let out = h.run(&socket, args);
    server.join().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "{args:?}: {err}");
    assert!(err.contains("running lablinkd is 0.3.0"), "{args:?}: {err}");
    assert!(err.contains("refused"), "{args:?}: {err}");
    assert!(
        err.contains("systemctl --user restart lablinkd"),
        "{args:?}: {err}"
    );
}

#[test]
fn security_sensitive_commands_are_refused_by_an_older_daemon() {
    for args in [
        &["resolve", "d"][..],
        &["exec", "d", "true"],
        &["ssh", "d"],
        &["trust", "d", "--fingerprint", "SHA256:x"],
        &["forget", "d"],
        &["doctor"],
        &["discover"],
    ] {
        old_daemon_refuses(args);
    }
}

#[test]
fn concurrent_site_adds_preserve_every_acknowledged_change() {
    let h = Home::new();
    std::thread::scope(|scope| {
        for worker in 0..6 {
            let h = &h;
            scope.spawn(move || {
                for i in 0..20 {
                    let name = format!("site-{worker}-{i}");
                    let out = h.run(Path::new(NO_DAEMON), &["site", "add", &name, "--id", &name]);
                    assert_eq!(code(&out), exit::OK, "{}", text(&out));
                }
            });
        }
    });
    let cfg = lablink_core::Config::load(&h.config()).unwrap();
    assert_eq!(cfg.sites.len(), 120);
    for worker in 0..6 {
        for i in 0..20 {
            assert!(cfg.site(&format!("site-{worker}-{i}")).is_some());
        }
    }
}

#[test]
fn renaming_an_unknown_site_preserves_the_exit_contract() {
    let h = Home::new();
    let socket = Path::new(NO_DAEMON);
    let added = h.run(socket, &["site", "add", "Known", "--id", "known"]);
    assert_eq!(code(&added), exit::OK, "{}", text(&added));
    let before = std::fs::read(h.config()).unwrap();
    let renamed = h.run(socket, &["site", "rename", "missing", "New name"]);
    assert_eq!(code(&renamed), exit::DEVICE_NOT_FOUND, "{}", text(&renamed));
    assert_eq!(std::fs::read(h.config()).unwrap(), before);
}

#[test]
fn adopt_export_import_round_trip_without_secrets() {
    let h = Home::new();
    let (d, _net, sock) = daemon_env(&h);
    let o = h.run(&sock, &["discover", "--json"]);
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    let o = h.run(
        &sock,
        &[
            "adopt",
            "10.9.0.77",
            "bench",
            "--label",
            "Bench PC",
            "--user",
            "ops",
            "--profile",
            "gpu_workstation",
        ],
    );
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    assert!(text(&o).contains("lablink trust bench"), "{}", text(&o));
    let v = wait_json(&h, &sock, &["status", "bench", "--json"], |v| {
        v["devices"][0]["identity"] == "unverified"
    });
    assert_eq!(v["devices"][0]["profile"], "gpu_workstation");
    // Explanations for a non-GREEN device.
    let o = h.run(&sock, &["status", "bench"]);
    let t = text(&o);
    assert!(t.contains("Host key not trusted yet"), "{t}");
    assert!(t.contains("Next step:"), "{t}");
    // A network-only device needs --no-ssh or the profile, never both.
    let o = h.run(&sock, &["adopt", "10.9.0.99", "x", "--profile", "toaster"]);
    assert_eq!(code(&o), exit::USAGE);

    let file = h.path().join("lab.lablink.yaml");
    let o = h.run(&sock, &["export", "-o", file.to_str().unwrap()]);
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    let exported = std::fs::read_to_string(&file).unwrap();
    assert!(exported.contains("name: bench"), "{exported}");
    assert!(exported.contains("label: Bench PC"), "{exported}");
    assert!(exported.contains("gpu_workstation"), "{exported}");
    let data: String = exported
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for secret in ["password", "PRIVATE KEY", "id_ed25519", "BEGIN"] {
        assert!(!data.contains(secret), "{secret}: {exported}");
    }
    // Import into a second fresh user.
    let h2 = Home::new();
    let o = h2.run(
        Path::new(NO_DAEMON),
        &["import", file.to_str().unwrap(), "--dry-run"],
    );
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    assert!(!h2.config().exists(), "dry run writes nothing");
    let o = h2.run(Path::new(NO_DAEMON), &["import", file.to_str().unwrap()]);
    assert_eq!(code(&o), exit::REFUSED, "no --yes without a terminal");
    let o = h2.run(
        Path::new(NO_DAEMON),
        &["import", file.to_str().unwrap(), "--yes"],
    );
    let t = text(&o);
    assert_eq!(code(&o), exit::OK, "{t}");
    assert!(t.contains("device default/bench: added"), "{t}");
    assert!(t.contains("were NOT imported"), "{t}");
    let cfg = lablink_core::Config::load(&h2.config()).unwrap();
    let bench = cfg.find_devices("bench")[0].1;
    assert_eq!(bench.usernames, ["ops"]);
    assert!(cfg
        .devices()
        .all(|(_, d)| d.host_key_fingerprints.is_empty()));
    // Idempotent.
    let o = h2.run(
        Path::new(NO_DAEMON),
        &["import", file.to_str().unwrap(), "--yes"],
    );
    assert!(text(&o).contains("nothing to change"), "{}", text(&o));
    d.stop().unwrap();
}

#[test]
fn support_bundle_is_redacted() {
    let h = Home::new();
    let (d, _net, sock) = daemon_env(&h);
    wait_json(&h, &sock, &["status", "jetson-a", "--json"], |v| {
        v["devices"][0]["ip"] == "10.9.0.31"
    });
    let out = h.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let o = h.run(
        &sock,
        &["support-bundle", "--no-doctor", "-o", out.to_str().unwrap()],
    );
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    let archive = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let x = h.path().join("x");
    std::fs::create_dir(&x).unwrap();
    assert!(Command::new("tar")
        .args(["-xzf", &archive, "-C"])
        .arg(&x)
        .status()
        .unwrap()
        .success());
    let inner = std::fs::read_dir(&x)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut all = String::new();
    for f in [
        "summary.txt",
        "config.redacted.yaml",
        "status.json",
        "sites.json",
        "devices.json",
        "metrics.json",
    ] {
        let p = inner.join(f);
        assert!(p.is_file(), "{f} missing");
        all.push_str(&std::fs::read_to_string(p).unwrap());
    }
    for leak in [
        "10.9.0.31",
        "02:4c:4c",
        "ops",
        "lab_net",
        "jetson-a",
        &fake_key("jetson-a").fingerprint,
    ] {
        assert!(!all.contains(leak), "{leak} leaked");
    }
    assert!(
        all.contains("device-1"),
        "device names become stable placeholders"
    );
    assert!(all.contains(lablink_core::VERSION));
    d.stop().unwrap();
}

#[test]
fn copy_id_goes_through_the_pinned_identity_only() {
    let h = Home::new();
    let (d, _net, sock) = daemon_env(&h);
    // A fake ssh-copy-id that records its arguments.
    let bin = h.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let rec = h.path().join("copy-id-args");
    std::fs::write(
        bin.join("ssh-copy-id"),
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", rec.display()),
    )
    .unwrap();
    std::fs::set_permissions(
        bin.join("ssh-copy-id"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::create_dir(h.path().join(".ssh")).unwrap();
    std::fs::write(
        h.path().join(".ssh/id_ed25519.pub"),
        "ssh-ed25519 AAAA test\n",
    )
    .unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    wait_json(&h, &sock, &["status", "jetson-a", "--json"], |v| {
        v["devices"][0]["identity"] == "verified"
    });
    let o = h
        .cmd(&sock, &["copy-id", "jetson-a"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    let args = std::fs::read_to_string(&rec).unwrap();
    for want in [
        "-i",
        "HostKeyAlias=lablink.default.jetson-a",
        "StrictHostKeyChecking=yes",
        "HostName=10.9.0.31",
        "ops@jetson-a",
    ] {
        assert!(args.lines().any(|l| l == want), "{want}: {args}");
    }
    let lines: Vec<&str> = args.lines().collect();
    assert!(lines[1].ends_with(".ssh/id_ed25519.pub"), "{args}");
    // An adopted, unpinned device is refused before ssh-copy-id runs.
    let _ = h.run(&sock, &["discover", "--json"]);
    let o = h.run(&sock, &["adopt", "10.9.0.77", "bench"]);
    assert_eq!(code(&o), exit::OK, "{}", text(&o));
    std::fs::remove_file(&rec).unwrap();
    let o = h
        .cmd(&sock, &["copy-id", "bench"])
        .env("PATH", &path)
        .output()
        .unwrap();
    assert_eq!(code(&o), exit::REFUSED, "{}", text(&o));
    assert!(text(&o).contains("lablink trust bench"), "{}", text(&o));
    assert!(
        !rec.exists(),
        "ssh-copy-id must not run for an unpinned device"
    );
    d.stop().unwrap();
}
