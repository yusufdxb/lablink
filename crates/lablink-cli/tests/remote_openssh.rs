//! [integration, real OpenSSH, loopback only] Remote access end to end with
//! the real `ssh`, `ssh-keyscan` and unprivileged `sshd` processes bound to
//! loopback addresses: 127.0.0.3 plays the device's LAN address, 127.0.0.2
//! its tailnet address (reported by a scripted `tailscale status --json`).
//! No daemon runs (the macOS / daemon-less client path). Skipped when the
//! OpenSSH server binary is not installed.

use lablink_core::exit;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const SSHD: &str = "/usr/sbin/sshd";
const LAN_IP: &str = "127.0.0.3";
const TS_IP: &str = "127.0.0.2";

fn available() -> bool {
    Path::new(SSHD).exists()
        && ["ssh", "ssh-keyscan", "ssh-keygen"].iter().all(|t| {
            Command::new("sh")
                .args(["-c", &format!("command -v {t}")])
                .output()
                .is_ok_and(|o| o.status.success())
        })
}

fn keygen(path: &Path) -> String {
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .unwrap()
        .success());
    let o = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(path.with_extension("pub"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

struct Sshd(Child);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_sshd(dir: &Path, tag: &str, ip: &str, port: u16, host_key: &Path) -> Sshd {
    let cfg = dir.join(format!("sshd-{tag}.conf"));
    std::fs::write(
        &cfg,
        format!(
            "ListenAddress {ip}\nPort {port}\nHostKey {}\nAuthorizedKeysFile {}\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile {}\nLogLevel ERROR\n",
            host_key.display(),
            dir.join("authorized_keys").display(),
            dir.join(format!("sshd-{tag}.pid")).display()
        ),
    )
    .unwrap();
    let child = Command::new(SSHD)
        .arg("-D")
        .arg("-f")
        .arg(&cfg)
        .arg("-E")
        .arg(dir.join(format!("sshd-{tag}.log")))
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect((ip, port)).is_err() {
        assert!(Instant::now() < deadline, "sshd {tag} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Sshd(child)
}

fn free_port() -> u16 {
    for _ in 0..50 {
        let l = std::net::TcpListener::bind(format!("{TS_IP}:0")).unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        if std::net::TcpListener::bind(format!("{LAN_IP}:{p}")).is_ok()
            && std::net::TcpListener::bind(format!("{TS_IP}:{p}")).is_ok()
        {
            return p;
        }
    }
    panic!("no free port");
}

struct Env {
    dir: tempfile::TempDir,
    port: u16,
    device_key: PathBuf,
    mitm_key: PathBuf,
    path: String,
}

impl Env {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lablink"))
            .args(args)
            .env("PATH", &self.path)
            .env("LABLINK_CONFIG", self.dir.path().join("config.yaml"))
            .env("LABLINK_STATE_DIR", self.dir.path().join("state"))
            .env("LABLINK_SOCKET", self.dir.path().join("none.sock"))
            .env("FAKE_DIR", self.dir.path())
            .output()
            .unwrap()
    }
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let device_key = d.join("device_host_key");
    let fp = keygen(&device_key);
    let mitm_key = d.join("mitm_host_key");
    keygen(&mitm_key);
    let client_key = d.join("client_key");
    keygen(&client_key);
    std::fs::copy(client_key.with_extension("pub"), d.join("authorized_keys")).unwrap();
    // The real ssh client, isolated from the developer's ~/.ssh/config.
    std::fs::write(
        d.join("ssh_config"),
        format!(
            "Host *\n  IdentityFile {}\n  IdentitiesOnly yes\n  BatchMode yes\n  ControlMaster no\n  ControlPath none\n  LogLevel ERROR\n",
            client_key.display()
        ),
    )
    .unwrap();
    let wrapper = d.join("ssh-isolated");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec ssh -F {} \"$@\"\n",
            d.join("ssh_config").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = d.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(
        bin.join("tailscale"),
        "#!/bin/sh\ncat \"$FAKE_DIR/ts.json\"\n",
    )
    .unwrap();
    std::fs::set_permissions(
        bin.join("tailscale"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(
        d.join("ts.json"),
        format!(r#"{{"BackendState":"Running","CurrentTailnet":{{"MagicDNSSuffix":"tail-ex.ts.net"}},"Peer":{{"k":{{"ID":"nBOX","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":["{TS_IP}"],"Online":true}}}}}}"#),
    )
    .unwrap();
    let port = free_port();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    std::fs::write(
        d.join("config.yaml"),
        format!(
            "ssh:\n  binary: {}\n  keyscan_binary: ssh-keyscan\ndevices:\n  - name: box\n    usernames: [{user}]\n    expected_ips: [{LAN_IP}]\n    ssh_port: {port}\n    host_key_fingerprints: [\"{fp}\"]\n    remote:\n      tailscale:\n        address: box.tail-ex.ts.net\n        tailnet: tail-ex.ts.net\n        node_id: nBOX\n",
            wrapper.display()
        ),
    )
    .unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Env {
        dir,
        port,
        device_key,
        mitm_key,
        path,
    }
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}): {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn file_digest(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}

#[test]
fn real_openssh_lan_then_tailnet_then_mitm() {
    if !available() {
        eprintln!("skipped: OpenSSH server/client not installed");
        return;
    }
    let user_kh = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh/known_hosts"));
    let user_kh_before = user_kh.as_deref().and_then(file_digest);

    let e = setup();
    let d = e.dir.path();
    let lan = start_sshd(d, "lan", LAN_IP, e.port, &e.device_key);
    let tailnet = start_sshd(d, "tailnet", TS_IP, e.port, &e.device_key);

    // 1. LAN works: real login over the LAN address.
    let o = e.run(&["exec", "box", "echo via-$((40+2))", "--json"]);
    let j = json(&o);
    assert_eq!(j["exit_code"], 0, "{j}");
    assert_eq!(j["stdout"], "via-42\n");
    assert_eq!(
        (j["transport"].as_str(), j["ip"].as_str()),
        (Some("lan"), Some(LAN_IP))
    );

    // 2. LAN gone: the same identity over the tailnet address.
    drop(lan);
    let o = e.run(&["exec", "box", "echo remote-ok", "--json"]);
    let j = json(&o);
    assert_eq!(j["exit_code"], 0, "{j}");
    assert_eq!(j["stdout"], "remote-ok\n");
    assert_eq!(
        (j["transport"].as_str(), j["ip"].as_str()),
        (Some("tailscale"), Some(TS_IP))
    );
    // Remote exit codes are preserved over the fallback path.
    let o = e.run(&["exec", "box", "exit 7"]);
    assert_eq!(o.status.code(), Some(7));

    // 3. Another server with another host key takes the tailnet address.
    drop(tailnet);
    let mitm = start_sshd(d, "mitm", TS_IP, e.port, &e.mitm_key);
    let o = e.run(&["exec", "box", "echo PWNED", "--json"]);
    assert_eq!(
        o.status.code(),
        Some(exit::IDENTITY_MISMATCH),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(json(&o)["error"]["code"], "host_key_mismatch");
    assert!(!String::from_utf8_lossy(&o.stdout).contains("PWNED\n"));

    // 4. Race: the impostor appears AFTER LabLink's pre-check passed. The
    // real ssh client must refuse on its own, from the pinned file.
    let pin = std::fs::read_to_string(d.join("state/remote/default.box.known_hosts")).unwrap();
    assert!(pin.contains("lablink.default.box ssh-ed25519 "), "{pin}");
    let t = lablink_ssh::Target {
        binary: d.join("ssh-isolated").display().to_string(),
        ip: TS_IP.into(),
        port: e.port,
        ssh_host: "box".into(),
        username: std::env::var("USER").ok(),
        host_key_alias: Some("lablink.default.box".into()),
        known_hosts_file: Some(d.join("state/remote/default.box.known_hosts")),
        connect_timeout_s: 5,
        options: Default::default(),
        proxy_command: None,
    };
    let args = lablink_ssh::build_args(
        &t,
        &lablink_ssh::Mode::Exec {
            command: "echo PWNED".into(),
            batch: true,
        },
        &[],
    );
    let o = Command::new(&t.binary).args(&args).output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(255), "{err}");
    assert!(!String::from_utf8_lossy(&o.stdout).contains("PWNED"));
    assert_eq!(
        lablink_ssh::classify_ssh_failure(&err),
        lablink_ssh::SshFailure::HostKeyChanged,
        "{err}"
    );
    drop(mitm);

    // 5. Nothing at all answers: unreachable on both paths, exit 5.
    let o = e.run(&["exec", "box", "true", "--json"]);
    assert_eq!(o.status.code(), Some(exit::DEVICE_UNREACHABLE));
    let m = json(&o)["error"]["message"].as_str().unwrap().to_string();
    assert!(
        m.contains("lan 127.0.0.3") && m.contains("tailscale box.tail-ex.ts.net"),
        "{m}"
    );

    // The user's own known_hosts was never written.
    assert_eq!(user_kh.as_deref().and_then(file_digest), user_kh_before);
}
