//! [integration, localhost] Cross-checks against the real OpenSSH tools.
//! Skipped (with a message) when the tools are not installed.

use std::process::Command;

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn fingerprint_agrees_with_ssh_keygen() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for kt in ["ed25519", "ecdsa", "rsa"] {
        let key = dir.path().join(format!("k_{kt}"));
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", kt, "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(st.success());
        let pubtext = std::fs::read_to_string(key.with_file_name(format!("k_{kt}.pub"))).unwrap();
        let f: Vec<&str> = pubtext.split_whitespace().collect();
        let ours = lablink_ssh::fingerprint_of_blob(f[0], f[1]).unwrap();
        let out = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(key.with_file_name(format!("k_{kt}.pub")))
            .output()
            .unwrap();
        let theirs = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        assert_eq!(ours, theirs, "{kt}");
    }
}

#[test]
fn known_hosts_lookup_via_ssh_keygen() {
    if !have("ssh-keygen") {
        eprintln!("SKIP: ssh-keygen not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("hk");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap()
        .success());
    let pubtext = std::fs::read_to_string(dir.path().join("hk.pub")).unwrap();
    let f: Vec<&str> = pubtext.split_whitespace().collect();
    let kh = dir.path().join("known_hosts");
    std::fs::write(
        &kh,
        format!(
            "192.168.10.70 {} {}\n[10.0.0.5]:2222 {} {}\n",
            f[0], f[1], f[0], f[1]
        ),
    )
    .unwrap();
    // Hash it like many distros do by default.
    assert!(Command::new("ssh-keygen")
        .arg("-H")
        .arg("-f")
        .arg(&kh)
        .output()
        .unwrap()
        .status
        .success());
    for host in ["192.168.10.70", "[10.0.0.5]:2222"] {
        let out = Command::new("ssh-keygen")
            .args(["-F", host, "-f"])
            .arg(&kh)
            .output()
            .unwrap();
        let keys = lablink_ssh::parse_known_hosts_lines(&String::from_utf8_lossy(&out.stdout));
        assert_eq!(keys.len(), 1, "{host}");
        assert_eq!(
            keys[0].fingerprint,
            lablink_ssh::fingerprint_of_blob(f[0], f[1]).unwrap()
        );
    }
}

/// The possession proof against a real, throwaway sshd on 127.0.0.1: the
/// server holding the pinned key gets to "Permission denied" (no credential
/// was offered), a pin of another key is refused. Skipped without sshd.
#[test]
fn key_proof_against_a_real_sshd() {
    let sshd = "/usr/sbin/sshd";
    if !std::path::Path::new(sshd).exists() || !have("ssh") || !have("ssh-keygen") {
        eprintln!("SKIP: sshd, ssh or ssh-keygen not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for k in ["hk", "other"] {
        assert!(Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(d.join(k))
            .status()
            .unwrap()
            .success());
    }
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = d.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nUsePAM no\nStrictModes no\n",
            d.join("hk").display(),
            d.join("sshd.pid").display()
        ),
    )
    .unwrap();
    let mut server = Command::new(sshd)
        .arg("-D")
        .arg("-f")
        .arg(&cfg)
        .arg("-E")
        .arg(d.join("sshd.log"))
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let proof = |pubkey: &str| {
        let line = std::fs::read_to_string(d.join(pubkey)).unwrap();
        let f: Vec<&str> = line.split_whitespace().collect();
        let kh = d.join(format!("kh_{pubkey}"));
        std::fs::write(&kh, format!("lablink.t.dev {} {}\n", f[0], f[1])).unwrap();
        let t = lablink_ssh::Target {
            binary: "ssh".into(),
            ip: "127.0.0.1".into(),
            port,
            ssh_host: "dev".into(),
            username: None,
            host_key_alias: Some("lablink.t.dev".into()),
            known_hosts_file: Some(kh),
            connect_timeout_s: 5,
            options: Default::default(),
            proxy_command: None,
        };
        let args = lablink_ssh::build_args(&t, &lablink_ssh::Mode::KeyProof, &[]);
        let o = lablink_ssh::run_captured(
            "ssh",
            &args,
            std::time::Duration::from_secs(15),
            lablink_ssh::OutputMode::Capture,
            true,
        )
        .unwrap();
        lablink_ssh::classify_key_proof(
            o.exit_code,
            &String::from_utf8_lossy(&o.stderr),
            o.timed_out,
        )
    };
    let held = proof("hk.pub");
    let other = proof("other.pub");
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(held, lablink_ssh::KeyProof::Proven);
    assert!(
        matches!(other, lablink_ssh::KeyProof::Refused(_)),
        "{other:?}"
    );
    let log = std::fs::read_to_string(d.join("sshd.log")).unwrap_or_default();
    assert!(!log.contains("Failed "), "no authentication attempt: {log}");
}
