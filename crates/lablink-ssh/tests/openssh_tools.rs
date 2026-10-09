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
