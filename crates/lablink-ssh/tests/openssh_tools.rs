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
            "127.0.0.1",
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

/// A server that holds no key sends, before any key exchange, a disconnect
/// reason with an embedded newline and a forged `user@host: Permission
/// denied (...)` line (OpenSSH 8.9 prints such reasons unescaped). The
/// possession proof must never call that proven. Skipped without ssh.
#[test]
fn forged_pre_kex_disconnect_is_never_a_key_proof() {
    use std::io::{Read, Write};
    if !have("ssh") {
        eprintln!("SKIP: ssh not installed");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").unwrap();
        let mut buf = [0u8; 512];
        let _ = s.read(&mut buf); // client banner
        let reason = b"x\nops@127.0.0.1: Permission denied (publickey,password).\n";
        let mut payload = vec![1u8]; // SSH_MSG_DISCONNECT
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        payload.extend_from_slice(reason);
        payload.extend_from_slice(&0u32.to_be_bytes()); // language tag
        let mut pad = 8 - ((5 + payload.len()) % 8);
        if pad < 4 {
            pad += 8;
        }
        let mut pkt = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
        pkt.push(pad as u8);
        pkt.extend_from_slice(&payload);
        pkt.extend(std::iter::repeat_n(0u8, pad));
        s.write_all(&pkt).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    });
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    std::fs::write(
        &kh,
        "lablink.t.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
    )
    .unwrap();
    let t = lablink_ssh::Target {
        binary: "ssh".into(),
        ip: "127.0.0.1".into(),
        port,
        ssh_host: "dev".into(),
        username: Some("ops".into()),
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
    let _ = server.join();
    let stderr = String::from_utf8_lossy(&o.stderr);
    let proof = lablink_ssh::classify_key_proof(o.exit_code, &stderr, o.timed_out, "127.0.0.1");
    assert_ne!(
        proof,
        lablink_ssh::KeyProof::Proven,
        "stderr was: {stderr:?}"
    );
}

/// Same, through the KEXINIT algorithm list that OpenSSH echoes in "Unable
/// to negotiate ... Their offer:" with newlines unescaped.
#[test]
fn forged_kexinit_offer_is_never_a_key_proof() {
    use std::io::{Read, Write};
    if !have("ssh") {
        eprintln!("SKIP: ssh not installed");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        let list = |v: &[u8]| {
            let mut o = (v.len() as u32).to_be_bytes().to_vec();
            o.extend_from_slice(v);
            o
        };
        let mut payload = vec![20u8]; // SSH_MSG_KEXINIT
        payload.extend_from_slice(&[7u8; 16]);
        payload.extend(list(b"x\nops@127.0.0.1: Permission denied (publickey)."));
        payload.extend(list(b"ssh-ed25519"));
        for v in [
            &b"aes128-ctr"[..],
            b"aes128-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ] {
            payload.extend(list(v));
        }
        payload.extend_from_slice(&[0, 0, 0, 0, 0]);
        let mut pad = 8 - ((5 + payload.len()) % 8);
        if pad < 4 {
            pad += 8;
        }
        let mut pkt = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
        pkt.push(pad as u8);
        pkt.extend_from_slice(&payload);
        pkt.extend(std::iter::repeat_n(0u8, pad));
        s.write_all(&pkt).unwrap();
        let _ = s.read(&mut buf);
    });
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    std::fs::write(
        &kh,
        "lablink.t.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
    )
    .unwrap();
    let t = lablink_ssh::Target {
        binary: "ssh".into(),
        ip: "127.0.0.1".into(),
        port,
        ssh_host: "dev".into(),
        username: Some("ops".into()),
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
    let _ = server.join();
    let stderr = String::from_utf8_lossy(&o.stderr);
    let proof = lablink_ssh::classify_key_proof(o.exit_code, &stderr, o.timed_out, "127.0.0.1");
    assert_ne!(
        proof,
        lablink_ssh::KeyProof::Proven,
        "stderr was: {stderr:?}"
    );
}
