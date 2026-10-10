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

/// Generate an ed25519 key `name` (and `name.pub`) in `d`.
fn keygen(d: &std::path::Path, name: &str) {
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(d.join(name))
        .status()
        .unwrap()
        .success());
}

/// The `type base64` part of a public key file.
fn pubkey(d: &std::path::Path, name: &str) -> String {
    let line = std::fs::read_to_string(d.join(format!("{name}.pub"))).unwrap();
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A throwaway sshd on 127.0.0.1 with host key `hostkey` (in `d`), logging
/// to `<tag>.log`. Killed when dropped.
struct Sshd(std::process::Child);
impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn sshd(d: &std::path::Path, tag: &str, hostkey: &str, extra: &str) -> (Sshd, u16) {
    let port = free_port();
    let cfg = d.join(format!("{tag}.conf"));
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nUsePAM no\nStrictModes no\nLogLevel VERBOSE\n{extra}",
            d.join(hostkey).display(),
            d.join(format!("{tag}.pid")).display()
        ),
    )
    .unwrap();
    let child = Command::new(SSHD)
        .arg("-D")
        .arg("-f")
        .arg(&cfg)
        .arg("-E")
        .arg(d.join(format!("{tag}.log")))
        .spawn()
        .unwrap();
    // Wait until it listens.
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    (Sshd(child), port)
}

const SSHD: &str = "/usr/sbin/sshd";

fn have_openssh_server() -> bool {
    let ok = std::path::Path::new(SSHD).exists() && have("ssh") && have("ssh-keygen");
    if !ok {
        eprintln!("SKIP: sshd, ssh or ssh-keygen not installed");
    }
    ok
}

/// A target pinned to `key` (a `type base64` string) under `lablink.t.dev`.
fn pinned(d: &std::path::Path, port: u16, key: &str) -> lablink_ssh::Target {
    let kh = d.join(format!("kh_{}", key.len() + port as usize + rand_suffix()));
    std::fs::write(&kh, format!("lablink.t.dev {key}\n")).unwrap();
    lablink_ssh::Target {
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
    }
}

fn rand_suffix() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst) * 100_000
}

const PROOF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// No authentication of any kind reached the server.
fn assert_no_auth(d: &std::path::Path, tag: &str) {
    let log = std::fs::read_to_string(d.join(format!("{tag}.log"))).unwrap_or_default();
    for bad in ["Failed ", "Accepted ", "Invalid user", "userauth"] {
        assert!(!log.contains(bad), "{bad:?} in {tag}.log: {log}");
    }
}

/// The possession proof against a real, throwaway sshd on 127.0.0.1: the
/// server holding the pinned key proves it before any authentication (the
/// connection is closed at NEWKEYS); a pin of another key is refused.
#[test]
fn key_proof_against_a_real_sshd() {
    if !have_openssh_server() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(d, "hk");
    keygen(d, "other");
    let (_server, port) = sshd(d, "dev", "hk", "");
    let held = lablink_ssh::prove_host_key(&pinned(d, port, &pubkey(d, "hk")), PROOF_TIMEOUT);
    let other = lablink_ssh::prove_host_key(&pinned(d, port, &pubkey(d, "other")), PROOF_TIMEOUT);
    assert_eq!(held, lablink_ssh::KeyProof::Proven);
    assert!(
        matches!(other, lablink_ssh::KeyProof::Refused(_)),
        "{other:?}"
    );
    assert_no_auth(d, "dev");
}

/// A machine in the middle that presents the pinned public key but does not
/// hold its private key: it relays to a real sshd with another key and puts
/// the pinned key's blob in the server's key-exchange reply. ssh accepts the
/// key against the pin, then the signature fails: never proven, refused.
#[test]
fn replayed_public_key_over_a_real_key_exchange_is_refused() {
    use std::io::{Read, Write};
    if !have_openssh_server() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(d, "pinned"); // the victim's key: only its public half is used
    keygen(d, "attacker");
    let (_server, real) = sshd(d, "mitm", "attacker", "HostKeyAlgorithms ssh-ed25519\n");
    let blob = |name: &str| {
        use base64::Engine as _;
        let k = pubkey(d, name);
        base64::engine::general_purpose::STANDARD
            .decode(k.split_whitespace().nth(1).unwrap())
            .unwrap()
    };
    let (from, to) = (blob("attacker"), blob("pinned"));
    assert_eq!(from.len(), to.len());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let swapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = swapped.clone();
    let mitm = std::thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = std::net::TcpStream::connect(("127.0.0.1", real)).unwrap();
        // sshd keeps an idle connection for its login grace time.
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let (mut c2, mut s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut c2, &mut s2);
        });
        // Server -> client: rewrite the host key in KEX_ECDH_REPLY (31).
        let (mut client, mut server) = (client, server);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let n = match server.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(from.len()).position(|w| w == from.as_slice()) {
                buf.splice(i..i + from.len(), to.iter().copied());
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if client.write_all(&buf).is_err() {
                return;
            }
            buf.clear();
        }
    });
    let proof = lablink_ssh::prove_host_key(&pinned(d, port, &pubkey(d, "pinned")), PROOF_TIMEOUT);
    let _ = mitm.join();
    assert!(
        swapped.load(std::sync::atomic::Ordering::SeqCst),
        "the MITM never saw the key"
    );
    assert!(
        matches!(proof, lablink_ssh::KeyProof::Refused(_)),
        "{proof:?}"
    );
    assert_no_auth(d, "mitm");
}

/// Whatever ssh prints or returns, possession is decided only by the bytes
/// it sends: an ssh that prints OpenSSH's own denial line for this host, or
/// one that exits 0, without completing a key exchange proves nothing.
#[test]
fn printed_text_and_exit_status_never_prove_possession() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = std::thread::spawn(move || {
        for _ in 0..3 {
            let _ = listener.accept();
        }
    });
    for (name, body) in [
        (
            "deny",
            "echo 'ops@127.0.0.1: Permission denied (publickey,password).' >&2; exit 255",
        ),
        ("zero", "exit 0"),
        (
            "banner",
            "printf 'SSH-2.0-OpenSSH_10.2\\r\\n'; sleep 1; exit 0",
        ),
    ] {
        let fake = d.join(name);
        std::fs::write(&fake, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mut t = pinned(
            d,
            port,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        );
        t.binary = fake.display().to_string();
        let proof = lablink_ssh::prove_host_key(&t, std::time::Duration::from_secs(5));
        assert!(
            matches!(proof, lablink_ssh::KeyProof::Inconclusive(_)),
            "{name}: {proof:?}"
        );
    }
    let _ = accept.join();
}

/// Through a gateway: LabLink runs the hop (`ssh -W`) itself and watches the
/// proof's own ssh across it. Real sshds for the gateway (key login) and for
/// the device behind it.
#[test]
fn key_proof_through_a_real_gateway() {
    if !have_openssh_server() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for k in ["gw_hk", "dev_hk", "other", "client"] {
        keygen(d, k);
    }
    std::fs::write(d.join("authorized_keys"), pubkey(d, "client") + "\n").unwrap();
    let (_dev, dev_port) = sshd(d, "dev", "dev_hk", "");
    let (_gw, gw_port) = sshd(
        d,
        "gw",
        "gw_hk",
        &format!(
            "AuthorizedKeysFile {}\nAllowTcpForwarding yes\nPasswordAuthentication no\n",
            d.join("authorized_keys").display()
        ),
    );
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let gw_kh = d.join("gw_kh");
    std::fs::write(&gw_kh, format!("lablink.t.gw {}\n", pubkey(d, "gw_hk"))).unwrap();
    let gw = lablink_ssh::Target {
        binary: "ssh".into(),
        ip: "127.0.0.1".into(),
        port: gw_port,
        ssh_host: "gw".into(),
        username: Some(user),
        host_key_alias: Some("lablink.t.gw".into()),
        known_hosts_file: Some(gw_kh),
        connect_timeout_s: 5,
        options: [
            (
                "IdentityFile".to_string(),
                d.join("client").display().to_string(),
            ),
            ("IdentitiesOnly".to_string(), "yes".to_string()),
            ("IdentityAgent".to_string(), "none".to_string()),
            ("ControlPath".to_string(), "none".to_string()),
        ]
        .into(),
        proxy_command: None,
    };
    let via = |key: &str| {
        let mut t = pinned(d, dev_port, key);
        t.proxy_command = Some(lablink_ssh::proxy_command_through(&gw, true));
        lablink_ssh::prove_host_key(&t, PROOF_TIMEOUT)
    };
    let held = via(&pubkey(d, "dev_hk"));
    let other = via(&pubkey(d, "other"));
    let gwlog = std::fs::read_to_string(d.join("gw.log")).unwrap_or_default();
    assert_eq!(held, lablink_ssh::KeyProof::Proven, "gateway log: {gwlog}");
    assert!(
        matches!(other, lablink_ssh::KeyProof::Refused(_)),
        "{other:?}"
    );
    assert!(gwlog.contains("Accepted publickey"), "{gwlog}");
    assert_no_auth(d, "dev");
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
    let proof = lablink_ssh::prove_host_key(&t, PROOF_TIMEOUT);
    let _ = server.join();
    assert!(
        matches!(proof, lablink_ssh::KeyProof::Inconclusive(_)),
        "{proof:?}"
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
    let proof = lablink_ssh::prove_host_key(&t, PROOF_TIMEOUT);
    let _ = server.join();
    assert!(
        matches!(proof, lablink_ssh::KeyProof::Inconclusive(_)),
        "{proof:?}"
    );
}

/// Only the ed25519 key of a host with two key types is pinned, and the
/// target's options ask for ECDSA first (an explicit list stops OpenSSH
/// preferring known key types). The proof offers only pinned types, so the
/// real device proves its key instead of landing in a false security stop.
#[test]
fn a_partial_pin_with_another_algorithm_order_still_proves() {
    if !have_openssh_server() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(d, "hk");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-N", "", "-f"])
        .arg(d.join("hk_ecdsa"))
        .status()
        .unwrap()
        .success());
    let (_server, port) = sshd(
        d,
        "dev",
        "hk",
        &format!("HostKey {}\n", d.join("hk_ecdsa").display()),
    );
    let mut t = pinned(d, port, &pubkey(d, "hk"));
    t.options.insert(
        "HostKeyAlgorithms".into(),
        "ecdsa-sha2-nistp256,ssh-ed25519".into(),
    );
    assert_eq!(
        lablink_ssh::prove_host_key(&t, PROOF_TIMEOUT),
        lablink_ssh::KeyProof::Proven
    );
    // A pin file without this device: never run, never a verdict.
    std::fs::write(
        t.known_hosts_file.as_ref().unwrap(),
        "lablink.t.other ssh-ed25519 AAAA\n",
    )
    .unwrap();
    assert!(matches!(
        lablink_ssh::prove_host_key(&t, PROOF_TIMEOUT),
        lablink_ssh::KeyProof::Inconclusive(_)
    ));
    assert_no_auth(d, "dev");
}

/// A hostile `~/.ssh/config`: a KnownHostsCommand that vouches for the
/// server's real key, a `Match` block that breaks only LabLink's option
/// probe, `GSSAPIKeyExchange`, `VerifyHostKeyDNS`, `ProxyUseFdpass`. With
/// another key pinned the proof must not succeed; with the real key pinned it
/// must. Rewrites the current user's ~/.ssh/config, so it runs only with
/// LABLINK_TEST_HOSTILE_SSH_CONFIG=1 (disposable containers).
#[test]
fn a_hostile_client_config_cannot_vouch_for_a_key() {
    if std::env::var_os("LABLINK_TEST_HOSTILE_SSH_CONFIG").is_none() {
        eprintln!("SKIP: set LABLINK_TEST_HOSTILE_SSH_CONFIG=1 (rewrites ~/.ssh/config)");
        return;
    }
    if !have_openssh_server() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(d, "hk");
    keygen(d, "other");
    let (_server, port) = sshd(d, "dev", "hk", "");
    let khc = d.join("khc.sh");
    std::fs::write(
        &khc,
        format!("#!/bin/sh\necho 'lablink.t.dev {}'\n", pubkey(d, "hk")),
    )
    .unwrap();
    std::fs::set_permissions(&khc, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let home = std::path::PathBuf::from(
        String::from_utf8(
            Command::new("sh")
                .args(["-c", "getent passwd $(id -u) | cut -d: -f6"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim(),
    );
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let cfg = home.join(".ssh/config");
    assert!(
        !cfg.exists(),
        "refusing to overwrite an existing {}",
        cfg.display()
    );
    // One attack per config, so that one cannot mask another.
    let configs = [
        format!(
            "IgnoreUnknown KnownHostsCommand,GSSAPIKeyExchange\n\
             Match host lablink-option-check\n  CanonicalizeHostname yes\n  CanonicalizeFallbackLocal no\n  CanonicalDomains nowhere.invalid\n\
             Host *\n  KnownHostsCommand {}\n  GSSAPIKeyExchange yes\n  VerifyHostKeyDNS yes\n",
            khc.display()
        ),
        "Host *\n  ProxyUseFdpass yes\n".to_string(),
    ];
    for c in configs {
        std::fs::write(&cfg, &c).unwrap();
        let impostor =
            lablink_ssh::prove_host_key(&pinned(d, port, &pubkey(d, "other")), PROOF_TIMEOUT);
        let real = lablink_ssh::prove_host_key(&pinned(d, port, &pubkey(d, "hk")), PROOF_TIMEOUT);
        std::fs::remove_file(&cfg).unwrap();
        assert!(
            !matches!(impostor, lablink_ssh::KeyProof::Proven),
            "{impostor:?} with {c}"
        );
        assert_eq!(real, lablink_ssh::KeyProof::Proven, "with {c}");
    }
}

/// A config `Match exec` prints OpenSSH's "incorrect signature" text while a
/// server that holds no key answers the key exchange with garbage: the proof
/// reads no config file, so that text never turns the failure into a
/// security stop. Rewrites ~/.ssh/config: only with
/// LABLINK_TEST_HOSTILE_SSH_CONFIG=1 (disposable containers).
#[test]
fn config_text_cannot_turn_a_failed_proof_into_a_security_stop() {
    use std::io::{Read, Write};
    if std::env::var_os("LABLINK_TEST_HOSTILE_SSH_CONFIG").is_none() {
        eprintln!("SKIP: set LABLINK_TEST_HOSTILE_SSH_CONFIG=1 (rewrites ~/.ssh/config)");
        return;
    }
    if !have("ssh") {
        return;
    }
    let packet = |payload: &[u8]| {
        let mut pad = 8 - ((5 + payload.len()) % 8);
        if pad < 4 {
            pad += 8;
        }
        let mut p = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
        p.push(pad as u8);
        p.extend_from_slice(payload);
        p.extend(std::iter::repeat_n(0u8, pad));
        p
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        s.write_all(b"SSH-2.0-OpenSSH_10.2\r\n").unwrap();
        let list = |v: &[u8]| {
            let mut o = (v.len() as u32).to_be_bytes().to_vec();
            o.extend_from_slice(v);
            o
        };
        let mut kexinit = vec![20u8];
        kexinit.extend_from_slice(&[7u8; 16]);
        for v in [
            &b"curve25519-sha256"[..],
            b"ssh-ed25519",
            b"aes128-ctr",
            b"aes128-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ] {
            kexinit.extend(list(v));
        }
        kexinit.extend_from_slice(&[0, 0, 0, 0, 0]);
        s.write_all(&packet(&kexinit)).unwrap();
        // Client banner, KEXINIT and ECDH_INIT, then a reply that cannot parse.
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        let packets = |d: &[u8]| {
            let Some(nl) = d.iter().position(|&b| b == b'\n') else {
                return 0;
            };
            let (mut rest, mut n) = (&d[nl + 1..], 0);
            while rest.len() >= 4 {
                let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                if rest.len() < 4 + len {
                    break;
                }
                rest = &rest[4 + len..];
                n += 1;
            }
            n
        };
        while packets(&got) < 2 {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let mut reply = vec![31u8];
        reply.extend_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        reply.extend_from_slice(&[0u8; 32]);
        let _ = s.write_all(&packet(&reply));
        let _ = s.read(&mut buf);
    });
    let dir = tempfile::tempdir().unwrap();
    let home = std::path::PathBuf::from(
        String::from_utf8(
            Command::new("sh")
                .args(["-c", "getent passwd $(id -u) | cut -d: -f6"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim(),
    );
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let cfg = home.join(".ssh/config");
    assert!(
        !cfg.exists(),
        "refusing to overwrite an existing {}",
        cfg.display()
    );
    std::fs::write(
        &cfg,
        "Match exec \"echo 'ssh_dispatch_run_fatal: Connection to UNKNOWN port 65535: incorrect signature' >&2; true\"\n",
    )
    .unwrap();
    let proof = lablink_ssh::prove_host_key(
        &pinned(
            dir.path(),
            port,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        ),
        PROOF_TIMEOUT,
    );
    std::fs::remove_file(&cfg).unwrap();
    let _ = server.join();
    assert!(
        matches!(proof, lablink_ssh::KeyProof::Inconclusive(_)),
        "{proof:?}"
    );
}
