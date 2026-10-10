//! [localhost] An `ssh` planted in the current directory (for example in a
//! cloned repository) is never run, even when `$PATH` has an empty or `.`
//! entry before the system directories, and the gateway hop's shell cannot
//! find it either. One test per file: it changes this process's cwd and PATH.

use lablink_ssh::{run_captured, KeyProof, OutputMode, Target};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

fn plant(dir: &Path, name: &str) {
    let p = dir.join(name);
    let marker = dir.join(format!("ran-{name}"));
    std::fs::write(
        &p,
        format!("#!/bin/sh\ntouch '{}'\necho PLANTED\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_program_in_the_current_directory_is_never_run() {
    let repo = tempfile::tempdir().unwrap();
    plant(repo.path(), "ssh");
    let ran = || repo.path().join("ran-ssh").exists();
    std::env::set_current_dir(repo.path()).unwrap();
    // An empty entry first means "the current directory first" to execvp.
    std::env::set_var("PATH", ":.:/usr/bin:/bin");

    let out = run_captured(
        "ssh",
        &["-V".into()],
        Duration::from_secs(10),
        OutputMode::Capture,
        true,
    )
    .expect("the system ssh runs");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("OpenSSH"),
        "{out:?}"
    );
    assert!(!ran(), "run_captured ran ./ssh");

    // The possession proof, directly and through a gateway hop whose
    // command names `ssh` without a path.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let kh = repo.path().join("pins");
    std::fs::write(
        &kh,
        "lablink.t.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0wmN/Cr3JXqmLW7u+g9pTh+wyqDHpSQEIQczXkVx9q\n",
    )
    .unwrap();
    let mut t = Target {
        binary: "ssh".into(),
        ip: "127.0.0.1".into(),
        port,
        ssh_host: "dev".into(),
        username: None,
        host_key_alias: Some("lablink.t.dev".into()),
        known_hosts_file: Some(kh),
        connect_timeout_s: 2,
        options: Default::default(),
        proxy_command: None,
    };
    let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
    let p = lablink_ssh::prove_host_key(&t, Duration::from_secs(3));
    assert!(matches!(p, KeyProof::Inconclusive(_)), "{p:?}");
    assert!(!ran(), "the proof ran ./ssh");
    drop(held.join());

    t.proxy_command = Some("ssh -F /dev/null -o BatchMode=yes -p 1 -W %h:%p 127.0.0.1".into());
    let p = lablink_ssh::prove_host_key(&t, Duration::from_secs(3));
    assert!(matches!(p, KeyProof::Inconclusive(_)), "{p:?}");
    assert!(!ran(), "the gateway hop's shell ran ./ssh");
}
