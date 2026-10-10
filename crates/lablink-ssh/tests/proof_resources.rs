//! [integration, localhost] The possession proof releases everything it
//! opened, even when the gateway command leaves a detached process holding
//! its stdin/stdout. Its own test binary, so that no other test changes the
//! descriptor count. Skipped without ssh.

use std::time::{Duration, Instant};

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn a_hop_that_leaves_a_process_behind_leaks_nothing() {
    if !std::process::Command::new("sh")
        .args(["-c", "command -v ssh"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("SKIP: ssh not installed");
        return;
    }
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
        port: 22,
        ssh_host: "dev".into(),
        username: None,
        host_key_alias: Some("lablink.t.dev".into()),
        known_hosts_file: Some(kh),
        connect_timeout_s: 1,
        options: Default::default(),
        // Escapes the hop's process group and keeps its stdio open.
        proxy_command: Some("sh -c 'setsid sleep 20 & exec sleep 20'".into()),
    };
    let timeout = Duration::from_secs(2);
    // Warm-up: the first call caches ssh's option support.
    let _ = lablink_ssh::prove_host_key(&t, timeout);
    let before = open_fds();
    for _ in 0..3 {
        let start = Instant::now();
        let p = lablink_ssh::prove_host_key(&t, timeout);
        assert!(matches!(p, lablink_ssh::KeyProof::Inconclusive(_)), "{p:?}");
        assert!(
            start.elapsed() < timeout + Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    }
    // Relay threads exit once LabLink's end is shut down.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(open_fds(), before, "descriptors leaked");
}
