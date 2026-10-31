use lablink_files::{
    transport::{guarded, IdentityGuard},
    worker::BrowseCmd,
    worker::Event,
    worker::Worker,
    Side,
};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    sync::Arc,
    time::Duration,
};

#[test]
fn old_daemon_refusal_explains_matching_daemon_requirement() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let daemon = std::thread::spawn(move || {
        // Exercise direct resolution and the browsing worker's error event.
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["method"], "ping");
            writeln!(
                stream,
                "{}",
                serde_json::json!({"ok":true,"result":{"version":"0.3.1","protocol_version":1}})
            )
            .unwrap();
        }
    });
    let error = IdentityGuard::resolve(&socket, "fixture")
        .err()
        .expect("an old daemon must refuse Files");
    assert!(error.to_string().contains("daemon version"));
    assert!(error.to_string().contains("matching feature daemon"));
    let (worker, events) = Worker::spawn(socket, Arc::new(|| {}));
    worker
        .browse(BrowseCmd::List {
            generation: 1,
            device: "fixture".into(),
            side: Side::Remote,
            path: ".".into(),
        })
        .unwrap();
    match events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Listed {
            generation: 1,
            side: Side::Remote,
            result: Err(error),
            ..
        } => {
            assert!(error.contains("matching feature daemon"));
        }
        _ => panic!("expected visible compatibility error, not an empty listing"),
    }
    drop(worker);
    daemon.join().unwrap();
}

#[test]
fn slow_valid_identity_checks_do_not_starve_transfer_or_cancellation() {
    use lablink_files::{worker::CancellationToken, Error};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("daemon.sock");
    let trust = root.path().join("known_hosts");
    std::fs::write(&trust, "disposable fixture trust\n").unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicUsize::new(0));
    let daemon_stop = stop.clone();
    let daemon_checks = checks.clone();
    let response = serde_json::json!({"ok": true, "result": {
        "schema_version": 1, "name": "fixture", "id": "test/fixture", "ip": "127.0.0.1", "port": 22,
        "ssh_host": "fixture", "identity": "verified", "color": "green",
        "network": "online", "host_key_alias": "lablink.fixture",
        "known_hosts_file": trust, "ssh_binary": "ssh", "connect_timeout_s": 2,
        "ssh_options": {}
    }})
    .to_string();
    let daemon = std::thread::spawn(move || {
        while !daemon_stop.load(Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(stream) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            if request["method"] == "ping" {
                writeln!(stream, "{}", serde_json::json!({"ok":true,"result":{
                    "version":lablink_core::VERSION,"protocol_version":lablink_core::protocol::PROTOCOL_VERSION,
                    "git_sha":lablink_core::GIT_SHA,"files_protocol_version":lablink_core::protocol::FILES_PROTOCOL_VERSION
                }})).unwrap();
                continue;
            }
            assert_eq!(request["params"]["device"], "test/fixture");
            daemon_checks.fetch_add(1, Ordering::SeqCst);
            // Above the 500 ms monitor period, below its 3 s IPC timeout.
            std::thread::sleep(Duration::from_millis(650));
            let _ = writeln!(stream, "{response}");
        }
    });
    let guard = IdentityGuard::resolve(&socket, "test/fixture").unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let cancel = CancellationToken::new();
        let transfer = tokio::time::timeout(
            Duration::from_secs(2),
            guarded(Some(guard.clone()), &cancel, async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            }),
        )
        .await;
        if !matches!(transfer, Ok(Ok(()))) {
            return Err("slow successful checks starved the transfer");
        }
        let before = checks.load(Ordering::SeqCst);
        let trigger = async {
            while checks.load(Ordering::SeqCst) == before {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            cancel.cancel();
        };
        let operation = async {
            tokio::time::timeout(
                Duration::from_millis(400),
                guarded(
                    Some(guard),
                    &cancel,
                    std::future::pending::<lablink_files::Result<()>>(),
                ),
            )
            .await
        };
        let (_, cancelled) = tokio::join!(trigger, operation);
        if !matches!(cancelled, Ok(Err(Error::Cancelled))) {
            return Err("cancellation waited for the slow identity check");
        }
        Ok(())
    });
    stop.store(true, Ordering::SeqCst);
    daemon.join().unwrap();
    assert_eq!(result, Ok(()));
}

#[test]
fn incompatible_security_build_is_refused_before_resolution() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let daemon = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["method"],
            "ping"
        );
        writeln!(
            stream,
            "{}",
            serde_json::json!({"ok":true,"result":{
                "version":"0.1.0","protocol_version":lablink_core::protocol::PROTOCOL_VERSION,
                "files_protocol_version":lablink_core::protocol::FILES_PROTOCOL_VERSION,
                "git_sha":"legacy-security-build"
            }})
        )
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(
            listener.accept().is_err(),
            "incompatible daemon must never receive resolution"
        );
    });
    assert!(IdentityGuard::resolve(&socket, "test/fixture")
        .err()
        .unwrap()
        .to_string()
        .contains("matching LabLink daemon"));
    daemon.join().unwrap();
}
