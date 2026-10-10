//! Exercise the kernel peer UID boundary, independently of socket mode bits.
//! Root fixtures are intended for disposable containers only.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(path: &Path, method: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    writeln!(stream, "{}", serde_json::json!({"method":method})).unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}

#[test]
#[ignore = "subprocess fixture invoked by a_foreign_uid_is_refused_after_connecting"]
fn foreign_uid_peer_fixture() {
    let Some(path) = std::env::var_os("LABLINK_TEST_FOREIGN_PEER_SOCKET") else {
        panic!("this fixture requires a socket supplied by the parent test");
    };
    // SAFETY: getuid is infallible and only reads this child's identity.
    assert_eq!(unsafe { libc::getuid() }, 65534);
    let mut stream = UnixStream::connect(path).expect("foreign UID must reach the socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // A successful connect proves DAC permissions are not doing the rejection.
    // The server may close before the write, so BrokenPipe is also acceptable.
    if let Err(error) = stream.write_all(b"{\"method\":\"ping\"}\n") {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
    }
    let mut response = [0u8; 1024];
    match stream.read(&mut response) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("foreign UID got a response or was not promptly closed: {other:?}"),
    }
    println!("foreign uid 65534 connected and was refused without a response");
}

#[test]
fn a_foreign_uid_is_refused_after_connecting() {
    // SAFETY: getuid is infallible.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("SKIP: actual foreign-UID IPC requires root in a disposable container");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    chmod(root.path(), 0o755);
    let config = root.path().join("config.yaml");
    std::fs::write(&config, "").unwrap();
    chmod(&config, 0o600);
    let config_before = std::fs::read(&config).unwrap();
    let socket = root.path().join("run/lablinkd.sock");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_lablinkd"))
            .args(["--no-netlink", "--no-mdns", "--no-startup-discovery"])
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(root.path().join("state"))
            .arg("--socket")
            .arg(&socket)
            .env("LABLINK_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "daemon did not create its socket"
        );
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited during startup"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(request(&socket, "ping")["version"].is_string());
    let before = request(&socket, "metrics");
    // Relax DAC after bind to isolate SO_PEERCRED from the directory/socket
    // checks. This fixture changes only paths created in its private tempdir.
    chmod(socket.parent().unwrap(), 0o755);
    chmod(&socket, 0o666);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "foreign_uid_peer_fixture",
            "--nocapture",
        ])
        .env("LABLINK_TEST_FOREIGN_PEER_SOCKET", &socket)
        .uid(65534)
        .gid(65534)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    let after = request(&socket, "metrics");
    assert_eq!(
        after["counters"]["ipc_rejected"].as_u64().unwrap(),
        before["counters"]["ipc_rejected"].as_u64().unwrap() + 1
    );
    // Only this test's second metrics request was dispatched, never the peer's.
    assert_eq!(
        after["counters"]["ipc_requests"].as_u64().unwrap(),
        before["counters"]["ipc_requests"].as_u64().unwrap() + 1
    );
    assert_eq!(std::fs::read(config).unwrap(), config_before);
    assert!(request(&socket, "ping")["version"].is_string());
}
