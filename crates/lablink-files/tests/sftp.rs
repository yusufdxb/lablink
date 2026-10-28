//! Disposable loopback-only OpenSSH fixtures; no lab devices, user SSH config,
//! installation, trust changes or passwords. Missing sshd is an explicit skip
//! unless LABLINK_REQUIRE_SFTP_TESTS=1 (CI sets it).
use lablink_files::{
    fs,
    transfer::{self, Hooks},
    transport::{Connection, IdentityGuard},
    worker, ConflictAction, Direction, Error, Job, Kind, Progress,
};
use lablink_ssh::Target;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::{symlink, PermissionsExt},
        net::UnixListener,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

struct Server {
    root: TempDir,
    child: Child,
    target: Target,
}
impl Server {
    fn new(sftp: bool) -> Option<Self> {
        Self::with_sftp_policy(sftp.then_some(""))
    }
    /// Options apply only to this disposable loopback server's internal SFTP.
    fn with_sftp_policy(options: Option<&str>) -> Option<Self> {
        let binary = std::env::var_os("LABLINK_TEST_SSHD")
            .map(PathBuf::from)
            .or_else(|| {
                [
                    "/usr/sbin/sshd",
                    "/usr/local/sbin/sshd",
                    "/usr/libexec/sshd",
                ]
                .into_iter()
                .map(PathBuf::from)
                .find(|p| p.exists())
            });
        let Some(binary) = binary else {
            assert!(
                std::env::var_os("LABLINK_REQUIRE_SFTP_TESTS").is_none(),
                "sshd is required"
            );
            eprintln!("SKIP SFTP fixture: sshd not installed");
            return None;
        };
        let root = tempfile::tempdir().unwrap();
        let key = |name: &str| {
            let path = root.path().join(name);
            assert!(Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path)
                .status()
                .unwrap()
                .success());
            path
        };
        let host = key("host");
        let identity = key("identity");
        let pubkey = std::fs::read_to_string(root.path().join("host.pub")).unwrap();
        let fields: Vec<_> = pubkey.split_whitespace().collect();
        let known = root.path().join("known_hosts");
        std::fs::write(
            &known,
            format!("lablink.fixture {} {}\n", fields[0], fields[1]),
        )
        .unwrap();
        let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned();
        let config = root.path().join("sshd_config");
        let subsystem = options
            .map(|options| format!("Subsystem sftp internal-sftp {options}\n"))
            .unwrap_or_default();
        let (port, child) = 'bind: {
            let mut attempts = 0;
            loop {
                attempts += 1;
                assert!(attempts <= 8, "fixture exhausted loopback bind retries");
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                drop(listener);
                std::fs::write(&config, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nPermitRootLogin yes\nAllowUsers {user}\nLogLevel VERBOSE\n{subsystem}", host.display(), root.path().join("sshd.pid").display(), identity.with_extension("pub").display())).unwrap();
                let log_path = root.path().join("sshd.log");
                let log = std::fs::File::create(&log_path).unwrap();
                let mut child = Command::new(&binary)
                    .args(["-D", "-e", "-f"])
                    .arg(&config)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(log)
                    .process_group(0)
                    .spawn()
                    .unwrap();
                let start = Instant::now();
                let listening = format!("Server listening on 127.0.0.1 port {port}.");
                loop {
                    let log = std::fs::read_to_string(&log_path).unwrap();
                    if let Some(status) = child.try_wait().unwrap() {
                        // Selecting an ephemeral port cannot reserve it for
                        // sshd. A competing fixture may bind before this child.
                        if log.contains("Address already in use") {
                            break;
                        }
                        panic!("fixture sshd exited {status}: {log}");
                    }
                    // A successful TCP probe alone can be another fixture.
                    // Require THIS child's acknowledgement of its own bind.
                    if log.contains(&listening) && TcpStream::connect(("127.0.0.1", port)).is_ok() {
                        break 'bind (port, child);
                    }
                    if start.elapsed() >= Duration::from_secs(5) {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("fixture startup timed out: {log}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let target = Target {
            binary: "ssh".into(),
            ip: "127.0.0.1".into(),
            port,
            ssh_host: "fixture".into(),
            username: Some(user),
            host_key_alias: Some("lablink.fixture".into()),
            known_hosts_file: Some(known),
            connect_timeout_s: 2,
            options: BTreeMap::from([
                ("IdentityFile".into(), identity.display().to_string()),
                ("IdentitiesOnly".into(), "yes".into()),
                ("LogLevel".into(), "ERROR".into()),
                ("StrictHostKeyChecking".into(), "no".into()),
            ]),
            proxy_command: None,
        };
        Some(Self {
            root,
            child,
            target,
        })
    }
    fn path(&self, name: &str) -> PathBuf {
        std::fs::canonicalize(self.root.path()).unwrap().join(name)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        // SAFETY: only our fixture's private process group.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn hooks(action: ConflictAction) -> Hooks {
    Hooks {
        progress: Arc::new(Mutex::new(Progress::default())),
        items: Arc::new(Mutex::new(Vec::new())),
        verify: None,
        checkpoint: None,
        conflict: Arc::new(move |_, _| {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            sender.send(action).unwrap();
            receiver
        }),
    }
}
fn upload(source: &Path, dest: &Path) -> Job {
    Job {
        id: 1,
        device: "fixture".into(),
        direction: Direction::Upload,
        local: source.into(),
        remote: dest.to_str().unwrap().into(),
    }
}
fn download(source: &Path, dest: &Path) -> Job {
    Job {
        id: 2,
        device: "fixture".into(),
        direction: Direction::Download,
        local: dest.into(),
        remote: source.to_str().unwrap().into(),
    }
}

#[test]
fn bidirectional_recursive_bytes_names_empty_files_and_symlinks() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let local = server.path("local");
    let remote = server.path("remote");
    let output = server.path("output");
    for dir in [&local, &remote, &output] {
        std::fs::create_dir(dir).unwrap();
    }
    let tree = local.join("Unicode 空间 folder ' $() ;");
    std::fs::create_dir(&tree).unwrap();
    std::fs::create_dir(tree.join("empty folder")).unwrap();
    std::fs::write(tree.join("empty"), []).unwrap();
    std::fs::write(tree.join("café 日本語.txt"), b"bytes, not shell commands").unwrap();
    let large: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(tree.join("large.bin"), &large).unwrap();
    symlink("/etc/passwd", tree.join("link")).unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let listing = fs::remote_listing(&connection.sftp, tree.to_str().unwrap(), &cancel)
            .await
            .unwrap();
        assert_eq!(
            listing
                .entries
                .iter()
                .find(|e| e.name == "link")
                .unwrap()
                .kind,
            Kind::Symlink
        );
        let h = hooks(ConflictAction::Skip);
        let out = transfer::run(&connection, &upload(&tree, &remote), &h, &cancel)
            .await
            .unwrap();
        assert_eq!(
            out.progress.bytes,
            (large.len() + b"bytes, not shell commands".len()) as u64
        );
        assert_eq!(out.progress.bytes, out.progress.total);
        assert_eq!(out.progress.files_done, 3);
        assert_eq!(out.progress.skipped, 1);
        let copied = remote.join(tree.file_name().unwrap());
        assert!(!copied.join("link").exists());
        assert!(copied.join("empty folder").is_dir());
        let out = transfer::run(
            &connection,
            &download(&copied, &output),
            &hooks(ConflictAction::Skip),
            &cancel,
        )
        .await
        .unwrap();
        assert_eq!(
            out.progress.bytes,
            (large.len() + b"bytes, not shell commands".len()) as u64
        );
        let returned = output.join(tree.file_name().unwrap());
        assert_eq!(std::fs::read(returned.join("large.bin")).unwrap(), large);
        assert_eq!(
            std::fs::read(returned.join("café 日本語.txt")).unwrap(),
            b"bytes, not shell commands"
        );
        assert_eq!(std::fs::metadata(returned.join("empty")).unwrap().len(), 0);
        assert_eq!(
            std::fs::metadata(returned.join("large.bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    });
}
#[test]
fn explicit_collisions_both_directions_and_no_clobber_rename() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let a = server.path("source");
    let b = server.path("destination");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    std::fs::write(a.join("a.txt"), b"new").unwrap();
    std::fs::write(b.join("a.txt"), b"old").unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        transfer::run(
            &conn,
            &upload(&a.join("a.txt"), &b),
            &hooks(ConflictAction::Skip),
            &c,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(b.join("a.txt")).unwrap(), b"old");
        transfer::run(
            &conn,
            &upload(&a.join("a.txt"), &b),
            &hooks(ConflictAction::KeepBoth),
            &c,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(b.join("a (copy 1).txt")).unwrap(), b"new");
        let e = transfer::run(
            &conn,
            &upload(&a.join("a.txt"), &b),
            &hooks(ConflictAction::Replace),
            &c,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("Replace refused"));
        assert_eq!(std::fs::read(b.join("a.txt")).unwrap(), b"old");
        transfer::run(
            &conn,
            &download(&b.join("a (copy 1).txt"), &a),
            &hooks(ConflictAction::Skip),
            &c,
        )
        .await
        .unwrap();
        transfer::run(
            &conn,
            &download(&b.join("a (copy 1).txt"), &a),
            &hooks(ConflictAction::KeepBoth),
            &c,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(a.join("a (copy 1) (copy 1).txt")).unwrap(),
            b"new"
        );
        assert!(transfer::run(
            &conn,
            &download(&b.join("a.txt"), &a),
            &hooks(ConflictAction::Replace),
            &c
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("Replace refused"));
        assert_eq!(std::fs::read(a.join("a.txt")).unwrap(), b"new");
        assert!(
            fs::remote_rename(&conn.sftp, b.to_str().unwrap(), "a.txt", "a (copy 1).txt")
                .await
                .is_err()
        );
        assert!(fs::local_rename(&a, "a.txt", "a (copy 1).txt").is_err());
        fs::remote_mkdir(&conn.sftp, b.to_str().unwrap(), "new directory")
            .await
            .unwrap();
        fs::remote_rename(
            &conn.sftp,
            b.to_str().unwrap(),
            "new directory",
            "renamed 空间",
        )
        .await
        .unwrap_err();
        assert!(b.join("new directory").is_dir());
        assert!(!b.join("renamed 空间").exists());
    });
}

#[test]
fn remote_symlink_ancestors_and_destination_links_refused() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"safe").unwrap();
    let dest = server.path("dest");
    std::fs::create_dir(&dest).unwrap();
    symlink(&source, dest.join("data")).unwrap();
    symlink(&dest, server.path("linked folder")).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        assert!(transfer::run(
            &conn,
            &upload(&source, &dest),
            &hooks(ConflictAction::Replace),
            &c
        )
        .await
        .is_err());
        assert!(
            fs::remote_dir(&conn.sftp, server.path("linked folder").to_str().unwrap())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"safe");
    });
    let (dir, _) = fs::local_root(&dest).unwrap();
    assert!(fs::local_open(&dir, "data", false).is_err());
}
#[test]
fn unavailable_subsystem_and_pinned_key_mismatch_fail_closed() {
    let Some(server) = Server::new(false) else {
        return;
    };
    runtime().block_on(async {
        let error = Connection::connect(&server.target, &CancellationToken::new())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("Unsupported server"), "{error}");
    });
    let Some(mut server) = Server::new(true) else {
        return;
    };
    // Pin a different disposable server's key; config tries to weaken strict checking.
    let other = std::fs::read(server.target.known_hosts_file.as_ref().unwrap()).unwrap();
    let Some(other_server) = Server::new(true) else {
        return;
    };
    std::fs::write(
        server.target.known_hosts_file.as_ref().unwrap(),
        std::fs::read(other_server.target.known_hosts_file.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    runtime().block_on(async {
        let error = Connection::connect(&server.target, &CancellationToken::new())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("host-key"), "{error}");
    });
    std::fs::write(server.target.known_hosts_file.as_ref().unwrap(), other).unwrap();
    server.target.host_key_alias = None;
    runtime().block_on(async {
        assert!(
            Connection::connect(&server.target, &CancellationToken::new())
                .await
                .is_err()
        );
    });
}

struct Daemon {
    socket: PathBuf,
    resolved: Arc<Mutex<serde_json::Value>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Daemon {
    fn new(server: &Server) -> Self {
        let socket = server.path("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let t = &server.target;
        let resolved = Arc::new(Mutex::new(serde_json::json!({"ok":true,"result":{
            "schema_version":1,"name":"fixture","id":"test/fixture","ip":t.ip,"port":t.port,"ssh_host":t.ssh_host,"username":t.username,
            "identity":"verified","color":"green","network":"online","host_key_alias":t.host_key_alias,"known_hosts_file":t.known_hosts_file,
            "ssh_binary":t.binary,"connect_timeout_s":t.connect_timeout_s,"ssh_options":t.options,"proxy_command":null
        }})));
        let stop = Arc::new(AtomicBool::new(false));
        let (state, done) = (resolved.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut line = String::new();
                        BufReader::new(&stream).read_line(&mut line).unwrap();
                        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                        if request["method"] == "ping" {
                            writeln!(stream, "{}", serde_json::json!({"ok":true,"result":{
                                "version":lablink_core::VERSION,"protocol_version":lablink_core::protocol::PROTOCOL_VERSION,
                                "git_sha":lablink_core::GIT_SHA,"files_protocol_version":lablink_core::protocol::FILES_PROTOCOL_VERSION
                            }})).unwrap();
                            continue;
                        }
                        assert_eq!(request["method"], "resolve_files");
                        let data = state.lock().unwrap().clone();
                        let _ = writeln!(stream, "{data}");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        Self {
            socket,
            resolved,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn cancellation_and_retry_preserve_destination_and_cleanup_staging() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("large.bin");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    let dest = server.path("dest");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("large.bin"), b"previous").unwrap();
    runtime().block_on(async {
        let mut h = hooks(ConflictAction::KeepBoth);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::ChunkWritten {
                c.cancel();
            }
            Ok(())
        }));
        assert!(matches!(
            worker::execute_job(&daemon.socket, &upload(&source, &dest), &h, &cancel).await,
            Err(Error::Cancelled)
        ));
        assert_eq!(std::fs::read(dest.join("large.bin")).unwrap(), b"previous");
        assert!(!dest.join("large (copy 1).bin").exists());
        let retained: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                e.file_name()
                    .to_str()
                    .unwrap()
                    .starts_with(".lablink-transfer-")
                    .then_some(e.path())
            })
            .collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(
            std::fs::metadata(&retained[0])
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let out = worker::execute_job(
            &daemon.socket,
            &upload(&source, &dest),
            &hooks(ConflictAction::KeepBoth),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(out.progress.bytes, 2 * 1024 * 1024);
        assert_eq!(
            std::fs::metadata(dest.join("large (copy 1).bin"))
                .unwrap()
                .len(),
            2 * 1024 * 1024
        );
        let output = server.path("output");
        std::fs::create_dir(&output).unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::ChunkWritten {
                c.cancel();
            }
            Ok(())
        }));
        assert!(matches!(
            worker::execute_job(
                &daemon.socket,
                &download(&dest.join("large (copy 1).bin"), &output),
                &h,
                &cancel
            )
            .await,
            Err(Error::Cancelled)
        ));
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
    });
}

#[test]
fn changed_trust_and_daemon_ambiguity_stop_transfers() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let guard = IdentityGuard::resolve(&daemon.socket, "fixture").unwrap();
    std::fs::write(
        server.target.known_hosts_file.as_ref().unwrap(),
        "changed trust\n",
    )
    .unwrap();
    assert!(guard.check().is_err());
    *daemon.resolved.lock().unwrap() = serde_json::json!({"ok":false,"error":{"code":"identity_mismatch","message":"ambiguous across sites"}});
    let h = hooks(ConflictAction::Skip);
    runtime().block_on(async {
        let error = worker::execute_job(
            &daemon.socket,
            &upload(&server.path("not-read"), server.root.path()),
            &h,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous across sites"));
        assert_eq!(h.progress.lock().unwrap().bytes, 0);
    });
}
#[test]
fn permission_errors_and_conflict_wait_cancellation() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("source");
    std::fs::write(&source, b"safe").unwrap();
    let dest = server.path("locked");
    std::fs::create_dir(&dest).unwrap();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o500)).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(transfer::run(
                &conn,
                &upload(&source, &dest),
                &hooks(ConflictAction::Skip),
                &c
            )
            .await
            .is_err());
        }
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dest.join("source"), b"old").unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let cancel = c.clone();
        let held = Arc::new(Mutex::new(None));
        let keep = held.clone();
        h.conflict = Arc::new(move |_, _| {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            *keep.lock().unwrap() = Some(sender);
            cancel.cancel();
            receiver
        });
        assert!(matches!(
            transfer::run(&conn, &upload(&source, &dest), &h, &c).await,
            Err(Error::Cancelled)
        ));
        assert_eq!(std::fs::read(dest.join("source")).unwrap(), b"old");
    });
}
#[test]
fn disconnection_during_operation_is_an_error() {
    let Some(server) = Server::new(true) else {
        return;
    };
    runtime().block_on(async {
        let c = CancellationToken::new();
        let connection = Connection::connect(&server.target, &c).await.unwrap();
        connection.sftp.close_session().unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            fs::remote_listing(
                &connection.sftp,
                std::fs::canonicalize(server.root.path())
                    .unwrap()
                    .to_str()
                    .unwrap(),
                &c,
            ),
        )
        .await;
        assert!(result.unwrap().is_err());
    });
}

#[test]
fn trust_change_during_conflict_wait_prevents_publication() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("data");
    std::fs::write(&source, b"new source").unwrap();
    let destination = server.path("destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("data"), b"previous").unwrap();
    let mut h = hooks(ConflictAction::Replace);
    let resolved = daemon.resolved.clone();
    h.conflict = Arc::new(move |_, _| {
        *resolved.lock().unwrap() = serde_json::json!({"ok":false,"error":{"code":"identity_mismatch","message":"changed trust"}});
        let (sender, receiver) = tokio::sync::oneshot::channel();
        sender.send(ConflictAction::Replace).unwrap();
        receiver
    });
    runtime().block_on(async {
        let error = worker::execute_job(
            &daemon.socket,
            &upload(&source, &destination),
            &h,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("changed trust"));
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"previous"
        );
        assert_eq!(h.progress.lock().unwrap().bytes, 0);
    });
}
#[test]
fn changed_destination_after_conflict_does_not_overwrite() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"new").unwrap();
    let destination = server.path("destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("data"), b"old").unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let mut h = hooks(ConflictAction::Replace);
        let path = destination.join("data");
        h.conflict = Arc::new(move |_, _| {
            std::fs::write(&path, b"changed by another writer").unwrap();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            sender.send(ConflictAction::Replace).unwrap();
            receiver
        });
        assert!(
            transfer::run(&connection, &upload(&source, &destination), &h, &cancel)
                .await
                .unwrap_err()
                .to_string()
                .contains("Replace refused")
        );
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"changed by another writer"
        );
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 1);
    });
}
#[test]
fn recursive_folder_merge_and_keep_both_are_explicit() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("tree");
    let destination = server.path("destination");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::create_dir(destination.join("tree")).unwrap();
    std::fs::write(source.join("data"), b"new").unwrap();
    std::fs::write(destination.join("tree/data"), b"old").unwrap();
    std::fs::write(destination.join("tree/retained"), b"keep").unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let conn = Connection::connect(&server.target, &cancel).await.unwrap();
        transfer::run(
            &conn,
            &upload(&source, &destination),
            &hooks(ConflictAction::KeepBoth),
            &cancel,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(destination.join("tree (copy 1)/data")).unwrap(),
            b"new"
        );
        let mut h = hooks(ConflictAction::Skip);
        h.conflict = Arc::new(|_, kind| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tx.send(if kind == Kind::Directory {
                ConflictAction::Replace
            } else {
                ConflictAction::KeepBoth
            })
            .unwrap();
            rx
        });
        transfer::run(&conn, &upload(&source, &destination), &h, &cancel)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(destination.join("tree/data")).unwrap(),
            b"old"
        );
        assert_eq!(
            std::fs::read(destination.join("tree/data (copy 1)")).unwrap(),
            b"new"
        );
        assert_eq!(
            std::fs::read(destination.join("tree/retained")).unwrap(),
            b"keep"
        );
    });
}

#[test]
fn transport_loss_mid_copy_never_publishes_partial_file() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("large.bin");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let destination = server.path("destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("large.bin"), b"previous").unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let h = hooks(ConflictAction::KeepBoth);
        let job = upload(&source, &destination);
        let operation = transfer::run(&connection, &job, &h, &cancel);
        let cut_transport = async {
            loop {
                if h.progress.lock().unwrap().bytes > 0 {
                    connection.abort();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let (result, _) = tokio::join!(operation, cut_transport);
        assert!(result.is_err());
        assert!(h.progress.lock().unwrap().bytes < 64 * 1024 * 1024);
        assert_eq!(
            std::fs::read(destination.join("large.bin")).unwrap(),
            b"previous"
        );
        // Loss of transport may leave .lablink-transfer-*; never delete arbitrary files.
        assert!(std::fs::read_dir(&destination).unwrap().all(|e| {
            let name = e.unwrap().file_name();
            name == "large.bin" || name.to_str().unwrap().starts_with(".lablink-transfer-")
        }));
    });
}

#[test]
fn bounded_queue_cancelled_jobs_and_browsing_during_conflict() {
    use lablink_files::{
        worker::{BrowseCmd, Event, Worker},
        Side,
    };
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"new").unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("data"), b"old").unwrap();
    let (worker, events) = Worker::spawn(daemon.socket.clone(), Arc::new(|| {}));
    let job = upload(&source, &destination);
    worker.enqueue(job.clone()).unwrap();
    let reply = match events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Conflict { reply, .. } => reply,
        _ => panic!("expected conflict"),
    };
    // The active transfer is parked; exactly 128 pending slots can be used.
    for id in 2..=129 {
        let mut queued = job.clone();
        queued.id = id;
        let handle = worker.enqueue(queued).unwrap();
        handle.cancel.cancel();
    }
    let mut rejected = job.clone();
    rejected.id = 130;
    assert!(worker.enqueue(rejected).is_err());
    worker
        .browse(BrowseCmd::List {
            generation: 7,
            device: "fixture".into(),
            side: Side::Local,
            path: destination.to_str().unwrap().into(),
        })
        .unwrap();
    match events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::Listed {
            generation: 7,
            result: Ok(listing),
            ..
        } => assert_eq!(listing.entries.len(), 1),
        _ => panic!("browsing blocked behind conflict"),
    }
    reply.send(ConflictAction::Skip).unwrap();
    let mut completed = 0;
    while completed < 129 {
        match events.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Finished {
                id: 1,
                result: Ok(_),
            } => completed += 1,
            Event::Finished {
                id,
                result: Err(error),
            } => {
                assert!(id >= 2);
                assert!(error.contains("cancelled"));
                completed += 1;
            }
            _ => panic!("unexpected result"),
        }
    }
    assert_eq!(std::fs::read(destination.join("data")).unwrap(), b"old");
}

#[test]
fn trust_revoked_after_copy_starts_preserves_old_destination() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("large.bin");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();
    let destination = server.path("destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("large.bin"), b"previous").unwrap();
    runtime().block_on(async {
        let mut h=hooks(ConflictAction::KeepBoth);let state=daemon.resolved.clone();
        h.checkpoint=Some(Arc::new(move |p| {if p.boundary==Boundary::ChunkWritten {*state.lock().unwrap()=serde_json::json!({"ok":false,"error":{"code":"identity_mismatch","message":"revoked during copy"}});}Ok(())}));
        let result=worker::execute_job(&daemon.socket,&upload(&source,&destination),&h,&CancellationToken::new()).await;
        assert!(result.unwrap_err().to_string().contains("revoked during copy"));
        assert_eq!(h.progress.lock().unwrap().bytes,32*1024);assert_eq!(std::fs::read(destination.join("large.bin")).unwrap(),b"previous");
        assert!(!destination.join("large (copy 1).bin").exists());
    });
}

#[test]
fn replaced_source_after_planning_is_refused_before_copy() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"old").unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("data"), b"destination").unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let mut h = hooks(ConflictAction::KeepBoth);
        let changed = source.clone();
        let substitute = server.path("substitute");
        h.conflict = Arc::new(move |_, _| {
            // Same byte length, different inode: size-only validation would miss this.
            std::fs::write(&substitute, b"new").unwrap();
            std::fs::rename(&substitute, &changed).unwrap();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            sender.send(ConflictAction::KeepBoth).unwrap();
            receiver
        });
        assert!(
            transfer::run(&connection, &upload(&source, &destination), &h, &cancel)
                .await
                .unwrap_err()
                .to_string()
                .contains("Source changed")
        );
        assert_eq!(h.progress.lock().unwrap().bytes, 0);
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"destination"
        );
    });
}

#[test]
fn remote_staging_collision_and_substitution_never_authorize_cleanup() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"ours").unwrap();
    std::fs::create_dir(&destination).unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let conn = Connection::connect(&server.target, &cancel).await.unwrap();
        let foreign = Arc::new(Mutex::new(None));
        let saved = foreign.clone();
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::StagePlanned {
                let path = PathBuf::from(p.staging.unwrap());
                std::fs::write(&path, b"foreign collision").unwrap();
                *saved.lock().unwrap() = Some(path);
            }
            Ok(())
        }));
        assert!(
            transfer::run(&conn, &upload(&source, &destination), &h, &cancel)
                .await
                .is_err()
        );
        assert!(conn.retained_stages().is_empty());
        conn.cleanup().await;
        assert_eq!(
            std::fs::read(foreign.lock().unwrap().as_ref().unwrap()).unwrap(),
            b"foreign collision"
        );
        let mut h = hooks(ConflictAction::Skip);
        let replaced = Arc::new(Mutex::new(None));
        let saved = replaced.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::BeforePublish {
                let path = PathBuf::from(p.staging.unwrap());
                std::fs::rename(&path, path.with_extension("owned-moved")).unwrap();
                std::fs::write(&path, b"foreign replacement").unwrap();
                *saved.lock().unwrap() = Some(path);
            }
            Ok(())
        }));
        let result = transfer::run(&conn, &upload(&source, &destination), &h, &cancel).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("staging substituted"));
        conn.cleanup().await;
        assert_eq!(
            std::fs::read(replaced.lock().unwrap().as_ref().unwrap()).unwrap(),
            b"foreign replacement"
        );
        assert!(!destination.join("data").exists());
    });
}
#[test]
fn concurrent_sftp_sessions_publish_one_complete_winner() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let a = server.path("a");
    let b = server.path("b");
    let out = server.path("out");
    for d in [&a, &b, &out] {
        std::fs::create_dir(d).unwrap();
    }
    let bytes_a = vec![0x41; 1024 * 1024];
    let bytes_b = vec![0x42; 1024 * 1024];
    std::fs::write(a.join("same.bin"), &bytes_a).unwrap();
    std::fs::write(b.join("same.bin"), &bytes_b).unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let one = Connection::connect(&server.target, &cancel).await.unwrap();
        let two = Connection::connect(&server.target, &cancel).await.unwrap();
        assert_ne!(one.process_id(), two.process_id());
        let h1 = hooks(ConflictAction::Skip);
        let h2 = hooks(ConflictAction::Skip);
        let j1 = upload(&a.join("same.bin"), &out);
        let j2 = upload(&b.join("same.bin"), &out);
        let (r1, r2) = tokio::join!(
            transfer::run(&one, &j1, &h1, &cancel),
            transfer::run(&two, &j2, &h2, &cancel)
        );
        assert!(r1.is_ok() || r2.is_ok());
        assert_eq!(
            h1.progress.lock().unwrap().files_done + h2.progress.lock().unwrap().files_done,
            1
        );
        let data = std::fs::read(out.join("same.bin")).unwrap();
        assert!(data == bytes_a || data == bytes_b);
    });
}
#[test]
fn independent_writer_and_symlink_win_without_being_overwritten() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let out = server.path("out");
    std::fs::write(&source, b"ours").unwrap();
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let path = out.join("data");
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::BeforePublish {
                assert!(Command::new("python3")
                    .args([
                        "-c",
                        "import sys;open(sys.argv[1],'xb').write(b'independent')"
                    ])
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success());
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &upload(&source, &out), &h, &c)
            .await
            .is_err());
        assert_eq!(std::fs::read(out.join("data")).unwrap(), b"independent");
        let local = server.path("local");
        std::fs::create_dir(&local).unwrap();
        let outside = server.path("outside");
        std::fs::write(&outside, b"unrelated").unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let dest = local.join("data");
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::BeforePublish {
                symlink(&outside, &dest).unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &download(&source, &local), &h, &c)
            .await
            .is_err());
        assert!(local.join("data").is_symlink());
        assert_eq!(std::fs::read(local.join("data")).unwrap(), b"unrelated");
    });
}
#[test]
fn scheduled_io_faults_never_publish_partial_files() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, vec![1u8; 96 * 1024]).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for (i, boundary, errno) in [
            (0, Boundary::ChunkWritten, libc::ENOSPC),
            (1, Boundary::BeforePublish, libc::EIO),
        ] {
            let remote = server.path(&format!("remote-{i}"));
            let local = server.path(&format!("local-{i}"));
            std::fs::create_dir(&remote).unwrap();
            std::fs::create_dir(&local).unwrap();
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    Err(std::io::Error::from_raw_os_error(errno).into())
                } else {
                    Ok(())
                }
            }));
            assert!(matches!(
                transfer::run(&conn, &upload(&source, &remote), &h, &c).await,
                Err(Error::Io(_))
            ));
            assert!(!remote.join("data").exists());
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    Err(std::io::Error::from_raw_os_error(errno).into())
                } else {
                    Ok(())
                }
            }));
            assert!(matches!(
                transfer::run(&conn, &download(&source, &local), &h, &c).await,
                Err(Error::Io(_))
            ));
            assert_eq!(std::fs::read_dir(&local).unwrap().count(), 0);
        }
    });
}
#[test]
fn server_write_and_fsync_refusals_never_publish_and_retain_staging() {
    use lablink_files::Publication;
    for (policy, expected_bytes, expected_staging_size) in
        [("-P write", 0, 0), ("-P fsync", 96 * 1024, 96 * 1024)]
    {
        let Some(server) = Server::with_sftp_policy(Some(policy)) else {
            return;
        };
        let source = server.path("data");
        let destination = server.path("destination");
        std::fs::write(&source, vec![0x41; 96 * 1024]).unwrap();
        std::fs::create_dir(&destination).unwrap();
        runtime().block_on(async {
            let cancel = CancellationToken::new();
            let mut connection = Connection::connect(&server.target, &cancel).await.unwrap();
            assert!(connection.hardlink);
            if policy == "-P fsync" {
                // OpenSSH suppresses denied extensions from its advertisement.
                // Verify the real negotiated refusal first, then override ONLY
                // this fixture connection to exercise an actual FSYNC denial
                // as if permission changed after extension negotiation.
                assert!(!connection.fsync);
                let h = hooks(ConflictAction::Skip);
                assert!(
                    transfer::run(&connection, &upload(&source, &destination), &h, &cancel)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("safe publication")
                );
                assert!(connection.retained_stages().is_empty());
                assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
                connection.fsync = true;
            } else {
                assert!(connection.fsync);
            }
            let h = hooks(ConflictAction::Skip);
            let error = transfer::run(&connection, &upload(&source, &destination), &h, &cancel)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    Error::Sftp(russh_sftp::client::error::Error::Status(ref status))
                        if status.status_code == russh_sftp::protocol::StatusCode::PermissionDenied
                ),
                "unexpected {policy} error: {error}"
            );
            {
                let progress = h.progress.lock().unwrap();
                assert_eq!(progress.bytes, expected_bytes);
                assert_eq!(progress.publication, Publication::NotRequested);
                assert_eq!(progress.files_done, 0);
            }
            assert!(!destination.join("data").exists());
            let stages = connection.retained_stages();
            assert_eq!(stages.len(), 1);
            connection.cleanup().await;
            let metadata = std::fs::metadata(&stages[0]).unwrap();
            assert_eq!(metadata.len(), expected_staging_size);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 1);
        });
    }
}

/// The resource limit and ignored signal affect only an isolated test process.
/// This exercises the real download write_all failure, not a checkpoint error.
#[test]
fn actual_local_write_failure_in_isolated_child_never_publishes() {
    const CHILD_MARKER: &str = "LABLINK_FILES_FSIZE_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "actual_local_write_failure_in_isolated_child_never_publishes",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated local write failure test failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, vec![0x41; 96 * 1024]).unwrap();
    std::fs::create_dir(&destination).unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        // Spawn both SSH and the fixture server before changing child limits.
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let limit = libc::rlimit {
            rlim_cur: 16 * 1024,
            rlim_max: 16 * 1024,
        };
        // SAFETY: this branch runs only in the disposable child process. No
        // parent limit, signal handler, service, or application state changes.
        unsafe {
            assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        }
        let h = hooks(ConflictAction::Skip);
        let error = transfer::run(&connection, &download(&source, &destination), &h, &cancel)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Io(ref error) if error.raw_os_error() == Some(libc::EFBIG)),
            "unexpected local write error: {error}"
        );
        assert_eq!(h.progress.lock().unwrap().files_done, 0);
        assert_eq!(
            h.progress.lock().unwrap().publication,
            lablink_files::Publication::NotRequested
        );
        assert!(!destination.join("data").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    });
}

#[test]
fn cancellation_at_commit_boundaries_reports_confirmed_publication() {
    use lablink_files::Publication;
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"complete").unwrap();
    runtime().block_on(async {
        for (i, boundary, expected) in [
            (0, Boundary::BeforePublish, Publication::NotRequested),
            (1, Boundary::Published, Publication::Confirmed),
        ] {
            let destination = server.path(&format!("destination-{i}"));
            std::fs::create_dir(&destination).unwrap();
            let c = CancellationToken::new();
            let conn = Connection::connect(&server.target, &c).await.unwrap();
            let mut h = hooks(ConflictAction::Skip);
            let token = c.clone();
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    token.cancel();
                }
                Ok(())
            }));
            assert!(matches!(
                transfer::run(&conn, &upload(&source, &destination), &h, &c).await,
                Err(Error::Cancelled)
            ));
            assert_eq!(h.progress.lock().unwrap().publication, expected);
            if expected == Publication::Confirmed {
                assert_eq!(
                    std::fs::read(destination.join("data")).unwrap(),
                    b"complete"
                );
            } else {
                assert!(!destination.join("data").exists());
            }
        }
    });
}
#[test]
fn source_changes_with_restored_mtime_and_directory_substitution_are_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, vec![0x41; 96 * 1024]).unwrap();
    let out = server.path("out");
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let path = source.clone();
        let mtime = std::fs::metadata(&source).unwrap().modified().unwrap();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::Copied {
                std::fs::write(&path, vec![0x42; 96 * 1024]).unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(mtime))
                    .unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &download(&source, &out), &h, &c)
            .await
            .unwrap_err()
            .to_string()
            .contains("source content changed"));
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
        let directory = server.path("tree");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("original"), b"safe").unwrap();
        let moved = server.path("original-tree");
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::SourceDirectoryOpening {
                std::fs::rename(&directory, &moved).unwrap();
                std::fs::create_dir(&directory).unwrap();
                std::fs::write(directory.join("foreign"), b"substitute").unwrap();
            }
            Ok(())
        }));
        assert!(
            transfer::run(&conn, &upload(&server.path("tree"), &out), &h, &c)
                .await
                .unwrap_err()
                .to_string()
                .contains("directory substituted")
        );
        assert!(!out.join("tree").exists());
    });
}
#[test]
fn missing_publication_extensions_are_refused_before_writing() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"data").unwrap();
    let out = server.path("out");
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let mut conn = Connection::connect(&server.target, &c).await.unwrap();
        conn.hardlink = false;
        assert!(transfer::run(
            &conn,
            &upload(&source, &out),
            &hooks(ConflictAction::Skip),
            &c
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("safe publication"));
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    });
}
#[test]
fn trust_refusal_is_latched_even_after_state_is_restored() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let guard = IdentityGuard::resolve(&daemon.socket, "fixture").unwrap();
    let original = daemon.resolved.lock().unwrap().clone();
    *daemon.resolved.lock().unwrap() =
        serde_json::json!({"ok":false,"error":{"code":"identity_mismatch","message":"revoked"}});
    assert!(guard.check().is_err());
    *daemon.resolved.lock().unwrap() = original;
    assert!(guard.check().is_err());
    assert!(guard.clone().check().is_err());
    assert!(IdentityGuard::resolve(&daemon.socket, "fixture")
        .unwrap()
        .check()
        .is_ok());
}
#[test]
fn failed_connection_and_drop_reap_the_private_ssh_child() {
    let Some(server) = Server::new(true) else {
        return;
    };
    runtime().block_on(async {
        let connection = Connection::connect(&server.target, &CancellationToken::new())
            .await
            .unwrap();
        let pid = connection.process_id().unwrap() as i32;
        drop(connection);
        // SAFETY: querying our child PID; no signal or mutation of another process.
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    });
}

#[test]
fn persistent_symlink_substitution_of_remote_source_is_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let chosen = server.path("chosen");
    let out = server.path("out");
    std::fs::create_dir(&chosen).unwrap();
    std::fs::create_dir(&out).unwrap();
    let source = chosen.join("data");
    let outside = server.path("outside");
    std::fs::write(&source, b"authorized").unwrap();
    std::fs::write(&outside, b"different!").unwrap();
    let time = std::fs::metadata(&source).unwrap().modified().unwrap();
    std::fs::File::options()
        .write(true)
        .open(&outside)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(time))
        .unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let path = source.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::RemoteSourceOpening {
                std::fs::rename(&path, path.with_extension("original")).unwrap();
                symlink(&outside, &path).unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &download(&source, &out), &h, &c)
            .await
            .unwrap_err()
            .to_string()
            .contains("pathname substituted"));
        assert_eq!(h.progress.lock().unwrap().bytes, 0);
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    });
}
/// This passing test proves a remaining capability gap, NOT safe containment.
/// A hostile same-UID server process can swap-and-restore around SFTP OPEN.
/// All data here is disposable fixture data; it is a merge blocker in the report.
#[test]
fn documented_sftp_open_swap_restore_limit_is_reproduced() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let chosen = server.path("chosen");
    let out = server.path("out");
    std::fs::create_dir(&chosen).unwrap();
    std::fs::create_dir(&out).unwrap();
    let source = chosen.join("data");
    let outside = server.path("outside");
    std::fs::write(&source, b"authorized").unwrap();
    std::fs::write(&outside, b"different!").unwrap();
    let time = std::fs::metadata(&source).unwrap().modified().unwrap();
    std::fs::File::options()
        .write(true)
        .open(&outside)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(time))
        .unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let path = source.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            match p.boundary {
                Boundary::RemoteSourceOpening => {
                    std::fs::rename(&path, path.with_extension("original")).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                Boundary::RemoteSourceOpened => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::rename(path.with_extension("original"), &path).unwrap();
                }
                _ => (),
            }
            Ok(())
        }));
        transfer::run(&conn, &download(&source, &out), &h, &c)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"authorized");
        assert_eq!(std::fs::read(out.join("data")).unwrap(), b"different!");
    });
}
#[test]
fn failed_publication_is_uncertain_and_never_removes_competing_file() {
    use lablink_files::Publication;
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let out = server.path("out");
    std::fs::write(&source, b"ours").unwrap();
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let path = out.join("data");
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::BeforePublish {
                std::fs::write(&path, b"competing").unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &upload(&source, &out), &h, &c)
            .await
            .is_err());
        assert_eq!(
            h.progress.lock().unwrap().publication,
            Publication::Uncertain
        );
        conn.cleanup().await;
        assert_eq!(std::fs::read(out.join("data")).unwrap(), b"competing");
    });
}
#[test]
fn saturated_gui_events_refuse_conflict_without_blocking_active_transport() {
    use lablink_files::{
        worker::{BrowseCmd, Event, Worker},
        Side,
    };
    use std::sync::atomic::AtomicUsize;
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("data");
    let out = server.path("out");
    std::fs::write(&source, b"new").unwrap();
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("data"), b"old").unwrap();
    let paints = Arc::new(AtomicUsize::new(0));
    let count = paints.clone();
    let (worker, events) = Worker::spawn(
        daemon.socket.clone(),
        Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }),
    );
    for generation in 0..64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let cmd = BrowseCmd::List {
                generation,
                device: "fixture".into(),
                side: Side::Local,
                path: out.to_str().unwrap().into(),
            };
            if worker.browse(cmd).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while paints.load(Ordering::SeqCst) < 128 {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let handle = worker.enqueue(upload(&source, &out)).unwrap();
    // Two additional repaints mean the conflict try_send returned (never blocked).
    while paints.load(Ordering::SeqCst) < 130 {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let mut finished = false;
    for _ in 0..65 {
        if let Event::Finished {
            result: Err(error), ..
        } = events.recv_timeout(Duration::from_secs(5)).unwrap()
        {
            assert!(error.contains("Conflict decision channel"));
            finished = true;
        }
    }
    assert!(finished);
    assert_eq!(handle.progress.lock().unwrap().bytes, 0);
    assert_eq!(std::fs::read(out.join("data")).unwrap(), b"old");
}

#[test]
fn same_metadata_remote_staging_substitution_is_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"authorized").unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for replace_inode in [false, true] {
            let out = server.path(&format!("out-{replace_inode}"));
            std::fs::create_dir(&out).unwrap();
            let foreign = Arc::new(Mutex::new(None));
            let saved = foreign.clone();
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == Boundary::BeforePublish {
                    let path = PathBuf::from(p.staging.unwrap());
                    let metadata = std::fs::metadata(&path).unwrap();
                    if replace_inode {
                        std::fs::rename(&path, path.with_extension("original")).unwrap();
                    }
                    std::fs::write(&path, b"different!").unwrap();
                    std::fs::set_permissions(&path, metadata.permissions()).unwrap();
                    std::fs::File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_times(
                            std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()),
                        )
                        .unwrap();
                    *saved.lock().unwrap() = Some(path);
                }
                Ok(())
            }));
            let error = transfer::run(&conn, &upload(&source, &out), &h, &c)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("staging pathname content changed"),
                "{error}"
            );
            assert!(!out.join("data").exists());
            conn.cleanup().await;
            assert_eq!(
                std::fs::read(foreign.lock().unwrap().as_ref().unwrap()).unwrap(),
                b"different!"
            );
        }
    });
}

/// Passing evidence of the remaining SFTP check-to-link race, not containment.
#[test]
fn documented_sftp_last_path_swap_limit_is_reproduced() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let out = server.path("out");
    std::fs::write(&source, b"authorized").unwrap();
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::RemoteStageVerified {
                let path = PathBuf::from(p.staging.unwrap());
                let metadata = std::fs::metadata(&path).unwrap();
                std::fs::rename(&path, path.with_extension("original")).unwrap();
                std::fs::write(&path, b"different!").unwrap();
                std::fs::set_permissions(&path, metadata.permissions()).unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
                    .unwrap();
            }
            Ok(())
        }));
        transfer::run(&conn, &upload(&source, &out), &h, &c)
            .await
            .unwrap();
        assert_eq!(std::fs::read(out.join("data")).unwrap(), b"different!");
    });
}

#[test]
fn local_staging_content_edit_is_refused_before_publication() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let out = server.path("out");
    std::fs::write(&source, b"authorized").unwrap();
    std::fs::create_dir(&out).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let destination = out.clone();
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::BeforePublish {
                let payload = destination.join(p.staging.unwrap()).join("payload");
                let time = std::fs::metadata(&payload).unwrap().modified().unwrap();
                std::fs::write(&payload, b"different!").unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&payload)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(time))
                    .unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &download(&source, &out), &h, &c)
            .await
            .unwrap_err()
            .to_string()
            .contains("Local staging content changed"));
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    });
}

#[test]
fn newly_created_and_existing_local_destination_directory_swaps_are_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("tree");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("data"), b"authorized").unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for exists in [false, true] {
            let out = server.path(&format!("out-{exists}"));
            std::fs::create_dir(&out).unwrap();
            let dest = out.join("tree");
            if exists {
                std::fs::create_dir(&dest).unwrap();
            }
            let mut h = hooks(ConflictAction::Replace);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == Boundary::DestinationDirectoryOpening {
                    std::fs::rename(&dest, dest.with_extension("original")).unwrap();
                    std::fs::create_dir(&dest).unwrap();
                    std::fs::write(dest.join("foreign"), b"unrelated").unwrap();
                }
                Ok(())
            }));
            assert!(transfer::run(&conn, &download(&source, &out), &h, &c)
                .await
                .unwrap_err()
                .to_string()
                .contains("Destination directory substituted"));
            assert!(!out.join("tree/data").exists());
            assert_eq!(
                std::fs::read(out.join("tree/foreign")).unwrap(),
                b"unrelated"
            );
            assert_eq!(
                std::fs::read_dir(out.join("tree.original"))
                    .unwrap()
                    .count(),
                0
            );
        }
    });
}

#[test]
fn persistent_remote_ancestor_swaps_after_conflict_and_source_open_are_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"authorized").unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for at_conflict in [false, true] {
            let out = server.path(&format!("out-{at_conflict}"));
            let outside = server.path(&format!("outside-{at_conflict}"));
            std::fs::create_dir(&out).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let mut h = hooks(ConflictAction::Skip);
            if at_conflict {
                std::fs::write(out.join("data"), b"original").unwrap();
                let dest = out.clone();
                h.conflict = Arc::new(move |_, _| {
                    std::fs::rename(&dest, dest.with_extension("original")).unwrap();
                    symlink(&outside, &dest).unwrap();
                    let (sender, receiver) = tokio::sync::oneshot::channel();
                    sender.send(ConflictAction::KeepBoth).unwrap();
                    receiver
                });
            } else {
                let dest = out.clone();
                h.checkpoint = Some(Arc::new(move |p| {
                    if p.boundary == Boundary::StagePlanned {
                        std::fs::rename(&dest, dest.with_extension("original")).unwrap();
                        symlink(&outside, &dest).unwrap();
                    }
                    Ok(())
                }));
            }
            assert!(transfer::run(&conn, &upload(&source, &out), &h, &c)
                .await
                .is_err());
            let outside = server.path(&format!("outside-{at_conflict}"));
            assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
        }
        let chosen = server.path("chosen");
        let foreign = server.path("foreign");
        let local = server.path("local");
        for dir in [&chosen, &foreign, &local] {
            std::fs::create_dir(dir).unwrap();
        }
        std::fs::write(chosen.join("data"), b"authorized").unwrap();
        std::fs::write(foreign.join("data"), b"different!").unwrap();
        let remote = chosen.join("data");
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::RemoteSourceOpening {
                std::fs::rename(&chosen, chosen.with_extension("original")).unwrap();
                symlink(&foreign, &chosen).unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &download(&remote, &local), &h, &c)
            .await
            .is_err());
        assert_eq!(h.progress.lock().unwrap().bytes, 0);
        assert_eq!(std::fs::read_dir(local).unwrap().count(), 0);
    });
}

#[test]
fn download_cancellation_at_publication_boundaries_preserves_confirmed_status() {
    use lablink_files::Publication;
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"authorized").unwrap();
    runtime().block_on(async {
        for (index, boundary, expected) in [
            (0, Boundary::BeforePublish, Publication::NotRequested),
            (1, Boundary::Published, Publication::Confirmed),
        ] {
            let out = server.path(&format!("out-{index}"));
            std::fs::create_dir(&out).unwrap();
            let c = CancellationToken::new();
            let conn = Connection::connect(&server.target, &c).await.unwrap();
            let token = c.clone();
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    token.cancel();
                }
                Ok(())
            }));
            assert!(matches!(
                transfer::run(&conn, &download(&source, &out), &h, &c).await,
                Err(Error::Cancelled)
            ));
            assert_eq!(h.progress.lock().unwrap().publication, expected);
            if expected == Publication::Confirmed {
                assert_eq!(std::fs::read(out.join("data")).unwrap(), b"authorized");
                assert_eq!(h.progress.lock().unwrap().files_done, 1);
            } else {
                assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
            }
        }
    });
}

#[test]
fn host_key_file_changes_during_both_directions_stop_before_publication() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let daemon = Daemon::new(&server);
    let source = server.path("data");
    std::fs::write(&source, vec![0x41; 96 * 1024]).unwrap();
    let known = server.target.known_hosts_file.as_ref().unwrap().clone();
    let original = std::fs::read(&known).unwrap();
    runtime().block_on(async {
        for (index, direction, boundary) in [
            (0, Direction::Upload, Boundary::ChunkWritten),
            (1, Direction::Download, Boundary::ChunkWritten),
            (2, Direction::Upload, Boundary::BeforePublish),
            (3, Direction::Download, Boundary::BeforePublish),
        ] {
            std::fs::write(&known, &original).unwrap();
            let out = server.path(&format!("out-{index}"));
            std::fs::create_dir(&out).unwrap();
            let trust = known.clone();
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    std::fs::write(&trust, b"revoked\n").unwrap();
                }
                Ok(())
            }));
            let job = if direction == Direction::Upload {
                upload(&source, &out)
            } else {
                download(&source, &out)
            };
            let error = worker::execute_job(&daemon.socket, &job, &h, &CancellationToken::new())
                .await
                .unwrap_err();
            assert!(error.to_string().contains("trust changed"), "{error}");
            assert!(!out.join("data").exists());
            if direction == Direction::Download {
                assert_eq!(std::fs::read_dir(out).unwrap().count(), 0);
            }
        }
    });
}

#[test]
fn growing_and_truncated_sources_in_both_directions_are_refused() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for (index, direction, length) in [
            (0, Direction::Upload, 128 * 1024),
            (1, Direction::Upload, 1024),
            (2, Direction::Download, 128 * 1024),
            (3, Direction::Download, 1024),
        ] {
            let source = server.path(&format!("data-{index}"));
            let out = server.path(&format!("out-{index}"));
            std::fs::write(&source, vec![0x41; 96 * 1024]).unwrap();
            std::fs::create_dir(&out).unwrap();
            let path = source.clone();
            let changed = AtomicBool::new(false);
            let mut h = hooks(ConflictAction::Skip);
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == Boundary::ChunkWritten && !changed.swap(true, Ordering::SeqCst) {
                    std::fs::File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(length)
                        .unwrap();
                }
                Ok(())
            }));
            let job = if direction == Direction::Upload {
                upload(&source, &out)
            } else {
                download(&source, &out)
            };
            assert!(transfer::run(&conn, &job, &h, &c).await.is_err());
            assert!(!out.join(source.file_name().unwrap()).exists());
            if direction == Direction::Download {
                assert_eq!(std::fs::read_dir(out).unwrap().count(), 0);
            }
        }
    });
}

#[test]
fn unsafe_server_rename_is_reproduced_and_files_refuses_it() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let old = server.path("old-link");
    let new = server.path("destination-link");
    symlink("source-missing", &old).unwrap();
    symlink("destination-missing", &new).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        assert!(fs::remote_rename(
            &conn.sftp,
            server.root.path().to_str().unwrap(),
            "old-link",
            "destination-link"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("Remote rename refused"));
        assert_eq!(
            std::fs::read_link(&old).unwrap(),
            Path::new("source-missing")
        );
        assert_eq!(
            std::fs::read_link(&new).unwrap(),
            Path::new("destination-missing")
        );
        // Raw upstream behavior is exercised only inside this disposable fixture.
        conn.sftp
            .rename(old.to_str().unwrap(), new.to_str().unwrap())
            .await
            .unwrap();
        assert!(old.symlink_metadata().is_err());
        assert_eq!(
            std::fs::read_link(&new).unwrap(),
            Path::new("source-missing")
        );
    });
}

#[test]
fn noncanonical_download_source_cannot_hide_a_symlink_ancestor() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let selected = server.path("selected");
    let outside = server.path("outside");
    let destination = server.path("download");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir_all(outside.join("child")).unwrap();
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(selected.join("secret"), b"selected directory bytes").unwrap();
    std::fs::write(outside.join("secret"), b"outside directory bytes").unwrap();
    symlink(outside.join("child"), selected.join("alias")).unwrap();
    // Lexical normalization says selected/secret, while SFTP filesystem
    // resolution follows alias first and actually opens outside/secret.
    let source = selected.join("alias/../secret");
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let result = transfer::run(
            &connection,
            &download(&source, &destination),
            &hooks(ConflictAction::Skip),
            &cancel,
        )
        .await;
        assert!(result.is_err(), "noncanonical source was accepted");
        assert!(!destination.join("secret").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    });
    assert_eq!(
        std::fs::read(outside.join("secret")).unwrap(),
        b"outside directory bytes"
    );
}

#[test]
fn files_connection_refuses_inherited_local_command() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let marker = server.path("local_command_marker");
    let config = server.path("local_command_config");
    std::fs::write(
        &config,
        format!(
            "Host fixture\n  PermitLocalCommand yes\n  ForwardX11 yes\n  LocalCommand touch {}\n",
            lablink_ssh::shell_quote(marker.to_str().unwrap())
        ),
    )
    .unwrap();
    let binary = server.path("ssh_with_local_command_config");
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\nexec ssh -F {} \"$@\"\n",
            lablink_ssh::shell_quote(config.to_str().unwrap())
        ),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut target = server.target.clone();
    target.binary = binary.to_str().unwrap().to_owned();
    runtime().block_on(async {
        Connection::connect(&target, &CancellationToken::new())
            .await
            .unwrap();
    });
    assert!(!marker.exists(), "Files ran the inherited LocalCommand");
}

#[test]
fn spaced_known_hosts_path_cannot_add_an_unpinned_trust_file() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let correct = std::fs::read(server.target.known_hosts_file.as_ref().unwrap()).unwrap();
    let directory = server.path("private state");
    std::fs::create_dir(&directory).unwrap();
    let configured = directory.join("known_hosts");
    let other_key = std::fs::read_to_string(server.path("identity.pub")).unwrap();
    let fields: Vec<_> = other_key.split_whitespace().collect();
    std::fs::write(
        &configured,
        format!("lablink.fixture {} {}\n", fields[0], fields[1]),
    )
    .unwrap();
    // An unquoted -o value splits this legitimate path into two trusted files.
    // The first filename contains the server key, outside the configured pin.
    std::fs::write(server.path("private"), &correct).unwrap();
    let mut target = server.target.clone();
    target.known_hosts_file = Some(configured.clone());
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let error = Connection::connect(&target, &cancel)
            .await
            .err()
            .expect("OpenSSH path splitting accepted a key outside the pinned file");
        assert!(error.to_string().contains("host-key verification failed"));
        std::fs::write(&configured, correct).unwrap();
        Connection::connect(&target, &cancel).await.unwrap();
    });
}

#[test]
fn inherited_known_hosts_command_cannot_bypass_a_wrong_pin() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let correct_hosts = server.target.known_hosts_file.as_ref().unwrap();
    let wrong_hosts = server.path("wrong_known_hosts");
    let other_key = std::fs::read_to_string(server.path("identity.pub")).unwrap();
    let key_fields: Vec<_> = other_key.split_whitespace().collect();
    std::fs::write(
        &wrong_hosts,
        format!("lablink.fixture {} {}\n", key_fields[0], key_fields[1]),
    )
    .unwrap();
    let config = server.path("client_config");
    std::fs::write(
        &config,
        format!(
            "Host fixture\n  KnownHostsCommand /bin/cat {}\n  VerifyHostKeyDNS yes\n",
            lablink_ssh::shell_quote(correct_hosts.to_str().unwrap())
        ),
    )
    .unwrap();
    let binary = server.path("ssh_with_fixture_config");
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\nexec ssh -F {} \"$@\"\n",
            lablink_ssh::shell_quote(config.to_str().unwrap())
        ),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut target = server.target.clone();
    target.binary = binary.to_str().unwrap().to_owned();
    target.known_hosts_file = Some(wrong_hosts);
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        let mut valid = target.clone();
        valid.known_hosts_file = Some(correct_hosts.clone());
        Connection::connect(&valid, &cancel).await.unwrap();
        let error = Connection::connect(&target, &cancel)
            .await
            .err()
            .expect("inherited KnownHostsCommand bypassed the pinned identity");
        assert!(error.to_string().contains("host-key verification failed"));
    });
}

// Kernel fault injection is confined to a disposable test subprocess. These
// filters exercise the production write_all/sync_all syscall error paths; they
// do not model an actually exhausted volume or physically failing storage.
#[cfg(target_os = "linux")]
fn local_syscall_failure_case(mode: &str, syscall: libc::c_long, errno: i32) {
    const CHILD_MARKER: &str = "LABLINK_FILES_SYSCALL_CHILD";
    let test_name = if mode == "write" {
        "kernel_injected_local_enospc_never_publishes"
    } else {
        "kernel_injected_local_fsync_eio_never_publishes"
    };
    if std::env::var(CHILD_MARKER).ok().as_deref() != Some(mode) {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MARKER, mode)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated {mode} test failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    let payload = vec![0x41; 96 * 1024];
    std::fs::write(&source, &payload).unwrap();
    std::fs::create_dir(&destination).unwrap();
    runtime().block_on(async {
        let cancel = CancellationToken::new();
        // SSH and sshd exist before the filter, and never inherit it.
        let connection = Connection::connect(&server.target, &cancel).await.unwrap();
        let installed = Arc::new(AtomicBool::new(false));
        let marker = installed.clone();
        let destination_path = destination.clone();
        let mut h = hooks(ConflictAction::Skip);
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == transfer::Boundary::StageCreated {
                let path = destination_path.join(p.staging.unwrap()).join("payload");
                let fd = std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(|entry| entry.ok())
                    .find(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&path))
                    .expect("held staging descriptor")
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse::<u32>()
                    .unwrap();
                // seccomp_data: syscall number at offset 0; args[0] at 16.
                // This is fault scheduling, not a security sandbox. Only the
                // selected syscall on the held payload descriptor is denied.
                let mut filter = [
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    },
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 3,
                        k: syscall as u32,
                    },
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 16,
                    },
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 1,
                        k: fd,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | errno as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ALLOW,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_mut_ptr(),
                };
                // SAFETY: valid BPF buffer kept live throughout prctl. This
                // branch runs only in the disposable subprocess's test thread.
                unsafe {
                    assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                    assert_eq!(
                        libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                        0
                    );
                }
                marker.store(true, Ordering::SeqCst);
            }
            Ok(())
        }));
        let error = transfer::run(&connection, &download(&source, &destination), &h, &cancel)
            .await
            .unwrap_err();
        assert!(installed.load(Ordering::SeqCst));
        assert!(
            matches!(error, Error::Io(ref e) if e.raw_os_error() == Some(errno)),
            "unexpected syscall error: {error}"
        );
        let progress = h.progress.lock().unwrap();
        assert_eq!(progress.files_done, 0);
        assert_eq!(
            progress.publication,
            lablink_files::Publication::NotRequested
        );
        assert_eq!(
            progress.bytes,
            if mode == "write" {
                0
            } else {
                payload.len() as u64
            }
        );
        assert!(!destination.join("data").exists());
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
        assert_eq!(std::fs::read(&source).unwrap(), payload);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_injected_local_enospc_never_publishes() {
    local_syscall_failure_case("write", libc::SYS_write, libc::ENOSPC);
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_injected_local_fsync_eio_never_publishes() {
    local_syscall_failure_case("sync", libc::SYS_fsync, libc::EIO);
}

/// Drop an actual SFTP HANDLE reply after the disposable server creates the file.
/// This tests uncertain creation, rather than injecting a failure before OPEN.
#[test]
fn lost_open_reply_reports_candidate_without_claiming_ownership_or_deleting() {
    use lablink_files::transport::RemoteStageState;
    let Some(mut server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"complete source").unwrap();
    std::fs::create_dir(&destination).unwrap();
    let wrapper = server.path("drop-handle-reply");
    std::fs::write(
        &wrapper,
        r#"#!/usr/bin/python3
import subprocess, sys
child = subprocess.Popen(['/usr/bin/ssh', *sys.argv[1:]], stdout=subprocess.PIPE)
try:
    while True:
        header = child.stdout.read(4)
        if len(header) != 4:
            break
        packet = child.stdout.read(int.from_bytes(header, 'big'))
        if packet and packet[0] == 102:
            break
        sys.stdout.buffer.write(header + packet)
        sys.stdout.buffer.flush()
finally:
    child.kill()
    child.wait()
"#,
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    server.target.binary = wrapper.to_str().unwrap().into();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let h = hooks(ConflictAction::Skip);
        assert!(transfer::run(&conn, &upload(&source, &destination), &h, &c)
            .await
            .is_err());
        let records = conn.stage_diagnostics();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, RemoteStageState::CreationUnconfirmed);
        assert!(conn.retained_stages().is_empty()); // acknowledged creations only
        assert_eq!(std::fs::metadata(&records[0].path).unwrap().len(), 0);
        assert!(!destination.join("data").exists());
        conn.cleanup().await;
        assert!(Path::new(&records[0].path).exists());
        assert!(records[0].state.diagnostic().contains("unrelated"));
    });
    // Repeat through the worker to prove the uncertain path reaches GUI diagnostics.
    let daemon = Daemon::new(&server);
    runtime().block_on(async {
        let h = hooks(ConflictAction::Skip);
        assert!(worker::execute_job(
            &daemon.socket,
            &upload(&source, &destination),
            &h,
            &CancellationToken::new()
        )
        .await
        .is_err());
        let items = h.items.lock().unwrap();
        assert!(items
            .iter()
            .any(|i| i.result.contains("creation unconfirmed") && Path::new(&i.path).exists()));
    });
}

#[test]
fn staging_lifecycle_distinguishes_cancellation_and_publication_acknowledgement() {
    use lablink_files::{transport::RemoteStageState, Publication};
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"verified bytes").unwrap();
    for (boundary, state, published) in [
        (Boundary::StageCreated, RemoteStageState::Created, false),
        (Boundary::BeforePublish, RemoteStageState::Created, false),
        (Boundary::Published, RemoteStageState::Published, true),
    ] {
        let destination = server.path(&format!("destination-{boundary:?}"));
        std::fs::create_dir(&destination).unwrap();
        runtime().block_on(async {
            let c = CancellationToken::new();
            let conn = Connection::connect(&server.target, &c).await.unwrap();
            let mut h = hooks(ConflictAction::Skip);
            let token = c.clone();
            h.checkpoint = Some(Arc::new(move |p| {
                if p.boundary == boundary {
                    token.cancel();
                }
                Ok(())
            }));
            assert!(matches!(
                transfer::run(&conn, &upload(&source, &destination), &h, &c).await,
                Err(Error::Cancelled)
            ));
            let records = conn.stage_diagnostics();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].state, state);
            assert_eq!(destination.join("data").exists(), published);
            assert_eq!(
                h.progress.lock().unwrap().publication,
                if published {
                    Publication::Confirmed
                } else {
                    Publication::NotRequested
                }
            );
            conn.cleanup().await;
            assert!(Path::new(&records[0].path).exists());
            if published {
                assert_eq!(
                    std::fs::read(destination.join("data")).unwrap(),
                    b"verified bytes"
                );
            }
        });
    }
}

#[test]
fn publication_refusal_has_uncertain_stage_diagnostic_and_preserves_competitor() {
    use lablink_files::transport::RemoteStageState;
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"ours").unwrap();
    std::fs::create_dir(&destination).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let competing = destination.join("data");
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::RemoteStageVerified {
                std::fs::write(&competing, b"competitor").unwrap();
            }
            Ok(())
        }));
        assert!(transfer::run(&conn, &upload(&source, &destination), &h, &c)
            .await
            .is_err());
        assert_eq!(
            conn.stage_diagnostics()[0].state,
            RemoteStageState::PublicationUncertain
        );
        conn.cleanup().await;
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"competitor"
        );
    });
}

/// REMOVE denial is a server capability test. LabLink does not attempt cleanup,
/// so this is evidence of explicit retention, not successful remote deletion.
#[test]
fn remote_remove_denied_retains_successful_alias_without_cleanup_requests() {
    use lablink_files::transport::RemoteStageState;
    let Some(server) = Server::with_sftp_policy(Some("-P remove,rmdir")) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"published").unwrap();
    std::fs::create_dir(&destination).unwrap();
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let h = hooks(ConflictAction::Skip);
        transfer::run(&conn, &upload(&source, &destination), &h, &c).await.unwrap();
        let stages = conn.stage_diagnostics();
        assert_eq!(stages[0].state, RemoteStageState::Published);
        // Explicit test-only denial probe on the disposable server.
        assert!(matches!(conn.sftp.remove(stages[0].path.clone()).await, Err(russh_sftp::client::error::Error::Status(s)) if s.status_code == russh_sftp::protocol::StatusCode::PermissionDenied));
        conn.cleanup().await;
        conn.cleanup().await;
        assert_eq!(std::fs::read(&stages[0].path).unwrap(), b"published");
        assert_eq!(std::fs::read(destination.join("data")).unwrap(), b"published");
        assert!(stages[0].state.diagnostic().contains("hardlink retained"));
    });
}

#[test]
fn missing_destination_directories_fail_before_staging_or_publication() {
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    std::fs::write(&source, b"ours").unwrap();
    let missing = server.path("missing/destination");
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        for job in [upload(&source, &missing), download(&source, &missing)] {
            let h = hooks(ConflictAction::Skip);
            assert!(transfer::run(&conn, &job, &h, &c).await.is_err());
            assert_eq!(h.progress.lock().unwrap().files_done, 0);
            assert!(conn.stage_diagnostics().is_empty());
            assert!(!missing.exists());
        }
        assert_eq!(std::fs::read(&source).unwrap(), b"ours");
    });
}

#[test]
fn interrupted_download_reports_failed_local_cleanup_without_deleting_foreign_entry() {
    use transfer::Boundary;
    let Some(server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"ours").unwrap();
    std::fs::create_dir(&destination).unwrap();
    let foreign = Arc::new(Mutex::new(None));
    runtime().block_on(async {
        let c = CancellationToken::new();
        let conn = Connection::connect(&server.target, &c).await.unwrap();
        let mut h = hooks(ConflictAction::Skip);
        let token = c.clone();
        let root = destination.clone();
        let saved = foreign.clone();
        h.checkpoint = Some(Arc::new(move |p| {
            if p.boundary == Boundary::StageCreated {
                let entry = root.join(p.staging.unwrap()).join("foreign");
                std::fs::write(&entry, b"foreign evidence").unwrap();
                *saved.lock().unwrap() = Some(entry);
                token.cancel();
            }
            Ok(())
        }));
        assert!(matches!(
            transfer::run(&conn, &download(&source, &destination), &h, &c).await,
            Err(Error::Cancelled)
        ));
        assert!(!destination.join("data").exists());
        assert!(h
            .items
            .lock()
            .unwrap()
            .iter()
            .any(|i| i.result.contains("directory cleanup failed")));
        assert_eq!(
            std::fs::read(foreign.lock().unwrap().as_ref().unwrap()).unwrap(),
            b"foreign evidence"
        );
    });
}

/// The server really commits the hardlink; only its reply is suppressed.
#[test]
fn lost_publication_reply_reports_uncertainty_with_complete_destination() {
    use lablink_files::{transport::RemoteStageState, Publication};
    let Some(mut server) = Server::new(true) else {
        return;
    };
    let source = server.path("data");
    let destination = server.path("destination");
    std::fs::write(&source, b"complete verified bytes").unwrap();
    std::fs::create_dir(&destination).unwrap();
    let wrapper = server.path("drop-publication-reply");
    std::fs::write(&wrapper, r#"#!/usr/bin/python3
import subprocess, sys, threading
child = subprocess.Popen(['/usr/bin/ssh', *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
publication = set()
def requests():
    while True:
        header = sys.stdin.buffer.read(4)
        if len(header) != 4:
            break
        packet = sys.stdin.buffer.read(int.from_bytes(header, 'big'))
        if packet and packet[0] == 200 and b'hardlink@openssh.com' in packet:
            publication.add(packet[1:5])
        child.stdin.write(header + packet)
        child.stdin.flush()
threading.Thread(target=requests, daemon=True).start()
try:
    while True:
        header = child.stdout.read(4)
        if len(header) != 4:
            break
        packet = child.stdout.read(int.from_bytes(header, 'big'))
        if packet and packet[0] == 101 and packet[1:5] in publication:
            break
        sys.stdout.buffer.write(header + packet)
        sys.stdout.buffer.flush()
finally:
    child.kill()
    child.wait()
"#).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    server.target.binary = wrapper.to_str().unwrap().into();
    let daemon = Daemon::new(&server);
    runtime().block_on(async {
        let h = hooks(ConflictAction::Skip);
        assert!(worker::execute_job(
            &daemon.socket,
            &upload(&source, &destination),
            &h,
            &CancellationToken::new()
        )
        .await
        .is_err());
        let progress = h.progress.lock().unwrap();
        assert_eq!(progress.publication, Publication::Uncertain);
        assert_eq!(progress.files_done, 0); // no acknowledgement of this real commit
        let items = h.items.lock().unwrap();
        assert!(items.iter().any(|i| i.result
            == RemoteStageState::PublicationUncertain.diagnostic()
            && std::fs::read(&i.path).unwrap() == b"complete verified bytes"));
        assert_eq!(
            std::fs::read(destination.join("data")).unwrap(),
            b"complete verified bytes"
        );
    });
}
