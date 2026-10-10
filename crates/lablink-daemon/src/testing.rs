//! Test support: a deterministic simulated network behind the [`Prober`]
//! trait, and a harness that runs a complete daemon (real Unix socket, real
//! SQLite cache, real task structure) on its own thread.
//!
//! Nothing here touches the real network. Used by this crate's integration
//! tests and by the CLI's end-to-end tests.

use crate::probe::{AuthOutcome, BoxFut, Prober};
use base64_free::encode_b64;
use ipnet::IpNet;
use lablink_core::client::Client;
use lablink_core::config::Config;
use lablink_core::identity::HostKey;
use lablink_discovery::{IcmpOutcome, Interface, NeighState, Neighbor, Snapshot, TcpOutcome};
use lablink_ssh::Target;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// How a simulated SSH port behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMode {
    Open,
    Refused,
    Timeout,
}

/// One simulated host.
#[derive(Debug, Clone)]
pub struct FakeHost {
    pub up: bool,
    pub icmp: bool,
    pub port: PortMode,
    pub keys: Vec<HostKey>,
    pub auth: AuthOutcome,
    /// Service-check commands -> exit code (missing = exit 0).
    pub commands: HashMap<String, i32>,
    pub mac: Option<String>,
    /// Per-round reachability overrides, consumed one per TCP probe.
    pub script: VecDeque<bool>,
    /// False for a host that replays public keys it does not hold: it
    /// answers ssh-keyscan with them but fails the possession proof.
    pub holds_keys: bool,
}

impl FakeHost {
    pub fn ssh_host(keys: Vec<HostKey>, mac: &str) -> Self {
        Self {
            up: true,
            icmp: true,
            port: PortMode::Open,
            keys,
            auth: AuthOutcome::Ok { hostname: None },
            mac: Some(mac.to_string()),
            commands: HashMap::new(),
            script: VecDeque::new(),
            holds_keys: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct World {
    pub hosts: HashMap<IpAddr, FakeHost>,
    pub local: Vec<IpNet>,
    pub resolve: HashMap<String, Vec<IpAddr>>,
    pub user_known: Vec<HostKey>,
    /// Default gateways of this host (their MAC comes from the host entry
    /// at that address, as in a real neighbor table).
    pub gateways: Vec<IpAddr>,
    /// Wi-Fi SSID this host is associated with.
    pub ssid: Option<String>,
    /// Up/down decided by the last TCP probe of a scripted host, reused by ICMP
    /// in the same round.
    last_round: HashMap<IpAddr, bool>,
}

/// A simulated network shared between a test and its daemon.
#[derive(Debug, Default)]
pub struct FakeNet {
    pub world: Mutex<World>,
    /// Every probe as `"<kind> <ip>"`, for asserting what was (not) touched.
    pub calls: Mutex<Vec<String>>,
    /// Set to false in soak tests so the test harness itself does not grow.
    pub record_calls: std::sync::atomic::AtomicBool,
}

impl FakeNet {
    pub fn new(local: &[&str]) -> Arc<Self> {
        let n = Self {
            record_calls: std::sync::atomic::AtomicBool::new(true),
            ..Self::default()
        };
        n.world.lock().unwrap().local = local.iter().map(|s| s.parse().unwrap()).collect();
        Arc::new(n)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut World) -> R) -> R {
        f(&mut self.world.lock().unwrap())
    }

    pub fn add(&self, ip: &str, h: FakeHost) {
        self.with(|w| w.hosts.insert(ip.parse().unwrap(), h));
    }

    pub fn host(&self, ip: &str, f: impl FnOnce(&mut FakeHost)) {
        self.with(|w| f(w.hosts.get_mut(&ip.parse().unwrap()).expect("host exists")));
    }

    /// Move a host to a new address (DHCP renumbering).
    pub fn move_host(&self, from: &str, to: &str) {
        self.with(|w| {
            let h = w.hosts.remove(&from.parse().unwrap()).expect("host exists");
            w.hosts.insert(to.parse().unwrap(), h);
        });
    }

    /// Emulate commands LabLink runs on a gateway: the via probe snippet
    /// (ping + optional /dev/tcp) and ssh-keyscan, against hosts in the
    /// simulated world (which may sit on networks this host is not attached to).
    fn gateway_command(&self, command: &str) -> crate::probe::ExecOutcome {
        let after = |marker: &str| -> Option<IpAddr> {
            let rest = &command[command.find(marker)? + marker.len()..];
            rest.split([' ', '/']).next()?.parse().ok()
        };
        if command.starts_with("ssh-keyscan") {
            let ip: Option<IpAddr> = command.split_whitespace().find_map(|t| t.parse().ok());
            let h = ip.and_then(|ip| self.with(|w| w.hosts.get(&ip).cloned()).map(|h| (ip, h)));
            let stdout = match h {
                Some((ip, h)) if h.up && h.port == PortMode::Open => h
                    .keys
                    .iter()
                    .map(|k| {
                        format!(
                            "{ip} {} {}\n",
                            k.key_type,
                            k.public_key.clone().unwrap_or_default()
                        )
                    })
                    .collect(),
                _ => String::new(),
            };
            return crate::probe::ExecOutcome {
                exit_code: Some(0),
                stdout,
                ..Default::default()
            };
        }
        let ip = after("ping -n -c 1 -W 1 ").expect("via command has a ping target");
        self.log("via-ping", ip);
        let h = self.with(|w| w.hosts.get(&ip).cloned());
        let ping = match &h {
            Some(h) if h.up && h.icmp => "ping=0 rtt=0.6",
            _ => "ping=1 rtt=",
        };
        let tcp = if command.contains("/dev/tcp/") {
            match &h {
                Some(h) if h.up => match h.port {
                    PortMode::Open => "0",
                    PortMode::Refused => "1",
                    PortMode::Timeout => "124",
                },
                _ => "124",
            }
        } else {
            "-"
        };
        crate::probe::ExecOutcome {
            exit_code: Some(0),
            stdout: format!("lablink-via {ping} tcp={tcp}\n"),
            ..Default::default()
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn log(&self, kind: &str, ip: IpAddr) {
        if !self.record_calls.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let mut c = self.calls.lock().unwrap();
        if c.len() < 100_000 {
            c.push(format!("{kind} {ip}"));
        }
    }

    /// Reachability for this round; consumes one scripted step on TCP probes.
    fn round(&self, ip: IpAddr, consume: bool) -> Option<FakeHost> {
        let mut w = self.world.lock().unwrap();
        let mut h = w.hosts.get(&ip).cloned()?;
        let up = if consume {
            let step = w.hosts.get_mut(&ip).and_then(|h| h.script.pop_front());
            let up = step.unwrap_or(h.up);
            w.last_round.insert(ip, up);
            up
        } else {
            *w.last_round.get(&ip).unwrap_or(&h.up)
        };
        h.up = up;
        Some(h)
    }
}

impl Prober for FakeNet {
    fn tcp(&self, addr: SocketAddr, _timeout: Duration) -> BoxFut<'_, TcpOutcome> {
        self.log("tcp", addr.ip());
        let h = self.round(addr.ip(), true);
        Box::pin(async move {
            match h {
                Some(h) if h.up => match h.port {
                    PortMode::Open => TcpOutcome::Open(Duration::from_millis(3)),
                    PortMode::Refused => TcpOutcome::Refused(Duration::from_millis(3)),
                    PortMode::Timeout => TcpOutcome::Timeout,
                },
                _ => TcpOutcome::Timeout,
            }
        })
    }

    fn icmp(&self, ip: IpAddr, _timeout: Duration) -> BoxFut<'_, IcmpOutcome> {
        self.log("icmp", ip);
        let h = self.round(ip, false);
        Box::pin(async move {
            match h {
                Some(h) if h.up && h.icmp => IcmpOutcome::Reply(Duration::from_millis(2)),
                _ => IcmpOutcome::Timeout,
            }
        })
    }

    fn keyscan(
        &self,
        ip: IpAddr,
        _port: u16,
        _timeout: Duration,
    ) -> BoxFut<'_, Result<Vec<HostKey>, String>> {
        self.log("keyscan", ip);
        let h = self.round(ip, false);
        Box::pin(async move {
            match h {
                Some(h) if h.up && h.port == PortMode::Open && !h.keys.is_empty() => Ok(h.keys),
                _ => Err("no host keys returned".into()),
            }
        })
    }

    fn user_known_keys(&self, _hosts: Vec<String>) -> BoxFut<'_, Vec<HostKey>> {
        let k = self.with(|w| w.user_known.clone());
        Box::pin(async move { k })
    }

    fn key_proof(&self, target: Target, _timeout: Duration) -> BoxFut<'_, lablink_ssh::KeyProof> {
        use lablink_ssh::KeyProof;
        let ip: IpAddr = target.ip.parse().unwrap();
        self.log("key_proof", ip);
        let h = self.round(ip, false);
        Box::pin(async move {
            match h {
                Some(h) if h.up && h.port == PortMode::Open && h.holds_keys => KeyProof::Proven,
                Some(h) if h.up && h.port == PortMode::Open => {
                    KeyProof::Refused("it could not sign with the pinned key".into())
                }
                _ => KeyProof::Inconclusive("connection timed out".into()),
            }
        })
    }

    fn auth(&self, target: Target, _timeout: Duration) -> BoxFut<'_, AuthOutcome> {
        let ip: IpAddr = target.ip.parse().unwrap();
        self.log("auth", ip);
        let h = self.round(ip, false);
        Box::pin(async move {
            match h {
                Some(h) if h.up && h.port == PortMode::Open => h.auth,
                _ => AuthOutcome::Error("connection timed out".into()),
            }
        })
    }

    fn resolve(&self, host: String, _timeout: Duration) -> BoxFut<'_, Vec<IpAddr>> {
        let v = self.with(|w| w.resolve.get(&host).cloned().unwrap_or_default());
        Box::pin(async move { v })
    }

    fn exec(
        &self,
        target: Target,
        command: String,
        _timeout: Duration,
    ) -> BoxFut<'_, crate::probe::ExecOutcome> {
        let ip: IpAddr = target.ip.parse().unwrap();
        self.log("exec", ip);
        let h = self.round(ip, false);
        Box::pin(async move {
            match h {
                Some(h)
                    if h.up
                        && (command.contains("lablink-via")
                            || command.starts_with("ssh-keyscan")) =>
                {
                    self.gateway_command(&command)
                }
                Some(h) if h.up => crate::probe::ExecOutcome {
                    exit_code: Some(*h.commands.get(&command).unwrap_or(&0)),
                    stdout: format!("{command} ran\n"),
                    ..Default::default()
                },
                _ => crate::probe::ExecOutcome {
                    exit_code: Some(255),
                    stderr: "ssh: connect to host: Connection timed out".into(),
                    ..Default::default()
                },
            }
        })
    }

    fn net_snapshot(&self) -> BoxFut<'_, Option<Snapshot>> {
        let s = self.with(|w| {
            let neighbors = w
                .hosts
                .iter()
                .filter(|(ip, h)| {
                    h.up && h.mac.is_some() && w.local.iter().any(|n| n.contains(*ip))
                })
                .map(|(ip, h)| Neighbor {
                    ip: *ip,
                    mac: h.mac.clone(),
                    ifindex: 2,
                    state: NeighState::Reachable,
                })
                .collect();
            Snapshot {
                interfaces: vec![Interface {
                    index: 2,
                    name: "eth0".into(),
                    up: true,
                    loopback: false,
                    mac: None,
                    addrs: w.local.clone(),
                }],
                neighbors,
                gateways: w
                    .gateways
                    .iter()
                    .map(|g| ("eth0".to_string(), *g))
                    .collect(),
                ssids: w
                    .ssid
                    .iter()
                    .map(|s| ("eth0".to_string(), s.clone()))
                    .collect(),
            }
        });
        Box::pin(async move { Some(s) })
    }
}

/// A deterministic ed25519-shaped host key whose fingerprint is computed the
/// same way OpenSSH does (so it passes config validation).
pub fn fake_key(seed: &str) -> HostKey {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    let mut k = [0u8; 32];
    for (i, b) in seed.bytes().cycle().take(32).enumerate() {
        k[i] = b.wrapping_add(i as u8);
    }
    blob.extend_from_slice(&k);
    let b64 = encode_b64(&blob);
    let fingerprint = lablink_ssh::fingerprint_of_blob("ssh-ed25519", &b64).expect("valid blob");
    HostKey {
        key_type: "ssh-ed25519".into(),
        fingerprint,
        public_key: Some(b64),
    }
}

mod base64_free {
    /// Standard base64 with padding (test keys only).
    pub fn encode_b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}

/// A daemon running on its own thread for the duration of a test.
pub struct TestDaemon {
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub net: Arc<FakeNet>,
    cancel: CancellationToken,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl TestDaemon {
    /// Start a daemon and wait until its socket accepts connections.
    pub fn start(
        cfg: Config,
        net: Arc<FakeNet>,
        state_dir: PathBuf,
        startup_discovery: bool,
    ) -> Result<Self, String> {
        // Test fixtures own their temporary directories. tempfile may use
        // 0755/0775 under the caller's umask; production never repairs an
        // existing shared state directory, so make the fixture private here.
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state_dir)
            .map_err(|e| e.to_string())?;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        if let Ok(f) = std::env::var("LABLINK_TEST_LOG") {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(f))
                .with_test_writer()
                .try_init();
        }
        let socket = state_dir.join("run").join("d.sock");
        let cancel = CancellationToken::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let (c, s, sd, p) = (
            cancel.clone(),
            socket.clone(),
            state_dir.clone(),
            net.clone(),
        );
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                let (rtx, rrx) = tokio::sync::oneshot::channel();
                let fut = crate::run(crate::RunOptions {
                    config: cfg,
                    socket: s,
                    state_dir: sd,
                    netlink: false,
                    mdns: false,
                    startup_discovery,
                    prober: Some(p),
                    cancel: c,
                    ready: Some(rtx),
                });
                tokio::pin!(fut);
                tokio::select! {
                    r = &mut fut => { let _ = tx.send(Err(r.clone().err().unwrap_or_else(|| "exited early".into()))); return r; }
                    _ = rrx => { let _ = tx.send(Ok(())); }
                }
                fut.await
            })
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(Self {
                socket,
                state_dir,
                net,
                cancel,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err("daemon did not become ready".into()),
        }
    }

    pub fn client(&self) -> Client {
        Client::new(&self.socket).with_timeout(Duration::from_secs(30))
    }

    /// Cancel and join; returns the daemon's result.
    pub fn stop(mut self) -> Result<(), String> {
        self.cancel.cancel();
        self.thread
            .take()
            .map(|t| t.join().unwrap_or_else(|_| Err("daemon panicked".into())))
            .unwrap_or(Ok(()))
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A fast test configuration: 1 s checks, short thresholds.
pub fn fast_config(yaml: &str) -> Config {
    fast_config_with("", yaml)
}

/// Like `fast_config`, with extra `daemon:` section lines (2-space indented, newline-terminated).
pub fn fast_config_with(extra_daemon: &str, yaml: &str) -> Config {
    let base = "daemon:\n  check_interval_s: 1\n  offline_backoff_max_s: 2\n  degraded_after: 2\n  offline_after: 3\n  recover_after: 2\n  port_check_interval_s: 1\n  identity_check_interval_s: 30\n  auth_check_interval_s: 30\n  scan_interval_s: 0\n  persist_interval_s: 1\n  mdns: false\n";
    Config::parse(&format!("{base}{extra_daemon}{yaml}"), "test")
        .unwrap_or_else(|e| panic!("bad test config: {e}"))
}
