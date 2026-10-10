//! Remote access for LabLink: reach a device from another network without
//! weakening its identity.
//!
//! - [`select`] chooses a verified endpoint: LAN first, then Tailscale.
//! - [`tailscale`] reads the local Tailscale client's state (read-only).
//! - [`SystemNet`] performs the real network operations with timeouts.
//! - [`write_pin_file`] writes the known_hosts file ssh is checked against.
//!
//! Tailscale only provides private reachability. Authentication and host
//! identity stay with OpenSSH and LabLink's pins: the same pinned host key is
//! required on every path. Nothing here stores, prints or forwards secrets.

pub mod select;
pub mod tailscale;

use lablink_core::identity::HostKey;
use lablink_ssh::KnownHostsEntry;
use select::{Net, TcpError};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tailscale::{Os, TsState};

/// The `HostKeyAlias` of a device: the same form the daemon uses, so one
/// identity has one name whichever path reaches it.
pub fn host_key_alias(site: &str, name: &str) -> String {
    format!("lablink.{site}.{name}")
}

/// Real network operations.
pub struct SystemNet {
    pub keyscan_binary: String,
    pub os: Os,
    pub timeouts: select::Timeouts,
    /// One `tailscale status` per command: every report sees the same state.
    ts: std::sync::OnceLock<TsState>,
}

impl SystemNet {
    pub fn new(keyscan_binary: &str) -> Self {
        Self {
            keyscan_binary: keyscan_binary.to_string(),
            os: Os::current(),
            timeouts: select::Timeouts::default(),
            ts: std::sync::OnceLock::new(),
        }
    }
}

impl Net for SystemNet {
    fn tailscale(&self) -> TsState {
        self.ts
            .get_or_init(|| {
                match tailscale::find_cli(self.os, std::env::var_os("PATH").as_deref()) {
                    None => TsState::Missing,
                    Some(cli) => tailscale::query(&cli, self.timeouts.tailscale_status),
                }
            })
            .clone()
    }

    fn lookup(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>, String> {
        // The system resolver has no timeout of its own: run it on a thread
        // and stop waiting after `timeout`.
        let (tx, rx) = std::sync::mpsc::channel();
        let host = format!("{name}:0");
        std::thread::spawn(move || {
            let r = host
                .to_socket_addrs()
                .map(|a| a.map(|s| s.ip()).collect::<Vec<_>>());
            let _ = tx.send(r);
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(ips)) if !ips.is_empty() => Ok(ips),
            Ok(Ok(_)) => Err("no addresses".into()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timed out".into()),
        }
    }

    fn tcp(&self, ip: IpAddr, port: u16, timeout: Duration) -> Result<(), TcpError> {
        match TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout) {
            Ok(_) => Ok(()),
            Err(e) => Err(match e.kind() {
                std::io::ErrorKind::ConnectionRefused => TcpError::Refused,
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TcpError::Timeout,
                _ => TcpError::Other(e.to_string()),
            }),
        }
    }

    fn keyscan(&self, ip: IpAddr, port: u16, timeout: Duration) -> Result<Vec<HostKey>, String> {
        let args = vec![
            "-T".to_string(),
            timeout.as_secs().max(1).to_string(),
            "-p".to_string(),
            port.to_string(),
            "-t".to_string(),
            "ed25519,ecdsa,rsa".to_string(),
            ip.to_string(),
        ];
        let out = lablink_ssh::run_captured(
            &self.keyscan_binary,
            &args,
            timeout + Duration::from_secs(2),
            lablink_ssh::OutputMode::Capture,
            true,
        )
        .map_err(|e| format!("cannot run ssh-keyscan: {e}"))?;
        Ok(lablink_ssh::parse_keyscan_output(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }
}

/// Write the known_hosts file for one device's remote connection:
/// `<state_dir>/remote/<site>.<name>.known_hosts` (directory 0700, file
/// 0600), holding only `keys` (pinned keys the endpoint offered) under the
/// device's alias. It never touches the daemon's pins or known_hosts file.
pub fn write_pin_file(
    state_dir: &Path,
    site: &str,
    name: &str,
    keys: &[HostKey],
) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = state_dir.join("remote");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    // Site ids and device names are validated ([a-z0-9-] / [A-Za-z0-9_.-]).
    let path = dir.join(format!("{site}.{name}.known_hosts"));
    let alias = host_key_alias(site, name);
    let entries: Vec<KnownHostsEntry> = keys
        .iter()
        .filter_map(|k| {
            Some(KnownHostsEntry {
                alias: alias.clone(),
                key_type: k.key_type.clone(),
                public_key: k.public_key.clone()?,
            })
        })
        .collect();
    // Concurrent connections to the same device each write a private temp
    // file and rename it into place, so no reader sees a partial file.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{site}.{name}.{}-{seq}.tmp", std::process::id()));
    lablink_ssh::write_known_hosts(&tmp, &entries)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_file_is_private_and_holds_only_the_given_keys() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let k = HostKey {
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
            public_key: Some(
                "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".into(),
            ),
        };
        let p = write_pin_file(d.path(), "home", "box", &[k]).unwrap();
        assert_eq!(p, d.path().join("remote/home.box.known_hosts"));
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines, ["lablink.home.box ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(&d.path().join("remote")), 0o700);
    }

    #[test]
    fn concurrent_pin_writes_never_expose_a_partial_file() {
        let d = tempfile::tempdir().unwrap();
        let k = HostKey {
            key_type: "ssh-ed25519".into(),
            fingerprint: "SHA256:x".into(),
            public_key: Some(
                "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".into(),
            ),
        };
        let want = format!(
            "lablink.home.box ssh-ed25519 {}",
            k.public_key.as_ref().unwrap()
        );
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..50 {
                        let p = write_pin_file(d.path(), "home", "box", std::slice::from_ref(&k))
                            .unwrap();
                        let t = std::fs::read_to_string(p).unwrap();
                        assert_eq!(
                            t.lines()
                                .filter(|l| !l.starts_with('#'))
                                .collect::<Vec<_>>(),
                            [want.as_str()]
                        );
                    }
                });
            }
        });
        let left: Vec<_> = std::fs::read_dir(d.path().join("remote"))
            .unwrap()
            .collect();
        assert_eq!(left.len(), 1, "no temp files left behind");
    }

    #[test]
    fn system_tcp_distinguishes_refused() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let net = SystemNet::new("ssh-keyscan");
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(net.tcp(ip, port, Duration::from_secs(1)), Ok(()));
        drop(l);
        assert_eq!(
            net.tcp(ip, port, Duration::from_secs(1)),
            Err(TcpError::Refused)
        );
    }

    #[test]
    fn system_lookup_reports_failures() {
        let net = SystemNet::new("ssh-keyscan");
        assert!(net
            .lookup("nonexistent.invalid", Duration::from_secs(3))
            .is_err());
        assert!(net
            .lookup("localhost", Duration::from_secs(3))
            .unwrap()
            .iter()
            .any(|i| i.is_loopback()));
    }
}
