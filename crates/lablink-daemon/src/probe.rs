//! The daemon's view of the outside world, behind a trait so that every
//! network interaction can be replaced by a deterministic fake in tests.

use lablink_core::identity::HostKey;
use lablink_discovery::{IcmpOutcome, Snapshot, TcpOutcome};
use lablink_ssh::{Mode, OutputMode, Target};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of a BatchMode SSH login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Login worked; `hostname` is the remote `hostname` output.
    Ok { hostname: Option<String> },
    /// The server rejected us.
    Rejected { password_only: bool, detail: String },
    /// The server presented a host key that does not match the pin.
    HostKeyChanged,
    /// Could not decide (network, host key, timeout).
    Error(String),
}

/// Captured result of a remote command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Everything the daemon does on the network.
pub trait Prober: Send + Sync + 'static {
    fn tcp(&self, addr: SocketAddr, timeout: Duration) -> BoxFut<'_, TcpOutcome>;
    fn icmp(&self, ip: IpAddr, timeout: Duration) -> BoxFut<'_, IcmpOutcome>;
    /// Host keys offered by the SSH server at `ip:port` (via `ssh-keyscan`).
    fn keyscan(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> BoxFut<'_, Result<Vec<HostKey>, String>>;
    /// Keys the user's own `~/.ssh/known_hosts` already trusts for any of `hosts`.
    fn user_known_keys(&self, hosts: Vec<String>) -> BoxFut<'_, Vec<HostKey>>;
    /// Non-interactive login check.
    fn auth(&self, target: Target, timeout: Duration) -> BoxFut<'_, AuthOutcome>;
    /// Does the host hold the pinned key? No credentials are offered
    /// (`Mode::KeyProof`).
    fn key_proof(&self, target: Target, timeout: Duration) -> BoxFut<'_, lablink_ssh::KeyProof>;
    /// Resolve a hostname (`.local` via mDNS when enabled).
    fn resolve(&self, host: String, timeout: Duration) -> BoxFut<'_, Vec<IpAddr>>;
    /// Run a command on a verified device (service checks), BatchMode.
    fn exec(&self, target: Target, command: String, timeout: Duration) -> BoxFut<'_, ExecOutcome>;
    /// Interfaces and neighbor table.
    fn net_snapshot(&self) -> BoxFut<'_, Option<Snapshot>>;
}

/// The production implementation.
pub struct RealProber {
    pub keyscan_binary: String,
    pub keygen_binary: String,
    pub user_known_hosts: std::path::PathBuf,
    pub mdns: Option<Arc<lablink_discovery::mdns::Mdns>>,
    /// Bounds concurrent OpenSSH subprocesses.
    pub ssh_slots: Arc<tokio::sync::Semaphore>,
    /// `ssh.reuse_control_master`: false forces fresh connections (ControlPath=none).
    pub reuse_control_master: bool,
}

impl Prober for RealProber {
    fn tcp(&self, addr: SocketAddr, timeout: Duration) -> BoxFut<'_, TcpOutcome> {
        Box::pin(lablink_discovery::tcp_probe(addr, timeout))
    }

    fn icmp(&self, ip: IpAddr, timeout: Duration) -> BoxFut<'_, IcmpOutcome> {
        Box::pin(lablink_discovery::icmp_echo(ip, timeout))
    }

    fn keyscan(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> BoxFut<'_, Result<Vec<HostKey>, String>> {
        Box::pin(async move {
            let _slot = self.ssh_slots.acquire().await.map_err(|e| e.to_string())?;
            let bin = self.keyscan_binary.clone();
            let secs = timeout.as_secs().max(1).to_string();
            let args = vec![
                "-T".to_string(),
                secs,
                "-p".to_string(),
                port.to_string(),
                "-t".to_string(),
                "ed25519,ecdsa,rsa".to_string(),
                ip.to_string(),
            ];
            let out = tokio::task::spawn_blocking(move || {
                lablink_ssh::run_captured(
                    &bin,
                    &args,
                    timeout + Duration::from_secs(2),
                    OutputMode::Capture,
                    true,
                )
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("cannot run ssh-keyscan: {e}"))?;
            let keys = lablink_ssh::parse_keyscan_output(&String::from_utf8_lossy(&out.stdout));
            if keys.is_empty() {
                Err(if out.timed_out {
                    "ssh-keyscan timed out".into()
                } else {
                    "no host keys returned".into()
                })
            } else {
                Ok(keys)
            }
        })
    }

    fn user_known_keys(&self, hosts: Vec<String>) -> BoxFut<'_, Vec<HostKey>> {
        Box::pin(async move {
            if !self.user_known_hosts.exists() {
                return Vec::new();
            }
            let bin = self.keygen_binary.clone();
            let file = self.user_known_hosts.clone();
            tokio::task::spawn_blocking(move || {
                let mut keys = Vec::new();
                for h in hosts {
                    let args = vec![
                        "-F".to_string(),
                        h,
                        "-f".to_string(),
                        file.display().to_string(),
                    ];
                    if let Ok(o) = lablink_ssh::run_captured(
                        &bin,
                        &args,
                        Duration::from_secs(5),
                        OutputMode::Capture,
                        true,
                    ) {
                        keys.extend(lablink_ssh::parse_known_hosts_lines(
                            &String::from_utf8_lossy(&o.stdout),
                        ));
                    }
                }
                keys.sort();
                keys.dedup();
                keys
            })
            .await
            .unwrap_or_default()
        })
    }

    fn key_proof(&self, target: Target, timeout: Duration) -> BoxFut<'_, lablink_ssh::KeyProof> {
        use lablink_ssh::KeyProof;
        Box::pin(async move {
            let Ok(_slot) = self.ssh_slots.acquire().await else {
                return KeyProof::Inconclusive("shutting down".into());
            };
            let args = lablink_ssh::build_args(&target, &Mode::KeyProof, &[]);
            let bin = target.binary.clone();
            match tokio::task::spawn_blocking(move || {
                lablink_ssh::run_captured(&bin, &args, timeout, OutputMode::Capture, true)
            })
            .await
            {
                Ok(Ok(o)) => lablink_ssh::classify_key_proof(
                    o.exit_code,
                    &String::from_utf8_lossy(&o.stderr),
                    o.timed_out,
                ),
                Ok(Err(e)) => KeyProof::Inconclusive(format!("cannot run ssh: {e}")),
                Err(e) => KeyProof::Inconclusive(e.to_string()),
            }
        })
    }

    fn auth(&self, target: Target, timeout: Duration) -> BoxFut<'_, AuthOutcome> {
        let target = self.no_mux_unless_allowed(target);
        Box::pin(async move {
            let Ok(_slot) = self.ssh_slots.acquire().await else {
                return AuthOutcome::Error("shutting down".into());
            };
            let args = lablink_ssh::build_args(&target, &Mode::AuthProbe, &[]);
            let bin = target.binary.clone();
            let res = tokio::task::spawn_blocking(move || {
                lablink_ssh::run_captured(&bin, &args, timeout, OutputMode::Capture, true)
            })
            .await;
            match res {
                Ok(Ok(o)) if o.exit_code == Some(0) => {
                    let h = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .next()
                        .map(|s| s.trim().to_string());
                    AuthOutcome::Ok {
                        hostname: h.filter(|s| !s.is_empty() && s.len() <= 253),
                    }
                }
                Ok(Ok(o)) if o.timed_out => AuthOutcome::Error("ssh login check timed out".into()),
                Ok(Ok(o)) => {
                    match lablink_ssh::classify_ssh_failure(&String::from_utf8_lossy(&o.stderr)) {
                        f @ lablink_ssh::SshFailure::AuthFailed { password_only } => {
                            AuthOutcome::Rejected {
                                password_only,
                                detail: f.describe(),
                            }
                        }
                        lablink_ssh::SshFailure::HostKeyChanged => AuthOutcome::HostKeyChanged,
                        f => AuthOutcome::Error(f.describe()),
                    }
                }
                Ok(Err(e)) => AuthOutcome::Error(format!("cannot run ssh: {e}")),
                Err(e) => AuthOutcome::Error(e.to_string()),
            }
        })
    }

    fn resolve(&self, host: String, timeout: Duration) -> BoxFut<'_, Vec<IpAddr>> {
        Box::pin(async move {
            let lower = host.trim_end_matches('.').to_ascii_lowercase();
            if lower.ends_with(".local") {
                if let Some(m) = &self.mdns {
                    let v = m.resolve(&lower, timeout).await;
                    if !v.is_empty() {
                        return v;
                    }
                }
            }
            lablink_discovery::probe::resolve_host(&lower, timeout).await
        })
    }

    fn exec(&self, target: Target, command: String, timeout: Duration) -> BoxFut<'_, ExecOutcome> {
        self.exec_impl(target, command, timeout)
    }

    fn net_snapshot(&self) -> BoxFut<'_, Option<Snapshot>> {
        Box::pin(async move {
            match lablink_discovery::netlink::snapshot_async(Duration::from_secs(3)).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "netlink snapshot failed");
                    None
                }
            }
        })
    }
}

impl RealProber {
    fn no_mux_unless_allowed(&self, mut target: Target) -> Target {
        if !self.reuse_control_master {
            target.options.insert("ControlPath".into(), "none".into());
        }
        target
    }

    fn exec_impl(
        &self,
        target: Target,
        command: String,
        timeout: Duration,
    ) -> BoxFut<'_, ExecOutcome> {
        let target = self.no_mux_unless_allowed(target);
        Box::pin(async move {
            let Ok(_slot) = self.ssh_slots.acquire().await else {
                return ExecOutcome::default();
            };
            let mut args = lablink_ssh::build_args(
                &target,
                &Mode::Exec {
                    command,
                    batch: true,
                },
                &lablink_ssh::automated_session_args(),
            );
            // Like the auth probe: reuse a user ControlMaster, never create one.
            args.splice(0..0, ["-o".to_string(), "ControlMaster=no".to_string()]);
            let bin = target.binary.clone();
            match tokio::task::spawn_blocking(move || {
                lablink_ssh::run_captured(&bin, &args, timeout, OutputMode::Capture, true)
            })
            .await
            {
                Ok(Ok(o)) => ExecOutcome {
                    exit_code: o.exit_code,
                    stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                    timed_out: o.timed_out,
                },
                _ => ExecOutcome {
                    exit_code: Some(255),
                    stderr: "cannot run ssh".into(),
                    ..Default::default()
                },
            }
        })
    }
}
