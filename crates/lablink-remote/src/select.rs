//! Choosing a verified endpoint for one device: the LAN first, then Tailscale.
//!
//! An endpoint is selected only when (1) a TCP connection to its SSH port
//! succeeds within a bounded time and (2) the SSH server there offers a host
//! key whose fingerprint is pinned for the device. The ssh client launched
//! afterwards enforces the pin with `StrictHostKeyChecking=yes`, which also
//! proves the server holds the private key. Nothing else (a ping, a TCP
//! connection, Tailscale's online flag or peer name) counts as identity.
//!
//! A host key that is not pinned, a tailnet other than the configured one,
//! or a tailnet address that belongs to a different node stops the selection
//! at once: LabLink never falls back past an identity disagreement.

use crate::tailscale::{printable, Snapshot, TsState};
use lablink_core::config::{normalize_tailnet, TailscaleRemote};
use lablink_core::identity::HostKey;
use std::net::IpAddr;
use std::time::Duration;

/// Time budget for each step.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub lan_connect: Duration,
    pub tailnet_connect: Duration,
    pub keyscan: Duration,
    pub dns: Duration,
    pub tailscale_status: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            lan_connect: Duration::from_millis(1500),
            // The first packet to a peer may wait for the tailnet path.
            tailnet_connect: Duration::from_secs(5),
            keyscan: Duration::from_secs(5),
            dns: Duration::from_secs(3),
            tailscale_status: Duration::from_secs(5),
        }
    }
}

/// The path a connection takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Lan,
    Tailscale,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Lan => "lan",
            Transport::Tailscale => "tailscale",
        }
    }
}

/// Which transports the user allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    Auto,
    Lan,
    Tailscale,
}

/// A LAN address hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanHint {
    Ip(IpAddr),
    /// Resolved with the system resolver (e.g. an mDNS `.local` name).
    Name(String),
}

/// Everything the selector needs to know about the device.
#[derive(Debug, Clone)]
pub struct DeviceSpec {
    pub port: u16,
    /// Pinned `SHA256:` fingerprints. Never empty for a device with remote
    /// access (config validation).
    pub pinned: Vec<String>,
    pub lan: Vec<LanHint>,
    pub tailscale: Option<TailscaleRemote>,
}

/// Why a TCP connection failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpError {
    Refused,
    Timeout,
    Other(String),
}

/// Side effects, behind a trait so the logic is tested without a network.
pub trait Net {
    fn tailscale(&self) -> TsState;
    fn lookup(&self, name: &str, timeout: Duration) -> Result<Vec<IpAddr>, String>;
    fn tcp(&self, ip: IpAddr, port: u16, timeout: Duration) -> Result<(), TcpError>;
    fn keyscan(&self, ip: IpAddr, port: u16, timeout: Duration) -> Result<Vec<HostKey>, String>;
}

/// Why an endpoint could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    DnsFailure {
        name: String,
    },
    Timeout,
    Refused,
    Unreachable(String),
    /// The port answered but no SSH host key was received.
    NoSsh,
    /// The server's host keys are not the pinned ones. Fatal.
    HostKeyMismatch {
        offered: Vec<String>,
    },
    TailscaleMissing,
    TailscaleFailed(&'static str),
    TailscaleLoggedOut {
        state: &'static str,
    },
    TailscaleStopped,
    TailscaleNotReady {
        state: &'static str,
    },
    /// The local client is in another tailnet. Fatal.
    TailnetMismatch {
        want: String,
        have: Option<String>,
    },
    /// The device is not in this machine's view of the tailnet.
    PeerNotFound,
    PeerExpired,
    /// The configured address belongs to another node than the configured
    /// node id, or names several nodes. Fatal.
    PeerConflict(String),
    NoTailnetAddress,
}

impl Problem {
    /// Stops the selection: an identity or tailnet disagreement.
    pub fn fatal(&self) -> bool {
        matches!(
            self,
            Problem::HostKeyMismatch { .. }
                | Problem::TailnetMismatch { .. }
                | Problem::PeerConflict(_)
        )
    }

    /// Stable machine-readable kind (part of the JSON interface).
    pub fn kind(&self) -> &'static str {
        match self {
            Problem::DnsFailure { .. } => "dns_failure",
            Problem::Timeout => "timeout",
            Problem::Refused => "ssh_refused",
            Problem::Unreachable(_) => "unreachable",
            Problem::NoSsh => "no_ssh_host_key",
            Problem::HostKeyMismatch { .. } => "host_key_mismatch",
            Problem::TailscaleMissing => "tailscale_missing",
            Problem::TailscaleFailed(_) => "tailscale_error",
            Problem::TailscaleLoggedOut { .. } => "tailscale_unauthenticated",
            Problem::TailscaleStopped => "tailscale_stopped",
            Problem::TailscaleNotReady { .. } => "tailscale_not_ready",
            Problem::TailnetMismatch { .. } => "tailnet_mismatch",
            Problem::PeerNotFound => "tailscale_peer_not_found",
            Problem::PeerExpired => "tailscale_peer_expired",
            Problem::PeerConflict(_) => "tailscale_peer_mismatch",
            Problem::NoTailnetAddress => "tailscale_no_address",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Problem::DnsFailure { name } => format!("could not resolve '{name}'"),
            Problem::Timeout => "no answer (timed out)".into(),
            Problem::Refused => "connection refused: no SSH server listening".into(),
            Problem::Unreachable(e) => format!("unreachable ({e})"),
            Problem::NoSsh => "the port answered but sent no SSH host key".into(),
            Problem::HostKeyMismatch { offered } => format!(
                "SECURITY STOP: the SSH server offered host key(s) {} which are not pinned for this device; it may be a different machine or an interception attempt",
                offered.join(", ")
            ),
            Problem::TailscaleMissing => "Tailscale is not installed or its CLI was not found".into(),
            Problem::TailscaleFailed(r) => (*r).to_string(),
            Problem::TailscaleLoggedOut { state } => format!(
                "Tailscale is not logged in on this machine (state {state}); log in yourself (`tailscale up` or the Tailscale app)"
            ),
            Problem::TailscaleStopped => "Tailscale is installed but disconnected; connect it yourself (`tailscale up` or the Tailscale app)".into(),
            Problem::TailscaleNotReady { state } => format!("Tailscale is not ready (state {state})"),
            Problem::TailnetMismatch { want, have } => format!(
                "this machine's Tailscale is connected to tailnet {}, but the device is configured for tailnet {want}; LabLink never connects across tailnets (switch with `tailscale switch`)",
                have.as_deref().unwrap_or("<unknown>")
            ),
            Problem::PeerNotFound => "the device is not visible in your tailnet: not enrolled, logged out, removed, not shared with this machine, or hidden by tailnet policy".into(),
            Problem::PeerExpired => "the device's Tailscale key has expired; re-authenticate Tailscale on the device".into(),
            Problem::PeerConflict(m) => m.clone(),
            Problem::NoTailnetAddress => "the device has no Tailscale address".into(),
        }
    }
}

/// One endpoint that was considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub transport: Transport,
    /// What was tried, for people: an address or a name.
    pub target: String,
    pub ip: Option<IpAddr>,
    /// None: selected (verified).
    pub problem: Option<Problem>,
}

/// A verified endpoint and the pinned keys it offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub transport: Transport,
    pub ip: IpAddr,
    pub port: u16,
    /// The offered keys whose fingerprints are pinned (with public keys, for
    /// the known_hosts file ssh checks against).
    pub keys: Vec<HostKey>,
}

/// The outcome of a selection.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub endpoint: Option<Endpoint>,
    pub attempts: Vec<Attempt>,
    /// Facts worth telling the user (never secrets).
    pub notes: Vec<String>,
}

impl Selection {
    /// The first fatal problem, if any.
    pub fn fatal(&self) -> Option<&Problem> {
        self.attempts
            .iter()
            .filter_map(|a| a.problem.as_ref())
            .find(|p| p.fatal())
    }
}

/// Stop at the first usable endpoint (`ssh`, `exec`), or evaluate every
/// candidate (`remote status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    FirstUsable,
    All,
}

/// Check one endpoint: bounded TCP connect, then the offered host keys
/// against the pins.
pub fn verify_endpoint(
    net: &dyn Net,
    ip: IpAddr,
    port: u16,
    pinned: &[String],
    connect: Duration,
    t: &Timeouts,
) -> Result<Vec<HostKey>, Problem> {
    net.tcp(ip, port, connect).map_err(|e| match e {
        TcpError::Refused => Problem::Refused,
        TcpError::Timeout => Problem::Timeout,
        TcpError::Other(m) => Problem::Unreachable(m),
    })?;
    let offered = net
        .keyscan(ip, port, t.keyscan)
        .map_err(|_| Problem::NoSsh)?;
    if offered.is_empty() {
        return Err(Problem::NoSsh);
    }
    let matching: Vec<HostKey> = offered
        .iter()
        .filter(|k| pinned.contains(&k.fingerprint) && k.public_key.is_some())
        .cloned()
        .collect();
    if matching.is_empty() {
        return Err(Problem::HostKeyMismatch {
            offered: offered.into_iter().map(|k| k.fingerprint).collect(),
        });
    }
    Ok(matching)
}

fn addr_names(t: &TailscaleRemote, p: &crate::tailscale::Peer) -> bool {
    match t.address.parse::<IpAddr>() {
        Ok(ip) => p.ips.contains(&ip),
        Err(_) => !p.dns_name.is_empty() && p.dns_name == normalize_tailnet(&t.address),
    }
}

/// The tailnet address to try, from the local client's view of the tailnet.
fn tailnet_ip_from(
    t: &TailscaleRemote,
    s: &Snapshot,
    notes: &mut Vec<String>,
) -> Result<IpAddr, Problem> {
    let want = normalize_tailnet(&t.tailnet);
    if s.tailnet.as_deref() != Some(want.as_str()) {
        return Err(Problem::TailnetMismatch {
            want,
            have: s.tailnet.clone(),
        });
    }
    let named: Vec<&crate::tailscale::Peer> = s.nodes().filter(|p| addr_names(t, p)).collect();
    let peer = match &t.node_id {
        Some(id) => {
            if let Some(other) = named.iter().find(|p| &p.id != id) {
                return Err(Problem::PeerConflict(format!(
                    "SECURITY STOP: tailnet address {} belongs to node {}, not to the configured node {id}; if the device was re-enrolled, verify it and update remote.tailscale.node_id",
                    t.address,
                    printable(&other.id)
                )));
            }
            s.nodes()
                .find(|p| &p.id == id)
                .ok_or(Problem::PeerNotFound)?
        }
        None => match named.as_slice() {
            [] => return Err(Problem::PeerNotFound),
            [one] => *one,
            many => {
                return Err(Problem::PeerConflict(format!(
                "SECURITY STOP: tailnet address {} matches {} nodes; set remote.tailscale.node_id",
                t.address,
                many.len()
            )))
            }
        },
    };
    if peer.expired {
        return Err(Problem::PeerExpired);
    }
    if !peer.online {
        notes.push(
            "Tailscale reports the device offline (not trusted either way; trying anyway)".into(),
        );
    }
    let ip = match t.address.parse::<IpAddr>() {
        Ok(ip) if peer.ips.contains(&ip) => Some(ip),
        _ => peer
            .ips
            .iter()
            .find(|i| i.is_ipv4())
            .or(peer.ips.first())
            .copied(),
    };
    ip.ok_or(Problem::NoTailnetAddress)
}

/// The tailnet address when the Tailscale CLI cannot be asked: the configured
/// IP, or the configured name through the system resolver (MagicDNS). The
/// tailnet and node are then unchecked; the pinned host key still is.
fn tailnet_ip_unchecked(
    net: &dyn Net,
    t: &TailscaleRemote,
    why: &str,
    timeouts: &Timeouts,
    notes: &mut Vec<String>,
) -> Result<IpAddr, Problem> {
    notes.push(format!(
        "{why}; the tailnet and node identity were not checked, the pinned SSH host key still is"
    ));
    if let Ok(ip) = t.address.parse::<IpAddr>() {
        return Ok(ip);
    }
    let ips = net
        .lookup(&t.address, timeouts.dns)
        .map_err(|_| Problem::DnsFailure {
            name: t.address.clone(),
        })?;
    ips.iter()
        .find(|i| i.is_ipv4())
        .or(ips.first())
        .copied()
        .ok_or(Problem::DnsFailure {
            name: t.address.clone(),
        })
}

/// Select an endpoint for `spec`.
pub fn select(
    spec: &DeviceSpec,
    pref: Preference,
    net: &dyn Net,
    mode: Mode,
    t: &Timeouts,
) -> Selection {
    let mut sel = Selection::default();
    let stop = |sel: &Selection| {
        mode == Mode::FirstUsable && (sel.endpoint.is_some() || sel.fatal().is_some())
    };

    if pref != Preference::Tailscale {
        'lan: for hint in &spec.lan {
            let (target, ips) = match hint {
                LanHint::Ip(ip) => (ip.to_string(), vec![*ip]),
                LanHint::Name(n) => match net.lookup(n, t.dns) {
                    Ok(ips) if !ips.is_empty() => {
                        let mut v = ips;
                        v.dedup();
                        v.truncate(4);
                        (n.clone(), v)
                    }
                    _ => {
                        sel.attempts.push(Attempt {
                            transport: Transport::Lan,
                            target: n.clone(),
                            ip: None,
                            problem: Some(Problem::DnsFailure { name: n.clone() }),
                        });
                        continue;
                    }
                },
            };
            for ip in ips {
                let r = verify_endpoint(net, ip, spec.port, &spec.pinned, t.lan_connect, t);
                record(&mut sel, Transport::Lan, &target, ip, spec.port, r);
                if stop(&sel) {
                    break 'lan;
                }
            }
        }
    }
    if stop(&sel) || pref == Preference::Lan {
        return sel;
    }

    let Some(ts) = &spec.tailscale else {
        return sel;
    };
    let ip = match net.tailscale() {
        TsState::Running(s) => tailnet_ip_from(ts, &s, &mut sel.notes),
        TsState::Missing => {
            tailnet_ip_unchecked(net, ts, "Tailscale CLI not found", t, &mut sel.notes)
        }
        TsState::Failed(why) => tailnet_ip_unchecked(net, ts, why, t, &mut sel.notes),
        TsState::NotRunning { state } => Err(match state {
            "NeedsLogin" | "NeedsMachineAuth" => Problem::TailscaleLoggedOut { state },
            "Stopped" => Problem::TailscaleStopped,
            _ => Problem::TailscaleNotReady { state },
        }),
    };
    match ip {
        Err(p) => sel.attempts.push(Attempt {
            transport: Transport::Tailscale,
            target: ts.address.clone(),
            ip: None,
            problem: Some(p),
        }),
        Ok(ip) => {
            let r = verify_endpoint(net, ip, spec.port, &spec.pinned, t.tailnet_connect, t);
            record(
                &mut sel,
                Transport::Tailscale,
                &ts.address,
                ip,
                spec.port,
                r,
            );
        }
    }
    sel
}

fn record(
    sel: &mut Selection,
    transport: Transport,
    target: &str,
    ip: IpAddr,
    port: u16,
    r: Result<Vec<HostKey>, Problem>,
) {
    let problem = match r {
        Ok(keys) => {
            // Never past an identity disagreement, even when evaluating all.
            if sel.endpoint.is_none() && sel.fatal().is_none() {
                sel.endpoint = Some(Endpoint {
                    transport,
                    ip,
                    port,
                    keys,
                });
            }
            None
        }
        Err(p) => Some(p),
    };
    sel.attempts.push(Attempt {
        transport,
        target: target.to_string(),
        ip: Some(ip),
        problem,
    });
}
