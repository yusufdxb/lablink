//! Device state model and the JSON views exchanged over IPC.
//!
//! Every enum here is serialized in `snake_case` and is part of the stable
//! JSON contract (`schema_version` 1). Add variants only at the end and never
//! rename existing ones.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the JSON output schema emitted by `--json` and the IPC API.
pub const SCHEMA_VERSION: u32 = 1;

/// Layer-3 reachability of the device's current address, with hysteresis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    #[default]
    Unknown,
    Online,
    Degraded,
    Offline,
}

/// TCP state of the SSH port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    #[default]
    Unknown,
    Open,
    /// Connection refused: host is up, nothing listening.
    Closed,
    /// No answer within the timeout (dropped by a firewall, or host down).
    Filtered,
    /// The device is configured without SSH.
    Disabled,
}

/// Result of the most recent non-interactive SSH login check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthState {
    #[default]
    Unknown,
    Ok,
    /// The server rejected every configured username / key.
    Failed,
    /// Could not be checked (identity unverified, port not open, ssh error).
    Unavailable,
    /// Auth checks disabled for this device (or SSH disabled).
    Disabled,
}

/// SSH host-key identity of the device at its current address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityState {
    /// No host key has been observed yet.
    #[default]
    Unknown,
    /// A host key was observed but nothing vouches for it yet.
    Unverified,
    /// The observed host key matches a pinned key.
    Verified,
    /// The observed host key differs from the pinned key. Security error.
    Mismatch,
}

/// Whether LabLink currently knows where the device is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    /// Never located since it was first configured.
    #[default]
    NeverSeen,
    /// Has a current address that answered recently.
    Located,
    /// Was located before; current address unknown or not answering.
    Searching,
}

/// Overall traffic-light state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Color {
    Green,
    Yellow,
    Red,
    Gray,
}

impl Color {
    pub fn as_str(self) -> &'static str {
        match self {
            Color::Green => "GREEN",
            Color::Yellow => "YELLOW",
            Color::Red => "RED",
            Color::Gray => "GRAY",
        }
    }
}

/// State of a pluggable service check (ROS 2, disk, GPU, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    #[default]
    Unknown,
    Ok,
    Degraded,
    Failed,
    Disabled,
}

/// One service check result attached to a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: ServiceState,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub checked_ms_ago: Option<u64>,
}

/// Inputs to the color decision.
#[derive(Debug, Clone, Copy)]
pub struct ColorInput {
    pub monitoring: bool,
    /// State of the device's site: AWAY devices are not evaluated, and an
    /// unconfirmed site never turns an unreachable device RED.
    pub site: crate::site::SiteState,
    pub discovery: DiscoveryState,
    pub network: NetworkState,
    pub ssh_enabled: bool,
    pub auth_check_enabled: bool,
    pub port: PortState,
    pub auth: AuthState,
    pub identity: IdentityState,
}

/// Derive the traffic-light color and the human-readable reasons behind it.
/// See `docs/STATUS_MODEL.md` for the full table.
pub fn compute_color(i: &ColorInput) -> (Color, Vec<String>) {
    let mut reasons = Vec::new();
    if !i.monitoring {
        return (Color::Gray, vec!["monitoring disabled".into()]);
    }
    if i.identity == IdentityState::Mismatch {
        return (
            Color::Red,
            vec![
                "SECURITY: SSH host key does not match the pinned identity (see `lablink inspect`)"
                    .into(),
            ],
        );
    }
    if i.site == crate::site::SiteState::Away {
        return (
            Color::Gray,
            vec!["site is away: not checked while you are at another site".into()],
        );
    }
    if i.network == NetworkState::Offline && i.site == crate::site::SiteState::Unknown {
        return (
            Color::Gray,
            vec![
                "unreachable, but the site is not confirmed, so this is not reported as a failure"
                    .into(),
            ],
        );
    }
    if i.discovery == DiscoveryState::NeverSeen {
        return (Color::Gray, vec!["never located".into()]);
    }
    match i.network {
        NetworkState::Unknown => return (Color::Gray, vec!["not checked yet".into()]),
        NetworkState::Offline => {
            return (
                Color::Red,
                vec!["unreachable after failure threshold".into()],
            )
        }
        NetworkState::Degraded => reasons.push("recent reachability checks failed".into()),
        NetworkState::Online => {}
    }
    if i.ssh_enabled {
        match i.port {
            PortState::Open => {}
            PortState::Closed => reasons.push("SSH port closed (connection refused)".into()),
            PortState::Filtered => reasons.push("SSH port not answering".into()),
            PortState::Unknown => reasons.push("SSH port not checked yet".into()),
            PortState::Disabled => {}
        }
        match i.identity {
            IdentityState::Verified => {}
            IdentityState::Unverified => {
                reasons.push("host key not pinned (run `lablink trust <device>`)".into())
            }
            IdentityState::Unknown => reasons.push("host key not observed yet".into()),
            IdentityState::Mismatch => unreachable!(),
        }
        if i.auth_check_enabled {
            match i.auth {
                AuthState::Ok | AuthState::Disabled => {}
                AuthState::Failed => reasons.push("SSH login failed (keys/agent rejected)".into()),
                AuthState::Unavailable => reasons.push("SSH login could not be checked".into()),
                AuthState::Unknown => reasons.push("SSH login not checked yet".into()),
            }
        }
    }
    if reasons.is_empty() {
        (Color::Green, reasons)
    } else {
        (Color::Yellow, reasons)
    }
}

/// Compact per-device status (`lablink status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceStatus {
    /// Friendly name (may exist at several sites).
    pub name: String,
    /// Canonical reference `site/name`, unique: use it in follow-up requests.
    #[serde(default)]
    pub id: String,
    /// Site id and display name.
    #[serde(default)]
    pub site: String,
    #[serde(default)]
    pub site_name: String,
    #[serde(default)]
    pub site_state: crate::site::SiteState,
    #[serde(default)]
    pub label: Option<String>,
    pub color: Color,
    pub ip: Option<String>,
    pub discovery: DiscoveryState,
    pub network: NetworkState,
    pub ssh_port: PortState,
    pub ssh_auth: AuthState,
    pub identity: IdentityState,
    pub latency_ms: Option<u64>,
    /// Milliseconds since the device last answered a probe.
    pub last_seen_ms: Option<u64>,
    pub username: Option<String>,
    pub interface: Option<String>,
    pub network_name: Option<String>,
    /// Gateway device used to reach this one, when not directly attached.
    #[serde(default)]
    pub via: Option<String>,
    /// The roaming site (Field Network) this device is visiting while its
    /// own site is AWAY: recognized there by its pinned host key alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visiting: Option<String>,
    pub monitoring: bool,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub services: Vec<ServiceStatus>,
    /// Optional device profile (`generic_linux`, `jetson`, ...).
    #[serde(default)]
    pub profile: Option<crate::profile::Profile>,
    /// What the device supports (`network`, `ssh`, `gpu`, ...).
    #[serde(default)]
    pub capabilities: Vec<crate::profile::Capability>,
}

/// `lablink status` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    pub schema_version: u32,
    pub daemon: DaemonInfo,
    pub devices: Vec<DeviceStatus>,
    /// How the active site is chosen.
    #[serde(default)]
    pub site_mode: crate::site::SiteMode,
    /// Every site with its state (devices of AWAY sites are only listed when
    /// asked for with `--all` or `--site`).
    #[serde(default)]
    pub sites: Vec<crate::site::SiteStatus>,
}

/// Identifies the daemon that produced a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub version: String,
    pub pid: u32,
    pub uptime_s: u64,
}

/// A host key as shown to users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyView {
    pub key_type: String,
    pub fingerprint: String,
    /// Where the pin came from: `config`, `user_known_hosts`, `trust`.
    #[serde(default)]
    pub source: Option<String>,
}

/// One address a device has used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressView {
    pub ip: String,
    pub current: bool,
    pub network_name: Option<String>,
    pub interface: Option<String>,
    pub mac: Option<String>,
    pub source: String,
    pub first_seen_ms_ago: u64,
    pub last_seen_ms_ago: u64,
}

/// Full detail (`lablink inspect`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceDetail {
    pub schema_version: u32,
    pub status: DeviceStatus,
    pub configured: bool,
    pub aliases: Vec<String>,
    pub usernames: Vec<String>,
    pub active_username: Option<String>,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub hostnames: Vec<String>,
    pub learned_hostnames: Vec<String>,
    pub mdns_names: Vec<String>,
    pub macs: Vec<String>,
    pub pinned_keys: Vec<KeyView>,
    pub observed_keys: Vec<KeyView>,
    pub expected_ips: Vec<String>,
    pub addresses: Vec<AddressView>,
    pub identity_signal: Option<String>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub notes: Option<String>,
    pub recent_events: Vec<HistoryEvent>,
    /// Settings changed at runtime (`lablink set`, the GUI), as opposed to
    /// values from the config file.
    #[serde(default)]
    pub overrides: OverridesView,
}

/// Runtime overrides of one device (`None`: not overridden).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OverridesView {
    pub label: Option<String>,
    pub username: Option<String>,
    pub monitoring: Option<bool>,
    pub profile: Option<crate::profile::Profile>,
    pub ssh: Option<bool>,
}

/// One connection-history event (state transitions only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub ts_ms: u64,
    pub device: Option<String>,
    pub kind: String,
    pub message: String,
}

/// A host seen on the network that is not (yet) a tracked device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: String,
    /// Site of the configured network the host is on (preferring the active site).
    #[serde(default)]
    pub site: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub network_name: Option<String>,
    pub interface: Option<String>,
    pub sources: Vec<String>,
    pub ssh_port: PortState,
    pub fingerprints: Vec<String>,
    pub matched_device: Option<String>,
    pub note: Option<String>,
    pub first_seen_ms_ago: u64,
    pub last_seen_ms_ago: u64,
}

/// Outcome of one discovery stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReport {
    pub stage: String,
    /// `ok`, `skipped`, `refused` or `error`.
    pub result: String,
    pub detail: String,
    pub duration_ms: u64,
}

/// `lablink discover` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoverReport {
    pub schema_version: u32,
    pub stages: Vec<StageReport>,
    pub probed_hosts: u64,
    pub responsive_hosts: u64,
    pub devices: Vec<DeviceStatus>,
    pub discovered: Vec<DiscoveredHost>,
}

/// What the CLI needs to launch OpenSSH for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResult {
    pub schema_version: u32,
    pub name: String,
    /// Canonical `site/name`.
    #[serde(default)]
    pub id: String,
    /// Display name of the device's site.
    #[serde(default)]
    pub site_name: String,
    /// Another site has a device with the same name: say which one was meant.
    #[serde(default)]
    pub shared_name: bool,
    /// The device's site is AWAY: its last address may now belong to a
    /// machine on another network.
    #[serde(default)]
    pub site_away: bool,
    pub ip: String,
    pub port: u16,
    pub ssh_host: String,
    pub username: Option<String>,
    pub identity: IdentityState,
    pub color: Color,
    pub network: NetworkState,
    /// Set when the identity is verified: connect with this HostKeyAlias
    /// against `known_hosts_file` and StrictHostKeyChecking=yes.
    pub host_key_alias: Option<String>,
    pub known_hosts_file: Option<String>,
    pub ssh_binary: String,
    pub connect_timeout_s: u64,
    pub ssh_options: BTreeMap<String, String>,
    /// Set for devices reached through a gateway: an OpenSSH ProxyCommand
    /// that connects through the gateway with its own pinned identity.
    #[serde(default)]
    pub proxy_command: Option<String>,
}

/// `lablink trust` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustReport {
    pub schema_version: u32,
    /// Canonical `site/name`.
    pub device: String,
    pub ip: String,
    /// `preview`, `pinned` or `unchanged`.
    pub action: String,
    pub scanned: Vec<KeyView>,
    pub pinned_before: Vec<KeyView>,
    pub pinned_now: Vec<KeyView>,
}

/// Daemon resource usage and activity counters (`lablink metrics`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsReport {
    pub schema_version: u32,
    pub daemon: DaemonInfo,
    pub rss_kib: Option<u64>,
    pub threads: Option<u64>,
    pub open_fds: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub tokio_alive_tasks: usize,
    pub monitored_devices: usize,
    pub counters: BTreeMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ColorInput {
        ColorInput {
            monitoring: true,
            site: crate::site::SiteState::Active,
            discovery: DiscoveryState::Located,
            network: NetworkState::Online,
            ssh_enabled: true,
            auth_check_enabled: true,
            port: PortState::Open,
            auth: AuthState::Ok,
            identity: IdentityState::Verified,
        }
    }

    #[test]
    fn green_requires_everything() {
        assert_eq!(compute_color(&base()).0, Color::Green);
        for f in [
            |c: &mut ColorInput| c.port = PortState::Closed,
            |c: &mut ColorInput| c.auth = AuthState::Failed,
            |c: &mut ColorInput| c.identity = IdentityState::Unverified,
            |c: &mut ColorInput| c.network = NetworkState::Degraded,
            |c: &mut ColorInput| c.auth = AuthState::Unknown,
        ] {
            let mut c = base();
            f(&mut c);
            let (color, reasons) = compute_color(&c);
            assert_eq!(color, Color::Yellow);
            assert!(!reasons.is_empty());
        }
    }

    #[test]
    fn red_gray_rules() {
        let mut c = base();
        c.network = NetworkState::Offline;
        assert_eq!(compute_color(&c).0, Color::Red);
        c.discovery = DiscoveryState::NeverSeen;
        assert_eq!(compute_color(&c).0, Color::Gray);
        let mut c = base();
        c.identity = IdentityState::Mismatch;
        assert_eq!(compute_color(&c).0, Color::Red);
        let mut c = base();
        c.monitoring = false;
        assert_eq!(compute_color(&c).0, Color::Gray);
    }

    #[test]
    fn away_is_gray_unknown_is_never_red_mismatch_stays_red() {
        use crate::site::SiteState;
        let mut c = base();
        c.site = SiteState::Away;
        c.network = NetworkState::Offline;
        assert_eq!(compute_color(&c).0, Color::Gray);
        c.site = SiteState::Unknown;
        assert_eq!(compute_color(&c).0, Color::Gray);
        c.network = NetworkState::Online;
        assert_eq!(compute_color(&c).0, Color::Green);
        for s in [SiteState::Away, SiteState::Unknown, SiteState::Active] {
            let mut c = base();
            c.site = s;
            c.identity = IdentityState::Mismatch;
            assert_eq!(compute_color(&c).0, Color::Red, "{s:?}");
        }
    }

    #[test]
    fn no_ssh_device_green_on_network_alone() {
        let mut c = base();
        c.ssh_enabled = false;
        c.port = PortState::Disabled;
        c.auth = AuthState::Disabled;
        c.identity = IdentityState::Unknown;
        assert_eq!(compute_color(&c).0, Color::Green);
    }

    #[test]
    fn auth_check_disabled_does_not_block_green() {
        let mut c = base();
        c.auth_check_enabled = false;
        c.auth = AuthState::Disabled;
        assert_eq!(compute_color(&c).0, Color::Green);
    }

    #[test]
    fn enums_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&NetworkState::Online).unwrap(),
            "\"online\""
        );
        assert_eq!(
            serde_json::to_string(&PortState::Filtered).unwrap(),
            "\"filtered\""
        );
        assert_eq!(
            serde_json::to_string(&DiscoveryState::NeverSeen).unwrap(),
            "\"never_seen\""
        );
        assert_eq!(serde_json::to_string(&Color::Yellow).unwrap(), "\"yellow\"");
    }
}
