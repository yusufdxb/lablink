//! The device registry: the single owner of all device state.
//!
//! All mutation happens through methods on [`Registry`], under one mutex held
//! for short, non-blocking critical sections (no I/O inside). Network work is
//! done by the monitors and the discovery coordinator, which feed results in
//! here. The registry decides identity, applies hysteresis, records history
//! events (transitions only) and tracks what needs persisting.

use crate::probe::AuthOutcome;
use crate::store::Batch;
use lablink_core::config::{
    device_id, normalize_hostname, normalize_mac, split_ref, Config, DeviceConfig, SshConfig,
};
use lablink_core::health::{NetTracker, PortTracker, Thresholds};
use lablink_core::identity::{classify, HostKey, KnownIdentity, MatchOutcome, Observation, Signal};
use lablink_core::model::*;
use lablink_core::net::Allowlist;
use lablink_core::profile::Profile;
use lablink_core::protocol::{ApiError, Candidate, DeviceChanges, ErrorCode};
use lablink_core::site::{self as sites, Decision, KeySighting, SiteMode, SiteState};
use lablink_discovery::{Neighbor, Snapshot};
use lablink_ssh::KeyProof;
use lablink_ssh::{KnownHostsEntry, Target};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// In-memory history ring size (older events stay in SQLite).
pub const EVENT_RING: usize = 1000;
/// Maximum unmatched hosts remembered.
pub const MAX_DISCOVERED: usize = 512;
/// Maximum address records per device.
const MAX_ADDRESSES: usize = 16;
/// Cap on remembered "ambiguous" notes (they only rate-limit duplicate events).
const MAX_AMBIGUITY_NOTES: usize = 1024;
/// Heartbeat-only changes (`last_seen`) are persisted at most this often.
const LAST_SEEN_PERSIST_MS: u64 = 300_000;
/// How long "this address came from resolving a configured name" counts as
/// identity evidence for IP-keyed known_hosts entries.
const NAME_EVIDENCE_TTL_MS: u64 = 600_000;
/// Prefix of the HostKeyAlias used for pinned devices
/// (`lablink.<site>.<name>`; site ids contain no dots).
pub const ALIAS_PREFIX: &str = "lablink.";
/// A pinned host key seen while its device's site was not engaged counts as
/// site evidence for this long.
const KEY_SIGHTING_TTL_MS: u64 = 600_000;
/// Gateway MACs remembered per network for site detection.
const MAX_LEARNED_GATEWAYS: usize = 4;

/// A pinned SSH host key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKey {
    pub key_type: String,
    pub fingerprint: String,
    #[serde(default)]
    pub public_key: Option<String>,
    /// `config`, `user_known_hosts` or `trust`.
    pub source: String,
    pub pinned_at_ms: u64,
}

/// One address a device has been seen at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRecord {
    pub ip: IpAddr,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    pub source: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Last time the user adopted the device at this address (explicit
    /// intent, unlike mDNS/DNS answers, which anyone on the network can
    /// forge). The evidence expires.
    #[serde(default)]
    pub last_adopted_ms: u64,
}

/// Runtime overrides set via `lablink set` / the GUI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Overrides {
    pub label: Option<String>,
    pub username: Option<String>,
    pub monitoring: Option<bool>,
    pub notes: Option<String>,
    /// Profile chosen at adoption or with `lablink set --profile`.
    pub profile: Option<lablink_core::profile::Profile>,
    /// SSH on/off for adopted devices (configured devices use the config).
    pub ssh: Option<bool>,
}

/// The persisted part of a device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceRecord {
    pub name: String,
    /// Site id (absent in records written before sites existed).
    pub site: Option<String>,
    /// Defined at runtime with `lablink adopt` rather than in the config file.
    pub adopted: bool,
    pub overrides: Overrides,
    pub learned_macs: BTreeSet<String>,
    pub learned_hostnames: BTreeSet<String>,
    pub mdns_names: BTreeSet<String>,
    pub pinned: Vec<PinnedKey>,
    pub current_ip: Option<IpAddr>,
    pub addresses: Vec<AddressRecord>,
    pub first_seen_ms: Option<u64>,
    pub last_seen_ms: Option<u64>,
    pub active_username: Option<String>,
}

/// A host seen on the network that is not a tracked device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredRecord {
    pub ip: IpAddr,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub sources: BTreeSet<String>,
    #[serde(default)]
    pub ssh_port: PortState,
    #[serde(default)]
    pub keys: Vec<HostKey>,
    #[serde(default)]
    pub note: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    #[serde(default)]
    pub last_tcp_ms: u64,
    #[serde(default)]
    pub last_keyscan_ms: u64,
}

/// Runtime state of one service check.
#[derive(Clone)]
pub struct ServiceSlot {
    pub check: std::sync::Arc<dyn crate::services::ServiceCheck>,
    pub state: ServiceState,
    pub detail: Option<String>,
    pub last_run_ms: u64,
}

impl std::fmt::Debug for ServiceSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceSlot")
            .field("name", &self.check.name())
            .field("state", &self.state)
            .finish()
    }
}

/// Live state of one tracked device.
#[derive(Debug, Clone)]
pub struct Device {
    /// Canonical `site/name`, the registry key.
    pub id: String,
    /// Site id.
    pub site: String,
    pub cfg: DeviceConfig,
    pub services: Vec<ServiceSlot>,
    pub configured: bool,
    pub rec: DeviceRecord,
    pub net: NetTracker,
    pub port: PortTracker,
    pub auth: AuthState,
    pub identity: IdentityState,
    pub latency_ms: Option<u64>,
    pub observed_keys: Vec<HostKey>,
    pub identity_signal: Option<Signal>,
    pub identity_ip: Option<IpAddr>,
    pub auth_ip: Option<IpAddr>,
    pub last_error: Option<String>,
    pub last_check_ms: u64,
    pub last_port_check_ms: u64,
    pub last_identity_check_ms: u64,
    pub last_auth_check_ms: u64,
    pub last_resolve_ms: u64,
    /// Port transitioned to open since the last identity check.
    pub port_opened: bool,
    /// Port transitioned to open since the last login check. Separate from
    /// `port_opened` because the identity check consumes that flag first, and
    /// a previously failed login must also be re-checked when SSH comes back.
    pub auth_recheck: bool,
    /// Evidence that a different machine may now answer at the current
    /// address (link-layer address changed): re-verify the host key now.
    pub identity_recheck: bool,
    /// This device has answered ICMP at least once.
    pub icmp_answered: bool,
    /// ICMP failed while TCP showed the host up (ICMP filtered).
    pub icmp_misses_while_up: u32,
    /// Names (mDNS/DNS) that moved the device to its current address. The
    /// next host-key check carries them, so a key that contradicts the pin
    /// at an address claimed by name is a MISMATCH, not an address reuse.
    pub attributed_names: Vec<String>,
    /// The host at this address presented a pinned key; it becomes Verified
    /// only after proving it holds the key (`Mode::KeyProof`): anyone can
    /// replay a public key to ssh-keyscan.
    pub key_proof_due: Option<IpAddr>,
    persisted_last_seen_ms: u64,
}

impl Device {
    fn new(cfg: DeviceConfig, site: &str, configured: bool) -> Self {
        let rec = DeviceRecord {
            name: cfg.name.clone(),
            site: Some(site.to_string()),
            adopted: !configured,
            ..Default::default()
        };
        let services = crate::services::from_config(&cfg)
            .into_iter()
            .map(|check| ServiceSlot {
                check,
                state: ServiceState::Unknown,
                detail: None,
                last_run_ms: 0,
            })
            .collect();
        Self {
            id: device_id(site, &cfg.name),
            site: site.to_string(),
            services,
            cfg,
            configured,
            rec,
            net: NetTracker::default(),
            port: PortTracker::default(),
            auth: AuthState::Unknown,
            identity: IdentityState::Unknown,
            latency_ms: None,
            observed_keys: Vec::new(),
            identity_signal: None,
            identity_ip: None,
            auth_ip: None,
            last_error: None,
            last_check_ms: 0,
            last_port_check_ms: 0,
            last_identity_check_ms: 0,
            last_auth_check_ms: 0,
            last_resolve_ms: 0,
            port_opened: false,
            auth_recheck: false,
            identity_recheck: false,
            icmp_answered: false,
            icmp_misses_while_up: 0,
            attributed_names: Vec::new(),
            key_proof_due: None,
            persisted_last_seen_ms: 0,
        }
    }

    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    pub fn monitoring(&self) -> bool {
        self.rec.overrides.monitoring.unwrap_or(self.cfg.monitor)
    }

    /// Effective profile: the runtime override, else the config.
    pub fn profile(&self) -> Option<lablink_core::profile::Profile> {
        self.rec.overrides.profile.or(self.cfg.profile)
    }

    /// Adopted devices have no config entry: their SSH switch lives in the
    /// overrides (a network-only profile always means no SSH).
    fn apply_runtime_ssh(&mut self) {
        if self.configured {
            return;
        }
        let ssh =
            self.rec.overrides.ssh.unwrap_or(true) && self.profile().is_none_or(|p| p.uses_ssh());
        if ssh != self.cfg.ssh {
            self.cfg.ssh = ssh;
            self.cfg.auth_check = ssh;
            self.port.reset();
            self.auth = AuthState::Unknown;
            self.port_opened = ssh;
            self.auth_recheck = ssh;
        }
    }

    pub fn label(&self) -> Option<String> {
        self.rec
            .overrides
            .label
            .clone()
            .or_else(|| self.cfg.label.clone())
    }

    /// Username used for `ssh`/`exec`: explicit override, else the one that
    /// last authenticated, else the first configured, else none (ssh config decides).
    pub fn username(&self) -> Option<String> {
        self.rec
            .overrides
            .username
            .clone()
            .or_else(|| self.rec.active_username.clone())
            .or_else(|| self.cfg.usernames.first().cloned())
    }

    /// Usernames for the auth check, in order, deduplicated.
    pub fn auth_usernames(&self) -> Vec<Option<String>> {
        let mut v: Vec<String> = Vec::new();
        for u in self
            .rec
            .overrides
            .username
            .iter()
            .chain(self.rec.active_username.iter())
            .chain(self.cfg.usernames.iter())
        {
            if !v.contains(u) {
                v.push(u.clone());
            }
        }
        if v.is_empty() {
            vec![None]
        } else {
            v.into_iter().map(Some).collect()
        }
    }

    pub fn ssh_host(&self) -> String {
        self.cfg
            .ssh_host
            .clone()
            .unwrap_or_else(|| self.cfg.name.clone())
    }

    pub fn pinned_fingerprints(&self) -> BTreeSet<String> {
        self.cfg
            .host_key_fingerprints
            .iter()
            .cloned()
            .chain(self.rec.pinned.iter().map(|p| p.fingerprint.clone()))
            .collect()
    }

    /// Pins with a public-key blob (usable in known_hosts).
    fn usable_pins(&self) -> Vec<&PinnedKey> {
        self.rec
            .pinned
            .iter()
            .filter(|p| p.public_key.is_some())
            .collect()
    }

    fn known_identity(&self) -> KnownIdentity {
        KnownIdentity {
            name: self.id.clone(),
            pinned: self.pinned_fingerprints(),
            macs: self
                .cfg
                .normalized_macs()
                .into_iter()
                .chain(self.rec.learned_macs.iter().cloned())
                .collect(),
            names: self
                .cfg
                .hostnames
                .iter()
                .map(|h| normalize_hostname(h))
                .chain(self.rec.learned_hostnames.iter().cloned())
                .chain(self.rec.mdns_names.iter().cloned())
                .collect(),
            static_ips: self.cfg.expected_ip_addrs(),
            current_ip: self.rec.current_ip,
            previous_ips: self
                .rec
                .addresses
                .iter()
                .map(|a| a.ip)
                .filter(|ip| Some(*ip) != self.rec.current_ip)
                .collect(),
        }
    }

    pub fn discovery(&self) -> DiscoveryState {
        if self.rec.first_seen_ms.is_none() {
            DiscoveryState::NeverSeen
        } else if self.rec.current_ip.is_some()
            && matches!(
                self.net.state,
                NetworkState::Online | NetworkState::Degraded
            )
        {
            DiscoveryState::Located
        } else {
            DiscoveryState::Searching
        }
    }

    fn healthy(&self) -> bool {
        self.rec.current_ip.is_some()
            && matches!(
                self.net.state,
                NetworkState::Online | NetworkState::Degraded
            )
    }

    fn reset_runtime_for_new_ip(&mut self) {
        self.port.reset();
        self.auth = AuthState::Unknown;
        if self.identity != IdentityState::Mismatch {
            self.identity = IdentityState::Unknown;
        }
        self.identity_ip = None;
        self.auth_ip = None;
        self.latency_ms = None;
        self.icmp_misses_while_up = 0;
        self.attributed_names.clear();
        self.key_proof_due = None;
    }
}

/// What a monitor should probe next for one device.
#[derive(Debug, Clone)]
pub struct CheckPlan {
    pub name: String,
    /// Gateway to check through (device not directly reachable from here).
    pub via: Option<String>,
    pub candidates: Vec<IpAddr>,
    pub hostnames_to_resolve: Vec<String>,
    pub ssh: bool,
    pub port: u16,
    pub port_check_due: bool,
    pub icmp_usable: bool,
}

/// Result of one liveness probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub ip: IpAddr,
    pub up: bool,
    /// `None` when the port was not checked this round.
    pub port: Option<PortState>,
    pub rtt: Option<Duration>,
    pub method: &'static str,
    pub detail: Option<String>,
    /// ICMP answered (Some(true)), timed out (Some(false)), or was not tried.
    pub icmp_answered: Option<bool>,
}

/// Follow-up SSH work due after a probe.
#[derive(Debug, Clone, Default)]
pub struct FollowUp {
    pub keyscan: Option<(IpAddr, u16)>,
    pub auth: Vec<Target>,
}

/// The registry.
pub struct Registry {
    pub cfg: Config,
    th: Thresholds,
    pub allowlist: Allowlist,
    known_hosts_path: PathBuf,
    devices: BTreeMap<String, Device>,
    discovered: BTreeMap<IpAddr, DiscoveredRecord>,
    ring: VecDeque<HistoryEvent>,
    pending: Vec<HistoryEvent>,
    dirty_devices: BTreeSet<String>,
    dirty_discovered: BTreeSet<IpAddr>,
    removed_discovered: BTreeSet<IpAddr>,
    /// Something important changed: flush soon rather than after the debounce.
    pub urgent: bool,
    pub known_hosts_dirty: bool,
    pub snapshot: Option<Snapshot>,
    neighbors: HashMap<IpAddr, (String, u32)>,
    noted_ambiguity: BTreeSet<(IpAddr, String)>,
    /// Cache rows written under an old key (a bare name from before sites)
    /// that must be deleted once rewritten under the device id.
    removed_devices: BTreeSet<String>,
    /// How the active site is chosen.
    pub mode: SiteMode,
    /// The current decision for every site, by site id.
    decisions: BTreeMap<String, Decision>,
    /// The evidence behind each decision, by site id.
    assessments: BTreeMap<String, sites::Assessment>,
    /// Gateway MACs learned per site: `(network name, mac)`.
    learned_gateways: BTreeMap<String, Vec<(String, String)>>,
    /// Pinned host keys seen for devices whose site was not engaged:
    /// device id -> (address, when).
    key_sightings: BTreeMap<String, (IpAddr, u64)>,
    /// Site mode or learned signatures changed: persist them.
    pub sites_dirty: bool,
    /// Something site detection depends on changed: re-evaluate.
    pub sites_stale: bool,
}

fn ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

impl Registry {
    /// Sizes of every long-lived collection, for attributing memory growth.
    pub fn state_sizes(&self) -> Vec<(&'static str, u64)> {
        let sum = |f: &dyn Fn(&Device) -> usize| -> u64 {
            self.devices.values().map(|d| f(d) as u64).sum()
        };
        vec![
            ("ring_events", self.ring.len() as u64),
            ("pending_events", self.pending.len() as u64),
            ("discovered_hosts", self.discovered.len() as u64),
            ("removed_discovered", self.removed_discovered.len() as u64),
            ("dirty_devices", self.dirty_devices.len() as u64),
            ("dirty_discovered", self.dirty_discovered.len() as u64),
            ("neighbors", self.neighbors.len() as u64),
            ("ambiguity_notes", self.noted_ambiguity.len() as u64),
            ("devices", self.devices.len() as u64),
            ("address_records_total", sum(&|d| d.rec.addresses.len())),
            ("learned_macs_total", sum(&|d| d.rec.learned_macs.len())),
            (
                "learned_hostnames_total",
                sum(&|d| d.rec.learned_hostnames.len()),
            ),
            ("mdns_names_total", sum(&|d| d.rec.mdns_names.len())),
            ("observed_keys_total", sum(&|d| d.observed_keys.len())),
        ]
    }

    pub fn new(cfg: Config, known_hosts_path: PathBuf) -> Self {
        let th = Thresholds {
            degraded_after: cfg.daemon.degraded_after,
            offline_after: cfg.daemon.offline_after,
            recover_after: cfg.daemon.recover_after,
        };
        let allowlist = cfg.allowlist();
        let devices = cfg
            .devices()
            .map(|(s, d)| {
                let dev = Device::new(d.clone(), &s.id, true);
                (dev.id.clone(), dev)
            })
            .collect();
        Self {
            cfg,
            th,
            allowlist,
            known_hosts_path,
            devices,
            discovered: BTreeMap::new(),
            ring: VecDeque::new(),
            pending: Vec::new(),
            dirty_devices: BTreeSet::new(),
            dirty_discovered: BTreeSet::new(),
            removed_discovered: BTreeSet::new(),
            urgent: false,
            known_hosts_dirty: true,
            snapshot: None,
            neighbors: HashMap::new(),
            noted_ambiguity: BTreeSet::new(),
            removed_devices: BTreeSet::new(),
            mode: SiteMode::Auto,
            decisions: BTreeMap::new(),
            assessments: BTreeMap::new(),
            learned_gateways: BTreeMap::new(),
            key_sightings: BTreeMap::new(),
            sites_dirty: false,
            sites_stale: true,
        }
    }

    // ------------------------------------------------------------ restore --

    /// Restore persisted records. Returns warnings for skipped records.
    pub fn restore(
        &mut self,
        devices: &[(String, String)],
        discovered: &[(String, String)],
        events: Vec<HistoryEvent>,
    ) -> Vec<String> {
        let mut warnings = Vec::new();
        for (key, json) in devices {
            let mut rec: DeviceRecord = match serde_json::from_str(json) {
                Ok(r) => r,
                Err(e) => {
                    warnings.push(format!(
                        "skipping unreadable cache record for device '{key}': {e}"
                    ));
                    continue;
                }
            };
            // Records from before sites are keyed by the bare name.
            let (site, name) = match split_ref(key) {
                (Some(s), n) => (Some(s.to_string()), n.to_string()),
                (None, n) => (rec.site.clone(), n.to_string()),
            };
            let configured: Vec<String> = match &site {
                Some(s) => self
                    .devices
                    .values()
                    .filter(|d| d.site.eq_ignore_ascii_case(s) && d.cfg.answers_to(&name))
                    .map(|d| d.id.clone())
                    .collect(),
                None => self
                    .devices
                    .values()
                    .filter(|d| d.configured && d.cfg.answers_to(&name))
                    .map(|d| d.id.clone())
                    .collect(),
            };
            let target = match configured.as_slice() {
                [one] => Some((one.clone(), true)),
                [] if rec.adopted && lablink_core::config::valid_name(&name) => {
                    match site.clone().or_else(|| self.legacy_site()) {
                        Some(s) if self.cfg.site(&s).is_some() => {
                            let s = self.cfg.site(&s).map(|x| x.id.clone()).unwrap_or(s);
                            let id = device_id(&s, &name);
                            if self.devices.contains_key(&id) {
                                None
                            } else {
                                Some((id, false))
                            }
                        }
                        _ => None,
                    }
                }
                [] => None, // removed from config: kept on disk, not tracked.
                _ => {
                    warnings.push(format!(
                        "cache record '{key}' matches devices at several sites; it was not restored"
                    ));
                    None
                }
            };
            let Some((id, existing)) = target else {
                continue;
            };
            if key != &id {
                self.removed_devices.insert(key.clone());
                self.dirty_devices.insert(id.clone());
            }
            if existing {
                let d = self.devices.get_mut(&id).expect("exists");
                let adopted = d.rec.adopted;
                rec.name = d.cfg.name.clone();
                rec.site = Some(d.site.clone());
                rec.adopted = adopted;
                d.persisted_last_seen_ms = rec.last_seen_ms.unwrap_or(0);
                d.rec = rec;
            } else {
                let (site, name) = split_ref(&id);
                let site = site.unwrap_or_default().to_string();
                let mut d = Device::new(DeviceConfig::named(name), &site, false);
                d.persisted_last_seen_ms = rec.last_seen_ms.unwrap_or(0);
                rec.name = name.to_string();
                rec.site = Some(site);
                d.rec = rec;
                d.apply_runtime_ssh();
                self.devices.insert(id, d);
            }
        }
        // A config edit may have created two devices claiming one address.
        // Only within a site: two sites may use the same private address.
        let mut owners: HashMap<(String, IpAddr), String> = HashMap::new();
        let names: Vec<String> = self.devices.keys().cloned().collect();
        for n in names {
            let d = &self.devices[&n];
            if let Some(ip) = d.rec.current_ip {
                if owners.insert((d.site.clone(), ip), n.clone()).is_some() {
                    self.devices.get_mut(&n).unwrap().rec.current_ip = None;
                }
            }
        }
        for (ip, json) in discovered {
            match serde_json::from_str::<DiscoveredRecord>(json) {
                Ok(r) => {
                    self.discovered.insert(r.ip, r);
                }
                Err(e) => warnings.push(format!(
                    "skipping unreadable discovered-host record {ip}: {e}"
                )),
            }
        }
        // Events from before sites name devices by their bare name.
        let renames: BTreeMap<String, String> = self
            .devices
            .values()
            .filter(|d| {
                self.devices
                    .values()
                    .filter(|o| o.cfg.name == d.cfg.name)
                    .count()
                    == 1
            })
            .map(|d| (d.cfg.name.clone(), d.id.clone()))
            .collect();
        self.ring = events
            .into_iter()
            .rev()
            .take(EVENT_RING)
            .rev()
            .map(|mut e| {
                if let Some(n) = e.device.as_ref().and_then(|d| renames.get(d)) {
                    e.device = Some(n.clone());
                }
                e
            })
            .collect();
        self.known_hosts_dirty = true;
        warnings
    }

    // ------------------------------------------------------------ lookups --

    /// The site a record without a site belongs to: the only site, else
    /// the migrated `default` site.
    fn legacy_site(&self) -> Option<String> {
        match self.cfg.sites.as_slice() {
            [one] => Some(one.id.clone()),
            _ => self
                .cfg
                .site(lablink_core::config::DEFAULT_SITE_ID)
                .map(|s| s.id.clone()),
        }
    }

    /// Display name of a site.
    pub fn site_name(&self, site: &str) -> String {
        self.cfg
            .site(site)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| site.to_string())
    }

    /// The device id for `reference`: `site/name`, or a bare name or alias
    /// that is unique, or unique among the confidently active site's
    /// devices. Never guesses between sites otherwise.
    pub fn resolve_ref(&self, reference: &str) -> Result<String, ApiError> {
        if let (Some(site), name) = split_ref(reference) {
            return self
                .devices
                .values()
                .find(|d| d.site.eq_ignore_ascii_case(site) && d.cfg.answers_to(name))
                .map(|d| d.id.clone())
                .ok_or_else(|| {
                    let known = self.cfg.site(site).is_some();
                    ApiError::new(
                        ErrorCode::DeviceNotFound,
                        if known {
                            format!("site '{site}' has no device '{name}'")
                        } else {
                            format!("unknown site '{site}' in '{reference}' (see `lablink sites`)")
                        },
                    )
                });
        }
        let hits: Vec<&Device> = self
            .devices
            .values()
            .filter(|d| d.cfg.answers_to(reference))
            .collect();
        match hits.as_slice() {
            [] => {
                let known: Vec<String> = self
                    .devices
                    .values()
                    .map(|d| self.label_of(&d.id))
                    .collect();
                Err(ApiError::new(
                    ErrorCode::DeviceNotFound,
                    format!("unknown device '{reference}' (known: {})", known.join(", ")),
                ))
            }
            [one] => Ok(one.id.clone()),
            many => {
                let confident: Vec<&&Device> = many
                    .iter()
                    .filter(|d| self.decisions.get(&d.site).is_some_and(Decision::confident))
                    .collect();
                if let [one] = confident.as_slice() {
                    return Ok(one.id.clone());
                }
                let mut e =
                    ApiError::new(
                        ErrorCode::Ambiguous,
                        format!(
                        "ambiguous device '{reference}': it exists at {} sites ({}); use site/name",
                        many.len(),
                        many.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                    );
                e.candidates = many
                    .iter()
                    .map(|d| Candidate {
                        id: d.id.clone(),
                        site_name: self.site_name(&d.site),
                        name: d.cfg.name.clone(),
                    })
                    .collect();
                Err(e)
            }
        }
    }

    fn require(&self, reference: &str) -> Result<String, ApiError> {
        self.resolve_ref(reference)
    }

    /// How to name a device in messages: its name when no other site has a
    /// device of that name, else `site/name`.
    pub fn label_of(&self, id: &str) -> String {
        match self.devices.get(id) {
            Some(d)
                if self
                    .devices
                    .values()
                    .filter(|o| o.cfg.name.eq_ignore_ascii_case(&d.cfg.name))
                    .count()
                    == 1 =>
            {
                d.cfg.name.clone()
            }
            _ => id.to_string(),
        }
    }

    pub fn device(&self, name: &str) -> Option<&Device> {
        self.devices.get(name)
    }

    #[cfg(test)]
    pub fn device_mut(&mut self, name: &str) -> Option<&mut Device> {
        self.devices.get_mut(name)
    }

    pub fn device_names(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    /// Devices that are monitored and whose site is not AWAY.
    pub fn monitored_names(&self) -> Vec<String> {
        self.devices
            .values()
            .filter(|d| d.monitoring() && self.site_engaged(&d.site))
            .map(|d| d.id.clone())
            .collect()
    }

    /// LabLink works with the devices of this site now (ACTIVE, or not yet
    /// confirmed); AWAY sites are left alone.
    pub fn site_engaged(&self, site: &str) -> bool {
        self.site_state(site) != SiteState::Away
    }

    pub fn site_state(&self, site: &str) -> SiteState {
        self.decisions
            .get(site)
            .map(|d| d.state)
            .unwrap_or(SiteState::Unknown)
    }

    /// The device should be probed now.
    pub fn engaged(&self, id: &str) -> bool {
        self.devices
            .get(id)
            .is_some_and(|d| d.monitoring() && self.site_engaged(&d.site))
    }

    /// Ids of the sites that are not AWAY.
    pub fn engaged_sites(&self) -> Vec<String> {
        self.cfg
            .sites
            .iter()
            .filter(|s| self.site_engaged(&s.id))
            .map(|s| s.id.clone())
            .collect()
    }

    /// The configured network containing `ip`, preferring `site`'s own.
    fn network_name_for(&self, site: Option<&str>, ip: IpAddr) -> Option<String> {
        let pref: Vec<String> = match site {
            Some(s) => vec![s.to_string()],
            None => self.engaged_sites(),
        };
        self.allowlist
            .network_for_sites(ip, &pref)
            .map(|n| n.name.clone())
    }

    /// Identities to match sightings against: devices of engaged sites only,
    /// so an address reused at another site is never attributed to an AWAY
    /// site's device.
    fn known_identities(&self) -> Vec<KnownIdentity> {
        self.devices
            .values()
            .filter(|d| self.site_engaged(&d.site))
            .map(Device::known_identity)
            .collect()
    }

    pub fn neighbor_mac(&self, ip: IpAddr) -> Option<String> {
        self.neighbors.get(&ip).map(|(m, _)| m.clone())
    }

    fn ifname(&self, ip: IpAddr) -> Option<String> {
        let s = self.snapshot.as_ref()?;
        if let Some((_, idx)) = self.neighbors.get(&ip) {
            if let Some(n) = s.ifname(*idx) {
                return Some(n.to_string());
            }
        }
        s.interface_for(ip).map(|i| i.name.clone())
    }

    /// True if `ip` is one of this host's own interface addresses.
    pub fn is_local_address(&self, ip: IpAddr) -> bool {
        self.snapshot.as_ref().is_some_and(|s| {
            s.interfaces
                .iter()
                .any(|i| i.addrs.iter().any(|a| a.addr() == ip))
        })
    }

    pub fn local_prefixes(&self) -> Vec<ipnet::IpNet> {
        self.snapshot
            .as_ref()
            .map(Snapshot::local_prefixes)
            .unwrap_or_default()
    }

    // ------------------------------------------------------------- events --

    /// Record a history event (state transitions only, never heartbeats).
    pub fn event(&mut self, device: Option<&str>, kind: &str, message: String) {
        tracing::info!(device = device.unwrap_or("-"), kind, "{message}");
        let ev = HistoryEvent {
            ts_ms: lablink_core::time::now_ms(),
            device: device.map(str::to_string),
            kind: kind.into(),
            message,
        };
        self.ring.push_back(ev.clone());
        while self.ring.len() > EVENT_RING {
            self.ring.pop_front();
        }
        self.pending.push(ev);
    }

    fn mark(&mut self, name: &str) {
        self.dirty_devices.insert(name.to_string());
    }

    // ------------------------------------------------------- snapshot/ARP --

    /// Install a fresh interface/neighbor snapshot. Returns observations for
    /// valid neighbor entries (to be fed to [`Registry::observe`]).
    pub fn set_snapshot(&mut self, s: Snapshot) -> Vec<(Observation, String)> {
        self.neighbors.clear();
        let mut obs = Vec::new();
        for n in &s.neighbors {
            if let Some(o) = self.neighbor_observation(n) {
                obs.push((o, "neighbor".to_string()));
            }
        }
        self.snapshot = Some(s);
        self.sites_stale = true;
        obs
    }

    /// Track one neighbor entry; returns an observation if it is worth matching.
    pub fn neighbor_observation(&mut self, n: &Neighbor) -> Option<Observation> {
        if !n.state.has_valid_lladdr() {
            if self.neighbors.remove(&n.ip).is_some() {
                self.sites_stale = true;
            }
            return None;
        }
        let mac = n.mac.as_deref().and_then(normalize_mac)?;
        if self
            .neighbors
            .insert(n.ip, (mac.clone(), n.ifindex))
            .map(|x| x.0)
            != Some(mac.clone())
        {
            self.sites_stale = true;
        }
        Some(Observation {
            ip: Some(n.ip),
            mac: Some(mac),
            names: vec![],
            host_keys: vec![],
        })
    }

    /// Healthy devices at `ip` (used to react to ARP failures without creating
    /// a probe feedback loop for devices that are already offline).
    pub fn healthy_devices_at(&self, ip: IpAddr) -> Vec<String> {
        self.devices
            .values()
            .filter(|d| d.rec.current_ip == Some(ip) && d.healthy())
            .map(|d| d.id.clone())
            .collect()
    }

    /// Devices currently claiming `ip`.
    pub fn devices_at(&self, ip: IpAddr) -> Vec<String> {
        self.devices
            .values()
            .filter(|d| d.rec.current_ip == Some(ip) && self.site_engaged(&d.site))
            .map(|d| d.id.clone())
            .collect()
    }

    // ------------------------------------------------------------ planning --

    pub fn plan(&self, name: &str, now: u64) -> Option<CheckPlan> {
        let d = self.devices.get(name)?;
        if !d.monitoring() || !self.site_engaged(&d.site) {
            return None;
        }
        let mut candidates: Vec<IpAddr> = Vec::new();
        let mut push = |ip: IpAddr| {
            if !candidates.contains(&ip) {
                candidates.push(ip);
            }
        };
        if let Some(ip) = d.rec.current_ip {
            push(ip);
        }
        for ip in d.cfg.expected_ip_addrs() {
            push(ip);
        }
        let mut recent: Vec<&AddressRecord> = d.rec.addresses.iter().collect();
        recent.sort_by_key(|a| std::cmp::Reverse(a.last_seen_ms));
        for a in recent.into_iter().take(4) {
            push(a.ip);
        }
        let resolve_due =
            now.saturating_sub(d.last_resolve_ms) >= self.cfg.daemon.resolve_interval_s * 1000;
        let hostnames_to_resolve =
            if (!d.healthy() && resolve_due) || (candidates.is_empty() && d.last_resolve_ms == 0) {
                d.cfg.hostnames.clone()
            } else {
                Vec::new()
            };
        let port_check_due = d.cfg.ssh
            && (d.port.state == PortState::Unknown
                || d.net.state != NetworkState::Online
                || now.saturating_sub(d.last_port_check_ms)
                    >= self.cfg.daemon.port_check_interval_s * 1000);
        let icmp_usable = self.cfg.daemon.icmp && d.icmp_misses_while_up < 3;
        // Behind a gateway and not directly attached: only the expected
        // addresses, checked from the gateway, never probed from here.
        let via = self.route_via(d);
        let (candidates, hostnames_to_resolve) = if via.is_some() {
            (d.cfg.expected_ip_addrs(), Vec::new())
        } else {
            (candidates, hostnames_to_resolve)
        };
        Some(CheckPlan {
            name: name.to_string(),
            via,
            candidates,
            hostnames_to_resolve,
            ssh: d.cfg.ssh,
            port: d.cfg.ssh_port,
            port_check_due,
            icmp_usable,
        })
    }

    pub fn note_resolved(&mut self, name: &str, now: u64) {
        if let Some(d) = self.devices.get_mut(name) {
            d.last_resolve_ms = now;
        }
    }

    /// Seconds until this device's next scheduled check.
    pub fn next_interval_s(&self, name: &str) -> u64 {
        let mut base = self.cfg.daemon.check_interval_s;
        match self.devices.get(name) {
            Some(d) if self.route_via(d).is_some() => {
                base = base.max(self.cfg.daemon.via_check_interval_s);
                lablink_core::health::next_interval_s(
                    d.net.state,
                    d.net.consecutive_failures,
                    base,
                    self.cfg.daemon.offline_backoff_max_s.max(base),
                )
            }
            Some(d) => lablink_core::health::next_interval_s(
                d.net.state,
                d.net.consecutive_failures,
                base,
                self.cfg.daemon.offline_backoff_max_s,
            ),
            None => base,
        }
    }

    // -------------------------------------------------------- probe result --

    /// Apply a liveness/port probe result for `name`.
    pub fn apply_probe(&mut self, name: &str, r: &ProbeReport, now: u64) {
        let th = self.th;
        let site = self.devices.get(name).map(|d| d.site.clone());
        let network_name = self.network_name_for(site.as_deref(), r.ip);
        let iface = self.ifname(r.ip);
        let mac = self.neighbor_mac(r.ip);
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        let mut events: Vec<(&str, String)> = Vec::new();
        d.last_check_ms = now;
        let how = match (&d.cfg.via, r.method) {
            (Some(gw), "via-gateway") => format!("through {gw}"),
            _ => r.method.to_string(),
        };

        if d.rec.current_ip.is_none() {
            if !r.up {
                // Never located: just count failures (no events).
                d.net.observe(false, &th);
                return;
            }
            d.rec.current_ip = Some(r.ip);
            events.push(("located", format!("located at {} ({how})", r.ip)));
            self.urgent = true;
        } else if d.rec.current_ip != Some(r.ip) {
            return; // stale result for an address we already moved away from
        }

        match r.icmp_answered {
            Some(true) => {
                d.icmp_answered = true;
                d.icmp_misses_while_up = 0;
            }
            Some(false) if r.up && !d.icmp_answered => {
                d.icmp_misses_while_up = d.icmp_misses_while_up.saturating_add(1)
            }
            _ => {}
        }

        let prev_net = d.net.state;
        if let Some(t) = d.net.observe(r.up, &th) {
            let msg = match (t.from, t.to) {
                (NetworkState::Unknown, NetworkState::Online) => format!(
                    "online at {} ({how}, {} ms)",
                    r.ip,
                    r.rtt.map(ms).unwrap_or(0)
                ),
                (NetworkState::Offline, NetworkState::Online) => {
                    format!("recovered at {} after confirmed checks", r.ip)
                }
                (NetworkState::Degraded, NetworkState::Online) => {
                    format!("reachability recovered at {}", r.ip)
                }
                (_, NetworkState::Degraded) => format!(
                    "reachability degraded: {} consecutive failed checks ({})",
                    d.net.consecutive_failures,
                    r.detail.clone().unwrap_or_else(|| "no answer".into())
                ),
                (_, NetworkState::Offline) => format!(
                    "offline: {} consecutive failed checks at {} ({})",
                    d.net.consecutive_failures,
                    r.ip,
                    r.detail.clone().unwrap_or_else(|| "no answer".into())
                ),
                (a, b) => format!("network {a:?} -> {b:?}"),
            };
            let kind = match t.to {
                NetworkState::Online => "network_online",
                NetworkState::Degraded => "network_degraded",
                NetworkState::Offline => "network_offline",
                NetworkState::Unknown => "network_unknown",
            };
            events.push((kind, msg));
        }
        if r.up {
            if d.identity != IdentityState::Mismatch && d.auth != AuthState::Failed {
                d.last_error = None; // recovered: do not show a stale error
            }
            d.rec.first_seen_ms.get_or_insert(now);
            d.rec.last_seen_ms = Some(now);
            d.latency_ms = r.rtt.map(ms);
            touch_address(&mut d.rec, r.ip, "probe", mac, network_name, iface, now);
            if now.saturating_sub(d.persisted_last_seen_ms) >= LAST_SEEN_PERSIST_MS {
                d.persisted_last_seen_ms = now;
                self.dirty_devices.insert(name.to_string());
            }
        } else {
            d.last_error = r.detail.clone();
        }
        if let Some(p) = r.port {
            d.last_port_check_ms = now;
            if let Some(t) = d.port.observe(p, &th) {
                let port = d.cfg.ssh_port;
                let msg = match t.to {
                    PortState::Open => format!("TCP/{port} became reachable"),
                    PortState::Closed => format!("TCP/{port} closed (connection refused)"),
                    PortState::Filtered => format!("TCP/{port} not answering"),
                    s => format!("TCP/{port} {s:?}"),
                };
                if t.to == PortState::Open {
                    d.port_opened = true;
                    d.auth_recheck = true;
                }
                // Port noise while the host itself is down adds nothing.
                if r.up || t.to == PortState::Open {
                    events.push(("ssh_port", msg));
                }
            }
        }
        if d.net.state == NetworkState::Offline && prev_net != NetworkState::Offline {
            d.auth = AuthState::Unknown;
        }
        let changed = !events.is_empty();
        for (k, m) in events {
            self.event(Some(name), k, m);
        }
        if changed {
            self.mark(name);
            self.sites_stale = true;
        }
    }

    /// SSH work due now: host-key verification and/or a login check.
    pub fn follow_up(&mut self, name: &str, now: u64) -> FollowUp {
        let mut f = FollowUp::default();
        let id_interval = self.cfg.daemon.identity_check_interval_s * 1000;
        let auth_interval = self.cfg.daemon.auth_check_interval_s * 1000;
        let Some(d) = self.devices.get(name) else {
            return f;
        };
        let Some(ip) = d.rec.current_ip else { return f };
        if !d.cfg.ssh || d.port.state != PortState::Open || !d.healthy() {
            return f;
        }
        let id_due = d.identity == IdentityState::Unknown
            || d.key_proof_due.is_some()
            || d.identity_recheck
            || d.identity_ip != Some(ip)
            || d.port_opened
            || now.saturating_sub(d.last_identity_check_ms) >= id_interval;
        if id_due {
            f.keyscan = Some((ip, d.cfg.ssh_port));
            return f; // auth runs after identity is (re)established
        }
        let auth_due = d.cfg.auth_check
            && d.identity == IdentityState::Verified
            && (matches!(d.auth, AuthState::Unknown | AuthState::Unavailable)
                || d.auth_ip != Some(ip)
                || d.auth_recheck
                || (auth_interval > 0
                    && now.saturating_sub(d.last_auth_check_ms) >= auth_interval));
        if auth_due {
            let users = d.auth_usernames();
            for u in users {
                if let Ok(t) = self.target_for(name, u) {
                    f.auth.push(t);
                }
            }
        }
        f
    }

    // ------------------------------------------------------------ identity --

    fn set_identity(
        &mut self,
        name: &str,
        new: IdentityState,
        signal: Option<Signal>,
        ip: IpAddr,
        detail: String,
    ) {
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        let old = d.identity;
        d.identity = new;
        d.identity_signal = signal;
        d.identity_ip = Some(ip);
        if new == IdentityState::Mismatch {
            d.last_error = Some(detail.clone());
            d.auth = AuthState::Unavailable;
        }
        if old != new {
            self.sites_stale = true;
            let kind = match new {
                IdentityState::Verified => "identity_verified",
                IdentityState::Unverified => "identity_unverified",
                IdentityState::Mismatch => "identity_mismatch",
                IdentityState::Unknown => "identity_unknown",
            };
            if new == IdentityState::Mismatch {
                tracing::warn!(device = name, %ip, "{detail}");
            }
            self.event(Some(name), kind, detail);
            self.mark(name);
            self.urgent = true;
        }
    }

    fn fill_pin_blobs(&mut self, name: &str, keys: &[HostKey], now: u64) {
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        let mut changed = false;
        for k in keys {
            if let Some(p) = d
                .rec
                .pinned
                .iter_mut()
                .find(|p| p.fingerprint == k.fingerprint)
            {
                if p.public_key.is_none() && k.public_key.is_some() {
                    p.public_key = k.public_key.clone();
                    changed = true;
                }
            } else if d.cfg.host_key_fingerprints.contains(&k.fingerprint) {
                d.rec.pinned.push(PinnedKey {
                    key_type: k.key_type.clone(),
                    fingerprint: k.fingerprint.clone(),
                    public_key: k.public_key.clone(),
                    source: "config".into(),
                    pinned_at_ms: now,
                });
                changed = true;
            }
        }
        if changed {
            self.known_hosts_dirty = true;
            self.mark(name);
        }
    }

    fn learn_mac(&mut self, name: &str, mac: &str) {
        let configured = self
            .devices
            .get(name)
            .is_some_and(|d| d.cfg.normalized_macs().iter().any(|m| m == mac));
        if configured {
            return;
        }
        // A MAC belongs to one device: move it if a USB NIC changed hosts.
        let others: Vec<String> = self
            .devices
            .values()
            .filter(|d| d.id != name && d.rec.learned_macs.contains(mac))
            .map(|d| d.id.clone())
            .collect();
        for o in others {
            self.devices
                .get_mut(&o)
                .unwrap()
                .rec
                .learned_macs
                .remove(mac);
            self.mark(&o);
        }
        let d = self.devices.get_mut(name).unwrap();
        if d.rec.learned_macs.insert(mac.to_string()) {
            self.event(Some(name), "mac_learned", format!("learned MAC {mac}"));
            self.mark(name);
        }
    }

    /// Clear `name`'s current address because another host now has it.
    fn release_ip(&mut self, name: &str, why: String) -> bool {
        let Some(d) = self.devices.get_mut(name) else {
            return false;
        };
        if d.rec.current_ip.is_none() {
            return false;
        }
        d.rec.current_ip = None;
        d.net.reset();
        // A MISMATCH stays visible until a pinned key is verified again or the
        // user runs `lablink trust --replace`; losing the address must not
        // clear it (reset_runtime_for_new_ip keeps it too).
        d.reset_runtime_for_new_ip();
        self.event(Some(name), "ip_released", why);
        self.mark(name);
        self.urgent = true;
        true
    }

    /// Apply a host-key scan of `name`'s current address.
    /// Returns devices whose monitors should run now.
    pub fn apply_keys(
        &mut self,
        name: &str,
        ip: IpAddr,
        scanned: Result<Vec<HostKey>, String>,
        user_known: &UserKnown,
        now: u64,
    ) -> Vec<String> {
        let mut wake = Vec::new();
        let Some(d) = self.devices.get_mut(name) else {
            return wake;
        };
        d.last_identity_check_ms = now;
        d.port_opened = false;
        d.identity_recheck = false;
        if d.rec.current_ip != Some(ip) {
            return wake;
        }
        let proven_here = d.identity == IdentityState::Verified
            && d.identity_ip == Some(ip)
            && d.key_proof_due.is_none();
        let keys = match scanned {
            Ok(k) => k,
            Err(e) => {
                d.last_error = Some(format!("host key scan failed: {e}"));
                tracing::debug!(device = name, %ip, error = %e, "host key scan failed");
                return wake;
            }
        };
        d.observed_keys = keys.clone();
        let names = d.attributed_names.clone();
        let obs = Observation {
            ip: Some(ip),
            mac: self.neighbor_mac(ip),
            names,
            host_keys: keys.clone(),
        };
        let outcome = classify(&obs, &self.known_identities());
        tracing::debug!(device = name, %ip, ?outcome, "identity classification");
        let fps = || {
            keys.iter()
                .map(|k| k.fingerprint.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match outcome {
            MatchOutcome::Matched {
                device,
                verified: true,
                ..
            } if device == name => {
                self.fill_pin_blobs(name, &keys, now);
                if !proven_here {
                    // Matching a pin is not enough at a new address: the
                    // monitor asks the host to prove it holds the key.
                    self.devices.get_mut(name).unwrap().key_proof_due = Some(ip);
                    return wake;
                }
                if let Some(mac) = obs.mac.as_deref() {
                    self.learn_mac(name, mac);
                }
                let fp = keys.iter().find(|k| {
                    self.devices[name]
                        .pinned_fingerprints()
                        .contains(&k.fingerprint)
                });
                let detail = format!(
                    "SSH fingerprint verified at {ip} ({})",
                    fp.map(|k| k.fingerprint.as_str()).unwrap_or("?")
                );
                self.set_identity(
                    name,
                    IdentityState::Verified,
                    Some(Signal::Fingerprint),
                    ip,
                    detail,
                );
            }
            MatchOutcome::Matched {
                device: other,
                verified: true,
                ..
            } => {
                // The host at this address is a different known device.
                self.release_ip(
                    name,
                    format!("{ip} now answers with the host key of '{other}'"),
                );
                wake.extend(self.observe(&obs, "keyscan", Some(&other), now));
                wake.push(name.to_string());
            }
            MatchOutcome::Mismatch { device, signal } if device == name => {
                let pins: Vec<String> = self.devices[name]
                    .pinned_fingerprints()
                    .into_iter()
                    .collect();
                let detail = format!(
                    "SECURITY: SSH host key mismatch at {ip} (matched by {}): presented [{}], pinned [{}]. Not accepted automatically; verify the machine, then run `lablink trust {name} --replace`",
                    signal.as_str(),
                    fps(),
                    pins.join(", ")
                );
                self.set_identity(name, IdentityState::Mismatch, Some(signal), ip, detail);
            }
            MatchOutcome::IpReused { previous_owner } if previous_owner == name => {
                self.release_ip(
                    name,
                    format!(
                        "{ip} was reassigned: it now answers with an unknown host key [{}]",
                        fps()
                    ),
                );
                self.upsert_discovered(
                    &obs,
                    "keyscan",
                    Some(format!("previously used by {name}")),
                    now,
                );
                wake.push(name.to_string());
            }
            MatchOutcome::Matched {
                device,
                verified: false,
                signal,
            } if device == name => {
                self.trust_from_user_known_hosts(name, ip, &keys, user_known, Some(signal), now);
            }
            MatchOutcome::Provisional { device } if device == name => {
                self.trust_from_user_known_hosts(
                    name,
                    ip,
                    &keys,
                    user_known,
                    Some(Signal::HistoricalIp),
                    now,
                );
            }
            other => {
                let detail = format!("identity at {ip} is ambiguous: {other:?}");
                self.devices.get_mut(name).unwrap().last_error = Some(detail.clone());
                self.set_identity(name, IdentityState::Unverified, None, ip, detail);
            }
        }
        wake
    }

    fn trust_from_user_known_hosts(
        &mut self,
        name: &str,
        ip: IpAddr,
        keys: &[HostKey],
        user_known: &UserKnown,
        signal: Option<Signal>,
        now: u64,
    ) {
        // Entries keyed by the device's configured names always count. Entries
        // keyed by the bare IP count only when the user tied this address to
        // the device: a configured static IP, or adopting the device at this
        // address (recently). MAC and mDNS/DNS answers do not count: anyone on
        // the network can forge them and point the device at a host whose key
        // the user once accepted for an unrelated reason.
        let d = &self.devices[name];
        let recently_adopted = d
            .rec
            .addresses
            .iter()
            .find(|a| a.ip == ip)
            .is_some_and(|a| {
                a.last_adopted_ms > 0
                    && now.saturating_sub(a.last_adopted_ms) <= NAME_EVIDENCE_TTL_MS
            });
        let ip_evidence = d.cfg.expected_ip_addrs().contains(&ip) || recently_adopted;
        let trusted: Vec<&HostKey> = keys
            .iter()
            .filter(|k| {
                user_known
                    .by_name
                    .iter()
                    .any(|u| u.fingerprint == k.fingerprint)
                    || (ip_evidence
                        && user_known
                            .by_ip
                            .iter()
                            .any(|u| u.fingerprint == k.fingerprint))
            })
            .collect();
        if trusted.is_empty() {
            let detail = format!(
                "host key at {ip} is not pinned and not in ~/.ssh/known_hosts ({}); run `lablink trust {name}` after verifying it",
                keys.first().map(|k| k.fingerprint.as_str()).unwrap_or("?")
            );
            self.set_identity(name, IdentityState::Unverified, signal, ip, detail);
            return;
        }
        let d = self.devices.get_mut(name).unwrap();
        for k in &trusted {
            if !d.rec.pinned.iter().any(|p| p.fingerprint == k.fingerprint) {
                d.rec.pinned.push(PinnedKey {
                    key_type: k.key_type.clone(),
                    fingerprint: k.fingerprint.clone(),
                    public_key: k.public_key.clone(),
                    source: "user_known_hosts".into(),
                    pinned_at_ms: now,
                });
            }
        }
        self.known_hosts_dirty = true;
        let fp = trusted[0].fingerprint.clone();
        self.event(
            Some(name),
            "key_pinned",
            format!("pinned host key {fp} (already trusted in ~/.ssh/known_hosts)"),
        );
        self.devices.get_mut(name).unwrap().key_proof_due = Some(ip);
        self.mark(name);
        self.urgent = true;
    }

    /// The target for a pending host-key possession proof (same addressing
    /// and pinned options as `lablink ssh`, through a gateway if any).
    pub fn key_proof_target(&self, name: &str) -> Option<(IpAddr, Target)> {
        let d = self.devices.get(name)?;
        let ip = d.key_proof_due.filter(|ip| d.rec.current_ip == Some(*ip))?;
        let t = self.target_for(name, d.username()).ok()?;
        t.host_key_alias.is_some().then_some((ip, t))
    }

    /// Apply a host-key possession proof (see [`Device::key_proof_due`]).
    pub fn apply_key_proof(&mut self, name: &str, ip: IpAddr, proof: &KeyProof, now: u64) {
        let mac = self.neighbor_mac(ip);
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        if d.key_proof_due != Some(ip) || d.rec.current_ip != Some(ip) {
            return;
        }
        d.key_proof_due = None;
        d.last_identity_check_ms = now;
        let pins = d
            .pinned_fingerprints()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        match proof {
            KeyProof::Proven => {
                if let Some(mac) = mac.as_deref() {
                    self.learn_mac(name, mac);
                }
                self.set_identity(
                    name,
                    IdentityState::Verified,
                    Some(Signal::Fingerprint),
                    ip,
                    format!("SSH fingerprint verified at {ip} ({pins}); the host proved it holds the key"),
                );
            }
            KeyProof::Refused(why) => {
                let detail = format!(
                    "SECURITY: {ip} showed the pinned host key of '{name}' to a scan, but in the possession proof {why}: another machine may be replaying the key. Not accepted; check the device, then `lablink status {name}`"
                );
                self.set_identity(
                    name,
                    IdentityState::Mismatch,
                    Some(Signal::Fingerprint),
                    ip,
                    detail,
                );
            }
            KeyProof::Inconclusive(why) => {
                let detail = format!(
                    "host key at {ip} matches the pin, but the host has not proved it holds the key yet ({why}); retrying at the next identity check"
                );
                self.devices.get_mut(name).unwrap().last_error = Some(detail.clone());
                self.set_identity(
                    name,
                    IdentityState::Unverified,
                    Some(Signal::Fingerprint),
                    ip,
                    detail,
                );
            }
        }
    }

    /// Apply a login check result.
    pub fn apply_auth(
        &mut self,
        name: &str,
        ip: IpAddr,
        username: Option<&str>,
        outcome: &AuthOutcome,
        now: u64,
    ) {
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        d.last_auth_check_ms = now;
        d.auth_ip = Some(ip);
        d.port_opened = false;
        d.auth_recheck = false;
        let old = d.auth;
        let who = username.unwrap_or("(ssh config default)");
        let (new, msg) = match outcome {
            AuthOutcome::Ok { hostname } => {
                if let Some(u) = username {
                    d.rec.active_username = Some(u.to_string());
                }
                if let Some(h) = hostname {
                    let n = normalize_hostname(h);
                    if lablink_core::config::valid_hostname(&n) && d.rec.learned_hostnames.insert(n)
                    {
                        self.dirty_devices.insert(name.to_string());
                    }
                }
                (AuthState::Ok, format!("SSH authenticated as {who}"))
            }
            AuthOutcome::Rejected { detail, .. } => (
                AuthState::Failed,
                format!("SSH login as {who} failed: {detail}"),
            ),
            AuthOutcome::Error(e) => (
                AuthState::Unavailable,
                format!("SSH login check failed: {e}"),
            ),
            AuthOutcome::HostKeyChanged => (
                AuthState::Unavailable,
                "SSH login refused: the server presented a host key that does not match the pin; re-verifying its identity now".to_string(),
            ),
        };
        let d = self.devices.get_mut(name).unwrap();
        if matches!(outcome, AuthOutcome::HostKeyChanged) {
            // Do not wait for the periodic identity check: the next round
            // scans the host key and reports a MISMATCH if it changed.
            d.identity_recheck = true;
        }
        d.auth = new;
        if new != AuthState::Ok {
            d.last_error = Some(msg.clone());
        } else if d.identity != IdentityState::Mismatch {
            // A working login supersedes any earlier login failure text.
            d.last_error = None;
        }
        if old != new {
            let kind = if new == AuthState::Ok {
                "auth_ok"
            } else {
                "auth_failed"
            };
            self.event(Some(name), kind, msg);
            self.mark(name);
        }
    }

    // ----------------------------------------------------- passive sightings --

    /// Classify and apply one sighting. `allow_switch` names a device whose
    /// current address is known to be failing right now (monitor failover), so
    /// a matching sighting may move it even before hysteresis marks it offline.
    pub fn observe(
        &mut self,
        obs: &Observation,
        source: &str,
        allow_switch: Option<&str>,
        now: u64,
    ) -> Vec<String> {
        let mut wake = Vec::new();
        let Some(ip) = obs.ip else { return wake };
        if !usable_address(ip) || self.is_local_address(ip) {
            return wake; // link-local v6 needs a scope id; our own addresses are not peers
        }
        // An mDNS/DNS answer (anyone on the network can send one) must not
        // point LabLink's probes at the Internet: a public address is
        // followed only when it is inside a configured network or attached.
        if matches!(source, "mdns" | "dns")
            && !private_address(ip)
            && self.allowlist.network_for(ip).is_none()
            && !self.is_attached_ip(ip)
        {
            tracing::debug!(%ip, source, "ignoring a name answer pointing outside the lab networks");
            return wake;
        }
        // Same address, different link-layer address: possibly a different
        // machine now answers there. Re-verify the host key before trusting it.
        if let Some(mac) = &obs.mac {
            let changed: Vec<String> = self
                .devices
                .values()
                .filter(|d| {
                    d.rec.current_ip == Some(ip)
                        && !d.identity_recheck
                        && self.site_engaged(&d.site)
                })
                .filter(|d| {
                    let known: BTreeSet<String> = d
                        .cfg
                        .normalized_macs()
                        .into_iter()
                        .chain(d.rec.learned_macs.iter().cloned())
                        .collect();
                    !known.is_empty() && !known.contains(mac)
                })
                .map(|d| d.id.clone())
                .collect();
            for n in changed {
                self.devices.get_mut(&n).unwrap().identity_recheck = true;
                self.event(
                    Some(&n),
                    "mac_changed",
                    format!(
                        "{ip} now answers with link-layer address {mac}; re-verifying identity"
                    ),
                );
                wake.push(n);
            }
        }
        self.note_key_sightings(obs, now);
        let outcome = classify(obs, &self.known_identities());
        match outcome {
            MatchOutcome::Matched {
                device,
                signal,
                verified,
            } => {
                self.attach(
                    &device,
                    ip,
                    obs,
                    source,
                    signal,
                    verified,
                    allow_switch == Some(device.as_str()),
                    now,
                    &mut wake,
                );
                if self.discovered.remove(&ip).is_some() {
                    self.removed_discovered.insert(ip);
                }
            }
            MatchOutcome::Provisional { device } => {
                let d = &self.devices[&device];
                let is_current = d.rec.current_ip == Some(ip);
                // Same host as before unless the link-layer address changed.
                let recorded_mac = d
                    .rec
                    .addresses
                    .iter()
                    .find(|a| a.ip == ip)
                    .and_then(|a| a.mac.clone());
                let mac_changed = matches!((&recorded_mac, &obs.mac), (Some(a), Some(b)) if a != b);
                if is_current || allow_switch == Some(device.as_str()) {
                    self.attach(
                        &device,
                        ip,
                        obs,
                        source,
                        Signal::HistoricalIp,
                        false,
                        allow_switch == Some(device.as_str()),
                        now,
                        &mut wake,
                    );
                } else if !mac_changed {
                    let site = self.devices[&device].site.clone();
                    let network_name = self.network_name_for(Some(&site), ip);
                    let iface = self.ifname(ip);
                    let d = self.devices.get_mut(&device).unwrap();
                    touch_address(
                        &mut d.rec,
                        ip,
                        source,
                        obs.mac.clone(),
                        network_name,
                        iface,
                        now,
                    );
                    if self.discovered.remove(&ip).is_some() {
                        self.removed_discovered.insert(ip);
                    }
                } else {
                    self.upsert_discovered(
                        obs,
                        source,
                        Some(format!(
                            "previously used by {device} (link-layer address changed)"
                        )),
                        now,
                    );
                }
            }
            MatchOutcome::Mismatch { device, signal } => {
                let pins: Vec<String> = self.devices[&device]
                    .pinned_fingerprints()
                    .into_iter()
                    .collect();
                let presented: Vec<&str> = obs
                    .host_keys
                    .iter()
                    .map(|k| k.fingerprint.as_str())
                    .collect();
                let detail = format!(
                    "SECURITY: host at {ip} matches '{device}' by {} but presented host key [{}], pinned [{}]",
                    signal.as_str(),
                    presented.join(", "),
                    pins.join(", ")
                );
                self.set_identity(&device, IdentityState::Mismatch, Some(signal), ip, detail);
                self.upsert_discovered(
                    obs,
                    source,
                    Some(format!("host key mismatch for {device}")),
                    now,
                );
            }
            MatchOutcome::IpReused { previous_owner } => {
                if self.devices[&previous_owner].rec.current_ip == Some(ip) {
                    self.release_ip(
                        &previous_owner,
                        format!("{ip} was reassigned to a host with a different key"),
                    );
                    wake.push(previous_owner.clone());
                }
                self.upsert_discovered(
                    obs,
                    source,
                    Some(format!("previously used by {previous_owner}")),
                    now,
                );
            }
            MatchOutcome::Ambiguous { candidates, reason } => {
                let note = (ip, reason.clone());
                if !self.noted_ambiguity.contains(&note)
                    && self.noted_ambiguity.len() >= MAX_AMBIGUITY_NOTES
                {
                    self.noted_ambiguity.clear();
                }
                if self.noted_ambiguity.insert(note) {
                    self.event(
                        None,
                        "ambiguous",
                        format!(
                            "{ip}: cannot attribute to one device ({}): {reason}",
                            candidates.join(", ")
                        ),
                    );
                }
                self.upsert_discovered(obs, source, Some(format!("ambiguous: {reason}")), now);
            }
            MatchOutcome::Unknown => {
                if self.allowlist.contains(ip)
                    || self.cfg.daemon.passive_unlisted
                    || matches!(source, "scan" | "keyscan")
                {
                    self.upsert_discovered(obs, source, None, now);
                }
            }
        }
        wake
    }

    #[allow(clippy::too_many_arguments)]
    fn attach(
        &mut self,
        name: &str,
        ip: IpAddr,
        obs: &Observation,
        source: &str,
        signal: Signal,
        verified: bool,
        allow_switch: bool,
        now: u64,
        wake: &mut Vec<String>,
    ) {
        let site = self.devices.get(name).map(|d| d.site.clone());
        let network_name = self.network_name_for(site.as_deref(), ip);
        let iface = self.ifname(ip);
        if verified {
            self.fill_pin_blobs(name, &obs.host_keys, now);
        }
        let d = self.devices.get_mut(name).unwrap();
        let is_current = d.rec.current_ip == Some(ip);
        let new_address = !d.rec.addresses.iter().any(|a| a.ip == ip);
        touch_address(
            &mut d.rec,
            ip,
            source,
            obs.mac.clone(),
            network_name,
            iface,
            now,
        );
        if verified && source == "mdns" {
            for n in &obs.names {
                d.rec.mdns_names.insert(normalize_hostname(n));
            }
        }
        if is_current {
            // A sighting with the pinned key re-checks the identity (with a
            // possession proof); it never sets Verified by itself.
            if verified && !(d.identity == IdentityState::Verified && d.identity_ip == Some(ip)) {
                d.identity_recheck = true;
                wake.push(name.to_string());
            }
            return;
        }
        // Keep a healthy current address (multi-homed devices). Move when the
        // caller saw it fail, or when a strong sighting arrives while the
        // current address has started failing. A pinned device verified at
        // its current address is never moved by an unverified name or MAC
        // sighting (both are forgeable) on a single missed probe, and a
        // key-verified sighting always replaces an address whose identity is
        // not verified (e.g. a stranger answering ping at an old address).
        let strong = verified || matches!(signal, Signal::Mac | Signal::Hostname);
        let current_failing = d.net.consecutive_failures > 0;
        let current_verified =
            d.identity == IdentityState::Verified && d.identity_ip == d.rec.current_ip;
        let pinned_and_verified = current_verified && !d.pinned_fingerprints().is_empty();
        let strong_move = strong && current_failing && (verified || !pinned_and_verified);
        let displaces_unverified = verified && !current_verified;
        if d.healthy() && !allow_switch && !strong_move && !displaces_unverified {
            if new_address {
                let cur = d.rec.current_ip.map(|c| c.to_string()).unwrap_or_default();
                self.event(Some(name), "address_seen", format!("also seen at {ip} via {source} (matched by {}); keeping {cur} while it is healthy", signal.as_str()));
                self.mark(name);
            }
            return;
        }
        let old = d.rec.current_ip.replace(ip);
        d.reset_runtime_for_new_ip();
        if signal == Signal::Hostname {
            d.attributed_names = obs.names.clone();
        }
        let msg = match old {
            Some(o) => format!(
                "IP changed {o} -> {ip} (matched by {} via {source})",
                signal.as_str()
            ),
            None => format!(
                "located at {ip} (matched by {} via {source})",
                signal.as_str()
            ),
        };
        self.event(
            Some(name),
            if old.is_some() {
                "ip_changed"
            } else {
                "located"
            },
            msg,
        );
        self.mark(name);
        self.urgent = true;
        wake.push(name.to_string());
        // Nobody else at this site may keep claiming this address.
        let d_site = self.devices[name].site.clone();
        let others: Vec<String> = self
            .devices
            .values()
            .filter(|o| o.id != name && o.rec.current_ip == Some(ip) && o.site == d_site)
            .map(|o| o.id.clone())
            .collect();
        for o in others {
            self.release_ip(&o, format!("{ip} now belongs to '{name}'"));
            wake.push(o);
        }
    }

    fn upsert_discovered(
        &mut self,
        obs: &Observation,
        source: &str,
        note: Option<String>,
        now: u64,
    ) {
        let Some(ip) = obs.ip else { return };
        let is_new = !self.discovered.contains_key(&ip);
        if is_new && self.discovered.len() >= MAX_DISCOVERED {
            if let Some(oldest) = self
                .discovered
                .values()
                .min_by_key(|r| r.last_seen_ms)
                .map(|r| r.ip)
            {
                self.discovered.remove(&oldest);
                self.removed_discovered.insert(oldest);
            }
        }
        let r = self
            .discovered
            .entry(ip)
            .or_insert_with(|| DiscoveredRecord {
                ip,
                mac: None,
                hostname: None,
                sources: BTreeSet::new(),
                ssh_port: PortState::Unknown,
                keys: vec![],
                note: None,
                first_seen_ms: now,
                last_seen_ms: now,
                last_tcp_ms: 0,
                last_keyscan_ms: 0,
            });
        let before = r.clone();
        r.last_seen_ms = now;
        r.sources.insert(source.to_string());
        if obs.mac.is_some() {
            r.mac = obs.mac.clone();
        }
        if let Some(n) = obs.names.first() {
            let n = n.trim_end_matches('.');
            if lablink_core::config::valid_hostname(n) {
                r.hostname = Some(n.to_string());
            }
        }
        if !obs.host_keys.is_empty() {
            r.keys = obs.host_keys.clone();
        }
        if note.is_some() {
            r.note = note;
        }
        // Heartbeat-only refreshes are not worth a disk write.
        let mut cmp = before.clone();
        cmp.last_seen_ms = r.last_seen_ms;
        if is_new || cmp != *r {
            self.dirty_discovered.insert(ip);
            self.removed_discovered.remove(&ip);
        }
        if is_new {
            tracing::debug!(%ip, source, "new unmatched host");
        }
    }

    /// Record an active-scan port result for an unmatched host.
    pub fn record_scan(&mut self, ip: IpAddr, port: PortState, now: u64) {
        if let Some(r) = self.discovered.get_mut(&ip) {
            r.last_tcp_ms = now;
            if r.ssh_port != port {
                r.ssh_port = port;
                self.dirty_discovered.insert(ip);
            }
        }
    }

    pub fn record_keyscan_attempt(&mut self, ip: IpAddr, now: u64) {
        if let Some(r) = self.discovered.get_mut(&ip) {
            r.last_keyscan_ms = now;
        }
    }

    /// Whether `ip` (an unmatched host) is due a TCP/22 check during a scan.
    pub fn scan_tcp_due(&self, ip: IpAddr, now: u64, recheck_ms: u64) -> bool {
        if self.devices.values().any(|d| d.rec.current_ip == Some(ip)) {
            return false; // the device's monitor owns it
        }
        self.discovered
            .get(&ip)
            .is_none_or(|r| now.saturating_sub(r.last_tcp_ms) >= recheck_ms)
    }

    /// Whether an unmatched host with SSH open should have its keys scanned.
    pub fn scan_keys_due(&self, ip: IpAddr, now: u64, recheck_ms: u64) -> bool {
        self.discovered.get(&ip).is_some_and(|r| {
            r.ssh_port == PortState::Open && now.saturating_sub(r.last_keyscan_ms) >= recheck_ms
        })
    }

    /// Unmatched hosts inside `net` with the given port state.
    pub fn discovered_in(&self, net: &ipnet::IpNet) -> Vec<IpAddr> {
        self.discovered
            .keys()
            .filter(|ip| net.contains(*ip))
            .copied()
            .collect()
    }

    // -------------------------------------------------------------- views --

    pub fn status(&self, name: &str, now: u64) -> Option<DeviceStatus> {
        let d = self.devices.get(name)?;
        let ip = d.rec.current_ip;
        let ssh_port = if d.cfg.ssh {
            d.port.state
        } else {
            PortState::Disabled
        };
        let ssh_auth = if !d.cfg.ssh || !d.cfg.auth_check {
            AuthState::Disabled
        } else {
            d.auth
        };
        let site_state = self.site_state(&d.site);
        let input = ColorInput {
            monitoring: d.monitoring(),
            site: site_state,
            discovery: d.discovery(),
            network: d.net.state,
            ssh_enabled: d.cfg.ssh,
            auth_check_enabled: d.cfg.ssh && d.cfg.auth_check,
            port: ssh_port,
            auth: ssh_auth,
            identity: d.identity,
        };
        let (color, mut reasons) = compute_color(&input);
        if site_state == SiteState::Away && d.identity != IdentityState::Mismatch {
            reasons = vec![format!(
                "site '{}' is away: not checked while you are at {}",
                self.site_name(&d.site),
                match self.active_site_names().as_slice() {
                    [] => "no known site".to_string(),
                    names => names.join(", "),
                }
            )];
        }
        if color != Color::Green
            && d.net.state != NetworkState::Unknown
            && site_state != SiteState::Away
        {
            if let Some(e) = &d.last_error {
                if !reasons.iter().any(|r| r == e) && color != Color::Gray {
                    reasons.push(e.clone());
                }
            }
        }
        if self.route_via(d).is_some() && d.net.state == NetworkState::Unknown {
            if let Some(e) = &d.last_error {
                reasons.push(e.clone());
            }
        }
        let latency_ms = if d.healthy() { d.latency_ms } else { None };
        Some(DeviceStatus {
            name: d.cfg.name.clone(),
            id: d.id.clone(),
            site: d.site.clone(),
            site_name: self.site_name(&d.site),
            site_state,
            label: d.label(),
            color,
            ip: ip.map(|i| i.to_string()),
            discovery: d.discovery(),
            network: d.net.state,
            ssh_port,
            ssh_auth,
            identity: d.identity,
            latency_ms,
            last_seen_ms: d.rec.last_seen_ms.map(|t| now.saturating_sub(t)),
            username: d.username(),
            interface: ip.and_then(|i| self.ifname(i)).or_else(|| {
                ip.and_then(|i| {
                    d.rec
                        .addresses
                        .iter()
                        .find(|a| a.ip == i)
                        .and_then(|a| a.interface.clone())
                })
            }),
            network_name: ip.and_then(|i| self.network_name_for(Some(&d.site), i)),
            via: self
                .route_via(d)
                .map(|_| d.cfg.via.clone().unwrap_or_default()),
            monitoring: d.monitoring(),
            reasons,
            services: d
                .services
                .iter()
                .map(|s| ServiceStatus {
                    name: s.check.name().to_string(),
                    state: s.state,
                    detail: s.detail.clone(),
                    checked_ms_ago: (s.last_run_ms > 0).then(|| now.saturating_sub(s.last_run_ms)),
                })
                .collect(),
            profile: d.profile(),
            capabilities: lablink_core::profile::capabilities(
                d.cfg.ssh,
                d.profile(),
                &d.cfg.capabilities,
                self.devices
                    .values()
                    .any(|o| o.site == d.site && o.cfg.via.as_deref() == Some(d.cfg.name.as_str())),
            ),
        })
    }

    pub fn status_all(&self, now: u64) -> Vec<DeviceStatus> {
        self.devices
            .keys()
            .filter_map(|n| self.status(n, now))
            .collect()
    }

    /// Device ids in a scope: one site, every site, or (default) the sites
    /// that are not AWAY.
    pub fn ids_in_scope(&self, site: Option<&str>, all: bool) -> Result<Vec<String>, ApiError> {
        if let Some(s) = site {
            let id = self.cfg.site(s).map(|x| x.id.clone()).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::DeviceNotFound,
                    format!("unknown site '{s}' (see `lablink sites`)"),
                )
            })?;
            return Ok(self
                .devices
                .values()
                .filter(|d| d.site == id)
                .map(|d| d.id.clone())
                .collect());
        }
        Ok(self
            .devices
            .values()
            .filter(|d| all || self.site_engaged(&d.site))
            .map(|d| d.id.clone())
            .collect())
    }

    /// Display names of the ACTIVE sites.
    pub fn active_site_names(&self) -> Vec<String> {
        self.cfg
            .sites
            .iter()
            .filter(|s| self.site_state(&s.id) == SiteState::Active)
            .map(|s| s.name.clone())
            .collect()
    }

    pub fn inspect(&self, name: &str, now: u64) -> Result<DeviceDetail, ApiError> {
        let name = self.require(name)?;
        let d = &self.devices[&name];
        let status = self.status(&name, now).expect("exists");
        let key_view = |p: &PinnedKey| KeyView {
            key_type: p.key_type.clone(),
            fingerprint: p.fingerprint.clone(),
            source: Some(p.source.clone()),
        };
        let mut pinned: Vec<KeyView> = d.rec.pinned.iter().map(key_view).collect();
        for f in &d.cfg.host_key_fingerprints {
            if !pinned.iter().any(|k| &k.fingerprint == f) {
                pinned.push(KeyView {
                    key_type: "unknown".into(),
                    fingerprint: f.clone(),
                    source: Some("config".into()),
                });
            }
        }
        let mut addresses: Vec<AddressView> = d
            .rec
            .addresses
            .iter()
            .map(|a| AddressView {
                ip: a.ip.to_string(),
                current: Some(a.ip) == d.rec.current_ip,
                network_name: a.network_name.clone(),
                interface: a.interface.clone(),
                mac: a.mac.clone(),
                source: a.source.clone(),
                first_seen_ms_ago: now.saturating_sub(a.first_seen_ms),
                last_seen_ms_ago: now.saturating_sub(a.last_seen_ms),
            })
            .collect();
        addresses.sort_by_key(|a| (!a.current, a.last_seen_ms_ago));
        let mine: Vec<&HistoryEvent> = self
            .ring
            .iter()
            .filter(|e| e.device.as_deref() == Some(name.as_str()))
            .collect();
        let recent_events: Vec<HistoryEvent> = mine[mine.len().saturating_sub(20)..]
            .iter()
            .map(|e| (*e).clone())
            .collect();
        Ok(DeviceDetail {
            schema_version: SCHEMA_VERSION,
            status,
            configured: d.configured,
            aliases: d.cfg.aliases.clone(),
            usernames: d.cfg.usernames.clone(),
            active_username: d.rec.active_username.clone(),
            ssh_host: d.ssh_host(),
            ssh_port: d.cfg.ssh_port,
            hostnames: d.cfg.hostnames.clone(),
            learned_hostnames: d.rec.learned_hostnames.iter().cloned().collect(),
            mdns_names: d.rec.mdns_names.iter().cloned().collect(),
            macs: d
                .cfg
                .normalized_macs()
                .into_iter()
                .chain(d.rec.learned_macs.iter().cloned())
                .collect(),
            pinned_keys: pinned,
            observed_keys: d
                .observed_keys
                .iter()
                .map(|k| KeyView {
                    key_type: k.key_type.clone(),
                    fingerprint: k.fingerprint.clone(),
                    source: None,
                })
                .collect(),
            expected_ips: d.cfg.expected_ips.clone(),
            addresses,
            identity_signal: d.identity_signal.map(|s| s.as_str().to_string()),
            consecutive_failures: d.net.consecutive_failures,
            last_error: d.last_error.clone(),
            notes: d
                .rec
                .overrides
                .notes
                .clone()
                .or_else(|| d.cfg.notes.clone()),
            recent_events,
            overrides: OverridesView {
                label: d.rec.overrides.label.clone(),
                username: d.rec.overrides.username.clone(),
                monitoring: d.rec.overrides.monitoring,
                profile: d.rec.overrides.profile,
                ssh: d.rec.overrides.ssh,
            },
        })
    }

    pub fn discovered_view(&self, now: u64) -> Vec<DiscoveredHost> {
        let mut v: Vec<DiscoveredHost> = self
            .discovered
            .values()
            .map(|r| DiscoveredHost {
                ip: r.ip.to_string(),
                site: self
                    .allowlist
                    .network_for_sites(r.ip, &self.engaged_sites())
                    .map(|n| n.site.clone()),
                mac: r.mac.clone(),
                hostname: r.hostname.clone(),
                network_name: self.network_name_for(None, r.ip),
                interface: self.ifname(r.ip),
                sources: r.sources.iter().cloned().collect(),
                ssh_port: r.ssh_port,
                fingerprints: r.keys.iter().map(|k| k.fingerprint.clone()).collect(),
                matched_device: None,
                note: r.note.clone(),
                first_seen_ms_ago: now.saturating_sub(r.first_seen_ms),
                last_seen_ms_ago: now.saturating_sub(r.last_seen_ms),
            })
            .collect();
        v.sort_by_key(|h| h.ip.parse::<IpAddr>().ok());
        v
    }

    /// History from the in-memory ring. `None` when the ring may not hold
    /// enough events and the caller should query the store.
    pub fn history(&self, device: Option<&str>, limit: usize) -> Option<Vec<HistoryEvent>> {
        let matching: Vec<&HistoryEvent> = self
            .ring
            .iter()
            .filter(|e| device.is_none() || e.device.as_deref() == device)
            .collect();
        if matching.len() < limit && self.ring.len() >= EVENT_RING {
            return None;
        }
        Some(
            matching
                .into_iter()
                .rev()
                .take(limit)
                .rev()
                .cloned()
                .collect(),
        )
    }

    // ------------------------------------------------------------- resolve --

    fn ssh_cfg(&self) -> &SshConfig {
        &self.cfg.ssh
    }

    /// Build the OpenSSH target for `name`.
    pub fn target_for(&self, name: &str, username: Option<String>) -> Result<Target, ApiError> {
        let r = self.resolve_inner(name, username, true)?;
        Target::from_resolve(&r).map_err(|e| ApiError::new(ErrorCode::IdentityMismatch, e))
    }

    /// Resolve for `lablink ssh/exec`.
    pub fn resolve(&self, name: &str) -> Result<ResolveResult, ApiError> {
        let name = self.require(name)?;
        let d = &self.devices[&name];
        self.resolve_inner(&name, d.username(), false)
    }

    /// `batch_jump`: a ProxyCommand through a gateway must not prompt
    /// (daemon checks); the CLI allows prompts on the user's terminal.
    fn resolve_inner(
        &self,
        name: &str,
        username: Option<String>,
        batch_jump: bool,
    ) -> Result<ResolveResult, ApiError> {
        let d = self.devices.get(name).ok_or_else(|| {
            ApiError::new(
                ErrorCode::DeviceNotFound,
                format!("unknown device '{name}'"),
            )
        })?;
        if !d.cfg.ssh {
            return Err(ApiError::new(
                ErrorCode::Refused,
                format!("'{name}' is configured without SSH (ssh: false)"),
            ));
        }
        if d.identity == IdentityState::Mismatch {
            return Err(ApiError::new(
                ErrorCode::IdentityMismatch,
                format!(
                    "refusing to connect to '{name}': {}",
                    d.last_error.clone().unwrap_or_else(|| {
                        "SSH host key does not match the pinned identity".into()
                    })
                ),
            ));
        }
        let ip = d.rec.current_ip.ok_or_else(|| {
            if self.site_state(&d.site) == SiteState::Away {
                ApiError::new(
                    ErrorCode::Unreachable,
                    format!(
                        "'{}' belongs to {}, which is AWAY: LabLink does not look for it while you are elsewhere (switch with `lablink site use {}`)",
                        self.label_of(name),
                        self.site_name(&d.site),
                        d.site
                    ),
                )
            } else {
                ApiError::new(
                    ErrorCode::Unreachable,
                    format!(
                        "'{}' has no known current address ({:?}); try `lablink discover`",
                        self.label_of(name),
                        d.discovery()
                    ),
                )
            }
        })?;
        let proxy_command = match self.route_via(d) {
            Some(gw) => {
                let gw_label = self.label_of(&gw);
                let name = self.label_of(name);
                let g = self.devices.get(&gw).ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::Unreachable,
                        format!("gateway '{gw_label}' is not a known device"),
                    )
                })?;
                // Never tunnel through a gateway whose identity LabLink has not
                // verified against a pin: the hop must run with LabLink's
                // HostKeyAlias + StrictHostKeyChecking=yes, not the user's
                // fallback policy.
                if g.identity != IdentityState::Verified || g.usable_pins().is_empty() {
                    return Err(ApiError::new(
                        ErrorCode::Refused,
                        format!(
                            "'{name}' is reached via '{gw_label}', whose host key is not verified against a pin (identity: {}); verify it with `lablink trust {gw_label}` first",
                            format!("{:?}", g.identity).to_lowercase()
                        ),
                    ));
                }
                let gr = self.resolve_inner(&gw, g.username(), true).map_err(|e| {
                    ApiError::new(
                        e.code,
                        format!(
                            "'{name}' is reached via '{gw_label}', which cannot be used: {}",
                            e.message
                        ),
                    )
                })?;
                let mut gt = Target::from_resolve(&gr)
                    .map_err(|e| ApiError::new(ErrorCode::IdentityMismatch, e))?;
                if batch_jump && !self.cfg.ssh.reuse_control_master {
                    gt.options.insert("ControlPath".into(), "none".into());
                }
                Some(lablink_ssh::proxy_command_through(&gt, batch_jump))
            }
            None => None,
        };
        let has_pins = !d.pinned_fingerprints().is_empty();
        let usable = !d.usable_pins().is_empty();
        if has_pins && !usable {
            return Err(ApiError::new(
                ErrorCode::Unreachable,
                format!("'{name}' has pinned fingerprints that have not been checked against the host yet; wait for the daemon to verify it (`lablink status {name}`)"),
            ));
        }
        let (alias, kh) = if usable {
            (
                Some(host_key_alias(&d.site, &d.cfg.name)),
                Some(self.known_hosts_path.display().to_string()),
            )
        } else {
            (None, None)
        };
        Ok(ResolveResult {
            schema_version: SCHEMA_VERSION,
            name: d.cfg.name.clone(),
            id: d.id.clone(),
            site_name: self.site_name(&d.site),
            shared_name: self.label_of(&d.id) != d.cfg.name,
            site_away: self.site_state(&d.site) == SiteState::Away,
            ip: ip.to_string(),
            port: d.cfg.ssh_port,
            ssh_host: d.ssh_host(),
            username,
            identity: d.identity,
            color: self
                .status(name, lablink_core::time::now_ms())
                .map(|s| s.color)
                .unwrap_or(Color::Gray),
            network: d.net.state,
            host_key_alias: alias,
            known_hosts_file: kh,
            ssh_binary: self.ssh_cfg().binary.clone(),
            connect_timeout_s: self.ssh_cfg().connect_timeout_s,
            ssh_options: self.ssh_cfg().options.clone(),
            proxy_command,
        })
    }

    pub fn known_hosts_entries(&self) -> Vec<KnownHostsEntry> {
        let mut v = Vec::new();
        for d in self.devices.values() {
            for p in d.usable_pins() {
                v.push(KnownHostsEntry {
                    alias: host_key_alias(&d.site, &d.cfg.name),
                    key_type: p.key_type.clone(),
                    public_key: p.public_key.clone().unwrap_or_default(),
                });
            }
        }
        v
    }

    // --------------------------------------------------------------- trust --

    /// Pin `confirm`ed keys after a fresh scan returned exactly them.
    pub fn trust(
        &mut self,
        name: &str,
        ip: IpAddr,
        scanned: &[HostKey],
        confirm: &[String],
        replace: bool,
        now: u64,
    ) -> Result<TrustReport, ApiError> {
        let d = self
            .devices
            .get(name)
            .ok_or_else(|| ApiError::new(ErrorCode::DeviceNotFound, name.to_string()))?;
        if d.rec.current_ip != Some(ip) {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!("'{name}' moved during the trust operation; retry"),
            ));
        }
        let mut want: Vec<&str> = confirm.iter().map(String::as_str).collect();
        want.sort();
        let mut got: Vec<&str> = scanned.iter().map(|k| k.fingerprint.as_str()).collect();
        got.sort();
        if want != got {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!(
                    "the host now presents [{}], not the confirmed [{}]; nothing pinned",
                    got.join(", "),
                    want.join(", ")
                ),
            ));
        }
        let pinned_before = self.pinned_view(name);
        let has_pins = !d.pinned_fingerprints().is_empty();
        let all_known = scanned
            .iter()
            .all(|k| d.pinned_fingerprints().contains(&k.fingerprint));
        if has_pins && !all_known && !replace && d.identity == IdentityState::Mismatch {
            return Err(ApiError::new(
                ErrorCode::IdentityMismatch,
                format!("'{name}' already has different pinned keys; pass --replace after verifying the machine out of band"),
            ));
        }
        if has_pins && !all_known && !replace {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!(
                    "'{name}' already has pinned keys that differ; pass --replace to discard them"
                ),
            ));
        }
        if all_known && has_pins {
            self.fill_pin_blobs(name, scanned, now);
            return Ok(TrustReport {
                schema_version: SCHEMA_VERSION,
                device: name.into(),
                ip: ip.to_string(),
                action: "unchanged".into(),
                scanned: key_views(scanned),
                pinned_before: pinned_before.clone(),
                pinned_now: pinned_before,
            });
        }
        if d.cfg
            .host_key_fingerprints
            .iter()
            .any(|f| !scanned.iter().any(|k| &k.fingerprint == f))
            && replace
        {
            return Err(ApiError::new(
                ErrorCode::Refused,
                format!("'{name}' has fingerprints pinned in the config file; edit host_key_fingerprints there instead"),
            ));
        }
        let d = self.devices.get_mut(name).unwrap();
        if replace {
            d.rec.pinned.clear();
        }
        for k in scanned {
            if !d.rec.pinned.iter().any(|p| p.fingerprint == k.fingerprint) {
                d.rec.pinned.push(PinnedKey {
                    key_type: k.key_type.clone(),
                    fingerprint: k.fingerprint.clone(),
                    public_key: k.public_key.clone(),
                    source: "trust".into(),
                    pinned_at_ms: now,
                });
            }
        }
        d.observed_keys = scanned.to_vec();
        if d.identity == IdentityState::Mismatch {
            d.identity = IdentityState::Unknown;
        }
        self.known_hosts_dirty = true;
        let fps: Vec<&str> = scanned.iter().map(|k| k.fingerprint.as_str()).collect();
        self.event(
            Some(name),
            "key_pinned",
            format!(
                "pinned host key(s) {} at {ip} by explicit `lablink trust`{}",
                fps.join(", "),
                if replace {
                    " (replaced previous pins)"
                } else {
                    ""
                }
            ),
        );
        // Verified once the host proves it holds the key (next check).
        self.devices.get_mut(name).unwrap().key_proof_due = Some(ip);
        self.mark(name);
        self.urgent = true;
        Ok(TrustReport {
            schema_version: SCHEMA_VERSION,
            device: name.into(),
            ip: ip.to_string(),
            action: "pinned".into(),
            scanned: key_views(scanned),
            pinned_before,
            pinned_now: self.pinned_view(name),
        })
    }

    pub fn pinned_view(&self, name: &str) -> Vec<KeyView> {
        self.devices
            .get(name)
            .map(|d| {
                d.rec
                    .pinned
                    .iter()
                    .map(|p| KeyView {
                        key_type: p.key_type.clone(),
                        fingerprint: p.fingerprint.clone(),
                        source: Some(p.source.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Current IP and port for a trust scan.
    pub fn trust_target(&self, name: &str) -> Result<(String, IpAddr, u16), ApiError> {
        let name = self.require(name)?;
        let d = &self.devices[&name];
        if !d.cfg.ssh {
            return Err(ApiError::new(
                ErrorCode::Refused,
                format!("'{name}' is configured without SSH"),
            ));
        }
        let ip = d.rec.current_ip.ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unreachable,
                format!("'{name}' has no known current address"),
            )
        })?;
        Ok((name, ip, d.cfg.ssh_port))
    }

    // ----------------------------------------------------------- overrides --

    pub fn set(&mut self, name: &str, c: &DeviceChanges) -> Result<DeviceStatus, ApiError> {
        let name = self.require(name)?;
        let configured = self.devices[&name].configured;
        let profile = validate_changes(c, configured, self.devices[&name].cfg.ssh)?;
        let msgs = self.apply_changes(&name, c, profile);
        if !msgs.is_empty() {
            self.event(Some(&name), "settings_changed", msgs.join(", "));
            self.mark(&name);
            self.urgent = true;
        }
        Ok(self.status(&name, lablink_core::time::now_ms()).unwrap())
    }

    /// Apply validated changes; returns one message per changed setting.
    fn apply_changes(
        &mut self,
        name: &str,
        c: &DeviceChanges,
        profile: Option<Option<Profile>>,
    ) -> Vec<String> {
        let d = self.devices.get_mut(name).unwrap();
        let clear = |s: &String| if s.is_empty() { None } else { Some(s.clone()) };
        let mut msgs = Vec::new();
        if let Some(l) = &c.label {
            d.rec.overrides.label = clear(l);
            msgs.push(format!("label = {l:?}"));
        }
        if let Some(u) = &c.username {
            d.rec.overrides.username = clear(u);
            d.auth = AuthState::Unknown;
            msgs.push(format!("username = {u:?}"));
        }
        if let Some(n) = &c.notes {
            d.rec.overrides.notes = clear(n);
            msgs.push("notes updated".into());
        }
        if let Some(m) = c.monitoring {
            d.rec.overrides.monitoring = Some(m);
            if !m {
                d.net.reset();
                d.port.reset();
            }
            msgs.push(format!("monitoring = {m}"));
        }
        if let Some(p) = profile {
            d.rec.overrides.profile = p;
            msgs.push(format!("profile = {}", p.map_or("none", |p| p.as_str())));
        }
        if let Some(s) = c.ssh {
            d.rec.overrides.ssh = Some(s);
            msgs.push(format!("ssh = {s}"));
        }
        d.apply_runtime_ssh();
        if c.recheck && d.cfg.ssh {
            // Not a setting: the monitor re-runs the login check on its next round.
            d.auth_recheck = true;
            if d.auth != AuthState::Ok {
                d.auth = AuthState::Unknown;
            }
        }
        msgs
    }

    /// Track a discovered host under a new name, with optional settings
    /// (label, username, profile, SSH on/off). Never pins a host key.
    pub fn adopt(
        &mut self,
        ip: IpAddr,
        name: &str,
        site: Option<&str>,
        changes: &DeviceChanges,
        now: u64,
    ) -> Result<DeviceStatus, ApiError> {
        if !lablink_core::config::valid_name(name) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("invalid device name '{name}'"),
            ));
        }
        let site = self.adoption_site(ip, site)?;
        if self
            .devices
            .values()
            .any(|d| d.site == site && d.cfg.answers_to(name))
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                format!(
                    "site '{}' already has a device named '{name}'",
                    self.site_name(&site)
                ),
            ));
        }
        let profile = validate_changes(changes, false, true)?;
        if !self.discovered.contains_key(&ip) {
            return Err(ApiError::new(
                ErrorCode::DeviceNotFound,
                format!("{ip} is not in the discovered-host list (run `lablink discover`)"),
            ));
        }
        let rec = self.discovered.remove(&ip).expect("checked above");
        self.removed_discovered.insert(ip);
        let mut d = Device::new(DeviceConfig::named(name), &site, false);
        d.rec.adopted = true;
        d.rec.current_ip = Some(ip);
        d.rec.first_seen_ms = Some(rec.first_seen_ms);
        d.rec.last_seen_ms = Some(rec.last_seen_ms);
        if let Some(m) = &rec.mac {
            d.rec.learned_macs.insert(m.clone());
        }
        if let Some(h) = rec
            .hostname
            .as_ref()
            .filter(|h| lablink_core::config::valid_hostname(h))
        {
            d.rec.learned_hostnames.insert(normalize_hostname(h));
        }
        touch_address(
            &mut d.rec,
            ip,
            "adopt",
            rec.mac.clone(),
            self.network_name_for(Some(&site), ip),
            self.ifname(ip),
            now,
        );
        d.observed_keys = rec.keys.clone();
        let id = d.id.clone();
        self.devices.insert(id.clone(), d);
        let settings = self.apply_changes(&id, changes, profile);
        let label = self.label_of(&id);
        let next = if self.devices[&id].cfg.ssh {
            format!("host key not pinned yet; run `lablink trust {label}`")
        } else {
            "network-only, no SSH".to_string()
        };
        let extra = if settings.is_empty() {
            String::new()
        } else {
            format!("; {}", settings.join(", "))
        };
        self.event(
            Some(&id),
            "adopted",
            format!(
                "adopted {ip} as '{name}' at site '{}' ({next}){extra}",
                self.site_name(&site)
            ),
        );
        self.mark(&id);
        self.urgent = true;
        Ok(self.status(&id, now).unwrap())
    }

    /// The site a newly adopted device joins: the one named, else the only
    /// engaged site whose networks contain the address, else the only
    /// active site, else the only site.
    fn adoption_site(&self, ip: IpAddr, site: Option<&str>) -> Result<String, ApiError> {
        if let Some(s) = site {
            return self.cfg.site(s).map(|x| x.id.clone()).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("unknown site '{s}' (see `lablink sites`)"),
                )
            });
        }
        if self.cfg.sites.is_empty() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "no site is configured yet: run `lablink init` (or create a site in the GUI) first",
            ));
        }
        let containing = self.allowlist.sites_containing(ip);
        let engaged: Vec<&String> = containing.iter().filter(|s| self.site_engaged(s)).collect();
        if let [one] = engaged.as_slice() {
            return Ok((*one).clone());
        }
        if let [one] = containing.as_slice() {
            return Ok(one.clone());
        }
        let active: Vec<&lablink_core::config::SiteConfig> = self
            .cfg
            .sites
            .iter()
            .filter(|s| self.site_state(&s.id) == SiteState::Active)
            .collect();
        if let [one] = active.as_slice() {
            return Ok(one.id.clone());
        }
        if let [one] = self.cfg.sites.as_slice() {
            return Ok(one.id.clone());
        }
        Err(ApiError::new(
            ErrorCode::BadRequest,
            format!(
                "cannot tell which site {ip} belongs to; choose one with --site ({})",
                self.cfg
                    .sites
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ))
    }

    // ---------------------------------------------------------- persistence --

    /// Take everything that needs writing. Leaves nothing dirty.
    pub fn take_batch(&mut self) -> Batch {
        let devices = std::mem::take(&mut self.dirty_devices)
            .into_iter()
            .filter_map(|n| {
                self.devices
                    .get(&n)
                    .map(|d| (n, serde_json::to_string(&d.rec).unwrap_or_default()))
            })
            .collect();
        let discovered = std::mem::take(&mut self.dirty_discovered)
            .into_iter()
            .filter_map(|ip| {
                self.discovered
                    .get(&ip)
                    .map(|r| (ip.to_string(), serde_json::to_string(r).unwrap_or_default()))
            })
            .collect();
        let removed = std::mem::take(&mut self.removed_discovered)
            .into_iter()
            .map(|ip| ip.to_string())
            .collect();
        let removed_devices = std::mem::take(&mut self.removed_devices)
            .into_iter()
            .collect();
        let meta = if std::mem::take(&mut self.sites_dirty) {
            vec![
                (
                    "site_mode".to_string(),
                    serde_json::to_string(&self.mode).unwrap_or_default(),
                ),
                (
                    "learned_gateways".to_string(),
                    serde_json::to_string(&self.learned_gateways).unwrap_or_default(),
                ),
            ]
        } else {
            Vec::new()
        };
        self.urgent = false;
        Batch {
            devices,
            discovered,
            removed_discovered: removed,
            removed_devices,
            meta,
            events: std::mem::take(&mut self.pending),
        }
    }

    /// Mark every device dirty (final flush on shutdown keeps last_seen exact).
    pub fn mark_all(&mut self) {
        let names: Vec<String> = self.devices.keys().cloned().collect();
        self.dirty_devices.extend(names);
    }

    pub fn has_dirty(&self) -> bool {
        !self.dirty_devices.is_empty()
            || !self.dirty_discovered.is_empty()
            || !self.removed_discovered.is_empty()
            || !self.removed_devices.is_empty()
            || self.sites_dirty
            || !self.pending.is_empty()
    }
}

/// Addresses LabLink can probe and hand to ssh without an interface scope:
/// excludes unspecified, loopback, multicast and IPv6 link-local addresses.
/// Check runtime changes before anything is modified. Returns the parsed
/// profile change (`Some(None)` clears the profile).
pub fn validate_changes(
    c: &DeviceChanges,
    configured: bool,
    configured_ssh: bool,
) -> Result<Option<Option<Profile>>, ApiError> {
    let bad = |m: String| Err(ApiError::new(ErrorCode::BadRequest, m));
    if let Some(u) = &c.username {
        if !u.is_empty() && !lablink_core::config::valid_username(u) {
            return bad(format!("invalid username '{u}'"));
        }
    }
    if let Some(l) = &c.label {
        if l.len() > 64 || l.chars().any(char::is_control) {
            return bad("label must be at most 64 printable characters".into());
        }
    }
    if let Some(n) = &c.notes {
        if !lablink_core::config::valid_notes(n) {
            return bad(
                "notes must be at most 2000 characters, without control characters other than newline and tab"
                    .into(),
            );
        }
    }
    let profile = match c.profile.as_deref() {
        None => None,
        Some("") => Some(None),
        Some(s) => match Profile::parse(s) {
            Some(p) => Some(Some(p)),
            None => {
                let names: Vec<&str> = Profile::ALL.iter().map(|p| p.as_str()).collect();
                return bad(format!(
                    "unknown profile '{s}' (expected one of: {})",
                    names.join(", ")
                ));
            }
        },
    };
    if configured {
        if c.ssh.is_some() {
            return bad("this device is defined in the config file; change `ssh:` there".into());
        }
        if let Some(Some(p)) = profile {
            if !p.uses_ssh() && configured_ssh {
                return bad(format!(
                    "profile {} needs `ssh: false`, and this device is defined in the config file with SSH; change it there",
                    p.as_str()
                ));
            }
        }
    }
    Ok(profile)
}

/// The HostKeyAlias LabLink uses for a pinned device.
pub fn host_key_alias(site: &str, name: &str) -> String {
    format!("{ALIAS_PREFIX}{site}.{name}")
}

/// RFC 1918 / link-local / CGNAT IPv4, or unique-local / link-local IPv6.
fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn usable_address(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

fn key_views(keys: &[HostKey]) -> Vec<KeyView> {
    keys.iter()
        .map(|k| KeyView {
            key_type: k.key_type.clone(),
            fingerprint: k.fingerprint.clone(),
            source: None,
        })
        .collect()
}

fn touch_address(
    rec: &mut DeviceRecord,
    ip: IpAddr,
    source: &str,
    mac: Option<String>,
    network_name: Option<String>,
    interface: Option<String>,
    now: u64,
) {
    let adopted = source == "adopt";
    if let Some(a) = rec.addresses.iter_mut().find(|a| a.ip == ip) {
        a.last_seen_ms = now;
        if adopted {
            a.last_adopted_ms = now;
        }
        if mac.is_some() {
            a.mac = mac;
        }
        if interface.is_some() {
            a.interface = interface;
        }
        a.network_name = network_name;
        return;
    }
    rec.addresses.push(AddressRecord {
        ip,
        network_name,
        interface,
        mac,
        source: source.to_string(),
        first_seen_ms: now,
        last_seen_ms: now,
        last_adopted_ms: if adopted { now } else { 0 },
    });
    if rec.addresses.len() > MAX_ADDRESSES {
        let cur = rec.current_ip;
        if let Some(pos) = rec
            .addresses
            .iter()
            .enumerate()
            .filter(|(_, a)| Some(a.ip) != cur)
            .min_by_key(|(_, a)| a.last_seen_ms)
            .map(|(i, _)| i)
        {
            rec.addresses.remove(pos);
        }
    }
}

impl Registry {
    /// Service checks due now. Only for devices whose host key is verified and
    /// whose SSH login works: a service check never authenticates to a host
    /// LabLink has not identified.
    pub fn services_due(
        &self,
        name: &str,
        now: u64,
    ) -> Vec<(usize, std::sync::Arc<dyn crate::services::ServiceCheck>)> {
        let Some(d) = self.devices.get(name) else {
            return Vec::new();
        };
        if d.services.is_empty()
            || !d.healthy()
            || d.identity != IdentityState::Verified
            || d.auth != AuthState::Ok
        {
            return Vec::new();
        }
        d.services
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.last_run_ms == 0 || now.saturating_sub(s.last_run_ms) >= ms(s.check.interval())
            })
            .map(|(i, s)| (i, s.check.clone()))
            .collect()
    }

    /// Record a service-check result; transitions become history events.
    pub fn apply_service(
        &mut self,
        name: &str,
        idx: usize,
        r: &crate::services::ServiceResult,
        now: u64,
    ) {
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        let Some(s) = d.services.get_mut(idx) else {
            return;
        };
        let old = s.state;
        s.state = r.state;
        s.detail = r.detail.clone();
        s.last_run_ms = now;
        if old != r.state {
            let svc = s.check.name().to_string();
            let detail = r
                .detail
                .clone()
                .map(|x| format!(" ({x})"))
                .unwrap_or_default();
            self.event(
                Some(name),
                "service",
                format!("service {svc}: {old:?} -> {:?}{detail}", r.state).to_lowercase(),
            );
        }
    }
}

impl Registry {
    /// The gateway to use for `d`, if it is configured with `via` and none of
    /// its expected addresses lies on a directly attached network.
    pub fn route_via(&self, d: &Device) -> Option<String> {
        let gw = device_id(&d.site, d.cfg.via.as_deref()?);
        let attached = self.snapshot.as_ref().is_some_and(|s| {
            d.cfg
                .expected_ip_addrs()
                .iter()
                .any(|ip| s.interface_for(*ip).is_some())
        });
        (!attached).then_some(gw)
    }

    /// A ready-to-use OpenSSH target for a gateway: it must be reachable,
    /// its host key verified and its login working. Commands are never sent
    /// through a gateway LabLink has not identified.
    pub fn gateway_target(&self, gw: &str) -> Result<Target, String> {
        let label = self.label_of(gw);
        let g = self
            .devices
            .get(gw)
            .ok_or_else(|| format!("gateway '{label}' is not a known device"))?;
        if !g.healthy() {
            return Err(format!("gateway '{label}' is not reachable"));
        }
        if g.identity != IdentityState::Verified {
            return Err(format!(
                "gateway '{label}' host key is not verified ({})",
                format!("{:?}", g.identity).to_lowercase()
            ));
        }
        if g.auth != AuthState::Ok {
            return Err(format!(
                "gateway '{label}' SSH login is not working ({})",
                format!("{:?}", g.auth).to_lowercase()
            ));
        }
        let r = self
            .resolve_inner(gw, g.username(), true)
            .map_err(|e| e.message)?;
        Target::from_resolve(&r)
    }

    /// The device cannot be observed because its gateway is unusable.
    pub fn via_unavailable(&mut self, name: &str, reason: String, now: u64) {
        let Some(d) = self.devices.get_mut(name) else {
            return;
        };
        d.last_check_ms = now;
        let changed = d.last_error.as_deref() != Some(reason.as_str())
            || d.net.state != NetworkState::Unknown;
        d.net.reset();
        d.port.reset();
        d.latency_ms = None;
        d.last_error = Some(reason.clone());
        if changed {
            self.event(
                Some(name),
                "via_unavailable",
                format!("cannot check: {reason}"),
            );
            self.mark(name);
        }
    }
}

impl Registry {
    /// The gateway has not been checked yet since startup: wait quietly
    /// instead of reporting it unusable.
    pub fn gateway_pending(&self, gw: &str) -> bool {
        // Not yet checked since startup, or reachable but its host key / login
        // has not been verified yet: wait instead of reporting it unusable.
        self.devices.get(gw).is_some_and(|g| {
            g.net.state == NetworkState::Unknown
                || (g.healthy() && g.identity == IdentityState::Unknown)
                || (g.healthy()
                    && g.identity == IdentityState::Verified
                    && g.auth == AuthState::Unknown)
        })
    }
}

/// Keys the user's own `~/.ssh/known_hosts` trusts, split by how the entry
/// was keyed: under one of the device's names, or under its bare IP.
#[derive(Debug, Clone, Default)]
pub struct UserKnown {
    pub by_name: Vec<HostKey>,
    pub by_ip: Vec<HostKey>,
}

impl Registry {
    /// `ip` lies on a directly attached, up interface.
    pub fn is_attached_ip(&self, ip: IpAddr) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|s| s.interface_for(ip).is_some())
    }
}

impl Registry {
    /// Restore the site mode and learned gateway signatures from the cache.
    pub fn restore_sites(&mut self, mode: Option<&str>, learned: Option<&str>) {
        if let Some(m) = mode.and_then(|m| serde_json::from_str::<SiteMode>(m).ok()) {
            match &m {
                SiteMode::Manual(s) if self.cfg.site(s).is_none() => {
                    self.event(
                        None,
                        "site_mode",
                        format!("site '{s}' chosen earlier no longer exists; back to automatic site detection"),
                    );
                    self.sites_dirty = true;
                }
                _ => self.mode = m,
            }
        }
        if let Some(l) = learned
            .and_then(|l| serde_json::from_str::<BTreeMap<String, Vec<(String, String)>>>(l).ok())
        {
            self.learned_gateways = l
                .into_iter()
                .filter(|(site, _)| self.cfg.site(site).is_some())
                .collect();
        }
        self.sites_stale = true;
    }

    /// Local, non-secret signals from the latest snapshot.
    fn local_signals(&self) -> sites::LocalSignals {
        let Some(snap) = self.snapshot.as_ref() else {
            return Default::default();
        };
        sites::LocalSignals {
            attached: snap
                .interfaces
                .iter()
                .filter(|i| i.up && !i.loopback)
                .flat_map(|i| {
                    i.addrs.iter().map(|a| sites::Attached {
                        interface: i.name.clone(),
                        net: a.trunc(),
                    })
                })
                .collect(),
            gateways: snap
                .gateways
                .iter()
                .map(|(iface, ip)| sites::Gateway {
                    interface: iface.clone(),
                    ip: *ip,
                    mac: self
                        .neighbors
                        .get(ip)
                        .map(|(m, _)| m.clone())
                        .or_else(|| snap.neighbor_mac(*ip).and_then(normalize_mac)),
                })
                .collect(),
            ssids: snap.ssids.clone(),
            neighbor_macs: self.neighbors.values().map(|(m, _)| m.clone()).collect(),
        }
    }

    fn knowledge(&self, site: &str) -> sites::SiteKnowledge {
        sites::SiteKnowledge {
            learned_gateway_macs: self.learned_gateways.get(site).cloned().unwrap_or_default(),
            device_macs: self
                .devices
                .values()
                .filter(|d| d.site == site)
                .flat_map(|d| {
                    d.cfg
                        .normalized_macs()
                        .into_iter()
                        .chain(d.rec.learned_macs.iter().cloned())
                        .map(|m| (d.id.clone(), m))
                        .collect::<Vec<_>>()
                })
                .collect(),
        }
    }

    /// Devices that proved their identity with a pinned host key on a
    /// directly attached network: verified now, or seen recently while their
    /// site was not engaged.
    fn key_evidence(&self, now: u64) -> Vec<KeySighting> {
        let mut v: Vec<KeySighting> = self
            .devices
            .values()
            .filter(|d| {
                d.identity == IdentityState::Verified
                    && d.healthy()
                    && self.route_via(d).is_none()
                    && d.rec.current_ip.is_some_and(|ip| self.is_attached_ip(ip))
            })
            .map(|d| KeySighting {
                site: d.site.clone(),
                device: d.id.clone(),
                ip: d.rec.current_ip.expect("filtered"),
            })
            .collect();
        for (id, (ip, ts)) in &self.key_sightings {
            if now.saturating_sub(*ts) <= KEY_SIGHTING_TTL_MS && self.is_attached_ip(*ip) {
                if let Some(d) = self.devices.get(id) {
                    v.push(KeySighting {
                        site: d.site.clone(),
                        device: id.clone(),
                        ip: *ip,
                    });
                }
            }
        }
        v
    }

    /// Remember pinned host keys presented by devices of sites that are not
    /// engaged (they are evidence for that site; nothing is attached).
    fn note_key_sightings(&mut self, obs: &Observation, now: u64) {
        let Some(ip) = obs.ip else { return };
        if obs.host_keys.is_empty() {
            return;
        }
        let hits: Vec<String> = self
            .devices
            .values()
            .filter(|d| !self.site_engaged(&d.site))
            .filter(|d| {
                let pins = d.pinned_fingerprints();
                obs.host_keys.iter().any(|k| pins.contains(&k.fingerprint))
            })
            .map(|d| d.id.clone())
            .collect();
        for id in hits {
            self.key_sightings.insert(id, (ip, now));
            self.sites_stale = true;
        }
    }

    /// Re-evaluate which site the user is at, if anything changed since the
    /// last evaluation. Returns devices whose monitors should run now.
    pub fn refresh_sites_if_stale(&mut self, now: u64) -> Vec<String> {
        if !self.sites_stale {
            return Vec::new();
        }
        self.refresh_sites(now)
    }

    /// Re-evaluate which site the user is at. Never changes trust: pins,
    /// identities and adoption are untouched; only probing and reporting
    /// follow the decision.
    pub fn refresh_sites(&mut self, now: u64) -> Vec<String> {
        self.sites_stale = false;
        self.key_sightings
            .retain(|_, (_, ts)| now.saturating_sub(*ts) <= KEY_SIGHTING_TTL_MS);
        let signals = self.local_signals();
        let keys = self.key_evidence(now);
        let assessments: Vec<sites::Assessment> = self
            .cfg
            .sites
            .iter()
            .map(|s| sites::assess(s, &self.knowledge(&s.id), &signals, &keys))
            .collect();
        let decisions = sites::decide(&self.cfg.sites, &assessments, &self.mode);
        let mut wake = Vec::new();
        for d in &decisions {
            let old = self.decisions.get(&d.site).map(|o| (o.state, o.confidence));
            if old.map(|o| o.0) != Some(d.state) {
                let name = self.site_name(&d.site);
                let how = match d.selected_by {
                    sites::SelectedBy::Manual => "chosen by hand".to_string(),
                    sites::SelectedBy::OnlySite => "the only site".to_string(),
                    sites::SelectedBy::Auto => format!("{} confidence", d.confidence.as_str()),
                };
                let (kind, msg) = match d.state {
                    SiteState::Active => {
                        ("site_active", format!("site '{name}' is ACTIVE ({how})"))
                    }
                    SiteState::Away => (
                        "site_away",
                        format!("site '{name}' is AWAY: its devices are not checked"),
                    ),
                    SiteState::Unknown => (
                        "site_unknown",
                        format!(
                            "site '{name}' is not confirmed: another site matches equally well"
                        ),
                    ),
                };
                if old.is_some() || d.state != SiteState::Away {
                    self.event(None, kind, msg);
                }
                if d.state == SiteState::Away {
                    self.park_site(&d.site);
                } else {
                    wake.extend(
                        self.devices
                            .values()
                            .filter(|x| x.site == d.site && x.monitoring())
                            .map(|x| x.id.clone()),
                    );
                }
            } else if old.map(|o| o.1) != Some(d.confidence) {
                tracing::debug!(site = %d.site, confidence = d.confidence.as_str(), "site confidence changed");
            }
        }
        for d in &decisions {
            if d.state == SiteState::Active && d.confidence == sites::Confidence::High {
                self.learn_gateways(&d.site, &signals);
            }
        }
        self.decisions = decisions.into_iter().map(|d| (d.site.clone(), d)).collect();
        self.assessments = assessments
            .into_iter()
            .map(|a| (a.site.clone(), a))
            .collect();
        wake
    }

    /// Record the gateway MACs of a site confirmed by host keys, so the next
    /// visit is recognized before any device answers.
    fn learn_gateways(&mut self, site: &str, signals: &sites::LocalSignals) {
        let Some(cfg) = self.cfg.site(site) else {
            return;
        };
        let mut learned = self.learned_gateways.get(site).cloned().unwrap_or_default();
        let mut changed = false;
        for g in &signals.gateways {
            let Some(mac) = &g.mac else { continue };
            for n in &cfg.networks {
                let inside = lablink_core::net::parse_cidr(&n.cidr)
                    .ok()
                    .is_some_and(|net| net.contains(&g.ip));
                if !inside || learned.iter().any(|(x, m)| x == &n.name && m == mac) {
                    continue;
                }
                learned.push((n.name.clone(), mac.clone()));
                let count = learned.iter().filter(|(x, _)| x == &n.name).count();
                if count > MAX_LEARNED_GATEWAYS {
                    if let Some(pos) = learned.iter().position(|(x, _)| x == &n.name) {
                        learned.remove(pos);
                    }
                }
                changed = true;
                tracing::info!(site, network = %n.name, "learned the gateway signature of this network");
            }
        }
        if changed {
            self.learned_gateways.insert(site.to_string(), learned);
            self.sites_dirty = true;
        }
    }

    /// Stop treating a site's devices as being checked: forget live probe
    /// state (so nothing stale turns RED later) but keep identity pins,
    /// addresses and any security finding.
    fn park_site(&mut self, site: &str) {
        for d in self.devices.values_mut().filter(|d| d.site == site) {
            d.net.reset();
            d.port.reset();
            d.auth = AuthState::Unknown;
            d.latency_ms = None;
            if d.identity != IdentityState::Mismatch {
                d.identity = IdentityState::Unknown;
            }
            d.identity_ip = None;
            d.auth_ip = None;
            d.port_opened = false;
            d.auth_recheck = true;
            for s in &mut d.services {
                s.state = ServiceState::Unknown;
            }
        }
    }

    /// Choose the active site by hand, or return to automatic detection.
    /// Returns devices to wake.
    pub fn set_mode(&mut self, site: Option<&str>, now: u64) -> Result<Vec<String>, ApiError> {
        let mode = match site {
            None => SiteMode::Auto,
            Some(s) => {
                SiteMode::Manual(self.cfg.site(s).map(|x| x.id.clone()).ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::DeviceNotFound,
                        format!("unknown site '{s}' (see `lablink sites`)"),
                    )
                })?)
            }
        };
        if mode != self.mode {
            let msg = match &mode {
                SiteMode::Auto => "site mode: automatic detection".to_string(),
                SiteMode::Manual(s) => format!("site mode: '{}' chosen by hand", self.site_name(s)),
            };
            self.event(None, "site_mode", msg);
            self.mode = mode;
            self.sites_dirty = true;
            self.urgent = true;
        }
        Ok(self.refresh_sites(now))
    }

    /// The current decision for a site.
    pub fn decision(&self, site: &str) -> Option<&Decision> {
        self.decisions.get(site)
    }

    /// Summaries of every site.
    pub fn site_statuses(&self, now: u64) -> Vec<sites::SiteStatus> {
        let attached = self.local_prefixes();
        self.cfg
            .sites
            .iter()
            .map(|s| {
                let d = self.decisions.get(&s.id);
                let mut counts = sites::DeviceCounts::default();
                for dev in self.devices.values().filter(|x| x.site == s.id) {
                    counts.total += 1;
                    match self.status(&dev.id, now).map(|x| x.color) {
                        Some(Color::Green) => counts.green += 1,
                        Some(Color::Yellow) => counts.yellow += 1,
                        Some(Color::Red) => counts.red += 1,
                        _ => counts.gray += 1,
                    }
                }
                sites::SiteStatus {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    state: d.map(|x| x.state).unwrap_or_default(),
                    confidence: d.map(|x| x.confidence).unwrap_or_default(),
                    selected_by: d.map(|x| x.selected_by).unwrap_or_default(),
                    contested: d.is_some_and(|x| x.contested),
                    auto_detect: s.auto_detect,
                    scan: d.and_then(|x| x.scan_permission().err()),
                    evidence: self
                        .assessments
                        .get(&s.id)
                        .map(|a| a.evidence.clone())
                        .unwrap_or_default(),
                    networks: s
                        .networks
                        .iter()
                        .map(|n| sites::SiteNetworkView {
                            name: n.name.clone(),
                            cidr: n.cidr.clone(),
                            active_scan: n.active_scan,
                            attached: lablink_core::net::parse_cidr(&n.cidr).ok().is_some_and(
                                |net| {
                                    attached.iter().any(|a| {
                                        a.trunc().contains(&net.network())
                                            || net.contains(&a.addr())
                                    })
                                },
                            ),
                        })
                        .collect(),
                    devices: counts,
                }
            })
            .collect()
    }

    /// `lablink sites` payload.
    pub fn sites_report(&self, now: u64) -> sites::SitesReport {
        let sig = self.local_signals();
        sites::SitesReport {
            schema_version: SCHEMA_VERSION,
            mode: self.mode.clone(),
            sites: self.site_statuses(now),
            signals: sites::SignalsView {
                attached: sig
                    .attached
                    .iter()
                    .map(|a| format!("{} on {}", a.net, a.interface))
                    .collect(),
                gateways: sig
                    .gateways
                    .iter()
                    .map(|g| match &g.mac {
                        Some(m) => format!("{} on {} (MAC {m})", g.ip, g.interface),
                        None => format!("{} on {}", g.ip, g.interface),
                    })
                    .collect(),
                ssids: sig
                    .ssids
                    .iter()
                    .map(|(i, s)| format!("\"{s}\" on {i}"))
                    .collect(),
            },
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::testing::fake_key;

    fn reg(yaml: &str) -> Registry {
        let cfg = Config::parse(yaml, "t").unwrap();
        Registry::new(cfg, PathBuf::from("/tmp/lablink-test-known_hosts"))
    }

    #[test]
    fn ambiguity_notes_are_bounded() {
        let k = fake_key("clone");
        // Config validation rejects shared pins, so pin the same key by hand
        // to model a cloned image.
        let mut r = reg("devices:\n  - name: a\n  - name: b\n");
        for n in ["default/a", "default/b"] {
            r.device_mut(n).unwrap().rec.pinned.push(PinnedKey {
                key_type: k.key_type.clone(),
                fingerprint: k.fingerprint.clone(),
                public_key: k.public_key.clone(),
                source: "trust".into(),
                pinned_at_ms: 1,
            });
        }
        let n = MAX_AMBIGUITY_NOTES + 300;
        for i in 0..n {
            let ip: IpAddr = format!("10.{}.{}.{}", 20 + i / 65_536, (i / 256) % 256, i % 256)
                .parse()
                .unwrap();
            let obs = Observation {
                ip: Some(ip),
                mac: None,
                names: vec![],
                host_keys: vec![k.clone()],
            };
            r.observe(&obs, "test", None, 1_000 + i as u64);
            let notes = r
                .state_sizes()
                .into_iter()
                .find(|(k, _)| *k == "ambiguity_notes");
            assert!(notes.unwrap().1 as usize <= MAX_AMBIGUITY_NOTES);
        }
        // The cap was actually reached and wrapped (not just never filled).
        let notes = r
            .state_sizes()
            .into_iter()
            .find(|(k, _)| *k == "ambiguity_notes");
        let notes = notes.unwrap().1 as usize;
        assert!(notes > 0 && notes < n, "notes={notes}");
    }

    #[test]
    fn resolve_refuses_tunnel_through_unverified_gateway() {
        let mut r = reg("devices:\n  - name: jetson-a\n  - name: payload\n    via: jetson-a\n    expected_ips: [192.168.50.20]\n");
        let k = fake_key("jetson-a");
        {
            let o = r.device_mut("default/jetson-a").unwrap();
            o.rec.current_ip = Some("10.9.0.31".parse().unwrap());
            o.identity = IdentityState::Unverified;
            let p = r.device_mut("default/payload").unwrap();
            p.rec.current_ip = Some("192.168.50.20".parse().unwrap());
        }
        let e = r.resolve("payload").unwrap_err();
        assert_eq!(e.code, ErrorCode::Refused, "{}", e.message);
        assert!(e.message.contains("not verified"), "{}", e.message);
        // Once the gateway is verified against a pin, the tunnel is allowed and
        // carries the gateway's pinned host-key options.
        {
            let o = r.device_mut("default/jetson-a").unwrap();
            o.identity = IdentityState::Verified;
            o.rec.pinned.push(PinnedKey {
                key_type: k.key_type.clone(),
                fingerprint: k.fingerprint.clone(),
                public_key: k.public_key.clone(),
                source: "trust".into(),
                pinned_at_ms: 1,
            });
        }
        let ok = r.resolve("payload").unwrap();
        let pc = ok.proxy_command.unwrap();
        assert!(
            pc.contains("HostKeyAlias=lablink.default.jetson-a")
                && pc.contains("StrictHostKeyChecking=yes"),
            "{pc}"
        );
    }

    #[test]
    fn known_hosts_entry_keyed_by_ip_alone_is_not_enough_for_a_history_only_address() {
        let ip: IpAddr = "10.9.0.77".parse().unwrap();
        let k = fake_key("someone-else");
        let setup = |source: &str, named_at: u64| {
            let mut r = reg("devices:\n  - name: dev\n");
            let d = r.device_mut("default/dev").unwrap();
            d.rec.current_ip = Some(ip);
            d.rec.addresses.push(AddressRecord {
                ip,
                network_name: None,
                interface: None,
                mac: None,
                source: source.into(),
                first_seen_ms: 1,
                last_seen_ms: 1,
                last_adopted_ms: if source == "adopt" { named_at } else { 0 },
            });
            r
        };
        let by_ip = UserKnown {
            by_name: vec![],
            by_ip: vec![k.clone()],
        };
        // History-only address: the IP-keyed entry is ignored.
        let mut r = setup("probe", 0);
        r.apply_keys("default/dev", ip, Ok(vec![k.clone()]), &by_ip, 10);
        assert_eq!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Unverified
        );
        assert!(r.device("default/dev").unwrap().rec.pinned.is_empty());
        // Address from an mDNS/DNS answer (forgeable by anyone on the
        // network): the IP-keyed entry is ignored, nothing is pinned.
        for src in ["mdns", "dns"] {
            let mut r = setup(src, 5);
            r.apply_keys("default/dev", ip, Ok(vec![k.clone()]), &by_ip, 10);
            assert_eq!(
                r.device("default/dev").unwrap().identity,
                IdentityState::Unverified,
                "{src}"
            );
            assert!(r.device("default/dev").unwrap().rec.pinned.is_empty());
        }
        // The user adopted the device at this address: pinned, and Verified
        // once the host proves it holds the key.
        let mut r = setup("adopt", 5);
        r.apply_keys("default/dev", ip, Ok(vec![k.clone()]), &by_ip, 10);
        assert_eq!(r.device("default/dev").unwrap().rec.pinned.len(), 1);
        assert_eq!(r.device("default/dev").unwrap().key_proof_due, Some(ip));
        assert_ne!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Verified
        );
        r.apply_key_proof("default/dev", ip, &KeyProof::Proven, 11);
        assert_eq!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Verified
        );
        // ...but only while that evidence is current (DHCP may have reassigned it).
        let mut r = setup("adopt", 5);
        r.apply_keys(
            "default/dev",
            ip,
            Ok(vec![k.clone()]),
            &by_ip,
            5 + NAME_EVIDENCE_TTL_MS + 1,
        );
        assert_eq!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Unverified
        );
        // Entry keyed by one of the device's names: accepted even for history.
        let mut r = setup("probe", 0);
        let by_name = UserKnown {
            by_name: vec![k.clone()],
            by_ip: vec![],
        };
        r.apply_keys("default/dev", ip, Ok(vec![k]), &by_name, 10);
        assert_eq!(r.device("default/dev").unwrap().key_proof_due, Some(ip));
        r.apply_key_proof("default/dev", ip, &KeyProof::Proven, 11);
        assert_eq!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Verified
        );
    }

    #[test]
    fn losing_the_address_does_not_clear_a_mismatch() {
        let mut r = reg("devices:\n  - name: dev\n");
        let d = r.device_mut("default/dev").unwrap();
        d.rec.current_ip = Some("10.9.0.5".parse().unwrap());
        d.identity = IdentityState::Mismatch;
        assert!(r.release_ip("default/dev", "test".into()));
        assert_eq!(
            r.device("default/dev").unwrap().identity,
            IdentityState::Mismatch
        );
    }
}
