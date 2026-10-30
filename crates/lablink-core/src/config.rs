//! Human-readable YAML configuration with strict validation.
//!
//! Unknown keys are rejected (typos must not silently disable a safety
//! setting), and every semantic error names the offending entry.

use crate::net::{self, AllowedNetwork, Allowlist, ScanRefusal};
use crate::profile::{Capability, Profile};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

/// Top-level configuration file.
///
/// Devices and networks live inside [`SiteConfig`]s. The single-site layout
/// of earlier releases (top-level `networks`, `devices` and `checks`) is still
/// accepted and is read as one site with the id [`DEFAULT_SITE_ID`]; LabLink
/// writes the `sites:` layout whenever it saves the file itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    pub daemon: DaemonConfig,
    pub ssh: SshConfig,
    /// Places the user works at (labs, offices, workshops, ...), each with
    /// its own networks and devices.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<SiteConfig>,
    /// Client preferences (GUI). The daemon ignores this section.
    #[serde(skip_serializing_if = "Preferences::is_default")]
    pub preferences: Preferences,
}

/// Site id given to a configuration written in the single-site layout.
pub const DEFAULT_SITE_ID: &str = "default";
/// Display name of the migrated single site.
pub const DEFAULT_SITE_NAME: &str = "Default";

/// The file as written, before the single-site layout is migrated.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    daemon: DaemonConfig,
    #[serde(default)]
    ssh: SshConfig,
    #[serde(default)]
    sites: Vec<SiteConfig>,
    #[serde(default)]
    networks: Vec<NetworkConfig>,
    #[serde(default)]
    devices: Vec<DeviceConfig>,
    #[serde(default)]
    checks: BTreeMap<String, Vec<crate::checks::CheckSpec>>,
    #[serde(default)]
    preferences: Preferences,
}

impl TryFrom<RawConfig> for Config {
    type Error = String;
    fn try_from(r: RawConfig) -> Result<Self, String> {
        let legacy = !r.networks.is_empty() || !r.devices.is_empty() || !r.checks.is_empty();
        if legacy && !r.sites.is_empty() {
            return Err("top-level `networks`, `devices` and `checks` (the single-site layout) cannot be combined with `sites:`; move them into a site".into());
        }
        let sites = if legacy {
            vec![SiteConfig {
                id: DEFAULT_SITE_ID.into(),
                name: DEFAULT_SITE_NAME.into(),
                auto_detect: true,
                networks: r.networks,
                devices: r.devices,
                checks: r.checks,
            }]
        } else {
            r.sites
        };
        Ok(Config {
            daemon: r.daemon,
            ssh: r.ssh,
            sites,
            preferences: r.preferences,
        })
    }
}

/// One place with its own networks and devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// Short stable id used in `site/device` references (`[a-z0-9-]`, 1-32).
    pub id: String,
    /// Display name ("Robotics Lab").
    pub name: String,
    /// Let `Auto` site mode select this site from network signals. When
    /// false, the site is only used when chosen by hand.
    #[serde(default = "yes")]
    pub auto_detect: bool,
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
    /// Read-only health checks for `lablink doctor`, keyed by device name
    /// (adopted devices of this site work too).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checks: BTreeMap<String, Vec<crate::checks::CheckSpec>>,
}

impl SiteConfig {
    /// An empty site.
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            auto_detect: true,
            networks: vec![],
            devices: vec![],
            checks: BTreeMap::new(),
        }
    }

    /// Find a device of this site by name or alias (case-insensitive).
    pub fn device(&self, name: &str) -> Option<&DeviceConfig> {
        self.devices.iter().find(|d| d.answers_to(name))
    }
}

/// Per-user client preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Preferences {
    /// Terminal emulator for "Open SSH terminal" (program name or absolute
    /// path); empty means `$TERMINAL`, then a list of common emulators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
}

impl Preferences {
    pub fn is_default(&self) -> bool {
        self == &Preferences::default()
    }
}

/// Timing, thresholds and discovery behaviour of `lablinkd`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonConfig {
    /// Health-check interval for reachable devices.
    pub check_interval_s: u64,
    /// Upper bound of the exponential back-off used for unreachable devices.
    pub offline_backoff_max_s: u64,
    /// Consecutive failed checks before ONLINE becomes DEGRADED.
    pub degraded_after: u32,
    /// Consecutive failed checks before the device is OFFLINE.
    pub offline_after: u32,
    /// Consecutive successful checks before OFFLINE becomes ONLINE again.
    pub recover_after: u32,
    /// TCP/22 is probed at most this often while a device is healthy. Liveness
    /// in between uses ICMP, because every TCP probe shows up in the remote
    /// sshd log as a pre-auth disconnect.
    pub port_check_interval_s: u64,
    /// TCP connect timeout per probe.
    pub connect_timeout_ms: u64,
    /// Use unprivileged ICMP echo when TCP gives no answer.
    pub icmp: bool,
    /// Re-verify the SSH login at most this often (0 disables periodic re-checks).
    pub auth_check_interval_s: u64,
    /// Checks of devices reached `via` a gateway run at most this often
    /// (each is one command over the gateway's SSH connection).
    pub via_check_interval_s: u64,
    /// Re-verify the SSH host key at most this often.
    pub identity_check_interval_s: u64,
    /// Background active scan of allowlisted networks (0 disables; startup,
    /// network changes and manual `discover` still scan).
    pub scan_interval_s: u64,
    /// Concurrent TCP probes during an active scan.
    pub scan_concurrency: usize,
    /// Per-scan host limit (clamped to the hard ceiling of 4096).
    pub max_scan_hosts: u32,
    /// Re-resolve configured hostnames for devices without a working address.
    pub resolve_interval_s: u64,
    /// Debounce interval for non-critical cache writes.
    pub persist_interval_s: u64,
    /// Number of history events retained in the cache.
    pub history_retention: u32,
    /// Enable passive mDNS browsing and `.local` resolution.
    pub mdns: bool,
    /// Service types browsed passively when `mdns` is enabled.
    pub mdns_service_types: Vec<String>,
    /// Record unmatched hosts seen in the neighbor table outside the allowlist.
    pub passive_unlisted: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            check_interval_s: 5,
            offline_backoff_max_s: 30,
            degraded_after: 2,
            offline_after: 4,
            recover_after: 2,
            port_check_interval_s: 30,
            connect_timeout_ms: 1500,
            icmp: true,
            auth_check_interval_s: 300,
            identity_check_interval_s: 600,
            via_check_interval_s: 10,
            scan_interval_s: 120,
            scan_concurrency: 32,
            max_scan_hosts: net::DEFAULT_MAX_SCAN_HOSTS,
            resolve_interval_s: 60,
            persist_interval_s: 30,
            history_retention: 10_000,
            mdns: true,
            mdns_service_types: vec![
                "_ssh._tcp.local.".into(),
                "_sftp-ssh._tcp.local.".into(),
                "_workstation._tcp.local.".into(),
            ],
            passive_unlisted: false,
        }
    }
}

/// How LabLink invokes the system OpenSSH client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct SshConfig {
    /// Path or name of the `ssh` binary.
    pub binary: String,
    /// Path or name of the `ssh-keyscan` binary.
    pub keyscan_binary: String,
    /// Path or name of the `ssh-keygen` binary (known_hosts lookups).
    pub keygen_binary: String,
    /// `ConnectTimeout` passed to non-interactive ssh invocations.
    pub connect_timeout_s: u64,
    /// Let background checks (login, service, gateway) reuse an OpenSSH
    /// ControlMaster connection the user already has open. Needed for
    /// password-only servers. A multiplexed session does not re-check the host
    /// key (the master checked it when it connected); set false to force every
    /// background check onto a fresh, LabLink-verified connection.
    pub reuse_control_master: bool,
    /// Extra `-o Key=Value` options appended to every invocation. Only
    /// allowlisted options are accepted (see `ALLOWED_SSH_OPTIONS`); they are
    /// never taken from an imported file.
    pub options: BTreeMap<String, String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            binary: "ssh".into(),
            keyscan_binary: "ssh-keyscan".into(),
            keygen_binary: "ssh-keygen".into(),
            connect_timeout_s: 5,
            reuse_control_master: true,
            options: BTreeMap::new(),
        }
    }
}

/// One allowlisted network of a site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub name: String,
    pub cidr: String,
    #[serde(default)]
    pub active_scan: bool,
    /// Detection hint: the local interface this network is usually on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Detection hint: the default gateway's address on this network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Detection signature: the default gateway's MAC address. Stronger than
    /// the subnet, because many sites use the same private ranges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    /// Detection hint: the Wi-Fi network name (SSID). A hint only: anyone can
    /// broadcast any SSID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
}

impl NetworkConfig {
    /// A network without detection hints.
    pub fn new(name: &str, cidr: &str, active_scan: bool) -> Self {
        Self {
            name: name.into(),
            cidr: cidr.into(),
            active_scan,
            interface: None,
            gateway: None,
            gateway_mac: None,
            ssid: None,
        }
    }
}

/// One device LabLink should track.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    /// Logical name used on the command line (`lablink ssh <name>`).
    pub name: String,
    /// Optional display label for the GUI (e.g. "JETSON A").
    #[serde(default)]
    pub label: Option<String>,
    /// Extra names accepted on the command line.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Candidate login names, tried in order by the SSH health check.
    #[serde(default)]
    pub usernames: Vec<String>,
    /// Hostnames / mDNS names that identify this device.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Addresses the device is expected to use (static leases, fixed IPs).
    #[serde(default)]
    pub expected_ips: Vec<String>,
    /// Names of configured networks the device normally lives on, in order of
    /// preference when it is reachable on several.
    #[serde(default)]
    pub expected_networks: Vec<String>,
    /// Known MAC addresses.
    #[serde(default)]
    pub macs: Vec<String>,
    /// Pinned SSH host-key fingerprints (`SHA256:...`).
    #[serde(default)]
    pub host_key_fingerprints: Vec<String>,
    /// Whether the device runs an SSH server LabLink should monitor.
    #[serde(default = "yes")]
    pub ssh: bool,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    /// Host alias in `~/.ssh/config` whose options (User, IdentityFile,
    /// ControlMaster, ...) should apply. Defaults to the logical name.
    #[serde(default)]
    pub ssh_host: Option<String>,
    /// Periodically verify that SSH login works (BatchMode, keys/agent only).
    #[serde(default = "yes")]
    pub auth_check: bool,
    /// Monitor this device at all.
    #[serde(default = "yes")]
    pub monitor: bool,
    #[serde(default)]
    pub notes: Option<String>,
    /// Reach this device through another device (a gateway such as the
    /// Jetson in front of the robot's internal network) when its address is
    /// not on a directly attached network. The gateway must have ssh enabled.
    #[serde(default)]
    pub via: Option<String>,
    /// Optional service checks (extension point; see docs/ARCHITECTURE.md).
    #[serde(default)]
    pub services: Vec<ServiceCheckConfig>,
    /// Optional profile: selects default `lablink doctor` checks and implies
    /// capabilities (see `lablink_core::profile`).
    #[serde(default)]
    pub profile: Option<Profile>,
    /// Extra capabilities beyond what `ssh`, `via` and the profile imply.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// A user-defined service check: a command run on the device over SSH
/// (BatchMode). Exit 0 = ok, 1 = degraded, anything else = failed. This keeps
/// robot-specific knowledge (ROS 2, DDS, GPU, ...) out of LabLink's core.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServiceCheckConfig {
    pub name: String,
    pub command: String,
    #[serde(default = "default_service_interval")]
    pub interval_s: u64,
    #[serde(default = "default_service_timeout")]
    pub timeout_s: u64,
}

fn default_service_interval() -> u64 {
    60
}
fn default_service_timeout() -> u64 {
    10
}

fn yes() -> bool {
    true
}
fn default_ssh_port() -> u16 {
    22
}

/// A configuration problem.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {message}")]
    Parse { path: String, message: String },
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// The only OpenSSH options accepted in `ssh.options` (lower case). This is an
/// allowlist: anything else could weaken host-key checking or addressing
/// (`StrictHostKeyChecking`, `HostName`, `ProxyCommand`, ...), run or load
/// code (`LocalCommand`, `PKCS11Provider`, `SecurityKeyProvider`, ...), hand
/// the device the user's agent or display (`ForwardAgent`, `ForwardX11*`),
/// open listeners (`*Forward`, `Tunnel`) or send local environment
/// (`SetEnv`, `SendEnv`). LabLink sets addressing, host-key and batch options
/// itself.
const ALLOWED_SSH_OPTIONS: &[&str] = &[
    "addressfamily",
    "certificatefile",
    "ciphers",
    "compression",
    "connectionattempts",
    "fingerprinthash",
    "gssapiauthentication",
    "hostkeyalgorithms",
    "identitiesonly",
    "identityfile",
    "ipqos",
    "kbdinteractiveauthentication",
    "kexalgorithms",
    "loglevel",
    "macs",
    "numberofpasswordprompts",
    "passwordauthentication",
    "preferredauthentications",
    "pubkeyacceptedalgorithms",
    "pubkeyauthentication",
    "rekeylimit",
    "serveralivecountmax",
    "serveraliveinterval",
    "tcpkeepalive",
];

/// Options accepted only to switch a feature OFF (value `no`).
const OFF_ONLY_SSH_OPTIONS: &[&str] = &["forwardagent", "forwardx11", "forwardx11trusted"];

/// Why `ssh.options.<k>` is refused, or None when it is acceptable.
fn ssh_option_problem(k: &str, v: &str) -> Option<String> {
    let lk = k.to_ascii_lowercase();
    if OFF_ONLY_SSH_OPTIONS.contains(&lk.as_str()) {
        if v.trim().eq_ignore_ascii_case("no") {
            return None;
        }
        return Some(format!(
            "ssh.options.{k} may only be 'no': LabLink never forwards your agent or display to a device"
        ));
    }
    if !ALLOWED_SSH_OPTIONS.contains(&lk.as_str()) {
        return Some(format!(
            "ssh.options.{k} is not allowed: LabLink controls host-key verification, addressing and forwarding itself (allowed: {})",
            ALLOWED_SSH_OPTIONS.join(", ")
        ));
    }
    if !valid_ssh_option(k, v) {
        return Some(format!(
            "ssh.options.{k}: option names are letters only and values must be one line without '=' tricks"
        ));
    }
    None
}

/// Largest configuration file LabLink reads (import files too).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Deepest flow-collection (`[...]`, `{...}`) nesting a configuration may
/// use. Real configs need 2; the YAML parser's cost grows faster than
/// linearly with depth, so a 64 KB file of nested brackets would otherwise
/// cost seconds of CPU and a 400 KB one minutes.
pub const MAX_YAML_FLOW_DEPTH: usize = 64;

/// Most `[` and `{` characters a configuration may contain, wherever they
/// are (inside quotes and comments too). Nesting can never be deeper than
/// this count, so it bounds the parser's cost even if the depth lexer below
/// disagrees with the YAML grammar somewhere. LabLink writes block style;
/// hand-written configs need a handful.
pub const MAX_YAML_FLOW_OPENERS: usize = 4096;

/// Most alias references (`*name`) a configuration may contain. Each one
/// is a full copy of its anchor when parsed, so many references to one deep
/// anchor cost seconds even though nothing is nested deeply. LabLink writes
/// no anchors.
pub const MAX_YAML_ALIASES: usize = 64;

/// Refuse YAML whose flow collections nest deeper than
/// [`MAX_YAML_FLOW_DEPTH`], before handing it to the parser. Quoted scalars
/// and comments are skipped; a quote only opens a scalar at the start of a
/// token, as in YAML, so an apostrophe inside a plain word cannot hide
/// brackets from the count.
pub fn check_yaml_nesting(text: &str) -> Result<(), String> {
    let b = text.as_bytes();
    let openers = b.iter().filter(|c| matches!(c, b'[' | b'{')).count();
    if openers > MAX_YAML_FLOW_OPENERS {
        return Err(format!(
            "the file has {openers} '[' or '{{' characters; LabLink configurations allow at most {MAX_YAML_FLOW_OPENERS} (use block style)"
        ));
    }
    let (mut depth, mut max, mut i, mut aliases) = (0usize, 0usize, 0usize, 0usize);
    let token_start = |i: usize| {
        i == 0
            || matches!(
                b[i - 1],
                // YAML needs whitespace after ':' and '-', so a quote right
                // after them is plain text (counting on is the safe side).
                b' ' | b'\t' | b'\n' | b'\r' | b'[' | b'{' | b','
            )
    };
    while i < b.len() {
        match b[i] {
            b'#' if token_start(i) => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' if token_start(i) => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' if token_start(i) => {
                i += 1;
                while i < b.len() {
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    i += 1;
                }
            }
            b'*' if token_start(i) => {
                aliases += 1;
                if aliases > MAX_YAML_ALIASES {
                    return Err(format!(
                        "more than {MAX_YAML_ALIASES} YAML aliases (*name); LabLink configurations do not need them"
                    ));
                }
            }
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    if max > MAX_YAML_FLOW_DEPTH {
        return Err(format!(
            "brackets nest {max} levels deep; LabLink configurations allow at most {MAX_YAML_FLOW_DEPTH}"
        ));
    }
    Ok(())
}

impl Config {
    /// Load and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let io = |source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        };
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let refuse = |message: String| ConfigError::Parse {
            path: path.display().to_string(),
            message,
        };
        // A missing file stays an I/O error (NotFound), which callers handle.
        std::fs::metadata(path).map_err(io)?;
        // The configuration names the programs LabLink runs and the keys it
        // trusts, so a file another user could have written is refused, and
        // so is anything that cannot be resolved to a file (`/dev/stdin` on
        // a pipe, `<(...)`). LabLink replaces the file atomically while it
        // writes, so a swap between the check and the open is retried a few
        // times; every attempt checks the file it then reads, and a path
        // that keeps changing is still refused.
        let mut attempts = 0;
        let (mut file, opened) = loop {
            attempts += 1;
            let checked = crate::paths::trusted_metadata(path).map_err(|why| {
                refuse(if why.starts_with("cannot check") {
                    format!("refusing the configuration: {why}")
                } else {
                    format!("refusing a configuration other users can change: {why}")
                })
            })?;
            if !checked.is_file() {
                return Err(refuse("not a regular file".into()));
            }
            // Read the very file that was checked, not whatever the path
            // names by the time it is opened.
            let file = std::fs::File::open(path).map_err(io)?;
            let opened = file.metadata().map_err(io)?;
            if (opened.dev(), opened.ino()) == (checked.dev(), checked.ino()) {
                break (file, opened);
            }
            if attempts >= 5 {
                return Err(refuse(
                    "the file was replaced while it was being checked".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let len = opened.len();
        if len > MAX_CONFIG_BYTES {
            return Err(refuse(format!(
                "file is {len} bytes; the limit is {MAX_CONFIG_BYTES}"
            )));
        }
        let mut text = String::new();
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        Self::parse(&text, &path.display().to_string())
    }

    /// Parse and validate configuration text. `origin` is used in messages.
    pub fn parse(text: &str, origin: &str) -> Result<Self, ConfigError> {
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Parse {
                path: origin.to_string(),
                message: format!("text is larger than {MAX_CONFIG_BYTES} bytes"),
            });
        }
        check_yaml_nesting(text).map_err(|message| ConfigError::Parse {
            path: origin.to_string(),
            message,
        })?;
        let cfg: Config = if text.trim().is_empty() {
            Config::default()
        } else {
            yaml_serde::from_str(text).map_err(|e| ConfigError::Parse {
                path: origin.to_string(),
                message: e.to_string(),
            })?
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Semantic validation. Collects every problem rather than stopping at the first.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errs = Vec::new();
        let d = &self.daemon;

        if d.check_interval_s == 0 {
            errs.push("daemon.check_interval_s must be at least 1".into());
        }
        if d.offline_backoff_max_s < d.check_interval_s {
            errs.push("daemon.offline_backoff_max_s must be >= daemon.check_interval_s".into());
        }
        if d.degraded_after == 0 || d.offline_after <= d.degraded_after {
            errs.push(format!(
                "daemon thresholds need 1 <= degraded_after < offline_after (got degraded_after={}, offline_after={})",
                d.degraded_after, d.offline_after
            ));
        }
        if d.port_check_interval_s < d.check_interval_s {
            errs.push("daemon.port_check_interval_s must be >= daemon.check_interval_s".into());
        }
        if d.recover_after == 0 {
            errs.push("daemon.recover_after must be at least 1".into());
        }
        if !(100..=30_000).contains(&d.connect_timeout_ms) {
            errs.push("daemon.connect_timeout_ms must be between 100 and 30000".into());
        }
        if d.scan_interval_s != 0 && d.scan_interval_s < 30 {
            errs.push("daemon.scan_interval_s must be 0 (disabled) or at least 30".into());
        }
        if d.via_check_interval_s < d.check_interval_s {
            errs.push("daemon.via_check_interval_s must be >= daemon.check_interval_s".into());
        }
        if d.identity_check_interval_s < 30 {
            errs.push("daemon.identity_check_interval_s must be at least 30".into());
        }
        if d.auth_check_interval_s != 0 && d.auth_check_interval_s < 30 {
            errs.push("daemon.auth_check_interval_s must be 0 (disabled) or at least 30".into());
        }
        if !(1..=256).contains(&d.scan_concurrency) {
            errs.push("daemon.scan_concurrency must be between 1 and 256".into());
        }
        if d.max_scan_hosts == 0 || d.max_scan_hosts > net::HARD_MAX_SCAN_HOSTS {
            errs.push(format!(
                "daemon.max_scan_hosts must be between 1 and {} (hard ceiling)",
                net::HARD_MAX_SCAN_HOSTS
            ));
        }
        for t in &d.mdns_service_types {
            if !t.ends_with("._tcp.local.") && !t.ends_with("._udp.local.") {
                errs.push(format!(
                    "daemon.mdns_service_types: '{t}' must look like '_ssh._tcp.local.'"
                ));
            }
        }
        if self.ssh.connect_timeout_s == 0 || self.ssh.connect_timeout_s > 120 {
            errs.push("ssh.connect_timeout_s must be between 1 and 120".into());
        }
        for (k, v) in &self.ssh.options {
            if let Some(e) = ssh_option_problem(k, v) {
                errs.push(e);
            }
        }
        for (what, bin) in [
            ("ssh.binary", &self.ssh.binary),
            ("ssh.keyscan_binary", &self.ssh.keyscan_binary),
            ("ssh.keygen_binary", &self.ssh.keygen_binary),
        ] {
            if !valid_program(bin) {
                errs.push(format!(
                    "{what} '{bin}' must be a program name or absolute path of [A-Za-z0-9_.+/-]"
                ));
            }
        }

        let mut site_ids = BTreeSet::new();
        let mut site_names = BTreeSet::new();
        for (si, site) in self.sites.iter().enumerate() {
            let at = format!("sites[{si}] ({})", site.id);
            if !valid_site_id(&site.id) {
                errs.push(format!(
                    "{at}: id must match [a-z0-9][a-z0-9-]* (1-32 characters, lower case)"
                ));
            }
            if !site_ids.insert(site.id.to_ascii_lowercase()) {
                errs.push(format!("{at}: duplicate site id"));
            }
            if !valid_display_name(&site.name) {
                errs.push(format!("{at}: name must be 1-64 printable characters"));
            } else if !site_names.insert(site.name.trim().to_lowercase()) {
                errs.push(format!(
                    "{at}: another site is already called '{}'",
                    site.name
                ));
            }
            validate_site(self, site, &at, &mut errs);
        }

        if let Some(t) = &self.preferences.terminal {
            if !valid_program(t) {
                errs.push(format!(
                    "preferences.terminal '{t}' must be a program name or absolute path of [A-Za-z0-9_.+/-]"
                ));
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(errs))
        }
    }

    /// The network allowlist derived from this configuration (every site).
    pub fn allowlist(&self) -> Allowlist {
        Allowlist {
            networks: self
                .sites
                .iter()
                .flat_map(|s| {
                    s.networks.iter().filter_map(|n| {
                        net::parse_cidr(&n.cidr).ok().map(|net| AllowedNetwork {
                            site: s.id.clone(),
                            name: n.name.clone(),
                            net,
                            active_scan: n.active_scan,
                        })
                    })
                })
                .collect(),
            max_scan_hosts: self.daemon.max_scan_hosts,
        }
    }

    /// Serialize as YAML without keys whose value equals the default, so a
    /// file written by LabLink (init, settings, import) stays as short as a
    /// hand-written one. Parsing the result gives back an equal `Config`.
    pub fn to_yaml(&self) -> String {
        use yaml_serde::Value;
        fn prune(v: &mut Value, default: &Value) {
            if let (Value::Mapping(m), Value::Mapping(d)) = (v, default) {
                m.retain(|k, val| d.get(k) != Some(val));
            }
        }
        fn to<T: Serialize>(x: &T) -> Value {
            yaml_serde::to_value(x).unwrap_or(Value::Null)
        }
        fn non_empty(v: &Value) -> bool {
            match v {
                Value::Mapping(x) => !x.is_empty(),
                Value::Sequence(x) => !x.is_empty(),
                Value::Null => false,
                _ => true,
            }
        }
        let mut root = to(self);
        if let Value::Mapping(m) = &mut root {
            let dflt = to(&Config::default());
            for key in ["daemon", "ssh", "preferences"] {
                if let (Some(v), Some(d)) = (m.get_mut(key), dflt.get(key)) {
                    prune(v, d);
                }
            }
            if let Some(Value::Sequence(sites)) = m.get_mut("sites") {
                for (sv, site) in sites.iter_mut().zip(&self.sites) {
                    let Value::Mapping(sm) = sv else { continue };
                    if sm.get("auto_detect") == Some(&Value::Bool(true)) {
                        sm.remove("auto_detect");
                    }
                    if let Some(Value::Sequence(nets)) = sm.get_mut("networks") {
                        for n in nets.iter_mut() {
                            if let Value::Mapping(nm) = n {
                                if nm.get("active_scan") == Some(&Value::Bool(false)) {
                                    nm.remove("active_scan");
                                }
                            }
                        }
                    }
                    if let Some(Value::Sequence(devs)) = sm.get_mut("devices") {
                        for (d, cfg) in devs.iter_mut().zip(&site.devices) {
                            let base = to(&DeviceConfig::named(&cfg.name));
                            if let Value::Mapping(dm) = d {
                                dm.retain(|k, val| {
                                    k.as_str() == Some("name") || base.get(k) != Some(val)
                                });
                            }
                        }
                    }
                    sm.retain(|k, v| matches!(k.as_str(), Some("id" | "name")) || non_empty(v));
                }
            }
            m.retain(|_, v| non_empty(v));
        }
        if root.as_mapping().is_some_and(|m| m.is_empty()) {
            return String::new();
        }
        let yaml = yaml_serde::to_string(&root).unwrap_or_default();
        if check_yaml_nesting(&yaml).is_ok() {
            return yaml;
        }
        // The emitter may write strings as plain or block scalars, which our
        // deliberately conservative input guard counts as YAML structure.
        // Retry in block style with every string JSON-quoted (valid YAML).
        // Keep the input guard unchanged, including the total opener cap.
        fn quoted_blocks(v: &Value, indent: usize, out: &mut String) {
            let pad = " ".repeat(indent);
            match v {
                Value::Mapping(m) if !m.is_empty() => {
                    for (key, val) in m {
                        out.push_str(&pad);
                        out.push_str(&serde_json::to_string(key).unwrap());
                        out.push(':');
                        field(val, indent, out);
                    }
                }
                Value::Sequence(a) if !a.is_empty() => {
                    for val in a {
                        out.push_str(&pad);
                        out.push('-');
                        field(val, indent, out);
                    }
                }
                _ => {
                    out.push_str(&pad);
                    out.push_str(&serde_json::to_string(v).unwrap());
                    out.push('\n');
                }
            }
        }
        fn field(v: &Value, indent: usize, out: &mut String) {
            if matches!(v, Value::Mapping(m) if !m.is_empty())
                || matches!(v, Value::Sequence(a) if !a.is_empty())
            {
                out.push('\n');
                quoted_blocks(v, indent + 2, out);
            } else {
                out.push(' ');
                out.push_str(&serde_json::to_string(v).unwrap());
                out.push('\n');
            }
        }
        let mut quoted = String::new();
        quoted_blocks(&root, 0, &mut quoted);
        quoted
    }

    /// Find a site by id (case-insensitive).
    pub fn site(&self, id: &str) -> Option<&SiteConfig> {
        self.sites.iter().find(|s| s.id.eq_ignore_ascii_case(id))
    }

    /// Mutable site by id (case-insensitive).
    pub fn site_mut(&mut self, id: &str) -> Option<&mut SiteConfig> {
        self.sites
            .iter_mut()
            .find(|s| s.id.eq_ignore_ascii_case(id))
    }

    /// Every configured device with its site.
    pub fn devices(&self) -> impl Iterator<Item = (&SiteConfig, &DeviceConfig)> {
        self.sites
            .iter()
            .flat_map(|s| s.devices.iter().map(move |d| (s, d)))
    }

    /// Every configured network with its site.
    pub fn networks(&self) -> impl Iterator<Item = (&SiteConfig, &NetworkConfig)> {
        self.sites
            .iter()
            .flat_map(|s| s.networks.iter().map(move |n| (s, n)))
    }

    /// Number of configured devices over all sites.
    pub fn device_count(&self) -> usize {
        self.sites.iter().map(|s| s.devices.len()).sum()
    }

    /// Number of configured networks over all sites.
    pub fn network_count(&self) -> usize {
        self.sites.iter().map(|s| s.networks.len()).sum()
    }

    /// Configured devices answering to `reference`: `site/name` or a bare
    /// name or alias (which may match devices at several sites).
    pub fn find_devices(&self, reference: &str) -> Vec<(&SiteConfig, &DeviceConfig)> {
        match split_ref(reference) {
            (Some(site), name) => self
                .site(site)
                .and_then(|s| s.device(name).map(|d| (s, d)))
                .into_iter()
                .collect(),
            (None, name) => self.devices().filter(|(_, d)| d.answers_to(name)).collect(),
        }
    }

    /// `doctor` checks keyed by device id (`site/name`).
    pub fn checks_by_id(&self) -> BTreeMap<String, Vec<crate::checks::CheckSpec>> {
        let mut out = BTreeMap::new();
        for s in &self.sites {
            for (dev, specs) in &s.checks {
                let name = s.device(dev).map(|d| d.name.as_str()).unwrap_or(dev);
                out.insert(device_id(&s.id, name), specs.clone());
            }
        }
        out
    }
}

/// Validation of one site: names, identity signals and gateways are unique
/// within the site (other sites may reuse the same private addresses).
fn validate_site(cfg: &Config, site: &SiteConfig, at_site: &str, errs: &mut Vec<String>) {
    let d = &cfg.daemon;
    let mut net_names = BTreeSet::new();
    for (i, n) in site.networks.iter().enumerate() {
        let at = format!("{at_site}.networks[{i}] ({})", n.name);
        if !valid_name(&n.name) {
            errs.push(format!(
                "{at}: name must match [A-Za-z0-9_.-]+ (1-64 chars)"
            ));
        }
        if !net_names.insert(n.name.to_ascii_lowercase()) {
            errs.push(format!("{at}: duplicate network name"));
        }
        match net::parse_cidr(&n.cidr) {
            Err(e) => errs.push(format!("{at}: {e}")),
            Ok(parsed) => {
                if n.active_scan {
                    if let Err(e) = net::validate_scan_range(&parsed.to_string(), d.max_scan_hosts)
                    {
                        let hint = match e {
                            ScanRefusal::TooLarge { .. } => {
                                " (set active_scan: false for passive-only monitoring of large networks)"
                            }
                            _ => "",
                        };
                        errs.push(format!("{at}: active_scan refused: {e}{hint}"));
                    }
                }
                if let Some(g) = &n.gateway {
                    match g.parse::<IpAddr>() {
                        Ok(ip) if parsed.contains(&ip) => {}
                        Ok(_) => errs.push(format!("{at}: gateway {g} is not inside {}", n.cidr)),
                        Err(_) => errs.push(format!("{at}: gateway '{g}' is not an IP address")),
                    }
                }
            }
        }
        if let Some(i) = &n.interface {
            if !valid_interface(i) {
                errs.push(format!(
                    "{at}: interface '{i}' is not a valid interface name"
                ));
            }
        }
        if let Some(m) = &n.gateway_mac {
            if normalize_mac(m).is_none() {
                errs.push(format!(
                    "{at}: gateway_mac '{m}' is not a valid MAC address"
                ));
            }
        }
        if let Some(s) = &n.ssid {
            if !valid_ssid(s) {
                errs.push(format!(
                    "{at}: ssid must be 1-32 bytes without control characters"
                ));
            }
        }
    }

    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut hostnames: BTreeMap<String, String> = BTreeMap::new();
    let mut ips: BTreeMap<IpAddr, String> = BTreeMap::new();
    let mut macs: BTreeMap<String, String> = BTreeMap::new();
    let mut fps: BTreeMap<String, String> = BTreeMap::new();
    for (i, dev) in site.devices.iter().enumerate() {
        let at = format!("{at_site}.devices[{i}] ({})", dev.name);
        if !valid_name(&dev.name) {
            errs.push(format!(
                "{at}: name must match [A-Za-z0-9_.-]+ (1-64 chars)"
            ));
        }
        if let Some(n) = &dev.notes {
            if !valid_notes(n) {
                errs.push(format!(
                    "{at}: notes must be at most 2000 characters, without control characters other than newline and tab"
                ));
            }
        }
        for n in std::iter::once(&dev.name).chain(dev.aliases.iter()) {
            let key = n.to_ascii_lowercase();
            if n != &dev.name && !valid_name(n) {
                errs.push(format!("{at}: alias '{n}' must match [A-Za-z0-9_.-]+"));
            }
            if let Some(prev) = names.insert(key, dev.name.clone()) {
                if prev != dev.name || n != &dev.name {
                    errs.push(format!(
                        "{at}: name/alias '{n}' is already used by device '{prev}'"
                    ));
                }
            }
        }
        let mut own_hosts = BTreeSet::new();
        for h in &dev.hostnames {
            if !valid_hostname(h) {
                errs.push(format!("{at}: hostname '{h}' is not a valid hostname"));
                continue;
            }
            let key = normalize_hostname(h);
            if !own_hosts.insert(key.clone()) {
                continue; // "x" and "x.local" in one device are fine.
            }
            if let Some(prev) = hostnames.insert(key, dev.name.clone()) {
                errs.push(format!(
                    "{at}: hostname '{h}' is already claimed by device '{prev}'"
                ));
            }
        }
        for s in &dev.expected_ips {
            match s.parse::<IpAddr>() {
                Err(_) => errs.push(format!(
                    "{at}: expected_ips entry '{s}' is not a valid IP address"
                )),
                Ok(ip) => {
                    if let Some(prev) = ips.insert(ip, dev.name.clone()) {
                        errs.push(format!(
                            "{at}: expected IP {ip} is already claimed by device '{prev}'"
                        ));
                    }
                }
            }
        }
        for m in &dev.macs {
            match normalize_mac(m) {
                None => errs.push(format!(
                    "{at}: '{m}' is not a valid MAC address (aa:bb:cc:dd:ee:ff)"
                )),
                Some(norm) => {
                    if let Some(prev) = macs.insert(norm, dev.name.clone()) {
                        errs.push(format!(
                            "{at}: MAC {m} is already claimed by device '{prev}'"
                        ));
                    }
                }
            }
        }
        for f in &dev.host_key_fingerprints {
            if !valid_fingerprint(f) {
                errs.push(format!(
                    "{at}: host_key_fingerprints entry '{f}' must be an OpenSSH SHA256 fingerprint (SHA256:<43 base64 chars>)"
                ));
            } else if let Some(prev) = fps.insert(f.clone(), dev.name.clone()) {
                // Cloned OS images can share host keys; allowed, but only
                // when other signals can tell the devices apart.
                if dev.macs.is_empty() && dev.hostnames.is_empty() && dev.expected_ips.is_empty() {
                    errs.push(format!(
                        "{at}: fingerprint {f} is shared with device '{prev}' and no MAC/hostname/IP is configured to tell them apart"
                    ));
                }
            }
        }
        for n in &dev.expected_networks {
            if !site.networks.iter().any(|x| &x.name == n) {
                errs.push(format!(
                    "{at}: expected_networks refers to unknown network '{n}' (networks of site '{}')",
                    site.id
                ));
            }
        }
        for u in &dev.usernames {
            if !valid_username(u) {
                errs.push(format!(
                    "{at}: username '{u}' contains characters not allowed in a login name"
                ));
            }
        }
        if let Some(l) = &dev.label {
            if !valid_display_name(l) {
                errs.push(format!("{at}: label must be 1-64 printable characters"));
            }
        }
        if let Some(h) = &dev.ssh_host {
            if !valid_ssh_host_alias(h) {
                errs.push(format!(
                    "{at}: ssh_host '{h}' must be a plain Host alias from ~/.ssh/config"
                ));
            }
        }
        if let Some(gw) = &dev.via {
            match site.devices.iter().find(|x| &x.name == gw) {
                None => errs.push(format!(
                    "{at}: via refers to unknown device '{gw}' (devices of site '{}')",
                    site.id
                )),
                Some(g) if g.name == dev.name => errs.push(format!("{at}: a device cannot be its own gateway")),
                Some(g) if !g.ssh => errs.push(format!("{at}: gateway '{gw}' must have ssh: true")),
                Some(g) if g.via.is_some() => errs.push(format!("{at}: gateway '{gw}' is itself reached via another device (only one hop is supported)")),
                Some(_) => {}
            }
            if dev.expected_ips.is_empty() {
                errs.push(format!("{at}: a device reached via a gateway needs expected_ips (it cannot be discovered from here)"));
            }
        }
        let mut svc_names = BTreeSet::new();
        for s in &dev.services {
            if !valid_name(&s.name) || !svc_names.insert(s.name.clone()) {
                errs.push(format!(
                    "{at}: service name '{}' must be unique and match [A-Za-z0-9_.-]+",
                    s.name
                ));
            }
            if s.command.trim().is_empty() || s.command.len() > 1000 {
                errs.push(format!(
                    "{at}: service '{}' needs a command of 1-1000 characters",
                    s.name
                ));
            }
            if s.interval_s < 10 || s.timeout_s == 0 || s.timeout_s >= s.interval_s {
                errs.push(format!(
                    "{at}: service '{}' needs interval_s >= 10 and 0 < timeout_s < interval_s",
                    s.name
                ));
            }
            if !dev.ssh {
                errs.push(format!("{at}: service '{}' requires ssh: true", s.name));
            }
        }
        if dev.ssh_port == 0 {
            errs.push(format!("{at}: ssh_port must be 1-65535"));
        }
        if let Some(p) = dev.profile {
            if !p.uses_ssh() && dev.ssh {
                errs.push(format!("{at}: profile {} needs ssh: false", p.as_str()));
            }
        }
        if !dev.ssh && dev.capabilities.contains(&Capability::Ssh) {
            errs.push(format!("{at}: capability ssh contradicts ssh: false"));
        }
        if dev.capabilities.contains(&Capability::Gateway) {
            errs.push(format!(
                "{at}: capability gateway is derived from other devices' `via:` and cannot be declared"
            ));
        }
    }

    for (dev, specs) in &site.checks {
        if !valid_name(dev) {
            errs.push(format!(
                "{at_site}.checks.{dev}: device name must match [A-Za-z0-9_.-]+ (1-64 chars)"
            ));
        }
        for (i, spec) in specs.iter().enumerate() {
            if let Err(e) = spec.validate() {
                errs.push(format!(
                    "{at_site}.checks.{dev}[{i}] ({}): {e}",
                    spec.kind()
                ));
            }
        }
    }
}

/// True when `text` uses the single-site layout (top-level `networks`,
/// `devices` or `checks`), which LabLink reads as site `default`.
pub fn uses_legacy_layout(text: &str) -> bool {
    yaml_serde::from_str::<yaml_serde::Value>(text)
        .ok()
        .and_then(|v| {
            v.as_mapping().map(|m| {
                ["networks", "devices", "checks"]
                    .iter()
                    .any(|k| m.contains_key(*k))
            })
        })
        .unwrap_or(false)
}

/// Canonical device reference: `site/name`.
pub fn device_id(site: &str, name: &str) -> String {
    format!("{site}/{name}")
}

/// Split `site/name` into its parts; a bare name has no site.
pub fn split_ref(s: &str) -> (Option<&str>, &str) {
    match s.split_once('/') {
        Some((site, name)) => (Some(site), name),
        None => (None, s),
    }
}

impl DeviceConfig {
    /// A minimal device definition (used for devices adopted at runtime).
    pub fn named(name: &str) -> Self {
        Self {
            name: name.into(),
            label: None,
            aliases: vec![],
            usernames: vec![],
            hostnames: vec![],
            expected_ips: vec![],
            expected_networks: vec![],
            macs: vec![],
            host_key_fingerprints: vec![],
            ssh: true,
            ssh_port: 22,
            ssh_host: None,
            auth_check: true,
            monitor: true,
            notes: None,
            services: vec![],
            via: None,
            profile: None,
            capabilities: vec![],
        }
    }

    /// Parsed `expected_ips` (invalid entries are rejected by validation).
    pub fn expected_ip_addrs(&self) -> Vec<IpAddr> {
        self.expected_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    /// Normalized MACs.
    pub fn normalized_macs(&self) -> Vec<String> {
        self.macs.iter().filter_map(|m| normalize_mac(m)).collect()
    }

    /// Whether `name` is this device's name or one of its aliases
    /// (case-insensitive).
    pub fn answers_to(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
            || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))
    }
}

/// Logical names: short, shell-safe, no whitespace.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !s.starts_with('-')
}

/// RFC 1123-ish hostname, optional trailing dot.
pub fn valid_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !l.starts_with('-')
        })
}

/// Lower-case, without trailing dot or a `.local` suffix, so that
/// `robot-host`, `Robot-Host.local` and `robot-host.local.` compare equal.
pub fn normalize_hostname(s: &str) -> String {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    s.strip_suffix(".local").map(str::to_string).unwrap_or(s)
}

/// Canonical `aa:bb:cc:dd:ee:ff`; accepts `:` or `-` separators.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    let mac = parts.join(":").to_ascii_lowercase();
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
        return None;
    }
    Some(mac)
}

/// `SHA256:` followed by 43 unpadded standard-base64 characters.
pub fn valid_fingerprint(s: &str) -> bool {
    match s.strip_prefix("SHA256:") {
        Some(b) => {
            b.len() == 43
                && b.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        }
        None => false,
    }
}

/// POSIX-portable login names (plus a few common extras).
pub fn valid_username(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// A program name or absolute path without whitespace or shell syntax.
pub fn valid_program(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('-')
        && (s.starts_with('/') || !s.contains('/'))
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/'))
}

/// Site ids: lower-case letters, digits and '-', 1-32 characters, starting
/// with a letter or digit. They appear in `site/device` references and in
/// the HostKeyAlias LabLink writes, so no '/', '.' or whitespace.
pub fn valid_site_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
}

/// Free-text notes: at most 2000 characters; newlines and tabs are fine,
/// other control characters (terminal escape sequences) are not.
pub fn valid_notes(s: &str) -> bool {
    s.chars().count() <= 2000 && !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

/// A display name (site name, label): 1-64 printable characters.
pub fn valid_display_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && s.chars().count() <= 64 && !s.chars().any(char::is_control)
}

/// A Linux interface name (IFNAMSIZ - 1 bytes, no '/' or whitespace).
pub fn valid_interface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@'))
}

/// A Wi-Fi SSID: 1-32 bytes, no control characters.
pub fn valid_ssid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && !s.chars().any(char::is_control)
}

/// Derive a site id from a display name ("Makerspace" -> "makerspace").
pub fn site_id_from_name(name: &str) -> String {
    let mut id = String::new();
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            id.push(c.to_ascii_lowercase());
        } else if !id.is_empty() && !id.ends_with('-') {
            id.push('-');
        }
        if id.len() >= 32 {
            break;
        }
    }
    let id = id.trim_matches('-').to_string();
    if id.is_empty() {
        "site".into()
    } else {
        id
    }
}

/// `ssh.options` entries: an option name of letters and digits, and a
/// one-line value (no newline, no NUL) that cannot smuggle a second option.
fn valid_ssh_option(k: &str, v: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.chars().all(|c| c.is_ascii_alphanumeric())
        && v.len() <= 1024
        && !v.chars().any(|c| c.is_control())
}

/// A Host alias: must not start with '-' (option injection) and has no
/// whitespace, wildcards or user@ prefix.
pub fn valid_ssh_host_alias(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
networks:
  - name: robot_net
    cidr: 192.168.50.0/24
    active_scan: true
  - name: lab_lan
    cidr: 192.168.10.0/24
    active_scan: true

devices:
  - name: jetson-a
    usernames: [ops]
    hostnames: [jetson-a-host, jetson-a-host.local]
    expected_networks: [robot_net, lab_lan]
    expected_ips: [192.168.50.18]
  - name: robot-a
    ssh: false
    expected_ips: [192.168.50.161]
  - name: jetson-b
    usernames: [ops2]
    hostnames: [jetson-b-host, jetson-b-host.local]
"#;

    fn errors(text: &str) -> Vec<String> {
        match Config::parse(text, "test.yaml") {
            Err(ConfigError::Invalid(v)) => v,
            Err(e) => vec![e.to_string()],
            Ok(_) => vec![],
        }
    }

    #[test]
    fn example_parses() {
        let c = Config::parse(EXAMPLE, "example").unwrap();
        assert_eq!(c.device_count(), 3);
        assert!(!c.sites[0].devices[1].ssh);
        assert_eq!(c.daemon.check_interval_s, 5);
        assert_eq!(c.allowlist().networks.len(), 2);
        assert_eq!(c.find_devices("JETSON-A")[0].1.name, "jetson-a");
    }

    #[test]
    fn empty_file_is_default() {
        let c = Config::parse("", "empty").unwrap();
        assert_eq!(c.device_count(), 0);
        assert!(c.sites.is_empty());
    }

    #[test]
    fn unknown_keys_rejected() {
        let e = errors("networks:\n  - name: a\n    cidr: 192.168.1.0/24\n    activescan: true\n");
        assert!(e[0].contains("activescan"), "{e:?}");
        let e = errors("daemon:\n  chek_interval_s: 3\n");
        assert!(e[0].contains("chek_interval_s"), "{e:?}");
    }

    #[test]
    fn malformed_yaml_reports_location() {
        let e = errors("devices:\n  - name: [unclosed\n");
        assert!(e[0].contains("test.yaml"), "{e:?}");
        assert!(e[0].contains("line"), "{e:?}");
    }

    #[test]
    fn huge_active_network_rejected_with_hint() {
        let e =
            errors("networks:\n  - name: campus\n    cidr: 10.0.0.0/8\n    active_scan: true\n");
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("above the scan limit"), "{e:?}");
        assert!(e[0].contains("active_scan: false"), "{e:?}");
        // The same network passively is fine.
        assert!(errors("networks:\n  - name: campus\n    cidr: 10.0.0.0/8\n").is_empty());
    }

    #[test]
    fn bad_cidrs_rejected() {
        let e = errors("networks:\n  - name: a\n    cidr: 192.168.1.7/24\n  - name: b\n    cidr: 300.1.1.0/24\n  - name: c\n    cidr: 8.8.8.0/24\n    active_scan: true\n");
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(e[0].contains("did you mean 192.168.1.0/24"));
        assert!(e[1].contains("not a valid CIDR"));
        assert!(e[2].contains("public"));
    }

    #[test]
    fn duplicate_hostnames_rejected() {
        let e = errors("devices:\n  - name: a\n    hostnames: [robot, robot.local]\n  - name: b\n    hostnames: [Robot.local]\n");
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("already claimed by device 'a'"));
    }

    #[test]
    fn duplicate_ips_names_macs_rejected() {
        let e = errors(
            "devices:\n  - name: a\n    expected_ips: [192.168.1.5]\n    macs: [AA:BB:CC:DD:EE:01]\n  - name: b\n    expected_ips: [192.168.1.5]\n    macs: [aa-bb-cc-dd-ee-01]\n  - name: A\n",
        );
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(e.iter().any(|x| x.contains("expected IP 192.168.1.5")));
        assert!(e.iter().any(|x| x.contains("MAC")));
        assert!(e.iter().any(|x| x.contains("already used by device 'a'")));
    }

    #[test]
    fn invalid_values_rejected() {
        let e = errors(
            "devices:\n  - name: 'bad name'\n    expected_ips: [192.168.1.300]\n    macs: [zz:zz]\n    host_key_fingerprints: [MD5:aa]\n    usernames: ['-oProxyCommand=x']\n    ssh_host: '-oProxyCommand=x'\n    expected_networks: [nowhere]\n",
        );
        assert_eq!(e.len(), 7, "{e:?}");
    }

    #[test]
    fn host_key_bypass_options_rejected() {
        for opt in [
            "KnownHostsCommand",
            "VerifyHostKeyDNS",
            "ControlPath",
            "ControlMaster",
            "ProxyJump",
            "RemoteCommand",
        ] {
            let e = errors(&format!("ssh:\n  options:\n    {opt}: x\n"));
            assert_eq!(e.len(), 1, "{opt}: {e:?}");
        }
    }

    #[test]
    fn code_loading_forwarding_and_env_options_rejected() {
        // Options that load code into ssh, hand the remote host the user's
        // agent or display, open listeners, or send local environment are not
        // on the allowlist (a denylist missed them before the 2026-10 security review).
        for opt in [
            "PKCS11Provider",
            "SecurityKeyProvider",
            "AddKeysToAgent",
            "ForwardAgent",
            "ForwardX11Trusted",
            "RemoteForward",
            "LocalForward",
            "DynamicForward",
            "SetEnv",
            "SendEnv",
            "IdentityAgent",
            "NoHostAuthenticationForLocalhost",
            "Tunnel",
            "Include",
            "Match",
        ] {
            let e = errors(&format!("ssh:\n  options:\n    {opt}: 'yes'\n"));
            assert_eq!(e.len(), 1, "{opt} must be refused: {e:?}");
            assert!(e[0].contains(opt), "{e:?}");
        }
        // Turning forwarding OFF is allowed; turning it on is not.
        assert!(
            errors("ssh:\n  options:\n    ForwardAgent: 'no'\n    ForwardX11: 'no'\n").is_empty()
        );
        assert_eq!(
            errors("ssh:\n  options:\n    forwardagent: 'yes'\n").len(),
            1
        );
        // Ordinary tuning keeps working, in any case.
        assert!(errors(
            "ssh:\n  options:\n    ServerAliveInterval: '10'\n    identitiesonly: 'yes'\n    IdentityFile: '~/.ssh/id_lab'\n    HostKeyAlgorithms: '+ssh-rsa'\n"
        )
        .is_empty());
    }

    #[test]
    fn weakening_ssh_options_rejected() {
        let e = errors(
            "ssh:\n  options:\n    StrictHostKeyChecking: 'no'\n    ServerAliveInterval: '10'\n",
        );
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("StrictHostKeyChecking"));
    }

    #[test]
    fn threshold_sanity() {
        let e = errors("daemon:\n  degraded_after: 3\n  offline_after: 3\n");
        assert_eq!(e.len(), 1, "{e:?}");
        let e = errors("daemon:\n  scan_interval_s: 5\n  max_scan_hosts: 100000\n");
        assert_eq!(e.len(), 2, "{e:?}");
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize_hostname("Robot-Host.local."), "robot-host");
        assert_eq!(normalize_hostname("robot-host"), "robot-host");
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert!(valid_fingerprint(
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        ));
        assert!(!valid_fingerprint("SHA256:short"));
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    #[test]
    fn shipped_example_config_is_valid() {
        let c =
            Config::parse(include_str!("../../../config/example.yaml"), "example.yaml").unwrap();
        assert_eq!(c.sites.len(), 2);
        assert_eq!(c.device_count(), 4);
        assert_eq!(
            c.find_devices("robot-a")[0].1.profile,
            Some(Profile::NetworkOnly)
        );
        assert_eq!(
            c.site("site-alpha").unwrap().networks[0]
                .gateway_mac
                .as_deref(),
            Some("02:00:5e:00:42:01")
        );
    }

    #[test]
    fn text_that_looks_like_yaml_structure_round_trips() {
        for command in [format!("echo x{}", "{".repeat(65)), "* text\n".repeat(65)] {
            let text = format!("devices:\n  - name: test-device\n    notes: {}\n    services:\n      - name: test-service\n        command: {}\n",
                serde_json::to_string(&command).unwrap(), serde_json::to_string(&command).unwrap());
            let cfg = Config::parse(&text, "in").unwrap();
            let out = cfg.to_yaml();
            assert_eq!(Config::parse(&out, "out").unwrap(), cfg, "{out}");
            assert!(check_yaml_nesting(&out).is_ok(), "{out}");
        }
        // Quoting for output must not weaken hostile input limits.
        assert!(Config::parse(&format!("a: {}{}", "[".repeat(65), "]".repeat(65)), "in").is_err());
        assert!(Config::parse(
            &format!("devices: [\n{}", "[".repeat(MAX_YAML_FLOW_OPENERS + 1)),
            "in"
        )
        .is_err());
        assert!(Config::parse("devices: [unterminated", "in").is_err());
    }

    #[test]
    fn minimal_yaml_round_trips_and_omits_defaults() {
        let text = "daemon:\n  check_interval_s: 10\n  offline_backoff_max_s: 60\n  port_check_interval_s: 60\n  via_check_interval_s: 10\nnetworks:\n  - name: lab\n    cidr: 192.168.7.0/24\n    active_scan: true\n  - name: wide\n    cidr: 10.0.0.0/16\ndevices:\n  - name: robot\n    ssh: false\n    profile: network_only\n    expected_ips: [192.168.7.9]\n  - name: box\n    usernames: [ops]\n    profile: jetson\n    capabilities: [ros2]\npreferences:\n  terminal: kitty\n";
        let c = Config::parse(text, "t").unwrap();
        let out = c.to_yaml();
        let again = Config::parse(&out, "out").unwrap();
        assert_eq!(c, again, "{out}");
        assert!(!out.contains("mdns"), "{out}");
        assert!(!out.contains("auth_check"), "{out}");
        assert!(!out.contains("active_scan: false"), "{out}");
        assert!(out.contains("check_interval_s: 10"), "{out}");
        assert!(out.contains("terminal: kitty"), "{out}");
        // `name` stays first in each device entry.
        let robot = out.find("- name: robot").unwrap();
        assert!(out[robot..].find("ssh: false").is_some(), "{out}");
        assert_eq!(Config::default().to_yaml(), "");
    }

    #[test]
    fn profile_and_capability_rules() {
        let e = |t: &str| match Config::parse(t, "t") {
            Err(ConfigError::Invalid(v)) => v,
            Err(e) => vec![e.to_string()],
            Ok(_) => vec![],
        };
        assert!(e("devices:\n  - name: r\n    profile: network_only\n")[0].contains("ssh: false"));
        assert!(
            e("devices:\n  - name: r\n    ssh: false\n    capabilities: [ssh]\n")[0]
                .contains("contradicts")
        );
        assert!(e("devices:\n  - name: r\n    capabilities: [gateway]\n")[0].contains("derived"));
        assert!(!e("devices:\n  - name: r\n    profile: warp_drive\n").is_empty());
        assert!(e("preferences:\n  terminal: \"xterm -e\"\n")[0].contains("terminal"));
        assert!(e("preferences:\n  terminal: /usr/bin/kitty\n").is_empty());
        assert!(e("preferences:\n  editor: vim\n")[0].contains("editor"));
    }
}

#[cfg(test)]
mod site_tests {
    use super::*;

    fn errs(text: &str) -> Vec<String> {
        match Config::parse(text, "t") {
            Err(ConfigError::Invalid(v)) => v,
            Err(e) => vec![e.to_string()],
            Ok(_) => vec![],
        }
    }

    const TWO_SITES: &str = "sites:\n  - id: site-alpha\n    name: Site Alpha\n    networks:\n      - name: lab\n        cidr: 192.168.50.0/24\n        active_scan: true\n    devices:\n      - name: jetson\n        expected_ips: [192.168.50.10]\n      - name: robot-a\n        ssh: false\n        via: jetson\n        expected_ips: [10.42.0.2]\n    checks:\n      jetson: [disk]\n  - id: site-beta\n    name: Site Beta\n    auto_detect: false\n    networks:\n      - name: lab\n        cidr: 192.168.50.0/24\n        gateway: 192.168.50.1\n        gateway_mac: 02:00:00:00:00:b1\n        ssid: ExampleNet\n        interface: wlan0\n    devices:\n      - name: jetson\n        expected_ips: [192.168.50.10]\n";

    #[test]
    fn legacy_single_site_layout_migrates_to_default_site() {
        let legacy = "networks:\n  - name: lab\n    cidr: 192.168.50.0/24\n    active_scan: true\ndevices:\n  - name: jetson-a\n    usernames: [ops]\nchecks:\n  jetson-a: [disk]\n";
        assert!(uses_legacy_layout(legacy));
        let c = Config::parse(legacy, "legacy").unwrap();
        assert_eq!(c.sites.len(), 1);
        let s = &c.sites[0];
        assert_eq!(
            (s.id.as_str(), s.name.as_str()),
            (DEFAULT_SITE_ID, DEFAULT_SITE_NAME)
        );
        assert_eq!(s.networks[0].cidr, "192.168.50.0/24");
        assert_eq!(s.devices[0].usernames, ["ops"]);
        assert_eq!(
            c.checks_by_id().keys().collect::<Vec<_>>(),
            ["default/jetson-a"]
        );
        // LabLink writes the sites layout, and it reads back identically.
        let out = c.to_yaml();
        assert!(out.starts_with("sites:"), "{out}");
        assert!(!uses_legacy_layout(&out));
        assert_eq!(Config::parse(&out, "out").unwrap(), c);
    }

    #[test]
    fn legacy_and_sites_cannot_be_mixed() {
        let e = errs(
            "networks:\n  - name: lab\n    cidr: 192.168.50.0/24\nsites:\n  - id: a\n    name: A\n",
        );
        assert!(e[0].contains("cannot be combined"), "{e:?}");
    }

    #[test]
    fn two_sites_may_reuse_names_and_addresses() {
        let c = Config::parse(TWO_SITES, "t").unwrap();
        assert_eq!(c.sites.len(), 2);
        assert_eq!(c.find_devices("jetson").len(), 2, "same name at both sites");
        assert_eq!(c.find_devices("site-beta/jetson")[0].0.id, "site-beta");
        assert!(c.find_devices("site-gamma/jetson").is_empty());
        assert!(!c.site("SITE-BETA").unwrap().auto_detect);
        let al = c.allowlist();
        assert_eq!(al.networks.len(), 2);
        let ip = "192.168.50.7".parse().unwrap();
        assert_eq!(al.sites_containing(ip), ["site-alpha", "site-beta"]);
        assert_eq!(
            al.network_for_sites(ip, &["site-beta".into()])
                .unwrap()
                .site,
            "site-beta"
        );
        let out = c.to_yaml();
        assert_eq!(Config::parse(&out, "out").unwrap(), c, "{out}");
        assert!(out.contains("auto_detect: false"));
        assert!(!out.contains("auto_detect: true"));
    }

    #[test]
    fn site_validation() {
        let e = errs("sites:\n  - id: Bad_Id\n    name: x\n  - id: ok\n    name: ''\n  - id: ok\n    name: Dup\n  - id: other\n    name: dup\n");
        assert!(e.iter().any(|x| x.contains("lower case")), "{e:?}");
        assert!(e.iter().any(|x| x.contains("printable")), "{e:?}");
        assert!(e.iter().any(|x| x.contains("duplicate site id")), "{e:?}");
        assert!(e.iter().any(|x| x.contains("already called")), "{e:?}");
        // Within a site, names and identity signals stay unique; via and
        // expected_networks only see the device's own site.
        let e = errs("sites:\n  - id: a\n    name: A\n    networks:\n      - name: n\n        cidr: 10.0.0.0/24\n        gateway: 10.0.1.1\n        gateway_mac: zz\n        interface: 'a b'\n    devices:\n      - name: x\n        expected_ips: [10.0.0.5]\n      - name: X\n        expected_ips: [10.0.0.5]\n  - id: b\n    name: B\n    devices:\n      - name: y\n        via: x\n        expected_ips: [10.0.0.6]\n        expected_networks: [n]\n");
        for needle in [
            "not inside",
            "gateway_mac",
            "interface",
            "already used",
            "expected IP",
            "unknown device 'x'",
            "unknown network 'n'",
        ] {
            assert!(e.iter().any(|x| x.contains(needle)), "{needle}: {e:?}");
        }
    }

    #[test]
    fn references_and_ids() {
        assert_eq!(
            split_ref("site-alpha/jetson"),
            (Some("site-alpha"), "jetson")
        );
        assert_eq!(split_ref("jetson"), (None, "jetson"));
        assert_eq!(device_id("site-beta", "robot-a"), "site-beta/robot-a");
        assert_eq!(site_id_from_name("Makerspace"), "makerspace");
        assert_eq!(site_id_from_name("  Lab #2 (east) "), "lab-2-east");
        assert_eq!(site_id_from_name("***"), "site");
        assert!(valid_site_id("site-alpha") && !valid_site_id("a/b") && !valid_site_id("a.b"));
    }

    #[test]
    fn ssh_binaries_and_options_cannot_inject() {
        let e = errs("ssh:\n  binary: 'ssh -oProxyCommand=x'\n");
        assert!(e[0].contains("ssh.binary"), "{e:?}");
        let e = errs("ssh:\n  options:\n    \"Ciphers aes\": x\n");
        assert!(e[0].contains("ssh.options"), "{e:?}");
        let e = errs("ssh:\n  options:\n    ServerAliveInterval: \"10\\nProxyCommand x\"\n");
        assert!(e[0].contains("ssh.options"), "{e:?}");
    }

    #[test]
    fn notes_with_terminal_escapes_are_refused() {
        let e = errs("devices:\n  - name: d\n    notes: \"hi\\e[2J\"\n");
        assert!(e[0].contains("notes"), "{e:?}");
        assert!(errs("devices:\n  - name: d\n    notes: \"line 1\\nline 2\\tok\"\n").is_empty());
    }

    #[test]
    fn deeply_nested_yaml_is_refused_quickly() {
        let n = 32_000;
        for deep in [
            format!("sites: {}{}\n", "[".repeat(n), "]".repeat(n)),
            format!("sites: {}1{}\n", "{a: ".repeat(n), "}".repeat(n)),
            // An apostrophe inside a word does not open a quoted scalar.
            format!("sites: it's{}\n", "[".repeat(n)),
            // Nor one right after '-' (the lexer used to take it for an
            // unterminated quote and stop counting).
            format!("zz: [-', {}{}]\n", "[".repeat(n), "]".repeat(n)),
            // An unterminated quote at a token start cannot hide brackets
            // from the opener count, which ignores quoting.
            format!("zz: ['{}{}]\n", "[".repeat(n), "]".repeat(n)),
        ] {
            let t0 = std::time::Instant::now();
            let e = errs(&deep);
            assert!(
                e[0].contains("nest") || e[0].contains("'[' or '{'"),
                "{e:?}"
            );
            assert!(t0.elapsed() < std::time::Duration::from_millis(200));
        }
        // Brackets in quoted scalars and comments are text, not nesting.
        let quoted = format!(
            "# {}\nsites:\n  - id: a\n    name: \"{}\"\n    devices:\n      - name: d\n        notes: '{}'\n",
            "[".repeat(100),
            "[".repeat(60),
            "{".repeat(100)
        );
        assert!(errs(&quoted).is_empty(), "{:?}", errs(&quoted));
        assert!(check_yaml_nesting(&format!("a: {}{}", "[".repeat(64), "]".repeat(64))).is_ok());
        // Many references to one deep anchor (re-review: 1 MiB cost 3.96 s).
        let mut wide = format!("a: &a {}{}\nl:\n", "[".repeat(64), "]".repeat(64));
        for _ in 0..5000 {
            wide.push_str("- *a\n");
        }
        let t0 = std::time::Instant::now();
        assert!(errs(&wide)[0].contains("aliases"), "{:?}", errs(&wide));
        assert!(t0.elapsed() < std::time::Duration::from_millis(200));
        assert!(check_yaml_nesting("a: &x 1\nb: *x\nc: 2 * 3\n").is_ok());
        // Below the opener cap, the depth lexer itself counts brackets after
        // a quote that follows '-'.
        let e = check_yaml_nesting(&format!("zz: [-', {}{}]", "[".repeat(100), "]".repeat(100)));
        assert!(e.unwrap_err().contains("nest"));
    }

    #[test]
    fn oversized_config_is_refused() {
        let big = format!("# {}\n", "x".repeat(MAX_CONFIG_BYTES as usize));
        assert!(matches!(
            Config::parse(&big, "big"),
            Err(ConfigError::Parse { .. })
        ));
    }
}

#[cfg(test)]
mod via_tests {
    use super::*;

    fn errs(text: &str) -> Vec<String> {
        match Config::parse(text, "t") {
            Err(ConfigError::Invalid(v)) => v,
            Err(e) => vec![e.to_string()],
            Ok(_) => vec![],
        }
    }

    #[test]
    fn via_gateway_rules() {
        let ok = "devices:\n  - name: jetson-a\n  - name: robot-a\n    ssh: false\n    via: jetson-a\n    expected_ips: [192.168.50.161]\n";
        assert!(errs(ok).is_empty(), "{:?}", errs(ok));
        let e = errs(
            "devices:\n  - name: robot-a\n    via: nowhere\n    expected_ips: [192.168.50.161]\n",
        );
        assert!(e[0].contains("unknown device 'nowhere'"), "{e:?}");
        let e = errs("devices:\n  - name: gw\n    ssh: false\n  - name: robot-a\n    via: gw\n    expected_ips: [10.0.0.2]\n");
        assert!(e[0].contains("must have ssh: true"), "{e:?}");
        let e = errs("devices:\n  - name: a\n  - name: b\n    via: a\n    expected_ips: [10.0.0.2]\n  - name: c\n    via: b\n    expected_ips: [10.0.0.3]\n");
        assert!(e.iter().any(|x| x.contains("only one hop")), "{e:?}");
        let e = errs("devices:\n  - name: a\n  - name: b\n    via: a\n");
        assert!(e[0].contains("needs expected_ips"), "{e:?}");
        let e = errs("devices:\n  - name: a\n    via: a\n    expected_ips: [10.0.0.2]\n");
        assert!(e[0].contains("own gateway"), "{e:?}");
    }
}

#[cfg(test)]
mod yaml_parser_migration_tests {
    use super::*;

    #[test]
    fn released_example_survives_config_round_trip() {
        let original = Config::parse(include_str!("../../../config/example.yaml"), "released-example")
            .expect("published example must continue to parse");
        let emitted = original.to_yaml();
        let reparsed = Config::parse(&emitted, "reparsed")
            .expect("serialized example must remain readable");
        assert_eq!(original, reparsed);
    }

    #[test]
    fn legacy_layout_and_quoted_unicode_survive_migration() {
        let legacy = "networks:\n  - name: lan\n    cidr: 10.42.0.0/24\ndevices:\n  - name: robot-a\n    label: \"Rōbot: α\"\n";
        assert!(uses_legacy_layout(legacy));
        let config = Config::parse(legacy, "legacy")
            .expect("legacy site layout must be supported");
        assert_eq!(config.sites[0].id, DEFAULT_SITE_ID);
        assert_eq!(config.sites[0].devices[0].label.as_deref(), Some("Rōbot: α"));
        let emitted = config.to_yaml();
        assert!(!uses_legacy_layout(&emitted));
        assert_eq!(config, Config::parse(&emitted, "migrated").unwrap());
    }

    #[test]
    fn duplicate_keys_and_multiple_documents_are_not_silently_accepted() {
        assert!(Config::parse("daemon:\n  check_interval_s: 5\n  check_interval_s: 6\n", "duplicate").is_err());
        assert!(Config::parse("sites: []\n---\nssh: {}\n", "multidoc").is_err());
    }
}
