//! The Field Network: a secure, temporary Wi-Fi network LabLink starts on
//! this machine so laptops, Jetsons and robots can reach each other where
//! there is no usable network (a field test, a demo hall, a basement).
//!
//! Linux with NetworkManager hosts it (WPA2-Personal by default, WPA3 as
//! an opt-in, never WEP or open). macOS gets capability detection and a
//! guided Internet Sharing workflow. Nothing here runs as root, starts a
//! service, writes firewall rules or sysctls itself, or talks to the
//! internet; every change goes through NetworkManager's own polkit-checked
//! API. NetworkManager's shared mode, which the hotspot uses for DHCP, does
//! turn on IPv4 forwarding and add a NAT rule for the hotspot subnet while
//! it runs. Isolation does not depend on either. Two layers keep hotspot
//! clients on this machine:
//!
//! - the field filter ([`filter`]): a NetworkManager dispatcher script an
//!   administrator installs once. Its nftables table drops forwarding from
//!   and to the Wi-Fi adapter, and limits what clients reach on this
//!   machine, from before the access point starts until after it stops.
//!   An isolated start is refused without it.
//! - `priority 0 iif <adapter> prohibit` routing rules (IPv4 and IPv6) in
//!   the profile, which NetworkManager installs and removes with the
//!   connection ([`isolation`]).
//!
//! `nm::start` and `nm::restart` check both after activation, and
//! `nm::enforce` (run by `lablinkd`) keeps checking and stops the hotspot
//! when either is gone. The filter and the rules are kernel state and
//! prevent; the check is recovery, seconds later. Internet sharing is a
//! separate, explicit mode without the rules (the filter opens the adapter
//! for it).
//!
//! The site side (a roaming `field-network` site whose visiting devices
//! are recognized by their pinned host key) lives in `lablink-core` and
//! the daemon; `field_site` here only writes that site's config entry.

pub mod clients;
pub mod filter;
pub mod host;
pub mod isolation;
pub mod macos;
pub mod nm;
pub mod ops;
pub mod password;
pub mod preflight;
pub mod state;
pub mod subnet;
pub mod system;

use lablink_core::config::{Config, NetworkConfig, SiteConfig};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Refused for safety or by policy (exit code 7).
    Refused(String),
    /// Nothing to act on (no Field Network set up).
    NotFound(String),
    /// The operation was attempted and failed.
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(m) | Error::NotFound(m) | Error::Failed(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

/// What this machine can do, for `lablink hotspot capabilities`.
#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    pub os: system::Os,
    /// LabLink can host a Field Network here.
    pub can_host: bool,
    /// "networkmanager", "macos-guided" or "none".
    pub backend: &'static str,
    pub networkmanager: Option<host::NmInfo>,
    pub adapters: Vec<host::WifiAdapter>,
    /// Starting would use the only Wi-Fi adapter, which carries a
    /// connection now (it will drop while the hotspot runs).
    pub single_adapter_in_use: bool,
    pub checkpoint_rollback: bool,
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos: Option<macos::MacGuide>,
}

pub fn capabilities(sys: &dyn system::System) -> Capabilities {
    let facts = host::gather(sys);
    let mut notes = facts.notes.clone();
    let macos = (facts.os == system::Os::Macos).then(|| macos::guide(sys));
    let capable: Vec<_> = facts.wifi.iter().filter(|w| w.can_host_wpa2()).collect();
    let nm_ok = facts
        .nm
        .as_ref()
        .is_some_and(|n| n.running && n.allowed("network-control"));
    let can_host = facts.os == system::Os::Linux && nm_ok && !capable.is_empty();
    if facts.os == system::Os::Linux
        && facts
            .nm
            .as_ref()
            .is_some_and(|n| !n.allowed("network-control"))
    {
        notes.push("NetworkManager requires administrator authorization for this user to control networking".into());
    }
    if facts.wifi.iter().any(|w| w.sae.is_none()) {
        notes.push(
            "WPA3 (SAE) access-point support cannot be verified without `iw`; WPA2 is the default"
                .into(),
        );
    }
    Capabilities {
        os: facts.os,
        can_host,
        backend: match facts.os {
            system::Os::Linux if facts.nm.is_some() => "networkmanager",
            system::Os::Macos => "macos-guided",
            _ => "none",
        },
        single_adapter_in_use: capable.len() == 1 && !capable[0].connection.is_empty(),
        checkpoint_rollback: facts
            .nm
            .as_ref()
            .is_some_and(|n| n.allowed("checkpoint-rollback")),
        networkmanager: facts.nm.clone(),
        adapters: facts.wifi.clone(),
        notes,
        macos,
    }
}

pub const FIELD_SITE_ID: &str = "field-network";

/// Add or update the roaming Field Network site for `subnet`. Returns
/// whether the config changed. An existing roaming site (whatever its id)
/// is reused; a non-roaming site already called `field-network` is left
/// alone and refused.
pub fn field_site(
    cfg: &mut Config,
    subnet: &ipnet::Ipv4Net,
    interface: Option<&str>,
    ssid: Option<&str>,
) -> Result<bool, String> {
    let gw = subnet::gateway(subnet).to_string();
    let idx = match cfg.sites.iter().position(|s| s.roaming) {
        Some(i) => i,
        None => {
            if cfg.sites.iter().any(|s| s.id == FIELD_SITE_ID) {
                return Err(format!(
                    "a site '{FIELD_SITE_ID}' already exists and is not a roaming site; rename it or mark it `roaming: true`"
                ));
            }
            let mut s = SiteConfig::new(FIELD_SITE_ID, "Field Network");
            s.roaming = true;
            cfg.sites.push(s);
            cfg.sites.len() - 1
        }
    };
    let before = cfg.sites[idx].networks.clone();
    let mut net = NetworkConfig::new("hotspot", &subnet.to_string(), true);
    net.interface = interface.map(str::to_string);
    net.ssid = ssid.map(str::to_string);
    net.gateway = Some(gw);
    cfg.sites[idx].networks = vec![net];
    Ok(cfg.sites[idx].networks != before)
}

#[cfg(test)]
mod tests;
