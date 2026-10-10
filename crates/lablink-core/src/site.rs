//! Sites: which place the user is at right now.
//!
//! A *site* is a place with its own networks and devices (a robotics lab, an
//! office, a workshop, a home network). Devices of a site the user is not at
//! are AWAY: LabLink does not probe them and never reports them as failed.
//!
//! This module is pure and platform-independent. The daemon gathers the
//! local, non-secret signals (attached subnets, default gateways and their
//! MAC addresses, Wi-Fi SSIDs, devices seen on the wire) on whatever OS it
//! runs on and feeds them to [`assess`] and [`decide`].
//!
//! Evidence, strongest first:
//!
//! | strength | signal |
//! |---|---|
//! | strong | a device of the site presented its pinned SSH host key at an address on one of the site's networks |
//! | medium | the default gateway's MAC matches the site's recorded gateway; a known device's MAC is on the local link; a pinned host key seen outside the site's networks |
//! | weak   | an attached subnet lies inside one of the site's networks; the default gateway address matches |
//! | hint   | the Wi-Fi SSID or interface name matches (never enough on its own) |
//!
//! A subnet match is voided when the site has a recorded gateway MAC for
//! that network and the gateway answering here has a different one: two
//! places that use the same private range are told apart by their gateways.
//! Site detection never changes trust: host keys, pins and adoption are
//! unaffected by which site is active.

use crate::config::{normalize_mac, SiteConfig};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Whether the user is at a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteState {
    /// The user is at this site: its devices are monitored.
    Active,
    /// The user is somewhere else: its devices are not probed and never
    /// shown as failed.
    Away,
    /// Not decided (several sites match equally well, or detection has not
    /// run yet). Devices are monitored so that their host keys can settle
    /// it, but an unreachable device is not reported RED.
    #[default]
    Unknown,
}

impl SiteState {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteState::Active => "ACTIVE",
            SiteState::Away => "AWAY",
            SiteState::Unknown => "UNKNOWN",
        }
    }
}

/// How sure the active-site decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    #[default]
    None,
    Low,
    Medium,
    High,
    /// Chosen by the user.
    Manual,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
            Confidence::Manual => "manual",
        }
    }
    fn rank(self) -> u8 {
        match self {
            Confidence::None => 0,
            Confidence::Low => 1,
            Confidence::Medium => 2,
            Confidence::High => 3,
            Confidence::Manual => 4,
        }
    }
}

/// How the active site is chosen.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "site")]
pub enum SiteMode {
    /// Infer the site from network signals (the default).
    #[default]
    Auto,
    /// The user chose this site.
    Manual(String),
}

impl SiteMode {
    pub fn describe(&self) -> String {
        match self {
            SiteMode::Auto => "auto".into(),
            SiteMode::Manual(s) => format!("manual ({s})"),
        }
    }
}

/// Why a site's state was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedBy {
    #[default]
    Auto,
    Manual,
    /// The only site, with no networks to detect it by: always active.
    OnlySite,
}

/// Strength of one piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    Hint,
    Weak,
    Medium,
    Strong,
    /// Counts against the site (e.g. same subnet, different gateway).
    Against,
}

/// One piece of evidence for (or against) a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub strength: Strength,
    /// `host_key`, `gateway_mac`, `device_mac`, `subnet`, `gateway`,
    /// `ssid`, `interface`, `gateway_mac_differs`.
    pub kind: String,
    pub detail: String,
}

/// An attached subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub interface: String,
    pub net: IpNet,
}

/// A default gateway currently in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    pub interface: String,
    pub ip: IpAddr,
    /// From the neighbor table, normalized.
    pub mac: Option<String>,
}

/// Local, non-secret network signals (collected by platform code).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalSignals {
    pub attached: Vec<Attached>,
    pub gateways: Vec<Gateway>,
    /// `(interface, ssid)` of connected Wi-Fi interfaces.
    pub ssids: Vec<(String, String)>,
    /// Normalized MACs with a valid neighbor-table entry.
    pub neighbor_macs: BTreeSet<String>,
}

/// A device of some site observed with its pinned host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySighting {
    pub site: String,
    /// `site/name`.
    pub device: String,
    pub ip: IpAddr,
}

/// What the daemon knows about one site besides its config.
#[derive(Debug, Clone, Default)]
pub struct SiteKnowledge {
    /// Gateway MACs learned while the site was confirmed by host keys:
    /// `(network name, mac)`.
    pub learned_gateway_macs: Vec<(String, String)>,
    /// Configured and learned MACs of the site's devices: `(device id, mac)`.
    pub device_macs: Vec<(String, String)>,
}

/// Evidence and score for one site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub site: String,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
    pub score: i64,
}

fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Collect evidence for one site.
pub fn assess(
    site: &SiteConfig,
    know: &SiteKnowledge,
    signals: &LocalSignals,
    keys: &[KeySighting],
) -> Assessment {
    let mut ev: Vec<Evidence> = Vec::new();
    let site_nets: Vec<(String, Option<IpNet>)> = site
        .networks
        .iter()
        .map(|n| (n.name.clone(), crate::net::parse_cidr(&n.cidr).ok()))
        .collect();
    let in_site_net = |ip: &IpAddr| {
        site_nets
            .iter()
            .any(|(_, n)| n.is_some_and(|n| n.contains(ip)))
    };
    let attached_ip = |ip: &IpAddr| signals.attached.iter().any(|a| a.net.contains(ip));

    // Strong / medium: pinned host keys of this site's devices.
    let mut key_devices = BTreeSet::new();
    for k in keys.iter().filter(|k| k.site == site.id) {
        if !key_devices.insert(k.device.clone()) {
            continue;
        }
        if in_site_net(&k.ip) && attached_ip(&k.ip) {
            ev.push(Evidence {
                strength: Strength::Strong,
                kind: "host_key".into(),
                detail: format!("{} presented its pinned host key at {}", k.device, k.ip),
            });
        } else {
            ev.push(Evidence {
                strength: Strength::Medium,
                kind: "host_key".into(),
                detail: format!(
                    "{} presented its pinned host key at {}, outside this site's networks",
                    k.device, k.ip
                ),
            });
        }
    }

    // Gateways, subnets and hints, per configured network.
    for n in &site.networks {
        let Some(net) = crate::net::parse_cidr(&n.cidr).ok() else {
            continue;
        };
        let here: Vec<&Attached> = signals
            .attached
            .iter()
            .filter(|a| overlaps(&a.net, &net))
            .collect();
        if here.is_empty() {
            continue;
        }
        let gws: Vec<&Gateway> = signals
            .gateways
            .iter()
            .filter(|g| net.contains(&g.ip) || here.iter().any(|a| a.net.contains(&g.ip)))
            .collect();
        let mut known_macs: Vec<String> = n
            .gateway_mac
            .as_deref()
            .and_then(normalize_mac)
            .into_iter()
            .collect();
        for (net_name, mac) in &know.learned_gateway_macs {
            if net_name == &n.name && !known_macs.contains(mac) {
                known_macs.push(mac.clone());
            }
        }
        let gw_macs: Vec<&String> = gws.iter().filter_map(|g| g.mac.as_ref()).collect();
        let mac_match = gw_macs.iter().any(|m| known_macs.contains(m));
        let mac_differs = !known_macs.is_empty() && !gw_macs.is_empty() && !mac_match;
        if mac_match {
            ev.push(Evidence {
                strength: Strength::Medium,
                kind: "gateway_mac".into(),
                detail: format!("gateway of {} ({}) has the recorded MAC", n.name, n.cidr),
            });
        }
        if mac_differs {
            ev.push(Evidence {
                strength: Strength::Against,
                kind: "gateway_mac_differs".into(),
                detail: format!(
                    "{} is attached but its gateway is a different machine than the one recorded for this site",
                    n.cidr
                ),
            });
            continue;
        }
        ev.push(Evidence {
            strength: Strength::Weak,
            kind: "subnet".into(),
            detail: format!(
                "attached to {} ({}) on {}",
                n.name,
                n.cidr,
                here.iter()
                    .map(|a| a.interface.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
        if let Some(g) = n.gateway.as_deref().and_then(|g| g.parse::<IpAddr>().ok()) {
            if gws.iter().any(|x| x.ip == g) {
                ev.push(Evidence {
                    strength: Strength::Weak,
                    kind: "gateway".into(),
                    detail: format!("default gateway {g} matches"),
                });
            }
        }
        if let Some(i) = &n.interface {
            if here.iter().any(|a| &a.interface == i) {
                ev.push(Evidence {
                    strength: Strength::Hint,
                    kind: "interface".into(),
                    detail: format!("on interface {i}"),
                });
            }
        }
        if let Some(want) = &n.ssid {
            if signals.ssids.iter().any(|(_, s)| s == want) {
                ev.push(Evidence {
                    strength: Strength::Hint,
                    kind: "ssid".into(),
                    detail: format!("Wi-Fi network \"{want}\" (a hint only)"),
                });
            }
        }
    }

    // Medium: known device MACs on the local link (at most three count).
    let mut seen = 0;
    let mut counted = BTreeSet::new();
    for (dev, mac) in &know.device_macs {
        if seen >= 3 || key_devices.contains(dev) || counted.contains(dev) {
            continue;
        }
        if signals.neighbor_macs.contains(mac) {
            counted.insert(dev.clone());
            seen += 1;
            ev.push(Evidence {
                strength: Strength::Medium,
                kind: "device_mac".into(),
                detail: format!("{dev} is on the local link (MAC address)"),
            });
        }
    }

    // Sightings of the site's devices (MAC on the local link, pinned key at
    // an address outside the site's networks) only support a site whose own
    // network is attached here. Otherwise they say where a device is, not
    // where you are: a carried laptop, or one forged MAC, must not make
    // another site ACTIVE and park the site whose subnet you are on.
    if !ev.iter().any(|e| e.kind == "subnet") {
        for e in ev.iter_mut() {
            if e.strength == Strength::Medium
                && matches!(e.kind.as_str(), "device_mac" | "host_key")
            {
                e.strength = Strength::Hint;
                e.detail
                    .push_str(" (a hint only: none of this site's networks is attached)");
            }
        }
    }

    let score: i64 = ev
        .iter()
        .map(|e| match e.strength {
            Strength::Strong => 100,
            Strength::Medium if e.kind == "gateway_mac" => 50,
            Strength::Medium if e.kind == "host_key" => 30,
            Strength::Medium => 25,
            Strength::Weak => 10,
            Strength::Hint if e.kind == "ssid" => 15,
            Strength::Hint => 3,
            Strength::Against => -20,
        })
        .sum();
    let has = |s: Strength| ev.iter().any(|e| e.strength == s);
    let confidence = if has(Strength::Strong) {
        Confidence::High
    } else if has(Strength::Medium) {
        Confidence::Medium
    } else if has(Strength::Weak) {
        Confidence::Low
    } else {
        Confidence::None // hints alone never place the user at a site
    };
    Assessment {
        site: site.id.clone(),
        evidence: ev,
        confidence,
        score,
    }
}

/// The state chosen for one site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub site: String,
    pub state: SiteState,
    pub confidence: Confidence,
    pub selected_by: SelectedBy,
    /// Another site has evidence of the same strength (e.g. both use the
    /// same subnet): automatic actions wait for stronger evidence.
    pub contested: bool,
}

impl Decision {
    /// Confident enough to resolve an ambiguous bare device name to this
    /// site, and to run automatic background scans.
    pub fn confident(&self) -> bool {
        self.state == SiteState::Active
            && match self.selected_by {
                SelectedBy::Manual | SelectedBy::OnlySite => true,
                SelectedBy::Auto => self.confidence.rank() >= Confidence::Medium.rank(),
            }
    }

    /// May LabLink actively scan this site's approved networks now?
    ///
    /// Only an ACTIVE site, and only when the decision does not rest on a
    /// subnet that another site claims too. A subnet match that contradicts
    /// the site's recorded gateway MAC never counts (see [`assess`]), so a
    /// foreign network that merely reuses the same private range is not
    /// scanned once the site's gateway is known.
    pub fn scan_permission(&self) -> Result<(), String> {
        match self.state {
            SiteState::Away => return Err("the site is away".into()),
            SiteState::Unknown => {
                return Err(
                    "the site is not confirmed (another site matches equally well); choose it with `lablink site use`"
                        .into(),
                )
            }
            SiteState::Active => {}
        }
        if self.confident() || (self.confidence == Confidence::Low && !self.contested) {
            return Ok(());
        }
        Err(format!(
            "the site was detected with {} confidence and another site matches this network too; scanning waits for a gateway or host-key match, or choose the site with `lablink site use`",
            self.confidence.as_str()
        ))
    }
}

/// Decide every site's state from the assessments and the mode.
/// `assessments` must be in the same order as `sites`.
pub fn decide(sites: &[SiteConfig], assessments: &[Assessment], mode: &SiteMode) -> Vec<Decision> {
    let away = |s: &SiteConfig, c: Confidence| Decision {
        site: s.id.clone(),
        state: SiteState::Away,
        confidence: c,
        selected_by: SelectedBy::Auto,
        contested: false,
    };
    if let SiteMode::Manual(id) = mode {
        if sites.iter().any(|s| s.id.eq_ignore_ascii_case(id)) {
            return sites
                .iter()
                .zip(assessments)
                .map(|(s, a)| {
                    if s.id.eq_ignore_ascii_case(id) {
                        Decision {
                            site: s.id.clone(),
                            state: SiteState::Active,
                            confidence: Confidence::Manual,
                            selected_by: SelectedBy::Manual,
                            contested: false,
                        }
                    } else {
                        Decision {
                            selected_by: SelectedBy::Manual,
                            ..away(s, a.confidence)
                        }
                    }
                })
                .collect();
        }
    }
    if sites.len() == 1 && sites[0].networks.is_empty() {
        return vec![Decision {
            site: sites[0].id.clone(),
            state: SiteState::Active,
            confidence: Confidence::None,
            selected_by: SelectedBy::OnlySite,
            contested: false,
        }];
    }
    let key = |a: &Assessment| (a.confidence.rank(), a.score);
    let best = sites
        .iter()
        .zip(assessments)
        .filter(|(s, a)| s.auto_detect && a.confidence != Confidence::None)
        .map(|(_, a)| key(a))
        .max();
    sites
        .iter()
        .zip(assessments)
        .map(|(s, a)| {
            let candidate = s.auto_detect && a.confidence != Confidence::None;
            match best {
                Some(b) if candidate && key(a) == b => {
                    let tied = sites
                        .iter()
                        .zip(assessments)
                        .filter(|(o, oa)| {
                            o.id != s.id
                                && o.auto_detect
                                && oa.confidence != Confidence::None
                                && key(oa) == b
                        })
                        .count();
                    let contested = sites.iter().zip(assessments).any(|(o, oa)| {
                        o.id != s.id && o.auto_detect && oa.confidence == a.confidence
                    });
                    Decision {
                        site: s.id.clone(),
                        state: if tied > 0 {
                            SiteState::Unknown
                        } else {
                            SiteState::Active
                        },
                        confidence: a.confidence,
                        selected_by: SelectedBy::Auto,
                        contested,
                    }
                }
                _ => away(s, a.confidence),
            }
        })
        .collect()
}

/// Per-site summary exchanged over IPC (`lablink sites`, the GUI).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteStatus {
    pub id: String,
    pub name: String,
    pub state: SiteState,
    pub confidence: Confidence,
    pub selected_by: SelectedBy,
    #[serde(default)]
    pub contested: bool,
    pub auto_detect: bool,
    /// Whether background active scans of this site's networks may run now,
    /// and why not.
    #[serde(default)]
    pub scan: Option<String>,
    pub evidence: Vec<Evidence>,
    pub networks: Vec<SiteNetworkView>,
    pub devices: DeviceCounts,
}

/// One network of a site, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteNetworkView {
    pub name: String,
    pub cidr: String,
    pub active_scan: bool,
    pub attached: bool,
}

/// Device colors of a site.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCounts {
    pub total: u32,
    pub green: u32,
    pub yellow: u32,
    pub red: u32,
    pub gray: u32,
}

/// `lablink sites` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SitesReport {
    pub schema_version: u32,
    pub mode: SiteMode,
    pub sites: Vec<SiteStatus>,
    /// What this machine sees right now (interfaces, gateways, SSIDs), for
    /// the "detection signals" view.
    pub signals: SignalsView,
}

/// Local signals, for display.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalsView {
    pub attached: Vec<String>,
    pub gateways: Vec<String>,
    pub ssids: Vec<String>,
}

impl SitesReport {
    /// The active site, when exactly one is active.
    pub fn active(&self) -> Option<&SiteStatus> {
        let mut it = self.sites.iter().filter(|s| s.state == SiteState::Active);
        match (it.next(), it.next()) {
            (Some(s), None) => Some(s),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkConfig, SiteConfig};

    fn site(id: &str, cidr: &str, gw_mac: Option<&str>) -> SiteConfig {
        let mut s = SiteConfig::new(id, id);
        let mut n = NetworkConfig::new("lan", cidr, true);
        n.gateway_mac = gw_mac.map(str::to_string);
        s.networks.push(n);
        s
    }

    fn attached(cidr: &str) -> LocalSignals {
        LocalSignals {
            attached: vec![Attached {
                interface: "eth0".into(),
                net: cidr.parse().unwrap(),
            }],
            ..Default::default()
        }
    }

    fn with_gateway(mut s: LocalSignals, ip: &str, mac: &str) -> LocalSignals {
        s.gateways.push(Gateway {
            interface: "eth0".into(),
            ip: ip.parse().unwrap(),
            mac: Some(mac.into()),
        });
        s
    }

    fn run(sites: &[SiteConfig], sig: &LocalSignals, keys: &[KeySighting]) -> Vec<Decision> {
        let a: Vec<Assessment> = sites
            .iter()
            .map(|s| assess(s, &SiteKnowledge::default(), sig, keys))
            .collect();
        decide(sites, &a, &SiteMode::Auto)
    }

    #[test]
    fn subnet_alone_is_low_and_other_site_is_away() {
        let sites = [
            site("alpha", "10.10.0.0/24", None),
            site("beta", "10.20.0.0/24", None),
        ];
        let d = run(&sites, &attached("10.10.0.0/24"), &[]);
        assert_eq!(d[0].state, SiteState::Active);
        assert_eq!(d[0].confidence, Confidence::Low);
        assert_eq!(d[1].state, SiteState::Away);
        assert!(
            !d[0].confident(),
            "a subnet alone never resolves ambiguous names"
        );
        assert!(d[0].scan_permission().is_ok(), "uncontested subnet match");
    }

    #[test]
    fn same_subnet_at_two_sites_is_unknown_until_a_stronger_signal() {
        let sites = [
            site("alpha", "192.168.50.0/24", None),
            site("beta", "192.168.50.0/24", None),
        ];
        let sig = attached("192.168.50.0/24");
        let d = run(&sites, &sig, &[]);
        assert!(d.iter().all(|x| x.state == SiteState::Unknown), "{d:?}");
        assert!(
            d.iter().all(|x| x.scan_permission().is_err()),
            "contested subnet"
        );
        // A pinned host key of a beta device, on beta's network, settles it.
        let keys = [KeySighting {
            site: "beta".into(),
            device: "beta/robot-a".into(),
            ip: "192.168.50.7".parse().unwrap(),
        }];
        let d = run(&sites, &sig, &keys);
        assert_eq!(d[1].state, SiteState::Active);
        assert_eq!(d[1].confidence, Confidence::High);
        assert_eq!(d[0].state, SiteState::Away);
        assert!(d[1].confident());
    }

    #[test]
    fn gateway_mac_tells_same_subnet_sites_apart_and_voids_a_mismatch() {
        let sites = [
            site("alpha", "192.168.50.0/24", Some("02:00:00:00:00:aa")),
            site("beta", "192.168.50.0/24", Some("02:00:00:00:00:bb")),
        ];
        let sig = with_gateway(
            attached("192.168.50.0/24"),
            "192.168.50.1",
            "02:00:00:00:00:bb",
        );
        let d = run(&sites, &sig, &[]);
        assert_eq!(d[1].state, SiteState::Active);
        assert_eq!(d[1].confidence, Confidence::Medium);
        assert_eq!(d[0].state, SiteState::Away);
        // A third place with the same subnet and another gateway: neither.
        let sig = with_gateway(
            attached("192.168.50.0/24"),
            "192.168.50.1",
            "02:00:00:00:00:cc",
        );
        let d = run(&sites, &sig, &[]);
        assert!(d.iter().all(|x| x.state == SiteState::Away), "{d:?}");
    }

    #[test]
    fn ssid_alone_never_selects_a_site() {
        let mut s = site("alpha", "10.10.0.0/24", None);
        s.networks[0].ssid = Some("ExampleNet".into());
        let sig = LocalSignals {
            ssids: vec![("wlan0".into(), "ExampleNet".into())],
            ..Default::default()
        };
        let d = run(&[s, site("beta", "10.20.0.0/24", None)], &sig, &[]);
        assert!(d.iter().all(|x| x.state == SiteState::Away), "{d:?}");
    }

    #[test]
    fn host_key_outweighs_subnet_and_ssid_of_another_site() {
        let mut a = site("alpha", "10.10.0.0/24", None);
        a.networks[0].ssid = Some("ExampleNet".into());
        let b = site("beta", "10.10.0.0/24", None);
        let mut sig = attached("10.10.0.0/24");
        sig.ssids.push(("wlan0".into(), "ExampleNet".into()));
        let keys = [KeySighting {
            site: "beta".into(),
            device: "beta/jetson-a".into(),
            ip: "10.10.0.9".parse().unwrap(),
        }];
        let d = run(&[a, b], &sig, &keys);
        assert_eq!(d[1].state, SiteState::Active, "{d:?}");
        assert_eq!(d[0].state, SiteState::Away);
    }

    #[test]
    fn carried_device_does_not_drag_its_home_site_along() {
        // beta's laptop is here, but on alpha's network: alpha keeps winning.
        let sites = [
            site("alpha", "10.10.0.0/24", None),
            site("beta", "10.20.0.0/24", None),
        ];
        let keys = [
            KeySighting {
                site: "alpha".into(),
                device: "alpha/gpu-workstation".into(),
                ip: "10.10.0.5".parse().unwrap(),
            },
            KeySighting {
                site: "beta".into(),
                device: "beta/laptop".into(),
                ip: "10.10.0.6".parse().unwrap(),
            },
        ];
        let d = run(&sites, &attached("10.10.0.0/24"), &keys);
        assert_eq!(d[0].state, SiteState::Active);
        assert_eq!(d[1].state, SiteState::Away);
    }

    #[test]
    fn manual_mode_and_single_site_without_networks() {
        let sites = [
            site("alpha", "10.10.0.0/24", None),
            site("beta", "10.20.0.0/24", None),
        ];
        let a: Vec<Assessment> = sites
            .iter()
            .map(|s| assess(s, &SiteKnowledge::default(), &attached("10.10.0.0/24"), &[]))
            .collect();
        let d = decide(&sites, &a, &SiteMode::Manual("beta".into()));
        assert_eq!(d[1].state, SiteState::Active);
        assert_eq!(d[1].confidence, Confidence::Manual);
        assert_eq!(d[0].state, SiteState::Away);
        assert!(d[1].scan_permission().is_ok());
        assert!(d[0].scan_permission().is_err(), "away");
        // An unknown manual site falls back to auto.
        let d = decide(&sites, &a, &SiteMode::Manual("gamma".into()));
        assert_eq!(d[0].state, SiteState::Active);

        let only = [SiteConfig::new("default", "Default")];
        let a = vec![assess(
            &only[0],
            &SiteKnowledge::default(),
            &LocalSignals::default(),
            &[],
        )];
        let d = decide(&only, &a, &SiteMode::Auto);
        assert_eq!(d[0].state, SiteState::Active);
        assert_eq!(d[0].selected_by, SelectedBy::OnlySite);
        assert!(d[0].confident());
    }

    #[test]
    fn auto_detect_off_is_never_chosen_automatically() {
        let mut a = site("alpha", "10.10.0.0/24", None);
        a.auto_detect = false;
        let d = run(
            &[a, site("beta", "10.20.0.0/24", None)],
            &attached("10.10.0.0/24"),
            &[],
        );
        assert!(d.iter().all(|x| x.state == SiteState::Away), "{d:?}");
    }

    #[test]
    fn learned_gateway_and_device_macs_are_medium() {
        let sites = [
            site("alpha", "10.10.0.0/24", None),
            site("beta", "10.10.0.0/24", None),
        ];
        let sig = with_gateway(attached("10.10.0.0/24"), "10.10.0.1", "02:00:00:00:00:aa");
        let know = SiteKnowledge {
            learned_gateway_macs: vec![("lan".into(), "02:00:00:00:00:aa".into())],
            device_macs: vec![],
        };
        let a = vec![
            assess(&sites[0], &know, &sig, &[]),
            assess(&sites[1], &SiteKnowledge::default(), &sig, &[]),
        ];
        let d = decide(&sites, &a, &SiteMode::Auto);
        assert_eq!(d[0].state, SiteState::Active);
        assert_eq!(d[0].confidence, Confidence::Medium);

        let mut sig2 = attached("10.10.0.0/24");
        sig2.neighbor_macs.insert("02:00:00:00:00:42".into());
        let know_b = SiteKnowledge {
            learned_gateway_macs: vec![],
            device_macs: vec![("beta/robot-a".into(), "02:00:00:00:00:42".into())],
        };
        let a = vec![
            assess(&sites[0], &SiteKnowledge::default(), &sig2, &[]),
            assess(&sites[1], &know_b, &sig2, &[]),
        ];
        let d = decide(&sites, &a, &SiteMode::Auto);
        assert_eq!(d[1].state, SiteState::Active);
        assert_eq!(d[0].state, SiteState::Away);
    }

    #[test]
    fn mode_serialization() {
        assert_eq!(
            serde_json::to_string(&SiteMode::Auto).unwrap(),
            r#"{"mode":"auto"}"#
        );
        assert_eq!(
            serde_json::to_string(&SiteMode::Manual("alpha".into())).unwrap(),
            r#"{"mode":"manual","site":"alpha"}"#
        );
    }
}
