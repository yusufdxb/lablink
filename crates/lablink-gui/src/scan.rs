//! What the Discovered tab says about how devices were found, and which
//! networks it may offer to scan once.
//!
//! Passive discovery (the neighbor table, configured names) always runs. An
//! active scan sends a ping and an SSH port check to every address of a
//! network, so the GUI only offers it for networks already approved in the
//! configuration that this computer is directly connected to, and only after
//! the person confirms. The daemon checks the same limits again (private
//! range, size cap, attached) and refuses anything else.
//!
//! Nothing here claims a complete inventory: a scan only finds devices that
//! answer.

use lablink_core::model::{DiscoverReport, DiscoveredHost, PortState};
use lablink_core::site::{SiteState, SiteStatus};

use crate::view::Level;

/// A network the person may scan once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub site_name: String,
    pub network: String,
    pub cidr: String,
    /// Usable addresses in the range.
    pub hosts: u64,
}

impl Offer {
    pub fn label(&self) -> String {
        format!("{} ({}, {})", self.cidr, self.network, self.site_name)
    }
}

/// Usable host addresses in an IPv4 CIDR (None for anything else).
pub fn host_count(cidr: &str) -> Option<u64> {
    let (addr, p) = cidr.split_once('/')?;
    addr.parse::<std::net::Ipv4Addr>().ok()?;
    let p: u32 = p.parse().ok().filter(|p| *p <= 32)?;
    let all = 1u64 << (32 - p);
    Some(if p >= 31 { all } else { all - 2 })
}

/// Approved (configured), attached IPv4 networks of active sites, without
/// duplicates.
pub fn offers(sites: &[SiteStatus]) -> Vec<Offer> {
    let mut out: Vec<Offer> = Vec::new();
    for s in sites.iter().filter(|s| s.state == SiteState::Active) {
        for n in s.networks.iter().filter(|n| n.attached) {
            let Some(hosts) = host_count(&n.cidr) else {
                continue;
            };
            if out.iter().any(|o| o.cidr == n.cidr) {
                continue;
            }
            out.push(Offer {
                site_name: s.name.clone(),
                network: n.name.clone(),
                cidr: n.cidr.clone(),
                hosts,
            });
        }
    }
    out
}

/// Networks scanned in the background right now: approved for active
/// scanning, attached, and on an active site whose scans are allowed.
pub fn background_scans(sites: &[SiteStatus]) -> Vec<String> {
    sites
        .iter()
        .filter(|s| s.state == SiteState::Active && s.scan.is_none())
        .flat_map(|s| s.networks.iter())
        .filter(|n| n.active_scan && n.attached)
        .map(|n| n.cidr.clone())
        .collect()
}

/// The sentence about scanning shown above the discovered list.
pub fn scanning_line(sites: &[SiteStatus]) -> String {
    let bg = background_scans(sites);
    if bg.is_empty() {
        "Active scanning is off. LabLink is listening passively for devices that are already talking on the network, so quiet devices may not be listed yet.".into()
    } else {
        format!(
            "Background scanning is on for {}. A scan only finds devices that answer, so it may not list everything.",
            bg.join(", ")
        )
    }
}

/// Networks the latest discovery actively scanned, with what it found.
pub fn scanned(report: &DiscoverReport) -> Vec<String> {
    report
        .stages
        .iter()
        .filter(|s| s.stage.starts_with("active_scan") && s.result == "ok")
        .map(|s| s.detail.clone())
        .collect()
}

/// Headline for `new` untracked and `tracked` already-listed hosts.
/// `scans` are the networks the latest discovery actively scanned.
pub fn headline(new: usize, tracked: usize, scans: &[String]) -> String {
    let devices = |n: usize| {
        if n == 1 {
            "1 device".to_string()
        } else {
            format!("{n} devices")
        }
    };
    let mut s = if scans.is_empty() {
        format!("Found {} using passive discovery.", devices(new))
    } else {
        format!(
            "Found {} using passive discovery and a scan ({}).",
            devices(new),
            scans.join("; ")
        )
    };
    if tracked > 0 {
        s.push_str(&format!(
            " {} already on your dashboard {} listed under Already tracked.",
            devices(tracked),
            if tracked == 1 { "is" } else { "are" }
        ));
    }
    s
}

/// A host not heard from for this long is shown as not reachable.
pub const STALE_MS: u64 = 15 * 60 * 1000;

/// One word on whether a discovered host can be connected to.
pub fn host_state(h: &DiscoveredHost) -> (String, Level) {
    if h.last_seen_ms_ago >= STALE_MS {
        return (
            format!(
                "Not seen for {}",
                lablink_core::time::format_age(h.last_seen_ms_ago)
            ),
            Level::Bad,
        );
    }
    match h.ssh_port {
        PortState::Open => ("Ready to connect".into(), Level::Good),
        PortState::Closed => ("Reachable, SSH is off".into(), Level::Warn),
        PortState::Filtered => ("Reachable, SSH not answering".into(), Level::Warn),
        PortState::Unknown | PortState::Disabled => ("Reachable".into(), Level::Neutral),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites(json: &str) -> Vec<SiteStatus> {
        serde_json::from_str(json).unwrap()
    }

    fn site(id: &str, state: &str, scan: Option<&str>, nets: &str) -> String {
        let scan = scan.map_or("null".into(), |s| format!("\"{s}\""));
        format!(
            r#"{{"id":"{id}","name":"{id} lab","state":"{state}","confidence":"high","selected_by":"auto","auto_detect":true,"scan":{scan},"evidence":[],"networks":[{nets}],"devices":{{"total":0,"green":0,"yellow":0,"red":0,"gray":0}}}}"#
        )
    }

    fn net(cidr: &str, active: bool, attached: bool) -> String {
        format!(r#"{{"name":"net","cidr":"{cidr}","active_scan":{active},"attached":{attached}}}"#)
    }

    #[test]
    fn host_counts() {
        assert_eq!(host_count("192.168.1.0/24"), Some(254));
        assert_eq!(host_count("10.0.0.0/31"), Some(2));
        assert_eq!(host_count("10.0.0.5/32"), Some(1));
        assert_eq!(host_count("fd00::/64"), None);
    }

    #[test]
    fn only_attached_networks_of_active_sites_are_offered() {
        let s = sites(&format!(
            "[{},{}]",
            site(
                "a",
                "active",
                None,
                &format!(
                    "{},{},{}",
                    net("192.168.1.0/24", false, true),
                    net("10.1.0.0/24", false, false),
                    net("192.168.1.0/24", true, true)
                )
            ),
            site("b", "away", None, &net("172.16.0.0/24", false, true)),
        ));
        let o = offers(&s);
        assert_eq!(o.len(), 1, "{o:?}");
        assert_eq!(o[0].cidr, "192.168.1.0/24");
        assert_eq!(o[0].hosts, 254);
    }

    #[test]
    fn scanning_is_reported_off_unless_it_really_runs() {
        let off = sites(&format!(
            "[{}]",
            site("a", "active", None, &net("192.168.1.0/24", false, true))
        ));
        assert!(scanning_line(&off).starts_with("Active scanning is off"));
        // Approved for scanning but the site does not allow scans now.
        let blocked = sites(&format!(
            "[{}]",
            site(
                "a",
                "active",
                Some("the site is not confirmed"),
                &net("192.168.1.0/24", true, true)
            )
        ));
        assert!(scanning_line(&blocked).starts_with("Active scanning is off"));
        let on = sites(&format!(
            "[{}]",
            site("a", "active", None, &net("192.168.1.0/24", true, true))
        ));
        let line = scanning_line(&on);
        assert!(line.contains("192.168.1.0/24") && line.contains("may not list everything"));
    }

    #[test]
    fn headlines_never_claim_more_than_was_done() {
        assert_eq!(
            headline(2, 0, &[]),
            "Found 2 devices using passive discovery."
        );
        let h = headline(
            1,
            3,
            &["192.168.1.0/24: 254 addresses probed, 4 responsive".into()],
        );
        assert!(h.starts_with("Found 1 device using passive discovery and a scan"));
        assert!(h.contains("3 devices already on your dashboard are listed"));
        assert!(!h.to_lowercase().contains("all devices"));
    }

    #[test]
    fn stale_hosts_are_not_offered_as_ready() {
        let mut h: DiscoveredHost = serde_json::from_str(
            r#"{"ip":"192.168.1.20","mac":null,"hostname":null,"network_name":null,"interface":null,"sources":["neigh"],"ssh_port":"open","fingerprints":[],"matched_device":null,"note":null,"first_seen_ms_ago":0,"last_seen_ms_ago":1000}"#,
        )
        .unwrap();
        assert_eq!(host_state(&h).1, Level::Good);
        h.last_seen_ms_ago = STALE_MS;
        let (w, l) = host_state(&h);
        assert!(w.starts_with("Not seen for"), "{w}");
        assert_eq!(l, Level::Bad);
        h.last_seen_ms_ago = 0;
        h.ssh_port = PortState::Filtered;
        assert_eq!(host_state(&h).1, Level::Warn);
    }
}
