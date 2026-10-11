//! Who is on the Field Network: the kernel neighbor table for the hotspot
//! interface, plus NetworkManager's DHCP leases when they are readable
//! (they are root-only on most systems). Read-only; nothing is probed.

use crate::system::{Cmd, System};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Presence {
    /// The neighbor answered recently.
    Present,
    /// Known, not confirmed recently.
    Stale,
    /// Only in the DHCP lease file: it had an address, it may have left.
    LeaseOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Client {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    /// The name the client asked DHCP for: a hint from an untrusted
    /// client, never an identity.
    pub hostname: Option<String>,
    pub presence: Presence,
}

pub fn list(sys: &dyn System, interface: &str, subnet: &Ipv4Net) -> Vec<Client> {
    let gw = crate::subnet::gateway(subnet);
    let mut by_ip: BTreeMap<Ipv4Addr, Client> = BTreeMap::new();
    let neigh = sys
        .run(&Cmd::new("ip", &["-4", "neigh", "show", "dev", interface]))
        .ok()
        .filter(|o| o.ok());
    match neigh {
        Some(out) => {
            for c in parse_neigh(&out.stdout) {
                by_ip.insert(c.ip, c);
            }
        }
        None => {
            if let Some(t) = sys.read_file(Path::new("/proc/net/arp")) {
                for c in parse_proc_arp(&t, interface) {
                    by_ip.insert(c.ip, c);
                }
            }
        }
    }
    let leases = sys.read_file(Path::new(&format!(
        "/var/lib/NetworkManager/dnsmasq-{interface}.leases"
    )));
    for (ip, mac, host) in leases.as_deref().map(parse_leases).unwrap_or_default() {
        let e = by_ip.entry(ip).or_insert(Client {
            ip,
            mac: Some(mac.clone()),
            hostname: None,
            presence: Presence::LeaseOnly,
        });
        if e.mac.is_none() {
            e.mac = Some(mac);
        }
        e.hostname = host;
    }
    by_ip
        .into_values()
        .filter(|c| subnet.contains(&c.ip) && c.ip != gw)
        .collect()
}

/// `ip -4 neigh show dev X`: "10.77.0.23 lladdr 02:00:00:00:a0:31 REACHABLE".
/// FAILED and INCOMPLETE entries are not clients.
pub fn parse_neigh(text: &str) -> Vec<Client> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let ip: Ipv4Addr = t.first()?.parse().ok()?;
            let mac = t
                .iter()
                .position(|w| *w == "lladdr")
                .and_then(|i| t.get(i + 1))
                .map(|m| m.to_ascii_lowercase());
            let state = *t.last()?;
            let presence = match state {
                "REACHABLE" | "DELAY" | "PROBE" | "PERMANENT" | "NOARP" => Presence::Present,
                "STALE" => Presence::Stale,
                _ => return None,
            };
            Some(Client {
                ip,
                mac: Some(mac?),
                hostname: None,
                presence,
            })
        })
        .collect()
}

/// `/proc/net/arp` rows on `interface` with a complete entry (flag 0x2).
pub fn parse_proc_arp(text: &str, interface: &str) -> Vec<Client> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.get(5) != Some(&interface) {
                return None;
            }
            let flags = u32::from_str_radix(t.get(2)?.trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            Some(Client {
                ip: t.first()?.parse().ok()?,
                mac: Some(t.get(3)?.to_ascii_lowercase()),
                hostname: None,
                presence: Presence::Stale,
            })
        })
        .collect()
}

/// dnsmasq lease lines: "expiry mac ip hostname client-id". The hostname
/// is client-chosen: kept only if it is a plain label.
pub fn parse_leases(text: &str) -> Vec<(Ipv4Addr, String, Option<String>)> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let ip: Ipv4Addr = t.get(2)?.parse().ok()?;
            let mac = t.get(1)?.to_ascii_lowercase();
            let host = t
                .get(3)
                .filter(|h| {
                    **h != "*"
                        && h.len() <= 63
                        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
                .map(|h| h.to_string());
            Some((ip, mac, host))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{FakeSystem, Output};

    #[test]
    fn neighbors_and_leases_merge_inside_the_subnet_only() {
        let f = FakeSystem::new();
        f.ok(
            "ip -4 neigh show dev wlan0",
            "10.77.0.23 lladdr 02:00:00:00:A0:31 REACHABLE\n10.77.0.40 lladdr 02:00:00:00:00:40 STALE\n10.77.0.50 FAILED\n10.77.0.1 lladdr 02:00:00:00:00:01 PERMANENT\n192.168.8.1 lladdr 94:83:c4:7e:d7:ec REACHABLE\n",
        );
        f.file(
            "/var/lib/NetworkManager/dnsmasq-wlan0.leases",
            "1760000000 02:00:00:00:a0:31 10.77.0.23 orin 01:02\n1760000000 02:00:00:00:00:77 10.77.0.77 phone$(reboot) *\n1760000000 02:00:00:00:00:78 10.77.0.78 * *\n",
        );
        let net: Ipv4Net = "10.77.0.0/24".parse().unwrap();
        let c = list(&f, "wlan0", &net);
        let ips: Vec<String> = c.iter().map(|x| x.ip.to_string()).collect();
        assert_eq!(
            ips,
            ["10.77.0.23", "10.77.0.40", "10.77.0.77", "10.77.0.78"]
        );
        assert_eq!(c[0].mac.as_deref(), Some("02:00:00:00:a0:31"));
        assert_eq!(c[0].hostname.as_deref(), Some("orin"));
        assert_eq!(c[0].presence, Presence::Present);
        assert_eq!(c[1].presence, Presence::Stale);
        assert_eq!(c[2].hostname, None, "a hostile DHCP hostname is dropped");
        assert_eq!(c[2].presence, Presence::LeaseOnly);
    }

    #[test]
    fn falls_back_to_proc_arp() {
        let f = FakeSystem::new();
        f.on("ip -4 neigh", Output::failure(1, "no ip"));
        f.file(
            "/proc/net/arp",
            "IP address       HW type     Flags       HW address            Mask     Device\n10.77.0.23       0x1         0x2         02:00:00:00:a0:31     *        wlan0\n10.77.0.24       0x1         0x0         00:00:00:00:00:00     *        wlan0\n10.77.0.25       0x1         0x2         02:00:00:00:a0:25     *        eth0\n",
        );
        let c = list(&f, "wlan0", &"10.77.0.0/24".parse().unwrap());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].ip, Ipv4Addr::new(10, 77, 0, 23));
    }
}
