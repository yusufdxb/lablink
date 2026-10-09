//! Network allowlist and active-scan safety limits.
//!
//! LabLink only ever *actively* scans IPv4 ranges that are (a) explicitly
//! configured with `active_scan: true` or deliberately requested once on the
//! command line, (b) private (RFC 1918) or link-local, and (c) no larger than
//! the configured host limit, which itself can never exceed
//! [`HARD_MAX_SCAN_HOSTS`]. Everything else is passive only.

use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Default per-scan host limit: a /22.
pub const DEFAULT_MAX_SCAN_HOSTS: u32 = 1024;
/// Absolute ceiling (a /20). Not configurable: a lab tool never needs more.
pub const HARD_MAX_SCAN_HOSTS: u32 = 4096;

/// Why an active scan was refused. Rendered verbatim in logs and CLI errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanRefusal {
    #[error("'{0}' is not a valid CIDR (expected e.g. 192.168.50.0/24)")]
    InvalidCidr(String),
    #[error("'{given}' has host bits set; did you mean {suggested}?")]
    HostBitsSet { given: String, suggested: String },
    #[error("active scanning of IPv6 ranges is not supported ({0}); IPv6 hosts are discovered passively")]
    Ipv6Unsupported(String),
    #[error("{cidr} contains {hosts} hosts, above the scan limit of {max} (use a smaller range such as a /24)")]
    TooLarge { cidr: String, hosts: u64, max: u32 },
    #[error("{0} is not a private (RFC 1918) or link-local range; LabLink never actively scans public address space")]
    NotPrivate(String),
    #[error("{0} is not in the configured network allowlist with active_scan: true")]
    NotAllowlisted(String),
    #[error("no local interface has an address inside {0}; refusing to scan a network this host is not directly attached to")]
    NotConnected(String),
}

/// Parse a CIDR strictly: valid syntax, explicit prefix, host bits clear.
pub fn parse_cidr(s: &str) -> Result<IpNet, ScanRefusal> {
    let s = s.trim();
    if !s.contains('/') {
        return Err(ScanRefusal::InvalidCidr(s.to_string()));
    }
    let net = IpNet::from_str(s).map_err(|_| ScanRefusal::InvalidCidr(s.to_string()))?;
    if net.trunc() != net {
        return Err(ScanRefusal::HostBitsSet {
            given: s.to_string(),
            suggested: net.trunc().to_string(),
        });
    }
    Ok(net)
}

/// Number of scannable host addresses (network/broadcast excluded below /31).
pub fn host_count(net: &Ipv4Net) -> u64 {
    let total: u64 = 1u64 << (32 - u32::from(net.prefix_len()));
    if net.prefix_len() >= 31 {
        total
    } else {
        total - 2
    }
}

/// RFC 1918 private or 169.254/16 link-local.
pub fn is_private_v4(net: &Ipv4Net) -> bool {
    const RANGES: [(Ipv4Addr, u8); 4] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
    ];
    RANGES.iter().any(|(a, p)| {
        Ipv4Net::new(*a, *p)
            .map(|r| r.contains(net))
            .unwrap_or(false)
    })
}

/// Validate a range for active scanning against syntax, family, privacy and size.
/// Allowlist membership and connectivity are checked separately.
pub fn validate_scan_range(cidr: &str, max_hosts: u32) -> Result<Ipv4Net, ScanRefusal> {
    let net = parse_cidr(cidr)?;
    let v4 = match net {
        IpNet::V4(v4) => v4,
        IpNet::V6(_) => return Err(ScanRefusal::Ipv6Unsupported(net.to_string())),
    };
    let max = max_hosts.min(HARD_MAX_SCAN_HOSTS);
    let hosts = host_count(&v4);
    if hosts > u64::from(max) {
        return Err(ScanRefusal::TooLarge {
            cidr: v4.to_string(),
            hosts,
            max,
        });
    }
    if !is_private_v4(&v4) {
        return Err(ScanRefusal::NotPrivate(v4.to_string()));
    }
    Ok(v4)
}

/// Scan targets for a validated range (excludes network/broadcast below /31).
pub fn scan_targets(net: &Ipv4Net) -> Vec<Ipv4Addr> {
    net.hosts().collect()
}

/// One configured network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedNetwork {
    /// Id of the site the network belongs to.
    pub site: String,
    pub name: String,
    pub net: IpNet,
    pub active_scan: bool,
}

/// The configured network allowlist.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    pub networks: Vec<AllowedNetwork>,
    pub max_scan_hosts: u32,
}

impl Allowlist {
    /// The most specific configured network containing `ip`.
    pub fn network_for(&self, ip: IpAddr) -> Option<&AllowedNetwork> {
        self.networks
            .iter()
            .filter(|n| n.net.contains(&ip))
            .max_by_key(|n| n.net.prefix_len())
    }

    /// The most specific network containing `ip`, preferring networks of the
    /// sites in `preferred` (several sites may use the same private range).
    pub fn network_for_sites(&self, ip: IpAddr, preferred: &[String]) -> Option<&AllowedNetwork> {
        self.networks
            .iter()
            .filter(|n| n.net.contains(&ip))
            .max_by_key(|n| (preferred.contains(&n.site), n.net.prefix_len()))
    }

    /// Whether `ip` lies inside any configured network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network_for(ip).is_some()
    }

    /// Ids of the sites with a network containing `ip`.
    pub fn sites_containing(&self, ip: IpAddr) -> Vec<String> {
        let mut v: Vec<String> = self
            .networks
            .iter()
            .filter(|n| n.net.contains(&ip))
            .map(|n| n.site.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Decide whether an automatic (background) active scan of a configured
    /// network is permitted, given the local interface prefixes currently up.
    pub fn check_auto_scan(
        &self,
        network: &AllowedNetwork,
        local_prefixes: &[IpNet],
    ) -> Result<Ipv4Net, ScanRefusal> {
        if !network.active_scan {
            return Err(ScanRefusal::NotAllowlisted(network.net.to_string()));
        }
        let v4 = validate_scan_range(&network.net.to_string(), self.max_scan_hosts)?;
        if !is_attached(&IpNet::V4(v4), local_prefixes) {
            return Err(ScanRefusal::NotConnected(v4.to_string()));
        }
        Ok(v4)
    }

    /// Decide whether a deliberate one-time scan requested by the user is
    /// permitted. The range need not be in the allowlist (the user typed it),
    /// but it must still be private, IPv4, within limits and directly attached.
    pub fn check_one_time_scan(
        &self,
        cidr: &str,
        local_prefixes: &[IpNet],
    ) -> Result<Ipv4Net, ScanRefusal> {
        let v4 = validate_scan_range(cidr, self.max_scan_hosts)?;
        if !is_attached(&IpNet::V4(v4), local_prefixes) {
            return Err(ScanRefusal::NotConnected(v4.to_string()));
        }
        Ok(v4)
    }
}

/// True if `net` lies entirely inside a directly attached subnet. A range
/// wider than the local subnet is not "attached", even if it overlaps it.
pub fn is_attached(net: &IpNet, local_prefixes: &[IpNet]) -> bool {
    local_prefixes.iter().any(|p| p.contains(net))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(v: &[&str]) -> Vec<IpNet> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn strict_cidr_parsing() {
        assert!(parse_cidr("192.168.50.0/24").is_ok());
        assert!(matches!(
            parse_cidr("192.168.50.5/24"),
            Err(ScanRefusal::HostBitsSet { ref suggested, .. }) if suggested == "192.168.50.0/24"
        ));
        assert!(matches!(
            parse_cidr("192.168.50.0"),
            Err(ScanRefusal::InvalidCidr(_))
        ));
        assert!(matches!(
            parse_cidr("192.168.50.0/33"),
            Err(ScanRefusal::InvalidCidr(_))
        ));
        assert!(matches!(
            parse_cidr("banana/24"),
            Err(ScanRefusal::InvalidCidr(_))
        ));
        assert!(matches!(parse_cidr(""), Err(ScanRefusal::InvalidCidr(_))));
    }

    #[test]
    fn host_counts() {
        assert_eq!(host_count(&"192.168.1.0/24".parse().unwrap()), 254);
        assert_eq!(host_count(&"192.168.1.0/22".parse().unwrap()), 1022);
        assert_eq!(host_count(&"192.168.1.0/31".parse().unwrap()), 2);
        assert_eq!(host_count(&"192.168.1.1/32".parse().unwrap()), 1);
        assert_eq!(host_count(&"10.0.0.0/8".parse().unwrap()), 16_777_214);
        assert_eq!(host_count(&"0.0.0.0/0".parse().unwrap()), 4_294_967_294);
    }

    #[test]
    fn large_networks_rejected() {
        for cidr in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "0.0.0.0/0",
            "10.1.0.0/20",
        ] {
            assert!(
                matches!(
                    validate_scan_range(cidr, DEFAULT_MAX_SCAN_HOSTS),
                    Err(ScanRefusal::TooLarge { .. })
                ),
                "{cidr} must be rejected"
            );
        }
        assert!(validate_scan_range("10.1.0.0/22", DEFAULT_MAX_SCAN_HOSTS).is_ok());
    }

    #[test]
    fn hard_ceiling_cannot_be_raised() {
        // A user-configured limit above the ceiling is clamped.
        assert!(validate_scan_range("10.1.0.0/20", u32::MAX).is_ok()); // 4094 hosts
        assert!(matches!(
            validate_scan_range("10.1.0.0/19", u32::MAX),
            Err(ScanRefusal::TooLarge {
                max: HARD_MAX_SCAN_HOSTS,
                ..
            })
        ));
    }

    #[test]
    fn public_and_v6_rejected() {
        assert!(matches!(
            validate_scan_range("8.8.8.0/24", 1024),
            Err(ScanRefusal::NotPrivate(_))
        ));
        assert!(matches!(
            validate_scan_range("203.0.113.0/24", 1024),
            Err(ScanRefusal::NotPrivate(_))
        ));
        assert!(matches!(
            validate_scan_range("fd00::/120", 1024),
            Err(ScanRefusal::Ipv6Unsupported(_))
        ));
        assert!(validate_scan_range("169.254.10.0/24", 1024).is_ok());
    }

    fn allowlist() -> Allowlist {
        Allowlist {
            networks: vec![
                AllowedNetwork {
                    site: "s".into(),
                    name: "robot-a".into(),
                    net: "192.168.50.0/24".parse().unwrap(),
                    active_scan: true,
                },
                AllowedNetwork {
                    site: "s".into(),
                    name: "lab".into(),
                    net: "192.168.10.0/24".parse().unwrap(),
                    active_scan: false,
                },
            ],
            max_scan_hosts: DEFAULT_MAX_SCAN_HOSTS,
        }
    }

    #[test]
    fn auto_scan_requires_flag_and_attachment() {
        let a = allowlist();
        let local = nets(&["192.168.50.10/24", "198.51.100.2/22"]);
        assert!(a.check_auto_scan(&a.networks[0], &local).is_ok());
        assert!(matches!(
            a.check_auto_scan(&a.networks[1], &local),
            Err(ScanRefusal::NotAllowlisted(_))
        ));
        let elsewhere = nets(&["198.51.100.2/22"]);
        assert!(matches!(
            a.check_auto_scan(&a.networks[0], &elsewhere),
            Err(ScanRefusal::NotConnected(_))
        ));
    }

    #[test]
    fn one_time_scan_still_bounded() {
        let a = allowlist();
        let local = nets(&["192.168.50.7/24", "10.0.0.5/8"]);
        assert!(a.check_one_time_scan("192.168.50.0/24", &local).is_ok());
        assert!(matches!(
            a.check_one_time_scan("10.0.0.0/8", &local),
            Err(ScanRefusal::TooLarge { .. })
        ));
        assert!(matches!(
            a.check_one_time_scan("192.168.77.0/24", &local),
            Err(ScanRefusal::NotConnected(_))
        ));
    }

    #[test]
    fn most_specific_network_wins() {
        let mut a = allowlist();
        a.networks.push(AllowedNetwork {
            site: "s".into(),
            name: "wide".into(),
            net: "192.168.0.0/16".parse().unwrap(),
            active_scan: false,
        });
        assert_eq!(
            a.network_for("192.168.50.161".parse().unwrap())
                .unwrap()
                .name,
            "robot-a"
        );
        assert_eq!(
            a.network_for("192.168.9.1".parse().unwrap()).unwrap().name,
            "wide"
        );
        assert!(a.network_for("10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn targets_exclude_network_and_broadcast() {
        let t = scan_targets(&"192.168.50.0/30".parse().unwrap());
        assert_eq!(
            t,
            vec![
                Ipv4Addr::new(192, 168, 50, 1),
                Ipv4Addr::new(192, 168, 50, 2)
            ]
        );
    }
}

#[cfg(test)]
mod attach_tests {
    use super::*;

    #[test]
    fn wider_range_than_local_subnet_is_not_attached() {
        let local: Vec<IpNet> = vec!["192.168.50.7/24".parse().unwrap()];
        assert!(is_attached(&"192.168.50.0/24".parse().unwrap(), &local));
        assert!(is_attached(&"192.168.50.128/25".parse().unwrap(), &local));
        assert!(
            !is_attached(&"192.168.48.0/22".parse().unwrap(), &local),
            "overlap is not containment"
        );
        assert!(!is_attached(&"192.168.51.0/24".parse().unwrap(), &local));
    }
}
