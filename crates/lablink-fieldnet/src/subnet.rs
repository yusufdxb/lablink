//! Choosing the Field Network's IPv4 subnet so it collides with nothing
//! this machine can already reach: attached networks, routes in any table
//! (VPNs keep theirs outside `main`), container bridges, the CGNAT range
//! VPN overlays use, and every network a LabLink site already claims.

use crate::host::HostFacts;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::net::Ipv4Addr;

pub const DEFAULT_SUBNET: &str = "10.77.0.0/24";

/// A range the Field Network must not overlap, and why.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Reserved {
    pub net: Ipv4Net,
    pub why: String,
}

/// Every range this machine already uses or that is commonly claimed.
/// `sites`: (site id, network cidr) of the other LabLink sites.
pub fn reserved(
    facts: &HostFacts,
    sites: &[(String, Ipv4Net)],
    hotspot_iface: Option<&str>,
) -> Vec<Reserved> {
    let mut out = Vec::new();
    for a in &facts.addresses {
        if a.net.addr().is_loopback() || Some(a.interface.as_str()) == hotspot_iface {
            continue;
        }
        out.push(Reserved {
            net: a.net.trunc(),
            why: format!("attached on {}", a.interface),
        });
    }
    for r in &facts.routes {
        if r.is_default() || Some(r.device.as_str()) == hotspot_iface || r.dest.addr().is_loopback()
        {
            continue;
        }
        out.push(Reserved {
            net: r.dest.trunc(),
            why: format!("routed via {} (table {})", r.device, r.table),
        });
    }
    for (net, why) in [
        (
            "100.64.0.0/10",
            "carrier-grade NAT range used by VPN overlays",
        ),
        ("172.17.0.0/16", "default container bridge range"),
    ] {
        out.push(Reserved {
            net: net.parse().unwrap(),
            why: why.into(),
        });
    }
    for (site, net) in sites {
        out.push(Reserved {
            net: *net,
            why: format!("LabLink site '{site}'"),
        });
    }
    out
}

pub fn overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Which reserved ranges `net` overlaps.
pub fn conflicts<'a>(net: &Ipv4Net, reserved: &'a [Reserved]) -> Vec<&'a Reserved> {
    reserved.iter().filter(|r| overlaps(net, &r.net)).collect()
}

/// A requested subnet must be private IPv4, between /22 and /28.
pub fn validate(net: &Ipv4Net) -> Result<(), String> {
    if net.trunc() != *net {
        return Err(format!(
            "{net} has host bits set; did you mean {}?",
            net.trunc()
        ));
    }
    if !lablink_core::net::is_private_v4(net) {
        return Err(format!("{net} is not a private (RFC 1918) range"));
    }
    if !(22..=28).contains(&net.prefix_len()) {
        return Err(format!(
            "{net}: use a prefix between /22 and /28 (a /24 suits a field network)"
        ));
    }
    Ok(())
}

/// The first free /24 among 10.77.0.0/24, 10.77.1.0/24 ... 10.79.255.0/24.
pub fn choose(reserved: &[Reserved]) -> Option<Ipv4Net> {
    (77u8..=79)
        .flat_map(|b| {
            (0u8..=255).map(move |c| Ipv4Net::new(Ipv4Addr::new(10, b, c, 0), 24).unwrap())
        })
        .find(|n| conflicts(n, reserved).is_empty())
}

/// The gateway (this machine) on the Field Network: the first host.
pub fn gateway(net: &Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(net.network()) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{gather, script_host};
    use crate::system::FakeSystem;

    fn facts() -> HostFacts {
        let f = FakeSystem::new();
        script_host(&f);
        gather(&f)
    }

    fn n(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn default_is_free_on_a_typical_host() {
        let r = reserved(&facts(), &[], Some("wlan0"));
        assert_eq!(choose(&r), Some(n(DEFAULT_SUBNET)));
        assert_eq!(gateway(&n(DEFAULT_SUBNET)), Ipv4Addr::new(10, 77, 0, 1));
    }

    #[test]
    fn avoids_sites_vpn_routes_and_bridges() {
        let mut f = facts();
        f.routes.push(crate::host::Route {
            dest: n("10.77.0.0/16"),
            device: "wg0".into(),
            via: None,
            table: "51820".into(),
        });
        let sites = vec![("lab".to_string(), n("10.78.0.0/24"))];
        let r = reserved(&f, &sites, Some("wlan0"));
        assert_eq!(choose(&r), Some(n("10.78.1.0/24")));
        let c = conflicts(&n("10.77.5.0/24"), &r);
        assert!(c.iter().any(|x| x.why.contains("wg0")));
        assert!(
            !conflicts(&n("100.100.0.0/24"), &r).is_empty(),
            "CGNAT is reserved"
        );
        assert!(!conflicts(&n("172.17.3.0/24"), &r).is_empty());
    }

    #[test]
    fn the_hotspot_interface_s_own_network_is_not_a_conflict() {
        // wlan0's current network goes away when the hotspot replaces that
        // connection (site networks are reserved separately); on another
        // adapter it stays attached and is a conflict.
        let r = reserved(&facts(), &[], Some("wlan0"));
        assert!(conflicts(&n("192.168.8.0/24"), &r).is_empty());
        let r = reserved(&facts(), &[], Some("wlan1"));
        assert!(!conflicts(&n("192.168.8.0/24"), &r).is_empty());
    }

    #[test]
    fn validation() {
        assert!(validate(&n("10.77.0.0/24")).is_ok());
        assert!(validate(&n("10.77.0.1/24"))
            .unwrap_err()
            .contains("host bits"));
        assert!(validate(&n("8.8.8.0/24")).unwrap_err().contains("private"));
        assert!(validate(&n("10.0.0.0/8")).unwrap_err().contains("prefix"));
    }
}
