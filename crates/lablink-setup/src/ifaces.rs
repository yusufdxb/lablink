//! Local IPv4 networks of this machine, for first-run network selection and
//! site creation.
//!
//! Read from `getifaddrs(3)`, `/sys/class/net` and (for the site detection
//! hints) the default routes, the ARP table and the Wi-Fi SSID; nothing is
//! sent on the network. Whether a network may be actively scanned is decided
//! by the same rule the daemon enforces (`lablink_core::net::validate_scan_range`).

use ipnet::Ipv4Net;
use lablink_core::config::NetworkConfig;
use lablink_core::net;
use std::net::Ipv4Addr;

/// What kind of link an interface is (best effort, from sysfs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Wired,
    Wireless,
    /// Bridges, container and VM networks, VPN tunnels.
    Virtual,
}

impl LinkKind {
    pub fn word(self) -> &'static str {
        match self {
            LinkKind::Wired => "wired",
            LinkKind::Wireless => "Wi-Fi",
            LinkKind::Virtual => "virtual",
        }
    }
}

/// One IPv4 network attached to this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    pub interface: String,
    pub address: Ipv4Addr,
    pub network: Ipv4Net,
    pub kind: LinkKind,
    pub private: bool,
    /// Why active scanning would be refused (`None`: allowed).
    pub scan_refusal: Option<String>,
    /// Default gateway on this network, if any.
    pub gateway: Option<Ipv4Addr>,
    /// The gateway's MAC address (from the ARP table).
    pub gateway_mac: Option<String>,
    /// Wi-Fi network name, for wireless links.
    pub ssid: Option<String>,
}

impl LocalNetwork {
    pub fn cidr(&self) -> String {
        self.network.to_string()
    }
    pub fn scan_allowed(&self) -> bool {
        self.scan_refusal.is_none()
    }
    /// Addresses an active scan would probe.
    pub fn host_count(&self) -> u64 {
        net::host_count(&self.network)
    }

    /// A config entry for this network, with the detection hints that let
    /// LabLink recognize the site later (interface, gateway and its MAC,
    /// SSID). None of them grant anything: they only identify the place.
    pub fn to_network_config(&self, name: &str, active_scan: bool) -> NetworkConfig {
        let mut n = NetworkConfig::new(name, &self.cidr(), active_scan);
        n.interface =
            lablink_core::config::valid_interface(&self.interface).then(|| self.interface.clone());
        n.gateway = self.gateway.map(|g| g.to_string());
        n.gateway_mac = self.gateway_mac.clone();
        n.ssid = self
            .ssid
            .clone()
            .filter(|s| lablink_core::config::valid_ssid(s));
        n
    }
}

fn link_kind(ifname: &str) -> LinkKind {
    let base = std::path::Path::new("/sys/class/net").join(ifname);
    if base.join("wireless").exists() || base.join("phy80211").exists() {
        return LinkKind::Wireless;
    }
    let virtual_name = [
        "docker",
        "br-",
        "veth",
        "virbr",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
        "vmnet",
        "lxc",
        "cni",
        "flannel",
    ]
    .iter()
    .any(|p| ifname.starts_with(p));
    let virtual_dev = std::fs::read_link(&base)
        .map(|t| t.to_string_lossy().contains("/virtual/"))
        .unwrap_or(false);
    if virtual_name || virtual_dev {
        LinkKind::Virtual
    } else {
        LinkKind::Wired
    }
}

/// Classify one interface address (pure, for tests).
pub fn classify(
    interface: &str,
    address: Ipv4Addr,
    prefix: u8,
    kind: LinkKind,
) -> Option<LocalNetwork> {
    if address.is_loopback() || address.is_link_local() || address.is_unspecified() {
        return None;
    }
    let network = Ipv4Net::new(address, prefix).ok()?.trunc();
    let scan_refusal = net::validate_scan_range(&network.to_string(), net::DEFAULT_MAX_SCAN_HOSTS)
        .err()
        .map(|e| e.to_string());
    Some(LocalNetwork {
        interface: interface.to_string(),
        address,
        private: net::is_private_v4(&network),
        network,
        kind,
        scan_refusal,
        gateway: None,
        gateway_mac: None,
        ssid: None,
    })
}

/// Up, non-loopback IPv4 networks, private ones first, then by interface.
pub fn detect() -> Vec<LocalNetwork> {
    let mut out: Vec<LocalNetwork> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list that we free below; we only read it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node of the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        let up = ifa.ifa_flags & (libc::IFF_UP as u32) != 0;
        let lo = ifa.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
        // SAFETY: ifa_addr is non-null; sa_family is valid for every sockaddr.
        if !up || lo || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_INET {
            continue;
        }
        // SAFETY: AF_INET means both are sockaddr_in.
        let (addr, mask) = unsafe {
            let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
            (
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u32::from_be(m.sin_addr.s_addr),
            )
        };
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let prefix = mask.leading_ones() as u8;
        if let Some(n) = classify(&name, addr, prefix, link_kind(&name)) {
            if !out.iter().any(|o| o.network == n.network) {
                out.push(n);
            }
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    let routes = lablink_platform::default_routes();
    for n in &mut out {
        if let Some(r) = routes
            .iter()
            .find(|r| r.interface == n.interface && n.network.contains(&r.gateway))
        {
            n.gateway = Some(r.gateway);
            n.gateway_mac = lablink_platform::arp_mac(r.gateway)
                .and_then(|m| lablink_core::config::normalize_mac(&m));
        }
        if n.kind == LinkKind::Wireless {
            n.ssid = lablink_platform::ssid(&n.interface);
        }
    }
    out.sort_by_key(|n| (!n.private, n.kind == LinkKind::Virtual, n.interface.clone()));
    out
}

/// A config network name for an interface: its name, made valid and unique.
pub fn network_name(interface: &str, taken: &[String]) -> String {
    let mut base: String = interface
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    base = base.trim_start_matches('-').to_string();
    if base.is_empty() {
        base = "net".into();
    }
    base.truncate(60);
    let mut name = base.clone();
    let mut n = 2;
    while taken.iter().any(|t| t.eq_ignore_ascii_case(&name)) {
        name = format!("{base}-{n}");
        n += 1;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_uses_the_daemon_scan_rules() {
        let a = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let lan = classify("wlp5s0", a("192.168.10.42"), 24, LinkKind::Wireless).unwrap();
        assert_eq!(lan.cidr(), "192.168.10.0/24");
        assert!(lan.private && lan.scan_allowed());
        assert_eq!(lan.host_count(), 254);
        let docker = classify("docker0", a("172.17.0.1"), 16, LinkKind::Virtual).unwrap();
        assert!(docker.private && !docker.scan_allowed());
        assert!(docker.scan_refusal.unwrap().contains("scan limit"));
        let public = classify("eth0", a("203.0.113.10"), 24, LinkKind::Wired).unwrap();
        assert!(!public.private && !public.scan_allowed());
        assert!(classify("lo", a("127.0.0.1"), 8, LinkKind::Virtual).is_none());
        assert!(classify("x", a("169.254.3.3"), 16, LinkKind::Wired).is_none());
    }

    #[test]
    fn network_names_are_valid_and_unique() {
        assert_eq!(network_name("wlp5s0", &[]), "wlp5s0");
        assert_eq!(network_name("eth0", &["ETH0".into()]), "eth0-2");
        assert_eq!(network_name("en p@1", &[]), "en_p_1");
        assert_eq!(network_name("--", &[]), "net");
        for n in [network_name("a:b", &[]), network_name(&"x".repeat(80), &[])] {
            assert!(lablink_core::config::valid_name(&n), "{n}");
        }
    }

    #[test]
    fn detect_runs_on_this_machine() {
        // Loopback is never reported; everything reported is a valid CIDR.
        for n in detect() {
            assert!(!n.address.is_loopback());
            lablink_core::net::parse_cidr(&n.cidr()).unwrap();
        }
    }
}
