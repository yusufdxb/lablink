//! macOS: honest capability detection and a guided Internet Sharing
//! workflow. LabLink does not create a hotspot on macOS: there is no
//! supported public interface for it, and private frameworks or GUI
//! scripting would be fragile and would claim support that is not there.
//! LabLink only reads (`networksetup -listallhardwareports`, `ifconfig`,
//! the Internet Sharing preferences) and tells the user what to click.

use crate::system::{Cmd, System};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MacGuide {
    /// (hardware port, device), e.g. ("Wi-Fi", "en0").
    pub ports: Vec<(String, String)>,
    pub wifi_device: Option<String>,
    /// Internet Sharing is switched on (from its preferences file), if
    /// readable.
    pub internet_sharing: Option<bool>,
    /// The Internet Sharing bridge (`bridge100`) and its subnet, when up.
    pub sharing_subnet: Option<Ipv4Net>,
    pub host_steps: Vec<String>,
    pub join_steps: Vec<String>,
    pub limits: Vec<String>,
}

pub fn guide(sys: &dyn System) -> MacGuide {
    let ports = sys
        .run(&Cmd::new("networksetup", &["-listallhardwareports"]))
        .ok()
        .filter(|o| o.ok())
        .map(|o| parse_hardware_ports(&o.stdout))
        .unwrap_or_default();
    let wifi_device = ports
        .iter()
        .find(|(p, _)| p == "Wi-Fi" || p == "AirPort")
        .map(|(_, d)| d.clone());
    let internet_sharing = sys
        .read_file(Path::new(
            "/Library/Preferences/SystemConfiguration/com.apple.nat.plist",
        ))
        .map(|t| parse_nat_enabled(&t));
    let sharing_subnet = sys
        .run(&Cmd::new("ifconfig", &["bridge100"]))
        .ok()
        .filter(|o| o.ok())
        .and_then(|o| parse_ifconfig_inet(&o.stdout));
    let has_other_uplink = ports.iter().any(|(p, _)| {
        let p = p.to_ascii_lowercase();
        p.contains("ethernet")
            || p.contains("thunderbolt")
            || p.contains("usb")
            || p.contains("iphone")
    });
    let mut host_steps = vec![
        "Connect the Mac's own internet source to something other than Wi-Fi (Ethernet, a USB or Thunderbolt adapter, or an iPhone over USB): Internet Sharing cannot share Wi-Fi to Wi-Fi.".to_string(),
        "Open System Settings > General > Sharing and click (i) next to Internet Sharing.".into(),
        "Share your connection from: the source above. To devices using: Wi-Fi.".into(),
        "Wi-Fi Options: choose a network name, Security WPA2/WPA3 Personal (never None) and a password of at least 12 characters.".into(),
        "Turn Internet Sharing on. Devices get 192.168.2.x addresses; the Mac is 192.168.2.1.".into(),
        "Run `lablink hotspot capabilities` again: LabLink reads the shared subnet and shows the command that adds it as your Field Network site.".into(),
    ];
    if !has_other_uplink {
        host_steps.insert(
            0,
            "This Mac reports no Ethernet, USB or Thunderbolt network port: you need one (an adapter works) before it can host a Field Network.".into(),
        );
    }
    MacGuide {
        wifi_device,
        ports,
        internet_sharing,
        sharing_subnet,
        host_steps,
        join_steps: vec![
            "Choose the Field Network in the Wi-Fi menu and type its password (on the Linux host: `lablink hotspot password`).".into(),
            "LabLink does not join networks for you on macOS: `networksetup -setairportnetwork` would put the password on the command line, where other local users can read it.".into(),
        ],
        limits: vec![
            "Hosting is manual (System Settings); LabLink cannot start, stop or verify the hotspot's security on macOS.".into(),
            "Internet Sharing always shares the Mac's internet connection with every client (NAT); it cannot run offline-only.".into(),
            "Internet Sharing's subnet is fixed by macOS (192.168.2.0/24 by default) and may collide with a site network.".into(),
        ],
    }
}

/// `networksetup -listallhardwareports` blocks:
/// "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: ...".
pub fn parse_hardware_ports(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut port: Option<String> = None;
    for l in text.lines() {
        if let Some(p) = l.strip_prefix("Hardware Port: ") {
            port = Some(p.trim().to_string());
        } else if let Some(d) = l.strip_prefix("Device: ") {
            if let Some(p) = port.take() {
                out.push((p, d.trim().to_string()));
            }
        }
    }
    out
}

/// `com.apple.nat.plist` (XML): `<key>Enabled</key>` followed by
/// `<integer>1</integer>` or `<true/>` inside the NAT dictionary.
pub fn parse_nat_enabled(text: &str) -> bool {
    let compact: String = text.split_whitespace().collect();
    compact.contains("<key>Enabled</key><integer>1</integer>")
        || compact.contains("<key>Enabled</key><true/>")
}

/// "inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255".
pub fn parse_ifconfig_inet(text: &str) -> Option<Ipv4Net> {
    for l in text.lines() {
        let t: Vec<&str> = l.split_whitespace().collect();
        if t.first() != Some(&"inet") {
            continue;
        }
        let ip: std::net::Ipv4Addr = t.get(1)?.parse().ok()?;
        let mask = t
            .iter()
            .position(|w| *w == "netmask")
            .and_then(|i| t.get(i + 1))
            .and_then(|m| u32::from_str_radix(m.trim_start_matches("0x"), 16).ok())?;
        return Ipv4Net::new(ip, mask.count_ones() as u8)
            .ok()
            .map(|n| n.trunc());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{FakeSystem, Os};

    #[test]
    fn mac_with_internet_sharing_on() {
        let mut f = FakeSystem::new();
        f.os_family = Some(Os::Macos);
        f.ok(
            "networksetup -listallhardwareports",
            "\nHardware Port: Thunderbolt Ethernet Slot 1\nDevice: en5\nEthernet Address: aa:bb:cc:dd:ee:01\n\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:02\n",
        );
        f.ok(
            "ifconfig bridge100",
            "bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255\n",
        );
        f.file(
            "/Library/Preferences/SystemConfiguration/com.apple.nat.plist",
            "<dict>\n<key>NAT</key>\n<dict>\n  <key>Enabled</key>\n  <integer>1</integer>\n</dict>\n</dict>",
        );
        let g = guide(&f);
        assert_eq!(g.wifi_device.as_deref(), Some("en0"));
        assert_eq!(g.internet_sharing, Some(true));
        assert_eq!(g.sharing_subnet, Some("192.168.2.0/24".parse().unwrap()));
        assert!(!g.host_steps[0].contains("no Ethernet"));
        assert!(g.limits.iter().any(|l| l.contains("NAT")));
    }

    #[test]
    fn wifi_only_mac_is_told_it_needs_another_port() {
        let mut f = FakeSystem::new();
        f.os_family = Some(Os::Macos);
        f.ok(
            "networksetup -listallhardwareports",
            "Hardware Port: Wi-Fi\nDevice: en0\n",
        );
        let g = guide(&f);
        assert!(g.host_steps[0].contains("no Ethernet"));
        assert_eq!(g.internet_sharing, None, "unreadable is unknown, not off");
        assert_eq!(g.sharing_subnet, None);
    }
}
