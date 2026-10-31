//! Add a device by hostname, Tailscale name or IP address.
//!
//! A device on a directly attached network is found by discovery and
//! adopted. A device LabLink cannot scan for (a hostname, a Tailscale or
//! other routed address) is added to `config.yaml` instead, with the name or
//! address the person typed; the daemon then resolves and monitors it like
//! any configured device. Nothing is scanned and nothing is trusted here:
//! the host key is still verified explicitly afterwards.

use lablink_core::config::{normalize_hostname, valid_hostname, valid_name, Config, DeviceConfig};
use std::net::{IpAddr, ToSocketAddrs};

/// What the person typed, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    Host(String),
}

impl Target {
    /// Accepts an IP address or a hostname (`orin`, `orin.local`,
    /// `orin.tail1234.ts.net`). Surrounding spaces and a trailing dot are
    /// ignored; anything else is refused with a reason.
    pub fn parse(input: &str) -> Result<Target, String> {
        let s = input.trim();
        if s.is_empty() {
            return Err("Enter the device's IP address or hostname.".into());
        }
        let bare = s.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
                return Err(format!("{ip} is not a device address."));
            }
            return Ok(Target::Ip(ip));
        }
        if s.contains('@') {
            return Err("Enter only the address. The username goes in the Username field.".into());
        }
        if s.contains(':') || s.contains('/') {
            return Err("Enter the address without a port or path.".into());
        }
        // All-numeric dotted text that is not an IP is a typo, not a name.
        if s.split('.').all(|l| l.chars().all(|c| c.is_ascii_digit())) {
            return Err(format!("'{s}' is not a valid IP address."));
        }
        if !valid_hostname(s) {
            return Err(format!("'{s}' is not a valid hostname."));
        }
        Ok(Target::Host(s.trim_end_matches('.').to_ascii_lowercase()))
    }

    pub fn display(&self) -> String {
        match self {
            Target::Ip(ip) => ip.to_string(),
            Target::Host(h) => h.clone(),
        }
    }
}

/// A LabLink name for the target: the first label of a hostname
/// (`orin.tail1234.ts.net` -> `orin`), else `device-<address>`.
pub fn suggest_name(t: &Target) -> String {
    let raw = match t {
        Target::Host(h) => normalize_hostname(h)
            .split('.')
            .next()
            .unwrap_or_default()
            .to_string(),
        Target::Ip(ip) => format!("device-{}", ip.to_string().replace(['.', ':'], "-")),
    };
    let name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(64)
        .collect();
    if valid_name(&name) {
        name
    } else {
        "device".into()
    }
}

/// `name` if the site has no device answering to it, else `name-2`,
/// `name-3`, ...
pub fn free_name(cfg: &Config, site: &str, name: &str) -> String {
    let taken = |n: &str| {
        cfg.sites
            .iter()
            .filter(|s| s.id == site)
            .flat_map(|s| s.devices.iter())
            .any(|d| d.answers_to(n))
    };
    if !taken(name) {
        return name.to_string();
    }
    (2..)
        .map(|i| format!("{name}-{i}"))
        .find(|n| !taken(n))
        .expect("unbounded")
}

/// Resolve a hostname to addresses with the system resolver (DNS, mDNS,
/// MagicDNS, /etc/hosts). Used to tell people early that a name does not
/// resolve; the daemon resolves it again on its own schedule.
pub fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    let mut v: Vec<IpAddr> = (host, 22)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .map(|a| a.ip())
        .collect();
    v.sort();
    v.dedup();
    if v.is_empty() {
        return Err("no addresses".into());
    }
    Ok(v)
}

/// Add a device named `name` that LabLink reaches at `target` to `site`.
/// Refuses a name already used in the site and an address or hostname
/// another device of the site already claims, so the dashboard never shows
/// one machine twice. Returns the new device id.
pub fn add_to_config(
    cfg: &mut Config,
    site: &str,
    name: &str,
    target: &Target,
    username: &str,
) -> Result<String, String> {
    if !valid_name(name) {
        return Err(format!("'{name}' is not a valid device name."));
    }
    let s = cfg
        .sites
        .iter_mut()
        .find(|s| s.id == site)
        .ok_or_else(|| format!("site '{site}' is not in the configuration"))?;
    if let Some(d) = s.devices.iter().find(|d| d.answers_to(name)) {
        return Err(format!(
            "This site already has a device named {}. Choose another name.",
            d.name
        ));
    }
    let claimed_by = |d: &DeviceConfig| match target {
        Target::Ip(ip) => d.expected_ip_addrs().contains(ip),
        Target::Host(h) => {
            let n = normalize_hostname(h);
            d.hostnames.iter().any(|x| normalize_hostname(x) == n)
        }
    };
    if let Some(d) = s.devices.iter().find(|d| claimed_by(d)) {
        return Err(format!(
            "{} is already {site}/{}. Open it from the dashboard instead.",
            target.display(),
            d.name
        ));
    }
    let mut d = DeviceConfig::named(name);
    match target {
        Target::Ip(ip) => d.expected_ips.push(ip.to_string()),
        Target::Host(h) => d.hostnames.push(h.clone()),
    }
    if !username.is_empty() {
        d.usernames.push(username.to_string());
    }
    s.devices.push(d);
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(format!("{site}/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "sites:\n  - id: lab\n    name: Lab\n    devices:\n      - name: jetson\n        hostnames: [jetson.local]\n        expected_ips: [192.168.50.10]\n  - id: home\n    name: Home\n    auto_detect: false\n    devices: []\n";

    fn cfg() -> Config {
        Config::parse(CFG, "test").unwrap()
    }

    #[test]
    fn parses_addresses_and_names() {
        assert_eq!(
            Target::parse(" 100.64.0.10 ").unwrap(),
            Target::Ip("100.64.0.10".parse().unwrap())
        );
        assert_eq!(
            Target::parse("[fd7a:115c::1]").unwrap(),
            Target::Ip("fd7a:115c::1".parse().unwrap())
        );
        assert_eq!(
            Target::parse("Orin.tail1234.ts.net.").unwrap(),
            Target::Host("orin.tail1234.ts.net".into())
        );
        for bad in [
            "",
            "10.0.0.256",
            "1.2.3",
            "nvidia@orin",
            "orin:22",
            "orin/x",
            "bad host",
            "127.0.0.1",
            "0.0.0.0",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_are_suggested_from_the_first_label() {
        let n = |s: &str| suggest_name(&Target::parse(s).unwrap());
        assert_eq!(n("orin.tail1234.ts.net"), "orin");
        assert_eq!(n("Jetson-A.local"), "jetson-a");
        assert_eq!(n("10.0.0.5"), "device-10-0-0-5");
        assert_eq!(n("fd7a::1"), "device-fd7a--1");
    }

    #[test]
    fn free_name_is_per_site() {
        let c = cfg();
        assert_eq!(free_name(&c, "lab", "jetson"), "jetson-2");
        assert_eq!(free_name(&c, "home", "jetson"), "jetson");
    }

    #[test]
    fn adds_a_valid_configured_device() {
        let mut c = cfg();
        let t = Target::parse("orin.tail1234.ts.net").unwrap();
        let id = add_to_config(&mut c, "home", "orin", &t, "nvidia").unwrap();
        assert_eq!(id, "home/orin");
        let d = &c.sites[1].devices[0];
        assert_eq!(d.hostnames, ["orin.tail1234.ts.net"]);
        assert_eq!(d.usernames, ["nvidia"]);
        assert!(
            d.ssh && d.host_key_fingerprints.is_empty(),
            "never pre-trusted"
        );
        let back = Config::parse(&c.to_yaml(), "test").unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn duplicates_in_the_same_site_are_refused() {
        let mut c = cfg();
        let ip = Target::parse("192.168.50.10").unwrap();
        let e = add_to_config(&mut c, "lab", "other", &ip, "").unwrap_err();
        assert!(e.contains("already lab/jetson"), "{e}");
        let host = Target::parse("JETSON.local").unwrap();
        assert!(add_to_config(&mut c, "lab", "other", &host, "").is_err());
        let fresh = Target::parse("10.0.0.9").unwrap();
        assert!(add_to_config(&mut c, "lab", "jetson", &fresh, "").is_err());
        assert_eq!(c, cfg());
        // The same name and address in another site is a different device.
        add_to_config(&mut c, "home", "jetson", &ip, "").unwrap();
    }

    #[test]
    fn localhost_resolves_and_garbage_does_not() {
        assert!(resolve("localhost").is_ok());
        assert!(resolve("no-such-host.invalid").is_err());
    }
}
