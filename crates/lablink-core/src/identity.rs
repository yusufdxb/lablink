//! Device identity matching.
//!
//! A device is never identified by IP address alone. Each observation of a
//! host (from the neighbor table, mDNS, a scan, a host-key scan or an SSH
//! login) is classified against the known devices using signals of
//! decreasing strength:
//!
//! 1. SSH host-key fingerprint (cryptographic; strongest)
//! 2. MAC address
//! 3. hostname / mDNS name / alias
//! 4. configured static IP (`expected_ips`)
//! 5. historical IP (weakest; never sufficient on its own to trust a host)
//!
//! A strong non-key signal that agrees while the host key disagrees is a
//! **mismatch** (possible reinstall or impersonation) and is never resolved
//! automatically. A host key that differs at an address the device merely
//! *used to have* (DHCP) is treated as the address being reused by another
//! host, not as an attack on the device.

use crate::config::normalize_hostname;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// An SSH host key observed on the wire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct HostKey {
    /// e.g. `ssh-ed25519`
    pub key_type: String,
    /// `SHA256:...`
    pub fingerprint: String,
    /// Base64 public-key blob (needed to write known_hosts entries).
    #[serde(default)]
    pub public_key: Option<String>,
}

/// The matching-relevant view of one known device.
#[derive(Debug, Clone, Default)]
pub struct KnownIdentity {
    pub name: String,
    /// Pinned fingerprints (config, user known_hosts, explicit trust).
    pub pinned: BTreeSet<String>,
    /// Normalized MACs (configured + learned).
    pub macs: BTreeSet<String>,
    /// Normalized hostnames (configured + learned + mDNS).
    pub names: BTreeSet<String>,
    pub static_ips: Vec<IpAddr>,
    pub current_ip: Option<IpAddr>,
    pub previous_ips: Vec<IpAddr>,
}

/// What was seen about one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    pub ip: Option<IpAddr>,
    pub mac: Option<String>,
    /// Hostnames from mDNS, SSH (`hostname`), or resolution. Normalized on use.
    pub names: Vec<String>,
    pub host_keys: Vec<HostKey>,
}

/// The signal that decided a match.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Fingerprint,
    Mac,
    Hostname,
    StaticIp,
    HistoricalIp,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Signal::Fingerprint => "fingerprint",
            Signal::Mac => "mac",
            Signal::Hostname => "hostname",
            Signal::StaticIp => "static_ip",
            Signal::HistoricalIp => "historical_ip",
        }
    }
}

/// Classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOutcome {
    /// The observation belongs to `device`. `verified` is true only when a
    /// pinned host key matched.
    Matched {
        device: String,
        signal: Signal,
        verified: bool,
    },
    /// `signal` says this is `device`, but the host key contradicts its pin.
    Mismatch { device: String, signal: Signal },
    /// Only an old address of `previous_owner` matched and the host key proves
    /// it is a different machine: the address was reassigned.
    IpReused { previous_owner: String },
    /// Only an old/current address matched and there is no key evidence
    /// either way. Usable as a probe target, not as proof of identity.
    Provisional { device: String },
    /// Signals point at more than one device.
    Ambiguous {
        candidates: Vec<String>,
        reason: String,
    },
    /// No signal matched any device.
    Unknown,
}

impl KnownIdentity {
    fn key_hit(&self, obs: &Observation) -> bool {
        obs.host_keys
            .iter()
            .any(|k| self.pinned.contains(&k.fingerprint))
    }
    /// The observation carries host keys, the device has pins, and none match.
    fn key_conflict(&self, obs: &Observation) -> bool {
        !obs.host_keys.is_empty() && !self.pinned.is_empty() && !self.key_hit(obs)
    }
    fn mac_hit(&self, obs: &Observation) -> bool {
        obs.mac
            .as_ref()
            .is_some_and(|m| self.macs.contains(&m.to_ascii_lowercase()))
    }
    fn name_hit(&self, obs: &Observation) -> bool {
        obs.names
            .iter()
            .any(|n| self.names.contains(&normalize_hostname(n)))
    }
    fn static_ip_hit(&self, obs: &Observation) -> bool {
        obs.ip.is_some_and(|ip| self.static_ips.contains(&ip))
    }
    fn strong_signal(&self, obs: &Observation) -> Option<Signal> {
        if self.mac_hit(obs) {
            Some(Signal::Mac)
        } else if self.name_hit(obs) {
            Some(Signal::Hostname)
        } else if self.static_ip_hit(obs) {
            Some(Signal::StaticIp)
        } else {
            None
        }
    }
}

/// Classify one observation against all known devices.
pub fn classify(obs: &Observation, devices: &[KnownIdentity]) -> MatchOutcome {
    // 1. Host key.
    let key_hits: Vec<&KnownIdentity> = devices.iter().filter(|d| d.key_hit(obs)).collect();
    match key_hits.len() {
        0 => {}
        1 => {
            return MatchOutcome::Matched {
                device: key_hits[0].name.clone(),
                signal: Signal::Fingerprint,
                verified: true,
            }
        }
        _ => {
            // Cloned images can share host keys: disambiguate with other signals.
            let narrowed: Vec<&&KnownIdentity> = key_hits
                .iter()
                .filter(|d| d.strong_signal(obs).is_some())
                .collect();
            if narrowed.len() == 1 {
                return MatchOutcome::Matched {
                    device: narrowed[0].name.clone(),
                    signal: Signal::Fingerprint,
                    verified: true,
                };
            }
            return MatchOutcome::Ambiguous {
                candidates: key_hits.iter().map(|d| d.name.clone()).collect(),
                reason: "host key is pinned on several devices (cloned image?) and no MAC/hostname/static IP tells them apart".into(),
            };
        }
    }

    // 2-4. MAC, hostname, static IP.
    let strong: Vec<(&KnownIdentity, Signal)> = devices
        .iter()
        .filter_map(|d| d.strong_signal(obs).map(|s| (d, s)))
        .collect();
    match strong.len() {
        0 => {}
        1 => {
            let (d, signal) = strong[0];
            return if d.key_conflict(obs) {
                MatchOutcome::Mismatch {
                    device: d.name.clone(),
                    signal,
                }
            } else {
                MatchOutcome::Matched {
                    device: d.name.clone(),
                    signal,
                    verified: false,
                }
            };
        }
        _ => {
            let reason = strong
                .iter()
                .map(|(d, s)| format!("{} matches {}", s.as_str(), d.name))
                .collect::<Vec<_>>()
                .join(", ");
            return MatchOutcome::Ambiguous {
                candidates: strong.iter().map(|(d, _)| d.name.clone()).collect(),
                reason,
            };
        }
    }

    // 5. Historical / current address.
    if let Some(ip) = obs.ip {
        let mut hist: Vec<&KnownIdentity> = devices
            .iter()
            .filter(|d| d.current_ip == Some(ip))
            .collect();
        if hist.is_empty() {
            hist = devices
                .iter()
                .filter(|d| d.previous_ips.contains(&ip))
                .collect();
        }
        if hist.len() == 1 {
            let d = hist[0];
            return if d.key_conflict(obs) {
                MatchOutcome::IpReused {
                    previous_owner: d.name.clone(),
                }
            } else {
                MatchOutcome::Provisional {
                    device: d.name.clone(),
                }
            };
        }
        if hist.len() > 1 {
            // Several devices used this address over time and nothing else
            // matched: it is just a recycled lease.
            return MatchOutcome::Ambiguous {
                candidates: hist.iter().map(|d| d.name.clone()).collect(),
                reason: format!("{ip} was previously used by several devices"),
            };
        }
    }
    MatchOutcome::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_JETSON_A: &str = "SHA256:jetsonAjetsonAjetsonAjetsonAjetsonAjetsonA0";
    const FP_JETSON_B: &str = "SHA256:jetsonBjetsonBjetsonBjetsonBjetsonBjetsonB0";
    const FP_EVIL: &str = "SHA256:evilevilevilevilevilevilevilevilevilevilevi";

    fn key(fp: &str) -> HostKey {
        HostKey {
            key_type: "ssh-ed25519".into(),
            fingerprint: fp.into(),
            public_key: None,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn devices() -> Vec<KnownIdentity> {
        vec![
            KnownIdentity {
                name: "jetson-a".into(),
                pinned: [FP_JETSON_A.to_string()].into(),
                macs: ["aa:bb:cc:00:00:01".to_string()].into(),
                names: ["jetson-a-host".to_string()].into(),
                static_ips: vec![ip("192.168.50.18")],
                current_ip: Some(ip("192.168.10.70")),
                previous_ips: vec![ip("192.168.10.2"), ip("192.168.10.4")],
            },
            KnownIdentity {
                name: "jetson-b".into(),
                pinned: [FP_JETSON_B.to_string()].into(),
                macs: ["aa:bb:cc:00:00:02".to_string()].into(),
                names: ["jetson-b-host".to_string()].into(),
                current_ip: None,
                previous_ips: vec![ip("192.168.10.45")],
                ..Default::default()
            },
            KnownIdentity {
                name: "robot-a".into(),
                static_ips: vec![ip("192.168.50.161")],
                ..Default::default()
            },
        ]
    }

    fn obs(ipaddr: Option<&str>, mac: Option<&str>, names: &[&str], keys: &[&str]) -> Observation {
        Observation {
            ip: ipaddr.map(ip),
            mac: mac.map(str::to_string),
            names: names.iter().map(|s| s.to_string()).collect(),
            host_keys: keys.iter().map(|k| key(k)).collect(),
        }
    }

    #[test]
    fn changed_ip_matched_by_fingerprint() {
        // DHCP moved jetson-a to a never-seen address; the host key proves it.
        let o = obs(Some("192.168.10.71"), None, &[], &[FP_JETSON_A]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Matched {
                device: "jetson-a".into(),
                signal: Signal::Fingerprint,
                verified: true
            }
        );
    }

    #[test]
    fn changed_ip_matched_by_mac_unverified() {
        let o = obs(Some("192.168.10.71"), Some("AA:BB:CC:00:00:01"), &[], &[]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Matched {
                device: "jetson-a".into(),
                signal: Signal::Mac,
                verified: false
            }
        );
    }

    #[test]
    fn changed_ip_matched_by_mdns_hostname() {
        let o = obs(Some("192.168.10.71"), None, &["Jetson-A-Host.local."], &[]);
        assert!(matches!(
            classify(&o, &devices()),
            MatchOutcome::Matched {
                signal: Signal::Hostname,
                ..
            }
        ));
    }

    #[test]
    fn changed_mac_still_matched_by_fingerprint() {
        // New NIC (or the wifi interface instead of ethernet): key wins.
        let o = obs(
            Some("192.168.10.70"),
            Some("de:ad:be:ef:00:99"),
            &[],
            &[FP_JETSON_A],
        );
        assert!(matches!(
            classify(&o, &devices()),
            MatchOutcome::Matched { verified: true, .. }
        ));
    }

    #[test]
    fn usb_nic_moved_between_robots_key_beats_mac() {
        // jetson-b's old MAC now shows up with jetson-a's host key.
        let o = obs(
            Some("192.168.10.80"),
            Some("aa:bb:cc:00:00:02"),
            &[],
            &[FP_JETSON_A],
        );
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Matched {
                device: "jetson-a".into(),
                signal: Signal::Fingerprint,
                verified: true
            }
        );
    }

    #[test]
    fn fingerprint_mismatch_with_matching_mac_is_security_error() {
        let o = obs(
            Some("192.168.10.70"),
            Some("aa:bb:cc:00:00:01"),
            &[],
            &[FP_EVIL],
        );
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Mismatch {
                device: "jetson-a".into(),
                signal: Signal::Mac
            }
        );
    }

    #[test]
    fn fingerprint_mismatch_at_static_ip_is_security_error() {
        let o = obs(Some("192.168.50.18"), None, &[], &[FP_EVIL]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Mismatch {
                device: "jetson-a".into(),
                signal: Signal::StaticIp
            }
        );
    }

    #[test]
    fn unknown_key_at_old_dhcp_address_is_reuse_not_attack() {
        let o = obs(Some("192.168.10.45"), None, &[], &[FP_EVIL]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::IpReused {
                previous_owner: "jetson-b".into()
            }
        );
        let o = obs(Some("192.168.10.70"), None, &[], &[FP_EVIL]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::IpReused {
                previous_owner: "jetson-a".into()
            }
        );
    }

    #[test]
    fn ip_only_is_provisional() {
        let o = obs(Some("192.168.10.70"), None, &[], &[]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Provisional {
                device: "jetson-a".into()
            }
        );
    }

    #[test]
    fn other_device_key_at_old_ip_matches_the_other_device() {
        // DHCP gave jetson-b's old address to jetson-a.
        let o = obs(Some("192.168.10.45"), None, &[], &[FP_JETSON_A]);
        assert!(
            matches!(classify(&o, &devices()), MatchOutcome::Matched { ref device, .. } if device == "jetson-a")
        );
    }

    #[test]
    fn conflicting_strong_signals_are_ambiguous() {
        let o = obs(
            Some("192.168.10.99"),
            Some("aa:bb:cc:00:00:01"),
            &["jetson-b-host"],
            &[],
        );
        assert!(matches!(
            classify(&o, &devices()),
            MatchOutcome::Ambiguous { .. }
        ));
    }

    #[test]
    fn shared_host_key_disambiguated_or_ambiguous() {
        let mut d = devices();
        d[1].pinned.insert(FP_JETSON_A.to_string()); // cloned image
        let o = obs(Some("192.168.10.99"), None, &[], &[FP_JETSON_A]);
        assert!(matches!(classify(&o, &d), MatchOutcome::Ambiguous { .. }));
        let o = obs(
            Some("192.168.10.99"),
            Some("aa:bb:cc:00:00:02"),
            &[],
            &[FP_JETSON_A],
        );
        assert!(
            matches!(classify(&o, &d), MatchOutcome::Matched { ref device, .. } if device == "jetson-b")
        );
    }

    #[test]
    fn device_without_pins_is_matched_unverified() {
        let o = obs(Some("192.168.50.161"), None, &[], &[FP_EVIL]);
        assert_eq!(
            classify(&o, &devices()),
            MatchOutcome::Matched {
                device: "robot-a".into(),
                signal: Signal::StaticIp,
                verified: false
            }
        );
    }

    #[test]
    fn nothing_matches() {
        let o = obs(
            Some("192.168.10.200"),
            Some("11:22:33:44:55:66"),
            &["printer"],
            &[FP_EVIL],
        );
        assert_eq!(classify(&o, &devices()), MatchOutcome::Unknown);
    }
}
