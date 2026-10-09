//! Device capabilities and optional device profiles.
//!
//! A capability says what LabLink may do with a device (`ssh`: log in and run
//! read-only checks; `gateway`: other devices are reached through it). A
//! profile is a named bundle of capabilities plus the read-only `lablink
//! doctor` checks that fit that kind of machine. Profiles never change the
//! identity or security model: a Jetson is pinned and verified exactly like
//! any other host.

use crate::checks::{CheckSpec, DiskCheck, NvidiaGpuCheck, Ros2Check, ThermalCheck};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a device supports. Serialized in `snake_case`; add variants only at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reachable on the network (every device).
    Network,
    /// Runs an SSH server LabLink may log in to.
    Ssh,
    /// Has an NVIDIA GPU (discrete or Jetson).
    Gpu,
    /// Runs ROS 2.
    Ros2,
    /// Is an NVIDIA Jetson module.
    Jetson,
    /// Other devices are reached through it (`via:`).
    Gateway,
}

impl Capability {
    pub const ALL: [Capability; 6] = [
        Capability::Network,
        Capability::Ssh,
        Capability::Gpu,
        Capability::Ros2,
        Capability::Jetson,
        Capability::Gateway,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Network => "network",
            Capability::Ssh => "ssh",
            Capability::Gpu => "gpu",
            Capability::Ros2 => "ros2",
            Capability::Jetson => "jetson",
            Capability::Gateway => "gateway",
        }
    }
}

/// An optional device profile. Serialized in `snake_case`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Any Linux machine with SSH.
    GenericLinux,
    /// NVIDIA Jetson (Orin, Xavier, Nano) with SSH.
    Jetson,
    /// Workstation or server with a discrete NVIDIA GPU.
    GpuWorkstation,
    /// Linux host running ROS 2.
    Ros2Host,
    /// A device LabLink only watches on the network (robots, PLCs, switches).
    NetworkOnly,
}

impl Profile {
    pub const ALL: [Profile; 5] = [
        Profile::GenericLinux,
        Profile::Jetson,
        Profile::GpuWorkstation,
        Profile::Ros2Host,
        Profile::NetworkOnly,
    ];

    /// Config / JSON name.
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::GenericLinux => "generic_linux",
            Profile::Jetson => "jetson",
            Profile::GpuWorkstation => "gpu_workstation",
            Profile::Ros2Host => "ros2_host",
            Profile::NetworkOnly => "network_only",
        }
    }

    /// Human name for menus.
    pub fn title(self) -> &'static str {
        match self {
            Profile::GenericLinux => "Generic Linux Host",
            Profile::Jetson => "NVIDIA Jetson",
            Profile::GpuWorkstation => "GPU Workstation",
            Profile::Ros2Host => "ROS 2 Host",
            Profile::NetworkOnly => "Network-only / Robot",
        }
    }

    /// One line on what the profile checks.
    pub fn summary(self) -> &'static str {
        match self {
            Profile::GenericLinux => "SSH, disk usage, temperature",
            Profile::Jetson => "SSH, disk usage, Jetson GPU, temperature",
            Profile::GpuWorkstation => "SSH, disk usage, NVIDIA GPU, temperature",
            Profile::Ros2Host => "SSH, disk usage, ROS 2 installation",
            Profile::NetworkOnly => "network reachability only; no SSH login",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// Whether devices with this profile run an SSH server.
    pub fn uses_ssh(self) -> bool {
        self != Profile::NetworkOnly
    }

    /// Capabilities implied by the profile.
    pub fn implied(self) -> &'static [Capability] {
        match self {
            Profile::GenericLinux => &[Capability::Ssh],
            Profile::Jetson => &[Capability::Ssh, Capability::Gpu, Capability::Jetson],
            Profile::GpuWorkstation => &[Capability::Ssh, Capability::Gpu],
            Profile::Ros2Host => &[Capability::Ssh, Capability::Ros2],
            Profile::NetworkOnly => &[],
        }
    }

    /// Read-only doctor checks used when the config has no `checks:` entry for
    /// the device. All of them come from the fixed check catalog.
    pub fn default_checks(self) -> Vec<CheckSpec> {
        match self {
            Profile::GenericLinux => vec![
                CheckSpec::Disk(DiskCheck::default()),
                CheckSpec::Thermal(ThermalCheck::default()),
            ],
            Profile::Jetson => vec![
                CheckSpec::Disk(DiskCheck::default()),
                CheckSpec::JetsonGpu,
                CheckSpec::Thermal(ThermalCheck::default()),
            ],
            Profile::GpuWorkstation => vec![
                CheckSpec::Disk(DiskCheck::default()),
                CheckSpec::NvidiaGpu(NvidiaGpuCheck::default()),
                CheckSpec::Thermal(ThermalCheck::default()),
            ],
            Profile::Ros2Host => vec![
                CheckSpec::Disk(DiskCheck::default()),
                CheckSpec::Ros2(Ros2Check::default()),
            ],
            Profile::NetworkOnly => vec![],
        }
    }
}

/// The capability set of a device: `network` always, `ssh` when it has SSH,
/// `gateway` when other devices are reached through it, plus whatever the
/// profile implies and the config declares.
pub fn capabilities(
    ssh: bool,
    profile: Option<Profile>,
    declared: &[Capability],
    is_gateway: bool,
) -> Vec<Capability> {
    let mut set = BTreeSet::from([Capability::Network]);
    if ssh {
        set.insert(Capability::Ssh);
    }
    if is_gateway {
        set.insert(Capability::Gateway);
    }
    if let Some(p) = profile {
        set.extend(
            p.implied()
                .iter()
                .copied()
                .filter(|c| ssh || *c != Capability::Ssh),
        );
    }
    set.extend(
        declared
            .iter()
            .copied()
            .filter(|c| ssh || *c != Capability::Ssh),
    );
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::parse(p.as_str()), Some(p));
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.as_str()));
        }
        assert_eq!(Profile::parse("jetsonn"), None);
        for c in Capability::ALL {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
        }
    }

    #[test]
    fn capability_sets() {
        use Capability::*;
        assert_eq!(capabilities(false, None, &[], false), [Network]);
        assert_eq!(capabilities(true, None, &[], true), [Network, Ssh, Gateway]);
        assert_eq!(
            capabilities(true, Some(Profile::Jetson), &[Ros2], false),
            [Network, Ssh, Gpu, Ros2, Jetson]
        );
        // A device without SSH never reports the ssh capability, whatever it declares.
        assert_eq!(
            capabilities(false, Some(Profile::GenericLinux), &[Ssh, Ros2], false),
            [Network, Ros2]
        );
    }

    #[test]
    fn profile_checks_come_from_the_catalog_and_validate() {
        for p in Profile::ALL {
            for c in p.default_checks() {
                c.validate().unwrap();
            }
        }
        assert!(Profile::NetworkOnly.default_checks().is_empty());
        assert!(!Profile::NetworkOnly.uses_ssh());
        assert_eq!(
            Profile::Jetson
                .default_checks()
                .iter()
                .map(|c| c.kind())
                .collect::<Vec<_>>(),
            ["disk", "jetson_gpu", "thermal"]
        );
    }
}
