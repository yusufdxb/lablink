//! Remove a device from LabLink: the one backend behind `lablink remove` and
//! the GUI's Remove device action.
//!
//! Removal only changes this computer. Nothing is sent to the device: its
//! accounts, authorized keys and files are left exactly as they are.
//!
//! - An adopted device lives in the daemon's cache, so the daemon deletes it
//!   (`Request::Forget` removes adopted devices outright).
//! - A configured device lives in `config.yaml`. Its entry (and its doctor
//!   checks) is deleted under the config lock, then the daemon is restarted;
//!   on restart the registry forgets cached state for devices that left the
//!   config, so its pins and addresses go too.
//!
//! This is different from `forget` (reset trust; a configured device stays),
//! from turning monitoring off (the device stays listed) and from dismissing
//! a discovery result (nothing was tracked).

use lablink_core::client::Client;
use lablink_core::config::Config;
use lablink_core::model::DeviceDetail;
use lablink_core::protocol::Request;
use std::path::{Path, PathBuf};

/// What a removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    /// An adopted device, deleted by the daemon.
    Adopted { id: String },
    /// A configured device, deleted from `config.yaml`.
    Configured {
        id: String,
        backup: Option<PathBuf>,
        /// Outcome of restarting the daemon so it stops monitoring the device.
        restart: String,
    },
}

impl Removed {
    pub fn id(&self) -> &str {
        match self {
            Removed::Adopted { id } | Removed::Configured { id, .. } => id,
        }
    }
    /// One plain sentence for people.
    pub fn summary(&self) -> String {
        match self {
            Removed::Adopted { id } => format!(
                "Removed {id}. LabLink no longer monitors it; nothing was changed on the device."
            ),
            Removed::Configured {
                id,
                backup,
                restart,
            } => {
                let mut s = format!(
                    "Removed {id} from the configuration; nothing was changed on the device. {}",
                    capitalize(restart)
                );
                if !s.ends_with('.') {
                    s.push('.');
                }
                if let Some(b) = backup {
                    s.push_str(&format!(" Previous config saved as {}.", b.display()));
                }
                s
            }
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Delete device `name` of site `site` from `cfg`, with its doctor checks.
/// Refuses when another device of the same site reaches the network through
/// it (`via:`), since removing it would leave that device unreachable.
pub fn remove_from_config(cfg: &mut Config, site: &str, name: &str) -> Result<(), String> {
    let s = cfg
        .sites
        .iter_mut()
        .find(|s| s.id == site)
        .ok_or_else(|| format!("site '{site}' is not in the configuration"))?;
    let before = s.devices.len();
    let dependants: Vec<String> = s
        .devices
        .iter()
        .filter(|d| d.via.as_deref() == Some(name))
        .map(|d| d.name.clone())
        .collect();
    if !dependants.is_empty() {
        return Err(format!(
            "{} connect{} through {site}/{name}. Remove {} first, or change how {} connect{}.",
            dependants.join(", "),
            if dependants.len() == 1 { "s" } else { "" },
            if dependants.len() == 1 { "it" } else { "them" },
            if dependants.len() == 1 { "it" } else { "they" },
            if dependants.len() == 1 { "s" } else { "" },
        ));
    }
    s.devices.retain(|d| d.name != name);
    if s.devices.len() == before {
        return Err(format!(
            "{site}/{name} is not in the configuration file. Reload and try again."
        ));
    }
    s.checks.remove(name);
    Ok(())
}

/// Remove `device` (any name the daemon accepts; resolved to `site/name`).
pub fn remove_device(client: &Client, config_path: &Path, device: &str) -> Result<Removed, String> {
    let detail: DeviceDetail = client
        .call_typed(&Request::Inspect {
            device: device.to_string(),
        })
        .map_err(|e| e.to_string())?;
    let id = detail.status.id.clone();
    if !detail.configured {
        let v = client
            .call(&Request::Forget { device: id.clone() })
            .map_err(|e| e.to_string())?;
        if v["removed"].as_bool() != Some(true) {
            // The device became configured between the two requests; the
            // daemon reset it instead of deleting it. Say so instead of
            // claiming a removal.
            return Err(format!(
                "{id} is now defined in the configuration file; its trust was reset but it is still listed. Try Remove again."
            ));
        }
        return Ok(Removed::Adopted { id });
    }
    let (site, name) = id
        .split_once('/')
        .ok_or_else(|| format!("unexpected device id '{id}'"))?;
    let backup = crate::configfile::update(config_path, |cfg| remove_from_config(cfg, site, name))?;
    Ok(Removed::Configured {
        id,
        backup,
        restart: crate::service::restart_if_active(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_SITES: &str = "sites:\n  - id: alpha\n    name: Alpha\n    devices:\n      - name: jetson\n        expected_ips: [192.168.50.10]\n      - name: robot\n        ssh: false\n        via: jetson\n        expected_ips: [10.42.0.2]\n      - name: spare\n    checks:\n      spare: [disk]\n      jetson: [disk]\n  - id: beta\n    name: Beta\n    auto_detect: false\n    devices:\n      - name: jetson\n        expected_ips: [192.168.60.10]\n      - name: spare\n";

    fn cfg() -> Config {
        Config::parse(TWO_SITES, "test").unwrap()
    }

    #[test]
    fn same_name_in_another_site_is_untouched() {
        let mut c = cfg();
        remove_from_config(&mut c, "beta", "jetson").unwrap();
        let names = |s: usize| {
            c.sites[s]
                .devices
                .iter()
                .map(|d| d.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(0), ["jetson", "robot", "spare"]);
        assert_eq!(names(1), ["spare"]);
        c.validate().unwrap();
    }

    #[test]
    fn checks_leave_with_the_device_and_the_result_is_valid() {
        let mut c = cfg();
        remove_from_config(&mut c, "alpha", "spare").unwrap();
        assert!(!c.sites[0].checks.contains_key("spare"));
        assert!(c.sites[0].checks.contains_key("jetson"));
        assert_eq!(c.sites[1].devices.len(), 2, "beta/spare stays");
        c.validate().unwrap();
        // Round-trips through the file format.
        let back = Config::parse(&c.to_yaml(), "test").unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn a_gateway_in_use_is_not_removed() {
        let mut c = cfg();
        let before = c.clone();
        let e = remove_from_config(&mut c, "alpha", "jetson").unwrap_err();
        assert!(e.contains("robot connects through alpha/jetson"), "{e}");
        assert_eq!(c, before);
    }

    #[test]
    fn unknown_entries_are_reported_not_ignored() {
        let mut c = cfg();
        assert!(remove_from_config(&mut c, "alpha", "ghost").is_err());
        assert!(remove_from_config(&mut c, "gamma", "jetson").is_err());
        assert_eq!(c, cfg());
    }

    #[test]
    fn file_removal_keeps_a_backup_and_other_sites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, TWO_SITES).unwrap();
        let backup = crate::configfile::update(&path, |c| remove_from_config(c, "alpha", "spare"))
            .unwrap()
            .expect("backup of the previous file");
        assert_eq!(std::fs::read_to_string(backup).unwrap(), TWO_SITES);
        let now = crate::configfile::load_or_default(&path).unwrap();
        assert_eq!(now.sites[0].devices.len(), 2);
        assert_eq!(now.sites[1].devices.len(), 2);
    }

    #[test]
    fn summaries_say_the_device_was_not_touched() {
        let a = Removed::Adopted {
            id: "alpha/x".into(),
        };
        assert!(a.summary().contains("nothing was changed on the device"));
        let c = Removed::Configured {
            id: "alpha/y".into(),
            backup: None,
            restart: "restarted lablinkd to apply the new configuration".into(),
        };
        assert_eq!(c.id(), "alpha/y");
        assert!(c
            .summary()
            .ends_with("Restarted lablinkd to apply the new configuration."));
    }
}
