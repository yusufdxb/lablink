//! What LabLink remembers about the Field Network between commands:
//! `fieldnet.json` in the state directory, mode 0600. It never holds the
//! password: that lives only in NetworkManager's root-only secret store,
//! inside the profile this file names by UUID.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// WPA2-Personal: RSN, CCMP only (no TKIP, never WEP or open).
    #[default]
    Wpa2,
    /// WPA3-Personal (SAE), PMF required. Opt-in: support is not verifiable
    /// on every host and older clients cannot join.
    Wpa3,
}

impl Security {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "wpa2" | "wpa2-personal" => Ok(Security::Wpa2),
            "wpa3" | "wpa3-personal" | "sae" => Ok(Security::Wpa3),
            "wep" | "open" | "none" | "wpa" | "tkip" => Err(format!(
                "'{s}' is insecure and not supported; use wpa2 (default) or wpa3"
            )),
            _ => Err(format!("unknown security '{s}': use wpa2 or wpa3")),
        }
    }

    pub fn key_mgmt(self) -> &'static str {
        match self {
            Security::Wpa2 => "wpa-psk",
            Security::Wpa3 => "sae",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Security::Wpa2 => "WPA2-Personal (CCMP)",
            Security::Wpa3 => "WPA3-Personal (SAE)",
        }
    }
}

/// The connection the Wi-Fi adapter had before the hotspot took it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Previous {
    pub uuid: String,
    pub name: String,
    pub device: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldState {
    pub version: u32,
    /// The NetworkManager profile LabLink created and owns.
    pub profile_uuid: Option<String>,
    pub interface: String,
    pub ssid: String,
    pub subnet: String,
    pub security: Security,
    /// Restored when the hotspot stops.
    pub previous: Option<Previous>,
    /// LabLink started the hotspot and has not stopped it.
    pub active: bool,
    pub started_ms: Option<u64>,
    /// `net.ipv4.ip_forward` before LabLink started the hotspot, so `status`
    /// can say whether NetworkManager's shared mode changed it.
    pub ip_forward_before: Option<bool>,
    /// Internet sharing was asked for: the profile carries no isolation
    /// rules. `false` (also when absent) means isolated.
    #[serde(default)]
    pub sharing: bool,
}

pub const STATE_FILE: &str = "fieldnet.json";

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}

pub fn load(state_dir: &Path) -> Result<Option<FieldState>, String> {
    let p = path(state_dir);
    match std::fs::read_to_string(&p) {
        Ok(t) => serde_json::from_str(&t)
            .map(Some)
            .map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Write atomically, mode 0600, in a 0700 directory no other user can
/// write.
pub fn save(state_dir: &Path, s: &FieldState) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state_dir)
        .map_err(|e| format!("cannot create {}: {e}", state_dir.display()))?;
    if let Some(why) = lablink_core::paths::writable_by_others(state_dir) {
        return Err(format!("refusing state directory: {why}"));
    }
    let p = path(state_dir);
    let tmp = state_dir.join(format!(".{STATE_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn remove(state_dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(path(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> FieldState {
        FieldState {
            version: 1,
            profile_uuid: Some("114930b6-edee-418c-bac6-3400a8517a6c".into()),
            interface: "wlan0".into(),
            ssid: "LabLink-ABCD".into(),
            subnet: "10.77.0.0/24".into(),
            security: Security::Wpa2,
            previous: Some(Previous {
                uuid: "a21bc2fd-4952-487d-91c0-a3248f648037".into(),
                name: "Home WiFi".into(),
                device: "wlan0".into(),
            }),
            active: true,
            started_ms: Some(1),
            ip_forward_before: Some(false),
            sharing: false,
        }
    }

    #[test]
    fn round_trip_private_and_secret_free() {
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().join("state");
        assert_eq!(load(&sd).unwrap(), None);
        save(&sd, &sample()).unwrap();
        assert_eq!(load(&sd).unwrap(), Some(sample()));
        let mode = std::fs::metadata(path(&sd)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let text = std::fs::read_to_string(path(&sd)).unwrap();
        assert!(!text.to_lowercase().contains("psk") && !text.contains("password"));
        remove(&sd).unwrap();
        remove(&sd).unwrap();
        assert_eq!(load(&sd).unwrap(), None);
    }

    #[test]
    fn insecure_modes_are_refused_by_name() {
        for s in ["wep", "open", "none", "WPA", "tkip"] {
            assert!(Security::parse(s).unwrap_err().contains("insecure"), "{s}");
        }
        assert_eq!(Security::parse("WPA3").unwrap(), Security::Wpa3);
        assert_eq!(Security::parse("wpa2").unwrap().key_mgmt(), "wpa-psk");
    }
}
