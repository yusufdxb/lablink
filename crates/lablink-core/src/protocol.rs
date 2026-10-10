//! Local IPC protocol between `lablinkd` and its clients.
//!
//! Transport: a Unix domain socket (mode 0600 inside a 0700 directory, peer
//! UID checked by the daemon). Framing: one JSON object per line. A client
//! writes one request line and reads one response line; connections may be
//! reused for further requests.

use crate::exit;
use serde::{Deserialize, Serialize};

/// Bumped on incompatible protocol changes.
pub const PROTOCOL_VERSION: u32 = 1;
/// Requests larger than this are rejected without parsing.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Responses larger than this are treated as a protocol error by clients.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A request to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check; returns `{protocol_version, version, pid}`.
    Ping,
    /// Compact status of one device, of one site, of every site (`all`), or
    /// by default of the sites the user is at (ACTIVE or not yet confirmed).
    Status {
        #[serde(default)]
        device: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        all: bool,
    },
    /// Full detail for the devices of the current site(s), one site, or all.
    Devices {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        all: bool,
    },
    /// Full detail for one device.
    Inspect { device: String },
    /// Connection history, newest last.
    History {
        #[serde(default)]
        device: Option<String>,
        #[serde(default = "default_history_limit")]
        limit: u32,
    },
    /// Hosts seen on the network that are not tracked devices.
    Discovered,
    /// Run staged discovery now (optionally with a one-time extra CIDR) and
    /// return once it completes.
    Discover {
        #[serde(default)]
        scan_cidr: Option<String>,
    },
    /// Resolve a device to everything needed to launch OpenSSH.
    Resolve { device: String },
    /// Scan the device's host keys. Without `confirm` this is a preview; with
    /// `confirm` set to the exact fingerprints the user approved, they are
    /// pinned if a fresh scan still returns exactly those keys.
    Trust {
        device: String,
        #[serde(default)]
        confirm: Option<Vec<String>>,
        #[serde(default)]
        replace: bool,
    },
    /// Forget everything LabLink learned about a device: pinned keys,
    /// addresses, MACs and runtime settings. An adopted device is removed;
    /// a configured one starts over as if just added. Returns
    /// `{device, removed}`.
    Forget { device: String },
    /// Change runtime overrides for a device.
    Set {
        device: String,
        changes: DeviceChanges,
    },
    /// Start tracking a discovered host under a new logical name. The
    /// optional settings are applied atomically with the adoption; nothing
    /// here pins a host key.
    Adopt {
        ip: String,
        name: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        username: Option<String>,
        /// Profile name (`generic_linux`, `network_only`, ...).
        #[serde(default)]
        profile: Option<String>,
        /// Whether the host runs an SSH server LabLink should log in to
        /// (default true; false for robots and other network-only devices).
        #[serde(default)]
        ssh: Option<bool>,
        /// Site the device belongs to (default: the site of the network the
        /// address is on, else the active site).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
    },
    /// Daemon resource usage and activity counters.
    Metrics,
    /// Every site with its state, evidence and the local detection signals.
    Sites,
    /// Choose the active site by hand (`site`), or return to automatic
    /// detection (`site: null`). Never changes any trust relationship.
    SetSiteMode {
        #[serde(default)]
        site: Option<String>,
    },
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Request {
    /// Parse one request line. Requests whose parameters are all optional
    /// may omit `params` entirely (`{"method":"devices"}`).
    pub fn parse(line: &str) -> Result<Self, serde_json::Error> {
        match serde_json::from_str::<Request>(line) {
            Ok(r) => Ok(r),
            Err(e) => {
                let mut v: serde_json::Value = serde_json::from_str(line).map_err(|_| e)?;
                match v.as_object_mut() {
                    Some(o) if !o.contains_key("params") => {
                        o.insert("params".into(), serde_json::json!({}));
                        serde_json::from_value(v)
                    }
                    _ => serde_json::from_str::<Request>(line),
                }
            }
        }
    }
}

fn default_history_limit() -> u32 {
    50
}

/// Runtime overrides (persisted in the cache, not the config file).
/// `Some("")` clears a string override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceChanges {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub monitoring: Option<bool>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Profile name; `Some("")` clears it.
    #[serde(default)]
    pub profile: Option<String>,
    /// SSH on/off. Only for devices adopted at runtime; configured devices
    /// take `ssh:` from the config file.
    #[serde(default)]
    pub ssh: Option<bool>,
    /// Re-run the SSH login check now (after installing a key).
    #[serde(default)]
    pub recheck: bool,
}

/// Machine-readable error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    DeviceNotFound,
    Unreachable,
    IdentityMismatch,
    Refused,
    Conflict,
    Busy,
    Internal,
    /// A bare device name matches devices at several sites.
    Ambiguous,
}

impl ErrorCode {
    /// The CLI exit code for this error.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorCode::BadRequest => exit::USAGE,
            ErrorCode::DeviceNotFound => exit::DEVICE_NOT_FOUND,
            ErrorCode::Unreachable => exit::DEVICE_UNREACHABLE,
            ErrorCode::IdentityMismatch => exit::IDENTITY_MISMATCH,
            ErrorCode::Refused => exit::REFUSED,
            ErrorCode::Ambiguous => exit::AMBIGUOUS,
            ErrorCode::Conflict | ErrorCode::Busy | ErrorCode::Internal => exit::FAILURE,
        }
    }
}

/// An error returned by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    /// For `ambiguous`: the devices the name could mean.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Candidate>,
}

/// One device an ambiguous name could refer to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// `site/name`
    pub id: String,
    pub site_name: String,
    pub name: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            candidates: Vec::new(),
        }
    }

    /// The ambiguity message for `lablink <command>`.
    pub fn ambiguity_text(&self, command: &str) -> Option<String> {
        if self.code != ErrorCode::Ambiguous || self.candidates.is_empty() {
            return None;
        }
        let name = &self.candidates[0].name;
        let mut s = format!("Ambiguous device '{name}':\n\n");
        for c in &self.candidates {
            s.push_str(&format!("{} / {}\n", c.site_name, c.name));
        }
        s.push_str("\nUse:\n");
        for c in &self.candidates {
            s.push_str(&format!("  lablink {command} {}\n", c.id));
        }
        Some(s)
    }
}

/// Response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Response {
    pub fn ok(result: serde_json::Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }
    pub fn err(e: ApiError) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&Request::Ping).unwrap(),
            r#"{"method":"ping"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Status {
                device: Some("jetson-a".into()),
                site: None,
                all: false,
            })
            .unwrap(),
            r#"{"method":"status","params":{"device":"jetson-a"}}"#
        );
        let r: Request = serde_json::from_str(r#"{"method":"history","params":{}}"#).unwrap();
        assert_eq!(
            r,
            Request::History {
                device: None,
                limit: 50
            }
        );
        let r: Request = serde_json::from_str(r#"{"method":"status","params":{}}"#).unwrap();
        assert_eq!(
            r,
            Request::Status {
                device: None,
                site: None,
                all: false
            }
        );
        let r = Request::parse(r#"{"method":"devices"}"#).unwrap();
        assert_eq!(
            r,
            Request::Devices {
                site: None,
                all: false
            }
        );
        let r: Request =
            serde_json::from_str(r#"{"method":"set_site_mode","params":{"site":"site-beta"}}"#)
                .unwrap();
        assert_eq!(
            r,
            Request::SetSiteMode {
                site: Some("site-beta".into())
            }
        );
    }

    #[test]
    fn unknown_method_rejected() {
        assert!(serde_json::from_str::<Request>(r#"{"method":"rm_rf"}"#).is_err());
        assert!(Request::parse(r#"{"method":"rm_rf"}"#).is_err());
        assert!(
            Request::parse(r#"{"method":"inspect"}"#).is_err(),
            "required params"
        );
        assert_eq!(
            Request::parse(r#"{"method":"ping"}"#).unwrap(),
            Request::Ping
        );
    }

    #[test]
    fn error_codes_map_to_exit_codes() {
        assert_eq!(
            ErrorCode::DeviceNotFound.exit_code(),
            exit::DEVICE_NOT_FOUND
        );
        assert_eq!(
            ErrorCode::IdentityMismatch.exit_code(),
            exit::IDENTITY_MISMATCH
        );
        assert_eq!(ErrorCode::Refused.exit_code(), exit::REFUSED);
        assert_eq!(ErrorCode::Ambiguous.exit_code(), exit::AMBIGUOUS);
        let e = Response::err(ApiError::new(ErrorCode::Refused, "x"));
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"ok":false,"error":{"code":"refused","message":"x"}}"#
        );
    }

    #[test]
    fn ambiguity_text_lists_every_site() {
        let mut e = ApiError::new(ErrorCode::Ambiguous, "ambiguous device 'jetson'");
        for (id, site) in [
            ("site-alpha/jetson", "Site Alpha"),
            ("site-beta/jetson", "Site Beta"),
        ] {
            e.candidates.push(Candidate {
                id: id.into(),
                site_name: site.into(),
                name: "jetson".into(),
            });
        }
        assert_eq!(
            e.ambiguity_text("ssh").unwrap(),
            "Ambiguous device 'jetson':\n\nSite Alpha / jetson\nSite Beta / jetson\n\nUse:\n  lablink ssh site-alpha/jetson\n  lablink ssh site-beta/jetson\n"
        );
    }
}
