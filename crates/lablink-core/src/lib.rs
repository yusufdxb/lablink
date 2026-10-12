//! LabLink core.
//!
//! Pure, synchronous building blocks shared by the daemon, the CLI and the GUI:
//! configuration parsing and validation, the network allowlist, device health
//! state machines, identity matching, the IPC protocol and a blocking IPC client.
//! Nothing in this crate touches the network except [`client`], which only talks
//! to the local daemon over a Unix domain socket.

pub mod checks;
pub mod client;
pub mod config;
pub mod exit;
pub mod explain;
pub mod health;
pub mod identity;
pub mod model;
pub mod net;
pub mod paths;
pub mod profile;
pub mod program;
pub mod protocol;
pub mod site;
pub mod time;

pub use config::Config;

/// `s` with control characters shown escaped, for text that may hold
/// something LabLink did not write (a path, ssh output, a hotspot client's
/// name): it can never move the cursor, rewrite a line or start a line that
/// looks like LabLink's own. Bidirectional and invisible formatting
/// characters are escaped too, so text cannot be reordered on screen (a
/// right-to-left override making `exe.txt` read as `txt.exe`) or hide in
/// zero-width characters.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_format_char(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Bidirectional controls (U+061C, U+200E/F, U+202A-202E, U+2066-2069) and
/// invisible characters (zero-width space and joiners, word joiner and the
/// invisible operators, byte-order mark).
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// LabLink release version (all binaries share it).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit of the build, when the packaging script provided it.
pub const GIT_SHA: Option<&str> = option_env!("LABLINK_GIT_SHA");

/// How a running daemon's build compares with this client: `"same"`,
/// `"different"` (version, protocol or both known commits differ, or the
/// daemon did not report a version) or `"unknown"` (same version but a commit
/// is missing, so the builds cannot be compared).
pub fn daemon_build_status(ping: &serde_json::Value) -> &'static str {
    if ping["version"].as_str() != Some(VERSION)
        || ping["protocol_version"].as_u64() != Some(protocol::PROTOCOL_VERSION as u64)
    {
        "different"
    } else {
        match (GIT_SHA, ping["git_sha"].as_str()) {
            (Some(a), Some(b)) if a == b => "same",
            (Some(_), Some(_)) => "different",
            _ => "unknown",
        }
    }
}

/// Why a command that resolves, pins or trusts host keys, or starts SSH
/// through the daemon, must not run against this daemon; `None` when the
/// build matches or cannot be compared. An old daemon can lack security
/// fixes that the client assumes. Nothing is restarted: open SSH sessions
/// are independent of the daemon.
pub fn daemon_build_refusal(ping: &serde_json::Value) -> Option<String> {
    (daemon_build_status(ping) == "different").then(|| {
        format!(
            "the running lablinkd is {} but this lablink is {}; the old daemon lacks security fixes in this build, so this command is refused. Run `systemctl --user restart lablinkd` (open SSH sessions are not affected), then check `lablink version`.",
            printable(ping["version"].as_str().unwrap_or("an unknown version")),
            VERSION
        )
    })
}

#[cfg(test)]
mod daemon_build_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn older_or_unversioned_daemons_are_refused_current_ones_are_not() {
        let old = json!({"version":"0.3.0","protocol_version":protocol::PROTOCOL_VERSION});
        assert_eq!(daemon_build_status(&old), "different");
        assert!(daemon_build_refusal(&old).unwrap().contains("0.3.0"));
        assert!(daemon_build_refusal(&json!({}))
            .unwrap()
            .contains("unknown version"));
        let wrong_protocol =
            json!({"version":VERSION,"protocol_version":protocol::PROTOCOL_VERSION+1});
        assert!(daemon_build_refusal(&wrong_protocol).is_some());
        let same = json!({"version":VERSION,"protocol_version":protocol::PROTOCOL_VERSION,"git_sha":GIT_SHA});
        assert!(daemon_build_refusal(&same).is_none());
        if GIT_SHA.is_some() {
            let other = json!({"version":VERSION,"protocol_version":protocol::PROTOCOL_VERSION,"git_sha":"zzz"});
            assert!(daemon_build_refusal(&other).is_some());
        }
    }
}

#[cfg(test)]
mod printable_tests {
    use super::printable;

    #[test]
    fn bidi_and_invisible_characters_are_escaped() {
        // A right-to-left override would show "jetson-\u{202e}txt.exe" as
        // "jetson-exe.txt".
        assert_eq!(printable("a\u{202e}txt.exe"), "a\\u{202e}txt.exe");
        for c in [
            '\u{061c}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202d}', '\u{2066}',
            '\u{2069}', '\u{2060}', '\u{feff}',
        ] {
            let p = printable(&format!("x{c}y"));
            assert!(!p.contains(c) && p.starts_with("x\\u{"), "{c:?} -> {p}");
        }
        assert_eq!(printable("x\x1b[2Ky\n"), "x\\u{1b}[2Ky\\n");
        // Ordinary non-ASCII text is kept.
        assert_eq!(printable("café ロボット ü"), "café ロボット ü");
    }
}
