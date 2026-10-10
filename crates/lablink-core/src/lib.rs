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
/// something LabLink did not write (a path, ssh output): it can never move
/// the cursor, rewrite a line or start a line that looks like LabLink's own.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// LabLink release version (all binaries share it).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Git commit of the build, when the packaging script provided it.
pub const GIT_SHA: Option<&str> = option_env!("LABLINK_GIT_SHA");
