//! A read-only adapter for the locally installed Tailscale client.
//!
//! LabLink only ever runs `tailscale status --json`. It never logs in, never
//! changes preferences, never enables Tailscale SSH, routes or exit nodes.
//!
//! The JSON is untrusted input in two ways: its schema changes between
//! releases, and peer names are chosen by other members of the tailnet. Only
//! the few fields LabLink needs are extracted, each one validated; the raw
//! output (which can contain a login URL and account e-mail addresses) is
//! dropped immediately and never logged, stored or echoed in errors.

use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Largest `status --json` output accepted (a tailnet of several thousand
/// nodes stays well below this).
pub const MAX_STATUS_BYTES: usize = 8 * 1024 * 1024;

/// The operating system, as far as finding the Tailscale CLI is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Other,
}

impl Os {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }
}

/// The CLI bundled inside the macOS app (App Store and standalone variants).
pub const MACOS_APP_CLI: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";

/// Where the Tailscale CLI is looked for, in order: every `PATH` entry, then
/// the usual install locations (a GUI-launched process may have a short PATH).
pub fn cli_candidates(os: Os, path_env: Option<&OsStr>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = path_env
        .map(|p| {
            std::env::split_paths(p)
                .filter(|d| d.is_absolute())
                .map(|d| d.join("tailscale"))
                .collect()
        })
        .unwrap_or_default();
    let fixed: &[&str] = match os {
        Os::MacOs => &[
            "/usr/local/bin/tailscale",
            "/opt/homebrew/bin/tailscale",
            MACOS_APP_CLI,
        ],
        Os::Linux | Os::Other => &["/usr/bin/tailscale", "/usr/local/bin/tailscale"],
    };
    for f in fixed {
        let p = PathBuf::from(f);
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The first usable Tailscale CLI, if any.
pub fn find_cli(os: Os, path_env: Option<&OsStr>) -> Option<PathBuf> {
    cli_candidates(os, path_env)
        .into_iter()
        .find(|p| is_executable_file(p))
}

/// What to tell the user when no CLI was found.
pub fn missing_cli_hint(os: Os) -> &'static str {
    match os {
        Os::MacOs => "Tailscale CLI not found. With the Mac app installed, LabLink also looks for it inside /Applications/Tailscale.app; otherwise enable it in the Tailscale app (Settings, CLI integration)",
        _ => "Tailscale CLI not found (install Tailscale, see docs/REMOTE_ACCESS.md)",
    }
}

/// One node of the tailnet, as LabLink sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Stable node ID (`ID`).
    pub id: String,
    /// MagicDNS name, lower case, without the trailing dot ("" if unusable).
    pub dns_name: String,
    pub ips: Vec<IpAddr>,
    /// Tailscale's opinion only: never evidence of identity or reachability.
    pub online: bool,
    pub expired: bool,
}

/// The parts of `tailscale status --json` LabLink uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The tailnet's MagicDNS suffix, normalized; None when unknown.
    pub tailnet: Option<String>,
    pub self_node: Option<Peer>,
    pub peers: Vec<Peer>,
}

impl Snapshot {
    /// This node and its peers.
    pub fn nodes(&self) -> impl Iterator<Item = &Peer> {
        self.self_node.iter().chain(self.peers.iter())
    }
}

/// The local Tailscale client's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsState {
    /// No CLI found.
    Missing,
    /// The CLI ran but gave no usable answer. The reason is LabLink's own
    /// fixed text, never the tool's output.
    Failed(&'static str),
    /// Installed but not connected. `state` is one of the documented
    /// BackendState values, or "unknown".
    NotRunning {
        state: &'static str,
    },
    Running(Snapshot),
}

const BACKEND_STATES: &[&str] = &[
    "NoState",
    "NeedsLogin",
    "NeedsMachineAuth",
    "Stopped",
    "Starting",
    "Running",
];

fn norm_dns(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_peer(v: &serde_json::Value) -> Option<Peer> {
    let id = v.get("ID")?.as_str()?;
    if !lablink_core::config::valid_node_id(id) {
        return None;
    }
    let dns = v.get("DNSName").and_then(|x| x.as_str()).unwrap_or("");
    let dns_name = if lablink_core::config::valid_hostname(dns) {
        norm_dns(dns)
    } else {
        String::new()
    };
    let ips = v
        .get("TailscaleIPs")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str()?.parse::<IpAddr>().ok())
                .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
                .collect()
        })
        .unwrap_or_default();
    let flag = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    Some(Peer {
        id: id.to_string(),
        dns_name,
        ips,
        online: flag("Online"),
        expired: flag("Expired"),
    })
}

/// Parse `tailscale status --json`. Unknown fields are ignored; malformed
/// peers are skipped; a missing or non-object document is an error.
pub fn parse_status(json: &[u8]) -> TsState {
    if json.len() > MAX_STATUS_BYTES {
        return TsState::Failed("tailscale status output is too large");
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else {
        return TsState::Failed("tailscale status output is not valid JSON");
    };
    if !v.is_object() {
        return TsState::Failed("tailscale status output has an unexpected format");
    }
    let Some(state) = v.get("BackendState").and_then(|x| x.as_str()) else {
        return TsState::Failed("tailscale status output has no BackendState");
    };
    let state = BACKEND_STATES
        .iter()
        .copied()
        .find(|s| *s == state)
        .unwrap_or("unknown");
    if state != "Running" {
        return TsState::NotRunning { state };
    }
    let suffix = v
        .get("CurrentTailnet")
        .and_then(|t| t.get("MagicDNSSuffix"))
        .and_then(|x| x.as_str())
        .or_else(|| v.get("MagicDNSSuffix").and_then(|x| x.as_str()))
        .filter(|s| lablink_core::config::valid_tailnet(s))
        .map(norm_dns);
    let peers = v
        .get("Peer")
        .and_then(|p| p.as_object())
        .map(|m| m.values().filter_map(parse_peer).collect())
        .unwrap_or_default();
    TsState::Running(Snapshot {
        tailnet: suffix,
        self_node: v.get("Self").and_then(parse_peer),
        peers,
    })
}

/// Run `<cli> status --json` with a timeout and parse it.
pub fn query(cli: &Path, timeout: Duration) -> TsState {
    let mut cmd = std::process::Command::new(cli);
    cmd.args(["status", "--json"])
        // The macOS app binary acts as the CLI only when it believes it runs
        // in a terminal; this forces CLI behavior (documented by Tailscale).
        .env("TAILSCALE_BE_CLI", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    use std::os::unix::process::CommandExt;
    let Ok(mut child) = cmd.spawn() else {
        return TsState::Failed("the Tailscale CLI could not be started");
    };
    let out = child.stdout.take();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        if let Some(o) = out {
            let _ = o.take(MAX_STATUS_BYTES as u64 + 1).read_to_end(&mut buf);
        }
        buf
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => {
                // SAFETY: signalling our own child's process group.
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                break None;
            }
        }
    };
    let Some(status) = status else {
        return TsState::Failed("tailscale status timed out");
    };
    let stdout = reader.join().unwrap_or_default();
    if stdout.is_empty() && !status.success() {
        return TsState::Failed("tailscale status failed (is tailscaled running?)");
    }
    // `tailscale status --json` exits 0 in every backend state; a non-zero
    // exit with a document still carries the state, so parse what we got.
    parse_status(&stdout)
}

/// Make a peer-supplied string safe to print on a terminal.
pub fn printable(s: &str) -> String {
    s.chars()
        .take(128)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{
      "Version": "1.80.0", "BackendState": "Running",
      "AuthURL": "https://login.tailscale.com/a/secret123",
      "MagicDNSSuffix": "old-suffix.ts.net",
      "CurrentTailnet": {"Name": "someone@example.com", "MagicDNSSuffix": "tail-ex.ts.net", "MagicDNSEnabled": true},
      "Self": {"ID": "nSELF1CNTRL", "DNSName": "laptop.tail-ex.ts.net.", "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"], "Online": true},
      "Peer": {
        "nodekey:aa": {"ID": "nBOX1CNTRL", "DNSName": "Box.tail-ex.ts.net.", "HostName": "box", "TailscaleIPs": ["100.64.0.2", "fd7a:115c:a1e0::2"], "Online": true},
        "nodekey:bb": {"ID": "bad id; rm -rf /", "DNSName": "evil.tail-ex.ts.net.", "TailscaleIPs": ["100.64.0.66"]},
        "nodekey:cc": {"ID": "nODD1CNTRL", "DNSName": "\u001b[31mred\u001b[0m", "TailscaleIPs": ["not-an-ip", "0.0.0.0", "100.64.0.3"], "Online": "yes", "Expired": true}
      },
      "User": {"1": {"LoginName": "someone@example.com"}}
    }"#;

    #[test]
    fn running_snapshot_extracts_only_validated_fields() {
        let TsState::Running(s) = parse_status(RUNNING.as_bytes()) else {
            panic!("not running");
        };
        assert_eq!(s.tailnet.as_deref(), Some("tail-ex.ts.net"));
        assert_eq!(s.self_node.as_ref().unwrap().id, "nSELF1CNTRL");
        assert_eq!(s.peers.len(), 2, "peer with an invalid ID is skipped");
        let b = s.peers.iter().find(|p| p.id == "nBOX1CNTRL").unwrap();
        assert_eq!(b.dns_name, "box.tail-ex.ts.net");
        assert_eq!(b.ips.len(), 2);
        let o = s.peers.iter().find(|p| p.id == "nODD1CNTRL").unwrap();
        assert_eq!(o.dns_name, "", "control characters make a name unusable");
        assert_eq!(o.ips, vec!["100.64.0.3".parse::<IpAddr>().unwrap()]);
        assert!(!o.online, "non-boolean Online is treated as false");
        assert!(o.expired);
        // Nothing sensitive survives parsing.
        let dbg = format!("{s:?}");
        for leak in ["secret123", "someone@example.com", "login.tailscale.com"] {
            assert!(!dbg.contains(leak), "{leak} leaked");
        }
    }

    #[test]
    fn deprecated_top_level_suffix_is_a_fallback() {
        let j = r#"{"BackendState":"Running","MagicDNSSuffix":"tail-old.ts.net.","Peer":null}"#;
        let TsState::Running(s) = parse_status(j.as_bytes()) else {
            panic!()
        };
        assert_eq!(s.tailnet.as_deref(), Some("tail-old.ts.net"));
        assert!(s.peers.is_empty() && s.self_node.is_none());
    }

    #[test]
    fn backend_states_and_malformed_documents() {
        for (j, want) in [
            (
                r#"{"BackendState":"NeedsLogin","AuthURL":"https://x/y"}"#,
                TsState::NotRunning {
                    state: "NeedsLogin",
                },
            ),
            (
                r#"{"BackendState":"Stopped"}"#,
                TsState::NotRunning { state: "Stopped" },
            ),
            (
                r#"{"BackendState":"NeedsMachineAuth"}"#,
                TsState::NotRunning {
                    state: "NeedsMachineAuth",
                },
            ),
            (
                r#"{"BackendState":"\u001b]0;pwn\u0007"}"#,
                TsState::NotRunning { state: "unknown" },
            ),
            (
                r#"{"BackendState":42}"#,
                TsState::Failed("tailscale status output has no BackendState"),
            ),
            (
                r#"[1,2]"#,
                TsState::Failed("tailscale status output has an unexpected format"),
            ),
            (
                r#"{"BackendState":"Running""#,
                TsState::Failed("tailscale status output is not valid JSON"),
            ),
            (
                "",
                TsState::Failed("tailscale status output is not valid JSON"),
            ),
        ] {
            assert_eq!(parse_status(j.as_bytes()), want, "{j}");
        }
        let big = vec![b' '; MAX_STATUS_BYTES + 1];
        assert_eq!(
            parse_status(&big),
            TsState::Failed("tailscale status output is too large")
        );
    }

    #[test]
    fn invalid_tailnet_suffix_is_unknown() {
        let j = r#"{"BackendState":"Running","CurrentTailnet":{"MagicDNSSuffix":"bad suffix\n"}}"#;
        let TsState::Running(s) = parse_status(j.as_bytes()) else {
            panic!()
        };
        assert_eq!(s.tailnet, None);
    }

    #[test]
    fn cli_candidates_per_os() {
        let path = OsStr::new("/opt/a:relative/dir:/usr/local/bin");
        let mac = cli_candidates(Os::MacOs, Some(path));
        assert_eq!(mac[0], PathBuf::from("/opt/a/tailscale"));
        assert!(
            !mac.iter().any(|p| p.starts_with("relative")),
            "relative PATH entries are ignored"
        );
        assert_eq!(mac.last().unwrap(), &PathBuf::from(MACOS_APP_CLI));
        assert_eq!(
            mac.iter()
                .filter(|p| p.as_path() == Path::new("/usr/local/bin/tailscale"))
                .count(),
            1
        );
        let linux = cli_candidates(Os::Linux, None);
        assert!(!linux.iter().any(|p| p.starts_with("/Applications")));
        assert!(linux.contains(&PathBuf::from("/usr/bin/tailscale")));
        assert!(missing_cli_hint(Os::MacOs).contains("Tailscale.app"));
    }

    #[test]
    fn printable_neutralizes_terminal_escapes() {
        assert_eq!(printable("a\u{1b}[31mb\n"), "a?[31mb?");
        assert_eq!(printable(&"x".repeat(500)).len(), 128);
    }
}
