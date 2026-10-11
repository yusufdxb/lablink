//! Plain-language explanations of non-GREEN device states.
//!
//! The daemon's `reasons` say *what* is wrong in a few words. An
//! [`Explanation`] adds what still works, the likely cause and the safest next
//! step, so the CLI and the GUI can show the same actionable text. It is
//! derived only from the status the daemon reports; nothing here probes.

use crate::model::{
    AuthState, Color, DeviceStatus, DiscoveryState, IdentityState, NetworkState, PortState,
};
use serde::Serialize;

/// Something the user can do about the problem. Front ends map these to
/// buttons (GUI) or commands (CLI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Install the user's public key on the device (`lablink copy-id`).
    SshSetup,
    /// Review and pin the host key (`lablink trust`).
    Trust,
    /// Review a changed host key; replacing the pin needs out-of-band proof.
    TrustReplace,
    /// Run discovery now.
    Discover,
    /// Turn monitoring back on.
    EnableMonitoring,
    /// Change the device's settings (username, profile, SSH on/off).
    EditSettings,
    /// Check the gateway device the device is reached through.
    CheckGateway,
    /// Make the device's site the active one (`lablink site use`).
    SwitchSite,
}

impl Action {
    /// The CLI command for this action on `d`.
    pub fn command(self, d: &DeviceStatus) -> String {
        let device = d.name.as_str();
        match self {
            Action::SwitchSite => format!("lablink site use {}", d.site),
            Action::SshSetup => format!("lablink copy-id {device}"),
            Action::Trust => format!("lablink trust {device}"),
            Action::TrustReplace => format!("lablink trust {device} --replace"),
            Action::Discover => "lablink discover".into(),
            Action::EnableMonitoring => format!("lablink set {device} --monitoring on"),
            Action::EditSettings => format!("lablink set {device} --user <name>"),
            Action::CheckGateway => "lablink status".into(),
        }
    }

    /// Button text.
    pub fn label(self) -> &'static str {
        match self {
            Action::SshSetup => "SSH Setup",
            Action::Trust => "Trust host key...",
            Action::TrustReplace => "Review changed key...",
            Action::Discover => "Discover",
            Action::EnableMonitoring => "Enable monitoring",
            Action::EditSettings => "Edit settings",
            Action::CheckGateway => "Show gateway",
            Action::SwitchSite => "Switch to this site",
        }
    }
}

/// An actionable explanation of one device's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explanation {
    pub color: Color,
    /// Short title, e.g. "SSH authentication failed".
    pub headline: String,
    /// One or two sentences.
    pub summary: String,
    pub failed: Vec<String>,
    pub still_works: Vec<String>,
    pub likely_cause: String,
    pub next_step: String,
    /// Host-key mismatch: never connect, never work around.
    pub security_stop: bool,
    pub actions: Vec<Action>,
}

fn working(d: &DeviceStatus) -> Vec<String> {
    let mut v = Vec::new();
    match d.network {
        NetworkState::Online => v.push(match (&d.ip, &d.via) {
            (Some(ip), Some(gw)) => format!("network: {ip} answers (checked through {gw})"),
            (Some(ip), None) => format!("network: {ip} answers"),
            _ => "network: answers".into(),
        }),
        NetworkState::Degraded => v.push("network: answers intermittently".into()),
        _ => {}
    }
    if d.ssh_port == PortState::Open {
        v.push("SSH server: accepting connections".into());
    }
    if d.identity == IdentityState::Verified {
        v.push("identity: verified against the pinned host key".into());
    }
    if d.ssh_auth == AuthState::Ok {
        v.push("SSH login: works".into());
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn ex(
    d: &DeviceStatus,
    color: Color,
    headline: &str,
    summary: String,
    failed: Vec<String>,
    likely_cause: &str,
    next_step: String,
    actions: Vec<Action>,
) -> Explanation {
    Explanation {
        color,
        headline: headline.into(),
        summary,
        failed,
        still_works: working(d),
        likely_cause: likely_cause.into(),
        next_step,
        security_stop: false,
        actions,
    }
}

/// Explain a device that is not GREEN. Returns `None` for GREEN devices.
pub fn explain(d: &DeviceStatus) -> Option<Explanation> {
    if d.color == Color::Green {
        return None;
    }
    let n = &d.name;
    let ip = d.ip.as_deref().unwrap_or("its last address");
    let user = d.username.as_deref().unwrap_or("your default user");
    let gateway_reason = d.reasons.iter().find(|r| r.contains("gateway")).cloned();

    if !d.monitoring {
        return Some(ex(
            d,
            Color::Gray,
            "Monitoring is off",
            format!("LabLink is not checking {n}."),
            vec![],
            "monitoring was turned off for this device",
            "Turn monitoring back on when you want LabLink to watch it again.".into(),
            vec![Action::EnableMonitoring],
        ));
    }
    if d.identity == IdentityState::Mismatch {
        return Some(Explanation {
            color: Color::Red,
            headline: "SECURITY STOP: host key changed".into(),
            summary: format!(
                "The machine answering at {ip} presents a different SSH host key than the one pinned for {n}. LabLink refuses ssh, exec and checks until this is resolved."
            ),
            failed: vec!["identity: host key does not match the pinned key".into()],
            still_works: vec![format!("network path to {ip} (do not log in)")],
            likely_cause: "the device was reinstalled or its SSH keys were regenerated; or a different machine now has its address; or someone is impersonating it".into(),
            next_step: format!(
                "Do not connect. On the device's own console run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` and compare. Only if it matches the new key, replace the pin: `lablink trust {n} --replace`."
            ),
            security_stop: true,
            actions: vec![Action::TrustReplace],
        });
    }
    let site = if d.site_name.is_empty() {
        d.site.as_str()
    } else {
        d.site_name.as_str()
    };
    if d.site_state == crate::site::SiteState::Away {
        return Some(ex(
            d,
            Color::Gray,
            "Site is away",
            format!("{n} belongs to {site}, and LabLink detects that you are not there, so it is not checked and not counted as failed."),
            vec![],
            "you are at another site (or no known site)",
            format!("Nothing to do while you are away. If you are at {site}, switch to it: `lablink site use {}`.", d.site),
            vec![Action::SwitchSite],
        ));
    }
    if d.site_state == crate::site::SiteState::Unknown
        && d.color == Color::Gray
        && d.network == NetworkState::Offline
    {
        return Some(ex(
                d,
                Color::Gray,
                "Site not confirmed",
                format!("{n} does not answer, but LabLink is not sure you are at {site} (another site matches this network equally well), so this is not reported as a failure."),
                vec![format!("network: {ip} does not answer")],
                "you may be at another site that uses the same addresses",
                format!("If you are at {site}, choose it: `lablink site use {}`.", d.site),
                vec![Action::SwitchSite],
            ));
    }
    if d.discovery == DiscoveryState::NeverSeen {
        if let (Some(gw), Some(r)) = (&d.via, &gateway_reason) {
            return Some(ex(
                d,
                d.color,
                "Waiting for the gateway",
                format!("{n} is checked through {gw}, and {r}."),
                vec![format!("gateway: {r}")],
                "the gateway device is off, unreachable, or its SSH login is not working",
                format!(
                    "Fix {gw} first (see its status); {n} is checked as soon as {gw} is GREEN."
                ),
                vec![Action::CheckGateway],
            ));
        }
        return Some(ex(
            d,
            Color::Gray,
            "Not found yet",
            format!("LabLink has not located {n} on any allowed network."),
            vec!["network: no address known".into()],
            "the device is off, on a network LabLink is not allowed to watch, or its address changed before LabLink first saw it",
            "Make sure it is powered and connected, then run Discover. If it lives on another network, add that network in Settings.".into(),
            vec![Action::Discover],
        ));
    }
    match d.network {
        NetworkState::Unknown => {
            return Some(ex(
                d,
                Color::Gray,
                "Not checked yet",
                format!("LabLink is checking {n} now."),
                vec![],
                "the daemon just started or the device was just added",
                "Wait a few seconds.".into(),
                vec![],
            ))
        }
        NetworkState::Offline => {
            let mut s = format!("{n} stopped answering at {ip}.");
            if d.identity == IdentityState::Verified {
                s.push_str(" Its identity stays pinned, so LabLink will recognise it again at any address.");
            }
            let (cause, actions) = match (&d.via, &gateway_reason) {
                (Some(_), Some(_)) => (
                    "the gateway it is checked through cannot reach it, or the gateway itself is down",
                    vec![Action::CheckGateway],
                ),
                _ => (
                    "powered off or asleep, cable or Wi-Fi disconnected, or moved to another network",
                    vec![Action::Discover],
                ),
            };
            return Some(ex(
                d,
                Color::Red,
                "Device is unreachable",
                s,
                vec!["network: no reply after the failure threshold".into()],
                cause,
                "Check power and cabling. LabLink keeps re-checking on its own; run Discover if the device may have a new address.".into(),
                actions,
            ));
        }
        _ => {}
    }
    let port = match &d.via {
        Some(_) => "the SSH port",
        None => "port 22 (or the configured SSH port)",
    };
    let ssh = d.ssh_port != PortState::Disabled;
    if ssh {
        match d.ssh_port {
            PortState::Closed => {
                return Some(ex(
                    d,
                    d.color,
                    "SSH is not accepting connections",
                    format!("{n} is online, but {port} refuses connections."),
                    vec!["SSH server: connection refused".into()],
                    "the SSH server is stopped or not installed on the device",
                    format!("On the device run `sudo systemctl enable --now ssh`. If {n} has no SSH server (a robot base, a PLC), set its profile to Network-only / Robot."),
                    vec![Action::EditSettings],
                ))
            }
            PortState::Filtered => {
                return Some(ex(
                    d,
                    d.color,
                    "SSH port is not answering",
                    format!("{n} is online, but {port} does not answer."),
                    vec!["SSH server: no answer (filtered)".into()],
                    "a firewall drops SSH, or the SSH server is still starting",
                    format!("Check the device's firewall (for example `sudo ufw allow ssh`). If {n} has no SSH server, set its profile to Network-only / Robot."),
                    vec![Action::EditSettings],
                ))
            }
            _ => {}
        }
        match d.identity {
            IdentityState::Unverified => {
                return Some(ex(
                    d,
                    d.color,
                    "Host key not trusted yet",
                    format!("{n} is reachable and its SSH server answers, but you have not confirmed its host key, so LabLink cannot prove it is the right machine."),
                    vec!["identity: host key not pinned".into()],
                    "the device was just adopted (expected), or it was never trusted",
                    "Open Trust, compare the fingerprint with the device's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on its console), then pin it.".into(),
                    vec![Action::Trust],
                ))
            }
            IdentityState::Unknown if d.ssh_port == PortState::Open => {
                return Some(ex(
                    d,
                    d.color,
                    "Reading the host key",
                    format!("{n}'s SSH server answers; LabLink has not read its host key yet."),
                    vec![],
                    "the device was just found",
                    "Wait a few seconds.".into(),
                    vec![],
                ))
            }
            _ => {}
        }
        match d.ssh_auth {
            AuthState::Failed => {
                let summary = if d.identity == IdentityState::Verified {
                    "Device is reachable and identity is verified, but no accepted SSH key was found."
                        .to_string()
                } else {
                    "Device is reachable, but no accepted SSH key was found.".to_string()
                };
                return Some(ex(
                    d,
                    d.color,
                    "SSH authentication failed",
                    summary,
                    vec![format!("SSH login as {user}: keys and agent rejected")],
                    "your public key is not in ~/.ssh/authorized_keys for that user on the device, the username is wrong, or the server only accepts passwords",
                    format!("Install your key with SSH Setup (`lablink copy-id {n}`; you type the device password once, LabLink never sees or stores it), or set the correct SSH username."),
                    vec![Action::SshSetup, Action::EditSettings],
                ));
            }
            AuthState::Unavailable
                if d.reasons
                    .iter()
                    .any(|r| r.contains("does not match the pin") || r.contains("key CHANGED")) =>
            {
                return Some(Explanation {
                    color: d.color,
                    headline: "Host key changed: re-verifying".into(),
                    summary: format!("SSH refused to log in to {n} because the server presented a different host key than the pinned one. LabLink is re-checking its identity now."),
                    failed: vec!["SSH login: refused, host key differs from the pin".into()],
                    still_works: vec![format!("network: {ip} answers (do not log in)")],
                    likely_cause: "the device was reinstalled or its SSH keys regenerated, or a different machine answers at this address".into(),
                    next_step: "Do not connect. If the identity check confirms a mismatch, verify the new key on the device's console before replacing the pin.".into(),
                    security_stop: true,
                    actions: vec![],
                });
            }
            AuthState::Unavailable => {
                return Some(ex(
                    d,
                    d.color,
                    "SSH login could not be checked",
                    format!("LabLink could not complete a test login to {n}."),
                    d.reasons.iter().map(|r| format!("ssh: {r}")).collect(),
                    "a network hiccup during the check, or an SSH error shown in the details",
                    "Look at the details below. LabLink re-checks on its own.".into(),
                    vec![],
                ));
            }
            _ => {}
        }
    }
    if d.network == NetworkState::Degraded {
        return Some(ex(
            d,
            d.color,
            "Connection is unstable",
            format!("Some recent checks of {n} got no reply."),
            vec!["network: recent checks failed".into()],
            "weak Wi-Fi, a busy link, or the device is under heavy load",
            "Usually transient. If it persists, check the cable or Wi-Fi signal.".into(),
            vec![],
        ));
    }
    // Remaining YELLOW states are transient (port or login not checked yet).
    Some(ex(
        d,
        d.color,
        "Checks in progress",
        format!("LabLink has not finished checking {n}."),
        d.reasons.clone(),
        "the device was just found or just came back",
        "Wait a few seconds.".into(),
        vec![],
    ))
}

/// Plain-text rendering for the CLI.
pub fn render_text(e: &Explanation) -> String {
    let mut s = format!("{}\n\n{}\n", e.headline, e.summary);
    if !e.failed.is_empty() {
        s.push_str("\nWhat failed:\n");
        for f in &e.failed {
            s.push_str(&format!("  - {f}\n"));
        }
    }
    if !e.still_works.is_empty() {
        s.push_str("What still works:\n");
        for w in &e.still_works {
            s.push_str(&format!("  - {w}\n"));
        }
    }
    s.push_str(&format!("Likely cause: {}\n", e.likely_cause));
    s.push_str(&format!("Next step: {}\n", e.next_step));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceStatus {
        DeviceStatus {
            name: "robot".into(),
            id: String::new(),
            site: "default".into(),
            site_name: "Default".into(),
            site_state: crate::site::SiteState::Active,
            label: None,
            color: Color::Green,
            ip: Some("10.0.0.5".into()),
            discovery: DiscoveryState::Located,
            network: NetworkState::Online,
            ssh_port: PortState::Open,
            ssh_auth: AuthState::Ok,
            identity: IdentityState::Verified,
            latency_ms: Some(2),
            last_seen_ms: Some(1000),
            username: Some("ops".into()),
            interface: None,
            network_name: None,
            via: None,
            visiting: None,
            monitoring: true,
            reasons: vec![],
            services: vec![],
            profile: None,
            capabilities: vec![],
        }
    }

    #[test]
    fn green_has_no_explanation() {
        assert_eq!(explain(&dev()), None);
    }

    #[test]
    fn auth_failure_matches_the_documented_wording() {
        let mut d = dev();
        d.color = Color::Yellow;
        d.ssh_auth = AuthState::Failed;
        let e = explain(&d).unwrap();
        assert_eq!(e.headline, "SSH authentication failed");
        assert_eq!(
            e.summary,
            "Device is reachable and identity is verified, but no accepted SSH key was found."
        );
        assert_eq!(e.actions[0], Action::SshSetup);
        assert!(e.still_works.iter().any(|w| w.starts_with("identity")));
        assert!(!e.security_stop);
        assert!(render_text(&e).contains("lablink copy-id robot"));
    }

    #[test]
    fn mismatch_is_a_security_stop_that_never_suggests_ssh() {
        let mut d = dev();
        d.color = Color::Red;
        d.identity = IdentityState::Mismatch;
        let e = explain(&d).unwrap();
        assert!(e.security_stop);
        assert_eq!(e.actions, [Action::TrustReplace]);
        assert!(e.next_step.starts_with("Do not connect"));
        assert!(!e.actions.contains(&Action::SshSetup));
    }

    #[test]
    fn each_state_has_a_next_step() {
        type Mutate = fn(&mut DeviceStatus);
        let cases: [(&str, Mutate); 8] = [
            ("Monitoring is off", |d| d.monitoring = false),
            ("Not found yet", |d| d.discovery = DiscoveryState::NeverSeen),
            ("Device is unreachable", |d| {
                d.network = NetworkState::Offline
            }),
            ("SSH is not accepting connections", |d| {
                d.ssh_port = PortState::Closed
            }),
            ("SSH port is not answering", |d| {
                d.ssh_port = PortState::Filtered
            }),
            ("Host key not trusted yet", |d| {
                d.identity = IdentityState::Unverified
            }),
            ("Connection is unstable", |d| {
                d.network = NetworkState::Degraded
            }),
            ("Checks in progress", |d| d.ssh_auth = AuthState::Unknown),
        ];
        for (want, f) in cases {
            let mut d = dev();
            d.color = Color::Yellow;
            f(&mut d);
            let e = explain(&d).unwrap();
            assert_eq!(e.headline, want);
            assert!(!e.next_step.is_empty() && !e.likely_cause.is_empty());
        }
    }

    #[test]
    fn gateway_problems_point_at_the_gateway() {
        let mut d = dev();
        d.color = Color::Gray;
        d.discovery = DiscoveryState::NeverSeen;
        d.via = Some("jetson-a".into());
        d.reasons = vec!["cannot check: gateway 'jetson-a' SSH login is not working".into()];
        let e = explain(&d).unwrap();
        assert_eq!(e.headline, "Waiting for the gateway");
        assert_eq!(e.actions, [Action::CheckGateway]);
    }

    #[test]
    fn network_only_devices_never_get_ssh_advice() {
        let mut d = dev();
        d.color = Color::Red;
        d.ssh_port = PortState::Disabled;
        d.ssh_auth = AuthState::Disabled;
        d.identity = IdentityState::Unknown;
        d.network = NetworkState::Offline;
        let e = explain(&d).unwrap();
        assert!(!e.actions.contains(&Action::SshSetup));
        d.network = NetworkState::Degraded;
        d.color = Color::Yellow;
        assert_eq!(explain(&d).unwrap().headline, "Connection is unstable");
    }
}
