//! Pure view-model helpers: color mapping, check indicators, text formatting.
//! Nothing here touches egui layout, so it is unit-testable.

use eframe::egui::Color32;
use lablink_core::model::{AuthState, Color, DeviceStatus, IdentityState, NetworkState, PortState};
use lablink_core::time::format_age;

pub const GREEN: Color32 = crate::theme::SUCCESS;
pub const YELLOW: Color32 = crate::theme::WARNING;
pub const RED: Color32 = crate::theme::ERROR;
pub const GRAY: Color32 = crate::theme::MUTED;

/// Traffic-light color for the big state dot.
pub fn state_color(c: Color) -> Color32 {
    match c {
        Color::Green => GREEN,
        Color::Yellow => YELLOW,
        Color::Red => RED,
        Color::Gray => GRAY,
    }
}

/// Severity of one check, independent of what the check measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Good,
    Warn,
    Bad,
    Neutral,
}

pub fn level_color(l: Level) -> Color32 {
    match l {
        Level::Good => GREEN,
        Level::Warn => YELLOW,
        Level::Bad => RED,
        Level::Neutral => GRAY,
    }
}

/// One small dot-plus-word indicator on a device card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Indicator {
    pub name: &'static str,
    pub word: &'static str,
    pub level: Level,
}

/// Network, SSH port, Login, Identity. Words match `lablink status`.
pub fn indicators(d: &DeviceStatus) -> [Indicator; 4] {
    let network = match d.network {
        // A device that was never located is unknown, not failed.
        _ if d.discovery == lablink_core::model::DiscoveryState::NeverSeen => {
            ("NOT FOUND", Level::Neutral)
        }
        NetworkState::Online => ("ONLINE", Level::Good),
        NetworkState::Degraded => ("DEGRADED", Level::Warn),
        NetworkState::Offline => ("OFFLINE", Level::Bad),
        NetworkState::Unknown => ("UNKNOWN", Level::Neutral),
    };
    let port = match d.ssh_port {
        PortState::Open => ("OPEN", Level::Good),
        PortState::Closed => ("CLOSED", Level::Warn),
        PortState::Filtered => ("FILTERED", Level::Warn),
        PortState::Unknown => ("UNKNOWN", Level::Neutral),
        PortState::Disabled => ("-", Level::Neutral),
    };
    let login = match d.ssh_auth {
        AuthState::Ok => ("OK", Level::Good),
        AuthState::Failed => ("AUTH_FAIL", Level::Bad),
        AuthState::Unavailable => ("UNAVAILABLE", Level::Neutral),
        AuthState::Unknown => ("UNKNOWN", Level::Neutral),
        AuthState::Disabled => ("-", Level::Neutral),
    };
    let identity = match d.identity {
        IdentityState::Verified => ("VERIFIED", Level::Good),
        IdentityState::Unverified => ("UNPINNED", Level::Warn),
        IdentityState::Mismatch => ("MISMATCH", Level::Bad),
        IdentityState::Unknown => ("UNKNOWN", Level::Neutral),
    };
    let ind = |name, (word, level)| Indicator { name, word, level };
    [
        ind("Network", network),
        ind("SSH port", port),
        ind("Login", login),
        ind("Identity", identity),
    ]
}

pub fn port_word(p: PortState) -> &'static str {
    match p {
        PortState::Open => "OPEN",
        PortState::Closed => "CLOSED",
        PortState::Filtered => "FILTERED",
        PortState::Unknown => "UNKNOWN",
        PortState::Disabled => "-",
    }
}

pub fn latency_text(ms: Option<u64>) -> String {
    ms.map_or_else(
        || "latency -".into(),
        |m| {
            if m == 0 {
                "<1 ms".into()
            } else {
                format!("{m} ms")
            }
        },
    )
}

pub fn last_seen_text(ms: Option<u64>) -> String {
    ms.map_or_else(
        || "never seen".into(),
        |m| format!("last seen {} ago", format_age(m)),
    )
}

/// Title line: `name` or `name (label)`.
pub fn title_text(d: &DeviceStatus) -> String {
    match d.label.as_deref().filter(|l| !l.is_empty()) {
        Some(l) => format!("{l} ({})", d.name),
        None => d.name.clone(),
    }
}

pub fn auth_word(a: AuthState) -> &'static str {
    match a {
        AuthState::Ok => "OK",
        AuthState::Failed => "FAILED",
        AuthState::Unavailable => "unavailable",
        AuthState::Disabled => "not checked",
        AuthState::Unknown => "unknown",
    }
}

pub fn identity_word(i: IdentityState) -> (&'static str, Level) {
    match i {
        IdentityState::Verified => ("VERIFIED", Level::Good),
        IdentityState::Unverified => ("UNPINNED", Level::Warn),
        IdentityState::Mismatch => ("MISMATCH (security stop)", Level::Bad),
        IdentityState::Unknown => ("unknown", Level::Neutral),
    }
}

pub fn service_word(s: lablink_core::model::ServiceState) -> (&'static str, Level) {
    use lablink_core::model::ServiceState as S;
    match s {
        S::Ok => ("OK", Level::Good),
        S::Degraded => ("DEGRADED", Level::Warn),
        S::Failed => ("FAILED", Level::Bad),
        S::Disabled => ("disabled", Level::Neutral),
        S::Unknown => ("unknown", Level::Neutral),
    }
}

#[cfg(test)]
pub mod tests_support {
    use super::*;
    use lablink_core::model::DiscoveryState;

    /// A GREEN, verified SSH device for tests.
    pub fn dev() -> DeviceStatus {
        DeviceStatus {
            name: "jetson-a".into(),
            id: String::new(),
            site: "default".into(),
            site_name: "Default".into(),
            site_state: lablink_core::site::SiteState::Active,
            label: None,
            color: Color::Green,
            ip: Some("10.0.0.5".into()),
            discovery: DiscoveryState::Located,
            network: NetworkState::Online,
            ssh_port: PortState::Open,
            ssh_auth: AuthState::Ok,
            identity: IdentityState::Verified,
            latency_ms: Some(3),
            last_seen_ms: Some(4_000),
            username: None,
            interface: None,
            network_name: None,
            via: None,
            monitoring: true,
            reasons: vec![],
            services: vec![],
            profile: None,
            capabilities: vec![],
        }
    }
}

/// Marker that separates the plain-language part of a message from the raw
/// error text behind it.
pub const DETAILS: &str = "\n\nTechnical details: ";

/// Split a message into what people read first and the technical details
/// shown on request.
pub fn split_details(msg: &str) -> (&str, Option<&str>) {
    match msg.split_once(DETAILS) {
        Some((head, tail)) if !tail.trim().is_empty() => (head, Some(tail)),
        Some((head, _)) => (head, None),
        None => (msg, None),
    }
}

/// Show `msg` in `color`, with any technical details behind a collapsed
/// "Technical details" section (nothing is hidden: it is one click away).
pub fn message_with_details(ui: &mut eframe::egui::Ui, color: Color32, msg: &str) {
    let (head, details) = split_details(msg);
    ui.colored_label(color, head);
    if let Some(d) = details {
        eframe::egui::CollapsingHeader::new("Technical details")
            .id_salt(("details", head))
            .default_open(false)
            .show(ui, |ui| {
                ui.add(eframe::egui::Label::new(eframe::egui::RichText::new(d).monospace()).wrap());
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::dev;

    #[test]
    fn technical_details_are_split_off_not_dropped() {
        assert_eq!(split_details("plain"), ("plain", None));
        let m = format!("Couldn't find it.{DETAILS}failed to lookup address");
        assert_eq!(
            split_details(&m),
            ("Couldn't find it.", Some("failed to lookup address"))
        );
        assert_eq!(split_details(&format!("x{DETAILS}  ")), ("x", None));
    }

    #[test]
    fn state_colors_are_distinct_and_fixed() {
        let all = [Color::Green, Color::Yellow, Color::Red, Color::Gray].map(state_color);
        assert_eq!(all, [GREEN, YELLOW, RED, GRAY]);
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(Color::Yellow.as_str(), "YELLOW");
    }

    #[test]
    fn levels_map_to_state_palette() {
        assert_eq!(level_color(Level::Good), GREEN);
        assert_eq!(level_color(Level::Warn), YELLOW);
        assert_eq!(level_color(Level::Bad), RED);
        assert_eq!(level_color(Level::Neutral), GRAY);
    }

    #[test]
    fn healthy_device_indicators() {
        let i = indicators(&dev());
        assert_eq!(
            i.map(|x| (x.name, x.word, x.level)),
            [
                ("Network", "ONLINE", Level::Good),
                ("SSH port", "OPEN", Level::Good),
                ("Login", "OK", Level::Good),
                ("Identity", "VERIFIED", Level::Good),
            ]
        );
    }

    #[test]
    fn problem_indicators() {
        let mut d = dev();
        d.network = NetworkState::Offline;
        d.ssh_port = PortState::Closed;
        d.ssh_auth = AuthState::Failed;
        d.identity = IdentityState::Mismatch;
        let i = indicators(&d);
        assert_eq!(i[0].level, Level::Bad);
        assert_eq!((i[1].word, i[1].level), ("CLOSED", Level::Warn));
        assert_eq!((i[2].word, i[2].level), ("AUTH_FAIL", Level::Bad));
        assert_eq!((i[3].word, i[3].level), ("MISMATCH", Level::Bad));
        d.identity = IdentityState::Unverified;
        d.ssh_port = PortState::Disabled;
        let i = indicators(&d);
        assert_eq!((i[3].word, i[3].level), ("UNPINNED", Level::Warn));
        assert_eq!((i[1].word, i[1].level), ("-", Level::Neutral));
    }

    #[test]
    fn text_helpers() {
        assert_eq!(latency_text(Some(12)), "12 ms");
        assert_eq!(latency_text(None), "latency -");
        assert_eq!(last_seen_text(Some(240_000)), "last seen 4m ago");
        assert_eq!(last_seen_text(None), "never seen");
        let mut d = dev();
        assert_eq!(title_text(&d), "jetson-a");
        d.label = Some("bench".into());
        assert_eq!(title_text(&d), "bench (jetson-a)");
        d.label = Some(String::new());
        assert_eq!(title_text(&d), "jetson-a");
    }
}
