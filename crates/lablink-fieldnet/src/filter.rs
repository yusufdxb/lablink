//! The field filter: the packet filter that keeps hotspot clients off every
//! other network and off this machine's unrelated services, from before
//! the access point starts until after it stops.
//!
//! It is a NetworkManager dispatcher script (`packaging/networkmanager/`
//! in the source tree) that an administrator installs once at [`SCRIPT`].
//! LabLink never runs as root and never changes the filter itself: it only
//! checks it. The script keeps one nftables table, `inet lablink_field`.
//! Every Wi-Fi interface (name `wl*`) is *armed* unless NetworkManager runs
//! an ordinary connection on it; the script opens an interface at pre-up of
//! a connection without LabLink's isolation rule and arms it again at
//! pre-down and down. Armed means:
//!
//! - nothing is forwarded from or to the interface (IPv4 and IPv6);
//! - this machine accepts from it only DHCP, ICMP, IGMP and the services
//!   the script lists (SSH, mDNS, ROS 2 DDS domain 0 by default), and only
//!   when addressed to the interface's own address, its broadcast or a
//!   multicast group; everything else, DNS included, is refused.
//!
//! So the interface is armed while it is disconnected before a hotspot
//! starts, the whole time the hotspot runs and after it stops. The table is
//! kernel state: it stays in force when NetworkManager, `lablinkd` or
//! LabLink stop or crash, and a drop verdict in it is final whatever other
//! firewall tables accept. That is prevention. `lablinkd`'s periodic check
//! is recovery: it notices a filter that was removed or opened and stops
//! the hotspot, seconds later.
//!
//! LabLink cannot read nftables without root, so it probes: a UDP datagram
//! to [`PROBE_ADDR`] port [`ARMED_PORT`] from a socket bound to the
//! interface (`SO_BINDTODEVICE`, unprivileged since Linux 5.7) is dropped
//! by the script's output chain while the interface is armed, which makes
//! `send` fail with `EPERM` before anything leaves. A control datagram to
//! [`CONTROL_PORT`] must go out; if it is refused too, some other firewall
//! denies output and the probe proves nothing. The same pair on the
//! loopback interface ([`LOOPBACK_PROBE`]) tells whether the table is
//! loaded at all. The probe shows that the table exists and that the
//! interface is armed; it cannot show that root has not edited the table's
//! other rules (root is trusted, see THREAT_MODEL.md).

use crate::system::System;
use serde::Serialize;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

/// Where the administrator installs the dispatcher script.
pub const SCRIPT: &str = "/etc/NetworkManager/dispatcher.d/90-lablink-field-filter";
/// RFC 7600's dummy address: nothing answers it.
pub const PROBE_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 8);
pub const LOOPBACK_PROBE: Ipv4Addr = Ipv4Addr::new(127, 77, 77, 77);
/// Dropped by the filter while the interface is armed.
pub const ARMED_PORT: u16 = 47977;
/// Never dropped by the filter.
pub const CONTROL_PORT: u16 = 47976;

/// The filter's state for one interface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", content = "detail", rename_all = "kebab-case")]
pub enum Filter {
    /// Loaded, and the interface is armed.
    Armed,
    /// Loaded, but the interface is open (an ordinary connection).
    Open,
    /// The table is not loaded.
    NotLoaded,
    /// The probe cannot tell.
    Unknown(String),
}

impl Filter {
    /// Why this state does not isolate `iface`; `None` when armed.
    pub fn problem(&self, iface: &str) -> Option<String> {
        match self {
            Filter::Armed => None,
            Filter::Open => Some(format!(
                "the field filter has opened {iface} (it treats the connection on it as an ordinary one)"
            )),
            Filter::NotLoaded => Some(format!(
                "the field filter is not loaded (table inet lablink_field is missing; an administrator runs `{SCRIPT} load`)"
            )),
            Filter::Unknown(why) => Some(format!("the field filter cannot be checked: {why}")),
        }
    }
}

fn eperm(r: &io::Result<()>) -> bool {
    matches!(r, Err(e) if e.raw_os_error() == Some(libc::EPERM))
}

/// One armed/control probe pair: `Ok(true)` when only the armed probe is
/// refused, `Ok(false)` when neither is.
fn pair(sys: &dyn System, iface: Option<&str>, addr: Ipv4Addr) -> Result<bool, String> {
    let on = iface.unwrap_or("the loopback interface");
    let probe = sys.send_probe(iface, SocketAddrV4::new(addr, ARMED_PORT));
    match probe {
        Ok(()) => return Ok(false),
        Err(e) if e.raw_os_error() != Some(libc::EPERM) => {
            return Err(format!("cannot send a probe on {on}: {e}"))
        }
        Err(_) => {}
    }
    let control = sys.send_probe(iface, SocketAddrV4::new(addr, CONTROL_PORT));
    if eperm(&control) {
        return Err(format!(
            "another firewall refuses this machine's own packets on {on}, so the probe cannot tell"
        ));
    }
    control
        .map(|()| true)
        .map_err(|e| format!("cannot send a probe on {on}: {e}"))
}

/// Whether the filter's table is loaded.
pub fn loaded(sys: &dyn System) -> Result<bool, String> {
    pair(sys, None, LOOPBACK_PROBE)
}

/// The filter's state for `iface`.
pub fn state(sys: &dyn System, iface: &str) -> Filter {
    match loaded(sys) {
        Ok(true) => {}
        Ok(false) => return Filter::NotLoaded,
        Err(why) => return Filter::Unknown(why),
    }
    match pair(sys, Some(iface), PROBE_ADDR) {
        Ok(true) => Filter::Armed,
        Ok(false) => Filter::Open,
        Err(why) => Filter::Unknown(why),
    }
}

/// The installed script's text (it is world-readable), `None` when it is
/// not installed.
pub fn script(sys: &dyn System) -> Option<String> {
    sys.read_file(Path::new(SCRIPT))
}

/// The services the installed script lets hotspot clients reach on this
/// machine, besides DHCP and ICMP ("tcp 22", "udp 5353, 7400-7649"). Read
/// from the file, so an edit the administrator has not loaded yet shows
/// here first.
pub fn services(script: &str) -> Vec<String> {
    ["TCP", "UDP"]
        .iter()
        .filter_map(|proto| {
            let key = format!("FIELD_{proto}=");
            let value = script
                .lines()
                .find_map(|l| l.trim().strip_prefix(key.as_str()))?
                .trim()
                .trim_matches('"')
                .trim();
            (!value.is_empty()).then(|| format!("{} {value}", proto.to_lowercase()))
        })
        .collect()
}

/// The verdicts the filter gives, for the fake system and debug-build end
/// to end tests: `armed` (the default), `open`, `unloaded`, `denied` (a
/// foreign firewall refuses every probe) or `down` (the interface cannot
/// send).
pub fn simulated_probe(mode: &str, iface: Option<&str>, to: SocketAddrV4) -> io::Result<()> {
    let refused = || Err(io::Error::from_raw_os_error(libc::EPERM));
    match mode.trim() {
        "denied" => refused(),
        "unloaded" => Ok(()),
        "down" if iface.is_some() => Err(io::Error::from_raw_os_error(libc::ENETUNREACH)),
        "open" if iface.is_some() => Ok(()),
        _ if to.port() == ARMED_PORT => refused(),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;

    #[test]
    fn the_probe_reads_the_filter() {
        let sys = FakeSystem::new();
        assert_eq!(state(&sys, "wlan0"), Filter::Armed);
        assert_eq!(loaded(&sys), Ok(true));
        sys.set_filter("open");
        assert_eq!(state(&sys, "wlan0"), Filter::Open);
        assert!(Filter::Open
            .problem("wlan0")
            .unwrap()
            .contains("opened wlan0"));
        sys.set_filter("unloaded");
        assert_eq!(state(&sys, "wlan0"), Filter::NotLoaded);
        assert_eq!(loaded(&sys), Ok(false));
        // A firewall that refuses everything proves nothing.
        sys.set_filter("denied");
        assert!(
            matches!(state(&sys, "wlan0"), Filter::Unknown(w) if w.contains("another firewall"))
        );
        assert!(loaded(&sys).is_err());
        sys.set_filter("down");
        assert!(matches!(state(&sys, "wlan0"), Filter::Unknown(w) if w.contains("cannot send")));
        assert_eq!(Filter::Armed.problem("wlan0"), None);
    }

    #[test]
    fn services_come_from_the_script() {
        let text = "set -u\nFIELD_TCP=\"22\"\nFIELD_UDP=\"5353, 7400-7649\"\n";
        assert_eq!(services(text), vec!["tcp 22", "udp 5353, 7400-7649"]);
        assert_eq!(
            services("FIELD_TCP=\"\"\nFIELD_UDP=\n"),
            Vec::<String>::new()
        );
        let shipped = include_str!("../../../packaging/networkmanager/90-lablink-field-filter");
        assert_eq!(services(shipped), vec!["tcp 22", "udp 5353, 7400-7649"]);
        // The probe constants match the script's output chain.
        assert!(shipped.contains(&format!(
            "ip daddr {PROBE_ADDR} udp dport {ARMED_PORT} oifname \"wl*\" oifname != @open drop"
        )));
        assert!(shipped.contains(&format!(
            "ip daddr {LOOPBACK_PROBE} udp dport {ARMED_PORT} drop"
        )));
        assert!(!shipped.contains(&CONTROL_PORT.to_string()));
    }

    /// The real probe on this machine's loopback interface: it must answer
    /// one way or the other without privileges.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_probe_runs_unprivileged() {
        let r = loaded(&crate::system::RealSystem);
        assert!(r.is_ok(), "{r:?}");
    }
}
