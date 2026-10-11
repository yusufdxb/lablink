//! Preflight: everything that decides whether starting the Field Network
//! is safe, computed from read-only `HostFacts` before anything changes.
//!
//! Blockers stop `start` outright. Most have no override: a hotspot that
//! would cut the SSH session running the command, an insecure or
//! unverifiable configuration, a subnet collision. One has an explicit
//! flag: sharing another uplink's internet with hotspot clients.
//! Warnings (a connection that will drop, equipment that will lose this
//! machine, forwarding exposure) need `--yes` or a typed confirmation.

use crate::host::{ActiveConnection, HostFacts, SessionPath, WifiAdapter};
use crate::state::Security;
use crate::subnet;
use crate::system::Os;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Block,
    Warn,
    Info,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub message: String,
    /// The flag that explicitly accepts this blocker, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_flag: Option<&'static str>,
}

/// What the user asked for.
#[derive(Debug, Clone)]
pub struct Request {
    pub interface: Option<String>,
    pub ssid: String,
    pub subnet: Option<Ipv4Net>,
    pub security: Security,
    pub allow_internet_sharing: bool,
}

/// A registered device currently reached from this machine (from the
/// daemon), so the preflight can say who loses this machine.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Equipment {
    pub name: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize)]
pub struct Preflight {
    pub interface: Option<String>,
    pub ssid: String,
    pub security: Security,
    pub subnet: Option<Ipv4Net>,
    pub gateway: Option<Ipv4Addr>,
    /// The connection the adapter carries now, which the hotspot replaces.
    pub would_disconnect: Option<ActiveConnection>,
    /// The hotspot (LabLink's profile) is already running on the adapter.
    pub already_running: bool,
    pub findings: Vec<Finding>,
}

impl Preflight {
    pub fn blockers(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.level == Level::Block)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.level == Level::Warn)
            .collect()
    }

    pub fn blocked(&self) -> bool {
        !self.blockers().is_empty()
    }

    pub fn needs_confirmation(&self) -> bool {
        !self.warnings().is_empty()
    }
}

/// Inputs beyond the host facts.
pub struct Context<'a> {
    /// (site id, cidr) of the other LabLink sites.
    pub sites: &'a [(String, Ipv4Net)],
    pub equipment: &'a [Equipment],
    /// LabLink's own profile, if it exists.
    pub own_profile: Option<&'a str>,
}

pub fn check(facts: &HostFacts, req: &Request, ctx: &Context) -> Preflight {
    let mut f = Vec::new();
    let mut pf = Preflight {
        interface: None,
        ssid: req.ssid.clone(),
        security: req.security,
        subnet: None,
        gateway: None,
        would_disconnect: None,
        already_running: false,
        findings: Vec::new(),
    };
    let block = |f: &mut Vec<Finding>, code, message: String| {
        f.push(Finding {
            level: Level::Block,
            code,
            message,
            override_flag: None,
        })
    };
    let warn = |f: &mut Vec<Finding>, code, message: String| {
        f.push(Finding {
            level: Level::Warn,
            code,
            message,
            override_flag: None,
        })
    };
    let info = |f: &mut Vec<Finding>, code, message: String| {
        f.push(Finding {
            level: Level::Info,
            code,
            message,
            override_flag: None,
        })
    };

    if let Err(e) = crate::password::validate_ssid(&req.ssid) {
        block(&mut f, "ssid", e);
    }
    match facts.os {
        Os::Linux => {}
        Os::Macos => {
            block(
                &mut f,
                "unsupported-os",
                "macOS: LabLink cannot create a hotspot itself. Use Internet Sharing (System Settings > General > Sharing); `lablink hotspot capabilities` shows the guided steps.".into(),
            );
            pf.findings = f;
            return pf;
        }
        Os::Other => {
            block(
                &mut f,
                "unsupported-os",
                "the Field Network needs Linux with NetworkManager".into(),
            );
            pf.findings = f;
            return pf;
        }
    }
    let Some(nm) = facts.nm.as_ref().filter(|n| n.running) else {
        block(
            &mut f,
            "networkmanager",
            if facts.nmcli {
                "NetworkManager is not running".into()
            } else {
                "NetworkManager (nmcli) is not installed; the Field Network uses it for the access point and DHCP".into()
            },
        );
        pf.findings = f;
        return pf;
    };
    if !nm.allowed("network-control") {
        block(
            &mut f,
            "permission",
            "NetworkManager does not let this user control networking without administrator authorization (polkit network-control). LabLink never asks for passwordless root.".into(),
        );
    }
    if ctx.own_profile.is_none() && !nm.allowed("settings.modify.system") {
        block(
            &mut f,
            "permission",
            "NetworkManager does not let this user create connection profiles without administrator authorization (polkit settings.modify.system)".into(),
        );
    }

    // The adapter. Never assume a second one exists.
    let capable: Vec<&WifiAdapter> = facts.wifi.iter().filter(|w| w.can_host_wpa2()).collect();
    let adapter = match &req.interface {
        Some(name) => match facts.wifi.iter().find(|w| &w.interface == name) {
            Some(w) if w.can_host_wpa2() => Some(w),
            Some(w) => {
                block(
                    &mut f,
                    "adapter",
                    format!("{name} cannot host a WPA2 access point ({})", missing(w)),
                );
                None
            }
            None => {
                block(
                    &mut f,
                    "adapter",
                    format!("{name} is not a Wi-Fi adapter managed by NetworkManager"),
                );
                None
            }
        },
        None => {
            let pick = capable
                .iter()
                .find(|w| w.connection.is_empty())
                .or_else(|| capable.first())
                .copied();
            if pick.is_none() {
                block(
                    &mut f,
                    "adapter",
                    if facts.wifi.is_empty() {
                        "no Wi-Fi adapter found".into()
                    } else {
                        format!(
                            "no Wi-Fi adapter here can host a WPA2 access point: {}",
                            facts
                                .wifi
                                .iter()
                                .map(|w| format!("{} ({})", w.interface, missing(w)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    },
                );
            }
            pick
        }
    };
    let Some(adapter) = adapter else {
        pf.findings = f;
        return pf;
    };
    let iface = adapter.interface.clone();
    pf.interface = Some(iface.clone());
    if capable.len() > 1 {
        info(
            &mut f,
            "adapter",
            format!(
                "{} capable adapters; using {iface} (choose with --interface)",
                capable.len()
            ),
        );
    }

    // Security.
    if req.security == Security::Wpa3 {
        match adapter.sae {
            Some(true) => {}
            Some(false) => block(
                &mut f,
                "security",
                format!("{iface} does not report WPA3-Personal (SAE) support; use the default, wpa2"),
            ),
            None => warn(
                &mut f,
                "security",
                format!("WPA3-Personal support of {iface} cannot be verified on this host (needs `iw`); activation may fail and older clients cannot join. wpa2 is the default."),
            ),
        }
    }

    // Our own SSH session must not ride on the adapter.
    match facts.session_path() {
        SessionPath::Local => {}
        SessionPath::Interface(i) if i == iface => block(
            &mut f,
            "remote-session",
            format!("this command runs over SSH through {iface}; starting the hotspot would cut this session, and an SSH connection is not a rollback path. Run it locally on this machine."),
        ),
        SessionPath::Interface(i) => info(&mut f, "remote-session", format!("running over SSH through {i}, which the hotspot does not touch")),
        SessionPath::Unknown(addr) => block(
            &mut f,
            "remote-session",
            format!("this command runs over SSH (to {addr}) and LabLink cannot tell which interface carries it, so it cannot rule out cutting the session. Run it locally."),
        ),
    }

    // What the adapter carries now.
    let current = facts.active_on(&iface).cloned();
    match &current {
        Some(c) if Some(c.uuid.as_str()) == ctx.own_profile => pf.already_running = true,
        Some(c) => {
            warn(
                &mut f,
                "disconnect",
                format!("{iface} will leave '{}' while the Field Network runs; `lablink hotspot stop` reconnects it", c.name),
            );
            pf.would_disconnect = Some(c.clone());
        }
        None => {}
    }
    let defaults = facts.default_routes();
    let others: Vec<_> = defaults.iter().filter(|r| r.device != iface).collect();
    if !pf.already_running
        && current.is_some()
        && defaults.iter().any(|r| r.device == iface)
        && others.is_empty()
    {
        warn(
            &mut f,
            "uplink",
            format!("{iface} carries this machine's only internet uplink: it is offline until the hotspot stops (the Field Network itself works offline)"),
        );
    }
    if !others.is_empty() {
        let names = others
            .iter()
            .map(|r| r.device.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if req.allow_internet_sharing {
            warn(
                &mut f,
                "internet-sharing",
                format!("hotspot clients will reach the internet through {names} (NetworkManager shared mode: NAT and IPv4 forwarding), as requested"),
            );
        } else {
            f.push(Finding {
                level: Level::Block,
                code: "internet-sharing",
                message: format!("this machine has another internet uplink ({names}); NetworkManager's shared mode would NAT hotspot clients onto it. LabLink does not share internet access unless you ask."),
                override_flag: Some("--allow-internet-sharing"),
            });
        }
    }
    let exposed: Vec<String> = facts
        .routes
        .iter()
        .filter(|r| {
            !r.is_default() && r.device != iface && r.device != "lo" && !r.dest.addr().is_loopback()
        })
        .map(|r| format!("{} ({})", r.dest, r.device))
        .collect();
    if !exposed.is_empty() {
        warn(
            &mut f,
            "forwarding",
            format!(
                "NetworkManager's shared mode enables IPv4 forwarding for hotspot clients. This machine also routes to {}; unless your firewall blocks forwarding from {iface}, hotspot clients can reach those networks through it. LabLink does not change firewall rules.",
                exposed.join(", ")
            ),
        );
    }
    if facts.ip_forward == Some(true) {
        info(
            &mut f,
            "forwarding",
            "IPv4 forwarding is already enabled on this machine (by another service)".into(),
        );
    }

    // Sessions and equipment reached over the adapter.
    if !pf.already_running {
        let nets = facts.addresses_on(&iface);
        let on_iface = |ip: &Ipv4Addr| nets.iter().any(|n| n.addr() == *ip);
        let inbound_ssh = facts
            .established
            .iter()
            .filter(|c| on_iface(&c.local.0) && c.local.1 == 22)
            .count();
        let others_tcp = facts
            .established
            .iter()
            .filter(|c| on_iface(&c.local.0) && c.local.1 != 22)
            .count();
        if inbound_ssh > 0 {
            warn(&mut f, "sessions", format!("{inbound_ssh} SSH session(s) into this machine arrive over {iface} and will drop"));
        }
        if others_tcp > 0 {
            info(
                &mut f,
                "sessions",
                format!("{others_tcp} other TCP connection(s) over {iface} will drop"),
            );
        }
        let reached: Vec<&Equipment> = ctx
            .equipment
            .iter()
            .filter(|e| nets.iter().any(|n| n.contains(&e.ip)))
            .collect();
        if !reached.is_empty() {
            warn(
                &mut f,
                "equipment",
                format!(
                    "{} registered device(s) are reached over {iface} and will lose their connection to this machine: {}. Make sure no robot is moving or depending on this link; LabLink does not assume a robot behaves safely when its network drops.",
                    reached.len(),
                    reached.iter().map(|e| format!("{} ({})", e.name, e.ip)).collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }

    // Subnet.
    let reserved = subnet::reserved(facts, ctx.sites, Some(&iface));
    match req.subnet {
        Some(net) => {
            if let Err(e) = subnet::validate(&net) {
                block(&mut f, "subnet", e);
            } else {
                let c = subnet::conflicts(&net, &reserved);
                if c.is_empty() {
                    pf.subnet = Some(net);
                } else {
                    block(
                        &mut f,
                        "subnet",
                        format!(
                            "{net} overlaps {}",
                            c.iter()
                                .map(|r| format!("{} ({})", r.net, r.why))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    );
                }
            }
        }
        None => match subnet::choose(&reserved) {
            Some(net) => pf.subnet = Some(net),
            None => block(
                &mut f,
                "subnet",
                "no free 10.77-10.79.x.0/24 subnet; choose one with --subnet".into(),
            ),
        },
    }
    pf.gateway = pf.subnet.as_ref().map(subnet::gateway);
    f.sort_by_key(|x| x.level);
    pf.findings = f;
    pf
}

fn missing(w: &WifiAdapter) -> String {
    let mut m = Vec::new();
    if !w.ap {
        m.push("no access-point mode");
    }
    if !w.wpa2 {
        m.push("no WPA2");
    }
    if !w.ccmp {
        m.push("no CCMP");
    }
    if m.is_empty() {
        "capable".into()
    } else {
        m.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{gather, script_host, Route, TcpConn};
    use crate::system::FakeSystem;

    fn facts() -> HostFacts {
        let f = FakeSystem::new();
        script_host(&f);
        gather(&f)
    }

    fn req() -> Request {
        Request {
            interface: None,
            ssid: "LabLink-TEST".into(),
            subnet: None,
            security: Security::Wpa2,
            allow_internet_sharing: false,
        }
    }

    fn ctx<'a>(eq: &'a [Equipment]) -> Context<'a> {
        Context {
            sites: &[],
            equipment: eq,
            own_profile: None,
        }
    }

    fn codes(pf: &Preflight, level: Level) -> Vec<&'static str> {
        pf.findings
            .iter()
            .filter(|f| f.level == level)
            .map(|f| f.code)
            .collect()
    }

    #[test]
    fn single_adapter_host_warns_about_disconnect_uplink_and_forwarding() {
        let pf = check(&facts(), &req(), &ctx(&[]));
        assert!(!pf.blocked(), "{:#?}", pf.findings);
        assert_eq!(pf.interface.as_deref(), Some("wlan0"));
        assert_eq!(pf.subnet, Some("10.77.0.0/24".parse().unwrap()));
        assert_eq!(pf.gateway, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(pf.would_disconnect.as_ref().unwrap().name, "Home WiFi");
        let w = codes(&pf, Level::Warn);
        assert!(
            w.contains(&"disconnect") && w.contains(&"uplink") && w.contains(&"forwarding"),
            "{w:?}"
        );
        assert!(pf.needs_confirmation());
        let fw = pf
            .findings
            .iter()
            .find(|f| f.code == "forwarding" && f.level == Level::Warn)
            .unwrap();
        assert!(fw.message.contains("tailscale0") && fw.message.contains("docker0"));
    }

    #[test]
    fn own_ssh_session_over_the_adapter_is_refused_without_override() {
        let mut h = facts();
        h.ssh_session = crate::host::parse_ssh_connection("192.168.8.20 51000 192.168.8.168 22");
        let pf = check(&h, &req(), &ctx(&[]));
        let b = pf.blockers();
        assert!(b
            .iter()
            .any(|f| f.code == "remote-session" && f.override_flag.is_none()));
        // An address LabLink cannot place is not assumed safe.
        h.ssh_session = crate::host::parse_ssh_connection("10.1.1.2 51000 10.1.1.1 22");
        assert!(check(&h, &req(), &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "remote-session"));
        // A session over another interface is fine.
        h.addresses.push(crate::host::Address {
            interface: "eno1".into(),
            net: "10.1.1.1/24".parse().unwrap(),
        });
        assert!(!check(&h, &req(), &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "remote-session"));
    }

    #[test]
    fn another_uplink_blocks_unless_sharing_is_explicit() {
        let mut h = facts();
        h.routes.push(Route {
            dest: "0.0.0.0/0".parse().unwrap(),
            device: "eno1".into(),
            via: Some(Ipv4Addr::new(10, 1, 1, 254)),
            table: "main".into(),
        });
        let pf = check(&h, &req(), &ctx(&[]));
        let b = pf.blockers();
        assert_eq!(b.len(), 1, "{b:#?}");
        assert_eq!(b[0].override_flag, Some("--allow-internet-sharing"));
        assert!(
            !codes(&pf, Level::Warn).contains(&"uplink"),
            "another uplink remains"
        );
        let mut r = req();
        r.allow_internet_sharing = true;
        let pf = check(&h, &r, &ctx(&[]));
        assert!(!pf.blocked());
        assert!(codes(&pf, Level::Warn).contains(&"internet-sharing"));
    }

    #[test]
    fn equipment_and_inbound_ssh_over_the_adapter_are_named() {
        let mut h = facts();
        h.established.push(TcpConn {
            local: (Ipv4Addr::new(192, 168, 8, 168), 22),
            remote: (Ipv4Addr::new(192, 168, 8, 20), 50000),
        });
        let eq = vec![
            Equipment {
                name: "orin".into(),
                ip: Ipv4Addr::new(192, 168, 8, 31),
            },
            Equipment {
                name: "far".into(),
                ip: Ipv4Addr::new(10, 20, 30, 4),
            },
        ];
        let pf = check(&h, &req(), &ctx(&eq));
        let e = pf.findings.iter().find(|f| f.code == "equipment").unwrap();
        assert!(e.message.contains("orin (192.168.8.31)") && !e.message.contains("far"));
        assert!(e.message.contains("robot"));
        assert!(pf
            .findings
            .iter()
            .any(|f| f.code == "sessions" && f.level == Level::Warn));
    }

    #[test]
    fn insecure_or_unverifiable_configurations() {
        let mut h = facts();
        h.wifi[0].ap = false;
        let pf = check(&h, &req(), &ctx(&[]));
        assert!(pf
            .blockers()
            .iter()
            .any(|f| f.code == "adapter" && f.message.contains("no access-point mode")));

        let mut r = req();
        r.security = Security::Wpa3;
        let pf = check(&facts(), &r, &ctx(&[]));
        assert!(
            codes(&pf, Level::Warn).contains(&"security"),
            "unverifiable WPA3 is a warning"
        );
        let mut h = facts();
        h.wifi[0].sae = Some(false);
        assert!(check(&h, &r, &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "security"));

        let mut r = req();
        r.ssid = "bad\nssid".into();
        assert!(check(&facts(), &r, &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "ssid"));
    }

    #[test]
    fn subnet_conflicts_with_sites_are_blockers() {
        let sites = vec![("lab".to_string(), "10.77.0.0/24".parse().unwrap())];
        let mut r = req();
        r.subnet = Some("10.77.0.0/24".parse().unwrap());
        let c = Context {
            sites: &sites,
            equipment: &[],
            own_profile: None,
        };
        let pf = check(&facts(), &r, &c);
        assert!(pf
            .blockers()
            .iter()
            .any(|f| f.code == "subnet" && f.message.contains("site 'lab'")));
        r.subnet = None;
        assert_eq!(
            check(&facts(), &r, &c).subnet,
            Some("10.77.1.0/24".parse().unwrap())
        );
    }

    #[test]
    fn no_networkmanager_or_no_permission() {
        let mut h = facts();
        h.nm = None;
        assert!(check(&h, &req(), &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "networkmanager"));
        let mut h = facts();
        h.nm.as_mut().unwrap().permissions.insert(
            "org.freedesktop.NetworkManager.network-control".into(),
            "auth".into(),
        );
        assert!(check(&h, &req(), &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "permission"));
        let mut h = facts();
        h.os = Os::Macos;
        assert!(check(&h, &req(), &ctx(&[]))
            .blockers()
            .iter()
            .any(|f| f.code == "unsupported-os"));
    }

    #[test]
    fn a_free_second_adapter_is_preferred_and_nothing_drops() {
        let mut h = facts();
        let mut w2 = h.wifi[0].clone();
        w2.interface = "wlan1".into();
        w2.connection.clear();
        h.wifi.push(w2);
        let pf = check(&h, &req(), &ctx(&[]));
        assert_eq!(pf.interface.as_deref(), Some("wlan1"));
        assert!(pf.would_disconnect.is_none());
        assert!(!codes(&pf, Level::Warn).contains(&"disconnect"));
        assert!(!codes(&pf, Level::Warn).contains(&"uplink"));
    }

    #[test]
    fn already_running_is_recognized() {
        let h = facts();
        let own = h.active_on("wlan0").unwrap().uuid.clone();
        let c = Context {
            sites: &[],
            equipment: &[],
            own_profile: Some(&own),
        };
        let pf = check(&h, &req(), &c);
        assert!(pf.already_running && pf.would_disconnect.is_none());
    }
}
