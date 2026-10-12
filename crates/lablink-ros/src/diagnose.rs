//! `lablink ros dds-check`: twelve checks over one or two inspections, and
//! the connectivity level they prove. Levels:
//!
//! 1. IP reachability (active ping both ways),
//! 2. compatible configuration (no failing configuration check),
//! 3. discovery (each side's graph query saw the other's),
//! 4. data exchange (the active pub/sub probe delivered messages).
//!
//! Level 4 is only ever reported from the active probe: a graph listing
//! proves discovery, not that data flows.

use crate::active::{ActiveReport, Probe};
use crate::dds::DdsConfig;
use crate::inspect::{shared_path, Inspection, NetPath, TopicQos};
use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
    NotTested,
    Unavailable,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
            Verdict::NotTested => "NOT TESTED",
            Verdict::Unavailable => "UNAVAILABLE",
        }
    }

    /// Worst of two, where Fail > Warn > Pass and "not run" ranks lowest
    /// unless nothing ran.
    fn worst(self, o: Verdict) -> Verdict {
        fn rank(v: Verdict) -> u8 {
            match v {
                Verdict::Fail => 4,
                Verdict::Warn => 3,
                Verdict::Pass => 2,
                Verdict::Unavailable => 1,
                Verdict::NotTested => 0,
            }
        }
        if rank(o) > rank(self) {
            o
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub verdict: Verdict,
    pub summary: String,
    pub evidence: Vec<String>,
    /// Devices (and addresses) the check looked at.
    pub endpoints: Vec<String>,
    pub interfaces: Vec<String>,
    pub domain: Option<u32>,
    pub method: String,
    pub timeout_ms: Option<u64>,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LevelStep {
    pub level: u8,
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub device: String,
    pub peer: Option<String>,
    pub active: bool,
    pub path: Option<NetPath>,
    pub checks: Vec<Check>,
    /// Highest level proven (0: none), only with a peer.
    pub level: Option<u8>,
    pub levels: Vec<LevelStep>,
}

impl Report {
    /// Remove DDS Security secrets from every text field (see
    /// [`crate::redact`]); evidence quotes device settings.
    pub fn redact_secrets(&mut self) {
        use crate::redact::redact_secrets as r;
        let all = |v: &mut Vec<String>| v.iter_mut().for_each(|s| *s = r(s));
        for c in &mut self.checks {
            c.summary = r(&c.summary);
            all(&mut c.evidence);
            all(&mut c.endpoints);
            all(&mut c.interfaces);
            c.method = r(&c.method);
            c.hint = c.hint.as_deref().map(r);
        }
        for l in &mut self.levels {
            l.detail = r(&l.detail);
        }
    }

    pub fn worst(&self) -> Verdict {
        self.checks
            .iter()
            .fold(Verdict::NotTested, |w, c| w.worst(c.verdict))
    }
}

/// One side of the check: its inspection and the address LabLink located it at.
pub struct Side<'a> {
    pub ins: &'a Inspection,
    pub ip: Option<Ipv4Addr>,
}

pub struct Input<'a> {
    pub a: Side<'a>,
    pub b: Option<Side<'a>>,
    pub active: Option<&'a ActiveReport>,
    /// How long each remote command was allowed.
    pub timeout_ms: u64,
}

struct Ctx<'a> {
    a: &'a Inspection,
    b: Option<&'a Inspection>,
    a_ip: Option<Ipv4Addr>,
    b_ip: Option<Ipv4Addr>,
    path: Option<NetPath>,
    timeout_ms: u64,
}

impl Ctx<'_> {
    fn sides(&self) -> Vec<&Inspection> {
        std::iter::once(self.a).chain(self.b).collect()
    }
    fn endpoints(&self) -> Vec<String> {
        let f = |i: &Inspection, ip: Option<Ipv4Addr>| match ip {
            Some(ip) => format!("{} ({ip})", i.device),
            None => i.device.clone(),
        };
        let mut v = vec![f(self.a, self.a_ip)];
        if let Some(b) = self.b {
            v.push(f(b, self.b_ip));
        }
        v
    }
    /// The interface `side` reaches the other device through.
    fn path_iface(&self, side: &Inspection) -> Option<String> {
        let p = self.path.as_ref()?;
        Some(if std::ptr::eq(side, self.a) {
            p.a_interface.clone()
        } else {
            p.b_interface.clone()
        })
    }
    fn check(&self, id: &'static str, title: &'static str, method: &str) -> Check {
        Check {
            id,
            title,
            verdict: Verdict::Pass,
            summary: String::new(),
            evidence: vec![],
            endpoints: self.endpoints(),
            interfaces: vec![],
            domain: Some(self.a.effective_domain()),
            method: method.into(),
            timeout_ms: Some(self.timeout_ms),
            hint: None,
        }
    }
}

/// Collects findings: the worst verdict wins and its message leads.
struct Findings {
    verdict: Verdict,
    lead: Option<String>,
    evidence: Vec<String>,
    hint: Option<String>,
}

impl Findings {
    fn new() -> Self {
        Findings {
            verdict: Verdict::NotTested,
            lead: None,
            evidence: vec![],
            hint: None,
        }
    }
    fn add(&mut self, v: Verdict, msg: impl Into<String>) {
        let msg = msg.into();
        if v.worst(self.verdict) != self.verdict || self.lead.is_none() {
            self.lead = Some(msg.clone());
        }
        self.verdict = self.verdict.worst(v);
        self.evidence.push(format!("{}: {msg}", v.label()));
    }
    fn hint(&mut self, h: impl Into<String>) {
        self.hint.get_or_insert(h.into());
    }
    fn into(self, mut c: Check, pass_msg: &str) -> Check {
        c.verdict = self.verdict;
        c.summary = match self.verdict {
            Verdict::Pass => self
                .lead
                .filter(|_| self.evidence.len() == 1)
                .unwrap_or_else(|| pass_msg.into()),
            _ => self.lead.unwrap_or_else(|| pass_msg.into()),
        };
        c.evidence = self.evidence;
        c.hint = self.hint;
        c
    }
}

pub fn diagnose(input: &Input) -> Report {
    let path = input
        .b
        .as_ref()
        .and_then(|b| shared_path(input.a.ins, b.ins, b.ip));
    let cx = Ctx {
        a: input.a.ins,
        b: input.b.as_ref().map(|b| b.ins),
        a_ip: input.a.ip,
        b_ip: input.b.as_ref().and_then(|b| b.ip),
        path,
        timeout_ms: input.timeout_ms,
    };
    let checks = vec![
        domain(&cx),
        binding(&cx),
        multicast(&cx, input.active),
        isolation(&cx, input.active),
        discovery(&cx),
        firewall(&cx),
        routing(&cx),
        rmw(&cx),
        localhost_only(&cx),
        peers(&cx),
        qos(&cx),
        cached_graph(&cx),
    ];
    let (level, levels) = match cx.b {
        Some(b) => {
            // Level 2 is about configuration: judge multicast without the
            // active packet test (which levels 1 and 4 already cover).
            let mut cfg = checks.clone();
            if input.active.is_some() {
                if let Some(m) = cfg.iter_mut().find(|c| c.id == "multicast") {
                    *m = multicast(&cx, None);
                }
            }
            let (l, s) = levels(&cx, b, &cfg, input.active);
            (Some(l), s)
        }
        None => (None, vec![]),
    };
    let mut r = Report {
        device: cx.a.device.clone(),
        peer: cx.b.map(|b| b.device.clone()),
        active: input.active.is_some(),
        path: cx.path.clone(),
        checks,
        level,
        levels,
    };
    r.redact_secrets();
    r
}

fn src(i: &Inspection) -> String {
    format!("{} ({})", i.device, i.effective_source.label())
}

fn domain(cx: &Ctx) -> Check {
    let c = cx.check(
        "domain",
        "ROS domain",
        "ROS_DOMAIN_ID of running nodes (/proc/<pid>/environ), shell startup files and the session",
    );
    let mut f = Findings::new();
    for i in cx.sides() {
        match i.effective.domain() {
            Err(e) => f.add(
                Verdict::Fail,
                format!(
                    "{}: ROS_DOMAIN_ID is invalid ({e}); nodes refuse to start",
                    i.device
                ),
            ),
            Ok(d) => f.add(
                Verdict::Pass,
                format!("{} uses domain {} [{}]", i.device, d.unwrap_or(0), src(i)),
            ),
        }
        if !i.processes_agree {
            f.add(
                Verdict::Warn,
                format!(
                    "{}: the running ROS processes do not all use the same discovery settings",
                    i.device
                ),
            );
        }
        if i.effective_source == crate::env::EnvSource::RunningNodes {
            let shell = i.shell.env();
            let (sd, nd) = (
                shell.domain().ok().flatten().unwrap_or(0),
                i.effective_domain(),
            );
            if (!i.shell.lines.is_empty() || !i.shell.sourced.is_empty()) && sd != nd {
                f.add(Verdict::Warn, format!("{}: nodes run on domain {nd}, but a new terminal gets domain {sd} from its startup files", i.device));
                f.hint("Commands typed in a new terminal will not see these nodes until ROS_DOMAIN_ID matches.");
            }
        }
    }
    if let Some(b) = cx.b {
        let (da, db) = (cx.a.effective_domain(), b.effective_domain());
        if da != db {
            f.add(
                Verdict::Fail,
                format!(
                    "{} is on domain {da}, {} on domain {db}: they will never discover each other",
                    cx.a.device, b.device
                ),
            );
            f.hint("Set the same ROS_DOMAIN_ID on both (LabLink does not change it for you).");
        }
    }
    f.into(c, "domain settings agree")
}

fn configs(i: &Inspection) -> Vec<&DdsConfig> {
    i.dds.iter().collect()
}

fn binding(cx: &Ctx) -> Check {
    let mut c = cx.check("interface-binding", "DDS interface binding", "interfaces named in the DDS XML (Cyclone NetworkInterface / Fast DDS interfaceWhiteList) against ip link / ip addr");
    let mut f = Findings::new();
    let mut ifaces = Vec::new();
    for i in cx.sides() {
        let to_peer = cx.path_iface(i);
        let mut any = false;
        for cfg in configs(i) {
            if let Some(p) = &cfg.problem {
                f.add(Verdict::Fail, format!("{}: {} ({p})", i.device, cfg.source));
                f.hint("A DDS configuration file that cannot be read stops the middleware from starting with it.");
                continue;
            }
            for sel in &cfg.interfaces {
                any = true;
                if let Some(n) = &sel.name {
                    ifaces.push(format!("{}:{n}", i.device));
                    match i.link(n) {
                        None => {
                            let have: Vec<&str> = i
                                .links
                                .iter()
                                .map(|l| l.name.as_str())
                                .filter(|n| *n != "lo")
                                .collect();
                            f.add(Verdict::Fail, format!("{}: {} binds DDS to '{n}', which does not exist (interfaces: {})", i.device, cfg.source, have.join(", ")));
                            f.hint("Edit the DDS XML to name the interface the device actually uses (LabLink does not rewrite it).");
                        }
                        Some(l) if !l.up => f.add(
                            Verdict::Fail,
                            format!(
                                "{}: {} binds DDS to '{n}', which is down",
                                i.device, cfg.source
                            ),
                        ),
                        Some(_) => {
                            match &to_peer {
                                Some(p) if p != n => {
                                    f.add(Verdict::Fail, format!("{}: {} binds DDS to '{n}', but the peer is reached through '{p}'", i.device, cfg.source));
                                    f.hint("Bind DDS to the interface on the shared network, or to both.");
                                }
                                _ => f.add(
                                    Verdict::Pass,
                                    format!("{}: DDS bound to '{n}' (up)", i.device),
                                ),
                            }
                        }
                    }
                }
                if let Some(a) = &sel.address {
                    let held = i
                        .addresses
                        .iter()
                        .any(|x| x.net.addr().to_string() == *a || x.net.to_string() == *a);
                    if !held {
                        f.add(
                            Verdict::Fail,
                            format!(
                                "{}: {} binds DDS to address {a}, which this device does not hold",
                                i.device, cfg.source
                            ),
                        );
                    } else {
                        f.add(
                            Verdict::Pass,
                            format!("{}: DDS bound to address {a}", i.device),
                        );
                    }
                }
            }
        }
        if !any {
            f.add(
                Verdict::Pass,
                format!(
                    "{}: no interface restriction (DDS chooses automatically)",
                    i.device
                ),
            );
            if let (Some(p), Some(m)) = (&to_peer, &i.multicast_route) {
                if p != m && i.effective_rmw().contains("cyclone") {
                    f.add(Verdict::Warn, format!("{}: Cyclone DDS picks one interface by default and multicast leaves through '{m}', but the peer is on '{p}'", i.device));
                    f.hint("Name the shared-network interface in the Cyclone XML (NetworkInterface name=...).");
                }
            }
        }
    }
    c.interfaces = ifaces;
    c = f.into(c, "DDS interface binding matches the network");
    c
}

fn multicast(cx: &Ctx, active: Option<&ActiveReport>) -> Check {
    let mut c = cx.check("multicast", "Multicast", "MULTICAST flag (ip link), route for 239.255.0.1 (ip route get), AllowMulticast in the DDS XML; with --active: ros2 multicast send/receive");
    let mut f = Findings::new();
    for i in cx.sides() {
        let iface = cx.path_iface(i).or_else(|| {
            i.routes
                .iter()
                .find(|r| r.dest == "default")
                .and_then(|r| r.device.clone())
        });
        if let Some(n) = &iface {
            c.interfaces.push(format!("{}:{n}", i.device));
            match i.link(n) {
                Some(l) if !l.multicast => {
                    f.add(
                        Verdict::Fail,
                        format!("{}: interface '{n}' has multicast disabled", i.device),
                    );
                    f.hint("Enable it (ip link set <if> multicast on) or configure unicast peers.");
                }
                Some(_) => f.add(
                    Verdict::Pass,
                    format!("{}: '{n}' supports multicast", i.device),
                ),
                None => {}
            }
        }
        match (&i.multicast_route, &iface) {
            (None, _) if !i.ip_tool => f.add(Verdict::Unavailable, format!("{}: multicast route unknown (no ip command)", i.device)),
            (None, _) => f.add(Verdict::Warn, format!("{}: no route for the DDS discovery group 239.255.0.1", i.device)),
            (Some(m), Some(n)) if m != n => f.add(
                Verdict::Warn,
                format!("{}: discovery multicast leaves through '{m}', not '{n}' (the network the peer is on)", i.device),
            ),
            _ => {}
        }
        for cfg in configs(i) {
            if cfg.multicast_disabled() {
                if cfg.peers.is_empty() && i.effective.static_peers().is_empty() {
                    f.add(Verdict::Fail, format!("{}: {} disables multicast and lists no peers, so nothing is discovered", i.device, cfg.source));
                } else {
                    f.add(
                        Verdict::Warn,
                        format!(
                            "{}: {} disables multicast; discovery relies on its peer list",
                            i.device, cfg.source
                        ),
                    );
                }
            }
        }
    }
    if let Some(a) = active {
        for p in [&a.multicast_ab, &a.multicast_ba] {
            f.add(p.verdict, format!("{} -> {}: {}", p.from, p.to, p.summary));
        }
        c.timeout_ms = Some(a.multicast_ab.timeout_ms);
        c.method.push_str(" [active]");
    }
    c = f.into(c, "multicast is available");
    c
}

fn isolation(cx: &Ctx, active: Option<&ActiveReport>) -> Check {
    let mut c = cx.check(
        "client-isolation",
        "Client isolation",
        "active only: ping and multicast in both directions on the shared network",
    );
    let Some(b) = cx.b else {
        c.verdict = Verdict::NotTested;
        c.summary = "needs --peer and --active".into();
        return c;
    };
    let Some(a) = active else {
        c.verdict = Verdict::NotTested;
        c.summary = format!("not tested: run with --active to check whether the network lets {} and {} talk directly", cx.a.device, b.device);
        c.hint = Some("Access points with client (AP) isolation pass traffic to the router but not between clients.".into());
        return c;
    };
    let pings = [&a.ping_ab, &a.ping_ba];
    let mcast = [&a.multicast_ab, &a.multicast_ba];
    let mut f = Findings::new();
    let ok = |p: &&Probe| p.verdict == Verdict::Pass;
    let ran = |p: &&Probe| matches!(p.verdict, Verdict::Pass | Verdict::Fail | Verdict::Warn);
    if !pings.iter().any(ran) {
        f.add(Verdict::Unavailable, "ping could not run");
    } else if pings.iter().all(ok) && mcast.iter().all(ok) {
        f.add(
            Verdict::Pass,
            "unicast and multicast pass in both directions: no client isolation",
        );
    } else if pings.iter().all(ok) {
        f.add(Verdict::Warn, "unicast passes but multicast does not: the network filters multicast (AP multicast isolation or IGMP snooping)");
        f.hint("Disable multicast filtering on the access point, or configure unicast discovery (ROS_STATIC_PEERS on Jazzy, DDS peers on Humble).");
    } else if cx.path.is_some() {
        f.add(
            Verdict::Fail,
            "ping fails between devices on the same subnet: client isolation or a host firewall",
        );
        f.hint("Disable client/AP isolation on the access point (a LabLink Field Network has it off) and check host firewalls.");
    } else {
        f.add(Verdict::Fail, "ping fails and the devices share no subnet");
    }
    for p in pings.iter().chain(mcast.iter()) {
        f.evidence.push(format!(
            "{} {} -> {}: {} ({})",
            p.name,
            p.from,
            p.to,
            p.verdict.label(),
            p.summary
        ));
    }
    c.timeout_ms = Some(a.ping_ab.timeout_ms);
    c = f.into(c, "no client isolation");
    c
}

fn discovery(cx: &Ctx) -> Check {
    let mut c = cx.check("discovery-restrictions", "Discovery restrictions", "ROS_AUTOMATIC_DISCOVERY_RANGE, ROS_DISCOVERY_SERVER, FASTDDS_BUILTIN_TRANSPORTS, Fast DDS discoveryProtocol");
    let mut f = Findings::new();
    let peer = cx.b.is_some();
    let sev = if peer { Verdict::Fail } else { Verdict::Warn };
    for i in cx.sides() {
        let humble = i.distro.as_deref() == Some("humble");
        if let Some(r) = i.effective.discovery_range() {
            if humble {
                f.add(Verdict::Warn, format!("{}: ROS_AUTOMATIC_DISCOVERY_RANGE={r} is set, but Humble ignores it (it exists from Iron on)", i.device));
            } else {
                match r {
                    "LOCALHOST" | "OFF" => f.add(
                        sev,
                        format!(
                            "{}: ROS_AUTOMATIC_DISCOVERY_RANGE={r} keeps discovery on this machine",
                            i.device
                        ),
                    ),
                    "SUBNET" | "SYSTEM_DEFAULT" => {
                        f.add(Verdict::Pass, format!("{}: discovery range {r}", i.device))
                    }
                    other => f.add(
                        Verdict::Warn,
                        format!(
                            "{}: unknown ROS_AUTOMATIC_DISCOVERY_RANGE '{other}'",
                            i.device
                        ),
                    ),
                }
            }
        } else if !humble && i.distro.is_some() {
            f.add(
                Verdict::Pass,
                format!("{}: default discovery range (SUBNET)", i.device),
            );
        }
        if let Some(s) = i.effective.get("ROS_DISCOVERY_SERVER") {
            f.add(Verdict::Warn, format!("{}: Fast DDS discovery server mode (ROS_DISCOVERY_SERVER={s}); only participants using the same server see each other", i.device));
        }
        if let Some(t) = i.effective.get("FASTDDS_BUILTIN_TRANSPORTS") {
            if t.eq_ignore_ascii_case("SHM") {
                f.add(sev, format!("{}: FASTDDS_BUILTIN_TRANSPORTS=SHM limits Fast DDS to shared memory on this machine", i.device));
            }
        }
        for cfg in configs(i) {
            if let Some(p) = &cfg.discovery_protocol {
                if !p.eq_ignore_ascii_case("SIMPLE") {
                    f.add(
                        Verdict::Warn,
                        format!("{}: {} sets discoveryProtocol {p}", i.device, cfg.source),
                    );
                }
            }
        }
    }
    if let Some(b) = cx.b {
        let (sa, sb) = (
            cx.a.effective.get("ROS_DISCOVERY_SERVER"),
            b.effective.get("ROS_DISCOVERY_SERVER"),
        );
        if sa.is_some() != sb.is_some() {
            f.add(Verdict::Fail, "one device uses a discovery server and the other simple discovery: they do not see each other");
        }
    }
    if f.evidence.is_empty() {
        f.add(Verdict::Pass, "no discovery restrictions");
    }
    c = f.into(c, "no discovery restrictions");
    c
}

fn firewall(cx: &Ctx) -> Check {
    let d = cx.a.effective_domain();
    let lo = 7400 + 250 * d;
    let mut c = cx.check("firewall", "Host firewall", "systemctl is-active ufw/firewalld/nftables and /etc/ufw/ufw.conf (rules need root and are not read)");
    let mut f = Findings::new();
    for i in cx.sides() {
        let active = i.firewall.active();
        if !i.firewall.known() {
            f.add(
                Verdict::Unavailable,
                format!("{}: firewall state unknown (no systemd?)", i.device),
            );
        } else if active.is_empty() {
            f.add(
                Verdict::Pass,
                format!("{}: no firewall service active", i.device),
            );
        } else {
            f.add(
                Verdict::Warn,
                format!(
                    "{}: {} active; its rules cannot be read without root",
                    i.device,
                    active.join(", ")
                ),
            );
            f.hint(format!("DDS on domain {d} uses UDP {lo}-{} (and multicast 239.255.0.1); LabLink never changes firewall rules.", lo + 249));
        }
    }
    c = f.into(c, "no host firewall in the way");
    c
}

fn routing(cx: &Ctx) -> Check {
    let mut c = cx.check(
        "routing",
        "Routing and subnet",
        "ip -4 addr / ip route on both devices",
    );
    let missing: Vec<&str> = cx
        .sides()
        .iter()
        .filter(|i| !i.ip_tool)
        .map(|i| i.device.as_str())
        .collect();
    if !missing.is_empty() {
        c.verdict = Verdict::Unavailable;
        c.summary = format!(
            "unavailable: the ip command is not installed on {}",
            missing.join(", ")
        );
        return c;
    }
    let mut f = Findings::new();
    for i in cx.sides() {
        let nets: Vec<_> = i
            .addresses
            .iter()
            .filter(|a| !a.net.addr().is_loopback())
            .collect();
        for (k, x) in nets.iter().enumerate() {
            for y in &nets[k + 1..] {
                if x.interface != y.interface
                    && (x.net.contains(&y.net.network()) || y.net.contains(&x.net.network()))
                {
                    f.add(Verdict::Warn, format!("{}: '{}' ({}) and '{}' ({}) overlap; traffic may leave through the wrong one", i.device, x.interface, x.net, y.interface, y.net));
                }
            }
        }
    }
    match (cx.b, &cx.path) {
        (None, _) => {
            if f.evidence.is_empty() {
                c.verdict = Verdict::NotTested;
                c.summary = "needs --peer".into();
                return c;
            }
        }
        (Some(b), Some(p)) => {
            c.interfaces = vec![
                format!("{}:{}", cx.a.device, p.a_interface),
                format!("{}:{}", b.device, p.b_interface),
            ];
            f.add(
                Verdict::Pass,
                format!(
                    "same subnet {}: {} {} ({}) and {} {} ({})",
                    p.net, cx.a.device, p.a_addr, p.a_interface, b.device, p.b_addr, p.b_interface
                ),
            );
        }
        (Some(b), None) => {
            if cx.a.routes.iter().any(|r| r.dest == "default") {
                f.add(Verdict::Warn, format!("{} and {} share no subnet: traffic is routed, and multicast discovery does not cross routers", cx.a.device, b.device));
                f.hint("Put both on one network (for example a LabLink Field Network) or configure unicast peers.");
            } else {
                f.add(
                    Verdict::Fail,
                    format!(
                        "{} and {} share no subnet and {} has no default route",
                        cx.a.device, b.device, cx.a.device
                    ),
                );
            }
        }
    }
    c = f.into(c, "routing is direct");
    c
}

fn rmw(cx: &Ctx) -> Check {
    let mut c = cx.check("rmw", "RMW implementation", "RMW_IMPLEMENTATION (or the distribution default) against /opt/ros/<distro>/lib/librmw_*_cpp.so");
    let mut f = Findings::new();
    for i in cx.sides() {
        let r = i.effective_rmw();
        let installed = i
            .distro
            .as_ref()
            .and_then(|d| i.distros.iter().find(|x| &x.name == d));
        match installed {
            Some(d) if !d.rmws.is_empty() && !d.rmws.contains(&r) => {
                f.add(
                    Verdict::Fail,
                    format!(
                        "{}: {r} is selected but not installed for {} (installed: {})",
                        i.device,
                        d.name,
                        d.rmws.join(", ")
                    ),
                );
            }
            _ => f.add(
                Verdict::Pass,
                format!(
                    "{}: {r} ({})",
                    i.device,
                    i.distro.as_deref().unwrap_or("distribution unknown")
                ),
            ),
        }
    }
    if let Some(b) = cx.b {
        let (ra, rb) = (cx.a.effective_rmw(), b.effective_rmw());
        if ra != rb {
            f.add(Verdict::Warn, format!("{} uses {ra} and {} uses {rb}: communication across RMW vendors is not supported by ROS 2 and often fails", cx.a.device, b.device));
            f.hint("Use the same RMW_IMPLEMENTATION on every machine.");
        }
        if let (Some(da), Some(db)) = (&cx.a.distro, &b.distro) {
            if da != db {
                f.add(
                    Verdict::Warn,
                    format!(
                        "{} runs {da} and {} runs {db}: mixing distributions is not supported",
                        cx.a.device, b.device
                    ),
                );
            }
        }
    }
    c = f.into(c, "RMW implementations match");
    c
}

fn localhost_only(cx: &Ctx) -> Check {
    let mut c = cx.check("localhost-only", "Localhost only", "ROS_LOCALHOST_ONLY");
    let mut f = Findings::new();
    let sev = if cx.b.is_some() {
        Verdict::Fail
    } else {
        Verdict::Warn
    };
    for i in cx.sides() {
        if i.effective.localhost_only() {
            f.add(
                sev,
                format!(
                    "{}: ROS_LOCALHOST_ONLY=1 keeps all ROS traffic on this machine",
                    i.device
                ),
            );
            if i.distro.as_deref() == Some("jazzy") {
                f.hint(
                    "On Jazzy ROS_LOCALHOST_ONLY is deprecated; use ROS_AUTOMATIC_DISCOVERY_RANGE.",
                );
            }
        } else {
            f.add(
                Verdict::Pass,
                format!("{}: not limited to localhost", i.device),
            );
        }
    }
    c = f.into(c, "not limited to localhost");
    c
}

fn peers(cx: &Ctx) -> Check {
    let mut c = cx.check("peers", "Static peers", "ROS_STATIC_PEERS and the DDS XML peer lists, against the other device's addresses and hostname");
    let mut f = Findings::new();
    let pairs: Vec<(&Inspection, Option<&Inspection>)> = match cx.b {
        Some(b) => vec![(cx.a, Some(b)), (b, Some(cx.a))],
        None => vec![(cx.a, None)],
    };
    for (i, other) in pairs {
        let mut list: Vec<String> = i.effective.static_peers();
        let mut mcast_off = false;
        for cfg in configs(i) {
            list.extend(cfg.peers.iter().cloned());
            mcast_off |= cfg.multicast_disabled();
        }
        if list.is_empty() {
            f.add(
                Verdict::Pass,
                format!("{}: no static peers (multicast discovery)", i.device),
            );
            continue;
        }
        let Some(o) = other else {
            f.add(
                Verdict::NotTested,
                format!(
                    "{}: peers {} (compare with --peer)",
                    i.device,
                    list.join(", ")
                ),
            );
            continue;
        };
        let names: Vec<String> = o
            .addresses
            .iter()
            .map(|a| a.net.addr().to_string())
            .chain([
                o.host.hostname.clone(),
                format!("{}.local", o.host.hostname),
            ])
            .filter(|s| !s.is_empty())
            .collect();
        let hit = list.iter().any(|p| {
            let host = p.split(':').next().unwrap_or(p);
            names.iter().any(|n| n.eq_ignore_ascii_case(host))
        });
        if hit {
            f.add(
                Verdict::Pass,
                format!("{}: its peer list includes {}", i.device, o.device),
            );
        } else {
            let v = if mcast_off {
                Verdict::Fail
            } else {
                Verdict::Warn
            };
            f.add(
                v,
                format!(
                    "{}: peers {} do not include {} (addresses: {})",
                    i.device,
                    list.join(", "),
                    o.device,
                    names.join(", ")
                ),
            );
            f.hint("A static peer is an address, and addresses change: a stale entry is a common cause after moving networks.");
        }
    }
    c = f.into(c, "static peers are consistent");
    c
}

fn qos_conflicts(q: &TopicQos) -> Vec<String> {
    let pubs: Vec<_> = q
        .endpoints
        .iter()
        .filter(|e| e.kind.eq_ignore_ascii_case("PUBLISHER"))
        .collect();
    let subs: Vec<_> = q
        .endpoints
        .iter()
        .filter(|e| e.kind.to_ascii_uppercase().starts_with("SUBSCRI"))
        .collect();
    let mut out = Vec::new();
    for p in &pubs {
        for s in &subs {
            if p.reliability == "BEST_EFFORT" && s.reliability == "RELIABLE" {
                out.push(format!(
                    "{}: publisher {} is BEST_EFFORT, subscriber {} wants RELIABLE",
                    q.topic, p.node, s.node
                ));
            }
            if p.durability == "VOLATILE" && s.durability == "TRANSIENT_LOCAL" {
                out.push(format!(
                    "{}: publisher {} is VOLATILE, subscriber {} wants TRANSIENT_LOCAL",
                    q.topic, p.node, s.node
                ));
            }
        }
    }
    out
}

fn qos(cx: &Ctx) -> Check {
    let mut c = cx.check(
        "qos",
        "QoS compatibility",
        "ros2 topic info -v (reliability, durability) for the topics given with --qos-topic",
    );
    let all: Vec<&TopicQos> = cx.sides().iter().flat_map(|i| i.qos.iter()).collect();
    if all.is_empty() {
        c.verdict = Verdict::NotTested;
        c.summary = "not tested: name topics with --qos-topic".into();
        return c;
    }
    let mut f = Findings::new();
    for q in all {
        if let Some(e) = &q.error {
            f.add(Verdict::Unavailable, format!("{}: {e}", q.topic));
            continue;
        }
        let bad = qos_conflicts(q);
        if bad.is_empty() {
            f.add(
                Verdict::Pass,
                format!("{}: {} endpoint(s), compatible", q.topic, q.endpoints.len()),
            );
        }
        for b in bad {
            f.add(Verdict::Fail, b);
        }
    }
    c = f.into(c, "QoS compatible");
    c
}

fn cached_graph(cx: &Ctx) -> Check {
    let mut c = cx.check(
        "cached-graph",
        "Cached graph (ros2 daemon)",
        "the running ros2 daemon's command line; LabLink never queries the daemon",
    );
    let mut f = Findings::new();
    for i in cx.sides() {
        if i.daemons.is_empty() {
            f.add(
                Verdict::Pass,
                format!("{}: no ros2 daemon running", i.device),
            );
        }
        for d in &i.daemons {
            let dd = d.domain.unwrap_or(0);
            let ed = i.effective_domain();
            let er = i.effective_rmw();
            if dd != ed || d.rmw.as_ref().is_some_and(|r| *r != er) {
                f.add(
                    Verdict::Warn,
                    format!("{}: a ros2 daemon (pid {}) caches domain {dd}{}, not the nodes' domain {ed} / {er}", i.device, d.pid, d.rmw.as_ref().map(|r| format!(" / {r}")).unwrap_or_default()),
                );
                f.hint("`ros2 node list` shows the daemon's stale view; `ros2 daemon stop` (run by you) clears it.");
            } else {
                f.add(
                    Verdict::Pass,
                    format!(
                        "{}: ros2 daemon (pid {}) matches the nodes' settings",
                        i.device, d.pid
                    ),
                );
            }
        }
    }
    c = f.into(c, "no stale cached graph");
    c
}

fn levels(
    cx: &Ctx,
    b: &Inspection,
    checks: &[Check],
    active: Option<&ActiveReport>,
) -> (u8, Vec<LevelStep>) {
    let a = cx.a;
    let mut steps = Vec::new();
    // L1
    steps.push(match active {
        Some(r) => {
            let v = r.ping_ab.verdict.worst(r.ping_ba.verdict);
            LevelStep {
                level: 1,
                name: "IP reachability",
                verdict: v,
                detail: format!("ping {} -> {}: {}; {} -> {}: {}", a.device, b.device, r.ping_ab.verdict.label(), b.device, a.device, r.ping_ba.verdict.label()),
            }
        }
        None => LevelStep {
            level: 1,
            name: "IP reachability",
            verdict: Verdict::NotTested,
            detail: "not tested between the devices (needs --active); LabLink itself reached both over SSH".into(),
        },
    });
    // L2
    let cfg_ids = [
        "domain",
        "interface-binding",
        "multicast",
        "discovery-restrictions",
        "routing",
        "rmw",
        "localhost-only",
        "peers",
    ];
    let failing: Vec<&str> = checks
        .iter()
        .filter(|c| cfg_ids.contains(&c.id) && c.verdict == Verdict::Fail)
        .map(|c| c.title)
        .collect();
    steps.push(LevelStep {
        level: 2,
        name: "Compatible configuration",
        verdict: if failing.is_empty() {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        detail: if failing.is_empty() {
            "no configuration check failed".into()
        } else {
            format!("failing: {}", failing.join(", "))
        },
    });
    // L3
    steps.push(graph_level(a, b));
    // L4
    steps.push(match active {
        Some(r) => {
            let v = r.pubsub_ab.verdict.worst(r.pubsub_ba.verdict);
            LevelStep {
                level: 4,
                name: "Data exchange",
                verdict: v,
                detail: format!(
                    "probe {} -> {}: {}; {} -> {}: {}",
                    a.device,
                    b.device,
                    r.pubsub_ab.summary,
                    b.device,
                    a.device,
                    r.pubsub_ba.summary
                ),
            }
        }
        None => LevelStep {
            level: 4,
            name: "Data exchange",
            verdict: Verdict::NotTested,
            detail:
                "only the active pub/sub probe (--active) can show data flows; a node list does not"
                    .into(),
        },
    });
    let mut level = 0;
    for s in &steps {
        if s.verdict == Verdict::Pass
            && steps
                .iter()
                .filter(|x| x.level < s.level)
                .all(|x| x.verdict != Verdict::Fail)
        {
            level = s.level;
        }
    }
    (level, steps)
}

fn graph_level(a: &Inspection, b: &Inspection) -> LevelStep {
    let step = |v, d: String| LevelStep {
        level: 3,
        name: "Discovery",
        verdict: v,
        detail: d,
    };
    let (Some(ga), Some(gb)) = (&a.graph, &b.graph) else {
        return step(
            Verdict::NotTested,
            "the graph was not queried on both devices".into(),
        );
    };
    if let Some(e) = ga.error.as_ref().or(gb.error.as_ref()) {
        return step(Verdict::Unavailable, format!("a graph query failed: {e}"));
    }
    // Two kinds of evidence that `x`'s graph shows `y`: the other side's
    // concurrent query node (unusable when both got the same pid, common in
    // fresh containers), and nodes `y` runs under an explicit name
    // (`__node:=`, which launch files set).
    let query = |gx: &crate::inspect::Graph, gy: &crate::inspect::Graph| -> Option<bool> {
        match (&gx.self_node, &gy.self_node) {
            (Some(sx), Some(sy)) if sx != sy => Some(gx.cli_nodes.contains(sy)),
            _ => None,
        }
    };
    let named = |y: &Inspection, gx: &crate::inspect::Graph| -> (Option<bool>, Vec<String>) {
        let names: Vec<&str> = y
            .processes
            .iter()
            .filter_map(|p| p.node.as_deref())
            .collect();
        if names.is_empty() {
            return (None, vec![]);
        }
        let seen: Vec<String> = names
            .iter()
            .filter(|n| gx.nodes.iter().any(|x| x.rsplit('/').next() == Some(**n)))
            .map(|n| n.to_string())
            .collect();
        (Some(!seen.is_empty()), seen)
    };
    let side = |x: &Inspection, gx, y: &Inspection, gy| -> (Option<bool>, String) {
        let q = query(gx, gy);
        let (n, seen) = named(y, gx);
        let mut parts = Vec::new();
        match q {
            Some(v) => parts.push(format!(
                "{}'s query node {}",
                y.device,
                if v { "seen" } else { "not seen" }
            )),
            None => parts.push("query nodes indistinguishable".into()),
        }
        match n {
            Some(true) => parts.push(format!("named node(s) {} seen", seen.join(", "))),
            Some(false) => parts.push(format!("none of {}'s named nodes seen", y.device)),
            None => {}
        }
        let v = match (q, n) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (None, None) => None,
            _ => Some(false),
        };
        (
            v,
            format!("{} -> {}: {}", x.device, y.device, parts.join("; ")),
        )
    };
    let (ab, dab) = side(a, ga, b, gb);
    let (ba, dba) = side(b, gb, a, ga);
    let detail = format!("{dab}. {dba}.");
    match (ab, ba) {
        (Some(true), Some(true)) => step(Verdict::Pass, detail),
        (Some(false), Some(false)) => step(Verdict::Fail, format!("neither device's graph shows the other. {detail}")),
        (Some(true), Some(false)) | (Some(false), Some(true)) => step(
            Verdict::Warn,
            format!("seen in one direction only within the query window (slow or asymmetric discovery; rerun or use --active). {detail}"),
        ),
        _ => step(Verdict::NotTested, format!("inconclusive. {detail}")),
    }
}

#[cfg(test)]
mod tests;
