//! `lablink ros inspect`: what a device's ROS 2 setup is, read over SSH.

use crate::dds::{self, DdsConfig, UriPart, Vendor};
use crate::env::{self, EnvSource, RosEnv, RosProcess, ShellEnv};
use crate::script::{self, Phase2, QueryEnv};
use crate::{Remote, RemoteError};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Host {
    pub home: String,
    pub user: String,
    pub hostname: String,
    pub arch: String,
    pub os: String,
    pub bash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Distro {
    pub name: String,
    pub ros2_cli: bool,
    pub rmws: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub name: String,
    pub up: bool,
    pub multicast: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Addr {
    pub interface: String,
    pub net: Ipv4Net,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    /// `default` or a CIDR.
    pub dest: String,
    pub device: Option<String>,
    pub via: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Firewall {
    /// Service name -> `systemctl is-active` (active, inactive, ...; empty: unknown).
    pub services: BTreeMap<String, String>,
    /// `/etc/ufw/ufw.conf` ENABLED=.
    pub ufw_enabled: Option<bool>,
}

impl Firewall {
    pub fn active(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .services
            .iter()
            .filter(|(_, s)| s.as_str() == "active")
            .map(|(n, _)| n.clone())
            .collect();
        if self.ufw_enabled == Some(true) && !v.iter().any(|n| n == "ufw") {
            v.push("ufw".into());
        }
        v
    }

    pub fn known(&self) -> bool {
        self.services.values().any(|s| !s.is_empty()) || self.ufw_enabled.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Daemon {
    pub pid: u32,
    pub rmw: Option<String>,
    pub domain: Option<u32>,
}

/// One endpoint of a topic, from `ros2 topic info -v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub node: String,
    /// PUBLISHER or SUBSCRIPTION.
    pub kind: String,
    pub reliability: String,
    pub durability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopicQos {
    pub topic: String,
    pub endpoints: Vec<Endpoint>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Graph {
    /// Node names, every `ros2` command-line node excluded.
    pub nodes: Vec<String>,
    /// This query's own hidden node (`/_ros2cli_<pid>`).
    pub self_node: Option<String>,
    /// Other hidden `ros2` command-line nodes seen (for example a
    /// concurrent LabLink query on another device).
    pub cli_nodes: Vec<String>,
    /// (topic, type).
    pub topics: Vec<(String, String)>,
    pub error: Option<String>,
    /// The environment the query ran in.
    pub domain: u32,
    pub rmw: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Inspection {
    pub device: String,
    pub host: Host,
    pub distros: Vec<Distro>,
    /// The distribution the nodes use (or would use).
    pub distro: Option<String>,
    pub shell: ShellEnv,
    pub session_env: RosEnv,
    pub processes: Vec<RosProcess>,
    pub processes_truncated: bool,
    /// ROS-looking processes whose environment this user cannot read
    /// (another user's or root's).
    pub unreadable_processes: u32,
    /// All running ROS processes agree on the discovery variables.
    pub processes_agree: bool,
    pub effective: RosEnv,
    pub effective_source: EnvSource,
    pub links: Vec<Link>,
    pub addresses: Vec<Addr>,
    pub routes: Vec<Route>,
    /// The interface multicast to 239.255.0.1 (the DDS discovery group)
    /// leaves through.
    pub multicast_route: Option<String>,
    /// `ip` (iproute2) is installed; without it addresses and routes are unknown.
    pub ip_tool: bool,
    pub firewall: Firewall,
    pub daemons: Vec<Daemon>,
    pub dds: Vec<DdsConfig>,
    pub graph: Option<Graph>,
    pub qos: Vec<TopicQos>,
    pub notes: Vec<String>,
    pub duration_ms: u64,
}

impl Inspection {
    pub fn effective_domain(&self) -> u32 {
        self.effective.domain().ok().flatten().unwrap_or(0)
    }

    pub fn effective_rmw(&self) -> String {
        self.effective
            .rmw()
            .map(str::to_string)
            .unwrap_or_else(|| env::default_rmw(self.distro.as_deref()).to_string())
    }

    pub fn addresses_on(&self, iface: &str) -> Vec<Ipv4Net> {
        self.addresses
            .iter()
            .filter(|a| a.interface == iface)
            .map(|a| a.net)
            .collect()
    }

    pub fn link(&self, name: &str) -> Option<&Link> {
        self.links.iter().find(|l| l.name == name)
    }

    /// The interface whose subnet holds `ip`.
    pub fn interface_for(&self, ip: std::net::Ipv4Addr) -> Option<&str> {
        self.addresses
            .iter()
            .find(|a| a.net.contains(&ip) && !a.net.addr().is_loopback())
            .map(|a| a.interface.as_str())
    }
}

/// How two devices reach each other: a subnet both have an address in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetPath {
    pub net: Ipv4Net,
    pub a_interface: String,
    pub a_addr: std::net::Ipv4Addr,
    pub b_interface: String,
    pub b_addr: std::net::Ipv4Addr,
}

/// The shared subnet of `a` and `b`, preferring the one holding `b_hint`
/// (the address LabLink located `b` at).
pub fn shared_path(
    a: &Inspection,
    b: &Inspection,
    b_hint: Option<std::net::Ipv4Addr>,
) -> Option<NetPath> {
    let mut found: Vec<NetPath> = Vec::new();
    for x in a.addresses.iter().filter(|x| !x.net.addr().is_loopback()) {
        for y in b.addresses.iter().filter(|y| !y.net.addr().is_loopback()) {
            if x.net.trunc() == y.net.trunc() && x.net.addr() != y.net.addr() {
                found.push(NetPath {
                    net: x.net.trunc(),
                    a_interface: x.interface.clone(),
                    a_addr: x.net.addr(),
                    b_interface: y.interface.clone(),
                    b_addr: y.net.addr(),
                });
            }
        }
    }
    let i = b_hint
        .and_then(|h| found.iter().position(|p| p.b_addr == h))
        .unwrap_or(0);
    (i < found.len()).then(|| found.swap_remove(i))
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Query the ROS graph (joins the domain for `spin_s` seconds as a
    /// hidden node; publishes nothing to robot topics).
    pub graph: bool,
    pub qos_topics: Vec<String>,
    pub spin_s: u32,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            graph: false,
            qos_topics: vec![],
            spin_s: 3,
            timeout: Duration::from_secs(30),
        }
    }
}

const SHELLS: [&str; 13] = [
    "bash", "sh", "dash", "zsh", "fish", "tmux", "screen", "sshd", "sudo", "sleep", "tail", "cat",
    "less",
];

/// Phase 1 and phase 2 on one device.
pub fn inspect(
    remote: &dyn Remote,
    device: &str,
    opts: &Options,
) -> Result<Inspection, RemoteError> {
    let mut ins = phase1(remote, device, opts)?;
    phase2(remote, &mut ins, opts)?;
    Ok(ins)
}

/// Two devices, with their graph queries running at the same time so each
/// can see the other's query node.
pub fn inspect_pair(
    remote: &dyn Remote,
    a: &str,
    b: &str,
    opts: &Options,
) -> (
    Result<Inspection, RemoteError>,
    Result<Inspection, RemoteError>,
) {
    let (ra, rb) = std::thread::scope(|s| {
        let hb = s.spawn(|| phase1(remote, b, opts));
        let ra = phase1(remote, a, opts);
        (
            ra,
            hb.join()
                .unwrap_or_else(|_| Err(RemoteError::Failed("inspection thread panicked".into()))),
        )
    });
    match (ra, rb) {
        (Ok(mut ia), Ok(mut ib)) => {
            let (pa, pb) = std::thread::scope(|s| {
                let hb = s.spawn(|| phase2(remote, &mut ib, opts));
                let pa = phase2(remote, &mut ia, opts);
                (
                    pa,
                    hb.join().unwrap_or_else(|_| {
                        Err(RemoteError::Failed("inspection thread panicked".into()))
                    }),
                )
            });
            (pa.map(|_| ia), pb.map(|_| ib))
        }
        other => other,
    }
}

/// The fixed, read-only inspection: files, `/proc`, `ip`. No ROS process.
pub fn phase1(
    remote: &dyn Remote,
    device: &str,
    opts: &Options,
) -> Result<Inspection, RemoteError> {
    let started = std::time::Instant::now();
    let out = remote.run(device, &script::inspect_script(), opts.timeout)?;
    let sec = script::sections(&out).ok_or_else(|| {
        RemoteError::Failed("the inspection did not complete (no end marker)".into())
    })?;
    let get = |k: &str| sec.get(k).cloned().unwrap_or_default();
    let mut notes = Vec::new();

    let host = parse_host(&get("host"));
    let distros = parse_distros(&get("distros"));
    let shell = env::parse_shell_files(&get("shell_files"), &host.home);
    let session_env = RosEnv::from_lines(get("session_env").iter().map(String::as_str));
    let (processes, processes_truncated) = env::parse_processes(&get("processes"));
    let unreadable_processes = get("unreadable")
        .iter()
        .find_map(|l| l.strip_prefix("count=")?.trim().parse().ok())
        .unwrap_or(0);
    // Processes started with --ros-args are nodes for certain; otherwise
    // anything that is not a shell or a pager (in containers every process
    // inherits the image's ROS environment).
    let nodes: Vec<RosProcess> = if processes.iter().any(|p| p.ros_args) {
        processes.iter().filter(|p| p.ros_args).cloned().collect()
    } else {
        processes
            .iter()
            .filter(|p| !SHELLS.contains(&p.comm.as_str()))
            .cloned()
            .collect()
    };
    let (effective, effective_source, processes_agree) = match env::consensus(&nodes) {
        Some((e, agree)) => (e, EnvSource::RunningNodes, agree),
        None if !shell.lines.is_empty() || !shell.sourced.is_empty() => {
            (shell.env(), EnvSource::ShellFiles, true)
        }
        None if !session_env.vars.is_empty() => (session_env.clone(), EnvSource::Session, true),
        None => (RosEnv::default(), EnvSource::Defaults, true),
    };
    if effective_source == EnvSource::ShellFiles && shell.approximate() {
        notes.push("Some shell settings are conditional or computed; LabLink reads startup files without running them, so their values are approximate.".into());
    }
    if get("interfaces").iter().any(|l| l == "ip=missing") {
        notes.push("The ip command (iproute2) is not installed: addresses and routes are unknown, so subnet and routing checks are unavailable.".into());
    }
    if unreadable_processes > 0 {
        notes.push(format!(
            "{unreadable_processes} ROS process(es) run as another user; their environment cannot be read without their privileges."
        ));
    }
    let installed: Vec<&str> = distros.iter().map(|d| d.name.as_str()).collect();
    let distro = effective
        .distro()
        .map(str::to_string)
        .or_else(|| shell.sourced.last().cloned())
        .or_else(|| match installed.as_slice() {
            [one] => Some(one.to_string()),
            _ => ["jazzy", "humble"]
                .iter()
                .find(|d| installed.contains(d))
                .map(|d| d.to_string())
                .or_else(|| installed.first().map(|d| d.to_string())),
        })
        .filter(|d| env::valid_distro(d));
    if let Some(d) = &distro {
        if !env::SUPPORTED_DISTROS.contains(&d.as_str()) {
            notes.push(format!("ROS 2 {d} is not one LabLink knows the defaults of (Humble, Jazzy); results may be incomplete."));
        }
        if !installed.contains(&d.as_str()) {
            notes.push(format!("The nodes use ROS 2 {d}, but /opt/ros/{d} is not installed (a container or a source build?)."));
        }
    }

    let mut ins = Inspection {
        device: device.to_string(),
        host,
        distros,
        distro,
        shell,
        session_env,
        processes,
        processes_truncated,
        unreadable_processes,
        processes_agree,
        effective,
        effective_source,
        ip_tool: !get("interfaces").iter().any(|l| l == "ip=missing"),
        links: parse_links(&get("interfaces")),
        addresses: parse_addrs(&get("addresses")),
        routes: parse_routes(&get("routes")),
        multicast_route: parse_route_get(&get("mcast_route")),
        firewall: parse_firewall(&get("firewall")),
        daemons: parse_daemons(&get("daemon")),
        dds: Vec::new(),
        graph: None,
        qos: Vec::new(),
        notes,
        duration_ms: 0,
    };
    ins.duration_ms = started.elapsed().as_millis() as u64;
    Ok(ins)
}

/// The DDS config files phase 1 found, and the graph when asked.
pub fn phase2(
    remote: &dyn Remote,
    ins: &mut Inspection,
    opts: &Options,
) -> Result<(), RemoteError> {
    let started = std::time::Instant::now();
    let device = ins.device.clone();
    let mut files = Vec::new();
    let mut inline = Vec::new();
    if let Some(u) = ins.effective.get("CYCLONEDDS_URI") {
        for part in dds::cyclone_uri_parts(u) {
            match part {
                UriPart::Inline(x) => inline.push(x),
                UriPart::File(f) if env::valid_path(&f) => files.push((Vendor::Cyclone, f)),
                UriPart::File(f) => ins.dds.push(DdsConfig::missing(
                    Vendor::Cyclone,
                    &f,
                    "not read: not a plain absolute path",
                )),
            }
        }
    }
    for k in [
        "FASTDDS_DEFAULT_PROFILES_FILE",
        "FASTRTPS_DEFAULT_PROFILES_FILE",
    ] {
        if let Some(f) = ins.effective.get(k) {
            if env::valid_path(f) && !files.iter().any(|(_, x)| x == f) {
                files.push((Vendor::FastDds, f.to_string()));
            }
        }
    }
    for x in inline {
        ins.dds
            .push(dds::parse_cyclone(&x, "inline (CYCLONEDDS_URI)"));
    }
    let installed_distro = ins
        .distro
        .clone()
        .filter(|d| ins.distros.iter().any(|x| &x.name == d && x.ros2_cli));
    let graph_env = match (&installed_distro, opts.graph, ins.host.bash) {
        (Some(d), true, true) => Some(QueryEnv::from_env(d, &ins.effective)),
        _ => None,
    };
    if opts.graph && graph_env.is_none() {
        ins.notes.push(if ins.host.bash {
            "The ROS graph was not queried: no installed ROS 2 distribution with the ros2 command line was found.".into()
        } else {
            "The ROS graph was not queried: bash is not installed.".into()
        });
    }
    if !files.is_empty() || graph_env.is_some() {
        let p2 = Phase2 {
            files: files.iter().map(|(_, f)| f.clone()).collect(),
            graph: graph_env.clone(),
            qos_topics: opts.qos_topics.clone(),
            spin_s: opts.spin_s,
        };
        let s = script::phase2(&p2).map_err(RemoteError::Failed)?;
        let out = remote.run(&device, &s, opts.timeout)?;
        let sec = script::sections(&out).ok_or_else(|| {
            RemoteError::Failed("the ROS query did not complete (no end marker)".into())
        })?;
        for (i, (vendor, f)) in files.iter().enumerate() {
            let lines = sec.get(&format!("file{i}")).cloned().unwrap_or_default();
            let cfg = match lines.first().map(String::as_str) {
                Some("present") => {
                    let xml = lines[1..].join("\n");
                    match vendor {
                        Vendor::Cyclone => dds::parse_cyclone(&xml, f),
                        Vendor::FastDds => dds::parse_fastdds(&xml, f),
                    }
                }
                _ => DdsConfig::missing(*vendor, f, "the file does not exist or is not readable"),
            };
            ins.dds.push(cfg);
        }
        if let Some(q) = &graph_env {
            let method = format!(
                "ros2 node list -a / topic list -t --no-daemon --spin-time {} (ROS 2 {}, domain {}, {})",
                opts.spin_s.clamp(1, 10),
                q.distro,
                q.domain.unwrap_or(0),
                q.rmw.clone().unwrap_or_else(|| env::default_rmw(Some(&q.distro)).into())
            );
            let nodes = sec.get("graph_nodes").cloned().unwrap_or_default();
            let topics = sec.get("graph_topics").cloned().unwrap_or_default();
            let (node_list, e1) = parse_listing(&nodes);
            let (topic_list, e2) = parse_listing(&topics);
            let self_node = nodes
                .iter()
                .find_map(|l| l.strip_prefix("pid="))
                .and_then(|p| p.trim().parse::<u32>().ok())
                .map(|p| format!("/_ros2cli_{p}"));
            let is_cli = |n: &String| {
                n.rsplit('/')
                    .next()
                    .is_some_and(|b| b.starts_with("_ros2cli_"))
            };
            ins.graph = Some(Graph {
                cli_nodes: node_list
                    .iter()
                    .filter(|n| is_cli(n) && Some(*n) != self_node.as_ref())
                    .cloned()
                    .collect(),
                self_node,
                nodes: node_list.iter().filter(|n| !is_cli(n)).cloned().collect(),
                topics: topic_list
                    .iter()
                    .filter_map(|t| parse_topic_line(t))
                    .collect(),
                error: e1.or(e2),
                domain: q.domain.unwrap_or(0),
                rmw: q
                    .rmw
                    .clone()
                    .unwrap_or_else(|| env::default_rmw(Some(&q.distro)).into()),
                method,
            });
            for (i, t) in opts.qos_topics.iter().enumerate().take(5) {
                let lines = sec.get(&format!("qos{i}")).cloned().unwrap_or_default();
                ins.qos.push(parse_topic_info(t, &lines));
            }
        }
    }
    ins.duration_ms += started.elapsed().as_millis() as u64;
    Ok(())
}

fn kv(lines: &[String]) -> BTreeMap<String, String> {
    lines
        .iter()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .collect()
}

pub fn parse_host(lines: &[String]) -> Host {
    let m = kv(lines);
    let g = |k: &str| m.get(k).cloned().unwrap_or_default();
    Host {
        home: g("home"),
        user: g("user"),
        hostname: g("hostname"),
        arch: g("arch"),
        os: format!("{} {}", g("ID"), g("VERSION_ID"))
            .trim()
            .to_string(),
        bash: g("bash") == "yes",
    }
}

pub fn parse_distros(lines: &[String]) -> Vec<Distro> {
    let mut out: Vec<Distro> = Vec::new();
    for l in lines {
        if let Some(rest) = l.strip_prefix("distro=") {
            let (name, ros2) = rest.split_once(" ros2=").unwrap_or((rest, "no"));
            if env::valid_distro(name) {
                out.push(Distro {
                    name: name.to_string(),
                    ros2_cli: ros2.trim() == "yes",
                    rmws: vec![],
                });
            }
        } else if let Some(r) = l.trim().strip_prefix("rmw=") {
            if let Some(d) = out.last_mut() {
                // librmw_fastrtps_cpp -> rmw_fastrtps_cpp; skip the shared helpers.
                if env::valid_rmw(r) && !r.contains("_shared_") && !r.contains("__") {
                    d.rmws.push(r.to_string());
                }
            }
        }
    }
    out
}

/// `ip -o link show`.
pub fn parse_links(lines: &[String]) -> Vec<Link> {
    lines
        .iter()
        .filter_map(|l| {
            let mut it = l.splitn(3, ": ");
            it.next()?;
            let name = it.next()?.split('@').next()?.to_string();
            let rest = it.next()?;
            let flags = rest.split_once('<')?.1.split_once('>')?.0;
            let flags: Vec<&str> = flags.split(',').collect();
            Some(Link {
                name,
                up: flags.contains(&"UP")
                    && (flags.contains(&"LOWER_UP") || flags.contains(&"LOOPBACK")),
                multicast: flags.contains(&"MULTICAST"),
            })
        })
        .collect()
}

/// `ip -o -4 addr show`.
pub fn parse_addrs(lines: &[String]) -> Vec<Addr> {
    lines
        .iter()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let i = t.iter().position(|w| *w == "inet")?;
            Some(Addr {
                interface: t
                    .get(1)?
                    .trim_end_matches(':')
                    .split('@')
                    .next()?
                    .to_string(),
                net: t.get(i + 1)?.parse().ok()?,
            })
        })
        .collect()
}

pub fn parse_routes(lines: &[String]) -> Vec<Route> {
    lines
        .iter()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let dest = t.first()?.to_string();
            if dest.contains("RTNETLINK") || dest == "Error:" {
                return None;
            }
            let after = |k: &str| {
                t.iter()
                    .position(|w| *w == k)
                    .and_then(|i| t.get(i + 1))
                    .map(|s| s.to_string())
            };
            Some(Route {
                dest,
                device: after("dev"),
                via: after("via"),
            })
        })
        .collect()
}

pub fn parse_route_get(lines: &[String]) -> Option<String> {
    let l = lines.first()?;
    let t: Vec<&str> = l.split_whitespace().collect();
    let i = t.iter().position(|w| *w == "dev")?;
    t.get(i + 1).map(|s| s.to_string())
}

pub fn parse_firewall(lines: &[String]) -> Firewall {
    let mut f = Firewall::default();
    for (k, v) in kv(lines) {
        match k.as_str() {
            "ENABLED" => f.ufw_enabled = Some(v.eq_ignore_ascii_case("yes")),
            "ufw" | "firewalld" | "nftables" => {
                f.services.insert(k, v);
            }
            _ => {}
        }
    }
    f
}

pub fn parse_daemons(lines: &[String]) -> Vec<Daemon> {
    lines
        .iter()
        .filter_map(|l| {
            let rest = l.strip_prefix("pid=")?;
            let t: Vec<&str> = rest.split_whitespace().collect();
            let after = |k: &str| {
                t.iter()
                    .position(|w| *w == k)
                    .and_then(|i| t.get(i + 1))
                    .map(|s| s.to_string())
            };
            Some(Daemon {
                pid: t.first()?.parse().ok()?,
                rmw: after("--rmw-implementation").filter(|r| env::valid_rmw(r)),
                domain: after("--ros-domain-id").and_then(|d| d.parse().ok()),
            })
        })
        .collect()
}

/// Lines of a `ros2 ... list` section, and an error when its rc is not 0.
pub fn parse_listing(lines: &[String]) -> (Vec<String>, Option<String>) {
    let rc = lines
        .iter()
        .rev()
        .find_map(|l| l.strip_prefix("rc=")?.trim().parse::<i32>().ok());
    let items: Vec<String> = lines
        .iter()
        .filter(|l| l.starts_with('/'))
        .map(|l| l.trim().to_string())
        .collect();
    let error = match rc {
        Some(0) => None,
        Some(124) | None => Some("timed out (no reply within the limit)".to_string()),
        Some(c) => Some(format!(
            "ros2 exited with {c}: {}",
            lines
                .iter()
                .find(|l| {
                    !l.starts_with('/')
                        && !l.starts_with("rc=")
                        && !l.starts_with("pid=")
                        && !l.starts_with("WARNING: Be aware")
                        && !l.trim().is_empty()
                })
                .map(|l| l.chars().take(160).collect::<String>())
                .unwrap_or_default()
        )),
    };
    (items, error)
}

/// `/chatter [std_msgs/msg/String]`.
pub fn parse_topic_line(l: &str) -> Option<(String, String)> {
    let (t, ty) = l.split_once(" [")?;
    Some((t.trim().to_string(), ty.trim_end_matches(']').to_string()))
}

pub fn parse_topic_info(topic: &str, lines: &[String]) -> TopicQos {
    let (_, error) = parse_listing(lines);
    let mut eps: Vec<Endpoint> = Vec::new();
    let mut node = String::new();
    for l in lines {
        let l = l.trim();
        if let Some(n) = l.strip_prefix("Node name:") {
            node = n.trim().to_string();
        } else if let Some(k) = l.strip_prefix("Endpoint type:") {
            eps.push(Endpoint {
                node: node.clone(),
                kind: k.trim().to_string(),
                reliability: String::new(),
                durability: String::new(),
            });
        } else if let Some(r) = l.strip_prefix("Reliability:") {
            if let Some(e) = eps.last_mut() {
                e.reliability = r.trim().to_string();
            }
        } else if let Some(d) = l.strip_prefix("Durability:") {
            if let Some(e) = eps.last_mut() {
                e.durability = d.trim().to_string();
            }
        }
    }
    TopicQos {
        topic: topic.to_string(),
        endpoints: eps,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Vec<String> {
        v.lines().map(str::to_string).collect()
    }

    #[test]
    fn links_addrs_routes() {
        let l = parse_links(&s("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n2: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN"));
        assert_eq!(l.len(), 3);
        assert_eq!(l[1].name, "eth0");
        assert!(l[1].up && l[1].multicast);
        assert!(!l[2].up, "no carrier");
        let a = parse_addrs(&s("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0"));
        assert_eq!(a[1].interface, "eth0");
        assert_eq!(a[1].net.to_string(), "172.18.0.2/16");
        let r = parse_routes(&s("default via 172.18.0.1 dev eth0\n172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.2"));
        assert_eq!(r[0].dest, "default");
        assert_eq!(r[0].via.as_deref(), Some("172.18.0.1"));
        assert_eq!(
            parse_route_get(&s(
                "multicast 239.255.0.1 dev eth0 table local src 172.18.0.2"
            ))
            .as_deref(),
            Some("eth0")
        );
        assert_eq!(
            parse_route_get(&s("RTNETLINK answers: Network is unreachable")),
            None
        );
    }

    #[test]
    fn listings_and_qos() {
        let (n, e) = parse_listing(&s("/talker\n/_ros2cli_77\nrc=0"));
        assert_eq!(n, ["/talker", "/_ros2cli_77"]);
        assert!(e.is_none());
        let (_, e) = parse_listing(&s("pid=12\nTraceback: boom\nrc=1"));
        assert_eq!(e.unwrap(), "ros2 exited with 1: Traceback: boom");
        let (_, e) = parse_listing(&s("/a"));
        assert!(e.unwrap().contains("timed out"), "no rc: killed by timeout");
        let q = parse_topic_info(
            "/chatter",
            &s("Type: std_msgs/msg/String\n\nPublisher count: 1\n\nNode name: talker\nNode namespace: /\nEndpoint type: PUBLISHER\nQoS profile:\n  Reliability: BEST_EFFORT\n  Durability: VOLATILE\n\nSubscription count: 1\n\nNode name: listener\nEndpoint type: SUBSCRIPTION\nQoS profile:\n  Reliability: RELIABLE\n  Durability: VOLATILE\nrc=0"),
        );
        assert_eq!(q.endpoints.len(), 2);
        assert_eq!(q.endpoints[0].reliability, "BEST_EFFORT");
        assert_eq!(q.endpoints[1].node, "listener");
        assert_eq!(
            parse_topic_line("/chatter [std_msgs/msg/String]")
                .unwrap()
                .1,
            "std_msgs/msg/String"
        );
    }

    #[test]
    fn host_distros_firewall_daemon() {
        let h = parse_host(&s("home=/home/u\nuser=u\nhostname=orin\narch=aarch64\nID=ubuntu\nVERSION_ID=\"22.04\"\nbash=yes"));
        assert_eq!(h.os, "ubuntu 22.04");
        assert!(h.bash);
        let d = parse_distros(&s("distro=humble ros2=yes\n  rmw=rmw_fastrtps_cpp\n  rmw=rmw_fastrtps_shared_cpp\n  rmw=rmw_cyclonedds_cpp\ndistro=bad name ros2=yes"));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rmws, ["rmw_fastrtps_cpp", "rmw_cyclonedds_cpp"]);
        let f = parse_firewall(&s("ufw=inactive\nfirewalld=\nnftables=active\nENABLED=no"));
        assert_eq!(f.active(), ["nftables"]);
        assert!(f.known());
        let f = parse_firewall(&s("ufw=\nfirewalld=\nnftables="));
        assert!(!f.known());
        let dm = parse_daemons(&s(
            "pid=55 --rmw-implementation rmw_cyclonedds_cpp --ros-domain-id 7 ",
        ));
        assert_eq!(dm[0].domain, Some(7));
        assert_eq!(dm[0].rmw.as_deref(), Some("rmw_cyclonedds_cpp"));
    }
}
