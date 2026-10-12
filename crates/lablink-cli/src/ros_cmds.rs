//! `lablink ros ...`: robotics mode (optional feature). Read-only ROS 2 and
//! DDS inspection of registered devices over the doctor's pinned-key SSH
//! path; nothing ROS-related is needed on this machine. Only
//! `dds-check --active` (with an explicit `--peer`) sends traffic of its
//! own, on a unique probe topic.

use crate::{Fail, R};
use clap::Subcommand;
use lablink_core::client::Client;
use lablink_core::exit;
use lablink_ros::redact::{redact_json, redact_secrets};

/// Remote text for the terminal: DDS secrets removed, then control and
/// bidirectional-format characters escaped.
fn p(s: &str) -> String {
    lablink_core::printable(&redact_secrets(s))
}

/// JSON output with DDS secrets removed from every string.
fn print_json(v: &serde_json::Value) {
    let mut v = v.clone();
    redact_json(&mut v);
    crate::print_json(&v);
}
use lablink_ros::diagnose::{Report, Verdict};
use lablink_ros::inspect::{self, Inspection, Options};
use lablink_ros::{active, check, RemoteError, SshRemote};
use serde_json::json;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(clap::Args, Debug, Clone)]
pub struct Common {
    /// Seconds each remote step may take (5-300)
    #[arg(long, default_value_t = 30)]
    timeout: u64,
    #[arg(long)]
    json: bool,
    /// [default: $XDG_CONFIG_HOME/lablink/config.yaml]
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum RosAction {
    /// A device's ROS 2 setup: distribution, RMW, domain and discovery
    /// variables (running nodes vs. shell startup files), DDS config files,
    /// interfaces, routes, firewall service. Reads files and /proc only:
    /// starts no ROS process and joins no DDS domain.
    Inspect {
        device: String,
        #[command(flatten)]
        common: Common,
    },
    /// The ROS graph as the device's nodes see it (their domain and RMW).
    /// Briefly joins the domain as a hidden `ros2` node; publishes nothing.
    Nodes {
        device: String,
        /// Seconds to wait for discovery (1-10)
        #[arg(long, default_value_t = 3)]
        spin: u32,
        #[command(flatten)]
        common: Common,
    },
    /// Topics and their types, as the device's nodes see them.
    Topics {
        device: String,
        #[arg(long, default_value_t = 3)]
        spin: u32,
        #[command(flatten)]
        common: Common,
    },
    /// Diagnose ROS 2 / DDS connectivity: twelve checks, and with --peer the
    /// level reached (1 IP, 2 configuration, 3 discovery, 4 data exchange;
    /// level 4 only from --active). Exit 0 when no check fails, 1 otherwise.
    DdsCheck {
        device: String,
        /// The other device to check against.
        #[arg(long)]
        peer: Option<String>,
        /// Also run active tests between the two (ping, one multicast packet,
        /// a pub/sub probe on a unique /lablink_probe_* topic). Sends a
        /// little traffic; never touches existing topics or robot motion.
        #[arg(long, requires = "peer")]
        active: bool,
        /// Check endpoint QoS of this topic (repeatable, up to 5).
        #[arg(long = "qos-topic")]
        qos_topic: Vec<String>,
        /// Do not query the ROS graph (configuration checks only).
        #[arg(long)]
        no_graph: bool,
        /// Seconds each graph query waits for discovery (1-10)
        #[arg(long, default_value_t = 5)]
        spin: u32,
        /// Show every check's method, endpoints, interfaces, timeout and evidence.
        #[arg(long)]
        details: bool,
        #[command(flatten)]
        common: Common,
    },
}

pub fn json_mode(a: &RosAction) -> bool {
    match a {
        RosAction::Inspect { common, .. }
        | RosAction::Nodes { common, .. }
        | RosAction::Topics { common, .. }
        | RosAction::DdsCheck { common, .. } => common.json,
    }
}

fn require_feature(path: &Path) -> Result<(), Fail> {
    let cfg = lablink_setup::configfile::load_or_default(path)
        .map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))?;
    if !cfg.preferences.features.robotics {
        return Err(Fail::new(
            exit::REFUSED,
            "feature_disabled",
            "robotics mode is an optional feature and is off: turn it on with `lablink feature enable robotics`",
        ));
    }
    Ok(())
}

fn remote_fail(e: RemoteError) -> Fail {
    match e {
        RemoteError::Mismatch(m) => Fail::new(exit::IDENTITY_MISMATCH, "identity_mismatch", m),
        RemoteError::Unknown(m) => Fail::new(exit::DEVICE_NOT_FOUND, "device_not_found", m),
        RemoteError::NotLocated(m) => Fail::new(exit::DEVICE_UNREACHABLE, "unreachable", m),
        RemoteError::NotPinned(m) => Fail::new(exit::REFUSED, "not_pinned", m),
        RemoteError::TimedOut(m) => Fail::new(exit::EXEC_TIMEOUT, "timeout", m),
        RemoteError::Failed(m) => Fail::new(exit::FAILURE, "remote_failed", m),
    }
}

/// Resolve through the daemon first: the usual errors and exit codes
/// (daemon down 3, unknown 4, unreachable 5, identity mismatch 6), and the
/// address LabLink located the device at.
fn locate(client: &Client, device: &str) -> Result<(String, Option<Ipv4Addr>), Fail> {
    Ok(check::locate(client, device)?)
}

fn check_ranges(common: &Common, spin: Option<u32>) -> Result<Duration, Fail> {
    if !(5..=300).contains(&common.timeout) {
        return Err(Fail::new(
            exit::USAGE,
            "bad_request",
            "--timeout must be 5-300 seconds",
        ));
    }
    if spin.is_some_and(|s| !(1..=10).contains(&s)) {
        return Err(Fail::new(
            exit::USAGE,
            "bad_request",
            "--spin must be 1-10 seconds",
        ));
    }
    Ok(Duration::from_secs(common.timeout))
}

pub fn cmd_ros(client: &Client, action: RosAction) -> R {
    let remote = SshRemote { client };
    match action {
        RosAction::Inspect { device, common } => {
            require_feature(&crate::fieldnet_cmds::config_path(common.config.clone()))?;
            let timeout = check_ranges(&common, None)?;
            let (name, _) = locate(client, &device)?;
            let ins = inspect::inspect(
                &remote,
                &name,
                &Options {
                    graph: false,
                    qos_topics: vec![],
                    spin_s: 3,
                    timeout,
                },
            )
            .map_err(remote_fail)?;
            if common.json {
                print_json(&json!({ "schema_version": 1, "inspection": ins }));
            } else {
                print_inspection(&ins);
            }
            Ok(exit::OK)
        }
        RosAction::Nodes {
            device,
            spin,
            common,
        } => graph(&remote, client, &device, spin, &common, false),
        RosAction::Topics {
            device,
            spin,
            common,
        } => graph(&remote, client, &device, spin, &common, true),
        RosAction::DdsCheck {
            device,
            peer,
            active: act,
            qos_topic,
            no_graph,
            spin,
            details,
            common,
        } => {
            require_feature(&crate::fieldnet_cmds::config_path(common.config.clone()))?;
            let timeout = check_ranges(&common, Some(spin))?;
            if qos_topic.len() > 5 {
                return Err(Fail::new(
                    exit::USAGE,
                    "bad_request",
                    "at most 5 --qos-topic",
                ));
            }
            if let Some(t) = qos_topic
                .iter()
                .find(|t| !lablink_ros::script::valid_topic(t))
            {
                return Err(Fail::new(
                    exit::USAGE,
                    "bad_request",
                    format!(
                        "invalid topic name '{}' (absolute, letters, digits, _ and /)",
                        p(t)
                    ),
                ));
            }
            if act && no_graph {
                return Err(Fail::new(
                    exit::USAGE,
                    "bad_request",
                    "--active needs the graph (drop --no-graph)",
                ));
            }
            let opts = Options {
                graph: !no_graph,
                qos_topics: qos_topic,
                spin_s: spin,
                timeout,
            };
            let req = check::CheckRequest {
                device,
                peer,
                active: act,
                opts,
            };
            let report = check::run(client, &remote, &req, |a, b| {
                if !common.json {
                    eprintln!(
                        "Running active tests between {} and {} (about 50 s)...",
                        p(a),
                        p(b)
                    );
                }
            })
            .map_err(|e| match e {
                check::CheckError::BadRequest(m) => Fail::new(exit::USAGE, "bad_request", m),
                check::CheckError::Daemon(e) => Fail::from(e),
                check::CheckError::Remote(e) => remote_fail(e),
            })?;
            let (r, act_report) = report;
            if common.json {
                print_json(&json!({ "schema_version": 1, "report": r, "active": act_report }));
            } else {
                print_report(&r, act_report.as_ref(), details);
            }
            Ok(if r.worst() == Verdict::Fail {
                exit::FAILURE
            } else {
                exit::OK
            })
        }
    }
}

fn graph(
    remote: &SshRemote,
    client: &Client,
    device: &str,
    spin: u32,
    common: &Common,
    topics: bool,
) -> R {
    require_feature(&crate::fieldnet_cmds::config_path(common.config.clone()))?;
    let timeout = check_ranges(common, Some(spin))?;
    let (name, _) = locate(client, device)?;
    let ins = inspect::inspect(
        remote,
        &name,
        &Options {
            graph: true,
            qos_topics: vec![],
            spin_s: spin,
            timeout,
        },
    )
    .map_err(remote_fail)?;
    let Some(g) = &ins.graph else {
        let why = ins
            .notes
            .last()
            .cloned()
            .unwrap_or_else(|| "the graph could not be queried".into());
        return Err(Fail::new(exit::FAILURE, "unavailable", why));
    };
    if common.json {
        print_json(&json!({
            "schema_version": 1,
            "device": ins.device,
            "domain": g.domain,
            "rmw": g.rmw,
            "method": g.method,
            "error": g.error,
            "nodes": if topics { None } else { Some(&g.nodes) },
            "topics": if topics { Some(g.topics.iter().map(|(t, ty)| json!({"name": t, "type": ty})).collect::<Vec<_>>()) } else { None },
        }));
    } else {
        println!(
            "{}: domain {}, {} ({})",
            p(&ins.device),
            g.domain,
            p(&g.rmw),
            p(&g.method)
        );
        if topics {
            for (t, ty) in &g.topics {
                println!("  {}  [{}]", p(t), p(ty));
            }
            if g.topics.is_empty() {
                println!("  (no topics)");
            }
        } else {
            for n in &g.nodes {
                println!("  {}", p(n));
            }
            if g.nodes.is_empty() {
                println!("  (no nodes)");
            }
        }
    }
    if let Some(e) = &g.error {
        eprintln!("warning: {}", p(e));
        return Ok(exit::FAILURE);
    }
    Ok(exit::OK)
}

fn print_inspection(i: &Inspection) {
    let h = &i.host;
    println!(
        "{}  ROS 2 {}  ({} {}, {})",
        p(&i.device),
        p(i.distro.as_deref().unwrap_or("not found")),
        p(&h.os),
        p(&h.arch),
        p(&h.hostname)
    );
    let installed: Vec<String> = i
        .distros
        .iter()
        .map(|d| {
            format!(
                "{}{} [{}]",
                d.name,
                if d.ros2_cli { "" } else { " (no ros2 CLI)" },
                d.rmws.join(", ")
            )
        })
        .collect();
    println!(
        "  Installed: {}",
        p(&if installed.is_empty() {
            "none under /opt/ros".into()
        } else {
            installed.join("; ")
        })
    );
    println!(
        "  Effective environment: from {}{}",
        i.effective_source.label(),
        if i.processes_agree {
            ""
        } else {
            " (the processes disagree; showing the most common)"
        }
    );
    println!("    ROS_DOMAIN_ID       {}", i.effective_domain());
    println!("    RMW                 {}", p(&i.effective_rmw()));
    for (k, v) in &i.effective.vars {
        if k != "ROS_DOMAIN_ID" && k != "RMW_IMPLEMENTATION" {
            println!("    {:<19} {}", k, p(v));
        }
    }
    if !i.shell.lines.is_empty() || !i.shell.sourced.is_empty() {
        println!("  Shell startup files (what a new terminal gets):");
        for d in &i.shell.sourced {
            println!("    sources /opt/ros/{}", p(d));
        }
        for l in &i.shell.lines {
            println!(
                "    {}:{}  {}={}{}",
                p(&l.file),
                l.line,
                l.key,
                p(&l.value),
                if l.approximate { "  (approximate)" } else { "" }
            );
        }
    }
    let nodes: Vec<String> = i
        .processes
        .iter()
        .map(|x| {
            format!(
                "{} {}{}",
                x.pid,
                x.comm,
                x.node
                    .as_ref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default()
            )
        })
        .collect();
    println!(
        "  ROS processes: {}{}",
        if nodes.is_empty() {
            "none".into()
        } else {
            p(&nodes.join(", "))
        },
        if i.processes_truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    for l in &i.links {
        if l.name == "lo" {
            continue;
        }
        let addrs: Vec<String> = i
            .addresses_on(&l.name)
            .iter()
            .map(|a| a.to_string())
            .collect();
        println!(
            "  Interface {}: {}{} {}",
            p(&l.name),
            if l.up { "up" } else { "down" },
            if l.multicast {
                ", multicast"
            } else {
                ", NO multicast"
            },
            addrs.join(" ")
        );
    }
    println!(
        "  Multicast route (239.255.0.1): {}",
        p(i.multicast_route.as_deref().unwrap_or("none"))
    );
    let fw = i.firewall.active();
    println!(
        "  Firewall: {}",
        if !i.firewall.known() {
            "unknown".into()
        } else if fw.is_empty() {
            "no service active".into()
        } else {
            format!("{} active (rules not read)", fw.join(", "))
        }
    );
    for d in &i.daemons {
        println!(
            "  ros2 daemon: pid {} domain {} {}",
            d.pid,
            d.domain.unwrap_or(0),
            p(d.rmw.as_deref().unwrap_or(""))
        );
    }
    for c in &i.dds {
        let ifs: Vec<String> = c.interfaces.iter().map(|s| s.describe()).collect();
        println!(
            "  DDS config {} ({:?}): {}{}{}",
            p(&c.source),
            c.vendor,
            if ifs.is_empty() {
                "no interface restriction".into()
            } else {
                format!("interfaces {}", p(&ifs.join(", ")))
            },
            if c.peers.is_empty() {
                String::new()
            } else {
                format!("; peers {}", p(&c.peers.join(", ")))
            },
            c.problem
                .as_ref()
                .map(|x| format!("; PROBLEM: {}", p(x)))
                .unwrap_or_default()
        );
    }
    for n in &i.notes {
        println!("  note: {}", p(n));
    }
}

fn print_report(r: &Report, act: Option<&active::ActiveReport>, details: bool) {
    match &r.peer {
        Some(b) => println!(
            "DDS check: {} <-> {} ({})",
            p(&r.device),
            p(b),
            if r.active {
                "passive + active"
            } else {
                "passive"
            }
        ),
        None => println!(
            "DDS check: {} (single device; add --peer for connectivity)",
            p(&r.device)
        ),
    }
    if let Some(path) = &r.path {
        println!(
            "  shared network {}: {} {} ({}) / {} ({})",
            path.net,
            p(&r.device),
            path.a_addr,
            p(&path.a_interface),
            path.b_addr,
            p(&path.b_interface)
        );
    }
    for c in &r.checks {
        println!(
            "  {:<11} {:<26} {}",
            c.verdict.label(),
            c.title,
            p(&c.summary)
        );
        if let Some(h) = c.hint.as_ref().filter(|_| {
            matches!(
                c.verdict,
                Verdict::Fail | Verdict::Warn | Verdict::NotTested
            )
        }) {
            println!("  {:<11} {:<26} hint: {}", "", "", p(h));
        }
        if details {
            println!("  {:<38} method: {}", "", p(&c.method));
            println!("  {:<38} endpoints: {}", "", p(&c.endpoints.join(", ")));
            if !c.interfaces.is_empty() {
                println!("  {:<38} interfaces: {}", "", p(&c.interfaces.join(", ")));
            }
            println!(
                "  {:<38} domain: {}  timeout: {}",
                "",
                c.domain
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "-".into()),
                c.timeout_ms
                    .map(|t| format!("{} s", t / 1000))
                    .unwrap_or_else(|| "-".into())
            );
            for e in &c.evidence {
                println!("  {:<38} - {}", "", p(e));
            }
        }
    }
    if let Some(level) = r.level {
        println!(
            "Level {level} of 4 reached{}",
            if level < 4 && !r.active {
                " (level 4 needs --active)"
            } else {
                ""
            }
        );
        for s in &r.levels {
            println!(
                "  L{} {:<26} {:<11} {}",
                s.level,
                s.name,
                s.verdict.label(),
                p(&s.detail)
            );
        }
    }
    if let Some(a) = act {
        println!("Active tests on {} (domain {}):", p(&a.topic), a.domain);
        for pr in [
            &a.ping_ab,
            &a.ping_ba,
            &a.multicast_ab,
            &a.multicast_ba,
            &a.pubsub_ab,
            &a.pubsub_ba,
        ] {
            println!(
                "  {:<11} {:<9} {} -> {} via {}: {}",
                pr.verdict.label(),
                pr.name,
                p(&pr.from),
                p(&pr.to),
                p(pr.interface.as_deref().unwrap_or("?")),
                p(&pr.summary)
            );
        }
        if a.leftover.is_empty() {
            println!("  cleanup: no probe process left on either device");
        } else {
            for l in &a.leftover {
                println!("  cleanup: {}", p(l));
            }
        }
    }
}
