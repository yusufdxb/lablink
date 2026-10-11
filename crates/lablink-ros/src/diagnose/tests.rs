//! Diagnosis over fake devices: canned phase-1/phase-2 replies parsed by
//! the real inspection code.

use super::*;
use crate::inspect::{self, Options};
use crate::script::END;
use crate::{Remote, RemoteError};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone)]
struct Dev {
    host: &'static str,
    iface: &'static str,
    addr: &'static str,
    node_env: Vec<&'static str>,
    node_name: Option<&'static str>,
    shell: Vec<&'static str>,
    rmws: Vec<&'static str>,
    files: BTreeMap<String, String>,
    multicast: bool,
    firewall: &'static str,
    daemon: Option<&'static str>,
    pid: u32,
    graph: Vec<String>,
    /// No iproute2 (link flags from sysfs only), as in ROS base images.
    ip_missing: bool,
    /// A container: an unrelated process also carries the image's ROS env.
    container: bool,
}

fn dev(host: &'static str, addr: &'static str, pid: u32) -> Dev {
    Dev {
        host,
        iface: "wlan0",
        addr,
        node_env: vec!["ROS_DISTRO=humble", "ROS_DOMAIN_ID=7"],
        node_name: None,
        shell: vec![
            "file=/home/u/.bashrc",
            "120:source /opt/ros/humble/setup.bash",
            "121:export ROS_DOMAIN_ID=7",
        ],
        rmws: vec!["rmw_fastrtps_cpp", "rmw_cyclonedds_cpp"],
        files: BTreeMap::new(),
        multicast: true,
        firewall: "inactive",
        daemon: None,
        pid,
        graph: vec!["/talker".into()],
        ip_missing: false,
        container: false,
    }
}

impl Dev {
    fn phase1(&self) -> String {
        let mut s = String::new();
        let mut w = |x: &str| {
            s.push_str(x);
            s.push('\n');
        };
        w("@@ll:host@@");
        w("home=/home/u");
        w("user=u");
        w(&format!("hostname={}", self.host));
        w("arch=aarch64\nID=ubuntu\nVERSION_ID=\"22.04\"\nbash=yes");
        w("@@ll:distros@@\ndistro=humble ros2=yes");
        for r in &self.rmws {
            w(&format!("  rmw={r}"));
        }
        w("@@ll:session_env@@\n@@ll:shell_files@@");
        for l in &self.shell {
            w(l);
        }
        w("@@ll:processes@@");
        if self.container {
            w("pid=1 comm=init_wrapper\n  node=\n  env ROS_DISTRO=humble");
        }
        if !self.node_env.is_empty() {
            w("pid=900 comm=robot_node");
            w(&format!("  node={}", self.node_name.unwrap_or("")));
            if self.container {
                w("  rosargs=yes");
            }
            for e in &self.node_env {
                w(&format!("  env {e}"));
            }
        }
        w("@@ll:unreadable@@\ncount=0\n@@ll:interfaces@@");
        if self.ip_missing {
            w(&format!("ip=missing\n1: lo: <LOOPBACK,UP,LOWER_UP> sysfs\n2: {}: <MULTICAST,UP,LOWER_UP> sysfs", self.iface));
            w("@@ll:addresses@@\n@@ll:routes@@\n@@ll:mcast_route@@");
            w(&format!(
                "@@ll:firewall@@\nufw={}\nfirewalld=\nnftables=inactive\n@@ll:daemon@@",
                self.firewall
            ));
            w(END);
            return s;
        }
        w("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536");
        let mc = if self.multicast {
            "BROADCAST,MULTICAST,"
        } else {
            "BROADCAST,"
        };
        w(&format!("3: {}: <{mc}UP,LOWER_UP> mtu 1500", self.iface));
        w("@@ll:addresses@@\n1: lo    inet 127.0.0.1/8 scope host lo");
        w(&format!(
            "3: {}    inet {}/24 brd x scope global {}",
            self.iface, self.addr, self.iface
        ));
        w(&format!(
            "@@ll:routes@@\ndefault via 10.42.0.1 dev {}",
            self.iface
        ));
        w(&format!(
            "@@ll:mcast_route@@\nmulticast 239.255.0.1 dev {} table local",
            self.iface
        ));
        w(&format!(
            "@@ll:firewall@@\nufw={}\nfirewalld=\nnftables=inactive",
            self.firewall
        ));
        w("@@ll:daemon@@");
        if let Some(d) = self.daemon {
            w(d);
        }
        w(END);
        s
    }

    fn phase2(&self, script: &str, peer: Option<u32>) -> String {
        let mut s = String::new();
        for (i, (path, xml)) in self.files.iter().enumerate() {
            if script.contains(path.as_str()) {
                s.push_str(&format!("@@ll:file{i}@@\npresent\n{xml}\n"));
            }
        }
        if script.contains("graph_nodes") {
            s.push_str(&format!("@@ll:graph_nodes@@\npid={}\n", self.pid));
            for n in &self.graph {
                s.push_str(&format!("{n}\n"));
            }
            s.push_str(&format!("/_ros2cli_{}\n", self.pid));
            if let Some(p) = peer {
                s.push_str(&format!("/_ros2cli_{p}\n"));
            }
            s.push_str("rc=0\n@@ll:graph_topics@@\npid=1\n/chatter [std_msgs/msg/String]\nrc=0\n");
        }
        s.push_str(END);
        s.push('\n');
        s
    }
}

struct Fake {
    devs: BTreeMap<String, Dev>,
    /// Pairs whose graph queries see each other.
    see: Vec<(String, String)>,
    scripts: Mutex<Vec<(String, String)>>,
}

impl Remote for Fake {
    fn run(&self, device: &str, script: &str, _t: Duration) -> Result<String, RemoteError> {
        self.scripts
            .lock()
            .unwrap()
            .push((device.into(), script.into()));
        let d = self
            .devs
            .get(device)
            .ok_or_else(|| RemoteError::NotLocated(device.into()))?;
        if script.contains("@@ll:host@@") {
            return Ok(d.phase1());
        }
        let peer = self
            .see
            .iter()
            .find(|(a, _)| a == device)
            .and_then(|(_, b)| self.devs.get(b))
            .map(|b| b.pid);
        Ok(d.phase2(script, peer))
    }
}

fn fake(devs: Vec<Dev>, see: &[(&str, &str)]) -> Fake {
    Fake {
        devs: devs.into_iter().map(|d| (d.host.to_string(), d)).collect(),
        see: see
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        scripts: Mutex::new(vec![]),
    }
}

fn opts() -> Options {
    Options {
        graph: true,
        ..Options::default()
    }
}

fn pair(f: &Fake, a: &str, b: &str) -> Report {
    let (ia, ib) = inspect::inspect_pair(f, a, b, &opts());
    let (ia, ib) = (ia.unwrap(), ib.unwrap());
    diagnose(&Input {
        a: Side { ins: &ia, ip: None },
        b: Some(Side { ins: &ib, ip: None }),
        active: None,
        timeout_ms: 30_000,
    })
}

fn get<'a>(r: &'a Report, id: &str) -> &'a Check {
    r.checks.iter().find(|c| c.id == id).unwrap()
}

#[test]
fn healthy_pair_reaches_level_3_but_never_4_without_the_probe() {
    let f = fake(
        vec![
            dev("orin", "10.42.0.20", 101),
            dev("laptop", "10.42.0.30", 202),
        ],
        &[("orin", "laptop"), ("laptop", "orin")],
    );
    let r = pair(&f, "orin", "laptop");
    assert_eq!(r.checks.len(), 12);
    for c in &r.checks {
        assert!(
            matches!(c.verdict, Verdict::Pass | Verdict::NotTested),
            "{} {:?}: {}",
            c.id,
            c.verdict,
            c.summary
        );
        assert!(
            !c.method.is_empty() && !c.endpoints.is_empty(),
            "{} lacks method/endpoints",
            c.id
        );
    }
    assert_eq!(get(&r, "client-isolation").verdict, Verdict::NotTested);
    assert_eq!(get(&r, "qos").verdict, Verdict::NotTested);
    assert_eq!(r.level, Some(3), "{:#?}", r.levels);
    assert_eq!(
        r.levels[3].verdict,
        Verdict::NotTested,
        "level 4 needs the active probe"
    );
    assert_eq!(r.path.as_ref().unwrap().a_interface, "wlan0");
    // Every remote script was read-only: no publishing, no daemon.
    for (_, s) in f.scripts.lock().unwrap().iter() {
        assert!(
            !s.contains("topic pub") && !s.contains("ros2 daemon") && !s.contains("multicast send")
        );
    }
}

#[test]
fn one_way_discovery_is_level_2() {
    let f = fake(
        vec![
            dev("orin", "10.42.0.20", 101),
            dev("laptop", "10.42.0.30", 202),
        ],
        &[("laptop", "orin")],
    );
    let r = pair(&f, "orin", "laptop");
    assert_eq!(r.levels[2].verdict, Verdict::Warn);
    assert!(
        r.levels[2].detail.contains("one direction only"),
        "{}",
        r.levels[2].detail
    );
    assert_eq!(r.level, Some(2));
}

#[test]
fn domain_mismatch_fails_and_caps_the_level() {
    let mut b = dev("laptop", "10.42.0.30", 202);
    b.node_env = vec!["ROS_DISTRO=humble", "ROS_DOMAIN_ID=8"];
    b.shell = vec![];
    let f = fake(vec![dev("orin", "10.42.0.20", 101), b], &[]);
    let r = pair(&f, "orin", "laptop");
    let d = get(&r, "domain");
    assert_eq!(d.verdict, Verdict::Fail);
    assert!(
        d.summary.contains("domain 7") && d.summary.contains("domain 8"),
        "{}",
        d.summary
    );
    assert_eq!(r.level, Some(0));
}

#[test]
fn shell_and_nodes_disagree_is_a_warning() {
    let mut a = dev("orin", "10.42.0.20", 101);
    a.shell = vec!["file=/home/u/.bashrc", "5:export ROS_DOMAIN_ID=3"];
    let f = fake(vec![a], &[]);
    let ia = inspect::inspect(&f, "orin", &Options::default()).unwrap();
    let r = diagnose(&Input {
        a: Side { ins: &ia, ip: None },
        b: None,
        active: None,
        timeout_ms: 1000,
    });
    let d = get(&r, "domain");
    assert_eq!(d.verdict, Verdict::Warn);
    assert!(d.summary.contains("nodes run on domain 7"), "{}", d.summary);
    assert_eq!(r.level, None, "no level without a peer");
    assert_eq!(get(&r, "routing").verdict, Verdict::NotTested);
}

#[test]
fn cyclone_bound_to_a_missing_interface_fails() {
    // The spec's example: a Cyclone config naming enP8p1s0 while wlan0 is active.
    let mut a = dev("orin", "10.42.0.20", 101);
    a.node_env = vec![
        "ROS_DISTRO=humble",
        "ROS_DOMAIN_ID=7",
        "RMW_IMPLEMENTATION=rmw_cyclonedds_cpp",
        "CYCLONEDDS_URI=file:///home/u/cyclone.xml",
    ];
    a.files.insert(
        "/home/u/cyclone.xml".into(),
        r#"<CycloneDDS><Domain><General><Interfaces><NetworkInterface name="enP8p1s0"/></Interfaces></General></Domain></CycloneDDS>"#.into(),
    );
    let mut b = dev("laptop", "10.42.0.30", 202);
    b.node_env = vec![
        "ROS_DISTRO=humble",
        "ROS_DOMAIN_ID=7",
        "RMW_IMPLEMENTATION=rmw_cyclonedds_cpp",
    ];
    let f = fake(vec![a, b], &[]);
    let r = pair(&f, "orin", "laptop");
    let c = get(&r, "interface-binding");
    assert_eq!(c.verdict, Verdict::Fail);
    assert!(
        c.summary.contains("enP8p1s0") && c.summary.contains("does not exist"),
        "{}",
        c.summary
    );
    assert!(
        c.summary.contains("wlan0"),
        "lists the real interfaces: {}",
        c.summary
    );
    assert!(c.hint.as_deref().unwrap().contains("does not rewrite"));
    assert_eq!(r.levels[1].verdict, Verdict::Fail);
}

#[test]
fn cyclone_bound_to_the_wrong_existing_interface_fails() {
    let mut a = dev("orin", "10.42.0.20", 101);
    a.node_env = vec!["ROS_DISTRO=humble", "ROS_DOMAIN_ID=7", "CYCLONEDDS_URI=<CycloneDDS><Domain><General><Interfaces><NetworkInterface name=\"lo\"/></Interfaces></General></Domain></CycloneDDS>"];
    let f = fake(vec![a, dev("laptop", "10.42.0.30", 202)], &[]);
    let r = pair(&f, "orin", "laptop");
    let c = get(&r, "interface-binding");
    assert_eq!(c.verdict, Verdict::Fail);
    assert!(
        c.summary.contains("reached through 'wlan0'"),
        "{}",
        c.summary
    );
}

#[test]
fn rmw_localhost_range_firewall_daemon_and_peers() {
    let mut a = dev("orin", "10.42.0.20", 101);
    a.node_env = vec![
        "ROS_DISTRO=humble",
        "ROS_DOMAIN_ID=7",
        "RMW_IMPLEMENTATION=rmw_connextdds",
        "ROS_LOCALHOST_ONLY=1",
        "ROS_STATIC_PEERS=10.42.0.99",
    ];
    a.firewall = "active";
    a.daemon = Some("pid=55 --rmw-implementation rmw_fastrtps_cpp --ros-domain-id 0 ");
    a.multicast = false;
    let f = fake(vec![a, dev("laptop", "10.42.0.30", 202)], &[]);
    let r = pair(&f, "orin", "laptop");
    assert_eq!(
        get(&r, "rmw").verdict,
        Verdict::Fail,
        "{}",
        get(&r, "rmw").summary
    );
    assert_eq!(get(&r, "localhost-only").verdict, Verdict::Fail);
    assert_eq!(get(&r, "firewall").verdict, Verdict::Warn);
    assert!(
        get(&r, "firewall")
            .hint
            .as_deref()
            .unwrap()
            .contains("UDP 9150-9399"),
        "domain 7 ports"
    );
    assert_eq!(get(&r, "cached-graph").verdict, Verdict::Warn);
    assert_eq!(get(&r, "peers").verdict, Verdict::Warn);
    assert!(get(&r, "peers").summary.contains("10.42.0.99"));
    assert_eq!(get(&r, "multicast").verdict, Verdict::Fail);
}

#[test]
fn humble_ignores_the_discovery_range_jazzy_honours_it() {
    let mut a = dev("orin", "10.42.0.20", 101);
    a.node_env = vec![
        "ROS_DISTRO=humble",
        "ROS_DOMAIN_ID=7",
        "ROS_AUTOMATIC_DISCOVERY_RANGE=LOCALHOST",
    ];
    let f = fake(vec![a, dev("laptop", "10.42.0.30", 202)], &[]);
    let r = pair(&f, "orin", "laptop");
    let c = get(&r, "discovery-restrictions");
    assert_eq!(c.verdict, Verdict::Warn);
    assert!(c.summary.contains("Humble ignores it"));
}

#[test]
fn different_subnets_warn_and_qos_conflicts_fail() {
    let b = dev("laptop", "192.168.50.30", 202);
    let f = fake(vec![dev("orin", "10.42.0.20", 101), b], &[]);
    let r = pair(&f, "orin", "laptop");
    assert_eq!(get(&r, "routing").verdict, Verdict::Warn);
    assert!(r.path.is_none());
    let q = inspect::parse_topic_info(
        "/scan",
        &"Node name: lidar\nEndpoint type: PUBLISHER\n  Reliability: BEST_EFFORT\n  Durability: VOLATILE\nNode name: slam\nEndpoint type: SUBSCRIPTION\n  Reliability: RELIABLE\n  Durability: VOLATILE\nrc=0"
            .lines()
            .map(String::from)
            .collect::<Vec<_>>(),
    );
    assert_eq!(qos_conflicts(&q).len(), 1);
}

#[test]
fn active_results_drive_levels_1_and_4() {
    let f = fake(
        vec![
            dev("orin", "10.42.0.20", 101),
            dev("laptop", "10.42.0.30", 202),
        ],
        &[("orin", "laptop"), ("laptop", "orin")],
    );
    let (ia, ib) = inspect::inspect_pair(&f, "orin", "laptop", &opts());
    let (ia, ib) = (ia.unwrap(), ib.unwrap());
    let p = |name: &str, v: Verdict| Probe {
        name: name.into(),
        from: "orin".into(),
        to: "laptop".into(),
        verdict: v,
        summary: format!("{name} {}", v.label()),
        evidence: vec![],
        method: "m".into(),
        interface: Some("wlan0".into()),
        timeout_ms: 8000,
    };
    let mk = |pubsub: Verdict, mcast: Verdict| ActiveReport {
        topic: "/lablink_probe_x".into(),
        domain: 7,
        ping_ab: p("ping", Verdict::Pass),
        ping_ba: p("ping", Verdict::Pass),
        multicast_ab: p("multicast", mcast),
        multicast_ba: p("multicast", mcast),
        pubsub_ab: p("pubsub", pubsub),
        pubsub_ba: p("pubsub", pubsub),
        leftover: vec![],
    };
    let run = |a: &ActiveReport| {
        diagnose(&Input {
            a: Side { ins: &ia, ip: None },
            b: Some(Side { ins: &ib, ip: None }),
            active: Some(a),
            timeout_ms: 1,
        })
    };
    let good = mk(Verdict::Pass, Verdict::Pass);
    let r = run(&good);
    assert_eq!(r.level, Some(4));
    assert_eq!(get(&r, "client-isolation").verdict, Verdict::Pass);
    let filtered = mk(Verdict::Fail, Verdict::Fail);
    let r = run(&filtered);
    assert_eq!(r.level, Some(3));
    assert_eq!(get(&r, "client-isolation").verdict, Verdict::Warn);
    assert!(get(&r, "client-isolation")
        .summary
        .contains("filters multicast"));
}

#[test]
fn same_pid_falls_back_to_named_nodes() {
    let mut a = dev("orin", "10.42.0.20", 22);
    a.node_name = Some("talker");
    a.graph = vec!["/talker".into(), "/listener".into()];
    let mut b = dev("laptop", "10.42.0.30", 22);
    b.node_name = Some("listener");
    b.graph = vec!["/talker".into(), "/listener".into()];
    let f = fake(vec![a, b], &[]);
    let r = pair(&f, "orin", "laptop");
    assert_eq!(r.levels[2].verdict, Verdict::Pass, "{}", r.levels[2].detail);
    assert!(r.levels[2].detail.contains("listener"));
}

#[test]
fn unknown_device_errors_propagate() {
    let f = fake(vec![dev("orin", "10.42.0.20", 1)], &[]);
    let (_, b) = inspect::inspect_pair(&f, "orin", "nope", &opts());
    assert!(matches!(b, Err(RemoteError::NotLocated(_))));
}

#[test]
fn missing_ip_tool_is_unavailable_not_a_routing_failure() {
    let mut b = dev("laptop", "10.42.0.30", 202);
    b.ip_missing = true;
    b.container = true;
    let f = fake(
        vec![dev("orin", "10.42.0.20", 101), b],
        &[("orin", "laptop"), ("laptop", "orin")],
    );
    let (ia, ib) = inspect::inspect_pair(&f, "orin", "laptop", &opts());
    let (ia, ib) = (ia.unwrap(), ib.unwrap());
    assert!(!ib.ip_tool);
    assert!(ib.notes.iter().any(|n| n.contains("iproute2")));
    assert_eq!(
        ib.effective_domain(),
        7,
        "the --ros-args node wins over the container's init process"
    );
    assert!(
        ib.link("wlan0").is_some_and(|l| l.up && l.multicast),
        "sysfs fallback"
    );
    let r = diagnose(&Input {
        a: Side { ins: &ia, ip: None },
        b: Some(Side { ins: &ib, ip: None }),
        active: None,
        timeout_ms: 1,
    });
    assert_eq!(get(&r, "routing").verdict, Verdict::Unavailable);
    assert_eq!(r.level, Some(3), "{:#?}", r.levels);
}
