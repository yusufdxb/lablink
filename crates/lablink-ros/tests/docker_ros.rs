//! Simulated multi-machine test: the real remote scripts against ROS 2
//! containers (Humble and Jazzy) on a private Docker network, through a
//! `Remote` that uses `docker exec` instead of SSH. This is simulation, not
//! hardware validation. Needs Docker and the images `ros:humble-ros-base`
//! and `ros:jazzy-ros-base`; run with:
//!
//!     cargo test -p lablink-ros --test docker_ros -- --ignored --nocapture

use lablink_ros::diagnose::{self, Input, Side, Verdict};
use lablink_ros::inspect::{self, Options};
use lablink_ros::{active, Remote, RemoteError};
use std::process::{Command, Stdio};
use std::time::Duration;

const NET: &str = "lablink-ros-it";
const A: &str = "ll-it-humble-a";
const B: &str = "ll-it-humble-b";
const C: &str = "ll-it-humble-c";
const J: &str = "ll-it-jazzy";

struct DockerRemote;

impl Remote for DockerRemote {
    fn run(&self, device: &str, script: &str, timeout: Duration) -> Result<String, RemoteError> {
        let out = Command::new("timeout")
            .args([
                "-k",
                "2",
                &timeout.as_secs().max(1).to_string(),
                "docker",
                "exec",
                "-i",
                device,
                "sh",
                "-c",
                script,
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| RemoteError::Failed(e.to_string()))?;
        match out.status.code() {
            Some(124) => Err(RemoteError::Failed("timed out".into())),
            Some(0) | Some(1) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            c => Err(RemoteError::Failed(format!(
                "docker exec exited {c:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            ))),
        }
    }
}

fn docker(args: &[&str]) -> (bool, String) {
    let o = Command::new("docker").args(args).output().expect("docker");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).trim().to_string(),
    )
}

fn sh(c: &str, script: &str) {
    let (ok, _) = docker(&["exec", c, "bash", "-c", script]);
    assert!(ok, "setup in {c} failed: {script}");
}

const NODE: &str = r#"
import sys, rclpy
from rclpy.node import Node
from std_msgs.msg import String
rclpy.init(args=sys.argv)
n = Node('robot_node')
pub = n.create_publisher(String, '/chatter', 10)
sub = n.create_subscription(String, '/chatter', lambda m: None, 10)
n.create_timer(1.0, lambda: pub.publish(String(data='hi')))
rclpy.spin(n)
"#;

fn cleanup() {
    for c in [A, B, C, J] {
        let _ = Command::new("docker").args(["rm", "-f", c]).output();
    }
    let _ = Command::new("docker").args(["network", "rm", NET]).output();
}

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        cleanup();
    }
}

fn start(name: &str, image: &str, distro: &str, bashrc: &str, node: Option<(&str, &str)>) {
    let (ok, _) = docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--hostname",
        name,
        "--network",
        NET,
        image,
        "sleep",
        "600",
    ]);
    assert!(ok, "docker run {name}");
    if name != C {
        // iproute2 and ping, as on a real robot (the ROS base images lack
        // them; C is left without, to exercise that path).
        sh(name, "(apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 iputils-ping) >/dev/null 2>&1 || echo 'apt failed' >&2");
    }
    sh(
        name,
        &format!("printf '%s\\n' {} >> /root/.bashrc", shell_words(bashrc)),
    );
    sh(name, &format!("cat > /tmp/node.py <<'EOF'\n{NODE}\nEOF"));
    if let Some((domain, node_name)) = node {
        let (ok, _) = docker(&[
            "exec",
            "-d",
            "-e",
            &format!("ROS_DOMAIN_ID={domain}"),
            name,
            "bash",
            "-c",
            &format!(". /opt/ros/{distro}/setup.bash; exec python3 /tmp/node.py --ros-args -r __node:={node_name}"),
        ]);
        assert!(ok);
    }
}

fn shell_words(s: &str) -> String {
    s.lines()
        .map(|l| format!("'{}'", l.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ip(c: &str) -> std::net::Ipv4Addr {
    let (_, o) = docker(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        c,
    ]);
    o.parse().expect("container ip")
}

fn print(r: &diagnose::Report) {
    println!(
        "== {} <-> {:?} (active: {}) level {:?}",
        r.device, r.peer, r.active, r.level
    );
    for c in &r.checks {
        println!("  [{}] {}: {}", c.verdict.label(), c.title, c.summary);
    }
    for l in &r.levels {
        println!(
            "  L{} {} [{}] {}",
            l.level,
            l.name,
            l.verdict.label(),
            l.detail
        );
    }
}

#[test]
#[ignore = "needs Docker and ROS 2 images; simulated multi-machine test"]
fn simulated_ros_machines() {
    cleanup();
    let _g = Guard;
    let (ok, _) = docker(&["network", "create", NET]);
    assert!(ok, "network create");
    start(
        A,
        "ros:humble-ros-base",
        "humble",
        "source /opt/ros/humble/setup.bash\nexport ROS_DOMAIN_ID=7",
        Some(("7", "robot_talker")),
    );
    start(
        B,
        "ros:humble-ros-base",
        "humble",
        "source /opt/ros/humble/setup.bash\nexport ROS_DOMAIN_ID=7",
        Some(("7", "robot_listener")),
    );
    // Shift B's pid counter so the two query nodes get different pids.
    for _ in 0..3 {
        sh(B, "true");
    }
    start(
        C,
        "ros:humble-ros-base",
        "humble",
        "source /opt/ros/humble/setup.bash\nexport ROS_DOMAIN_ID=9\nexport RMW_IMPLEMENTATION=rmw_cyclonedds_cpp\nexport CYCLONEDDS_URI=file:///root/cyclone.xml",
        None,
    );
    sh(C, "printf '%s' '<CycloneDDS><Domain><General><Interfaces><NetworkInterface name=\"enP8p1s0\"/></Interfaces></General></Domain></CycloneDDS>' > /root/cyclone.xml");
    start(
        J,
        "ros:jazzy-ros-base",
        "jazzy",
        "source /opt/ros/jazzy/setup.bash\nexport ROS_DOMAIN_ID=7",
        Some(("7", "jazzy_node")),
    );
    std::thread::sleep(Duration::from_secs(3));
    let r = DockerRemote;
    let opts = Options {
        graph: true,
        qos_topics: vec!["/chatter".into()],
        spin_s: 5,
        timeout: Duration::from_secs(40),
    };

    // 1. Inspection of one machine.
    let ia = inspect::inspect(&r, A, &opts).expect("inspect A");
    println!(
        "A: distro {:?} source {} domain {} rmw {} procs {:?}",
        ia.distro,
        ia.effective_source.label(),
        ia.effective_domain(),
        ia.effective_rmw(),
        ia.processes
            .iter()
            .map(|p| (&p.comm, &p.node))
            .collect::<Vec<_>>()
    );
    assert_eq!(ia.distro.as_deref(), Some("humble"));
    assert_eq!(
        ia.effective_source,
        lablink_ros::env::EnvSource::RunningNodes
    );
    assert_eq!(ia.effective_domain(), 7);
    assert!(ia
        .processes
        .iter()
        .any(|p| p.node.as_deref() == Some("robot_talker")));
    assert!(ia.distros[0].rmws.contains(&"rmw_fastrtps_cpp".to_string()));
    let g = ia.graph.as_ref().unwrap();
    println!(
        "A graph: {:?} self {:?} cli {:?} err {:?}",
        g.nodes, g.self_node, g.cli_nodes, g.error
    );
    assert!(
        g.nodes.iter().any(|n| n == "/robot_talker"),
        "A sees its own node"
    );
    assert!(
        ia.qos.first().is_some_and(|q| !q.endpoints.is_empty()),
        "{:?}",
        ia.qos
    );

    // 2. Passive pair check A <-> B.
    let (ia, ib) = inspect::inspect_pair(&r, A, B, &opts);
    let (ia, ib) = (ia.unwrap(), ib.unwrap());
    for i in [&ia, &ib] {
        let g = i.graph.as_ref().unwrap();
        println!(
            "{} graph: {:?} self {:?} cli {:?} err {:?} took {} ms",
            i.device, g.nodes, g.self_node, g.cli_nodes, g.error, i.duration_ms
        );
    }
    let rep = diagnose::diagnose(&Input {
        a: Side {
            ins: &ia,
            ip: Some(ip(A)),
        },
        b: Some(Side {
            ins: &ib,
            ip: Some(ip(B)),
        }),
        active: None,
        timeout_ms: 40_000,
    });
    print(&rep);
    assert_eq!(
        rep.level,
        Some(3),
        "passive check proves discovery, never data exchange"
    );
    assert_eq!(rep.levels[3].verdict, Verdict::NotTested);

    // 3. Active pair check A <-> B: the robot nodes keep running untouched.
    let node_pid = |c: &str| {
        docker(&[
            "exec",
            c,
            "sh",
            "-c",
            "pgrep -f '__node:=robot_' | head -n1",
        ])
        .1
    };
    let (pa, pb) = (node_pid(A), node_pid(B));
    let act = active::run(&r, &ia, &ib, Some(ip(B)));
    println!("active: {act:#?}");
    let rep = diagnose::diagnose(&Input {
        a: Side {
            ins: &ia,
            ip: Some(ip(A)),
        },
        b: Some(Side {
            ins: &ib,
            ip: Some(ip(B)),
        }),
        active: Some(&act),
        timeout_ms: 40_000,
    });
    print(&rep);
    assert!(
        act.leftover.is_empty(),
        "probe processes left: {:?}",
        act.leftover
    );
    assert_eq!(act.pubsub_ab.verdict, Verdict::Pass);
    assert_eq!(act.pubsub_ba.verdict, Verdict::Pass);
    assert_eq!(rep.level, Some(4));
    assert_eq!(
        (node_pid(A), node_pid(B)),
        (pa, pb),
        "robot nodes were not restarted"
    );

    // 4. A misconfigured machine: shell files only, wrong domain, Cyclone
    //    selected but not installed, bound to an interface that does not exist.
    let (ia2, ic) = inspect::inspect_pair(&r, A, C, &opts);
    let (ia2, ic) = (ia2.unwrap(), ic.unwrap());
    assert_eq!(ic.effective_source, lablink_ros::env::EnvSource::ShellFiles);
    let rep = diagnose::diagnose(&Input {
        a: Side {
            ins: &ia2,
            ip: Some(ip(A)),
        },
        b: Some(Side {
            ins: &ic,
            ip: Some(ip(C)),
        }),
        active: None,
        timeout_ms: 40_000,
    });
    print(&rep);
    let v = |id: &str| rep.checks.iter().find(|c| c.id == id).unwrap().verdict;
    assert_eq!(v("domain"), Verdict::Fail);
    assert_eq!(v("interface-binding"), Verdict::Fail);
    assert_eq!(v("rmw"), Verdict::Fail);
    assert_eq!(rep.levels[1].verdict, Verdict::Fail);

    // 5. Humble <-> Jazzy: reported, whatever the outcome.
    let (ia3, ij) = inspect::inspect_pair(&r, A, J, &opts);
    let (ia3, ij) = (ia3.unwrap(), ij.unwrap());
    assert_eq!(ij.distro.as_deref(), Some("jazzy"));
    let rep = diagnose::diagnose(&Input {
        a: Side {
            ins: &ia3,
            ip: Some(ip(A)),
        },
        b: Some(Side {
            ins: &ij,
            ip: Some(ip(J)),
        }),
        active: None,
        timeout_ms: 40_000,
    });
    print(&rep);
    assert_eq!(
        rep.checks.iter().find(|c| c.id == "rmw").unwrap().verdict,
        Verdict::Warn,
        "mixed distributions warn"
    );
}
