//! The remote scripts. Phase 1 ([`INSPECT`]) is a constant: it reads files
//! and `/proc` only, starts no ROS process and joins no DDS domain. Phase 2
//! ([`phase2`]) reads the DDS config files phase 1 found and, only when
//! asked, queries the ROS graph with `--no-daemon` (so no `ros2 daemon` is
//! left behind) under bounded `timeout`s. Every parameter is validated by
//! the caller and checked again here, then shell-quoted.

use crate::env::{valid_distro, valid_path, valid_range, valid_rmw, RosEnv};
use lablink_ssh::shell_quote;
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub const END: &str = "@@ll:end@@";

/// Skips the processes of this SSH session (its own shell and pipeline).
const OWN_SESSION: &str = r#"own_sid=$(sed 's/.*) //' /proc/$$/stat 2>/dev/null | cut -d' ' -f4)
not_ours() { [ "$(sed 's/.*) //' "$1/stat" 2>/dev/null | cut -d' ' -f4)" != "$own_sid" ]; }
"#;

pub const INSPECT: &str = r#"LC_ALL=C; export LC_ALL
echo @@ll:host@@
echo "home=$HOME"
echo "user=$(id -un 2>/dev/null)"
echo "hostname=$(hostname 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
[ -r /etc/os-release ] && grep -E '^(ID|VERSION_ID)=' /etc/os-release
if command -v bash >/dev/null 2>&1; then echo bash=yes; else echo bash=no; fi
echo @@ll:distros@@
for d in /opt/ros/*/; do
  [ -f "${d}setup.bash" ] || continue
  r=no; [ -x "${d}bin/ros2" ] && r=yes
  echo "distro=$(basename "$d") ros2=$r"
  for l in "${d}"lib/librmw_*_cpp.so; do [ -e "$l" ] && echo "  rmw=$(basename "$l" .so | sed 's/^lib//')"; done
done
echo @@ll:session_env@@
env | grep -E '^(ROS_DISTRO|ROS_DOMAIN_ID|ROS_LOCALHOST_ONLY|ROS_AUTOMATIC_DISCOVERY_RANGE|ROS_STATIC_PEERS|RMW_IMPLEMENTATION|CYCLONEDDS_URI|FASTRTPS_DEFAULT_PROFILES_FILE|FASTDDS_DEFAULT_PROFILES_FILE|ROS_DISCOVERY_SERVER|FASTDDS_BUILTIN_TRANSPORTS)=' | cut -c1-4000 | head -n 20
echo @@ll:shell_files@@
for f in /etc/environment /etc/profile.d/*.sh "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.bashrc"; do
  [ -r "$f" ] || continue
  echo "file=$f"
  grep -nE '^[[:space:]]*(export[[:space:]]+)?(ROS_DISTRO|ROS_DOMAIN_ID|ROS_LOCALHOST_ONLY|ROS_AUTOMATIC_DISCOVERY_RANGE|ROS_STATIC_PEERS|RMW_IMPLEMENTATION|CYCLONEDDS_URI|FASTRTPS_DEFAULT_PROFILES_FILE|FASTDDS_DEFAULT_PROFILES_FILE|ROS_DISCOVERY_SERVER|FASTDDS_BUILTIN_TRANSPORTS)=|^[[:space:]]*(source|\.)[[:space:]]+[^#]*setup\.(bash|sh)' "$f" 2>/dev/null | cut -c1-4000 | head -n 40
done
echo @@ll:processes@@
@OWN_SESSION@n=0
for p in /proc/[0-9]*; do
  [ -r "$p/environ" ] || continue
  not_ours "$p" || continue
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -qE '^(ROS_DISTRO|AMENT_PREFIX_PATH)=' || continue
  n=$((n+1))
  if [ $n -gt 40 ]; then echo truncated; break; fi
  echo "pid=${p#/proc/} comm=$(cat "$p/comm" 2>/dev/null)"
  echo "  node=$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | sed -n 's/^__node:=//p' | head -n 1 | cut -c1-120)"
  case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in *--ros-args*) echo "  rosargs=yes";; esac
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^(ROS_DISTRO|ROS_DOMAIN_ID|ROS_LOCALHOST_ONLY|ROS_AUTOMATIC_DISCOVERY_RANGE|ROS_STATIC_PEERS|RMW_IMPLEMENTATION|CYCLONEDDS_URI|FASTRTPS_DEFAULT_PROFILES_FILE|FASTDDS_DEFAULT_PROFILES_FILE|ROS_DISCOVERY_SERVER|FASTDDS_BUILTIN_TRANSPORTS)=' | cut -c1-4000 | sed 's/^/  env /'
done
echo @@ll:unreadable@@
u=0
for p in /proc/[0-9]*; do
  [ -r "$p/environ" ] && continue
  case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in *--ros-args*|*/opt/ros/*) u=$((u+1));; esac
done
echo "count=$u"
echo @@ll:interfaces@@
if command -v ip >/dev/null 2>&1; then
  ip -o link show 2>&1 | head -n 40
else
  echo "ip=missing"
  n=0
  for i in /sys/class/net/*; do
    [ -r "$i/flags" ] || continue
    n=$((n+1)); f=$(($(cat "$i/flags"))); fl=""
    [ $((f & 8)) -ne 0 ] && fl="${fl}LOOPBACK,"
    [ $((f & 4096)) -ne 0 ] && fl="${fl}MULTICAST,"
    [ $((f & 1)) -ne 0 ] && fl="${fl}UP,"
    [ "$(cat "$i/operstate" 2>/dev/null)" = up ] && fl="${fl}LOWER_UP,"
    echo "$n: ${i##*/}: <${fl%,}> sysfs"
  done
fi
echo @@ll:addresses@@
command -v ip >/dev/null 2>&1 && ip -o -4 addr show 2>&1 | head -n 60
echo @@ll:routes@@
command -v ip >/dev/null 2>&1 && ip -4 route show 2>&1 | head -n 60
echo @@ll:mcast_route@@
command -v ip >/dev/null 2>&1 && ip -4 route get 239.255.0.1 2>&1 | head -n 2
echo @@ll:firewall@@
for s in ufw firewalld nftables; do echo "$s=$(systemctl is-active "$s" 2>/dev/null)"; done
[ -r /etc/ufw/ufw.conf ] && grep -E '^ENABLED=' /etc/ufw/ufw.conf
echo @@ll:daemon@@
for p in /proc/[0-9]*; do
  not_ours "$p" || continue
  c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$c" in *_ros2_daemon*) echo "pid=${p#/proc/} $(echo "$c" | grep -oE -- '--(rmw-implementation|ros-domain-id) [^ ]+' | tr '\n' ' ')";; esac
done
echo @@ll:end@@
"#;

/// The phase-1 script, ready to run.
pub fn inspect_script() -> String {
    INSPECT.replace("@OWN_SESSION@", OWN_SESSION)
}

/// Split output into named sections. `None` without the end marker (the
/// session did not complete).
pub fn sections(stdout: &str) -> Option<BTreeMap<String, Vec<String>>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        if line == END {
            return Some(map);
        }
        if let Some(name) = line
            .strip_prefix("@@ll:")
            .and_then(|r| r.strip_suffix("@@"))
        {
            map.entry(name.to_string()).or_default();
            cur = Some(name.to_string());
            continue;
        }
        if let Some(c) = &cur {
            map.get_mut(c).unwrap().push(line.to_string());
        }
    }
    None
}

/// The environment a graph query runs in: what the robot's nodes use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEnv {
    pub distro: String,
    pub domain: Option<u32>,
    pub rmw: Option<String>,
    pub localhost_only: bool,
    pub range: Option<String>,
    pub cyclone_uri: Option<String>,
    pub fastdds_profile: Option<String>,
}

impl QueryEnv {
    /// From an environment, keeping only values that pass validation.
    pub fn from_env(distro: &str, e: &RosEnv) -> QueryEnv {
        QueryEnv {
            distro: distro.to_string(),
            domain: e.domain().ok().flatten(),
            rmw: e.rmw().filter(|r| valid_rmw(r)).map(str::to_string),
            localhost_only: e.localhost_only(),
            range: e
                .discovery_range()
                .filter(|r| valid_range(r))
                .map(str::to_string),
            cyclone_uri: e
                .get("CYCLONEDDS_URI")
                .filter(|u| valid_cyclone_uri(u))
                .map(str::to_string),
            fastdds_profile: e
                .get("FASTDDS_DEFAULT_PROFILES_FILE")
                .or(e.get("FASTRTPS_DEFAULT_PROFILES_FILE"))
                .filter(|u| valid_path(u))
                .map(str::to_string),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if !valid_distro(&self.distro) {
            return Err(format!("invalid distro '{}'", self.distro));
        }
        if self.domain.is_some_and(|d| d > 232) {
            return Err("invalid domain".into());
        }
        if self.rmw.as_deref().is_some_and(|r| !valid_rmw(r)) {
            return Err("invalid RMW".into());
        }
        if self.range.as_deref().is_some_and(|r| !valid_range(r)) {
            return Err("invalid discovery range".into());
        }
        if self
            .cyclone_uri
            .as_deref()
            .is_some_and(|u| !valid_cyclone_uri(u))
        {
            return Err("invalid CYCLONEDDS_URI".into());
        }
        if self
            .fastdds_profile
            .as_deref()
            .is_some_and(|p| !valid_path(p))
        {
            return Err("invalid config path".into());
        }
        Ok(())
    }

    /// `bash` commands that set exactly this environment.
    pub(crate) fn prelude(&self) -> String {
        let mut s = String::from(
            "unset ROS_DOMAIN_ID RMW_IMPLEMENTATION ROS_LOCALHOST_ONLY ROS_AUTOMATIC_DISCOVERY_RANGE ROS_STATIC_PEERS CYCLONEDDS_URI FASTRTPS_DEFAULT_PROFILES_FILE FASTDDS_DEFAULT_PROFILES_FILE; ",
        );
        let _ = write!(s, ". /opt/ros/{}/setup.bash >/dev/null 2>&1; ", self.distro);
        if let Some(d) = self.domain {
            let _ = write!(s, "export ROS_DOMAIN_ID={d}; ");
        }
        if let Some(r) = &self.rmw {
            let _ = write!(s, "export RMW_IMPLEMENTATION={r}; ");
        }
        if self.localhost_only {
            s.push_str("export ROS_LOCALHOST_ONLY=1; ");
        }
        if let Some(r) = &self.range {
            let _ = write!(s, "export ROS_AUTOMATIC_DISCOVERY_RANGE={r}; ");
        }
        if let Some(p) = &self.cyclone_uri {
            let _ = write!(s, "export CYCLONEDDS_URI={}; ", shell_quote(p));
        }
        if let Some(p) = &self.fastdds_profile {
            let _ = write!(
                s,
                "export FASTRTPS_DEFAULT_PROFILES_FILE={}; ",
                shell_quote(p)
            );
        }
        s
    }
}

/// `CYCLONEDDS_URI` values passed back to the same device's graph query:
/// file paths (`file://` or plain) that pass [`valid_path`], or inline XML
/// without control characters. Always shell-quoted.
pub fn valid_cyclone_uri(u: &str) -> bool {
    let u = u.trim();
    if u.starts_with('<') {
        return u.len() <= 4000 && !u.chars().any(|c| c.is_control() && !c.is_whitespace());
    }
    !u.is_empty()
        && u.split(',')
            .map(|p| p.trim())
            .all(|p| valid_path(p.strip_prefix("file://").unwrap_or(p)))
}

/// A ROS topic name LabLink may pass to `ros2 topic info`.
pub fn valid_topic(t: &str) -> bool {
    t.starts_with('/')
        && t.len() <= 256
        && !t.contains("//")
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/')
}

/// What phase 2 does.
#[derive(Debug, Clone, Default)]
pub struct Phase2 {
    /// DDS config files to read (validated absolute paths).
    pub files: Vec<String>,
    /// Query the graph in this environment.
    pub graph: Option<QueryEnv>,
    /// Topics to read endpoint QoS of (`ros2 topic info -v`).
    pub qos_topics: Vec<String>,
    /// Seconds each graph query waits for discovery.
    pub spin_s: u32,
}

/// One bounded `ros2` command in the graph environment. It prints its pid
/// first: a daemonless query shows up in the graph as the hidden node
/// `/_ros2cli_<pid>`, which is how two concurrent queries on two devices
/// recognise each other.
pub(crate) fn ros2(s: &mut String, section: &str, env: &QueryEnv, args: &str, limit: u32) {
    let cmd = format!(
        "{}ros2 {args} & p=$!; echo \"pid=$p\"; wait $p; echo \"rc=$?\"",
        env.prelude()
    );
    let _ = writeln!(
        s,
        "echo @@ll:{section}@@\ntimeout -k 2 {limit} bash --norc --noprofile -c {} 2>&1 | head -n 400",
        shell_quote(&cmd)
    );
}

pub fn phase2(p: &Phase2) -> Result<String, String> {
    let mut s = String::from("LC_ALL=C; export LC_ALL\n");
    for (i, f) in p.files.iter().enumerate().take(6) {
        if !valid_path(f) {
            return Err(format!("refusing to read '{f}'"));
        }
        let q = shell_quote(f);
        let _ = writeln!(
            s,
            "echo @@ll:file{i}@@\nif [ -f {q} ] && [ -r {q} ]; then echo present; head -c 65536 {q}; echo; else echo missing; fi"
        );
    }
    if let Some(env) = &p.graph {
        env.validate()?;
        let spin = p.spin_s.clamp(1, 10);
        let limit = spin + 10;
        ros2(
            &mut s,
            "graph_nodes",
            env,
            &format!("node list -a --no-daemon --spin-time {spin}"),
            limit,
        );
        ros2(
            &mut s,
            "graph_topics",
            env,
            &format!("topic list -t --no-daemon --spin-time {spin}"),
            limit,
        );
        for (i, t) in p.qos_topics.iter().enumerate().take(5) {
            if !valid_topic(t) {
                return Err(format!("invalid topic name '{t}'"));
            }
            ros2(
                &mut s,
                &format!("qos{i}"),
                env,
                &format!(
                    "topic info -v {} --no-daemon --spin-time {spin}",
                    shell_quote(t)
                ),
                limit,
            );
        }
    }
    s.push_str("echo ");
    s.push_str(END);
    s.push('\n');
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_is_read_only() {
        let s = inspect_script();
        assert!(!s.contains("@OWN_SESSION@"));
        for bad in [
            "ros2 ",
            "rm ",
            "kill",
            "sudo",
            "systemctl restart",
            "systemctl stop",
            " > /",
            ">>",
            "tee ",
            "ros2 daemon",
            "ros2 topic pub",
            "ros2 service call",
            "ros2 param set",
            "iptables",
            "ufw allow",
            "ufw enable",
            "ufw disable",
            "nft ",
        ] {
            assert!(!s.contains(bad), "phase 1 contains '{bad}'");
        }
        assert!(s.ends_with("echo @@ll:end@@\n"));
    }

    #[test]
    fn sections_need_the_end_marker() {
        assert!(sections("@@ll:host@@\nhome=/h\n").is_none());
        let m =
            sections("junk\n@@ll:host@@\nhome=/h\n@@ll:distros@@\n@@ll:end@@\nafter\n").unwrap();
        assert_eq!(m["host"], ["home=/h"]);
        assert!(m["distros"].is_empty());
    }

    fn env() -> QueryEnv {
        QueryEnv {
            distro: "humble".into(),
            domain: Some(42),
            rmw: Some("rmw_cyclonedds_cpp".into()),
            localhost_only: false,
            range: None,
            cyclone_uri: Some("file:///home/u/cyclone.xml".into()),
            fastdds_profile: None,
        }
    }

    #[test]
    fn phase2_uses_no_daemon_timeouts_and_exact_env() {
        let s = phase2(&Phase2 {
            files: vec!["/home/u/cyclone.xml".into()],
            graph: Some(env()),
            qos_topics: vec!["/cmd_vel".into()],
            spin_s: 3,
        })
        .unwrap();
        assert!(s.contains("head -c 65536 /home/u/cyclone.xml"));
        assert_eq!(s.matches("--no-daemon").count(), 3);
        assert_eq!(
            s.matches("timeout -k 2 13 bash --norc --noprofile -c")
                .count(),
            3
        );
        assert!(s.contains("export ROS_DOMAIN_ID=42"));
        assert!(s.contains("RMW_IMPLEMENTATION=rmw_cyclonedds_cpp"));
        assert!(s.contains("CYCLONEDDS_URI=file:///home/u/cyclone.xml"));
        assert!(s.contains("topic info -v /cmd_vel"));
        for bad in [
            "topic pub",
            "service call",
            "param set",
            "daemon stop",
            "daemon start",
        ] {
            assert!(!s.contains(bad));
        }
    }

    #[test]
    fn phase2_refuses_invalid_parameters() {
        let mut e = env();
        e.distro = "humble; reboot".into();
        assert!(phase2(&Phase2 {
            graph: Some(e),
            spin_s: 2,
            ..Default::default()
        })
        .is_err());
        let mut e = env();
        e.rmw = Some("rmw_x$(id)".into());
        assert!(phase2(&Phase2 {
            graph: Some(e),
            spin_s: 2,
            ..Default::default()
        })
        .is_err());
        assert!(phase2(&Phase2 {
            files: vec!["/etc/../etc/shadow".into()],
            ..Default::default()
        })
        .is_err());
        assert!(phase2(&Phase2 {
            graph: Some(env()),
            qos_topics: vec!["/a; rm -rf ~".into()],
            spin_s: 2,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn query_env_drops_invalid_values() {
        let e = RosEnv::from_lines([
            "ROS_DOMAIN_ID=999",
            "RMW_IMPLEMENTATION=evil;cmd",
            "CYCLONEDDS_URI=<CycloneDDS/>",
            "ROS_AUTOMATIC_DISCOVERY_RANGE=SUBNET",
        ]);
        let q = QueryEnv::from_env("jazzy", &e);
        assert_eq!(q.domain, None);
        assert_eq!(q.rmw, None);
        assert_eq!(
            q.cyclone_uri.as_deref(),
            Some("<CycloneDDS/>"),
            "inline XML is passed back, quoted"
        );
        assert_eq!(q.range.as_deref(), Some("SUBNET"));
        let q = QueryEnv::from_env(
            "jazzy",
            &RosEnv::from_lines(["CYCLONEDDS_URI=file:///x/../y"]),
        );
        assert_eq!(q.cyclone_uri, None);
        assert!(
            !valid_cyclone_uri("<a>\u{7}</a>"),
            "control characters are refused"
        );
        assert!(valid_topic("/robot/cmd_vel") && !valid_topic("cmd_vel") && !valid_topic("/a b"));
    }
}
