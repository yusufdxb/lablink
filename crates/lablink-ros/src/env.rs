//! ROS 2 environment variables, from three places that often disagree:
//! the shell startup files (what a new terminal gets), the SSH session's
//! own environment, and the running ROS processes (what the nodes actually
//! use). Values are remote, untrusted text: they are validated here before
//! anything uses them, and only ever displayed otherwise.

use serde::Serialize;
use std::collections::BTreeMap;

/// The variables LabLink reads (and nothing else from an environment).
pub const VARS: [&str; 11] = [
    "ROS_DISTRO",
    "ROS_DOMAIN_ID",
    "ROS_LOCALHOST_ONLY",
    "ROS_AUTOMATIC_DISCOVERY_RANGE",
    "ROS_STATIC_PEERS",
    "RMW_IMPLEMENTATION",
    "CYCLONEDDS_URI",
    "FASTRTPS_DEFAULT_PROFILES_FILE",
    "FASTDDS_DEFAULT_PROFILES_FILE",
    "ROS_DISCOVERY_SERVER",
    "FASTDDS_BUILTIN_TRANSPORTS",
];

/// Distributions LabLink knows the defaults of.
pub const SUPPORTED_DISTROS: [&str; 2] = ["humble", "jazzy"];

/// One environment (a set of the [`VARS`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RosEnv {
    pub vars: BTreeMap<String, String>,
}

impl RosEnv {
    /// From `KEY=value` lines (other keys are ignored).
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> RosEnv {
        let mut vars = BTreeMap::new();
        for l in lines {
            if let Some((k, v)) = l.trim().split_once('=') {
                if VARS.contains(&k) {
                    vars.insert(k.to_string(), v.to_string());
                }
            }
        }
        RosEnv { vars }
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.vars
            .get(k)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    pub fn distro(&self) -> Option<&str> {
        self.get("ROS_DISTRO")
    }

    /// `ROS_DOMAIN_ID`, `Err` with the raw text when it is set but invalid.
    pub fn domain(&self) -> Result<Option<u32>, String> {
        match self.get("ROS_DOMAIN_ID") {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|d| *d <= 232)
                .map(Some)
                .ok_or_else(|| v.to_string()),
        }
    }

    pub fn rmw(&self) -> Option<&str> {
        self.get("RMW_IMPLEMENTATION")
    }

    pub fn localhost_only(&self) -> bool {
        self.get("ROS_LOCALHOST_ONLY") == Some("1")
    }

    pub fn discovery_range(&self) -> Option<&str> {
        self.get("ROS_AUTOMATIC_DISCOVERY_RANGE")
    }

    /// `ROS_STATIC_PEERS`: semicolon-separated addresses or host names.
    pub fn static_peers(&self) -> Vec<String> {
        self.get("ROS_STATIC_PEERS")
            .map(|v| {
                v.split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Where the effective environment came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvSource {
    /// The environment of the running ROS processes (most common one).
    RunningNodes,
    /// Parsed from the shell startup files (approximate: not executed).
    ShellFiles,
    /// The SSH session's environment.
    Session,
    /// Nothing set: ROS defaults.
    Defaults,
}

impl EnvSource {
    pub fn label(self) -> &'static str {
        match self {
            EnvSource::RunningNodes => "running ROS processes",
            EnvSource::ShellFiles => "shell startup files",
            EnvSource::Session => "SSH session environment",
            EnvSource::Defaults => "ROS defaults",
        }
    }
}

/// The default RMW of a distribution.
pub fn default_rmw(_distro: Option<&str>) -> &'static str {
    // Humble and Jazzy both default to Fast DDS.
    "rmw_fastrtps_cpp"
}

/// RMW names LabLink accepts to pass on (to a graph query).
pub fn valid_rmw(s: &str) -> bool {
    s.len() <= 64
        && s.starts_with("rmw_")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub fn valid_distro(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_lowercase())
}

pub fn valid_range(s: &str) -> bool {
    matches!(s, "SUBNET" | "LOCALHOST" | "OFF" | "SYSTEM_DEFAULT")
}

/// A local path LabLink may read (a DDS config file): absolute, no `..`,
/// a conservative character set.
pub fn valid_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 512
        && !s.split('/').any(|c| c == "..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@".contains(c))
}

/// One assignment found in a shell startup file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellLine {
    pub file: String,
    pub line: u32,
    pub key: String,
    pub value: String,
    /// The value uses something LabLink did not expand (`$(..)`, other
    /// variables), or the line is indented (maybe inside a condition).
    pub approximate: bool,
}

/// What the shell startup files set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ShellEnv {
    pub lines: Vec<ShellLine>,
    /// Distributions sourced (`source /opt/ros/<distro>/setup.bash`), in order.
    pub sourced: Vec<String>,
    /// Other setup files sourced (workspaces).
    pub overlays: Vec<String>,
}

impl ShellEnv {
    /// The last assignment of each variable wins, as in a shell.
    pub fn env(&self) -> RosEnv {
        let mut vars = BTreeMap::new();
        for l in &self.lines {
            vars.insert(l.key.clone(), l.value.clone());
        }
        if let Some(d) = self.sourced.last() {
            vars.entry("ROS_DISTRO".into()).or_insert_with(|| d.clone());
        }
        RosEnv { vars }
    }

    pub fn approximate(&self) -> bool {
        self.lines.iter().any(|l| l.approximate)
    }
}

/// Parse the `shell_files` section: `file=<path>` headers followed by
/// `grep -n` lines (`<n>:<text>`). `home` expands `~`, `$HOME`, `${HOME}`.
pub fn parse_shell_files(lines: &[String], home: &str) -> ShellEnv {
    let mut out = ShellEnv::default();
    let mut file = String::new();
    for raw in lines {
        if let Some(f) = raw.strip_prefix("file=") {
            file = f.to_string();
            continue;
        }
        let Some((n, text)) = raw.split_once(':') else {
            continue;
        };
        let Ok(n) = n.parse::<u32>() else { continue };
        let indented = text.starts_with([' ', '\t']);
        let t = text.trim();
        if let Some(rest) = t.strip_prefix("source ").or_else(|| t.strip_prefix(". ")) {
            let path = expand_home(unquote(rest.split('#').next().unwrap_or("").trim()), home);
            match path
                .strip_prefix("/opt/ros/")
                .and_then(|r| r.split_once('/'))
            {
                Some((d, _)) if valid_distro(d) => out.sourced.push(d.to_string()),
                _ => out.overlays.push(path),
            }
            continue;
        }
        let t = t.strip_prefix("export ").map(str::trim_start).unwrap_or(t);
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        if !VARS.contains(&k) {
            continue;
        }
        let v = strip_comment(v);
        let value = expand_home(unquote(v), home);
        let approximate = indented || value.contains('$') || value.contains('`');
        out.lines.push(ShellLine {
            file: file.clone(),
            line: n,
            key: k.to_string(),
            value,
            approximate,
        });
    }
    out
}

fn strip_comment(v: &str) -> &str {
    let v = v.trim();
    if v.starts_with('"') || v.starts_with('\'') {
        let q = v.chars().next().unwrap();
        return match v[1..].find(q) {
            Some(i) => &v[..i + 2],
            None => v,
        };
    }
    v.split_once(" #").map_or(v, |(a, _)| a).trim()
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

/// Expand `~/`, `$HOME` and `${HOME}` (nothing else).
pub fn expand_home(v: &str, home: &str) -> String {
    let v = match v.strip_prefix("~/") {
        Some(r) => format!("{home}/{r}"),
        None if v == "~" => home.to_string(),
        None => v.to_string(),
    };
    let v = v.replace("${HOME}", home);
    v.replace("$HOME", home)
}

/// A running process with a ROS environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RosProcess {
    pub pid: u32,
    pub comm: String,
    /// `__node:=` from its command line, when given.
    pub node: Option<String>,
    /// Its command line has `--ros-args` (a ROS node, not just a process
    /// that inherited a ROS environment).
    pub ros_args: bool,
    pub env: RosEnv,
}

/// Parse the `processes` section.
pub fn parse_processes(lines: &[String]) -> (Vec<RosProcess>, bool) {
    let mut out: Vec<RosProcess> = Vec::new();
    let mut truncated = false;
    for l in lines {
        if let Some(rest) = l.strip_prefix("pid=") {
            let (pid, comm) = rest.split_once(" comm=").unwrap_or((rest, ""));
            if let Ok(pid) = pid.trim().parse() {
                out.push(RosProcess {
                    pid,
                    comm: comm.trim().to_string(),
                    node: None,
                    ros_args: false,
                    env: RosEnv::default(),
                });
            }
        } else if let Some(n) = l.strip_prefix("  node=") {
            if let Some(p) = out.last_mut() {
                p.node = Some(n.trim().to_string()).filter(|s| !s.is_empty());
            }
        } else if l.trim() == "rosargs=yes" {
            if let Some(p) = out.last_mut() {
                p.ros_args = true;
            }
        } else if let Some(e) = l.strip_prefix("  env ") {
            if let (Some(p), Some((k, v))) = (out.last_mut(), e.split_once('=')) {
                if VARS.contains(&k) {
                    p.env.vars.insert(k.to_string(), v.to_string());
                }
            }
        } else if l.trim() == "truncated" {
            truncated = true;
        }
    }
    (out, truncated)
}

/// The most common environment among the processes, and whether they all
/// agree on the variables that decide discovery.
pub fn consensus(procs: &[RosProcess]) -> Option<(RosEnv, bool)> {
    let mut counts: Vec<(RosEnv, usize)> = Vec::new();
    for p in procs {
        let key = discovery_view(&p.env);
        match counts.iter_mut().find(|(e, _)| *e == key) {
            Some((_, n)) => *n += 1,
            None => counts.push((key, 1)),
        }
    }
    let agree = counts.len() == 1;
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let top = counts.into_iter().next()?.0;
    // Return the full env of a process that has the winning view.
    let full = procs
        .iter()
        .find(|p| discovery_view(&p.env) == top)
        .map(|p| p.env.clone())
        .unwrap_or(top);
    Some((full, agree))
}

/// Only the variables that decide whether two participants discover each other.
pub fn discovery_view(e: &RosEnv) -> RosEnv {
    let keep = [
        "ROS_DOMAIN_ID",
        "ROS_LOCALHOST_ONLY",
        "ROS_AUTOMATIC_DISCOVERY_RANGE",
        "ROS_STATIC_PEERS",
        "RMW_IMPLEMENTATION",
        "CYCLONEDDS_URI",
        "FASTRTPS_DEFAULT_PROFILES_FILE",
        "FASTDDS_DEFAULT_PROFILES_FILE",
        "ROS_DISCOVERY_SERVER",
        "FASTDDS_BUILTIN_TRANSPORTS",
    ];
    RosEnv {
        vars: e
            .vars
            .iter()
            .filter(|(k, v)| keep.contains(&k.as_str()) && !v.is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn shell_files_last_assignment_wins_and_home_expands() {
        let e = parse_shell_files(
            &s(&[
                "file=/etc/profile.d/ros.sh",
                "3:export ROS_DOMAIN_ID=7",
                "file=/home/u/.bashrc",
                "118:source /opt/ros/humble/setup.bash",
                "119:source ~/ws/install/setup.bash  # overlay",
                "120:export ROS_DOMAIN_ID=42 # robot",
                "121:export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp",
                "122:export CYCLONEDDS_URI=file://$HOME/cyclone.xml",
                "123:  export ROS_LOCALHOST_ONLY=1",
                "124:export PATH=/x",
                "125:export ROS_STATIC_PEERS=\"$(cat /etc/peers)\"",
            ]),
            "/home/u",
        );
        let env = e.env();
        assert_eq!(env.domain(), Ok(Some(42)));
        assert_eq!(env.distro(), Some("humble"));
        assert_eq!(env.rmw(), Some("rmw_cyclonedds_cpp"));
        assert_eq!(
            env.get("CYCLONEDDS_URI"),
            Some("file:///home/u/cyclone.xml")
        );
        assert_eq!(e.sourced, ["humble"]);
        assert_eq!(e.overlays, ["/home/u/ws/install/setup.bash"]);
        assert!(
            e.lines
                .iter()
                .find(|l| l.key == "ROS_LOCALHOST_ONLY")
                .unwrap()
                .approximate,
            "indented"
        );
        assert!(
            e.lines
                .iter()
                .find(|l| l.key == "ROS_STATIC_PEERS")
                .unwrap()
                .approximate
        );
        assert!(
            !e.lines
                .iter()
                .find(|l| l.key == "ROS_DOMAIN_ID" && l.line == 120)
                .unwrap()
                .approximate
        );
        assert!(!e.lines.iter().any(|l| l.key == "PATH"));
    }

    #[test]
    fn domain_validation() {
        let e = RosEnv::from_lines(["ROS_DOMAIN_ID=233"]);
        assert_eq!(e.domain(), Err("233".into()));
        let e = RosEnv::from_lines(["ROS_DOMAIN_ID=abc"]);
        assert!(e.domain().is_err());
        let e = RosEnv::from_lines(["ROS_DOMAIN_ID="]);
        assert_eq!(e.domain(), Ok(None));
        let e = RosEnv::from_lines(["ROS_DOMAIN_ID= 5", "SECRET=x"]);
        assert_eq!(e.domain(), Ok(Some(5)));
        assert!(
            !e.vars.contains_key("SECRET"),
            "only ROS variables are kept"
        );
    }

    #[test]
    fn processes_and_consensus() {
        let (p, truncated) = parse_processes(&s(&[
            "pid=101 comm=talker",
            "  node=talker",
            "  env ROS_DISTRO=humble",
            "  env ROS_DOMAIN_ID=5",
            "  env AWS_SECRET=leak",
            "pid=102 comm=listener",
            "  env ROS_DISTRO=humble",
            "  env ROS_DOMAIN_ID=5",
            "pid=103 comm=bash",
            "  env ROS_DISTRO=humble",
            "  env ROS_DOMAIN_ID=0",
            "truncated",
        ]));
        assert!(truncated);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].node.as_deref(), Some("talker"));
        assert!(!p[0].env.vars.contains_key("AWS_SECRET"));
        let (env, agree) = consensus(&p).unwrap();
        assert_eq!(env.domain(), Ok(Some(5)));
        assert_eq!(env.distro(), Some("humble"));
        assert!(!agree);
        assert!(consensus(&[]).is_none());
    }

    #[test]
    fn validators() {
        assert!(valid_rmw("rmw_cyclonedds_cpp"));
        assert!(!valid_rmw("rmw_x; rm -rf /"));
        assert!(!valid_rmw("cyclonedds"));
        assert!(valid_path("/home/u/cyclone.xml"));
        assert!(!valid_path("/home/u/../../etc/shadow"));
        assert!(!valid_path("relative.xml"));
        assert!(!valid_path("/tmp/$(id).xml"));
        assert!(valid_range("SUBNET") && !valid_range("subnet"));
        assert!(valid_distro("jazzy") && !valid_distro("ja zzy"));
    }
}
