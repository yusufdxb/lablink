//! Remote script generation and output parsing.
//!
//! One POSIX `sh` script per device. Every section is a fixed command template
//! from a closed catalog; the only variable parts are parameters that passed
//! `CheckSpec::validate` and are shell-quoted. Nothing here writes, restarts,
//! publishes or runs a user-supplied command.

use lablink_core::checks::CheckSpec;
use lablink_ssh::shell_quote;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

pub const END_MARKER: &str = "@@lablink:end@@";

/// One check to put in the script. `idx` is the check's position in the plan.
pub struct ScriptEntry<'a> {
    pub idx: usize,
    pub spec: &'a CheckSpec,
    /// Required for `reach`: the address to ping.
    pub reach_ip: Option<IpAddr>,
}

/// Build the script. Parameters are validated again here (defense in depth).
pub fn build_script(entries: &[ScriptEntry]) -> Result<String, String> {
    let mut s = String::from("LC_ALL=C; export LC_ALL\n");
    for e in entries {
        e.spec.validate()?;
        let kind = e.spec.kind();
        let _ = writeln!(s, "echo @@lablink:{}:{kind}@@", e.idx);
        match e.spec {
            CheckSpec::Disk(d) => {
                let _ = writeln!(s, "df -P {} 2>&1", shell_quote(&d.path));
            }
            CheckSpec::NvidiaGpu(_) => s.push_str(
                "timeout 5 nvidia-smi --query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>&1\n",
            ),
            CheckSpec::JetsonGpu => s.push_str(
                "head -n 1 /etc/nv_tegra_release 2>/dev/null\nif [ -e /dev/nvhost-gpu ] || [ -e /dev/nvgpu ]; then\necho gpu_node=yes\nelse\necho gpu_node=no\nfi\n",
            ),
            CheckSpec::Thermal(_) => s.push_str(
                "for z in /sys/class/thermal/thermal_zone*; do\n[ -r \"$z/temp\" ] || continue\necho \"$(cat \"$z/type\" 2>/dev/null) $(cat \"$z/temp\" 2>/dev/null)\"\ndone\n",
            ),
            CheckSpec::Ros2(_) => s.push_str(
                "for d in /opt/ros/*/; do\n[ -d \"$d\" ] || continue\ns=no\nr=no\n[ -f \"${d}setup.bash\" ] && s=yes\n[ -f \"${d}bin/ros2\" ] && r=yes\necho \"$(basename \"$d\") setup=$s ros2=$r\"\ndone\n",
            ),
            CheckSpec::Dds(d) => {
                s.push_str("for f in /opt/ros/*/lib/librmw_cyclonedds_cpp.so; do\n[ -e \"$f\" ] || continue\necho \"rmw=$f\"\nbreak\ndone\necho ip_begin\n");
                let _ = writeln!(s, "ip -br -4 addr show dev {} 2>&1", shell_quote(&d.interface));
                s.push_str("echo \"ip_rc=$?\"\n");
                if let Some(c) = &d.config {
                    let q = shell_quote(c);
                    let _ = writeln!(s, "if [ -f {q} ]; then\necho cfg=present\nhead -c 262144 {q} 2>/dev/null\necho\nelse\necho cfg=missing\nfi");
                }
            }
            CheckSpec::Reach(_) => {
                let ip = e
                    .reach_ip
                    .ok_or_else(|| "reach check without an address".to_string())?;
                let _ = writeln!(s, "ping -c 3 -W 1 {ip} 2>&1");
            }
        }
        s.push_str("echo \"@@rc:$?@@\"\n");
    }
    s.push_str("echo ");
    s.push_str(END_MARKER);
    s.push('\n');
    Ok(s)
}

/// Output of one section.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Section {
    pub lines: Vec<String>,
    pub rc: Option<i32>,
}

/// Split the session output into sections. `None` when the end marker is
/// missing (the session did not run to completion).
pub fn parse_sections(stdout: &str) -> Option<BTreeMap<usize, Section>> {
    let mut map = BTreeMap::new();
    let mut cur: Option<usize> = None;
    let mut ended = false;
    for line in stdout.lines() {
        let line = line.trim_end_matches('\r');
        if line == END_MARKER {
            ended = true;
            break;
        }
        if let Some(rest) = line.strip_prefix("@@lablink:") {
            let idx = rest.split(':').next().and_then(|n| n.parse::<usize>().ok());
            if let Some(i) = idx {
                map.insert(i, Section::default());
                cur = Some(i);
                continue;
            }
        }
        if let Some(rc) = line
            .strip_prefix("@@rc:")
            .and_then(|r| r.strip_suffix("@@"))
        {
            if let Some(i) = cur.take() {
                if let Some(sec) = map.get_mut(&i) {
                    sec.rc = rc.parse().ok();
                }
            }
            continue;
        }
        if let Some(i) = cur {
            if let Some(sec) = map.get_mut(&i) {
                sec.lines.push(line.to_string());
            }
        }
    }
    ended.then_some(map)
}

use crate::CheckStatus::{self, Fail, Ok as Pass, Skip, Warn};

fn first_line(sec: &Section) -> String {
    sec.lines
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .chars()
        .take(120)
        .collect()
}

/// Turn one section into a status and detail.
pub fn evaluate(
    spec: &CheckSpec,
    via: Option<&str>,
    sec: Option<&Section>,
) -> (CheckStatus, String) {
    let Some(sec) = sec else {
        return (Fail, "no output from the check".into());
    };
    match spec {
        CheckSpec::Disk(d) => eval_disk(d, sec),
        CheckSpec::NvidiaGpu(g) => eval_nvidia(g.expect.as_deref(), sec),
        CheckSpec::JetsonGpu => eval_jetson(sec),
        CheckSpec::Thermal(t) => eval_thermal(t.warn_c, t.fail_c, sec),
        CheckSpec::Ros2(r) => eval_ros2(r.distro.as_deref(), sec),
        CheckSpec::Dds(d) => eval_dds(&d.interface, d.config.as_deref(), sec),
        CheckSpec::Reach(_) => eval_reach(via, sec),
    }
}

// ---- disk -----------------------------------------------------------------

/// Percent used from `df -P` output.
pub fn parse_df(lines: &[String]) -> Option<u32> {
    lines
        .iter()
        .filter(|l| !l.starts_with("Filesystem"))
        .find_map(|l| {
            l.split_whitespace()
                .skip(1)
                .find_map(|t| t.strip_suffix('%').and_then(|n| n.parse::<u32>().ok()))
        })
}

fn eval_disk(d: &lablink_core::checks::DiskCheck, sec: &Section) -> (CheckStatus, String) {
    let Some(pct) = parse_df(&sec.lines) else {
        return (Fail, format!("df failed: {}", first_line(sec)));
    };
    let on = if d.path == "/" {
        String::new()
    } else {
        format!(" on {}", d.path)
    };
    let detail = format!("{pct}% used{on}");
    let st = if pct >= d.fail_pct {
        Fail
    } else if pct >= d.warn_pct {
        Warn
    } else {
        Pass
    };
    (st, detail)
}

// ---- nvidia ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpu {
    pub name: String,
    pub util: Option<u32>,
    pub temp: Option<u32>,
    pub mem_used: Option<u32>,
    pub mem_total: Option<u32>,
}

pub fn parse_nvidia(lines: &[String]) -> Vec<Gpu> {
    lines
        .iter()
        .filter_map(|l| {
            let mut f: Vec<&str> = l.rsplitn(5, ',').map(str::trim).collect();
            if f.len() != 5 {
                return None;
            }
            f.reverse();
            let num = |s: &str| s.parse::<u32>().ok();
            let g = Gpu {
                name: f[0].to_string(),
                util: num(f[1]),
                temp: num(f[2]),
                mem_used: num(f[3]),
                mem_total: num(f[4]),
            };
            (!g.name.is_empty() && (g.temp.is_some() || g.mem_total.is_some())).then_some(g)
        })
        .collect()
}

fn eval_nvidia(expect: Option<&str>, sec: &Section) -> (CheckStatus, String) {
    let gpus = parse_nvidia(&sec.lines);
    if gpus.is_empty() {
        let why = match sec.rc {
            Some(127) => "nvidia-smi not installed".to_string(),
            Some(124) => "nvidia-smi timed out".to_string(),
            _ => format!("no NVIDIA GPU reported: {}", first_line(sec)),
        };
        return (Fail, why);
    }
    let q = |v: Option<u32>| v.map_or("?".to_string(), |n| n.to_string());
    let detail = gpus
        .iter()
        .map(|g| {
            format!(
                "{}, {}% util, {} C, {}/{} MiB",
                g.name,
                q(g.util),
                q(g.temp),
                q(g.mem_used),
                q(g.mem_total)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(e) = expect {
        let e = e.to_ascii_lowercase();
        if !gpus
            .iter()
            .any(|g| g.name.to_ascii_lowercase().contains(&e))
        {
            return (
                Fail,
                format!("expected '{}' but found {detail}", expect.unwrap_or("")),
            );
        }
    }
    let hot = gpus.iter().any(|g| g.temp.is_some_and(|t| t >= 85));
    (if hot { Warn } else { Pass }, detail)
}

// ---- jetson ---------------------------------------------------------------

/// `R36.4.7` from the first line of /etc/nv_tegra_release.
pub fn parse_tegra_release(line: &str) -> Option<String> {
    let major = line.strip_prefix("# ")?.split_whitespace().next()?;
    if !major.starts_with('R') {
        return None;
    }
    let rev = line
        .split("REVISION:")
        .nth(1)
        .map(|r| r.split(',').next().unwrap_or("").trim().to_string())
        .filter(|r| !r.is_empty());
    Some(match rev {
        Some(r) => format!("{major}.{r}"),
        None => major.to_string(),
    })
}

fn eval_jetson(sec: &Section) -> (CheckStatus, String) {
    let tegra = sec.lines.iter().find(|l| l.starts_with('#'));
    let node = sec.lines.iter().any(|l| l.trim() == "gpu_node=yes");
    let Some(t) = tegra else {
        return (Fail, "not a Jetson (no /etc/nv_tegra_release)".into());
    };
    let rel = parse_tegra_release(t).unwrap_or_else(|| "unknown release".into());
    if node {
        (Pass, format!("L4T {rel}, GPU device present"))
    } else {
        (Fail, format!("L4T {rel}, no GPU device node"))
    }
}

// ---- thermal --------------------------------------------------------------

/// Hottest zone as (millidegrees, type).
pub fn parse_thermal(lines: &[String]) -> Option<(i64, String)> {
    lines
        .iter()
        .filter_map(|l| {
            let (ty, t) = l.trim().rsplit_once(char::is_whitespace)?;
            Some((t.trim().parse::<i64>().ok()?, ty.trim().to_string()))
        })
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
}

fn eval_thermal(warn_c: u32, fail_c: u32, sec: &Section) -> (CheckStatus, String) {
    let Some((milli, ty)) = parse_thermal(&sec.lines) else {
        return (Skip, "no thermal zones exposed".into());
    };
    let tenths = (milli + 50).div_euclid(100);
    let detail = format!(
        "max {}.{} C ({ty})",
        tenths.div_euclid(10),
        tenths.rem_euclid(10)
    );
    let st = if tenths >= i64::from(fail_c) * 10 {
        Fail
    } else if tenths >= i64::from(warn_c) * 10 {
        Warn
    } else {
        Pass
    };
    (st, detail)
}

// ---- ros2 -----------------------------------------------------------------

/// (distro, has setup.bash, has bin/ros2) per `/opt/ros/*` entry.
pub fn parse_ros(lines: &[String]) -> Vec<(String, bool, bool)> {
    lines
        .iter()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let s = it.next()?.strip_prefix("setup=")? == "yes";
            let r = it.next()?.strip_prefix("ros2=")? == "yes";
            (name != "*").then(|| (name.to_string(), s, r))
        })
        .collect()
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
        .unwrap_or_default()
}

fn eval_ros2(distro: Option<&str>, sec: &Section) -> (CheckStatus, String) {
    let all = parse_ros(&sec.lines);
    let ready: Vec<&(String, bool, bool)> = all.iter().filter(|d| d.1 && d.2).collect();
    match distro {
        Some(d) => match all.iter().find(|x| x.0 == d) {
            Some((_, true, true)) => (Pass, format!("{} / OK", cap(d))),
            Some((_, s, r)) => {
                let missing = match (s, r) {
                    (false, false) => "setup.bash and bin/ros2",
                    (false, true) => "setup.bash",
                    _ => "bin/ros2",
                };
                (Fail, format!("{} incomplete: missing {missing}", cap(d)))
            }
            None if all.is_empty() => (Fail, format!("{} not installed (no /opt/ros)", cap(d))),
            None => (
                Fail,
                format!(
                    "{} not installed (found: {})",
                    cap(d),
                    all.iter()
                        .map(|x| x.0.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
        },
        None if ready.is_empty() => (Fail, "no ROS 2 distro under /opt/ros".into()),
        None => (
            Pass,
            format!(
                "{} / OK",
                ready
                    .iter()
                    .map(|x| cap(&x.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    }
}

// ---- dds ------------------------------------------------------------------

/// (state, first IPv4 without prefix length) from `ip -br -4 addr show`.
pub fn parse_ip_br(lines: &[String]) -> Option<(String, Option<String>)> {
    let l = lines.iter().find(|l| !l.trim().is_empty())?;
    let mut it = l.split_whitespace();
    it.next()?;
    let state = it.next()?.to_string();
    let ip = it
        .find(|t| t.contains('.'))
        .map(|t| t.split('/').next().unwrap_or(t).to_string());
    Some((state, ip))
}

/// Does a CycloneDDS XML file name this interface (ignoring XML comments)?
pub fn cyclone_config_names(xml: &str, iface: &str) -> bool {
    let mut text = String::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<!--") {
        text.push_str(&rest[..i]);
        rest = match rest[i..].find("-->") {
            Some(j) => &rest[i + j + 3..],
            None => "",
        };
    }
    text.push_str(rest);
    let mut from = 0;
    while let Some(i) = text[from..].find("<NetworkInterface") {
        let start = from + i + "<NetworkInterface".len();
        from = start;
        let tail = &text[start..];
        if let Some(addr) = tail.strip_prefix("Address>") {
            if addr.split('<').next().is_some_and(|v| v.trim() == iface) {
                return true;
            }
        } else if tail.starts_with(char::is_whitespace) {
            let tag = tail.split('>').next().unwrap_or("");
            if tag.contains(&format!("name=\"{iface}\""))
                || tag.contains(&format!("name='{iface}'"))
            {
                return true;
            }
        }
    }
    false
}

fn eval_dds(iface: &str, config: Option<&str>, sec: &Section) -> (CheckStatus, String) {
    let rmw = sec.lines.iter().any(|l| l.starts_with("rmw="));
    if !rmw {
        return (
            Fail,
            "librmw_cyclonedds_cpp.so not found under /opt/ros".into(),
        );
    }
    let pos = |p: &str| sec.lines.iter().position(|l| l.starts_with(p));
    let (Some(b), Some(e)) = (pos("ip_begin"), pos("ip_rc=")) else {
        return (Fail, "no interface information".into());
    };
    let ip_rc = sec.lines[e]
        .strip_prefix("ip_rc=")
        .and_then(|v| v.trim().parse::<i32>().ok());
    let ip_lines = &sec.lines[b + 1..e];
    let Some((state, ip)) = parse_ip_br(ip_lines).filter(|_| ip_rc == Some(0)) else {
        return (Fail, format!("interface {iface} not found or ip failed"));
    };
    if state != "UP" {
        return (Fail, format!("interface {iface} is {state}, not UP"));
    }
    let Some(ip) = ip else {
        return (Fail, format!("interface {iface} has no IPv4 address"));
    };
    if let Some(cfg) = config {
        match pos("cfg=") {
            Some(c) if sec.lines[c].trim() == "cfg=present" => {
                let xml = sec.lines[c + 1..].join("\n");
                if !cyclone_config_names(&xml, iface) {
                    return (Fail, format!("{cfg} does not name interface {iface}"));
                }
            }
            _ => return (Fail, format!("config {cfg} not found")),
        }
    }
    (Pass, format!("cyclonedds on {iface} {ip}"))
}

// ---- reach ----------------------------------------------------------------

/// (packet loss percent, average rtt ms) from ping output.
pub fn parse_ping(lines: &[String]) -> (Option<u32>, Option<f64>) {
    let mut loss = None;
    let mut rtt = None;
    for l in lines {
        if let Some(i) = l.find("% packet loss") {
            loss = l[..i]
                .rsplit(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<u32>().ok());
        }
        if l.starts_with("rtt ") || l.starts_with("round-trip ") {
            rtt = l
                .split('=')
                .nth(1)
                .and_then(|v| v.trim().split('/').nth(1))
                .and_then(|a| a.trim().parse::<f64>().ok());
        }
    }
    (loss, rtt)
}

fn eval_reach(via: Option<&str>, sec: &Section) -> (CheckStatus, String) {
    let (loss, rtt) = parse_ping(&sec.lines);
    let prefix = via.map(|g| format!("via {g}, ")).unwrap_or_default();
    let rtt_s = rtt.map(|r| format!("rtt {r:.1} ms")).unwrap_or_default();
    match (sec.rc, loss) {
        (Some(127), _) => (Fail, "ping not available on the checking device".into()),
        (_, Some(l)) if l >= 100 => (Fail, format!("{prefix}no reply (100% packet loss)")),
        (Some(0), Some(0)) => (Pass, format!("{prefix}{rtt_s}")),
        (_, Some(l)) if l > 0 => (Warn, format!("{prefix}{l}% packet loss, {rtt_s}")),
        _ => (Fail, format!("{prefix}no reply: {}", first_line(sec))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_core::checks::*;

    fn l(s: &str) -> Vec<String> {
        s.lines().map(String::from).collect()
    }
    fn sec(s: &str, rc: i32) -> Section {
        Section {
            lines: l(s),
            rc: Some(rc),
        }
    }

    #[test]
    fn df_fixture() {
        let out = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/nvme0n1p1   243521944 173149280  57929580      75% /";
        assert_eq!(parse_df(&l(out)), Some(75));
        let d = DiskCheck::default();
        assert_eq!(eval_disk(&d, &sec(out, 0)), (Pass, "75% used".into()));
        let hot = out.replace("75%", "90%");
        assert_eq!(eval_disk(&d, &sec(&hot, 0)).0, Warn);
        assert_eq!(eval_disk(&d, &sec(&out.replace("75%", "96%"), 0)).0, Fail);
        let wrapped = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/very-long-name\n 100 50 50 50% /x";
        assert_eq!(parse_df(&l(wrapped)), Some(50));
        assert_eq!(
            eval_disk(&d, &sec("df: /nope: No such file or directory", 1)).0,
            Fail
        );
    }

    #[test]
    fn nvidia_fixture() {
        let out = "NVIDIA RTX A4000, 0, 28, 457, 16303";
        let g = parse_nvidia(&l(out));
        assert_eq!(g.len(), 1);
        assert_eq!(
            (g[0].util, g[0].temp, g[0].mem_used, g[0].mem_total),
            (Some(0), Some(28), Some(457), Some(16303))
        );
        let (st, d) = eval_nvidia(Some("RTX A4000"), &sec(out, 0));
        assert_eq!(
            (st, d.as_str()),
            (Pass, "NVIDIA RTX A4000, 0% util, 28 C, 457/16303 MiB")
        );
        assert_eq!(eval_nvidia(Some("RTX 4090"), &sec(out, 0)).0, Fail);
        assert_eq!(
            eval_nvidia(None, &sec(&out.replace(", 28,", ", 88,"), 0)).0,
            Warn
        );
        let missing = eval_nvidia(None, &sec("sh: 1: nvidia-smi: not found", 127));
        assert_eq!(missing, (Fail, "nvidia-smi not installed".into()));
        assert_eq!(eval_nvidia(None, &sec("No devices were found", 6)).0, Fail);
    }

    #[test]
    fn jetson_fixture() {
        let rel = "# R36 (release), REVISION: 4.7, GCID: 42132812, BOARD: generic, EABI: aarch64, DATE: Thu Sep 18 22:54:44 UTC 2025";
        assert_eq!(parse_tegra_release(rel).as_deref(), Some("R36.4.7"));
        let ok = eval_jetson(&sec(&format!("{rel}\ngpu_node=yes"), 0));
        assert_eq!(ok, (Pass, "L4T R36.4.7, GPU device present".into()));
        assert_eq!(eval_jetson(&sec(&format!("{rel}\ngpu_node=no"), 0)).0, Fail);
        assert_eq!(eval_jetson(&sec("gpu_node=no", 0)).0, Fail);
    }

    #[test]
    fn thermal_fixture() {
        let types = [
            "cpu-thermal",
            "gpu-thermal",
            "cv0-thermal",
            "cv1-thermal",
            "cv2-thermal",
            "soc0-thermal",
            "soc1-thermal",
            "soc2-thermal",
            "tj-thermal",
        ];
        let temps = [
            60750, 57062, 58843, 58437, 57781, 59125, 61250, 57750, 61343,
        ];
        let out: String = types
            .iter()
            .zip(temps)
            .map(|(t, v)| format!("{t} {v}\n"))
            .collect();
        assert_eq!(parse_thermal(&l(&out)), Some((61343, "tj-thermal".into())));
        let (st, d) = eval_thermal(85, 95, &sec(&out, 0));
        assert_eq!((st, d.as_str()), (Pass, "max 61.3 C (tj-thermal)"));
        assert_eq!(eval_thermal(60, 95, &sec(&out, 0)).0, Warn);
        assert_eq!(eval_thermal(30, 61, &sec(&out, 0)).0, Fail);
        assert_eq!(eval_thermal(85, 95, &sec("", 0)).0, Skip);
    }

    #[test]
    fn ros2_cases() {
        let out = "humble setup=yes ros2=yes\njazzy setup=yes ros2=no\n* setup=no ros2=no";
        assert_eq!(parse_ros(&l(out)).len(), 2);
        assert_eq!(
            eval_ros2(Some("humble"), &sec(out, 0)),
            (Pass, "Humble / OK".into())
        );
        assert!(eval_ros2(Some("jazzy"), &sec(out, 0))
            .1
            .contains("bin/ros2"));
        assert!(eval_ros2(Some("iron"), &sec(out, 0))
            .1
            .contains("found: humble, jazzy"));
        assert_eq!(eval_ros2(None, &sec(out, 0)), (Pass, "Humble / OK".into()));
        assert_eq!(eval_ros2(None, &sec("* setup=no ros2=no", 0)).0, Fail);
    }

    const XML: &str = "<CycloneDDS><Domain><General><Interfaces>\n<NetworkInterface name=\"eth1\" priority=\"default\" multicast=\"default\" />\n</Interfaces></General></Domain></CycloneDDS>";

    #[test]
    fn dds_cases() {
        let ip = "eth1         UP             192.168.50.18/24";
        assert_eq!(
            parse_ip_br(&l(ip)),
            Some(("UP".into(), Some("192.168.50.18".into())))
        );
        assert_eq!(
            parse_ip_br(&l("lo UNKNOWN")),
            Some(("UNKNOWN".into(), None))
        );
        assert!(cyclone_config_names(XML, "eth1"));
        assert!(!cyclone_config_names(XML, "eth0"));
        assert!(!cyclone_config_names(
            "<!-- <NetworkInterface name=\"eth0\"/> -->",
            "eth0"
        ));
        assert!(cyclone_config_names(
            "<NetworkInterfaceAddress> eth0 </NetworkInterfaceAddress>",
            "eth0"
        ));
        assert!(!cyclone_config_names(
            "<NetworkInterfaceAddress>eth1</NetworkInterfaceAddress>",
            "eth0"
        ));
        let body = format!("rmw=/opt/ros/humble/lib/librmw_cyclonedds_cpp.so\nip_begin\n{ip}\nip_rc=0\ncfg=present\n{XML}\n");
        let (st, d) = eval_dds("eth1", Some("/c.xml"), &sec(&body, 0));
        assert_eq!((st, d.as_str()), (Pass, "cyclonedds on eth1 192.168.50.18"));
        assert!(eval_dds(
            "eth0",
            Some("/c.xml"),
            &sec(&body.replace("eth1         UP", "eth0 UP"), 0)
        )
        .1
        .contains("does not name"));
        assert!(eval_dds("eth1", None, &sec(&body.replace("rmw=", "x="), 0))
            .1
            .contains("librmw"));
        assert!(
            eval_dds("eth1", None, &sec(&body.replace("UP  ", "DOWN"), 0))
                .1
                .contains("not UP")
        );
        let nocfg = body.replace("cfg=present", "cfg=missing");
        assert!(eval_dds("eth1", Some("/c.xml"), &sec(&nocfg, 0))
            .1
            .contains("not found"));
        let noif = "rmw=/x\nip_begin\nDevice \"zz\" does not exist.\nip_rc=1";
        assert!(eval_dds("zz", None, &sec(noif, 0)).1.contains("not found"));
    }

    #[test]
    fn ping_cases() {
        let out = "PING 192.168.50.161 (192.168.50.161) 56(84) bytes of data.\n64 bytes from 192.168.50.161: icmp_seq=1 ttl=64 time=0.17 ms\n\n--- 192.168.50.161 ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss, time 2040ms\nrtt min/avg/max/mdev = 0.170/0.170/0.170/0.000 ms";
        assert_eq!(parse_ping(&l(out)), (Some(0), Some(0.17)));
        assert_eq!(
            eval_reach(Some("jetson-a"), &sec(out, 0)),
            (Pass, "via jetson-a, rtt 0.2 ms".into())
        );
        assert_eq!(eval_reach(None, &sec(out, 0)).1, "rtt 0.2 ms");
        let lossy = out.replace("0% packet", "33% packet");
        assert_eq!(eval_reach(None, &sec(&lossy, 0)).0, Warn);
        let dead = "3 packets transmitted, 0 received, 100% packet loss, time 2040ms";
        assert_eq!(eval_reach(None, &sec(dead, 1)).0, Fail);
        assert_eq!(eval_reach(None, &sec("sh: ping: not found", 127)).0, Fail);
    }

    fn entries(specs: &[CheckSpec]) -> Vec<ScriptEntry<'_>> {
        specs
            .iter()
            .enumerate()
            .map(|(idx, spec)| ScriptEntry {
                idx,
                spec,
                reach_ip: Some("192.168.50.161".parse().unwrap()),
            })
            .collect()
    }

    fn all_specs() -> Vec<CheckSpec> {
        vec![
            CheckSpec::Disk(DiskCheck {
                path: "/home/x-1".into(),
                ..Default::default()
            }),
            CheckSpec::NvidiaGpu(NvidiaGpuCheck {
                expect: Some("RTX A4000".into()),
            }),
            CheckSpec::JetsonGpu,
            CheckSpec::Thermal(ThermalCheck::default()),
            CheckSpec::Ros2(Ros2Check {
                distro: Some("jazzy".into()),
            }),
            CheckSpec::Dds(DdsCheck {
                interface: "eth1".into(),
                config: Some("/home/u/c.xml".into()),
                rmw: "cyclonedds".into(),
            }),
            CheckSpec::Reach(ReachCheck::default()),
        ]
    }

    #[test]
    fn script_is_read_only_and_allow_listed() {
        let specs = all_specs();
        let s = build_script(&entries(&specs)).unwrap();
        let sanitized = s.replace("2>&1", "").replace("2>/dev/null", "");
        assert!(
            !sanitized.contains('>') && !sanitized.contains('<'),
            "redirection to a file: {s}"
        );
        for bad in [
            "rm ",
            "sudo",
            "systemctl",
            "ros2 topic",
            "ros2 run",
            "pub",
            "kill",
            "reboot",
            "shutdown",
            "mv ",
            "chmod",
            "chown",
            "tee ",
            "dd ",
            "mkdir",
            "touch",
            "wget",
            "curl",
            "service ",
            "eval",
            "ssh ",
        ] {
            assert!(!s.contains(bad), "script contains '{bad}': {s}");
        }
        let allowed = [
            "LC_ALL=C;",
            "echo",
            "df",
            "timeout",
            "head",
            "if",
            "else",
            "fi",
            "for",
            "[",
            "continue",
            "break",
            "done",
            "s=no",
            "r=no",
            "ip",
            "ping",
        ];
        for line in s.lines() {
            let w = line.split_whitespace().next().unwrap();
            assert!(
                allowed.contains(&w),
                "command '{w}' not allow-listed in line: {line}"
            );
        }
        assert!(s.contains("echo @@lablink:5:dds@@") && s.trim_end().ends_with(END_MARKER));
        assert!(s.contains("df -P /home/x-1 2>&1"));
    }

    #[test]
    fn script_rejects_bad_params() {
        let ip = Some("10.0.0.1".parse().unwrap());
        for spec in [
            CheckSpec::Disk(DiskCheck {
                path: "/a; reboot".into(),
                ..Default::default()
            }),
            CheckSpec::Disk(DiskCheck {
                path: "/a/../b".into(),
                ..Default::default()
            }),
            CheckSpec::Dds(DdsCheck {
                interface: "eth0; id".into(),
                config: None,
                rmw: "cyclonedds".into(),
            }),
            CheckSpec::Dds(DdsCheck {
                interface: "eth0".into(),
                config: Some("$(id)".into()),
                rmw: "cyclonedds".into(),
            }),
            CheckSpec::Ros2(Ros2Check {
                distro: Some("x;y".into()),
            }),
            CheckSpec::NvidiaGpu(NvidiaGpuCheck {
                expect: Some("a'b".into()),
            }),
        ] {
            assert!(
                build_script(&[ScriptEntry {
                    idx: 0,
                    spec: &spec,
                    reach_ip: ip
                }])
                .is_err(),
                "{spec:?}"
            );
        }
        let r = CheckSpec::Reach(ReachCheck::default());
        assert!(build_script(&[ScriptEntry {
            idx: 0,
            spec: &r,
            reach_ip: None
        }])
        .is_err());
    }

    #[test]
    fn session_parsing() {
        let out = "@@lablink:0:disk@@\nFilesystem x\n/dev/a 1 1 1 5% /\n@@rc:0@@\n@@lablink:2:reach@@\n@@rc:1@@\n@@lablink:end@@\n";
        let m = parse_sections(out).unwrap();
        assert_eq!(m[&0].rc, Some(0));
        assert_eq!(m[&0].lines.len(), 2);
        assert_eq!(m[&2].rc, Some(1));
        assert!(parse_sections("@@lablink:0:disk@@\nx\n").is_none());
        assert!(parse_sections("").is_none());
    }
}
