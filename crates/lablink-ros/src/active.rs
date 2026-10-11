//! Active tests between two devices, run only when the user asks for them
//! (`--active`). They send a little traffic of their own and touch nothing
//! else: three pings each way, one `ros2 multicast` packet each way, and a
//! pub/sub probe on a topic name no robot uses (`/lablink_probe_<random>`,
//! `std_msgs/msg/String`, three messages at 2 Hz). Every command runs under
//! `timeout -k`, and afterwards LabLink checks that no probe process is
//! left. Nothing here starts, stops or commands a robot, and nothing reads
//! or writes an existing topic.

use crate::diagnose::Verdict;
use crate::inspect::{shared_path, Inspection};
use crate::script::{valid_topic, QueryEnv, END};
use crate::{Remote, RemoteError};
use lablink_ssh::shell_quote;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub name: String,
    pub from: String,
    pub to: String,
    pub verdict: Verdict,
    pub summary: String,
    pub evidence: Vec<String>,
    pub method: String,
    pub interface: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveReport {
    pub topic: String,
    pub domain: u32,
    pub ping_ab: Probe,
    pub ping_ba: Probe,
    pub multicast_ab: Probe,
    pub multicast_ba: Probe,
    pub pubsub_ab: Probe,
    pub pubsub_ba: Probe,
    /// Probe processes still running afterwards (expected: 0 on both).
    pub leftover: Vec<String>,
}

/// A random 16-hex-digit token (std only: `RandomState` is randomly keyed).
pub fn token() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    format!("{:016x}", h.finish())
}

const PING_LIMIT: u32 = 8;
const MCAST_LIMIT: u32 = 9;
const PUBSUB_LIMIT: u32 = 16;

fn probe(name: &str, from: &str, to: &str, method: String, limit: u32) -> Probe {
    Probe {
        name: name.into(),
        from: from.into(),
        to: to.into(),
        verdict: Verdict::NotTested,
        summary: String::new(),
        evidence: vec![],
        method,
        interface: None,
        timeout_ms: u64::from(limit) * 1000,
    }
}

fn unavailable(mut p: Probe, why: &str) -> Probe {
    p.verdict = Verdict::Unavailable;
    p.summary = why.into();
    p
}

pub fn ping_script(target: Ipv4Addr) -> String {
    format!(
        "LC_ALL=C; export LC_ALL\necho @@ll:ping@@\nif command -v ping >/dev/null 2>&1; then o=$(timeout -k 2 {PING_LIMIT} ping -n -c 3 -W 1 -i 0.5 {target} 2>&1); r=$?; printf '%s\\n' \"$o\" | tail -n 4; echo \"rc=$r\"; else echo missing; fi\necho {END}\n"
    )
}

/// `ros2 multicast receive` (bounded), optionally preceded by a pause.
pub fn mcast_receive_script(env: &QueryEnv) -> String {
    let cmd = format!("{}ros2 multicast receive", env.prelude());
    format!(
        "LC_ALL=C; export LC_ALL\necho @@ll:mcast@@\no=$(timeout -k 2 {MCAST_LIMIT} bash --norc --noprofile -c {} 2>&1); r=$?; printf '%s\\n' \"$o\" | head -n 5; echo \"rc=$r\"\necho {END}\n",
        shell_quote(&cmd)
    )
}

pub fn mcast_send_script(env: &QueryEnv) -> String {
    let cmd = format!("sleep 3; {}ros2 multicast send", env.prelude());
    format!(
        "LC_ALL=C; export LC_ALL\necho @@ll:mcast@@\no=$(timeout -k 2 {MCAST_LIMIT} bash --norc --noprofile -c {} 2>&1); r=$?; printf '%s\\n' \"$o\" | head -n 5; echo \"rc=$r\"\necho {END}\n",
        shell_quote(&cmd)
    )
}

/// Echo one message on `t_in` while publishing three on `t_out` (after the
/// other side's subscriber had time to appear). Both topics are LabLink's
/// own; `pub -w 1` waits for that one subscriber before sending.
pub fn pubsub_script(
    env: &QueryEnv,
    t_in: &str,
    t_out: &str,
    payload: &str,
) -> Result<String, String> {
    env.validate()?;
    for t in [t_in, t_out] {
        if !valid_topic(t) || !t.starts_with("/lablink_probe_") {
            return Err(format!("refusing probe topic '{t}'"));
        }
    }
    if !payload
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("invalid payload".into());
    }
    let echo = format!(
        "{}ros2 topic echo --once {} std_msgs/msg/String",
        env.prelude(),
        shell_quote(t_in)
    );
    let publ = format!(
        "sleep 3; {}ros2 topic pub -w 1 -t 3 -r 2 {} std_msgs/msg/String {}",
        env.prelude(),
        shell_quote(t_out),
        shell_quote(&format!("{{data: {payload}}}"))
    );
    let limit = PUBSUB_LIMIT;
    Ok(format!(
        "LC_ALL=C; export LC_ALL\n\
         d=$(mktemp -d 2>/dev/null) || exit 1\n\
         timeout -k 2 {limit} bash --norc --noprofile -c {} >\"$d/echo\" 2>&1 & e=$!\n\
         timeout -k 2 {limit} bash --norc --noprofile -c {} >\"$d/pub\" 2>&1 & p=$!\n\
         wait $e; erc=$?; wait $p; prc=$?\n\
         echo @@ll:echo@@\nhead -n 20 \"$d/echo\"; echo \"rc=$erc\"\n\
         echo @@ll:pub@@\nhead -n 20 \"$d/pub\"; echo \"rc=$prc\"\n\
         rm -rf \"$d\"\necho {END}\n",
        shell_quote(&echo),
        shell_quote(&publ)
    ))
}

/// Counts probe processes still running. The bracket keeps the pattern
/// from matching this script's own command line.
pub fn leftover_script(hex: &str) -> Result<String, String> {
    if hex.len() != 16 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid token".into());
    }
    let (first, rest) = hex.split_at(1);
    Ok(format!(
        "echo @@ll:left@@\nif command -v pgrep >/dev/null 2>&1; then echo \"count=$(pgrep -fc 'lablink_probe_[{first}]{rest}')\"; else echo unknown; fi\necho {END}\n"
    ))
}

fn rc(lines: &[String]) -> Option<i32> {
    lines
        .iter()
        .rev()
        .find_map(|l| l.strip_prefix("rc=")?.trim().parse().ok())
}

fn section(out: &Result<String, RemoteError>, name: &str) -> Result<Vec<String>, String> {
    match out {
        Ok(o) => crate::script::sections(o)
            .and_then(|m| m.get(name).cloned())
            .ok_or_else(|| "no complete reply".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn judge_ping(mut p: Probe, out: &Result<String, RemoteError>) -> Probe {
    match section(out, "ping") {
        Err(e) => unavailable(p, &format!("could not run: {e}")),
        Ok(l) if l.first().map(String::as_str) == Some("missing") => {
            unavailable(p, "ping is not installed")
        }
        Ok(l) => {
            let stats = l
                .iter()
                .find(|x| x.contains("packets transmitted"))
                .cloned();
            let ok = stats
                .as_deref()
                .is_some_and(|s| !s.contains(" 0 received") && !s.contains(" 100% packet loss"));
            p.verdict = if ok { Verdict::Pass } else { Verdict::Fail };
            p.summary = stats.clone().unwrap_or_else(|| "no reply".into());
            p.evidence = l.into_iter().filter(|x| !x.starts_with("rc=")).collect();
            p
        }
    }
}

pub fn judge_mcast(
    mut p: Probe,
    recv: &Result<String, RemoteError>,
    sender_addrs: &[Ipv4Addr],
) -> Probe {
    match section(recv, "mcast") {
        Err(e) => unavailable(p, &format!("could not run: {e}")),
        Ok(l) => {
            // "Received from 172.18.0.2:43210: 'Hello World!'"
            let got = l.iter().find_map(|x| {
                let rest = x.strip_prefix("Received from ")?;
                let ip: Ipv4Addr = rest.split(':').next()?.parse().ok()?;
                Some((ip, x.clone()))
            });
            match got {
                Some((ip, line)) if sender_addrs.contains(&ip) => {
                    p.verdict = Verdict::Pass;
                    p.summary = format!("received the multicast packet from {ip}");
                    p.evidence = vec![line];
                }
                Some((ip, line)) => {
                    p.verdict = Verdict::Warn;
                    p.summary =
                        format!("received a multicast packet, but from {ip}, not from the sender");
                    p.evidence = vec![line];
                }
                None => {
                    p.verdict = Verdict::Fail;
                    p.summary = match rc(&l) {
                        Some(124) | Some(137) => {
                            "no multicast packet arrived within the limit".into()
                        }
                        _ => "the receiver did not get the packet".into(),
                    };
                    p.evidence = l;
                }
            }
            p
        }
    }
}

pub fn judge_pubsub(
    mut p: Probe,
    recv: &Result<String, RemoteError>,
    send: &Result<String, RemoteError>,
    payload: &str,
) -> Probe {
    let echo = section(recv, "echo");
    let publ = section(send, "pub");
    match (echo, publ) {
        (Err(e), _) | (_, Err(e)) => unavailable(p, &format!("could not run: {e}")),
        (Ok(e), Ok(pl)) => {
            let got = e.iter().any(|l| l.trim() == format!("data: {payload}"));
            p.verdict = if got { Verdict::Pass } else { Verdict::Fail };
            p.summary = if got {
                "the subscriber received the probe message".into()
            } else if pl
                .iter()
                .any(|l| l.contains("Waiting for at least 1 matching subscription"))
                && rc(&pl) != Some(0)
            {
                "the publisher never matched the subscriber (discovery or QoS did not complete)"
                    .into()
            } else {
                "the subscriber received nothing".into()
            };
            p.evidence = e
                .iter()
                .map(|l| format!("echo: {l}"))
                .chain(pl.iter().map(|l| format!("pub: {l}")))
                .take(16)
                .collect();
            p
        }
    }
}

/// Run every active test between `a` and `b`. `b_hint` is where LabLink
/// located `b`.
pub fn run(
    remote: &dyn Remote,
    a: &Inspection,
    b: &Inspection,
    b_hint: Option<Ipv4Addr>,
) -> ActiveReport {
    let hex = token();
    let topic_ab = format!("/lablink_probe_{hex}_ab");
    let topic_ba = format!("/lablink_probe_{hex}_ba");
    let payload = format!("lablink-probe-{hex}");
    let (an, bn) = (a.device.as_str(), b.device.as_str());
    let path = shared_path(a, b, b_hint);
    let (a_target, b_target) = match &path {
        Some(p) => (Some(p.b_addr), Some(p.a_addr)),
        None => (b_hint, None),
    };
    let t = |s: u32| Duration::from_secs(u64::from(s) + 15);

    let ping_m = |ip: Option<Ipv4Addr>| match ip {
        Some(ip) => format!("ping -c 3 -W 1 {ip}"),
        None => "ping".into(),
    };
    let mut ping_ab = probe("ping", an, bn, ping_m(a_target), PING_LIMIT);
    let mut ping_ba = probe("ping", bn, an, ping_m(b_target), PING_LIMIT);
    let (ra, rb) = std::thread::scope(|s| {
        let hb = s.spawn(|| b_target.map(|ip| remote.run(bn, &ping_script(ip), t(PING_LIMIT))));
        let ra = a_target.map(|ip| remote.run(an, &ping_script(ip), t(PING_LIMIT)));
        (ra, hb.join().ok().flatten())
    });
    ping_ab = match ra {
        Some(r) => judge_ping(ping_ab, &r),
        None => unavailable(ping_ab, "no address of the peer is known"),
    };
    ping_ba = match rb {
        Some(r) => judge_ping(ping_ba, &r),
        None => unavailable(
            ping_ba,
            "the devices share no subnet, so there is no address to ping back",
        ),
    };
    if let Some(p) = &path {
        ping_ab.interface = Some(p.a_interface.clone());
        ping_ba.interface = Some(p.b_interface.clone());
    }

    let qenv = |i: &Inspection| {
        i.distro
            .clone()
            .filter(|d| i.distros.iter().any(|x| &x.name == d && x.ros2_cli) && i.host.bash)
            .map(|d| QueryEnv::from_env(&d, &i.effective))
    };
    let (qa, qb) = (qenv(a), qenv(b));
    let domain = a.effective_domain();
    let mc_m = "ros2 multicast send / receive (UDP 225.0.0.1:49150, one packet)".to_string();
    let mut multicast_ab = probe("multicast", an, bn, mc_m.clone(), MCAST_LIMIT);
    let mut multicast_ba = probe("multicast", bn, an, mc_m, MCAST_LIMIT);
    let ps_m = |t: &str| {
        format!("ros2 topic pub -w 1 -t 3 -r 2 {t} std_msgs/msg/String / topic echo --once (domain {domain})")
    };
    let mut pubsub_ab = probe("pubsub", an, bn, ps_m(&topic_ab), PUBSUB_LIMIT);
    let mut pubsub_ba = probe("pubsub", bn, an, ps_m(&topic_ba), PUBSUB_LIMIT);
    let mut leftover = Vec::new();

    match (&qa, &qb) {
        (Some(qa), Some(qb)) => {
            let a_addrs: Vec<Ipv4Addr> = a.addresses.iter().map(|x| x.net.addr()).collect();
            let b_addrs: Vec<Ipv4Addr> = b.addresses.iter().map(|x| x.net.addr()).collect();
            // Multicast one direction at a time (a receiver also hears its
            // own host's packets).
            for (from, to, q_from, q_to, addrs, slot) in [
                (an, bn, qa, qb, &a_addrs, &mut multicast_ab),
                (bn, an, qb, qa, &b_addrs, &mut multicast_ba),
            ] {
                let (rr, _rs) = std::thread::scope(|s| {
                    let hs =
                        s.spawn(|| remote.run(from, &mcast_send_script(q_from), t(MCAST_LIMIT)));
                    let rr = remote.run(to, &mcast_receive_script(q_to), t(MCAST_LIMIT));
                    (rr, hs.join())
                });
                *slot = judge_mcast(slot.clone(), &rr, addrs);
            }
            match (
                pubsub_script(qa, &topic_ba, &topic_ab, &payload),
                pubsub_script(qb, &topic_ab, &topic_ba, &payload),
            ) {
                (Ok(sa), Ok(sb)) => {
                    let (ra, rb) = std::thread::scope(|s| {
                        let hb = s.spawn(|| remote.run(bn, &sb, t(PUBSUB_LIMIT)));
                        let ra = remote.run(an, &sa, t(PUBSUB_LIMIT));
                        (
                            ra,
                            hb.join().unwrap_or_else(|_| {
                                Err(RemoteError::Failed("probe thread panicked".into()))
                            }),
                        )
                    });
                    pubsub_ab = judge_pubsub(pubsub_ab, &rb, &ra, &payload);
                    pubsub_ba = judge_pubsub(pubsub_ba, &ra, &rb, &payload);
                }
                (Err(e), _) | (_, Err(e)) => {
                    pubsub_ab = unavailable(pubsub_ab, &e);
                    pubsub_ba = unavailable(pubsub_ba, &e);
                }
            }
            if let Ok(s) = leftover_script(&hex) {
                for dev in [an, bn] {
                    let r = remote.run(dev, &s, Duration::from_secs(15));
                    let n = section(&r, "left").ok().and_then(|l| {
                        l.iter()
                            .find_map(|x| x.strip_prefix("count=")?.trim().parse::<u32>().ok())
                    });
                    match n {
                        Some(0) => {}
                        Some(n) => {
                            leftover.push(format!("{dev}: {n} probe process(es) still running"))
                        }
                        None => leftover.push(format!(
                            "{dev}: could not check for leftover probe processes"
                        )),
                    }
                }
            }
        }
        _ => {
            let why = "needs an installed ROS 2 distribution with the ros2 command line and bash on both devices";
            multicast_ab = unavailable(multicast_ab, why);
            multicast_ba = unavailable(multicast_ba, why);
            pubsub_ab = unavailable(pubsub_ab, why);
            pubsub_ba = unavailable(pubsub_ba, why);
        }
    }
    if let Some(p) = &path {
        for (pr, i) in [
            (&mut multicast_ab, &p.a_interface),
            (&mut pubsub_ab, &p.a_interface),
            (&mut multicast_ba, &p.b_interface),
            (&mut pubsub_ba, &p.b_interface),
        ] {
            pr.interface = Some(i.clone());
        }
    }
    ActiveReport {
        topic: format!("/lablink_probe_{hex}_{{ab,ba}}"),
        domain,
        ping_ab,
        ping_ba,
        multicast_ab,
        multicast_ba,
        pubsub_ab,
        pubsub_ba,
        leftover,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> QueryEnv {
        QueryEnv {
            distro: "humble".into(),
            domain: Some(7),
            rmw: None,
            localhost_only: false,
            range: None,
            cyclone_uri: None,
            fastdds_profile: None,
        }
    }

    #[test]
    fn tokens_are_unique_hex() {
        let (a, b) = (token(), token());
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn probe_scripts_are_bounded_and_own_topic_only() {
        let s = pubsub_script(
            &q(),
            "/lablink_probe_0123456789abcdef_ba",
            "/lablink_probe_0123456789abcdef_ab",
            "lablink-probe-0123456789abcdef",
        )
        .unwrap();
        assert_eq!(s.matches("timeout -k 2 16 bash").count(), 2);
        assert!(s.contains("pub -w 1 -t 3 -r 2"));
        assert!(s.contains("echo --once"));
        assert!(s.contains("export ROS_DOMAIN_ID=7"));
        assert!(s.contains("rm -rf \"$d\""));
        for bad in ["/cmd_vel", "/chatter", "sport", "daemon"] {
            assert!(!s.contains(bad));
        }
        assert!(
            pubsub_script(&q(), "/cmd_vel", "/lablink_probe_x", "p").is_err(),
            "never a robot topic"
        );
        assert!(pubsub_script(&q(), "/lablink_probe_a", "/lablink_probe_b", "x; reboot").is_err());
        assert!(ping_script(Ipv4Addr::new(10, 42, 0, 5))
            .contains("timeout -k 2 8 ping -n -c 3 -W 1 -i 0.5 10.42.0.5"));
        let l = leftover_script("0123456789abcdef").unwrap();
        assert!(l.contains("'lablink_probe_[0]123456789abcdef'"), "{l}");
        assert!(leftover_script("x'; rm -rf /").is_err());
    }

    fn ok(body: &str) -> Result<String, RemoteError> {
        Ok(format!("{body}\n{END}\n"))
    }

    #[test]
    fn judging() {
        let p = || probe("ping", "a", "b", "ping".into(), 8);
        let r = judge_ping(
            p(),
            &ok(
                "@@ll:ping@@\n3 packets transmitted, 3 received, 0% packet loss, time 1002ms\nrc=0",
            ),
        );
        assert_eq!(r.verdict, Verdict::Pass);
        let r = judge_ping(p(), &ok("@@ll:ping@@\n3 packets transmitted, 0 received, 100% packet loss, time 2050ms\nrc=1"));
        assert_eq!(r.verdict, Verdict::Fail);
        let r = judge_ping(p(), &Err(RemoteError::Mismatch("host key mismatch".into())));
        assert_eq!(r.verdict, Verdict::Unavailable);
        let a = [Ipv4Addr::new(172, 18, 0, 2)];
        let r = judge_mcast(
            p(),
            &ok("@@ll:mcast@@\nReceived from 172.18.0.2:41234: 'Hello World!'\nrc=0"),
            &a,
        );
        assert_eq!(r.verdict, Verdict::Pass);
        let r = judge_mcast(p(), &ok("@@ll:mcast@@\nrc=124"), &a);
        assert_eq!(r.verdict, Verdict::Fail);
        let pl = "lablink-probe-00";
        let r = judge_pubsub(
            p(),
            &ok("@@ll:echo@@\ndata: lablink-probe-00\n---\nrc=0"),
            &ok("@@ll:pub@@\npublishing #1\nrc=0"),
            pl,
        );
        assert_eq!(r.verdict, Verdict::Pass);
        let r = judge_pubsub(
            p(),
            &ok("@@ll:echo@@\nrc=124"),
            &ok("@@ll:pub@@\nWaiting for at least 1 matching subscription(s)...\nrc=124"),
            pl,
        );
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.summary.contains("never matched"));
    }
}
