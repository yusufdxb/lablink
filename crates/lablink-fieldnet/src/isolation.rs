//! Keeping hotspot clients off every other network.
//!
//! NetworkManager's shared mode (the only mode that gives hotspot clients
//! DHCP without a root helper) turns on IPv4 forwarding and NAT. LabLink
//! does not rely on the firewall to stop that forwarding. Instead the
//! hotspot profile carries one policy-routing rule per address family:
//!
//! ```text
//! priority 0 iif <adapter> prohibit
//! ```
//!
//! - NetworkManager owns the rules: it installs them when the profile
//!   activates and removes them when it goes down, also on failure.
//! - The kernel evaluates rules before any routing table, in priority order,
//!   and adds a new rule behind existing rules of the same priority. Rule 0
//!   comes right after `0: lookup local`, so packets for this machine's own
//!   addresses are still delivered, and every other packet that arrives on
//!   the adapter is refused before routing. A rule, route, VPN or uplink
//!   added later is evaluated after it.
//! - It does not depend on iptables/nftables rule order, on `ip_forward`, or
//!   on the routes that exist.
//! - Clients reach each other through the access point itself (802.11
//!   frames between stations never enter this machine's IP stack).
//!
//! [`check`] verifies the rules (and that nothing on the adapter bypasses
//! routing: a bridge, an upper device, tc or XDP) after the hotspot starts,
//! and `lablinkd` repeats it while the hotspot runs. When it fails the
//! hotspot is stopped: isolation that cannot be verified is treated as
//! absent.
//!
//! [`dns_relay`] covers the one path that is not routing: NetworkManager's
//! dnsmasq answers hotspot clients' DNS queries by forwarding them to this
//! machine's resolvers unless a drop-in tells it not to.

use crate::system::{Cmd, System};
use serde::Serialize;
use std::path::Path;

/// The rule as LabLink writes it into the profile.
pub fn profile_rule(iface: &str) -> String {
    format!("priority 0 iif {iface} prohibit")
}

/// The rules as `nmcli` reads them back (IPv4, IPv6).
pub fn profile_rules_readback(iface: &str) -> (String, String) {
    (
        format!("priority 0 from 0.0.0.0/0 iif {iface} type prohibit"),
        format!("priority 0 from ::/0 iif {iface} type prohibit"),
    )
}

/// One line of `ip rule show`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub priority: u32,
    /// Selector and action, whitespace-normalized ("from all lookup local").
    pub spec: String,
}

/// `ip [-4|-6] rule show`.
pub fn parse_rules(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| {
            let (p, rest) = l.split_once(':')?;
            Some(Rule {
                priority: p.trim().parse().ok()?,
                spec: rest.split_whitespace().collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}

fn is_ours(r: &Rule, iface: &str) -> bool {
    r.priority == 0
        && (r.spec == format!("from all iif {iface} prohibit")
            || r.spec == format!("from all iif {iface} [detached] prohibit"))
}

/// Rules that would be evaluated before LabLink's rule for `iface`. Only
/// the kernel's own `lookup local` rule may come first.
pub fn rules_ahead(rules: &[Rule], iface: &str) -> Vec<String> {
    rules
        .iter()
        .take_while(|r| !is_ours(r, iface))
        .filter(|r| !(r.priority == 0 && r.spec == "from all lookup local"))
        .map(|r| format!("{}: {}", r.priority, r.spec))
        .collect()
}

/// Problems with one family's rules ("IPv4"/"IPv6"); empty when LabLink's
/// rule is present and nothing can match first.
pub fn rule_problems(family: &str, rules: &[Rule], iface: &str) -> Vec<String> {
    if !rules.iter().any(|r| is_ours(r, iface)) {
        return vec![format!(
            "the {family} isolation rule (priority 0 iif {iface} prohibit) is missing"
        )];
    }
    rules_ahead(rules, iface)
        .into_iter()
        .map(|r| format!("{family} rule '{r}' is evaluated before the isolation rule"))
        .collect()
}

/// Rules of priority 0 other than `lookup local`, which a new isolation
/// rule would be placed behind (checked before starting).
pub fn preexisting_priority0(rules: &[Rule], iface: &str) -> Vec<String> {
    rules
        .iter()
        .filter(|r| r.priority == 0 && r.spec != "from all lookup local" && !is_ours(r, iface))
        .map(|r| format!("0: {}", r.spec))
        .collect()
}

/// Ways around routing on the adapter, from `ip -o -d link show` and
/// `tc qdisc show dev <iface>`: a bridge or bond master (frames would be
/// switched at layer 2), an upper device such as a VLAN or macvlan (its
/// packets arrive with another `iif`), XDP or tc ingress programs (they can
/// redirect packets before routing).
pub fn bypass_problems(links: &str, qdiscs: Option<&str>, iface: &str) -> Vec<String> {
    let mut v = Vec::new();
    for line in links.lines() {
        // "7: wlan0: <...> ..." or "9: mv0@wlan0: <...> ..."
        let mut parts = line.splitn(3, ": ");
        let (Some(_), Some(name), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let (name, lower) = match name.split_once('@') {
            Some((n, l)) => (n, Some(l)),
            None => (name, None),
        };
        if name == iface {
            if let Some(m) = rest
                .split_whitespace()
                .skip_while(|w| *w != "master")
                .nth(1)
            {
                v.push(format!(
                    "{iface} is attached to {m}, which would switch frames past routing"
                ));
            }
            if rest
                .split_whitespace()
                .any(|w| w.starts_with("xdp") || w == "prog/xdp")
            {
                v.push(format!("an XDP program is attached to {iface}"));
            }
        } else if lower == Some(iface) {
            v.push(format!(
                "{name} is stacked on {iface}; its packets would bypass the isolation rule"
            ));
        }
    }
    match qdiscs {
        Some(q) => {
            if q.lines()
                .any(|l| l.starts_with("qdisc ingress") || l.starts_with("qdisc clsact"))
            {
                v.push(format!("{iface} has a tc ingress/clsact qdisc, whose filters could redirect packets past routing"));
            }
        }
        None => v.push(format!(
            "cannot read {iface}'s tc qdiscs (`tc`), so redirects past routing cannot be ruled out"
        )),
    }
    v
}

/// The isolation state of a running hotspot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Isolation {
    pub verified: bool,
    pub problems: Vec<String>,
    /// IPv6 is off on the adapter too (a second layer; the IPv6 rule is the
    /// guarantee).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_disabled: Option<bool>,
}

fn run_text(sys: &dyn System, program: &str, args: &[&str]) -> Option<String> {
    sys.run(&Cmd::new(program, args))
        .ok()
        .filter(|o| o.ok())
        .map(|o| o.stdout)
}

/// Verify that hotspot clients on `iface` cannot be routed anywhere.
pub fn check(sys: &dyn System, iface: &str) -> Isolation {
    let mut problems = Vec::new();
    for (family, flag) in [("IPv4", "-4"), ("IPv6", "-6")] {
        match run_text(sys, "ip", &[flag, "rule", "show"]) {
            Some(t) => problems.extend(rule_problems(family, &parse_rules(&t), iface)),
            None => problems.push(format!("cannot read the {family} routing rules")),
        }
    }
    match run_text(sys, "ip", &["-o", "-d", "link", "show"]) {
        Some(links) => {
            let qdiscs = run_text(sys, "tc", &["qdisc", "show", "dev", iface]);
            problems.extend(bypass_problems(&links, qdiscs.as_deref(), iface));
        }
        None => problems.push("cannot list network interfaces".into()),
    }
    Isolation {
        verified: problems.is_empty(),
        problems,
        ipv6_disabled: sys
            .read_file(Path::new(&format!(
                "/proc/sys/net/ipv6/conf/{iface}/disable_ipv6"
            )))
            .map(|t| t.trim() == "1"),
    }
}

/// What the preflight reads before the hotspot exists.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostView {
    pub rules4: Option<Vec<Rule>>,
    pub rules6: Option<Vec<Rule>>,
    /// `ip -o -d link show`.
    pub links: Option<String>,
    /// `tc qdisc show` (every device).
    pub qdiscs: Option<String>,
    pub dns: Option<DnsRelay>,
}

pub fn gather(sys: &dyn System) -> HostView {
    HostView {
        rules4: run_text(sys, "ip", &["-4", "rule", "show"]).map(|t| parse_rules(&t)),
        rules6: run_text(sys, "ip", &["-6", "rule", "show"]).map(|t| parse_rules(&t)),
        links: run_text(sys, "ip", &["-o", "-d", "link", "show"]),
        qdiscs: run_text(sys, "tc", &["qdisc", "show"]),
        dns: Some(dns_relay(sys)),
    }
}

impl HostView {
    /// What would stop the isolation rule from being first, or would let
    /// packets around it, on `iface`. Anything unreadable is a problem.
    pub fn problems(&self, iface: &str) -> Vec<String> {
        let mut v = Vec::new();
        for (family, rules) in [("IPv4", &self.rules4), ("IPv6", &self.rules6)] {
            match rules {
                Some(r) => v.extend(preexisting_priority0(r, iface).into_iter().map(|r| {
                    format!("{family} rule '{r}' would be evaluated before the isolation rule")
                })),
                None => v.push(format!(
                    "cannot read the {family} routing rules (`ip rule`)"
                )),
            }
        }
        match &self.links {
            Some(links) => {
                let dev = format!(" dev {iface} ");
                let q = self.qdiscs.as_ref().map(|q| {
                    q.lines()
                        .filter(|l| l.contains(&dev))
                        .collect::<Vec<_>>()
                        .join("\n")
                });
                v.extend(bypass_problems(links, q.as_deref(), iface));
            }
            None => v.push("cannot list network interfaces (`ip link`)".into()),
        }
        v
    }
}

/// Where NetworkManager's shared-mode dnsmasq reads extra options.
pub const DNSMASQ_SHARED_DIR: &str = "/etc/NetworkManager/dnsmasq-shared.d";
/// The drop-in LabLink's documentation tells administrators to install.
pub const DNS_DROPIN: &str = "/etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf";

/// Whether hotspot clients' DNS queries are forwarded to this machine's
/// upstream resolvers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", content = "detail", rename_all = "kebab-case")]
pub enum DnsRelay {
    /// A drop-in stops forwarding (`no-resolv`) or DNS entirely (`port=0`).
    Off(String),
    /// Queries are forwarded (no drop-in, or one that adds servers).
    Forwarded(String),
    /// The drop-ins cannot be read, so forwarding cannot be ruled out.
    Unknown(String),
}

/// Options that make dnsmasq forward queries or read more configuration.
const FORWARDING_KEYS: [&str; 7] = [
    "server",
    "rev-server",
    "servers-file",
    "resolv-file",
    "conf-file",
    "conf-dir",
    "conf-script",
];

/// Read the shared-mode dnsmasq drop-ins the way dnsmasq's `--conf-dir`
/// does (every file except `.*`, `*~` and `#*#`).
pub fn dns_relay(sys: &dyn System) -> DnsRelay {
    let dir = Path::new(DNSMASQ_SHARED_DIR);
    let names = match sys.list_dir(dir) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return DnsRelay::Unknown(format!("cannot list {DNSMASQ_SHARED_DIR}: {e}")),
    };
    let mut no_resolv = None;
    let mut port0 = None;
    let mut forwarding = Vec::new();
    for name in names {
        if name.starts_with('.')
            || name.ends_with('~')
            || (name.starts_with('#') && name.ends_with('#'))
        {
            continue;
        }
        let path = dir.join(&name);
        let Some(text) = sys.read_file(&path) else {
            return DnsRelay::Unknown(format!("cannot read {}", path.display()));
        };
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let (key, value) = match l.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (l, ""),
            };
            match key {
                "no-resolv" => no_resolv = Some(path.display().to_string()),
                "port" if value == "0" => port0 = Some(path.display().to_string()),
                k if FORWARDING_KEYS.contains(&k) => {
                    forwarding.push(format!("{} sets {k}", path.display()))
                }
                _ => {}
            }
        }
    }
    if let Some(p) = port0 {
        return DnsRelay::Off(format!("{p} turns DNS off (port=0)"));
    }
    if !forwarding.is_empty() {
        return DnsRelay::Forwarded(forwarding.join("; "));
    }
    match no_resolv {
        Some(p) => DnsRelay::Off(format!("{p} stops forwarding (no-resolv)")),
        None => DnsRelay::Forwarded(format!("no drop-in in {DNSMASQ_SHARED_DIR} sets no-resolv")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;

    const RULES_OK: &str = "0:\tfrom all lookup local\n0:\tfrom all iif wlan0 prohibit\n5210:\tfrom all fwmark 0x80000/0xff0000 lookup main\n5270:\tfrom all lookup 52\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n";

    #[test]
    fn rule_right_after_local_is_verified() {
        let r = parse_rules(RULES_OK);
        assert_eq!(
            r[1],
            Rule {
                priority: 0,
                spec: "from all iif wlan0 prohibit".into()
            }
        );
        assert!(rule_problems("IPv4", &r, "wlan0").is_empty());
    }

    #[test]
    fn missing_or_preceded_rule_is_a_problem() {
        let r = parse_rules("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n");
        assert!(rule_problems("IPv4", &r, "wlan0")[0].contains("missing"));
        let r = parse_rules(
            "0:\tfrom all lookup local\n0:\tfrom all iif wlan0 lookup main\n0:\tfrom all iif wlan0 prohibit\n",
        );
        let p = rule_problems("IPv6", &r, "wlan0");
        assert_eq!(p.len(), 1);
        assert!(
            p[0].contains("'0: from all iif wlan0 lookup main' is evaluated before"),
            "{p:?}"
        );
        // Another adapter's rule is not ours.
        let r = parse_rules("0:\tfrom all lookup local\n0:\tfrom all iif wlan1 prohibit\n");
        assert!(rule_problems("IPv4", &r, "wlan0")[0].contains("missing"));
    }

    #[test]
    fn rules_added_later_at_priority_0_come_after_ours() {
        // What the kernel shows after `ip rule add pref 0 iif wlan0 lookup main`
        // once the hotspot runs: behind the existing priority-0 rules.
        let r = parse_rules("0:\tfrom all lookup local\n0:\tfrom all iif wlan0 prohibit\n0:\tfrom all iif wlan0 lookup main\n");
        assert!(rule_problems("IPv4", &r, "wlan0").is_empty());
        assert!(preexisting_priority0(&r, "wlan0") == vec!["0: from all iif wlan0 lookup main"]);
    }

    #[test]
    fn bypasses_on_the_adapter_are_found() {
        let links = "1: lo: <LOOPBACK,UP> mtu 65536\n7: wlan0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue master br0 state UP\n9: mv0@wlan0: <BROADCAST> mtu 1500\n10: wlan1: <UP> mtu 1500 prog/xdp id 3\n";
        let p = bypass_problems(links, Some("qdisc noqueue 0: root refcnt 2\n"), "wlan0");
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].contains("attached to br0"));
        assert!(p[1].contains("mv0 is stacked on wlan0"));
        let p = bypass_problems(
            "7: wlan0: <UP> mtu 1500 xdpgeneric/id:4\n",
            Some("qdisc clsact ffff: parent ffff:fff1\n"),
            "wlan0",
        );
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(
            bypass_problems("7: wlan0: <UP> mtu 1500\n", None, "wlan0")[0].contains("cannot read")
        );
        assert!(bypass_problems(
            "7: wlan0: <UP> mtu 1500 qdisc noqueue\n",
            Some("qdisc noqueue 0: root\n"),
            "wlan0"
        )
        .is_empty());
    }

    #[test]
    fn check_runs_ip_and_tc() {
        let sys = FakeSystem::new();
        sys.ok("ip -4 rule show", RULES_OK);
        sys.ok(
            "ip -6 rule show",
            "0:\tfrom all lookup local\n0:\tfrom all iif wlan0 prohibit\n32766:\tfrom all lookup main\n",
        );
        sys.ok(
            "ip -o -d link show",
            "7: wlan0: <UP> mtu 1500 qdisc noqueue\n",
        );
        sys.ok(
            "tc qdisc show dev wlan0",
            "qdisc noqueue 0: root refcnt 2\n",
        );
        sys.file("/proc/sys/net/ipv6/conf/wlan0/disable_ipv6", "1\n");
        let iso = check(&sys, "wlan0");
        assert!(iso.verified, "{:?}", iso.problems);
        assert_eq!(iso.ipv6_disabled, Some(true));
        // The IPv6 rule vanished (later rules win in FakeSystem).
        sys.ok(
            "ip -6 rule show",
            "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
        );
        let iso = check(&sys, "wlan0");
        assert!(!iso.verified);
        assert!(
            iso.problems[0].contains("IPv6 isolation rule"),
            "{:?}",
            iso.problems
        );
    }

    #[test]
    fn dns_relay_needs_a_drop_in() {
        let dir = DNSMASQ_SHARED_DIR;
        let sys = FakeSystem::new();
        assert!(matches!(dns_relay(&sys), DnsRelay::Forwarded(_)));
        sys.file(DNS_DROPIN, "# LabLink\nno-resolv\n");
        assert!(matches!(dns_relay(&sys), DnsRelay::Off(d) if d.contains("no-resolv")));
        sys.file(DNS_DROPIN, "no-resolv\nserver=1.1.1.1\n");
        assert!(matches!(dns_relay(&sys), DnsRelay::Forwarded(d) if d.contains("server")));
        sys.file(DNS_DROPIN, "no-resolv\n");
        sys.file(&format!("{dir}/other.conf"), "conf-dir=/etc/dnsmasq.d\n");
        assert!(matches!(dns_relay(&sys), DnsRelay::Forwarded(_)));
        sys.file(&format!("{dir}/other.conf"), "port=0\n");
        assert!(matches!(dns_relay(&sys), DnsRelay::Off(d) if d.contains("port=0")));
        // Files dnsmasq skips do not count either way.
        let sys = FakeSystem::new();
        sys.file(&format!("{dir}/.hidden"), "no-resolv\n");
        sys.file(&format!("{dir}/old.conf~"), "no-resolv\n");
        assert!(matches!(dns_relay(&sys), DnsRelay::Forwarded(_)));
    }
}
