//! Keeping hotspot clients off every other network.
//!
//! NetworkManager's shared mode (the only mode that gives hotspot clients
//! DHCP without a root helper) turns on IPv4 forwarding and NAT. LabLink
//! does not rely on either being off. Two independent layers stop hotspot
//! traffic from leaving this machine:
//!
//! 1. The field filter ([`crate::filter`]), installed once by an
//!    administrator: an nftables table that drops every forwarded packet
//!    from or to the adapter, armed before the access point starts and
//!    until after it stops. A drop verdict is final in nftables, so no
//!    other table, rule order or priority can let such a packet through.
//! 2. One policy-routing rule per address family in the hotspot profile:
//!
//!    ```text
//!    priority 0 iif <adapter> prohibit
//!    ```
//!
//!    NetworkManager installs it when the profile activates and removes it
//!    when it goes down. Priority 0 places it right after the kernel's
//!    `0: lookup local`, so packets for this machine's own addresses are
//!    still delivered and every other packet from the adapter is refused
//!    before any routing table. Rules added later without a priority get
//!    one below the second rule's, which a higher priority than 0 would
//!    put ahead of this rule (wg-quick does this); at 0 they land behind
//!    it. The check reads the real evaluation order (`ip rule show`)
//!    instead of trusting equal-priority insertion order.
//!
//! Clients reach each other through the access point itself (802.11 frames
//! between stations never enter this machine's IP stack).
//!
//! [`check`] verifies both layers (and that nothing on the adapter bypasses
//! routing: a bridge, an upper device, tc or XDP) after the hotspot starts,
//! and `lablinkd` repeats it while the hotspot runs. When it fails the
//! hotspot is stopped: isolation that cannot be verified is treated as
//! absent. The two layers prevent leaks; the repeated check only recovers,
//! seconds later.
//!
//! DNS needs nothing extra: the filter refuses port 53 from hotspot
//! clients, so NetworkManager's dnsmasq never gets a query to forward, and
//! no system-wide dnsmasq drop-in is needed (one in
//! `/etc/NetworkManager/dnsmasq-shared.d` would apply to every shared
//! connection on the machine).

use crate::filter::{self, Filter};
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
    /// The field filter's state for the adapter (must be armed).
    pub filter: Filter,
    /// IPv6 is off on the adapter too (an extra layer; the filter and the
    /// IPv6 rule do not depend on it).
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
    let filter = filter::state(sys, iface);
    problems.extend(filter.problem(iface));
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
        filter,
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
    /// The field filter script is installed.
    pub filter_installed: bool,
    /// Its table is loaded (`None`: not probed).
    pub filter_loaded: Option<Result<bool, String>>,
    /// What the installed script lets clients reach on this machine.
    pub filter_services: Vec<String>,
}

pub fn gather(sys: &dyn System) -> HostView {
    let script = filter::script(sys);
    HostView {
        rules4: run_text(sys, "ip", &["-4", "rule", "show"]).map(|t| parse_rules(&t)),
        rules6: run_text(sys, "ip", &["-6", "rule", "show"]).map(|t| parse_rules(&t)),
        links: run_text(sys, "ip", &["-o", "-d", "link", "show"]),
        qdiscs: run_text(sys, "tc", &["qdisc", "show"]),
        filter_installed: script.is_some(),
        filter_loaded: Some(filter::loaded(sys)),
        filter_services: script.as_deref().map(filter::services).unwrap_or_default(),
    }
}

impl HostView {
    /// What would stop the isolation rule from being first, or would let
    /// packets around it, on `iface`. Anything unreadable is a problem.
    pub fn problems(&self, iface: &str) -> Vec<String> {
        let mut v = Vec::new();
        if !iface.starts_with("wl") {
            v.push(format!(
                "the field filter arms only Wi-Fi adapters named wl*, and {iface} is not one"
            ));
        }
        if !self.filter_installed {
            v.push(format!(
                "the field filter is not installed ({}; see docs/FIELD_NETWORK.md, \"The field filter\")",
                filter::SCRIPT
            ));
        }
        match &self.filter_loaded {
            Some(Ok(true)) => {}
            Some(Ok(false)) if self.filter_installed => v.push(format!(
                "the field filter is installed but not loaded (an administrator runs `{} load`)",
                filter::SCRIPT
            )),
            Some(Ok(false)) => {}
            Some(Err(why)) => v.push(format!("the field filter cannot be checked: {why}")),
            None => v.push("the field filter was not checked".into()),
        }
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
        // The routing rules alone are not enough: the filter must be armed.
        sys.ok(
            "ip -6 rule show",
            "0:\tfrom all lookup local\n0:\tfrom all iif wlan0 prohibit\n",
        );
        sys.set_filter("open");
        let iso = check(&sys, "wlan0");
        assert!(!iso.verified);
        assert_eq!(iso.filter, Filter::Open);
        assert_eq!(iso.problems.len(), 1, "{:?}", iso.problems);
        sys.set_filter("unloaded");
        assert!(check(&sys, "wlan0").problems[0].contains("not loaded"));
    }

    #[test]
    fn preflight_view_needs_the_filter_and_a_wifi_name() {
        let sys = FakeSystem::new();
        sys.ok("ip -4 rule show", RULES_OK);
        sys.ok("ip -6 rule show", "0:\tfrom all lookup local\n");
        sys.ok("ip -o -d link show", "7: wlan0: <UP> mtu 1500\n");
        sys.ok(
            "tc qdisc show",
            "qdisc noqueue 0: dev wlan0 root refcnt 2\n",
        );
        let v = gather(&sys);
        assert_eq!(
            v.problems("wlan0"),
            vec![format!(
                "the field filter is not installed ({}; see docs/FIELD_NETWORK.md, \"The field filter\")",
                filter::SCRIPT
            )]
        );
        sys.file(filter::SCRIPT, "FIELD_TCP=\"22\"\nFIELD_UDP=\"\"\n");
        let v = gather(&sys);
        assert!(v.problems("wlan0").is_empty(), "{:?}", v.problems("wlan0"));
        assert_eq!(v.filter_services, vec!["tcp 22"]);
        assert!(v.problems("eth1")[0].contains("named wl*"));
        sys.set_filter("unloaded");
        assert!(gather(&sys).problems("wlan0")[0].contains("installed but not loaded"));
        sys.set_filter("denied");
        assert!(gather(&sys).problems("wlan0")[0].contains("cannot be checked"));
    }
}
