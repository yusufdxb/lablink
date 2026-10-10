//! One health-monitor task per tracked device.
//!
//! Each task sleeps on a timer (5 s while reachable, exponential back-off up
//! to 30 s while not) or until woken by an event (neighbor-table change, mDNS
//! sighting, discovery, settings change). A woken monitor never runs more than
//! once per [`MIN_GAP`], so an event storm cannot turn into a probe storm.

use crate::metrics::inc;
use crate::probe::AuthOutcome;
use crate::registry::{CheckPlan, ProbeReport};
use crate::state::State;
use lablink_core::identity::Observation;
use lablink_core::model::PortState;
use lablink_core::time::now_ms;
use lablink_discovery::{IcmpOutcome, TcpOutcome};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Minimum spacing between two checks of the same device.
pub const MIN_GAP: Duration = Duration::from_secs(1);
const KEYSCAN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run(state: Arc<State>, name: String) {
    let wake = state.waker(&name);
    let mut last_check: Option<Instant> = None;
    // First check promptly but staggered slightly so startup is not a burst.
    let mut first = true;
    loop {
        let monitoring = state.reg().engaged(&name);
        let woken = if !monitoring {
            tokio::select! {
                _ = state.cancel.cancelled() => break,
                _ = wake.notified() => true,
            }
        } else if first {
            first = false;
            true
        } else {
            let interval = Duration::from_secs(state.reg().next_interval_s(&name));
            tokio::select! {
                _ = state.cancel.cancelled() => break,
                _ = wake.notified() => true,
                _ = tokio::time::sleep(interval) => false,
            }
        };
        if woken {
            if let Some(t) = last_check {
                let since = t.elapsed();
                if since < MIN_GAP {
                    tokio::select! {
                        _ = state.cancel.cancelled() => break,
                        _ = tokio::time::sleep(MIN_GAP - since) => {}
                    }
                }
            }
        }
        if !state.reg().engaged(&name) {
            continue;
        }
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            _ = check_device(&state, &name) => {}
        }
        state.after_update();
        last_check = Some(Instant::now());
    }
    tracing::debug!(device = %name, "monitor stopped");
}

fn connect_timeout(state: &State) -> Duration {
    Duration::from_millis(state.cfg.daemon.connect_timeout_ms)
}

/// One liveness probe of `ip` for `plan`.
async fn liveness(state: &State, plan: &CheckPlan, ip: IpAddr) -> ProbeReport {
    let to = connect_timeout(state);
    let icmp_ok = plan.icmp_usable && !state.icmp_unsupported.load(Ordering::Relaxed);
    let mut rep = ProbeReport {
        ip,
        up: false,
        port: None,
        rtt: None,
        method: "none",
        detail: None,
        icmp_answered: None,
    };

    let addr = SocketAddr::new(ip, plan.port);
    async fn tcp(st: &State, addr: SocketAddr, to: Duration) -> TcpOutcome {
        inc(&st.metrics.tcp_probes);
        st.prober.tcp(addr, to).await
    }
    async fn icmp(st: &State, ip: IpAddr, to: Duration) -> IcmpOutcome {
        inc(&st.metrics.icmp_probes);
        st.prober.icmp(ip, to).await
    }
    let apply_tcp = |rep: &mut ProbeReport, t: &TcpOutcome| match t {
        TcpOutcome::Open(rtt) => {
            rep.up = true;
            rep.port = Some(PortState::Open);
            rep.rtt = Some(*rtt);
            rep.method = "tcp";
            true
        }
        TcpOutcome::Refused(rtt) => {
            rep.up = true;
            rep.port = Some(PortState::Closed);
            rep.rtt = Some(*rtt);
            rep.method = "tcp";
            true
        }
        TcpOutcome::Timeout => {
            rep.detail = Some(format!("TCP/{} timed out", plan.port));
            false
        }
        TcpOutcome::Unreachable(e) | TcpOutcome::Error(e) => {
            rep.detail = Some(e.clone());
            false
        }
    };
    let apply_icmp = |rep: &mut ProbeReport, r: IcmpOutcome| match r {
        IcmpOutcome::Reply(rtt) => {
            rep.up = true;
            rep.rtt = rep.rtt.or(Some(rtt));
            if rep.method == "none" {
                rep.method = "icmp";
            }
            rep.icmp_answered = Some(true);
            true
        }
        IcmpOutcome::Timeout => {
            rep.icmp_answered = Some(false);
            rep.detail
                .get_or_insert_with(|| "ICMP echo timed out".into());
            false
        }
        IcmpOutcome::Unreachable(e) => {
            rep.icmp_answered = Some(false);
            rep.detail = Some(e);
            false
        }
        IcmpOutcome::Unsupported(e) => {
            // Only an IPv4 permission failure means ICMP is unusable on this host.
            if ip.is_ipv4() && !state.icmp_unsupported.swap(true, Ordering::Relaxed) {
                tracing::warn!(error = %e, "unprivileged ICMP unavailable; falling back to TCP probes");
            }
            false
        }
    };

    if plan.ssh && (plan.port_check_due || !icmp_ok) {
        let t = tcp(state, addr, to).await;
        if !apply_tcp(&mut rep, &t) && icmp_ok {
            let r = icmp(state, ip, to).await;
            if apply_icmp(&mut rep, r) {
                rep.port = Some(PortState::Filtered);
            }
        }
    } else if icmp_ok {
        let r = icmp(state, ip, to).await;
        if !apply_icmp(&mut rep, r) && plan.ssh {
            // ICMP may be filtered while the host is fine: confirm over TCP.
            let t = tcp(state, addr, to).await;
            apply_tcp(&mut rep, &t);
        }
    } else if plan.ssh {
        let t = tcp(state, addr, to).await;
        apply_tcp(&mut rep, &t);
    } else {
        rep.detail = Some("no probe method available (ICMP disabled and ssh: false)".into());
    }
    rep
}

/// Keys the user's known_hosts trusts for this device, split into entries
/// keyed by the device's names and entries keyed by its bare IP.
async fn lookup_user_known(
    state: &State,
    name: &str,
    ip: IpAddr,
    port: u16,
) -> crate::registry::UserKnown {
    inc(&state.metrics.known_hosts_lookups);
    let fmt = |h: &str| {
        if port == 22 {
            h.to_string()
        } else {
            format!("[{h}]:{port}")
        }
    };
    // Only names the user wrote (configured hostnames, the ssh host or the
    // device name). Learned hostnames were announced by the network and must
    // not select which of the user's known_hosts entries apply.
    let mut names: Vec<String> = Vec::new();
    if let Some(d) = state.reg().device(name) {
        for h in &d.cfg.hostnames {
            names.push(fmt(h));
        }
        names.push(fmt(&d.ssh_host()));
    }
    names.sort();
    names.dedup();
    crate::registry::UserKnown {
        by_name: state.prober.user_known_keys(names).await,
        by_ip: state
            .prober
            .user_known_keys(vec![fmt(&ip.to_string())])
            .await,
    }
}

/// Run one full check of a device: resolve (if needed), probe, fail over,
/// then verify identity and login when due.
pub async fn check_device(state: &State, name: &str) {
    inc(&state.metrics.device_checks);
    let now = now_ms();
    let Some(mut plan) = state.reg().plan(name, now) else {
        return;
    };
    if let Some(gw) = plan.via.clone() {
        check_via(state, name, &plan, &gw).await;
        return;
    }

    if !plan.hostnames_to_resolve.is_empty() {
        state.reg().note_resolved(name, now);
        for h in plan.hostnames_to_resolve.clone() {
            inc(&state.metrics.resolves);
            let ips = state
                .prober
                .resolve(h.clone(), Duration::from_secs(2))
                .await;
            let mut ips: Vec<IpAddr> = ips
                .into_iter()
                .filter(|ip| crate::registry::usable_address(*ip))
                .collect();
            // Prefer addresses on directly attached networks (mDNS caches can
            // still offer a link this host is no longer on), then IPv4.
            {
                let reg = state.reg();
                ips.sort_by_key(|ip| (!reg.is_attached_ip(*ip), !ip.is_ipv4()));
            }
            for ip in ips {
                let src = if h
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
                    .ends_with(".local")
                {
                    "mdns"
                } else {
                    "dns"
                };
                let obs = Observation {
                    ip: Some(ip),
                    mac: None,
                    names: vec![h.clone()],
                    host_keys: vec![],
                };
                let wake = state.reg().observe(&obs, src, None, now);
                state.wake_many(wake.into_iter().filter(|n| n != name));
            }
        }
        match state.reg().plan(name, now) {
            Some(p) => plan = p,
            None => return,
        }
    }
    let Some(&primary) = plan.candidates.first() else {
        tracing::trace!(device = name, "no candidate address yet");
        return;
    };

    let mut report = liveness(state, &plan, primary).await;
    if !report.up {
        for &alt in plan.candidates.iter().skip(1).take(4) {
            let ar = liveness(state, &plan, alt).await;
            if !ar.up {
                continue;
            }
            let mut keys = Vec::new();
            if plan.ssh && ar.port == Some(PortState::Open) {
                inc(&state.metrics.keyscans);
                if let Ok(k) = state.prober.keyscan(alt, plan.port, KEYSCAN_TIMEOUT).await {
                    keys = k;
                }
            }
            let mac = state.reg().neighbor_mac(alt);
            let obs = Observation {
                ip: Some(alt),
                mac,
                names: vec![],
                host_keys: keys,
            };
            let wake = state.reg().observe(&obs, "failover", Some(name), now_ms());
            state.wake_many(wake.into_iter().filter(|n| n != name));
            let moved = state.reg().device(name).and_then(|d| d.rec.current_ip) == Some(alt);
            if moved {
                tracing::info!(device = name, from = %primary, to = %alt, "failed over to alternate address");
                report = ar;
                break;
            }
        }
    }
    state.reg().apply_probe(name, &report, now_ms());

    let f = state.reg().follow_up(name, now_ms());
    let auth_targets = if let Some((ip, port)) = f.keyscan {
        inc(&state.metrics.keyscans);
        let scanned = state.prober.keyscan(ip, port, KEYSCAN_TIMEOUT).await;
        let user_known = if scanned.is_ok() {
            lookup_user_known(state, name, ip, port).await
        } else {
            Default::default()
        };
        let wake = state
            .reg()
            .apply_keys(name, ip, scanned, &user_known, now_ms());
        state.wake_many(wake.into_iter().filter(|n| n != name));
        state.reg().follow_up(name, now_ms()).auth
    } else {
        f.auth
    };

    if !auth_targets.is_empty() {
        crate::ipc::ensure_known_hosts(state).await;
        let ip: Option<IpAddr> = auth_targets[0].ip.parse().ok();
        let timeout = Duration::from_secs(state.cfg.ssh.connect_timeout_s + 10);
        let mut last: Option<(Option<String>, AuthOutcome)> = None;
        for t in auth_targets {
            inc(&state.metrics.auth_checks);
            let user = t.username.clone();
            let out = state.prober.auth(t, timeout).await;
            let stop = !matches!(out, AuthOutcome::Rejected { .. });
            last = Some((user, out));
            if stop {
                break;
            }
        }
        if let (Some(ip), Some((user, out))) = (ip, last) {
            state
                .reg()
                .apply_auth(name, ip, user.as_deref(), &out, now_ms());
        }
    }
    let due = state.reg().services_due(name, now_ms());
    if !due.is_empty() {
        let user = state.reg().device(name).and_then(|d| d.username());
        let target = state.reg().target_for(name, user);
        if let Ok(target) = target {
            crate::ipc::ensure_known_hosts(state).await;
            for (idx, check) in due {
                let r = check.run(&*state.prober, target.clone()).await;
                state.reg().apply_service(name, idx, &r, now_ms());
            }
        }
    }
    if state.reg().has_dirty() {
        state.request_persist();
    }
}

/// Shell snippet run on a gateway to check `ip` (and `port` if given). The
/// address is an `IpAddr`, so nothing user-controlled reaches the shell.
pub fn via_probe_command(ip: IpAddr, port: Option<u16>) -> String {
    let mut s = format!(
        "out=$(ping -n -c 1 -W 1 {ip} 2>/dev/null); p=$?; r=$(printf '%s' \"$out\" | sed -n 's/.*time=\\([0-9.]*\\).*/\\1/p' | head -n 1);"
    );
    match port {
        Some(port) => s.push_str(&format!(
            " timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/{port}' >/dev/null 2>&1; t=$?;"
        )),
        None => s.push_str(" t=-;"),
    }
    s.push_str(" echo \"lablink-via ping=$p rtt=$r tcp=$t\"");
    s
}

/// Parse the `lablink-via ping=<n> rtt=<ms> tcp=<n|->` line.
pub fn parse_via_output(stdout: &str) -> Option<(i32, Option<f64>, Option<i32>)> {
    let line = stdout.lines().find(|l| l.starts_with("lablink-via "))?;
    let mut ping = None;
    let mut rtt = None;
    let mut tcp = None;
    for kv in line.split_whitespace().skip(1) {
        match kv.split_once('=') {
            Some(("ping", v)) => ping = v.parse().ok(),
            Some(("rtt", v)) => rtt = v.parse().ok(),
            Some(("tcp", v)) => tcp = v.parse().ok(),
            _ => {}
        }
    }
    Some((ping?, rtt, tcp))
}

/// Check a device that is only reachable through a gateway device.
async fn check_via(state: &State, name: &str, plan: &CheckPlan, gw: &str) {
    let Some(&ip) = plan.candidates.first() else {
        return;
    };
    // Bind first: a guard in the match scrutinee would live through the arms.
    if state.reg().gateway_pending(gw) {
        return; // gateway not checked yet; retry on the next round
    }
    let gateway = state.reg().gateway_target(gw);
    let gt = match gateway {
        Ok(t) => t,
        Err(reason) => {
            state.reg().via_unavailable(name, reason, now_ms());
            return;
        }
    };
    crate::ipc::ensure_known_hosts(state).await;
    inc(&state.metrics.via_checks);
    let cmd = via_probe_command(ip, plan.ssh.then_some(plan.port));
    let out = state
        .prober
        .exec(gt.clone(), cmd, Duration::from_secs(8))
        .await;
    let Some((ping, rtt, tcp)) = parse_via_output(&out.stdout) else {
        let why = out
            .stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no output")
            .to_string();
        state.reg().via_unavailable(
            name,
            format!("check through gateway '{gw}' failed: {why}"),
            now_ms(),
        );
        return;
    };
    let up = ping == 0 || tcp == Some(0);
    let port = match (plan.ssh, tcp) {
        (false, _) => None,
        (true, Some(0)) => Some(PortState::Open),
        (true, Some(1)) if up => Some(PortState::Closed),
        (true, Some(124)) if up => Some(PortState::Filtered),
        _ => None,
    };
    let report = ProbeReport {
        ip,
        up,
        port,
        rtt: rtt.map(|ms| Duration::from_micros((ms * 1000.0) as u64)),
        method: "via-gateway",
        detail: (!up).then(|| format!("no answer to ping from gateway '{gw}'")),
        icmp_answered: None,
    };
    state.reg().apply_probe(name, &report, now_ms());

    // Identity and login of SSH devices behind the gateway.
    let f = state.reg().follow_up(name, now_ms());
    let auth = if let Some((kip, kport)) = f.keyscan {
        inc(&state.metrics.keyscans);
        let o = state
            .prober
            .exec(
                gt,
                format!("ssh-keyscan -T 5 -p {kport} -t ed25519,ecdsa,rsa {kip} 2>/dev/null"),
                Duration::from_secs(10),
            )
            .await;
        let keys = lablink_ssh::parse_keyscan_output(&o.stdout);
        let scanned = if keys.is_empty() {
            Err(format!("no host keys returned through gateway '{gw}'"))
        } else {
            Ok(keys)
        };
        let user_known = if scanned.is_ok() {
            lookup_user_known(state, name, kip, kport).await
        } else {
            Default::default()
        };
        state
            .reg()
            .apply_keys(name, kip, scanned, &user_known, now_ms());
        state.reg().follow_up(name, now_ms()).auth
    } else {
        f.auth
    };
    if let Some(t) = auth.into_iter().next() {
        inc(&state.metrics.auth_checks);
        let user = t.username.clone();
        let o = state
            .prober
            .auth(
                t,
                Duration::from_secs(state.cfg.ssh.connect_timeout_s * 2 + 10),
            )
            .await;
        state
            .reg()
            .apply_auth(name, ip, user.as_deref(), &o, now_ms());
    }
    if state.reg().has_dirty() {
        state.request_persist();
    }
}

/// Host keys of `name` at `ip:port`: scanned directly, or by running
/// ssh-keyscan on its gateway when the device is behind one.
pub async fn scan_keys(
    state: &State,
    name: &str,
    ip: IpAddr,
    port: u16,
) -> Result<Vec<lablink_core::identity::HostKey>, String> {
    inc(&state.metrics.keyscans);
    let via = {
        let reg = state.reg();
        reg.device(name).and_then(|d| reg.route_via(d))
    };
    match via {
        None => state.prober.keyscan(ip, port, KEYSCAN_TIMEOUT).await,
        Some(gw) => {
            let gt = state.reg().gateway_target(&gw)?;
            crate::ipc::ensure_known_hosts(state).await;
            let o = state
                .prober
                .exec(
                    gt,
                    format!("ssh-keyscan -T 5 -p {port} -t ed25519,ecdsa,rsa {ip} 2>/dev/null"),
                    Duration::from_secs(10),
                )
                .await;
            let keys = lablink_ssh::parse_keyscan_output(&o.stdout);
            if keys.is_empty() {
                Err(format!("no host keys returned through gateway '{gw}'"))
            } else {
                Ok(keys)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via_command_and_parse() {
        let c = via_probe_command("192.168.50.161".parse().unwrap(), None);
        assert!(c.contains("ping -n -c 1 -W 1 192.168.50.161"));
        assert!(!c.contains("/dev/tcp"));
        let c = via_probe_command("192.168.50.20".parse().unwrap(), Some(22));
        assert!(c.contains("/dev/tcp/192.168.50.20/22"));
        assert_eq!(
            parse_via_output("lablink-via ping=0 rtt=0.412 tcp=-\n"),
            Some((0, Some(0.412), None))
        );
        assert_eq!(
            parse_via_output("motd\nlablink-via ping=1 rtt= tcp=124\n"),
            Some((1, None, Some(124)))
        );
        assert_eq!(parse_via_output("garbage"), None);
    }

    /// [localhost] The snippet really runs in sh and produces a parseable line.
    #[test]
    fn via_command_runs_in_a_real_shell() {
        let c = via_probe_command("127.0.0.1".parse().unwrap(), Some(1));
        let o = std::process::Command::new("sh")
            .args(["-c", &c])
            .output()
            .unwrap();
        let (ping, _, tcp) =
            parse_via_output(&String::from_utf8_lossy(&o.stdout)).expect("parseable");
        assert_eq!(ping, 0, "loopback answers ping");
        assert_eq!(tcp, Some(1), "port 1 on loopback is closed (refused)");
    }
}
