//! Staged discovery. Runs at startup, on network changes, on request, and
//! (optionally) on a slow background interval. Stages, cheapest first:
//!
//! 1. known/cached devices and configured static addresses (wake monitors)
//! 2. OS neighbor table (rtnetlink dump)
//! 3. mDNS resolution of configured `.local` names
//! 4. system hostname resolution of other configured names
//! 5. bounded active scan of allowlisted, directly attached networks of the
//!    ACTIVE site (ICMP sweep; the kernel's ARP replies reveal hosts that
//!    drop ICMP; TCP/22 only for hosts not checked recently). A site that is
//!    AWAY, unconfirmed, or chosen only by a subnet another site shares is
//!    never scanned (`lablink_core::site::Decision::scan_permission`).
//! 6. SSH host-key verification of responsive unmatched hosts, which is how a
//!    device that moved to an unexpected address is re-identified.

use crate::metrics::{add, inc};
use crate::state::State;
use lablink_core::identity::Observation;
use lablink_core::model::{DiscoverReport, PortState, StageReport, SCHEMA_VERSION};
use lablink_core::net::{scan_targets, ScanRefusal};
use lablink_core::protocol::{ApiError, ErrorCode};
use lablink_core::time::now_ms;
use lablink_discovery::{sweep, IcmpOutcome, TcpOutcome};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// TCP/22 re-check interval for unmatched hosts during scans.
const SCAN_TCP_RECHECK_MS: u64 = 600_000;
/// Host-key re-scan interval for unmatched hosts.
const SCAN_KEYS_RECHECK_MS: u64 = 600_000;
const SWEEP_ICMP_TIMEOUT: Duration = Duration::from_millis(800);
const KEYSCAN_CONCURRENCY: usize = 4;

/// A request to run discovery.
pub struct DiscoverCmd {
    pub scan_cidr: Option<String>,
    pub reason: &'static str,
    pub reply: Option<oneshot::Sender<Result<DiscoverReport, ApiError>>>,
}

pub async fn run_coordinator(state: Arc<State>, mut rx: mpsc::Receiver<DiscoverCmd>) {
    let interval = state.cfg.daemon.scan_interval_s;
    let mut next_periodic = (interval > 0).then(|| Instant::now() + Duration::from_secs(interval));
    loop {
        let sleep_for = next_periodic
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_secs(86_400));
        let cmd = tokio::select! {
            _ = state.cancel.cancelled() => break,
            c = rx.recv() => match c { Some(c) => c, None => break },
            _ = tokio::time::sleep(sleep_for), if next_periodic.is_some() => {
                DiscoverCmd { scan_cidr: None, reason: "periodic", reply: None }
            }
        };
        let result = tokio::select! {
            _ = state.cancel.cancelled() => break,
            r = run_discovery(&state, cmd.scan_cidr.as_deref(), cmd.reason) => r,
        };
        if let Some(reply) = cmd.reply {
            let _ = reply.send(result);
        }
        if interval > 0 {
            next_periodic = Some(Instant::now() + Duration::from_secs(interval));
        }
    }
}

fn stage(stages: &mut Vec<StageReport>, name: &str, result: &str, detail: String, t: Instant) {
    stages.push(StageReport {
        stage: name.into(),
        result: result.into(),
        detail,
        duration_ms: t.elapsed().as_millis() as u64,
    });
}

/// Validate a one-time scan request without running it.
pub fn check_one_time(state: &State, cidr: &str) -> Result<ipnet::Ipv4Net, ScanRefusal> {
    let reg = state.reg();
    let prefixes = reg.local_prefixes();
    reg.allowlist.check_one_time_scan(cidr, &prefixes)
}

pub async fn run_discovery(
    state: &State,
    scan_cidr: Option<&str>,
    reason: &str,
) -> Result<DiscoverReport, ApiError> {
    inc(&state.metrics.discoveries);
    let started = Instant::now();
    tracing::debug!(reason, "discovery started");
    let mut stages = Vec::new();
    let mut probed = 0u64;
    let mut responsive = 0u64;

    // Stage 2 first so that attachment checks below use fresh interfaces.
    let t = Instant::now();
    match state.prober.net_snapshot().await {
        Some(s) => {
            let n_entries = s.neighbors.len();
            let now = now_ms();
            let mut wake = Vec::new();
            let mut reg = state.reg();
            let obs = reg.set_snapshot(s);
            let valid = obs.len();
            for (o, src) in obs {
                wake.extend(reg.observe(&o, &src, None, now));
            }
            let wake2 = reg.refresh_sites_if_stale(now);
            drop(reg);
            state.wake_many(wake);
            state.wake_many(wake2);
            stage(
                &mut stages,
                "neighbor_table",
                "ok",
                format!("{n_entries} entries, {valid} with a valid link-layer address"),
                t,
            );
        }
        None => stage(
            &mut stages,
            "neighbor_table",
            "error",
            "netlink dump failed".into(),
            t,
        ),
    }

    // One-time scans are validated before anything else runs.
    let one_time = match scan_cidr {
        Some(c) => match check_one_time(state, c) {
            Ok(v4) => Some(v4),
            Err(refusal) => {
                tracing::warn!(cidr = c, reason = %refusal, "one-time active scan refused");
                state.reg().event(
                    None,
                    "scan_refused",
                    format!("one-time scan of {c} refused: {refusal}"),
                );
                return Err(ApiError::new(ErrorCode::Refused, refusal.to_string()));
            }
        },
        None => None,
    };

    // Stage 1: wake monitors of known devices (they probe cached and static addresses).
    let t = Instant::now();
    let names = state.reg().monitored_names();
    let n = names.len();
    state.wake_many(names);
    stage(
        &mut stages,
        "known_devices",
        "ok",
        format!("{n} monitored devices re-checking cached and configured addresses"),
        t,
    );

    // Stages 3+4: resolve configured hostnames of devices that are not located.
    type DeviceHostnames = Vec<(String, String)>;
    let (local_names, dns_names): (DeviceHostnames, DeviceHostnames) = {
        let reg = state.reg();
        let mut all = Vec::new();
        for name in reg.monitored_names() {
            let d = reg.device(&name).unwrap();
            if d.discovery() == lablink_core::model::DiscoveryState::Located {
                continue;
            }
            for h in &d.cfg.hostnames {
                all.push((name.clone(), h.clone()));
            }
        }
        all.into_iter().partition(|(_, h)| {
            h.trim_end_matches('.')
                .to_ascii_lowercase()
                .ends_with(".local")
        })
    };
    for (label, list) in [("mdns", local_names), ("hostname_resolution", dns_names)] {
        let t = Instant::now();
        if label == "mdns" && !state.cfg.daemon.mdns {
            stage(
                &mut stages,
                label,
                "skipped",
                "mDNS disabled in config".into(),
                t,
            );
            continue;
        }
        if list.is_empty() {
            stage(
                &mut stages,
                label,
                "skipped",
                "no unlocated device has such hostnames".into(),
                t,
            );
            continue;
        }
        let total = list.len();
        let mut found = 0;
        for (dev, h) in list {
            inc(&state.metrics.resolves);
            let ips = state
                .prober
                .resolve(h.clone(), Duration::from_secs(2))
                .await;
            let now = now_ms();
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
                found += 1;
                let obs = Observation {
                    ip: Some(ip),
                    mac: None,
                    names: vec![h.clone()],
                    host_keys: vec![],
                };
                let src = if label == "mdns" { "mdns" } else { "dns" };
                let wake = state.reg().observe(&obs, src, None, now);
                state.wake_many(wake);
                tracing::debug!(device = %dev, host = %h, %ip, "resolved");
            }
        }
        stage(
            &mut stages,
            label,
            "ok",
            format!("{total} names queried, {found} addresses found"),
            t,
        );
    }

    // Stage 5: bounded active scans.
    let mut scanned_nets = Vec::new();
    let nets = state.reg().allowlist.networks.clone();
    for net in nets.iter().filter(|n| n.active_scan) {
        let t = Instant::now();
        let label = format!("active_scan:{}/{}", net.site, net.name);
        let site_gate = {
            let reg = state.reg();
            match reg.decision(&net.site) {
                Some(d) => d
                    .scan_permission()
                    .map_err(|why| format!("site '{}': {why}", reg.site_name(&net.site))),
                None => Err(format!("site '{}' has not been evaluated yet", net.site)),
            }
        };
        if let Err(why) = site_gate {
            tracing::debug!(network = %net.name, site = %net.site, reason = %why, "active scan skipped");
            stage(&mut stages, &label, "skipped", why, t);
            continue;
        }
        let decision = {
            let reg = state.reg();
            let prefixes = reg.local_prefixes();
            reg.allowlist.check_auto_scan(net, &prefixes)
        };
        match decision {
            Ok(v4) => {
                let (p, r) = sweep_network(state, v4).await;
                probed += p;
                responsive += r;
                scanned_nets.push(ipnet::IpNet::V4(v4));
                stage(
                    &mut stages,
                    &label,
                    "ok",
                    format!("{v4}: {p} addresses probed, {r} responsive"),
                    t,
                );
            }
            Err(refusal @ ScanRefusal::NotConnected(_)) => {
                tracing::debug!(network = %net.name, reason = %refusal, "active scan skipped");
                stage(&mut stages, &label, "skipped", refusal.to_string(), t);
            }
            Err(refusal) => {
                tracing::info!(network = %net.name, reason = %refusal, "active scan refused");
                stage(&mut stages, &label, "refused", refusal.to_string(), t);
            }
        }
    }
    if let Some(v4) = one_time {
        let t = Instant::now();
        tracing::info!(cidr = %v4, "running user-requested one-time scan");
        state.reg().event(
            None,
            "scan_one_time",
            format!("user-requested one-time scan of {v4}"),
        );
        let (p, r) = sweep_network(state, v4).await;
        probed += p;
        responsive += r;
        scanned_nets.push(ipnet::IpNet::V4(v4));
        stage(
            &mut stages,
            "active_scan:one_time",
            "ok",
            format!("{v4}: {p} addresses probed, {r} responsive"),
            t,
        );
    }
    if scanned_nets.is_empty() && !stages.iter().any(|s| s.stage.starts_with("active_scan")) {
        stage(
            &mut stages,
            "active_scan",
            "skipped",
            "no network has active_scan: true".into(),
            Instant::now(),
        );
    }

    // Stage 6: host keys of responsive unmatched hosts.
    let t = Instant::now();
    let now = now_ms();
    let candidates: Vec<IpAddr> = {
        let reg = state.reg();
        scanned_nets
            .iter()
            .flat_map(|n| reg.discovered_in(n))
            .filter(|ip| reg.scan_keys_due(*ip, now, SCAN_KEYS_RECHECK_MS))
            .collect()
    };
    let n_cand = candidates.len();
    {
        let mut reg = state.reg();
        for ip in &candidates {
            reg.record_keyscan_attempt(*ip, now);
        }
    }
    let prober = state.prober.clone();
    let results = sweep::bounded(
        candidates,
        KEYSCAN_CONCURRENCY,
        state.cancel.clone(),
        move |ip| {
            let p = prober.clone();
            async move { (ip, p.keyscan(ip, 22, Duration::from_secs(5)).await) }
        },
    )
    .await;
    add(&state.metrics.keyscans, results.len() as u64);
    let mut matched = 0;
    for (ip, res) in results {
        if let Ok(keys) = res {
            let before: Vec<String> = state.reg().devices_at(ip);
            let mac = state.reg().neighbor_mac(ip);
            let obs = Observation {
                ip: Some(ip),
                mac,
                names: vec![],
                host_keys: keys,
            };
            let wake = state.reg().observe(&obs, "keyscan", None, now_ms());
            if !wake.is_empty() || state.reg().devices_at(ip) != before {
                matched += 1;
            }
            state.wake_many(wake);
        }
    }
    stage(
        &mut stages,
        "identity_verification",
        if n_cand == 0 { "skipped" } else { "ok" },
        format!("{n_cand} unmatched SSH hosts key-scanned, {matched} attributed to known devices"),
        t,
    );

    // Give woken monitors a moment so the report reflects their results.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    state.after_update();
    if state.reg().has_dirty() {
        state.request_persist();
    }
    let now = now_ms();
    let reg = state.reg();
    let ids = reg.ids_in_scope(None, false).unwrap_or_default();
    tracing::debug!(
        reason,
        elapsed_ms = started.elapsed().as_millis() as u64,
        probed,
        responsive,
        "discovery finished"
    );
    Ok(DiscoverReport {
        schema_version: SCHEMA_VERSION,
        stages,
        probed_hosts: probed,
        responsive_hosts: responsive,
        devices: ids.iter().filter_map(|i| reg.status(i, now)).collect(),
        discovered: reg.discovered_view(now),
    })
}

/// Sweep one validated network. Returns (addresses probed, hosts responsive).
async fn sweep_network(state: &State, net: ipnet::Ipv4Net) -> (u64, u64) {
    let targets = scan_targets(&net);
    let n = targets.len() as u64;
    add(&state.metrics.scan_hosts_probed, n);
    let conc = state.cfg.daemon.scan_concurrency;
    let prober = state.prober.clone();
    let use_icmp = state.cfg.daemon.icmp && !state.icmp_unsupported.load(Ordering::Relaxed);
    let to = Duration::from_millis(state.cfg.daemon.connect_timeout_ms);
    let mut responders: Vec<(Ipv4Addr, Option<PortState>)> = Vec::new();
    if use_icmp {
        add(&state.metrics.icmp_probes, n);
        let results = sweep::bounded(targets, conc, state.cancel.clone(), move |ip| {
            let p = prober.clone();
            async move { (ip, p.icmp(IpAddr::V4(ip), SWEEP_ICMP_TIMEOUT).await) }
        })
        .await;
        for (ip, r) in results {
            match r {
                IcmpOutcome::Reply(_) => responders.push((ip, None)),
                IcmpOutcome::Unsupported(_) => {
                    state.icmp_unsupported.store(true, Ordering::Relaxed)
                } // IPv4 only here
                _ => {}
            }
        }
        // ARP resolution happened for every address we pinged: hosts that drop
        // ICMP still answered ARP and now sit in the neighbor table.
        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Some(s) = state.prober.net_snapshot().await {
            let mut reg = state.reg();
            for nb in &s.neighbors {
                if let IpAddr::V4(v4) = nb.ip {
                    if net.contains(&v4)
                        && nb.state.has_valid_lladdr()
                        && !responders.iter().any(|(r, _)| *r == v4)
                    {
                        responders.push((v4, None));
                    }
                }
            }
            let obs = reg.set_snapshot(s);
            let now = now_ms();
            let mut wake = Vec::new();
            for (o, src) in obs {
                wake.extend(reg.observe(&o, &src, None, now));
            }
            drop(reg);
            state.wake_many(wake);
        }
    } else {
        add(&state.metrics.tcp_probes, n);
        let results = sweep::bounded(targets, conc, state.cancel.clone(), move |ip| {
            let p = prober.clone();
            async move { (ip, p.tcp(SocketAddr::new(IpAddr::V4(ip), 22), to).await) }
        })
        .await;
        for (ip, r) in results {
            match r {
                TcpOutcome::Open(_) => responders.push((ip, Some(PortState::Open))),
                TcpOutcome::Refused(_) => responders.push((ip, Some(PortState::Closed))),
                _ => {}
            }
        }
    }
    let responsive = responders.len() as u64;
    let now = now_ms();
    {
        let mut reg = state.reg();
        let mut wake = Vec::new();
        for (ip, _) in &responders {
            let ip = IpAddr::V4(*ip);
            let obs = Observation {
                ip: Some(ip),
                mac: reg.neighbor_mac(ip),
                names: vec![],
                host_keys: vec![],
            };
            wake.extend(reg.observe(&obs, "scan", None, now));
        }
        drop(reg);
        state.wake_many(wake);
    }
    // TCP/22 for unmatched responders not checked recently.
    let (known, todo): (Vec<_>, Vec<_>) = {
        let reg = state.reg();
        responders.into_iter().partition(|(ip, p)| {
            p.is_some() || !reg.scan_tcp_due(IpAddr::V4(*ip), now, SCAN_TCP_RECHECK_MS)
        })
    };
    {
        let mut reg = state.reg();
        for (ip, p) in &known {
            if let Some(p) = p {
                reg.record_scan(IpAddr::V4(*ip), *p, now);
            }
        }
    }
    let todo: Vec<Ipv4Addr> = todo.into_iter().map(|(ip, _)| ip).collect();
    add(&state.metrics.tcp_probes, todo.len() as u64);
    let prober = state.prober.clone();
    let results = sweep::bounded(todo, conc, state.cancel.clone(), move |ip| {
        let p = prober.clone();
        async move { (ip, p.tcp(SocketAddr::new(IpAddr::V4(ip), 22), to).await) }
    })
    .await;
    let mut reg = state.reg();
    for (ip, r) in results {
        let p = match r {
            TcpOutcome::Open(_) => PortState::Open,
            TcpOutcome::Refused(_) => PortState::Closed,
            _ => PortState::Filtered,
        };
        reg.record_scan(IpAddr::V4(ip), p, now);
    }
    (n, responsive)
}
