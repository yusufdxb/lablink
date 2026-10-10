//! Daemon assembly: task ownership, startup, and graceful shutdown.
//!
//! Every long-lived task is spawned on one [`TaskTracker`] and observes one
//! [`CancellationToken`]. Shutdown cancels the token, waits (bounded) for all
//! tasks, writes a final cache flush, and removes the socket.
//!
//! Long-lived tasks: IPC accept loop, discovery coordinator, persistence,
//! netlink monitor, network-change debouncer, mDNS consumer (+1 per browsed
//! service type), and one monitor per tracked device. Short-lived tasks: one
//! per IPC connection (capped) and bounded scan workers during discovery.

use crate::discovery::DiscoverCmd;
use crate::ipc;
use crate::metrics::{add, inc};
use crate::probe::{Prober, RealProber};
use crate::registry::Registry;
use crate::state::{Paths, State};
use crate::store::{OpenNote, Store};
use lablink_core::config::Config;
use lablink_core::time::now_ms;
use lablink_discovery::{netlink, NetEvent};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

/// How to run a daemon instance.
pub struct RunOptions {
    pub config: Config,
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    /// Subscribe to rtnetlink events.
    pub netlink: bool,
    /// Allow mDNS (also requires `daemon.mdns` in the config).
    pub mdns: bool,
    /// Run a discovery pass right after startup.
    pub startup_discovery: bool,
    /// Replace all network access (tests).
    pub prober: Option<Arc<dyn Prober>>,
    pub cancel: CancellationToken,
    /// Signalled once the socket is accepting connections.
    pub ready: Option<oneshot::Sender<()>>,
}

struct LockFile {
    _file: std::fs::File,
}

fn lock_state_dir(dir: &std::path::Path) -> Result<LockFile, String> {
    let p = dir.join("lablinkd.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .map_err(|e| format!("cannot open {}: {e}", p.display()))?;
    // SAFETY: flock on a valid fd owned by `f`.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(format!("another lablinkd is using {}", dir.display()));
    }
    Ok(LockFile { _file: f })
}

pub async fn run(opts: RunOptions) -> Result<(), String> {
    let t0 = Instant::now();
    let cfg = opts.config;
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&opts.state_dir)
            .map_err(|e| format!("cannot create state dir {}: {e}", opts.state_dir.display()))?;
        let _ = std::fs::set_permissions(&opts.state_dir, std::fs::Permissions::from_mode(0o700));
    }
    let lock = lock_state_dir(&opts.state_dir)?;
    let paths = Paths {
        socket: opts.socket.clone(),
        state_dir: opts.state_dir.clone(),
        db: lablink_core::paths::cache_db_path(&opts.state_dir),
        known_hosts: lablink_core::paths::known_hosts_path(&opts.state_dir),
    };

    let (store, note) = Store::open(&paths.db, cfg.daemon.history_retention)?;
    let loaded = store.load(crate::registry::EVENT_RING as u32)?;
    let mut reg = Registry::new(cfg.clone(), paths.known_hosts.clone());
    for w in reg.restore(&loaded.devices, &loaded.discovered, loaded.events) {
        tracing::warn!("{w}");
    }
    let meta = |k: &str| {
        loaded
            .meta
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    reg.restore_sites(
        meta("site_mode").as_deref(),
        meta("learned_gateways").as_deref(),
    );
    match &note {
        OpenNote::RecoveredFromCorruption(aside, why) => {
            tracing::warn!(moved_to = %aside.display(), reason = %why, "cache was corrupt; started with an empty cache");
            reg.event(
                None,
                "cache_recovered",
                format!(
                    "cache was unreadable ({why}); moved to {} and started fresh",
                    aside.display()
                ),
            );
        }
        n => tracing::debug!(?n, path = %paths.db.display(), "cache opened"),
    }
    reg.event(
        None,
        "daemon_started",
        format!(
            "lablinkd {} started ({} sites, {} devices, {} networks)",
            env!("CARGO_PKG_VERSION"),
            cfg.sites.len(),
            cfg.device_count(),
            cfg.network_count()
        ),
    );

    let mdns = if opts.mdns && cfg.daemon.mdns && opts.prober.is_none() {
        match lablink_discovery::mdns::Mdns::start() {
            Ok(m) => Some(Arc::new(m)),
            Err(e) => {
                tracing::warn!(error = %e, "mDNS unavailable");
                None
            }
        }
    } else {
        None
    };
    let prober: Arc<dyn Prober> = match opts.prober {
        Some(p) => p,
        None => Arc::new(RealProber {
            keyscan_binary: cfg.ssh.keyscan_binary.clone(),
            keygen_binary: cfg.ssh.keygen_binary.clone(),
            user_known_hosts: lablink_core::paths::user_known_hosts(),
            mdns: mdns.clone(),
            ssh_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            reuse_control_master: cfg.ssh.reuse_control_master,
        }),
    };

    let (tx, rx) = mpsc::channel::<DiscoverCmd>(8);
    let state = Arc::new(State::new(
        cfg.clone(),
        reg,
        store,
        prober,
        tx,
        opts.cancel.clone(),
        paths.clone(),
    ));

    // Initial interface/neighbor snapshot before monitors start.
    if let Some(s) = state.prober.net_snapshot().await {
        let now = now_ms();
        let mut reg = state.reg();
        let obs = reg.set_snapshot(s);
        for (o, src) in obs {
            reg.observe(&o, &src, None, now);
        }
    }
    // Decide which site we are at before any monitor probes anything.
    let _ = state.reg().refresh_sites(now_ms());

    let listener = ipc::bind(&paths.socket)?;
    let tracker = state.tracker.clone();
    tracker.spawn(ipc::serve(state.clone(), listener));
    tracker.spawn(crate::discovery::run_coordinator(state.clone(), rx));
    tracker.spawn(persist_task(state.clone()));
    for name in state.reg().device_names() {
        tracker.spawn(crate::monitor::run(state.clone(), name));
    }
    let netchange = Arc::new(Notify::new());
    if opts.netlink {
        tracker.spawn(netlink_task(state.clone(), netchange.clone()));
        tracker.spawn(netchange_task(state.clone(), netchange.clone()));
    }
    if let Some(m) = &mdns {
        let (stx, mut srx) = mpsc::channel(64);
        for h in m.browse(&cfg.daemon.mdns_service_types, stx, state.cancel.clone()) {
            // Browse tasks end on cancellation; track their completion too.
            tracker.spawn(async move {
                let _ = h.await;
            });
        }
        let st = state.clone();
        tracker.spawn(async move {
            loop {
                let s = tokio::select! {
                    _ = st.cancel.cancelled() => break,
                    s = srx.recv() => match s { Some(s) => s, None => break },
                };
                inc(&st.metrics.mdns_sightings);
                // Names from the network are untrusted input.
                let name = s.hostname.trim_end_matches('.');
                if !lablink_core::config::valid_hostname(name) {
                    tracing::debug!(ip = %s.ip, "ignoring mDNS answer with an invalid host name");
                    continue;
                }
                let obs = lablink_core::identity::Observation {
                    ip: Some(s.ip),
                    mac: None,
                    names: vec![s.hostname.clone()],
                    host_keys: vec![],
                };
                let wake = st.reg().observe(&obs, "mdns", None, now_ms());
                st.wake_many(wake);
                st.after_update();
            }
        });
    }
    if opts.startup_discovery {
        let _ = state.discover_tx.try_send(DiscoverCmd {
            scan_cidr: None,
            reason: "startup",
            reply: None,
        });
    }
    tracing::info!(
        socket = %paths.socket.display(),
        state_dir = %paths.state_dir.display(),
        devices = cfg.device_count(),
        startup_ms = t0.elapsed().as_millis() as u64,
        "lablinkd ready"
    );
    if let Some(r) = opts.ready {
        let _ = r.send(());
    }

    state.cancel.cancelled().await;
    tracing::info!("shutting down");
    tracker.close();
    if tokio::time::timeout(Duration::from_secs(5), tracker.wait())
        .await
        .is_err()
    {
        tracing::warn!(
            remaining = tracker.len(),
            "some tasks did not stop within 5 s"
        );
    }
    {
        let mut reg = state.reg();
        reg.event(None, "daemon_stopped", "lablinkd stopped".into());
        reg.mark_all();
    }
    ipc::flush(&state).await;
    let _ = std::fs::remove_file(&paths.socket);
    drop(mdns);
    drop(lock);
    tracing::info!("stopped cleanly");
    Ok(())
}

async fn persist_task(state: Arc<State>) {
    let interval = Duration::from_secs(state.cfg.daemon.persist_interval_s.max(1));
    'outer: loop {
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            _ = state.persist.notified() => {}
        }
        let deadline = tokio::time::Instant::now()
            + if state.reg().urgent {
                Duration::from_secs(1)
            } else {
                interval
            };
        loop {
            let d = if state.reg().urgent {
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(1))
            } else {
                deadline
            };
            tokio::select! {
                _ = state.cancel.cancelled() => break 'outer,
                _ = tokio::time::sleep_until(d) => break,
                _ = state.persist.notified() => continue,
            }
        }
        ipc::flush(&state).await;
    }
}

async fn netlink_task(state: Arc<State>, netchange: Arc<Notify>) {
    let mut mon = match netlink::Monitor::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "rtnetlink monitor unavailable; network changes will only be noticed by periodic discovery");
            return;
        }
    };
    loop {
        let evs = tokio::select! {
            _ = state.cancel.cancelled() => break,
            r = mon.next() => r,
        };
        let evs = match evs {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "netlink receive failed");
                tokio::select! {
                    _ = state.cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                }
            }
        };
        add(&state.metrics.netlink_events, evs.len() as u64);
        let mut wake = Vec::new();
        let mut changed = false;
        {
            let mut reg = state.reg();
            let now = now_ms();
            for e in evs {
                match e {
                    NetEvent::Neighbor { neighbor, deleted } => {
                        if deleted || !neighbor.state.has_valid_lladdr() {
                            if deleted || neighbor.state == lablink_discovery::NeighState::Failed {
                                wake.extend(reg.healthy_devices_at(neighbor.ip));
                            }
                            reg.neighbor_observation(&neighbor);
                        } else if let Some(o) = reg.neighbor_observation(&neighbor) {
                            wake.extend(reg.observe(&o, "neighbor", None, now));
                        }
                    }
                    NetEvent::Address { .. } | NetEvent::Link { .. } => changed = true,
                    NetEvent::Overrun => {
                        inc(&state.metrics.netlink_overruns);
                        changed = true;
                    }
                }
            }
        }
        wake.sort();
        wake.dedup();
        state.wake_many(wake);
        state.after_update();
        if changed {
            netchange.notify_one();
        }
    }
}

/// Debounce link/address changes, then refresh the snapshot and, if the set
/// of local prefixes changed, re-run discovery.
async fn netchange_task(state: Arc<State>, netchange: Arc<Notify>) {
    let mut last = state.reg().local_prefixes();
    loop {
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            _ = netchange.notified() => {}
        }
        // Absorb the burst of events an interface change produces.
        loop {
            tokio::select! {
                _ = state.cancel.cancelled() => return,
                _ = netchange.notified() => continue,
                _ = tokio::time::sleep(Duration::from_secs(2)) => break,
            }
        }
        let Some(s) = state.prober.net_snapshot().await else {
            continue;
        };
        let now_prefixes = s.local_prefixes();
        let mut reg = state.reg();
        let obs = reg.set_snapshot(s);
        let mut wake = Vec::new();
        for (o, src) in obs {
            wake.extend(reg.observe(&o, &src, None, now_ms()));
        }
        if now_prefixes != last {
            let added: Vec<String> = now_prefixes
                .iter()
                .filter(|p| !last.contains(p))
                .map(|p| p.to_string())
                .collect();
            let removed: Vec<String> = last
                .iter()
                .filter(|p| !now_prefixes.contains(p))
                .map(|p| p.to_string())
                .collect();
            reg.event(
                None,
                "network_change",
                format!(
                    "local networks changed: added [{}], removed [{}]",
                    added.join(", "),
                    removed.join(", ")
                ),
            );
            last = now_prefixes;
            wake.extend(reg.monitored_names());
            drop(reg);
            let _ = state.discover_tx.try_send(DiscoverCmd {
                scan_cidr: None,
                reason: "network_change",
                reply: None,
            });
        } else {
            drop(reg);
        }
        wake.sort();
        wake.dedup();
        state.wake_many(wake);
        state.after_update();
        state.request_persist();
    }
}
