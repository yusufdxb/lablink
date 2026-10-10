//! Unix-domain-socket API server.
//!
//! Security: the socket lives in a 0700 directory owned by the daemon's user,
//! is itself 0600, and every connection's peer UID (SO_PEERCRED) must equal
//! the daemon's UID. No TCP listener exists. Requests are size-limited and
//! connections are capped and time out when idle.

use crate::discovery::DiscoverCmd;
use crate::metrics::inc;
use crate::state::State;
use lablink_core::model::{DaemonInfo, MetricsReport, StatusReport, SCHEMA_VERSION};
use lablink_core::protocol::{
    ApiError, ErrorCode, Request, Response, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
use lablink_core::time::now_ms;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

const MAX_CONNECTIONS: usize = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(120);

fn uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

/// Create the socket directory/socket safely and bind.
pub fn bind(path: &Path) -> Result<UnixListener, String> {
    let dir = path.parent().ok_or("socket path has no parent directory")?;
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "{} is a symbolic link; refusing to use it for the socket",
            dir.display()
        ));
    }
    if std::fs::symlink_metadata(dir).is_err() {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot create {}: {e}", dir.display())),
        }
    }
    // lstat, not stat: a symlink planted after the first check (e.g. at
    // /tmp/lablink-<uid> before the directory existed) is refused here. Once
    // this is a real directory we own, nobody else can replace it (/tmp is
    // sticky), so the checks below cannot be raced.
    let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() {
        return Err(format!(
            "{} is not a directory; refusing to use it for the socket",
            dir.display()
        ));
    }
    if meta.uid() != uid() {
        return Err(format!(
            "{} is owned by uid {}, not by us; refusing to use it",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o077 != 0
        && dir
            .file_name()
            .is_some_and(|n| n == "lablink" || n.to_string_lossy().starts_with("lablink-"))
    {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(format!(
                "another lablinkd is already serving {}",
                path.display()
            ));
        }
        std::fs::remove_file(path)
            .map_err(|e| format!("cannot remove stale socket {}: {e}", path.display()))?;
    }
    let l = UnixListener::bind(path).map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    Ok(l)
}

pub async fn serve(state: Arc<State>, listener: UnixListener) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = tokio::select! {
            _ = state.cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        match stream.peer_cred() {
            Ok(c) if c.uid() == uid() => {}
            Ok(c) => {
                inc(&state.metrics.ipc_rejected);
                tracing::warn!(
                    peer_uid = c.uid(),
                    "rejected IPC connection from another user"
                );
                continue;
            }
            Err(e) => {
                inc(&state.metrics.ipc_rejected);
                tracing::warn!(error = %e, "cannot read peer credentials; connection rejected");
                continue;
            }
        }
        if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            inc(&state.metrics.ipc_rejected);
            let mut s = stream;
            let resp = Response::err(ApiError::new(ErrorCode::Busy, "too many connections"));
            let _ = s
                .write_all(
                    format!("{}\n", serde_json::to_string(&resp).unwrap_or_default()).as_bytes(),
                )
                .await;
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let (st, act) = (state.clone(), active.clone());
        state.tracker.spawn(async move {
            handle(st, stream).await;
            act.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle(state: Arc<State>, stream: UnixStream) {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    loop {
        let mut line = String::new();
        let read = async {
            let mut limited = (&mut reader).take(MAX_REQUEST_BYTES as u64 + 1);
            limited.read_line(&mut line).await
        };
        let n = tokio::select! {
            _ = state.cancel.cancelled() => return,
            r = tokio::time::timeout(IDLE_TIMEOUT, read) => match r {
                Ok(Ok(n)) => n,
                _ => return,
            },
        };
        if n == 0 {
            return;
        }
        inc(&state.metrics.ipc_requests);
        let resp = if n > MAX_REQUEST_BYTES || !line.ends_with('\n') && n >= MAX_REQUEST_BYTES {
            Response::err(ApiError::new(ErrorCode::BadRequest, "request too large"))
        } else {
            match Request::parse(line.trim_end()) {
                Ok(req) => {
                    tracing::debug!(?req, "ipc request");
                    match dispatch(&state, req).await {
                        Ok(v) => Response::ok(v),
                        Err(e) => Response::err(e),
                    }
                }
                Err(e) => Response::err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!("invalid request: {e}"),
                )),
            }
        };
        let mut out = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
        out.push(b'\n');
        if wr.write_all(&out).await.is_err() {
            return;
        }
        if n > MAX_REQUEST_BYTES {
            return;
        }
    }
}

fn daemon_info(state: &State) -> DaemonInfo {
    DaemonInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        pid: std::process::id(),
        uptime_s: state.uptime_s(),
    }
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))
}

async fn dispatch(state: &Arc<State>, req: Request) -> Result<serde_json::Value, ApiError> {
    let now = now_ms();
    match req {
        Request::Ping => Ok(serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "uptime_s": state.uptime_s(),
        })),
        Request::Status { device, site, all } => {
            let reg = state.reg();
            let devices = match device {
                Some(d) => {
                    let id = reg.resolve_ref(&d)?;
                    vec![reg.status(&id, now).expect("exists")]
                }
                None => reg
                    .ids_in_scope(site.as_deref(), all)?
                    .iter()
                    .filter_map(|i| reg.status(i, now))
                    .collect(),
            };
            to_value(&StatusReport {
                schema_version: SCHEMA_VERSION,
                daemon: daemon_info(state),
                devices,
                site_mode: reg.mode.clone(),
                sites: reg.site_statuses(now),
            })
        }
        Request::Devices { site, all } => {
            let reg = state.reg();
            let all: Result<Vec<_>, _> = reg
                .ids_in_scope(site.as_deref(), all)?
                .iter()
                .map(|n| reg.inspect(n, now))
                .collect();
            to_value(&serde_json::json!({ "schema_version": SCHEMA_VERSION, "devices": all? }))
        }
        Request::Sites => to_value(&state.reg().sites_report(now)),
        Request::SetSiteMode { site } => {
            let wake = state.reg().set_mode(site.as_deref(), now)?;
            state.wake_many(wake);
            state.request_persist();
            // A newly active site may now be scanned: run discovery soon.
            let _ = state.discover_tx.try_send(DiscoverCmd {
                scan_cidr: None,
                reason: "site_change",
                reply: None,
            });
            to_value(&state.reg().sites_report(now))
        }
        Request::Inspect { device } => to_value(&state.reg().inspect(&device, now)?),
        Request::History { device, limit } => {
            let limit = limit.clamp(1, 10_000);
            let dev = match &device {
                Some(d) => Some(state.reg().resolve_ref(d)?),
                None => None,
            };
            let from_ring = state.reg().history(dev.as_deref(), limit as usize);
            let events = match from_ring {
                Some(v) => v,
                None => {
                    flush(state).await;
                    let store = state.store.clone();
                    tokio::task::spawn_blocking(move || {
                        store
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .history(dev.as_deref(), limit)
                    })
                    .await
                    .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
                    .map_err(|e| ApiError::new(ErrorCode::Internal, e))?
                }
            };
            to_value(&serde_json::json!({ "schema_version": SCHEMA_VERSION, "events": events }))
        }
        Request::Discovered => {
            let reg = state.reg();
            to_value(
                &serde_json::json!({ "schema_version": SCHEMA_VERSION, "discovered": reg.discovered_view(now) }),
            )
        }
        Request::Discover { scan_cidr } => {
            if let Some(c) = &scan_cidr {
                // Fail fast with a precise reason before queueing.
                if let Err(r) = crate::discovery::check_one_time(state, c) {
                    tracing::warn!(cidr = %c, reason = %r, "one-time active scan refused");
                    state.reg().event(
                        None,
                        "scan_refused",
                        format!("one-time scan of {c} refused: {r}"),
                    );
                    return Err(ApiError::new(ErrorCode::Refused, r.to_string()));
                }
            }
            let (tx, rx) = oneshot::channel();
            state
                .discover_tx
                .try_send(DiscoverCmd {
                    scan_cidr,
                    reason: "manual",
                    reply: Some(tx),
                })
                .map_err(|_| {
                    ApiError::new(ErrorCode::Busy, "discovery queue is full; retry shortly")
                })?;
            match tokio::time::timeout(DISCOVER_TIMEOUT, rx).await {
                Ok(Ok(r)) => to_value(&r?),
                Ok(Err(_)) => Err(ApiError::new(
                    ErrorCode::Internal,
                    "discovery was cancelled",
                )),
                Err(_) => Err(ApiError::new(
                    ErrorCode::Busy,
                    "discovery did not finish in time",
                )),
            }
        }
        Request::Resolve { device } => {
            let r = state.reg().resolve(&device)?;
            if r.host_key_alias.is_some() {
                ensure_known_hosts(state).await;
            }
            to_value(&r)
        }
        Request::Trust {
            device,
            confirm,
            replace,
        } => {
            let (name, ip, port) = state.reg().trust_target(&device)?;
            let keys = crate::monitor::scan_keys(state, &name, ip, port)
                .await
                .map_err(|e| {
                    ApiError::new(
                        ErrorCode::Unreachable,
                        format!("cannot read host keys from {ip}: {e}"),
                    )
                })?;
            match confirm {
                None => {
                    let reg = state.reg();
                    to_value(&lablink_core::model::TrustReport {
                        schema_version: SCHEMA_VERSION,
                        device: name.clone(),
                        ip: ip.to_string(),
                        action: "preview".into(),
                        scanned: keys
                            .iter()
                            .map(|k| lablink_core::model::KeyView {
                                key_type: k.key_type.clone(),
                                fingerprint: k.fingerprint.clone(),
                                source: None,
                            })
                            .collect(),
                        pinned_before: reg.pinned_view(&name),
                        pinned_now: reg.pinned_view(&name),
                    })
                }
                Some(c) => {
                    let r = state.reg().trust(&name, ip, &keys, &c, replace, now_ms())?;
                    flush(state).await;
                    state.wake(&name);
                    to_value(&r)
                }
            }
        }
        Request::Set { device, changes } => {
            let s = state.reg().set(&device, &changes)?;
            state.wake(&s.id);
            state.request_persist();
            to_value(&s)
        }
        Request::Adopt {
            ip,
            name,
            label,
            username,
            profile,
            ssh,
            site,
        } => {
            let ip: std::net::IpAddr = ip.parse().map_err(|_| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("'{ip}' is not an IP address"),
                )
            })?;
            let changes = lablink_core::protocol::DeviceChanges {
                label,
                username,
                profile,
                ssh,
                ..Default::default()
            };
            let s = state
                .reg()
                .adopt(ip, &name, site.as_deref(), &changes, now)?;
            let st = state.clone();
            let n = s.id.clone();
            state
                .tracker
                .spawn(async move { crate::monitor::run(st, n).await });
            state.request_persist();
            to_value(&s)
        }
        Request::Metrics => {
            let p = crate::metrics::proc_stats();
            let alive = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks();
            let mut counters = state.metrics.to_map();
            counters.insert("tracked_tasks".into(), state.tracker.len() as u64);
            if let Some((in_use, arena, free)) = crate::metrics::heap_stats() {
                counters.insert("heap_in_use_bytes".into(), in_use);
                counters.insert("heap_arena_bytes".into(), arena);
                counters.insert("heap_free_bytes".into(), free);
            }
            let sizes = state.reg().state_sizes();
            let monitored = state.reg().monitored_names().len();
            for (k, v) in sizes {
                counters.insert(k.into(), v);
            }
            let store = state.store.clone();
            let stats = tokio::task::spawn_blocking(move || {
                store.lock().unwrap_or_else(|p| p.into_inner()).stats()
            })
            .await
            .unwrap_or_default();
            for (k, v) in stats {
                counters.insert(k.into(), v);
            }
            to_value(&MetricsReport {
                schema_version: SCHEMA_VERSION,
                daemon: daemon_info(state),
                rss_kib: p.rss_kib,
                threads: p.threads,
                open_fds: p.open_fds,
                cpu_user_ms: p.cpu_user_ms,
                cpu_system_ms: p.cpu_system_ms,
                tokio_alive_tasks: alive,
                monitored_devices: monitored,
                counters,
            })
        }
    }
}

/// Write pending state now (used before disk-backed queries and on shutdown).
pub async fn flush(state: &State) {
    ensure_known_hosts(state).await;
    let batch = state.reg().take_batch();
    if batch.is_empty() {
        return;
    }
    inc(&state.metrics.persist_writes);
    crate::metrics::add(&state.metrics.history_events, batch.events.len() as u64);
    let store = state.store.clone();
    let res = tokio::task::spawn_blocking(move || {
        store.lock().unwrap_or_else(|p| p.into_inner()).save(&batch)
    })
    .await;
    match res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "cache write failed"),
        Err(e) => tracing::error!(error = %e, "cache writer panicked"),
    }
}

/// Make sure LabLink's known_hosts file reflects the current pins. Must run
/// before any ssh invocation that uses `HostKeyAlias` (resolve, auth checks).
pub async fn ensure_known_hosts(state: &State) {
    let entries = {
        let mut reg = state.reg();
        // Also rewrite a file that was deleted behind LabLink's back.
        if !reg.known_hosts_dirty && state.paths.known_hosts.exists() {
            return;
        }
        reg.known_hosts_dirty = false;
        reg.known_hosts_entries()
    };
    let path = state.paths.known_hosts.clone();
    match tokio::task::spawn_blocking(move || lablink_ssh::write_known_hosts(&path, &entries)).await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::error!(error = %e, "cannot write LabLink known_hosts");
            state.reg().known_hosts_dirty = true;
        }
        Err(e) => tracing::error!(error = %e, "known_hosts writer panicked"),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn symlinked_socket_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("lablink-1000");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = super::bind(&link.join("lablinkd.sock")).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
        assert!(super::bind(&real.join("lablinkd.sock")).is_ok());
    }

    #[tokio::test]
    async fn socket_directory_is_created_private_and_must_be_a_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("run").join("lablink-1000");
        assert!(super::bind(&fresh.join("lablinkd.sock")).is_ok());
        let mode = std::fs::symlink_metadata(&fresh)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        let file = dir.path().join("lablink-file");
        std::fs::write(&file, "x").unwrap();
        let e = super::bind(&file.join("lablinkd.sock")).unwrap_err();
        assert!(!e.is_empty());
    }
}
