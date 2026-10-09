//! Shared daemon state and small helpers.

use crate::discovery::DiscoverCmd;
use crate::metrics::Metrics;
use crate::probe::Prober;
use crate::registry::Registry;
use crate::store::Store;
use lablink_core::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Filesystem locations used by a daemon instance.
#[derive(Debug, Clone)]
pub struct Paths {
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub db: PathBuf,
    pub known_hosts: PathBuf,
}

pub struct State {
    pub cfg: Config,
    reg: Mutex<Registry>,
    pub store: Arc<Mutex<Store>>,
    pub prober: Arc<dyn Prober>,
    wakers: Mutex<HashMap<String, Arc<Notify>>>,
    pub persist: Notify,
    pub discover_tx: mpsc::Sender<DiscoverCmd>,
    pub metrics: Metrics,
    pub cancel: CancellationToken,
    pub tracker: TaskTracker,
    pub started: Instant,
    pub paths: Paths,
    pub icmp_unsupported: AtomicBool,
}

impl State {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Config,
        reg: Registry,
        store: Store,
        prober: Arc<dyn Prober>,
        discover_tx: mpsc::Sender<DiscoverCmd>,
        cancel: CancellationToken,
        paths: Paths,
    ) -> Self {
        Self {
            cfg,
            reg: Mutex::new(reg),
            store: Arc::new(Mutex::new(store)),
            prober,
            wakers: Mutex::new(HashMap::new()),
            persist: Notify::new(),
            discover_tx,
            metrics: Metrics::default(),
            cancel,
            tracker: TaskTracker::new(),
            started: Instant::now(),
            paths,
            icmp_unsupported: AtomicBool::new(false),
        }
    }

    /// Lock the registry. Critical sections never await or do I/O.
    pub fn reg(&self) -> MutexGuard<'_, Registry> {
        self.reg.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The wake handle of a device monitor (created on first use).
    pub fn waker(&self, name: &str) -> Arc<Notify> {
        self.wakers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub fn wake(&self, name: &str) {
        self.waker(name).notify_one();
    }

    pub fn wake_many<I: IntoIterator<Item = String>>(&self, names: I) {
        for n in names {
            self.wake(&n);
        }
    }

    /// Re-evaluate the active site if its inputs changed, and wake the
    /// monitors of devices whose site just became engaged.
    pub fn after_update(&self) {
        let (wake, dirty) = {
            let mut reg = self.reg();
            let w = reg.refresh_sites_if_stale(lablink_core::time::now_ms());
            (w, reg.sites_dirty || reg.has_dirty())
        };
        self.wake_many(wake);
        if dirty {
            self.request_persist();
        }
    }

    /// Ask the persistence task to flush (soon if the registry marked it urgent).
    pub fn request_persist(&self) {
        self.persist.notify_one();
    }

    pub fn uptime_s(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}
