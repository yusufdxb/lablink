//! Activity counters and process resource usage, so the low-idle-cost
//! requirement can be measured rather than asserted.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        /// Monotonic activity counters.
        #[derive(Debug, Default)]
        pub struct Metrics { $(pub $name: AtomicU64,)* }
        impl Metrics {
            pub fn to_map(&self) -> BTreeMap<String, u64> {
                let mut m = BTreeMap::new();
                $(m.insert(stringify!($name).to_string(), self.$name.load(Ordering::Relaxed));)*
                m
            }
        }
    };
}

counters!(
    device_checks,
    via_checks,
    tcp_probes,
    icmp_probes,
    keyscans,
    known_hosts_lookups,
    auth_checks,
    resolves,
    discoveries,
    scan_hosts_probed,
    netlink_events,
    netlink_overruns,
    mdns_sightings,
    ipc_requests,
    ipc_rejected,
    persist_writes,
    history_events,
);

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// Process statistics from /proc/self.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcStats {
    pub rss_kib: Option<u64>,
    pub threads: Option<u64>,
    pub open_fds: Option<u64>,
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
}

/// glibc heap numbers (bytes): (in_use, arena, free). None off linux-gnu,
/// and on glibc older than 2.33, which has no `mallinfo2`. The symbol is
/// looked up at run time so that the binary itself runs on glibc 2.31
/// (Ubuntu 20.04); linking it directly would raise the minimum glibc.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn heap_stats() -> Option<(u64, u64, u64)> {
    type Mallinfo2 = unsafe extern "C" fn() -> libc::mallinfo2;
    // SAFETY: dlsym with RTLD_DEFAULT and a NUL-terminated name only reads.
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mallinfo2".as_ptr()) };
    if sym.is_null() {
        return None;
    }
    // SAFETY: glibc's mallinfo2 has exactly this signature, takes no
    // arguments and returns a plain struct.
    let m = unsafe { std::mem::transmute::<*mut libc::c_void, Mallinfo2>(sym)() };
    Some((
        (m.uordblks + m.hblkhd) as u64,
        m.arena as u64,
        m.fordblks as u64,
    ))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn heap_stats() -> Option<(u64, u64, u64)> {
    None
}

pub fn proc_stats() -> ProcStats {
    let mut s = ProcStats::default();
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let val = || {
                line.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            };
            if line.starts_with("VmRSS:") {
                s.rss_kib = val();
            } else if line.starts_with("Threads:") {
                s.threads = val();
            }
        }
    }
    s.open_fds = std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|d| d.count() as u64);
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        // Fields after the parenthesised comm: utime is field 14, stime 15 (1-based).
        if let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) {
            let f: Vec<&str> = rest.split_whitespace().collect();
            // SAFETY: sysconf has no preconditions.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
            let ticks = |i: usize| {
                f.get(i)
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|t| t * 1000 / hz)
            };
            s.cpu_user_ms = ticks(11);
            s.cpu_system_ms = ticks(12);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn proc_stats_readable() {
        let s = super::proc_stats();
        assert!(s.rss_kib.unwrap() > 0);
        assert!(s.threads.unwrap() >= 1);
        assert!(s.open_fds.unwrap() >= 3);
        assert!(s.cpu_user_ms.is_some());
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        assert!(super::heap_stats().unwrap().1 > 0);
    }
}
