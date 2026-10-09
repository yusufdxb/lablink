//! Hysteresis state machines. A single dropped probe never flips a device to
//! OFFLINE; recovery from OFFLINE must be confirmed by repeated successes.
//!
//! ```text
//! UNKNOWN  --ok-->                         ONLINE
//! UNKNOWN  --offline_after fails-->        OFFLINE
//! ONLINE   --degraded_after fails-->       DEGRADED
//! DEGRADED --ok-->                         ONLINE
//! DEGRADED --offline_after fails-->        OFFLINE
//! OFFLINE  --recover_after consecutive ok-> ONLINE
//! ```

use crate::model::{NetworkState, PortState};
use serde::{Deserialize, Serialize};

/// Failure/recovery thresholds (validated: 1 <= degraded < offline, recover >= 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub degraded_after: u32,
    pub offline_after: u32,
    pub recover_after: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            degraded_after: 2,
            offline_after: 4,
            recover_after: 2,
        }
    }
}

/// A state change produced by a tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<S> {
    pub from: S,
    pub to: S,
}

/// Network reachability with hysteresis.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetTracker {
    pub state: NetworkState,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl NetTracker {
    /// Feed one probe result; returns the transition if the state changed.
    pub fn observe(&mut self, ok: bool, t: &Thresholds) -> Option<Transition<NetworkState>> {
        let from = self.state;
        if ok {
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
        let f = self.consecutive_failures;
        let to = match (from, ok) {
            (NetworkState::Unknown, true) => NetworkState::Online,
            (NetworkState::Unknown, false) if f >= t.offline_after => NetworkState::Offline,
            (NetworkState::Online, false) if f >= t.offline_after => NetworkState::Offline,
            (NetworkState::Online, false) if f >= t.degraded_after => NetworkState::Degraded,
            (NetworkState::Degraded, true) => NetworkState::Online,
            (NetworkState::Degraded, false) if f >= t.offline_after => NetworkState::Offline,
            (NetworkState::Offline, true) if self.consecutive_successes >= t.recover_after => {
                NetworkState::Online
            }
            (s, _) => s,
        };
        self.state = to;
        (from != to).then_some(Transition { from, to })
    }

    /// Forget history (e.g. the device moved to a new address).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// SSH port state, debounced: OPEN is reported immediately, but leaving OPEN
/// (or switching between CLOSED and FILTERED) needs `degraded_after`
/// consecutive identical observations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortTracker {
    pub state: PortState,
    pending: Option<PortState>,
    pending_count: u32,
}

impl PortTracker {
    pub fn observe(&mut self, raw: PortState, t: &Thresholds) -> Option<Transition<PortState>> {
        let from = self.state;
        if raw == from {
            self.pending = None;
            self.pending_count = 0;
            return None;
        }
        let immediate =
            raw == PortState::Open || from == PortState::Unknown || raw == PortState::Disabled;
        if immediate {
            self.state = raw;
            self.pending = None;
            self.pending_count = 0;
            return Some(Transition { from, to: raw });
        }
        if self.pending == Some(raw) {
            self.pending_count += 1;
        } else {
            self.pending = Some(raw);
            self.pending_count = 1;
        }
        if self.pending_count >= t.degraded_after {
            self.state = raw;
            self.pending = None;
            self.pending_count = 0;
            Some(Transition { from, to: raw })
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Exponential back-off for unreachable devices: `base * 2^(failures-offline)`,
/// capped at `max`. Reachable devices use `base`.
pub fn next_interval_s(state: NetworkState, consecutive_failures: u32, base: u64, max: u64) -> u64 {
    match state {
        NetworkState::Online | NetworkState::Degraded => base,
        NetworkState::Unknown | NetworkState::Offline => {
            let exp = consecutive_failures.saturating_sub(1).min(16);
            base.saturating_mul(1u64 << exp).clamp(base, max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use NetworkState::*;

    const T: Thresholds = Thresholds {
        degraded_after: 2,
        offline_after: 4,
        recover_after: 2,
    };

    fn run(t: &mut NetTracker, seq: &str) -> Vec<NetworkState> {
        seq.chars()
            .map(|c| {
                t.observe(c == '1', &T);
                t.state
            })
            .collect()
    }

    #[test]
    fn single_drop_never_degrades() {
        let mut t = NetTracker::default();
        let s = run(&mut t, "1101101101");
        assert!(s.iter().all(|x| *x == Online), "{s:?}");
    }

    #[test]
    fn intermittent_loss_degrades_but_does_not_go_offline() {
        // 50% packet loss in pairs: 2 fails then a success, repeatedly.
        let mut t = NetTracker::default();
        let s = run(&mut t, "1001001001001");
        assert!(!s.contains(&Offline), "{s:?}");
        assert!(s.contains(&Degraded));
        assert_eq!(*s.last().unwrap(), Online);
    }

    #[test]
    fn full_lifecycle() {
        let mut t = NetTracker::default();
        assert_eq!(run(&mut t, "1"), vec![Online]);
        assert_eq!(run(&mut t, "0"), vec![Online]);
        assert_eq!(run(&mut t, "0"), vec![Degraded]);
        assert_eq!(run(&mut t, "0"), vec![Degraded]);
        assert_eq!(run(&mut t, "0"), vec![Offline]);
        // One success is not a confirmed recovery.
        assert_eq!(run(&mut t, "1"), vec![Offline]);
        assert_eq!(run(&mut t, "0"), vec![Offline]);
        assert_eq!(run(&mut t, "11"), vec![Offline, Online]);
    }

    #[test]
    fn never_seen_device_goes_offline_after_threshold() {
        let mut t = NetTracker::default();
        assert_eq!(
            run(&mut t, "0000"),
            vec![Unknown, Unknown, Unknown, Offline]
        );
    }

    #[test]
    fn transitions_reported_once() {
        let mut t = NetTracker::default();
        let mut transitions = 0;
        for c in "1111000000000011111".chars() {
            if t.observe(c == '1', &T).is_some() {
                transitions += 1;
            }
        }
        // Unknown->Online, Online->Degraded, Degraded->Offline, Offline->Online
        assert_eq!(transitions, 4);
    }

    #[test]
    fn port_open_immediate_close_debounced() {
        let mut p = PortTracker::default();
        assert!(p.observe(PortState::Closed, &T).is_some()); // from Unknown: immediate
        assert!(p.observe(PortState::Open, &T).is_some());
        assert!(p.observe(PortState::Closed, &T).is_none());
        assert_eq!(p.state, PortState::Open);
        assert!(p.observe(PortState::Open, &T).is_none());
        assert!(p.observe(PortState::Closed, &T).is_none());
        let tr = p.observe(PortState::Closed, &T).unwrap();
        assert_eq!((tr.from, tr.to), (PortState::Open, PortState::Closed));
        // Flapping between closed and filtered needs consistency too.
        assert!(p.observe(PortState::Filtered, &T).is_none());
        assert!(p.observe(PortState::Closed, &T).is_none());
        assert_eq!(p.state, PortState::Closed);
    }

    #[test]
    fn backoff() {
        assert_eq!(next_interval_s(Online, 0, 5, 30), 5);
        assert_eq!(next_interval_s(Degraded, 3, 5, 30), 5);
        assert_eq!(next_interval_s(Offline, 1, 5, 30), 5);
        assert_eq!(next_interval_s(Offline, 2, 5, 30), 10);
        assert_eq!(next_interval_s(Offline, 3, 5, 30), 20);
        assert_eq!(next_interval_s(Offline, 4, 5, 30), 30);
        assert_eq!(next_interval_s(Offline, 400, 5, 30), 30);
    }
}
