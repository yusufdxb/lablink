//! Host discovery primitives for LabLink. Linux only.
//!
//! - [`netlink`]: rtnetlink dumps and an event-driven monitor for links,
//!   addresses and the neighbor (ARP/ND) table. No polling, no `ip` subprocess.
//! - [`probe`]: TCP connect probes and unprivileged ICMP echo
//!   (`SOCK_DGRAM`/`IPPROTO_ICMP`, allowed by `net.ipv4.ping_group_range`).
//! - [`sweep`]: a bounded-concurrency runner for active scans.
//! - [`mdns`]: passive mDNS browsing and `.local` resolution.
//!
//! Policy (what may be scanned, when) lives in the daemon and
//! `lablink_core::net`; this crate only executes bounded operations.

pub mod mdns;
pub mod netlink;
pub mod probe;
pub mod sweep;

pub use netlink::{Interface, NeighState, Neighbor, NetEvent, Snapshot};
pub use probe::{icmp_echo, tcp_probe, IcmpOutcome, TcpOutcome};
