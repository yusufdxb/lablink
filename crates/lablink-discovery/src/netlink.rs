//! Minimal rtnetlink client: dumps and multicast monitoring of links,
//! addresses and neighbors.
//!
//! This is ~300 lines of explicit parsing instead of a netlink crate: the
//! message layouts used here are stable kernel ABI, the parser is covered by
//! byte-level tests, and it avoids pulling a fast-moving dependency tree into
//! a daemon whose main requirement is being small and predictable.

use ipnet::IpNet;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;

const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_NEIGH: u32 = 0x4;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;

/// Kernel neighbor-cache state (NUD_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    NoArp,
    Permanent,
    Other(u16),
}

impl NeighState {
    fn from_bits(b: u16) -> Self {
        match b {
            0x01 => NeighState::Incomplete,
            0x02 => NeighState::Reachable,
            0x04 => NeighState::Stale,
            0x08 => NeighState::Delay,
            0x10 => NeighState::Probe,
            0x20 => NeighState::Failed,
            0x40 => NeighState::NoArp,
            0x80 => NeighState::Permanent,
            x => NeighState::Other(x),
        }
    }
    /// The entry holds a valid link-layer address for a host that answered
    /// at some point (REACHABLE, STALE, DELAY, PROBE, PERMANENT).
    pub fn has_valid_lladdr(self) -> bool {
        matches!(
            self,
            NeighState::Reachable
                | NeighState::Stale
                | NeighState::Delay
                | NeighState::Probe
                | NeighState::Permanent
        )
    }
}

/// One neighbor-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub ifindex: u32,
    pub state: NeighState,
}

/// One network interface with its addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub loopback: bool,
    pub mac: Option<String>,
    pub addrs: Vec<IpNet>,
}

/// A parsed rtnetlink notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    Neighbor {
        neighbor: Neighbor,
        deleted: bool,
    },
    Address {
        ifindex: u32,
        addr: IpNet,
        deleted: bool,
    },
    Link {
        ifindex: u32,
        name: Option<String>,
        up: bool,
        deleted: bool,
    },
    /// The kernel dropped notifications (ENOBUFS): consumers must re-dump.
    Overrun,
}

/// Full state from one dump.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub interfaces: Vec<Interface>,
    pub neighbors: Vec<Neighbor>,
    /// IPv4 default gateways `(interface, address)`, preferred route first.
    pub gateways: Vec<(String, IpAddr)>,
    /// `(interface, ssid)` of associated Wi-Fi interfaces (a site hint).
    pub ssids: Vec<(String, String)>,
}

impl Snapshot {
    /// Interface name by index.
    pub fn ifname(&self, index: u32) -> Option<&str> {
        self.interfaces
            .iter()
            .find(|i| i.index == index)
            .map(|i| i.name.as_str())
    }
    /// MAC of `ip` from the neighbor table (valid entries only).
    pub fn neighbor_mac(&self, ip: IpAddr) -> Option<&str> {
        self.neighbors
            .iter()
            .find(|n| n.ip == ip && n.state.has_valid_lladdr())
            .and_then(|n| n.mac.as_deref())
    }
    /// All addresses on interfaces that are up (loopback excluded).
    pub fn local_prefixes(&self) -> Vec<IpNet> {
        self.interfaces
            .iter()
            .filter(|i| i.up && !i.loopback)
            .flat_map(|i| i.addrs.iter().copied())
            .collect()
    }
    /// The interface whose subnet contains `ip`, if directly attached.
    pub fn interface_for(&self, ip: IpAddr) -> Option<&Interface> {
        self.interfaces
            .iter()
            .filter(|i| i.up && !i.loopback)
            .filter_map(|i| {
                i.addrs
                    .iter()
                    .filter(|a| a.contains(&ip))
                    .map(|a| a.prefix_len())
                    .max()
                    .map(|p| (i, p))
            })
            .max_by_key(|(_, p)| *p)
            .map(|(i, _)| i)
    }
}

// ---------------------------------------------------------------- parsing --

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

/// Iterate `(type, payload)` over rtattrs.
fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = u16_at(b, 0)? as usize;
        let ty = u16_at(b, 2)? & 0x3fff;
        if len < 4 || len > b.len() {
            return None;
        }
        let payload = &b[4..len];
        b = b.get(align4(len)..).unwrap_or(&[]);
        Some((ty, payload))
    })
}

fn mac_from(b: &[u8]) -> Option<String> {
    if b.len() != 6 || b.iter().all(|x| *x == 0) {
        return None;
    }
    Some(
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn ip_from(family: u8, b: &[u8]) -> Option<IpAddr> {
    match (family as i32, b.len()) {
        (libc::AF_INET, 4) => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        (libc::AF_INET6, 16) => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Parsed message from a dump or notification.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Msg {
    Link(Interface, bool),
    Addr(u32, IpNet, bool),
    Neigh(Neighbor, bool),
    Done,
    Error(i32),
    Other,
}

fn parse_one(ty: u16, body: &[u8]) -> Msg {
    match ty {
        NLMSG_DONE => Msg::Done,
        NLMSG_ERROR => Msg::Error(u32_at(body, 0).map(|e| e as i32).unwrap_or(-1)),
        RTM_NEWLINK | RTM_DELLINK => {
            // struct ifinfomsg: family u8, pad u8, type u16, index i32, flags u32, change u32
            let (Some(index), Some(flags)) = (u32_at(body, 4), u32_at(body, 8)) else {
                return Msg::Other;
            };
            let mut i = Interface {
                index,
                up: flags & IFF_UP != 0 && flags & IFF_RUNNING != 0,
                loopback: flags & IFF_LOOPBACK != 0,
                ..Default::default()
            };
            for (t, p) in attrs(body.get(16..).unwrap_or(&[])) {
                match t {
                    IFLA_IFNAME => {
                        i.name = String::from_utf8_lossy(p)
                            .trim_end_matches('\0')
                            .to_string()
                    }
                    IFLA_ADDRESS => i.mac = mac_from(p),
                    _ => {}
                }
            }
            Msg::Link(i, ty == RTM_DELLINK)
        }
        RTM_NEWADDR | RTM_DELADDR => {
            // struct ifaddrmsg: family u8, prefixlen u8, flags u8, scope u8, index u32
            let (Some(&family), Some(&prefix), Some(index)) =
                (body.first(), body.get(1), u32_at(body, 4))
            else {
                return Msg::Other;
            };
            let mut local = None;
            let mut address = None;
            for (t, p) in attrs(body.get(8..).unwrap_or(&[])) {
                match t {
                    IFA_LOCAL => local = ip_from(family, p),
                    IFA_ADDRESS => address = ip_from(family, p),
                    _ => {}
                }
            }
            match local.or(address).and_then(|ip| IpNet::new(ip, prefix).ok()) {
                Some(net) => Msg::Addr(index, net, ty == RTM_DELADDR),
                None => Msg::Other,
            }
        }
        RTM_NEWNEIGH | RTM_DELNEIGH => {
            // struct ndmsg: family u8, pad u8, pad u16, ifindex i32, state u16, flags u8, type u8
            let (Some(&family), Some(ifindex), Some(state)) =
                (body.first(), u32_at(body, 4), u16_at(body, 8))
            else {
                return Msg::Other;
            };
            let mut ip = None;
            let mut mac = None;
            for (t, p) in attrs(body.get(12..).unwrap_or(&[])) {
                match t {
                    NDA_DST => ip = ip_from(family, p),
                    NDA_LLADDR => mac = mac_from(p),
                    _ => {}
                }
            }
            match ip {
                Some(ip) => Msg::Neigh(
                    Neighbor {
                        ip,
                        mac,
                        ifindex,
                        state: NeighState::from_bits(state),
                    },
                    ty == RTM_DELNEIGH,
                ),
                None => Msg::Other,
            }
        }
        _ => Msg::Other,
    }
}

/// Split a datagram into netlink messages.
fn parse_datagram(mut b: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    while b.len() >= 16 {
        let len = u32_at(b, 0).unwrap_or(0) as usize;
        let ty = u16_at(b, 4).unwrap_or(0);
        if len < 16 || len > b.len() {
            break;
        }
        out.push(parse_one(ty, &b[16..len]));
        b = b.get(align4(len)..).unwrap_or(&[]);
    }
    out
}

/// Convert notification messages to events.
fn to_events(msgs: Vec<Msg>) -> Vec<NetEvent> {
    msgs.into_iter()
        .filter_map(|m| match m {
            Msg::Neigh(n, deleted) => Some(NetEvent::Neighbor {
                neighbor: n,
                deleted,
            }),
            Msg::Addr(ifindex, addr, deleted) => Some(NetEvent::Address {
                ifindex,
                addr,
                deleted,
            }),
            Msg::Link(i, deleted) => Some(NetEvent::Link {
                ifindex: i.index,
                name: (!i.name.is_empty()).then_some(i.name),
                up: i.up,
                deleted,
            }),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------- sockets --

fn open_socket(groups: u32, nonblocking: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
    if nonblocking {
        flags |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: plain socket(2) call; the returned fd is owned below.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, flags, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly created, valid descriptor we exclusively own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_nl is plain data; zeroed is a valid initial value.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = groups;
    // SAFETY: addr is a valid sockaddr_nl and the length matches.
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: buf is valid for writes of buf.len() bytes.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn send_dump(fd: RawFd, ty: u16, seq: u32, family_header_len: usize) -> io::Result<()> {
    let len = 16 + family_header_len;
    let mut m = vec![0u8; len];
    m[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    m[4..6].copy_from_slice(&ty.to_ne_bytes());
    m[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    // family byte (offset 16) stays AF_UNSPEC = 0: dump IPv4 and IPv6.
    // SAFETY: m is a valid buffer of len bytes.
    let n = unsafe { libc::send(fd, m.as_ptr() as *const libc::c_void, len, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn dump(fd: RawFd, ty: u16, seq: u32, hdr_len: usize) -> io::Result<Vec<Msg>> {
    send_dump(fd, ty, seq, hdr_len)?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = recv(fd, &mut buf)?;
        for m in parse_datagram(&buf[..n]) {
            match m {
                Msg::Done => return Ok(out),
                Msg::Error(e) if e != 0 => return Err(io::Error::from_raw_os_error(-e)),
                Msg::Error(_) => return Ok(out),
                other => out.push(other),
            }
        }
    }
}

/// Dump links, addresses and neighbors (blocking; call from a worker thread).
pub fn snapshot() -> io::Result<Snapshot> {
    let fd = open_socket(0, false)?;
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: valid timeval pointer and size.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
    }
    let raw = fd.as_raw_fd();
    let mut ifaces: BTreeMap<u32, Interface> = BTreeMap::new();
    for m in dump(raw, RTM_GETLINK, 1, 16)? {
        if let Msg::Link(i, false) = m {
            ifaces.insert(i.index, i);
        }
    }
    for m in dump(raw, RTM_GETADDR, 2, 8)? {
        if let Msg::Addr(idx, net, false) = m {
            if let Some(i) = ifaces.get_mut(&idx) {
                i.addrs.push(net);
            }
        }
    }
    let neighbors = dump(raw, RTM_GETNEIGH, 3, 12)?
        .into_iter()
        .filter_map(|m| match m {
            Msg::Neigh(n, false) => Some(n),
            _ => None,
        })
        .collect();
    Ok(Snapshot {
        interfaces: ifaces.into_values().collect(),
        neighbors,
        gateways: lablink_platform::default_routes()
            .into_iter()
            .map(|r| (r.interface, IpAddr::V4(r.gateway)))
            .collect(),
        ssids: lablink_platform::ssids(),
    })
}

/// Event-driven rtnetlink monitor. Owns one netlink socket registered with
/// the Tokio reactor; idle cost is zero (no timers, no polling).
pub struct Monitor {
    fd: tokio::io::unix::AsyncFd<OwnedFd>,
    buf: Vec<u8>,
}

impl Monitor {
    /// Subscribe to link, IPv4/IPv6 address and neighbor notifications.
    pub fn new() -> io::Result<Self> {
        let fd = open_socket(
            RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
            true,
        )?;
        // A larger receive buffer makes ENOBUFS (lost events) unlikely.
        let size: libc::c_int = 1 << 20;
        // SAFETY: valid int pointer and size.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            );
        }
        Ok(Self {
            fd: tokio::io::unix::AsyncFd::new(fd)?,
            buf: vec![0u8; 64 * 1024],
        })
    }

    /// Wait for the next batch of events.
    pub async fn next(&mut self) -> io::Result<Vec<NetEvent>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let raw = self.fd.get_ref().as_raw_fd();
            match guard.try_io(|_| recv(raw, &mut self.buf)) {
                Ok(Ok(n)) => return Ok(to_events(parse_datagram(&self.buf[..n]))),
                Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Ok(vec![NetEvent::Overrun])
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Timeout helper so callers do not wait forever on a wedged dump.
pub async fn snapshot_async(timeout: Duration) -> io::Result<Snapshot> {
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(snapshot)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(io::Error::other(e.to_string())),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "netlink dump timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(len as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        v.resize(align4(len), 0);
        v
    }

    fn msg(ty: u16, body: Vec<u8>) -> Vec<u8> {
        let len = 16 + body.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(len as u32).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&0u16.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(&body);
        v.resize(align4(len), 0);
        v
    }

    fn neigh_body(ip: [u8; 4], mac: &[u8], state: u16, ifindex: u32) -> Vec<u8> {
        let mut b = vec![libc::AF_INET as u8, 0, 0, 0];
        b.extend_from_slice(&ifindex.to_ne_bytes());
        b.extend_from_slice(&state.to_ne_bytes());
        b.extend_from_slice(&[0, 1]);
        b.extend(attr(NDA_DST, &ip));
        b.extend(attr(NDA_LLADDR, mac));
        b
    }

    #[test]
    fn parses_neighbor_messages() {
        let mut dgram = msg(
            RTM_NEWNEIGH,
            neigh_body([192, 168, 10, 70], &[0x02, 0x4c, 0x4c, 1, 2, 3], 0x02, 3),
        );
        dgram.extend(msg(
            RTM_DELNEIGH,
            neigh_body([192, 168, 10, 71], &[0, 0, 0, 0, 0, 0], 0x20, 3),
        ));
        let ev = to_events(parse_datagram(&dgram));
        assert_eq!(ev.len(), 2);
        match &ev[0] {
            NetEvent::Neighbor {
                neighbor,
                deleted: false,
            } => {
                assert_eq!(neighbor.ip, "192.168.10.70".parse::<IpAddr>().unwrap());
                assert_eq!(neighbor.mac.as_deref(), Some("02:4c:4c:01:02:03"));
                assert_eq!(neighbor.state, NeighState::Reachable);
                assert!(neighbor.state.has_valid_lladdr());
                assert_eq!(neighbor.ifindex, 3);
            }
            e => panic!("{e:?}"),
        }
        match &ev[1] {
            NetEvent::Neighbor {
                neighbor,
                deleted: true,
            } => {
                assert_eq!(neighbor.mac, None, "all-zero MAC is not a MAC");
                assert_eq!(neighbor.state, NeighState::Failed);
            }
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn parses_address_and_link() {
        let mut addr = vec![libc::AF_INET as u8, 24, 0, 0];
        addr.extend_from_slice(&2u32.to_ne_bytes());
        addr.extend(attr(IFA_ADDRESS, &[192, 168, 50, 10]));
        addr.extend(attr(IFA_LOCAL, &[192, 168, 50, 10]));
        let mut link = vec![0u8, 0, 1, 0];
        link.extend_from_slice(&2u32.to_ne_bytes());
        link.extend_from_slice(&(IFF_UP | IFF_RUNNING).to_ne_bytes());
        link.extend_from_slice(&0u32.to_ne_bytes());
        link.extend(attr(IFLA_IFNAME, b"eno1\0"));
        link.extend(attr(IFLA_ADDRESS, &[1, 2, 3, 4, 5, 6]));
        let mut d = msg(RTM_NEWADDR, addr);
        d.extend(msg(RTM_NEWLINK, link));
        d.extend(msg(NLMSG_DONE, vec![0, 0, 0, 0]));
        let m = parse_datagram(&d);
        assert_eq!(
            m[0],
            Msg::Addr(2, "192.168.50.10/24".parse().unwrap(), false)
        );
        match &m[1] {
            Msg::Link(i, false) => {
                assert_eq!(i.name, "eno1");
                assert!(i.up);
                assert_eq!(i.mac.as_deref(), Some("01:02:03:04:05:06"));
            }
            x => panic!("{x:?}"),
        }
        assert_eq!(m[2], Msg::Done);
    }

    #[test]
    fn truncated_and_garbage_input_is_safe() {
        let good = msg(
            RTM_NEWNEIGH,
            neigh_body([10, 0, 0, 1], &[1, 2, 3, 4, 5, 6], 2, 1),
        );
        for cut in 0..good.len() {
            let _ = parse_datagram(&good[..cut]);
        }
        let mut bad = good.clone();
        bad[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(parse_datagram(&bad).is_empty());
        // Attribute with a bogus length inside an otherwise valid message.
        let mut body = neigh_body([10, 0, 0, 1], &[1, 2, 3, 4, 5, 6], 2, 1);
        body[12..14].copy_from_slice(&200u16.to_ne_bytes());
        let _ = parse_datagram(&msg(RTM_NEWNEIGH, body));
    }

    #[test]
    fn interface_for_picks_most_specific() {
        let s = Snapshot {
            interfaces: vec![
                Interface {
                    index: 1,
                    name: "lo".into(),
                    up: true,
                    loopback: true,
                    mac: None,
                    addrs: vec!["127.0.0.1/8".parse().unwrap()],
                },
                Interface {
                    index: 2,
                    name: "eno1".into(),
                    up: true,
                    loopback: false,
                    mac: None,
                    addrs: vec!["192.168.0.10/16".parse().unwrap()],
                },
                Interface {
                    index: 3,
                    name: "wlan0".into(),
                    up: true,
                    loopback: false,
                    mac: None,
                    addrs: vec!["192.168.10.20/24".parse().unwrap()],
                },
                Interface {
                    index: 4,
                    name: "down0".into(),
                    up: false,
                    loopback: false,
                    mac: None,
                    addrs: vec!["192.168.10.30/28".parse().unwrap()],
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            s.interface_for("192.168.10.70".parse().unwrap())
                .unwrap()
                .name,
            "wlan0"
        );
        assert_eq!(
            s.interface_for("192.168.5.5".parse().unwrap())
                .unwrap()
                .name,
            "eno1"
        );
        assert!(s.interface_for("10.0.0.1".parse().unwrap()).is_none());
        assert_eq!(s.local_prefixes().len(), 2);
    }

    /// [integration, localhost] Real kernel dump on this machine.
    #[test]
    fn real_snapshot_has_loopback() {
        let s = snapshot().expect("netlink dump");
        assert!(
            s.interfaces.iter().any(|i| i.loopback && i.name == "lo"),
            "{:?}",
            s.interfaces
        );
    }
}
