//! Lightweight reachability probes. No root, no subprocesses.

use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

/// Result of a TCP connect probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOutcome {
    /// Handshake completed: something is listening.
    Open(Duration),
    /// RST received: host is up, port closed.
    Refused(Duration),
    /// No answer within the timeout.
    Timeout,
    /// The kernel reported the host or network unreachable (e.g. ARP failed).
    Unreachable(String),
    /// Any other local error.
    Error(String),
}

impl TcpOutcome {
    /// The host answered at layer 3/4 (open or refused).
    pub fn host_up(&self) -> bool {
        matches!(self, TcpOutcome::Open(_) | TcpOutcome::Refused(_))
    }
    pub fn rtt(&self) -> Option<Duration> {
        match self {
            TcpOutcome::Open(d) | TcpOutcome::Refused(d) => Some(*d),
            _ => None,
        }
    }
}

/// Connect to `addr` and immediately close. Note: on an SSH server this
/// appears in the server log as a pre-auth disconnect, which is why the daemon
/// prefers ICMP for liveness and probes TCP/22 at a lower rate.
pub async fn tcp_probe(addr: SocketAddr, timeout: Duration) -> TcpOutcome {
    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Err(_) => TcpOutcome::Timeout,
        Ok(Ok(stream)) => {
            let rtt = start.elapsed();
            drop(stream);
            TcpOutcome::Open(rtt)
        }
        Ok(Err(e)) => match e.raw_os_error() {
            Some(libc::ECONNREFUSED) => TcpOutcome::Refused(start.elapsed()),
            Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) | Some(libc::EHOSTDOWN) => {
                TcpOutcome::Unreachable(e.to_string())
            }
            Some(libc::ETIMEDOUT) => TcpOutcome::Timeout,
            _ => TcpOutcome::Error(e.to_string()),
        },
    }
}

/// Result of an ICMP echo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpOutcome {
    Reply(Duration),
    Timeout,
    /// Unprivileged ICMP is not permitted (`net.ipv4.ping_group_range`) or
    /// the address family is unsupported. Callers fall back to TCP.
    Unsupported(String),
    Unreachable(String),
}

static SEQ: AtomicU16 = AtomicU16::new(1);

/// One ICMP echo request over an unprivileged datagram ICMP socket.
/// The kernel assigns the identifier and computes the checksum.
pub async fn icmp_echo(ip: IpAddr, timeout: Duration) -> IcmpOutcome {
    let IpAddr::V4(v4) = ip else {
        return IcmpOutcome::Unsupported("ICMPv6 echo not implemented".into());
    };
    let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => return IcmpOutcome::Unsupported(e.to_string()),
    };
    if let Err(e) = sock.set_nonblocking(true) {
        return IcmpOutcome::Unsupported(e.to_string());
    }
    if let Err(e) = sock.connect(&SocketAddr::new(IpAddr::V4(v4), 0).into()) {
        return IcmpOutcome::Unsupported(e.to_string());
    }
    // SAFETY: AsyncFd owns this Socket; its descriptor is never replaced or
    // closed independently while registered, and access below is by shared reference.
    let fd = match unsafe { AsyncFd::register(sock) } {
        Ok(f) => f,
        Err(e) => return IcmpOutcome::Unsupported(e.to_string()),
    };
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut pkt = [0u8; 24];
    pkt[0] = 8; // echo request
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt[8..24].copy_from_slice(b"lablink-liveness");

    let start = Instant::now();
    let fut = async {
        loop {
            let mut g = fd.writable().await?;
            match g.try_io(|s| s.get_ref().write(&pkt)) {
                Ok(r) => {
                    r?;
                    break;
                }
                Err(_) => continue,
            }
        }
        let mut buf = [0u8; 512];
        loop {
            let mut g = fd.readable().await?;
            match g.try_io(|s| s.get_ref().read(&mut buf)) {
                Ok(Ok(n)) if n >= 8 && buf[0] == 0 && buf[6..8] == seq.to_be_bytes() => {
                    return Ok::<Duration, io::Error>(start.elapsed())
                }
                Ok(Ok(_)) => continue, // unrelated or stale reply
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => IcmpOutcome::Timeout,
        Ok(Ok(rtt)) => IcmpOutcome::Reply(rtt),
        Ok(Err(e)) => match e.raw_os_error() {
            Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => {
                IcmpOutcome::Unreachable(e.to_string())
            }
            Some(libc::EACCES) | Some(libc::EPERM) => IcmpOutcome::Unsupported(e.to_string()),
            _ => IcmpOutcome::Unreachable(e.to_string()),
        },
    }
}

/// Resolve a hostname with the system resolver (`getaddrinfo`: /etc/hosts,
/// DNS, and `.local` via nss-mdns when installed), bounded by `timeout`.
pub async fn resolve_host(host: &str, timeout: Duration) -> Vec<IpAddr> {
    let query = format!("{host}:0");
    match tokio::time::timeout(timeout, tokio::net::lookup_host(query)).await {
        Ok(Ok(addrs)) => {
            let mut v: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            v.sort();
            v.dedup();
            v
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [localhost] Open and closed ports on loopback.
    #[tokio::test]
    async fn tcp_open_and_refused() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = l.local_addr().unwrap();
        let o = tcp_probe(open, Duration::from_secs(1)).await;
        assert!(matches!(o, TcpOutcome::Open(_)), "{o:?}");
        drop(l);
        let c = tcp_probe(open, Duration::from_secs(1)).await;
        assert!(matches!(c, TcpOutcome::Refused(_)), "{c:?}");
        assert!(c.host_up());
    }

    /// [localhost] TEST-NET-1 is never routed: the probe must time out or
    /// report unreachable, never hang past the timeout.
    #[tokio::test]
    async fn tcp_timeout_is_bounded() {
        let start = Instant::now();
        let o = tcp_probe("192.0.2.1:22".parse().unwrap(), Duration::from_millis(300)).await;
        assert!(!o.host_up());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    /// [localhost] ICMP to loopback (skips if unprivileged ICMP is disabled).
    #[tokio::test]
    async fn icmp_loopback() {
        match icmp_echo("127.0.0.1".parse().unwrap(), Duration::from_secs(1)).await {
            IcmpOutcome::Reply(rtt) => assert!(rtt < Duration::from_secs(1)),
            IcmpOutcome::Unsupported(e) => eprintln!("SKIP: unprivileged ICMP unavailable: {e}"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_localhost() {
        let v = resolve_host("localhost", Duration::from_secs(2)).await;
        assert!(v.iter().any(|ip| ip.is_loopback()), "{v:?}");
    }
}
