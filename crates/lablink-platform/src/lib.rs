//! Platform-specific, read-only network signals used to detect which site
//! the user is at: default gateways, the neighbor (ARP) table and Wi-Fi
//! SSIDs. Linux only; every function returns an empty result elsewhere or
//! when the information is unavailable. Nothing here sends packets.
//!
//! The generic site logic (`lablink_core::site`) never calls the OS: it only
//! consumes the values produced here, so a port to another OS replaces this
//! crate and the rtnetlink code in `lablink-discovery`, nothing else.

use std::net::Ipv4Addr;

/// An IPv4 default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Ipv4Addr,
    pub metric: u32,
}

/// IPv4 default routes from `/proc/net/route`, lowest metric first.
pub fn default_routes() -> Vec<DefaultRoute> {
    std::fs::read_to_string("/proc/net/route")
        .map(|t| parse_routes(&t))
        .unwrap_or_default()
}

/// Parse `/proc/net/route` (pure, for tests).
pub fn parse_routes(text: &str) -> Vec<DefaultRoute> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    let mut v: Vec<DefaultRoute> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            let hex = |s: &str| u32::from_str_radix(s, 16).ok();
            let (dest, gw, flags, metric, mask) = (
                hex(f[1])?,
                hex(f[2])?,
                hex(f[3])?,
                f[6].parse().ok()?,
                hex(f[7])?,
            );
            if dest != 0 || mask != 0 || flags & (RTF_UP | RTF_GATEWAY) != (RTF_UP | RTF_GATEWAY) {
                return None;
            }
            // The kernel prints the address in host byte order of a
            // network-order u32, i.e. little-endian on every Linux target.
            Some(DefaultRoute {
                interface: f[0].to_string(),
                gateway: Ipv4Addr::from(gw.swap_bytes()),
                metric,
            })
        })
        .collect();
    v.sort_by_key(|r| r.metric);
    v
}

/// MAC address of `ip` from `/proc/net/arp` (complete entries only),
/// lower-case `aa:bb:cc:dd:ee:ff`.
pub fn arp_mac(ip: Ipv4Addr) -> Option<String> {
    let t = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp(&t, ip)
}

/// Parse `/proc/net/arp` (pure, for tests).
pub fn parse_arp(text: &str, ip: Ipv4Addr) -> Option<String> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let complete = f
            .get(2)
            .and_then(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok())
            .is_some_and(|flags| flags & 0x2 != 0);
        (f.len() >= 4 && f[0].parse::<Ipv4Addr>().ok() == Some(ip) && complete)
            .then(|| f[3].to_ascii_lowercase())
            .filter(|m| m != "00:00:00:00:00:00")
    })
}

/// The SSID a Wi-Fi interface is associated with, if any.
#[cfg(target_os = "linux")]
pub fn ssid(interface: &str) -> Option<String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // Wireless-extensions ioctl; served by cfg80211's compatibility layer
    // and readable without privileges (`iwgetid` uses the same call).
    const SIOCGIWESSID: libc::c_ulong = 0x8B1B;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IwPoint {
        pointer: *mut libc::c_void,
        length: u16,
        flags: u16,
    }
    #[repr(C)]
    union IwData {
        essid: IwPoint,
        _size: [u8; 16],
    }
    #[repr(C)]
    struct IwReq {
        name: [libc::c_char; 16],
        u: IwData,
    }
    if interface.is_empty() || interface.len() >= 16 || interface.contains('/') {
        return None;
    }
    if !std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("wireless")
        .exists()
    {
        return None;
    }
    // SAFETY: plain socket(2); the descriptor is owned below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd is a fresh descriptor we exclusively own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut buf = [0u8; 33];
    let mut req = IwReq {
        name: [0; 16],
        u: IwData {
            essid: IwPoint {
                pointer: buf.as_mut_ptr().cast(),
                length: buf.len() as u16,
                flags: 0,
            },
        },
    };
    for (d, s) in req.name.iter_mut().zip(interface.bytes()) {
        *d = s as libc::c_char;
    }
    // SAFETY: req is a valid iwreq whose essid pointer refers to `buf`,
    // which outlives the call; the kernel writes at most `length` bytes.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCGIWESSID as _, &mut req) };
    if rc != 0 {
        return None;
    }
    // SAFETY: the essid member is the one the kernel filled in.
    let len = usize::from(unsafe { req.u.essid.length }).min(32);
    let s = String::from_utf8_lossy(&buf[..len])
        .trim_end_matches('\0')
        .to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(not(target_os = "linux"))]
pub fn ssid(_interface: &str) -> Option<String> {
    None
}

/// `(interface, ssid)` for every associated Wi-Fi interface.
pub fn ssids() -> Vec<(String, String)> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut v: Vec<(String, String)> = dir
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| ssid(&n).map(|s| (n, s)))
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_routes() {
        let t =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
wlan0\t00000000\t010AA8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
eth0\t00000000\t0132A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0032A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let r = parse_routes(t);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].interface, "eth0");
        assert_eq!(r[0].gateway, Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(r[1].gateway, Ipv4Addr::new(192, 168, 10, 1));
        assert!(parse_routes("garbage\nx y\n").is_empty());
    }

    #[test]
    fn parses_arp() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.50.1     0x1         0x2         02:00:00:AA:BB:01     *        eth0\n\
192.168.50.9     0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert_eq!(
            parse_arp(t, Ipv4Addr::new(192, 168, 50, 1)).as_deref(),
            Some("02:00:00:aa:bb:01")
        );
        assert_eq!(parse_arp(t, Ipv4Addr::new(192, 168, 50, 9)), None);
        assert_eq!(parse_arp(t, Ipv4Addr::new(10, 0, 0, 1)), None);
    }

    #[test]
    fn ssid_of_a_non_wireless_or_bogus_interface_is_none() {
        assert_eq!(ssid("lo"), None);
        assert_eq!(ssid("../../etc"), None);
        assert_eq!(ssid(""), None);
        let _ = ssids(); // must not panic on this machine
    }
}
