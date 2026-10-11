//! Read-only facts about this machine: NetworkManager, Wi-Fi adapters,
//! addresses, routes, the SSH session we run in and established TCP
//! connections. Gathering never changes anything; the parsers are pure.

use crate::system::{Cmd, Os, System};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NmInfo {
    pub running: bool,
    pub version: String,
    /// `nmcli general permissions`: permission -> yes / no / auth.
    pub permissions: BTreeMap<String, String>,
}

impl NmInfo {
    pub fn allowed(&self, permission: &str) -> bool {
        self.permissions
            .get(&format!("org.freedesktop.NetworkManager.{permission}"))
            .is_some_and(|v| v == "yes")
    }
}

/// A network device as NetworkManager lists it.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct NmDevice {
    pub name: String,
    pub kind: String,
    pub state: String,
    /// The active connection's name ("" when none).
    pub connection: String,
}

impl NmDevice {
    pub fn connected(&self) -> bool {
        self.state.starts_with("connected") && !self.connection.is_empty()
    }
}

/// A Wi-Fi adapter and what its driver reports it can do.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct WifiAdapter {
    pub interface: String,
    pub driver: String,
    pub state: String,
    pub connection: String,
    pub ap: bool,
    pub wpa2: bool,
    pub ccmp: bool,
    pub band_2ghz: bool,
    pub band_5ghz: bool,
    /// WPA3-Personal (SAE) in AP mode. NetworkManager does not report it;
    /// `None` means it cannot be verified on this host.
    pub sae: Option<bool>,
}

impl WifiAdapter {
    /// Can host a WPA2-Personal (RSN/CCMP) access point.
    pub fn can_host_wpa2(&self) -> bool {
        self.ap && self.wpa2 && self.ccmp
    }
}

/// An active NetworkManager connection.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ActiveConnection {
    pub name: String,
    pub uuid: String,
    pub kind: String,
    pub device: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Address {
    pub interface: String,
    pub net: Ipv4Net,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Route {
    pub dest: Ipv4Net,
    pub device: String,
    pub via: Option<Ipv4Addr>,
    pub table: String,
}

impl Route {
    pub fn is_default(&self) -> bool {
        self.dest.prefix_len() == 0
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TcpConn {
    pub local: (Ipv4Addr, u16),
    pub remote: (Ipv4Addr, u16),
}

/// The session this command runs in, from `$SSH_CONNECTION`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SshSession {
    pub client: String,
    /// This machine's address the session arrived on (IPv4 or IPv6, maybe
    /// with a `%interface` scope).
    pub server: String,
    pub server_port: u16,
}

/// Which interface carries the SSH session this command runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPath {
    /// Not running over SSH.
    Local,
    Interface(String),
    /// Running over SSH, but the interface cannot be determined: treated as
    /// if it were the target, never as safe.
    Unknown(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct HostFacts {
    pub os: Os,
    pub nmcli: bool,
    pub nm: Option<NmInfo>,
    pub devices: Vec<NmDevice>,
    pub wifi: Vec<WifiAdapter>,
    pub active: Vec<ActiveConnection>,
    pub addresses: Vec<Address>,
    /// IPv6 addresses as (interface, address), only to place an SSH
    /// session that arrived over IPv6.
    pub addresses6: Vec<(String, String)>,
    pub routes: Vec<Route>,
    pub ssh_session: Option<SshSession>,
    pub established: Vec<TcpConn>,
    pub ip_forward: Option<bool>,
    /// Read-only problems met while gathering (a missing tool, a parse
    /// failure), reported rather than hidden.
    pub notes: Vec<String>,
}

impl HostFacts {
    pub fn addresses_on(&self, interface: &str) -> Vec<Ipv4Net> {
        self.addresses
            .iter()
            .filter(|a| a.interface == interface)
            .map(|a| a.net)
            .collect()
    }

    pub fn interface_of(&self, ip: Ipv4Addr) -> Option<&str> {
        self.addresses
            .iter()
            .find(|a| a.net.addr() == ip)
            .map(|a| a.interface.as_str())
    }

    /// The interface our own SSH session (if any) arrives on.
    pub fn session_path(&self) -> SessionPath {
        let Some(s) = &self.ssh_session else {
            return SessionPath::Local;
        };
        if let Some((_, scope)) = s.server.split_once('%') {
            return SessionPath::Interface(scope.to_string());
        }
        let found = match s.server.parse::<Ipv4Addr>() {
            Ok(ip) => self.interface_of(ip).map(str::to_string),
            Err(_) => self
                .addresses6
                .iter()
                .find(|(_, a)| a.eq_ignore_ascii_case(&s.server))
                .map(|(i, _)| i.clone()),
        };
        match found {
            Some(i) => SessionPath::Interface(i),
            None => SessionPath::Unknown(s.server.clone()),
        }
    }

    pub fn default_routes(&self) -> Vec<&Route> {
        self.routes
            .iter()
            .filter(|r| r.is_default() && r.table == "main")
            .collect()
    }

    pub fn active_on(&self, interface: &str) -> Option<&ActiveConnection> {
        self.active.iter().find(|a| a.device == interface)
    }
}

/// Gather everything, read-only. Missing tools leave fields empty and add
/// a note.
pub fn gather(sys: &dyn System) -> HostFacts {
    let mut notes = Vec::new();
    let os = sys.os();
    let mut facts = HostFacts {
        os,
        nmcli: false,
        nm: None,
        devices: Vec::new(),
        wifi: Vec::new(),
        active: Vec::new(),
        addresses: Vec::new(),
        addresses6: Vec::new(),
        routes: Vec::new(),
        ssh_session: sys
            .env("SSH_CONNECTION")
            .and_then(|v| parse_ssh_connection(&v)),
        established: Vec::new(),
        ip_forward: None,
        notes: Vec::new(),
    };
    if os != Os::Linux {
        return facts;
    }
    match sys.run(&Cmd::new(
        "nmcli",
        &["-t", "-f", "RUNNING,VERSION", "general"],
    )) {
        Ok(out) if out.ok() => {
            facts.nmcli = true;
            let row = split_terse(out.stdout.lines().next().unwrap_or_default());
            let running = row.first().is_some_and(|r| r == "running");
            let mut nm = NmInfo {
                running,
                version: row.get(1).cloned().unwrap_or_default(),
                permissions: BTreeMap::new(),
            };
            if let Ok(p) = sys.run(&Cmd::new("nmcli", &["-t", "general", "permissions"])) {
                nm.permissions = parse_permissions(&p.stdout);
            }
            facts.nm = Some(nm);
        }
        Ok(out) => {
            facts.nmcli = true;
            notes.push(format!("NetworkManager is not running: {}", out.reason()));
        }
        Err(_) => notes.push("nmcli is not installed (NetworkManager not found)".into()),
    }
    if facts.nm.as_ref().is_some_and(|n| n.running) {
        if let Ok(out) = sys.run(&Cmd::new(
            "nmcli",
            &["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"],
        )) {
            facts.devices = parse_devices(&out.stdout);
        }
        for d in facts.devices.iter().filter(|d| d.kind == "wifi") {
            match sys.run(&Cmd::new(
                "nmcli",
                &[
                    "-t",
                    "-f",
                    "GENERAL.DEVICE,GENERAL.DRIVER,GENERAL.STATE,GENERAL.CONNECTION,WIFI-PROPERTIES",
                    "device",
                    "show",
                    &d.name,
                ],
            )) {
                Ok(out) if out.ok() => facts.wifi.push(parse_wifi_adapter(&out.stdout)),
                Ok(out) => notes.push(format!("{}: {}", d.name, out.reason())),
                Err(e) => notes.push(format!("{}: {e}", d.name)),
            }
        }
        for a in &mut facts.wifi {
            a.sae = sae_support(sys, &a.interface);
        }
        if let Ok(out) = sys.run(&Cmd::new(
            "nmcli",
            &[
                "-t",
                "-f",
                "NAME,UUID,TYPE,DEVICE",
                "connection",
                "show",
                "--active",
            ],
        )) {
            facts.active = parse_active(&out.stdout);
        }
    }
    match sys.run(&Cmd::new("ip", &["-4", "-o", "addr", "show"])) {
        Ok(out) if out.ok() => facts.addresses = parse_addresses(&out.stdout),
        _ => notes.push("cannot list addresses (ip -4 addr)".into()),
    }
    if facts.ssh_session.is_some() {
        match sys.run(&Cmd::new("ip", &["-6", "-o", "addr", "show"])) {
            Ok(out) if out.ok() => facts.addresses6 = parse_addresses6(&out.stdout),
            _ => notes.push("cannot list IPv6 addresses (ip -6 addr)".into()),
        }
    }
    match sys.run(&Cmd::new(
        "ip",
        &["-4", "-o", "route", "show", "table", "all"],
    )) {
        Ok(out) if out.ok() => facts.routes = parse_routes(&out.stdout),
        _ => notes.push("cannot list routes (ip -4 route)".into()),
    }
    if let Some(t) = sys.read_file(Path::new("/proc/net/tcp")) {
        facts.established = parse_proc_tcp(&t);
    }
    facts.ip_forward = sys
        .read_file(Path::new("/proc/sys/net/ipv4/ip_forward"))
        .map(|t| t.trim() == "1");
    facts.notes = notes;
    facts
}

/// WPA3-Personal AP support needs `iw` (SAE in the phy's AKM suites or the
/// SAE_OFFLOAD_AP / SAE extended features). Without `iw`: unknown.
fn sae_support(sys: &dyn System, interface: &str) -> Option<bool> {
    let phy = sys
        .read_file(Path::new(&format!(
            "/sys/class/net/{interface}/phy80211/name"
        )))?
        .trim()
        .to_string();
    if !lablink_core::config::valid_interface(&phy) {
        return None;
    }
    let out = sys
        .run(&Cmd::new("iw", &["phy", &phy, "info"]))
        .ok()
        .filter(|o| o.ok())?;
    Some(parse_iw_sae(&out.stdout))
}

/// SAE in `iw phy info`: an "SAE" cipher-suite/AKM line, or the SAE
/// offload extended feature. Old `iw` versions print neither; that is
/// reported as unsupported, the safe reading.
pub fn parse_iw_sae(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.contains("SAE_OFFLOAD_AP")
            || l.starts_with("* SAE")
            || (l.contains("AKM") && l.contains("SAE"))
            || l.contains("00-0f-ac:8")
    })
}

/// Split one `nmcli -t` line on unescaped colons, unescaping `\:` and `\\`.
pub fn split_terse(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    fields.last_mut().unwrap().push(n);
                }
            }
            ':' => fields.push(String::new()),
            c => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

/// `KEY:value` lines (`nmcli -t ... show`), split at the first colon.
pub fn parse_kv(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .collect()
}

pub fn parse_permissions(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(split_terse)
        .filter(|f| f.len() >= 2)
        .map(|f| (f[0].clone(), f[1].clone()))
        .collect()
}

pub fn parse_devices(text: &str) -> Vec<NmDevice> {
    text.lines()
        .map(split_terse)
        .filter(|f| f.len() >= 4)
        .map(|f| NmDevice {
            name: f[0].clone(),
            kind: f[1].clone(),
            state: f[2].clone(),
            connection: f[3].clone(),
        })
        .collect()
}

pub fn parse_active(text: &str) -> Vec<ActiveConnection> {
    text.lines()
        .map(split_terse)
        .filter(|f| f.len() >= 4)
        .map(|f| ActiveConnection {
            name: f[0].clone(),
            uuid: f[1].clone(),
            kind: f[2].clone(),
            device: f[3].clone(),
        })
        .collect()
}

pub fn parse_wifi_adapter(text: &str) -> WifiAdapter {
    let mut a = WifiAdapter::default();
    for (k, v) in parse_kv(text) {
        let yes = v.trim() == "yes";
        match k.as_str() {
            "GENERAL.DEVICE" => a.interface = v,
            "GENERAL.DRIVER" => a.driver = v,
            "GENERAL.STATE" => a.state = v,
            "GENERAL.CONNECTION" => a.connection = v,
            "WIFI-PROPERTIES.AP" => a.ap = yes,
            "WIFI-PROPERTIES.WPA2" => a.wpa2 = yes,
            "WIFI-PROPERTIES.CCMP" => a.ccmp = yes,
            "WIFI-PROPERTIES.2GHZ" => a.band_2ghz = yes,
            "WIFI-PROPERTIES.5GHZ" => a.band_5ghz = yes,
            _ => {}
        }
    }
    a
}

/// `ip -4 -o addr show`.
pub fn parse_addresses(text: &str) -> Vec<Address> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let i = t.iter().position(|w| *w == "inet")?;
            let net: Ipv4Net = t.get(i + 1)?.parse().ok()?;
            Some(Address {
                interface: t.get(1)?.trim_end_matches(':').to_string(),
                net,
            })
        })
        .collect()
}

/// `ip -6 -o addr show`: (interface, address without prefix).
pub fn parse_addresses6(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let i = t.iter().position(|w| *w == "inet6")?;
            let addr = t.get(i + 1)?.split('/').next()?.to_string();
            Some((t.get(1)?.trim_end_matches(':').to_string(), addr))
        })
        .collect()
}

/// `ip -4 -o route show table all`.
pub fn parse_routes(text: &str) -> Vec<Route> {
    const TYPES: [&str; 10] = [
        "unicast",
        "local",
        "broadcast",
        "multicast",
        "throw",
        "unreachable",
        "prohibit",
        "blackhole",
        "nat",
        "anycast",
    ];
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let (kind, rest) = match t.first() {
                Some(k) if TYPES.contains(k) => (*k, &t[1..]),
                _ => ("unicast", &t[..]),
            };
            if kind != "unicast" {
                return None;
            }
            let dest = match *rest.first()? {
                "default" => Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).ok()?,
                d if d.contains('/') => d.parse().ok()?,
                d => Ipv4Net::new(d.parse().ok()?, 32).ok()?,
            };
            let after = |key: &str| {
                rest.iter()
                    .position(|w| *w == key)
                    .and_then(|i| rest.get(i + 1))
                    .map(|s| s.to_string())
            };
            Some(Route {
                dest,
                device: after("dev").unwrap_or_default(),
                via: after("via").and_then(|v| v.parse().ok()),
                table: after("table").unwrap_or_else(|| "main".into()),
            })
        })
        .collect()
}

/// Established connections from `/proc/net/tcp` (state 01).
pub fn parse_proc_tcp(text: &str) -> Vec<TcpConn> {
    fn endpoint(s: &str) -> Option<(Ipv4Addr, u16)> {
        let (ip, port) = s.split_once(':')?;
        let ip = u32::from_str_radix(ip, 16).ok()?;
        let port = u16::from_str_radix(port, 16).ok()?;
        Some((Ipv4Addr::from(ip.swap_bytes()), port))
    }
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.get(3) != Some(&"01") {
                return None;
            }
            Some(TcpConn {
                local: endpoint(t.get(1)?)?,
                remote: endpoint(t.get(2)?)?,
            })
        })
        .collect()
}

/// `$SSH_CONNECTION` = "client_ip client_port server_ip server_port".
pub fn parse_ssh_connection(v: &str) -> Option<SshSession> {
    let t: Vec<&str> = v.split_whitespace().collect();
    if t.len() != 4 {
        return None;
    }
    Some(SshSession {
        client: format!("{} port {}", t[0], t[1]),
        server: t[2].to_string(),
        server_port: t[3].parse().ok()?,
    })
}

/// A fake host for tests elsewhere in the crate: a typical laptop, one Wi-Fi
/// adapter connected to the home network and carrying the only uplink.
#[cfg(test)]
pub(crate) fn script_host(f: &crate::system::FakeSystem) {
    f.ok("nmcli -t -f RUNNING,VERSION general", "running:1.36.6\n");
    f.ok(
        "nmcli -t general permissions",
        "org.freedesktop.NetworkManager.checkpoint-rollback:auth\norg.freedesktop.NetworkManager.network-control:yes\norg.freedesktop.NetworkManager.settings.modify.system:yes\n",
    );
    f.ok(
        "nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device",
        "wlan0:wifi:connected:Home WiFi\ntailscale0:tun:connected (externally):tailscale0\ndocker0:bridge:connected (externally):docker0\np2p-dev-wlan0:wifi-p2p:disconnected:\neno1:ethernet:unavailable:\nlo:loopback:unmanaged:\n",
    );
    f.ok(
        "nmcli -t -f GENERAL.DEVICE,GENERAL.DRIVER,GENERAL.STATE,GENERAL.CONNECTION,WIFI-PROPERTIES device show wlan0",
        "GENERAL.DEVICE:wlan0\nGENERAL.DRIVER:mt7925e\nGENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:Home WiFi\nWIFI-PROPERTIES.WEP:yes\nWIFI-PROPERTIES.WPA:yes\nWIFI-PROPERTIES.WPA2:yes\nWIFI-PROPERTIES.TKIP:yes\nWIFI-PROPERTIES.CCMP:yes\nWIFI-PROPERTIES.AP:yes\nWIFI-PROPERTIES.ADHOC:no\nWIFI-PROPERTIES.2GHZ:yes\nWIFI-PROPERTIES.5GHZ:yes\nWIFI-PROPERTIES.MESH:no\nWIFI-PROPERTIES.IBSS-RSN:no\n",
    );
    f.ok(
        "nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active",
        "Home WiFi:a21bc2fd-4952-487d-91c0-a3248f648037:802-11-wireless:wlan0\ntailscale0:2832d90a-7ed3-41e4-a65c-b27edb8422f7:tun:tailscale0\ndocker0:6f9ea155-622b-4014-be91-48e765a7857d:bridge:docker0\n",
    );
    f.ok(
        "ip -4 -o addr show",
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n3: wlan0    inet 192.168.8.168/24 brd 192.168.8.255 scope global dynamic noprefixroute wlan0\\       valid_lft 80000sec preferred_lft 80000sec\n4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever\n5: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever preferred_lft forever\n",
    );
    f.ok(
        "ip -4 -o route show table all",
        "100.64.0.0/10 dev tailscale0 table 52\ndefault via 192.168.8.1 dev wlan0 proto dhcp metric 600\n172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown\n192.168.8.0/24 dev wlan0 proto kernel scope link src 192.168.8.168 metric 600\nlocal 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1\nbroadcast 192.168.8.255 dev wlan0 table local proto kernel scope link src 192.168.8.168\n",
    );
    f.file("/proc/sys/net/ipv4/ip_forward", "1\n");
    f.file(
        "/proc/net/tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FakeSystem;

    #[test]
    fn terse_fields_unescape_colons() {
        assert_eq!(split_terse(r"a\:b:c\\d:"), vec!["a:b", r"c\d", ""]);
        assert_eq!(
            split_terse("Home WiFi 1:uuid:802-11-wireless:wlp9s0"),
            vec!["Home WiFi 1", "uuid", "802-11-wireless", "wlp9s0"]
        );
    }

    #[test]
    fn gathers_a_typical_laptop_host() {
        let f = FakeSystem::new();
        script_host(&f);
        f.set_env("SSH_CONNECTION", "192.168.8.20 51000 192.168.8.168 22");
        let h = gather(&f);
        let nm = h.nm.as_ref().unwrap();
        assert!(nm.running && nm.version == "1.36.6");
        assert!(nm.allowed("network-control"));
        assert!(!nm.allowed("checkpoint-rollback"), "auth is not yes");
        assert_eq!(h.wifi.len(), 1);
        let w = &h.wifi[0];
        assert!(w.can_host_wpa2() && w.band_5ghz && w.driver == "mt7925e");
        assert_eq!(w.sae, None, "no iw: WPA3 cannot be verified");
        assert_eq!(h.active_on("wlan0").unwrap().name, "Home WiFi");
        assert_eq!(h.default_routes().len(), 1);
        assert_eq!(h.default_routes()[0].device, "wlan0");
        assert!(h
            .routes
            .iter()
            .any(|r| r.table == "52" && r.device == "tailscale0"));
        assert!(
            !h.routes
                .iter()
                .any(|r| r.dest.addr() == Ipv4Addr::new(127, 0, 0, 1)),
            "local routes are skipped"
        );
        assert_eq!(
            h.interface_of(Ipv4Addr::new(192, 168, 8, 168)),
            Some("wlan0")
        );
        assert_eq!(h.ssh_session.as_ref().unwrap().server_port, 22);
        assert_eq!(h.ip_forward, Some(true));
        assert!(h.established.is_empty(), "LISTEN is not established");
    }

    #[test]
    fn missing_networkmanager_is_a_note_not_a_crash() {
        let f = FakeSystem::new();
        f.ok("ip -4 -o addr show", "");
        f.ok("ip -4 -o route show table all", "");
        let h = gather(&f);
        assert!(h.nm.is_none() && !h.nmcli);
        assert!(h.notes.iter().any(|n| n.contains("nmcli is not installed")));
    }

    #[test]
    fn proc_tcp_established_rows() {
        let t = "  sl  local_address rem_address   st\n   0: A808A8C0:0016 1408A8C0:C738 01 0\n   1: A808A8C0:0016 1408A8C0:C739 06 0\n";
        let c = parse_proc_tcp(t);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].local, (Ipv4Addr::new(192, 168, 8, 168), 22));
        assert_eq!(c[0].remote, (Ipv4Addr::new(192, 168, 8, 20), 51000));
    }

    #[test]
    fn iw_sae_detection() {
        assert!(parse_iw_sae("\tSupported extended features:\n\t\t* [ SAE_OFFLOAD_AP ]: AP mode SAE authentication offload\n"));
        assert!(parse_iw_sae(
            "\tSupported AKM suites:\n\t\t* PSK\n\t\t* SAE\n"
        ));
        assert!(!parse_iw_sae(
            "\tSupported Ciphers:\n\t\t* CCMP-128 (00-0f-ac:4)\n"
        ));
    }

    #[test]
    fn ssh_connection_parsing() {
        assert!(parse_ssh_connection("bogus").is_none());
        let f = FakeSystem::new();
        script_host(&f);
        f.ok("ip -6 -o addr show", "3: wlan0    inet6 fe80::aa:bbff:fecc:dd01/64 scope link noprefixroute \\       valid_lft forever preferred_lft forever\n");
        for (env, want) in [
            (
                "192.168.8.20 51000 192.168.8.168 22",
                SessionPath::Interface("wlan0".into()),
            ),
            (
                "fe80::1 51000 fe80::aa:bbff:fecc:dd01 22",
                SessionPath::Interface("wlan0".into()),
            ),
            (
                "fe80::1 51000 fe80::5%eno1 22",
                SessionPath::Interface("eno1".into()),
            ),
            (
                "10.0.0.9 51000 10.0.0.1 22",
                SessionPath::Unknown("10.0.0.1".into()),
            ),
        ] {
            f.set_env("SSH_CONNECTION", env);
            assert_eq!(gather(&f).session_path(), want, "{env}");
        }
        let local = FakeSystem::new();
        script_host(&local);
        assert_eq!(gather(&local).session_path(), SessionPath::Local);
    }
}
