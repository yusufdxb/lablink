//! [unit, simulated] Endpoint selection against a scripted network: every
//! transport outcome, Tailscale state and identity attack the selector must
//! handle, without sockets or subprocesses.

use lablink_core::config::TailscaleRemote;
use lablink_core::identity::HostKey;
use lablink_remote::select::*;
use lablink_remote::tailscale::{parse_status, TsState};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

fn key(seed: u8) -> HostKey {
    // A syntactically valid ed25519 blob per seed.
    use base64_shim::encode;
    let mut blob = vec![0, 0, 0, 11];
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&[0, 0, 0, 32]);
    blob.extend_from_slice(&[seed; 32]);
    let b64 = encode(&blob);
    HostKey {
        key_type: "ssh-ed25519".into(),
        fingerprint: lablink_ssh::fingerprint_of_blob("ssh-ed25519", &b64).unwrap(),
        public_key: Some(b64),
    }
}

/// Minimal standard base64 so the test needs no extra dependency.
mod base64_shim {
    pub fn encode(b: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }
}

#[derive(Clone)]
enum Host {
    Ssh(Vec<HostKey>),
    Refused,
    Silent,
    /// TCP open, but nothing speaks SSH.
    NotSsh,
}

#[derive(Default)]
struct MockNet {
    ts: Option<TsState>,
    hosts: BTreeMap<IpAddr, Host>,
    dns: BTreeMap<String, Vec<IpAddr>>,
    log: RefCell<Vec<String>>,
}

impl MockNet {
    fn host(mut self, ip: &str, h: Host) -> Self {
        self.hosts.insert(ip.parse().unwrap(), h);
        self
    }
    fn ts(mut self, s: TsState) -> Self {
        self.ts = Some(s);
        self
    }
    fn ts_json(self, j: &str) -> Self {
        self.ts(parse_status(j.as_bytes()))
    }
    fn dns(mut self, n: &str, ips: &[&str]) -> Self {
        self.dns
            .insert(n.into(), ips.iter().map(|i| i.parse().unwrap()).collect());
        self
    }
    fn touched(&self, ip: &str) -> bool {
        self.log.borrow().iter().any(|l| l.ends_with(ip))
    }
}

impl Net for MockNet {
    fn tailscale(&self) -> TsState {
        self.log.borrow_mut().push("tailscale".into());
        self.ts.clone().unwrap_or(TsState::Missing)
    }
    fn lookup(&self, name: &str, _: Duration) -> Result<Vec<IpAddr>, String> {
        self.log.borrow_mut().push(format!("dns {name}"));
        self.dns.get(name).cloned().ok_or_else(|| "NXDOMAIN".into())
    }
    fn tcp(&self, ip: IpAddr, _: u16, _: Duration) -> Result<(), TcpError> {
        self.log.borrow_mut().push(format!("tcp {ip}"));
        match self.hosts.get(&ip) {
            None | Some(Host::Silent) => Err(TcpError::Timeout),
            Some(Host::Refused) => Err(TcpError::Refused),
            Some(_) => Ok(()),
        }
    }
    fn keyscan(&self, ip: IpAddr, _: u16, _: Duration) -> Result<Vec<HostKey>, String> {
        self.log.borrow_mut().push(format!("keyscan {ip}"));
        match self.hosts.get(&ip) {
            Some(Host::Ssh(k)) => Ok(k.clone()),
            _ => Ok(vec![]),
        }
    }
}

const LAN: &str = "192.168.1.20";
const TS: &str = "100.64.0.2";

fn ts_cfg(node_id: Option<&str>) -> TailscaleRemote {
    TailscaleRemote {
        address: "box.tail-ex.ts.net".into(),
        tailnet: "tail-ex.ts.net".into(),
        node_id: node_id.map(str::to_string),
    }
}

fn spec(node_id: Option<&str>) -> DeviceSpec {
    DeviceSpec {
        port: 22,
        pinned: vec![key(1).fingerprint],
        lan: vec![LanHint::Ip(LAN.parse().unwrap())],
        tailscale: Some(ts_cfg(node_id)),
    }
}

fn running(peers: &str) -> String {
    format!(
        r#"{{"BackendState":"Running","CurrentTailnet":{{"Name":"x","MagicDNSSuffix":"tail-ex.ts.net"}},
        "Self":{{"ID":"nSELF","DNSName":"laptop.tail-ex.ts.net.","TailscaleIPs":["100.64.0.1"],"Online":true}},
        "Peer":{{{peers}}}}}"#
    )
}

const BOX_PEER: &str = r#""k1":{"ID":"nBOX","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":["100.64.0.2","fd7a:115c:a1e0::2"],"Online":true}"#;

fn run(spec: &DeviceSpec, pref: Preference, net: &MockNet) -> Selection {
    select(spec, pref, net, Mode::FirstUsable, &Timeouts::default())
}

fn kinds(s: &Selection) -> Vec<(&'static str, &'static str)> {
    s.attempts
        .iter()
        .map(|a| {
            (
                a.transport.as_str(),
                a.problem.as_ref().map(Problem::kind).unwrap_or("ok"),
            )
        })
        .collect()
}

#[test]
fn lan_success_never_asks_tailscale() {
    let net = MockNet::default()
        .host(LAN, Host::Ssh(vec![key(1), key(9)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(Some("nBOX")), Preference::Auto, &net);
    let e = s.endpoint.unwrap();
    assert_eq!(e.transport, Transport::Lan);
    assert_eq!(e.ip.to_string(), LAN);
    assert_eq!(e.keys, vec![key(1)], "only pinned keys go to known_hosts");
    assert!(!net.log.borrow().contains(&"tailscale".to_string()));
}

#[test]
fn lan_down_remote_success() {
    let net = MockNet::default()
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(Some("nBOX")), Preference::Auto, &net);
    assert_eq!(kinds(&s), [("lan", "timeout"), ("tailscale", "ok")]);
    let e = s.endpoint.unwrap();
    assert_eq!(
        (e.transport, e.ip.to_string()),
        (Transport::Tailscale, TS.to_string())
    );
}

#[test]
fn both_unavailable() {
    let net = MockNet::default()
        .host(LAN, Host::Refused)
        .host(TS, Host::Silent)
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(None), Preference::Auto, &net);
    assert!(s.endpoint.is_none() && s.fatal().is_none());
    assert_eq!(
        kinds(&s),
        [("lan", "ssh_refused"), ("tailscale", "timeout")]
    );
}

#[test]
fn lan_host_key_mismatch_is_fatal_and_tailscale_is_not_tried() {
    let net = MockNet::default()
        .host(LAN, Host::Ssh(vec![key(66)]))
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(Some("nBOX")), Preference::Auto, &net);
    assert!(s.endpoint.is_none());
    assert_eq!(s.fatal().unwrap().kind(), "host_key_mismatch");
    assert!(
        !net.touched(TS),
        "no fallback past an identity disagreement"
    );
    assert!(s.fatal().unwrap().describe().contains(&key(66).fingerprint));
}

#[test]
fn tailscale_mitm_is_fatal() {
    // Something answers on the tailnet address with another key.
    let net = MockNet::default()
        .host(TS, Host::Ssh(vec![key(66)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(Some("nBOX")), Preference::Auto, &net);
    assert!(s.endpoint.is_none());
    assert_eq!(
        kinds(&s).last().unwrap(),
        &("tailscale", "host_key_mismatch")
    );
}

#[test]
fn replayed_public_key_without_a_blob_is_not_accepted() {
    // A matching fingerprint with no public key cannot be written to known_hosts.
    let mut k = key(1);
    k.public_key = None;
    let net = MockNet::default().host(LAN, Host::Ssh(vec![k]));
    let s = run(&spec(None), Preference::Lan, &net);
    assert_eq!(kinds(&s), [("lan", "host_key_mismatch")]);
}

#[test]
fn stale_lan_ip_belonging_to_a_non_ssh_host_is_skipped() {
    let net = MockNet::default()
        .host(LAN, Host::NotSsh)
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(None), Preference::Auto, &net);
    assert_eq!(kinds(&s), [("lan", "no_ssh_host_key"), ("tailscale", "ok")]);
}

#[test]
fn missing_tailscale_with_name_uses_system_dns_or_reports_dns_failure() {
    let mut sp = spec(Some("nBOX"));
    sp.lan.clear();
    let net = MockNet::default().ts(TsState::Missing);
    let s = run(&sp, Preference::Auto, &net);
    assert_eq!(kinds(&s), [("tailscale", "dns_failure")]);
    assert!(s.notes[0].contains("not checked"));

    let net = MockNet::default()
        .ts(TsState::Missing)
        .dns("box.tail-ex.ts.net", &[TS])
        .host(TS, Host::Ssh(vec![key(1)]));
    let s = run(&sp, Preference::Auto, &net);
    assert_eq!(s.endpoint.unwrap().ip.to_string(), TS);
}

#[test]
fn missing_tailscale_with_ip_address_still_requires_the_pinned_key() {
    let mut sp = spec(None);
    sp.lan.clear();
    sp.tailscale.as_mut().unwrap().address = TS.into();
    let net = MockNet::default()
        .ts(TsState::Failed("tailscale status timed out"))
        .host(TS, Host::Ssh(vec![key(5)]));
    let s = run(&sp, Preference::Auto, &net);
    assert_eq!(kinds(&s), [("tailscale", "host_key_mismatch")]);
    assert!(s.notes[0].starts_with("tailscale status timed out"));
}

#[test]
fn unauthenticated_and_stopped_tailscale() {
    for (j, kind) in [
        (
            r#"{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/abc"}"#,
            "tailscale_unauthenticated",
        ),
        (
            r#"{"BackendState":"NeedsMachineAuth"}"#,
            "tailscale_unauthenticated",
        ),
        (r#"{"BackendState":"Stopped"}"#, "tailscale_stopped"),
        (r#"{"BackendState":"Starting"}"#, "tailscale_not_ready"),
    ] {
        let net = MockNet::default()
            .ts_json(j)
            .host(TS, Host::Ssh(vec![key(1)]));
        let s = run(&spec(None), Preference::Tailscale, &net);
        assert_eq!(kinds(&s), [("tailscale", kind)], "{j}");
        assert!(
            !net.touched(TS),
            "nothing is sent while Tailscale is not up"
        );
        let msg = s.attempts[0].problem.as_ref().unwrap().describe();
        assert!(!msg.contains("login.tailscale.com"), "{msg}");
    }
}

#[test]
fn other_tailnet_is_refused_before_any_connection() {
    let j = running(BOX_PEER).replace("tail-ex.ts.net\"}", "tail-other.ts.net\"}");
    let net = MockNet::default()
        .ts_json(&j)
        .host(TS, Host::Ssh(vec![key(1)]));
    let s = run(&spec(None), Preference::Tailscale, &net);
    assert_eq!(s.fatal().unwrap().kind(), "tailnet_mismatch");
    assert!(!net.touched(TS));
}

#[test]
fn address_owned_by_another_node_is_fatal() {
    // The device was replaced: same MagicDNS name, different stable node id.
    let peers = r#""k9":{"ID":"nIMPOSTOR","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":["100.64.0.9"],"Online":true}"#;
    let net = MockNet::default()
        .ts_json(&running(peers))
        .host("100.64.0.9", Host::Ssh(vec![key(1)]));
    let s = run(&spec(Some("nBOX")), Preference::Tailscale, &net);
    assert_eq!(s.fatal().unwrap().kind(), "tailscale_peer_mismatch");
    assert!(!net.touched("100.64.0.9"));
}

#[test]
fn hostname_collisions_use_full_names_and_node_ids_only() {
    // Another node whose short HostName is also "box" (other user, shared
    // node) must not be picked; nor may a malicious DNSName with escapes.
    let peers = format!(
        r#"{BOX_PEER},
        "k2":{{"ID":"nOTHER","DNSName":"box.other-tailnet.ts.net.","HostName":"box","TailscaleIPs":["100.64.0.7"],"Online":true}},
        "k3":{{"ID":"nEVIL","DNSName":"box.tail-ex.ts.net.\u001b[2J","HostName":"box","TailscaleIPs":["100.64.0.8"]}}"#
    );
    let net = MockNet::default()
        .ts_json(&running(&peers))
        .host(TS, Host::Ssh(vec![key(1)]))
        .host("100.64.0.7", Host::Ssh(vec![key(1)]))
        .host("100.64.0.8", Host::Ssh(vec![key(1)]));
    let s = run(&spec(None), Preference::Tailscale, &net);
    assert_eq!(s.endpoint.unwrap().ip.to_string(), TS);
    assert!(!net.touched("100.64.0.7") && !net.touched("100.64.0.8"));
}

#[test]
fn duplicate_names_without_node_id_are_refused() {
    let peers = format!(
        r#"{BOX_PEER},"k2":{{"ID":"nTWIN","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":["100.64.0.7"]}}"#
    );
    let net = MockNet::default().ts_json(&running(&peers));
    let s = run(&spec(None), Preference::Tailscale, &net);
    assert_eq!(s.fatal().unwrap().kind(), "tailscale_peer_mismatch");
}

#[test]
fn peer_missing_expired_or_addressless() {
    let net = MockNet::default().ts_json(&running(""));
    assert_eq!(
        kinds(&run(&spec(Some("nBOX")), Preference::Tailscale, &net)),
        [("tailscale", "tailscale_peer_not_found")]
    );
    let expired = BOX_PEER.replace("\"Online\":true", "\"Online\":true,\"Expired\":true");
    let net = MockNet::default().ts_json(&running(&expired));
    assert_eq!(
        kinds(&run(&spec(None), Preference::Tailscale, &net)),
        [("tailscale", "tailscale_peer_expired")]
    );
    let noaddr = r#""k1":{"ID":"nBOX","DNSName":"box.tail-ex.ts.net.","TailscaleIPs":[]}"#;
    let net = MockNet::default().ts_json(&running(noaddr));
    assert_eq!(
        kinds(&run(&spec(Some("nBOX")), Preference::Tailscale, &net)),
        [("tailscale", "tailscale_no_address")]
    );
}

#[test]
fn offline_flag_is_a_note_not_a_verdict() {
    let off = BOX_PEER.replace("\"Online\":true", "\"Online\":false");
    let net = MockNet::default()
        .ts_json(&running(&off))
        .host(TS, Host::Ssh(vec![key(1)]));
    let s = run(&spec(None), Preference::Tailscale, &net);
    assert!(s.endpoint.is_some());
    assert!(s.notes.iter().any(|n| n.contains("offline")));
}

#[test]
fn stale_tailnet_ip_in_config_follows_the_node() {
    // Configured IP no longer belongs to the node: the node id wins only when
    // no other node holds that IP.
    let mut sp = spec(Some("nBOX"));
    sp.tailscale.as_mut().unwrap().address = "100.64.0.99".into();
    let net = MockNet::default()
        .ts_json(&running(BOX_PEER))
        .host(TS, Host::Ssh(vec![key(1)]));
    let s = run(&sp, Preference::Tailscale, &net);
    assert_eq!(s.endpoint.unwrap().ip.to_string(), TS);
}

#[test]
fn transport_preferences() {
    let net = MockNet::default()
        .host(LAN, Host::Ssh(vec![key(1)]))
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = run(&spec(None), Preference::Tailscale, &net);
    assert_eq!(kinds(&s), [("tailscale", "ok")]);
    assert!(!net.touched(LAN));
    let net = MockNet::default()
        .ts_json(&running(BOX_PEER))
        .host(TS, Host::Ssh(vec![key(1)]));
    let s = run(&spec(None), Preference::Lan, &net);
    assert_eq!(kinds(&s), [("lan", "timeout")]);
    assert!(s.endpoint.is_none());
}

#[test]
fn lan_names_resolve_and_dns_failure_is_distinct() {
    let mut sp = spec(None);
    sp.lan = vec![
        LanHint::Name("box.local".into()),
        LanHint::Name("gone.local".into()),
    ];
    sp.tailscale = None;
    let net = MockNet::default()
        .dns("box.local", &["192.168.1.21"])
        .host("192.168.1.21", Host::Ssh(vec![key(1)]));
    let s = run(&sp, Preference::Auto, &net);
    assert_eq!(s.endpoint.unwrap().ip.to_string(), "192.168.1.21");
    sp.lan.reverse();
    let s = run(&sp, Preference::Auto, &net);
    assert_eq!(kinds(&s), [("lan", "dns_failure"), ("lan", "ok")]);
}

#[test]
fn evaluate_all_reports_everything_but_never_selects_past_a_mismatch() {
    let net = MockNet::default()
        .host(LAN, Host::Ssh(vec![key(66)]))
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = select(
        &spec(None),
        Preference::Auto,
        &net,
        Mode::All,
        &Timeouts::default(),
    );
    assert_eq!(
        kinds(&s),
        [("lan", "host_key_mismatch"), ("tailscale", "ok")]
    );
    assert!(s.endpoint.is_none());

    let net = MockNet::default()
        .host(LAN, Host::Ssh(vec![key(1)]))
        .host(TS, Host::Ssh(vec![key(1)]))
        .ts_json(&running(BOX_PEER));
    let s = select(
        &spec(None),
        Preference::Auto,
        &net,
        Mode::All,
        &Timeouts::default(),
    );
    assert_eq!(kinds(&s), [("lan", "ok"), ("tailscale", "ok")]);
    assert_eq!(s.endpoint.unwrap().transport, Transport::Lan);
}

#[test]
fn self_node_can_be_the_target() {
    let mut sp = spec(Some("nSELF"));
    sp.lan.clear();
    sp.tailscale.as_mut().unwrap().address = "laptop.tail-ex.ts.net".into();
    let net = MockNet::default()
        .ts_json(&running(""))
        .host("100.64.0.1", Host::Ssh(vec![key(1)]));
    assert!(run(&sp, Preference::Auto, &net).endpoint.is_some());
}
