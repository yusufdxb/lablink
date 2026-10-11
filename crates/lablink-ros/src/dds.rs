//! What a Cyclone DDS or Fast DDS XML configuration restricts: the network
//! interfaces DDS binds to, multicast, static peers, discovery servers and
//! transports. A deliberately small scanner (no XML dependency): it reads
//! elements by local name and never evaluates anything. LabLink only reads
//! these files; it never writes or "fixes" them.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Vendor {
    Cyclone,
    FastDds,
}

/// One interface selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IfaceSel {
    pub name: Option<String>,
    pub address: Option<String>,
    /// `autodetermine="true"` or `auto`: DDS picks one.
    pub auto: bool,
}

impl IfaceSel {
    pub fn describe(&self) -> String {
        match (&self.name, &self.address, self.auto) {
            (_, _, true) => "auto".into(),
            (Some(n), _, _) => n.clone(),
            (None, Some(a), _) => a.clone(),
            _ => "?".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DdsConfig {
    pub vendor: Vendor,
    /// The file it came from, or "inline".
    pub source: String,
    pub interfaces: Vec<IfaceSel>,
    /// Cyclone `AllowMulticast` (false, true, spdp, asm, ssm, default).
    pub allow_multicast: Option<String>,
    /// Static unicast peers (Cyclone `Peer`, Fast DDS initial peers).
    pub peers: Vec<String>,
    /// Cyclone `<Domain id=..>` values ("any" or a number).
    pub domain_ids: Vec<String>,
    /// Fast DDS `discoveryProtocol` (SIMPLE, CLIENT, SERVER, SUPER_CLIENT ...).
    pub discovery_protocol: Option<String>,
    /// Fast DDS `useBuiltinTransports`.
    pub builtin_transports: Option<bool>,
    /// The file could not be read or parsed.
    pub problem: Option<String>,
}

impl DdsConfig {
    fn empty(vendor: Vendor, source: &str) -> DdsConfig {
        DdsConfig {
            vendor,
            source: source.to_string(),
            interfaces: vec![],
            allow_multicast: None,
            peers: vec![],
            domain_ids: vec![],
            discovery_protocol: None,
            builtin_transports: None,
            problem: None,
        }
    }

    pub fn missing(vendor: Vendor, source: &str, why: &str) -> DdsConfig {
        let mut c = DdsConfig::empty(vendor, source);
        c.problem = Some(why.to_string());
        c
    }

    /// Multicast is off for discovery.
    pub fn multicast_disabled(&self) -> bool {
        matches!(self.allow_multicast.as_deref(), Some("false"))
    }
}

/// An element: its attributes and its (raw) text content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Elem {
    pub attrs: BTreeMap<String, String>,
    pub text: String,
}

fn strip_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        match rest[i..].find("-->") {
            Some(j) => rest = &rest[i + j + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn parse_attrs(s: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut rest = s;
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq]
            .trim()
            .rsplit(char::is_whitespace)
            .next()
            .unwrap_or("");
        let after = rest[eq + 1..].trim_start();
        let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some(end) = after[1..].find(q) else { break };
        let local = key.rsplit(':').next().unwrap_or(key);
        if !local.is_empty() {
            m.insert(local.to_string(), after[1..1 + end].to_string());
        }
        rest = &after[end + 2..];
    }
    m
}

/// Every element whose local name is `name` (namespace prefixes ignored).
pub fn elements(xml: &str, name: &str) -> Vec<Elem> {
    let xml = strip_comments(xml);
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = xml[pos..].find('<') {
        let start = pos + i + 1;
        pos = start;
        let rest = &xml[start..];
        if rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('!') {
            continue;
        }
        let tag_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let full = &rest[..tag_end];
        if full.rsplit(':').next() != Some(name) {
            continue;
        }
        let Some(close) = rest.find('>') else { break };
        let head = &rest[tag_end..close];
        let self_closing = head.trim_end().ends_with('/');
        let attrs = parse_attrs(head.trim_end_matches('/'));
        let text = if self_closing {
            String::new()
        } else {
            let body = &rest[close + 1..];
            let end = body.find(&format!("</{full}")).unwrap_or(body.len());
            body[..end].to_string()
        };
        out.push(Elem { attrs, text });
        pos = start + close;
    }
    out
}

fn texts(xml: &str, name: &str) -> Vec<String> {
    elements(xml, name)
        .into_iter()
        .map(|e| e.text.trim().to_string())
        .filter(|t| !t.is_empty() && !t.contains('<'))
        .collect()
}

pub fn parse_cyclone(xml: &str, source: &str) -> DdsConfig {
    let mut c = DdsConfig::empty(Vendor::Cyclone, source);
    for e in elements(xml, "NetworkInterface") {
        c.interfaces.push(IfaceSel {
            name: e.attrs.get("name").cloned(),
            address: e.attrs.get("address").cloned(),
            auto: e.attrs.get("autodetermine").is_some_and(|v| v == "true"),
        });
    }
    // Older (deprecated) form: an interface name, an address or "auto".
    for t in texts(xml, "NetworkInterfaceAddress") {
        let sel = if t.eq_ignore_ascii_case("auto") {
            IfaceSel {
                auto: true,
                ..Default::default()
            }
        } else if t.parse::<std::net::IpAddr>().is_ok() {
            IfaceSel {
                address: Some(t),
                ..Default::default()
            }
        } else {
            IfaceSel {
                name: Some(t),
                ..Default::default()
            }
        };
        c.interfaces.push(sel);
    }
    c.allow_multicast = texts(xml, "AllowMulticast")
        .pop()
        .map(|v| v.to_ascii_lowercase());
    for e in elements(xml, "Peer") {
        if let Some(a) = e.attrs.get("address").or(e.attrs.get("Address")) {
            c.peers.push(a.clone());
        }
    }
    c.domain_ids = elements(xml, "Domain")
        .into_iter()
        .filter_map(|e| e.attrs.get("id").cloned())
        .collect();
    if !xml.contains("CycloneDDS") && !xml.contains("<General") && !xml.contains("<Domain") {
        c.problem = Some("not a Cyclone DDS configuration".into());
    }
    c
}

pub fn parse_fastdds(xml: &str, source: &str) -> DdsConfig {
    let mut c = DdsConfig::empty(Vendor::FastDds, source);
    for wl in elements(xml, "interfaceWhiteList") {
        for a in texts(&wl.text, "address") {
            c.interfaces.push(IfaceSel {
                address: Some(a),
                ..Default::default()
            });
        }
        for n in texts(&wl.text, "interface") {
            c.interfaces.push(IfaceSel {
                name: Some(n),
                ..Default::default()
            });
        }
    }
    for pl in elements(xml, "initialPeersList") {
        c.peers.extend(texts(&pl.text, "address"));
    }
    c.discovery_protocol = texts(xml, "discoveryProtocol").pop();
    c.builtin_transports = texts(xml, "useBuiltinTransports")
        .pop()
        .map(|v| v == "true");
    if !xml.contains("profiles") && !xml.contains("dds") {
        c.problem = Some("not a Fast DDS profiles file".into());
    }
    c
}

/// A part of `CYCLONEDDS_URI`: inline XML, or a file to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriPart {
    Inline(String),
    File(String),
}

/// Split `CYCLONEDDS_URI` (inline XML, `file://` URIs, plain paths,
/// comma-separated).
pub fn cyclone_uri_parts(uri: &str) -> Vec<UriPart> {
    let u = uri.trim();
    if u.starts_with('<') {
        return vec![UriPart::Inline(u.to_string())];
    }
    u.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.starts_with('<') {
                UriPart::Inline(p.to_string())
            } else {
                UriPart::File(p.strip_prefix("file://").unwrap_or(p).to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CYCLONE_NEW: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<CycloneDDS xmlns="https://cdds.io/config">
  <Domain id="any">
    <General>
      <Interfaces>
        <NetworkInterface name="enP8p1s0" priority="default" multicast="default" />
        <!-- <NetworkInterface name="wlan0"/> -->
      </Interfaces>
      <AllowMulticast>spdp</AllowMulticast>
    </General>
    <Discovery>
      <Peers><Peer address="192.168.123.18"/><Peer address='192.168.123.161'/></Peers>
    </Discovery>
  </Domain>
</CycloneDDS>"#;

    #[test]
    fn cyclone_interfaces_peers_and_comments() {
        let c = parse_cyclone(CYCLONE_NEW, "/home/u/cyclone.xml");
        assert_eq!(
            c.interfaces.len(),
            1,
            "the commented-out interface is ignored"
        );
        assert_eq!(c.interfaces[0].name.as_deref(), Some("enP8p1s0"));
        assert_eq!(c.allow_multicast.as_deref(), Some("spdp"));
        assert_eq!(c.peers, ["192.168.123.18", "192.168.123.161"]);
        assert_eq!(c.domain_ids, ["any"]);
        assert!(c.problem.is_none());
        assert!(!c.multicast_disabled());
    }

    #[test]
    fn cyclone_old_form_and_inline() {
        let c = parse_cyclone(
            "<CycloneDDS><Domain><General><NetworkInterfaceAddress>wlan0</NetworkInterfaceAddress><AllowMulticast>false</AllowMulticast></General></Domain></CycloneDDS>",
            "inline",
        );
        assert_eq!(c.interfaces[0].name.as_deref(), Some("wlan0"));
        assert!(c.multicast_disabled());
        let c = parse_cyclone(
            "<General><NetworkInterfaceAddress>10.0.0.5</NetworkInterfaceAddress></General>",
            "inline",
        );
        assert_eq!(c.interfaces[0].address.as_deref(), Some("10.0.0.5"));
        let c = parse_cyclone(
            "<General><NetworkInterface autodetermine=\"true\"/></General>",
            "x",
        );
        assert!(c.interfaces[0].auto);
        assert_eq!(c.interfaces[0].describe(), "auto");
        assert!(parse_cyclone("hello", "x").problem.is_some());
    }

    #[test]
    fn fastdds_whitelist_peers_discovery() {
        let x = r#"<?xml version="1.0"?>
<dds><profiles xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
  <transport_descriptors><transport_descriptor><transport_id>udp</transport_id><type>UDPv4</type>
    <interfaceWhiteList><address>192.168.1.10</address><interface>wlan0</interface></interfaceWhiteList>
  </transport_descriptor></transport_descriptors>
  <participant profile_name="p" is_default_profile="true"><rtps>
    <useBuiltinTransports>false</useBuiltinTransports>
    <builtin><discovery_config><discoveryProtocol>CLIENT</discoveryProtocol></discovery_config>
      <initialPeersList><locator><udpv4><address>192.168.1.20</address></udpv4></locator></initialPeersList>
    </builtin>
  </rtps></participant>
</profiles></dds>"#;
        let c = parse_fastdds(x, "/etc/fastdds.xml");
        assert_eq!(c.interfaces.len(), 2);
        assert_eq!(c.interfaces[0].address.as_deref(), Some("192.168.1.10"));
        assert_eq!(c.interfaces[1].name.as_deref(), Some("wlan0"));
        assert_eq!(c.peers, ["192.168.1.20"]);
        assert_eq!(c.discovery_protocol.as_deref(), Some("CLIENT"));
        assert_eq!(c.builtin_transports, Some(false));
        assert!(c.problem.is_none());
    }

    #[test]
    fn uri_parts() {
        assert_eq!(
            cyclone_uri_parts("file:///a/b.xml, /c/d.xml"),
            [
                UriPart::File("/a/b.xml".into()),
                UriPart::File("/c/d.xml".into())
            ]
        );
        assert!(matches!(
            cyclone_uri_parts("<CycloneDDS><Domain/></CycloneDDS>")[0],
            UriPart::Inline(_)
        ));
        assert!(cyclone_uri_parts("").is_empty());
    }

    #[test]
    fn scanner_survives_garbage() {
        for x in [
            "<",
            "<NetworkInterface",
            "<NetworkInterface name=\"x",
            "<<<>>>",
            "<a b='1' c=\"2\">",
        ] {
            let _ = parse_cyclone(x, "x");
            let _ = parse_fastdds(x, "x");
        }
    }
}
