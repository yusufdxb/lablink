//! The steps the CLI and the app share around a Field Network change:
//! the preflight plan (with the daemon's view of which registered devices
//! this machine reaches) and the classification of hotspot clients.
//!
//! A client is matched to a registered device only through the daemon's
//! verdict, which rests on the device's pinned host key. A hostname, MAC
//! or address alone never makes a client a known device.

use crate::host::HostFacts;
use crate::preflight::{self, Equipment, Level};
use crate::state::{self, Security};
use crate::system::System;
use lablink_core::client::Client;
use lablink_core::model::{AuthState, Color, DeviceStatus, IdentityState, PortState, StatusReport};
use lablink_core::protocol::Request;
use serde::Serialize;
use std::path::Path;

/// What to start, as typed (validated by [`plan`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanArgs {
    pub interface: Option<String>,
    pub ssid: Option<String>,
    pub subnet: Option<String>,
    /// `wpa2` or `wpa3`.
    pub security: String,
    pub allow_internet_sharing: bool,
    pub allow_dns_relay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The arguments are invalid (usage error).
    BadRequest(String),
    /// LabLink's own hotspot record cannot be read.
    State(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::BadRequest(m) | PlanError::State(m) => f.write_str(m),
        }
    }
}

pub struct Planned {
    pub facts: HostFacts,
    pub pf: preflight::Preflight,
}

/// The networks of the other (non-roaming) sites, for subnet conflicts.
pub fn site_networks(cfg: &lablink_core::Config) -> Vec<(String, ipnet::Ipv4Net)> {
    cfg.sites
        .iter()
        .filter(|s| !s.roaming)
        .flat_map(|s| {
            s.networks
                .iter()
                .filter_map(move |n| n.cidr.parse().ok().map(|c| (s.id.clone(), c)))
        })
        .collect()
}

fn all_devices(client: &Client) -> Option<Vec<DeviceStatus>> {
    let r: StatusReport = client
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .ok()?;
    Some(r.devices)
}

/// Registered devices this machine reaches now, from the daemon. `None`
/// when the daemon cannot be asked.
pub fn equipment(client: &Client) -> Option<Vec<Equipment>> {
    Some(
        all_devices(client)?
            .iter()
            .filter(|d| matches!(d.color, Color::Green | Color::Yellow))
            .filter_map(|d| {
                Some(Equipment {
                    name: d.id.clone(),
                    ip: d.ip.as_deref()?.parse().ok()?,
                })
            })
            .collect(),
    )
}

/// The read-only preflight for `args`: validates the request, fills the
/// defaults from LabLink's previous hotspot, gathers host facts and checks.
/// Changes nothing.
pub fn plan(
    sys: &dyn System,
    client: &Client,
    cfg: &lablink_core::Config,
    state_dir: &Path,
    args: &PlanArgs,
) -> Result<Planned, PlanError> {
    let security = Security::parse(&args.security).map_err(PlanError::BadRequest)?;
    let old = state::load(state_dir).map_err(PlanError::State)?;
    let subnet = match &args.subnet {
        Some(s) => Some(
            s.parse()
                .map_err(|_| PlanError::BadRequest(format!("'{s}' is not an IPv4 CIDR")))?,
        ),
        None => old.as_ref().and_then(|o| o.subnet.parse().ok()),
    };
    if let Some(i) = &args.interface {
        if !lablink_core::config::valid_interface(i) {
            return Err(PlanError::BadRequest(format!(
                "'{i}' is not an interface name"
            )));
        }
    }
    let ssid = args
        .ssid
        .clone()
        .or_else(|| old.as_ref().map(|o| o.ssid.clone()))
        .unwrap_or_else(|| crate::password::default_ssid(sys));
    let req = preflight::Request {
        interface: args.interface.clone(),
        ssid,
        subnet,
        security,
        allow_internet_sharing: args.allow_internet_sharing,
        allow_dns_relay: args.allow_dns_relay,
    };
    let facts = crate::host::gather(sys);
    let sites = site_networks(cfg);
    let equipment = equipment(client);
    let own = old.as_ref().and_then(|o| o.profile_uuid.clone());
    let mut pf = preflight::check(
        &facts,
        &req,
        &preflight::Context {
            sites: &sites,
            equipment: equipment.as_deref().unwrap_or_default(),
            own_profile: own.as_deref(),
        },
    );
    if equipment.is_none() && !pf.already_running {
        pf.findings.push(preflight::Finding {
            level: Level::Warn,
            code: "equipment",
            message: "lablinkd is not running, so LabLink cannot tell which registered devices use this link, and nothing will re-check isolation while the hotspot runs (`status` checks only when you run it). Make sure no robot is moving or depending on it, and start lablinkd first.".into(),
            override_flag: None,
        });
        pf.findings.sort_by_key(|f| f.level);
    }
    Ok(Planned { facts, pf })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClientRow {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub presence: crate::clients::Presence,
    /// discovered-untrusted, registered, ssh-available, ssh-authenticated,
    /// ssh-unreachable, identity-mismatch or disconnected.
    pub state: &'static str,
    /// The registered device (`site/name`) at this address, proven by its
    /// pinned host key (never by name, MAC or address).
    pub device: Option<String>,
    pub address_changed: bool,
}

/// The state of each hotspot client, from the daemon's verdicts. Without
/// the daemon every client is `discovered-untrusted`.
pub fn classify_clients(
    client: &Client,
    clients: &[crate::clients::Client],
    started_ms: Option<u64>,
) -> Vec<ClientRow> {
    let devices = all_devices(client).unwrap_or_default();
    let mut rows: Vec<ClientRow> = clients
        .iter()
        .map(|c| {
            let ip = c.ip.to_string();
            // An address alone proves nothing: another client can take a
            // departed device's address (and MAC). Only a key verdict names
            // the device.
            let d = devices.iter().find(|d| {
                d.ip.as_deref() == Some(ip.as_str()) && d.visiting.is_some() && names_device(d)
            });
            let address_changed = d.is_some_and(|d| changed_since(client, &d.id, started_ms));
            ClientRow {
                ip,
                mac: c.mac.clone(),
                hostname: c.hostname.clone(),
                presence: c.presence,
                state: d.map_or("discovered-untrusted", device_state),
                device: d.map(|d| d.id.clone()),
                address_changed,
            }
        })
        .collect();
    // Registered devices visiting the Field Network that are not here now.
    for d in devices
        .iter()
        .filter(|d| d.visiting.is_some() && d.color == Color::Gray)
    {
        if !rows
            .iter()
            .any(|r| r.device.as_deref() == Some(d.id.as_str()))
        {
            rows.push(ClientRow {
                ip: d.ip.clone().unwrap_or_default(),
                mac: None,
                hostname: None,
                presence: crate::clients::Presence::Stale,
                state: "disconnected",
                device: Some(d.id.clone()),
                address_changed: false,
            });
        }
    }
    rows
}

/// A client at a device's address is shown as that device only when the
/// daemon proved its pinned key there, or caught a different key (a
/// mismatch, shown as such).
fn names_device(d: &DeviceStatus) -> bool {
    matches!(
        d.identity,
        IdentityState::Verified | IdentityState::Mismatch
    )
}

fn device_state(d: &DeviceStatus) -> &'static str {
    match d {
        d if d.identity == IdentityState::Mismatch => "identity-mismatch",
        d if d.identity != IdentityState::Verified => "discovered-untrusted",
        d if d.identity == IdentityState::Verified && d.ssh_auth == AuthState::Ok => {
            "ssh-authenticated"
        }
        d if d.identity == IdentityState::Verified && d.ssh_port == PortState::Open => {
            "ssh-available"
        }
        d if matches!(d.ssh_port, PortState::Closed | PortState::Filtered) => "ssh-unreachable",
        _ => "registered",
    }
}

fn changed_since(client: &Client, id: &str, since: Option<u64>) -> bool {
    let Some(since) = since else { return false };
    client
        .call(&Request::History {
            device: Some(id.to_string()),
            limit: 10,
        })
        .ok()
        .and_then(|v| v["events"].as_array().cloned())
        .is_some_and(|ev| {
            ev.iter().any(|e| {
                e["kind"] == "ip_changed" && e["ts_ms"].as_u64().is_some_and(|t| t >= since)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_core::model::{DiscoveryState, NetworkState};

    fn dev(identity: IdentityState, port: PortState, auth: AuthState) -> DeviceStatus {
        DeviceStatus {
            name: "orin".into(),
            id: "lab/orin".into(),
            site: "lab".into(),
            site_name: "Lab".into(),
            site_state: lablink_core::site::SiteState::Active,
            label: None,
            color: Color::Green,
            ip: Some("10.77.0.31".into()),
            discovery: DiscoveryState::Located,
            network: NetworkState::Online,
            ssh_port: port,
            ssh_auth: auth,
            identity,
            latency_ms: None,
            last_seen_ms: None,
            username: None,
            interface: None,
            network_name: None,
            via: None,
            visiting: None,
            monitoring: true,
            reasons: vec![],
            services: vec![],
            profile: None,
            capabilities: vec![],
        }
    }

    #[test]
    fn only_a_key_verdict_names_a_client() {
        use AuthState as A;
        use IdentityState as I;
        use PortState as P;
        for (identity, port, auth, names, state) in [
            (I::Verified, P::Open, A::Ok, true, "ssh-authenticated"),
            (I::Verified, P::Open, A::Unknown, true, "ssh-available"),
            (I::Verified, P::Closed, A::Unknown, true, "ssh-unreachable"),
            (I::Verified, P::Unknown, A::Unknown, true, "registered"),
            (I::Mismatch, P::Open, A::Unknown, true, "identity-mismatch"),
            // Same address, SSH closed or key not seen: not the device.
            (
                I::Unverified,
                P::Open,
                A::Unknown,
                false,
                "discovered-untrusted",
            ),
            (
                I::Unknown,
                P::Closed,
                A::Unknown,
                false,
                "discovered-untrusted",
            ),
        ] {
            let d = dev(identity, port, auth);
            assert_eq!(names_device(&d), names, "{identity:?} {port:?}");
            assert_eq!(device_state(&d), state, "{identity:?} {port:?}");
        }
    }
}
