//! The `dds-check` flow the CLI and the app share: locate the devices
//! through the daemon, inspect them (a pair at the same time), run the
//! active probe only when asked, and diagnose.

use crate::active::{self, ActiveReport};
use crate::diagnose::{self, Input, Report, Side};
use crate::inspect::{self, Options};
use crate::{Remote, RemoteError};
use lablink_core::client::{Client, ClientError};
use lablink_core::model::ResolveResult;
use lablink_core::protocol::Request;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub device: String,
    pub peer: Option<String>,
    /// Run the active probe (needs `peer` and the graph).
    pub active: bool,
    pub opts: Options,
}

#[derive(Debug)]
pub enum CheckError {
    /// The arguments are invalid (usage error).
    BadRequest(String),
    /// The daemon refused or could not be reached (its own exit codes).
    Daemon(ClientError),
    Remote(RemoteError),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::BadRequest(m) => f.write_str(m),
            CheckError::Daemon(e) => write!(f, "{e}"),
            CheckError::Remote(e) => write!(f, "{e}"),
        }
    }
}

/// Resolve through the daemon first: the usual errors (daemon down,
/// unknown, unreachable, identity mismatch), and the address LabLink
/// located the device at.
pub fn locate(client: &Client, device: &str) -> Result<(String, Option<Ipv4Addr>), ClientError> {
    let r: ResolveResult = client.call_typed(&Request::Resolve {
        device: device.to_string(),
        batch: true,
    })?;
    Ok((r.name.clone(), r.ip.parse().ok()))
}

/// Validate `req` without touching the daemon or a device.
pub fn validate(req: &CheckRequest) -> Result<(), CheckError> {
    let bad = |m: &str| Err(CheckError::BadRequest(m.into()));
    if req.opts.qos_topics.len() > 5 {
        return bad("at most 5 QoS topics");
    }
    if let Some(t) = req
        .opts
        .qos_topics
        .iter()
        .find(|t| !crate::script::valid_topic(t))
    {
        return Err(CheckError::BadRequest(format!(
            "invalid topic name '{}' (absolute, letters, digits, _ and /)",
            lablink_core::printable(t)
        )));
    }
    if req.active && !req.opts.graph {
        return bad("the active test needs the graph");
    }
    if req.active && req.peer.is_none() {
        return bad("the active test needs a peer device");
    }
    Ok(())
}

/// Run the check. `on_active` is called (with both device names) just
/// before the active probe starts, so a caller can say it is running.
pub fn run(
    client: &Client,
    remote: &dyn Remote,
    req: &CheckRequest,
    on_active: impl FnOnce(&str, &str),
) -> Result<(Report, Option<ActiveReport>), CheckError> {
    validate(req)?;
    let timeout_ms = req.opts.timeout.as_millis() as u64;
    let (a, a_ip) = locate(client, &req.device).map_err(CheckError::Daemon)?;
    let Some(peer) = &req.peer else {
        let ia = inspect::inspect(remote, &a, &req.opts).map_err(CheckError::Remote)?;
        let r = diagnose::diagnose(&Input {
            a: Side { ins: &ia, ip: a_ip },
            b: None,
            active: None,
            timeout_ms,
        });
        return Ok((r, None));
    };
    let (b, b_ip) = locate(client, peer).map_err(CheckError::Daemon)?;
    if b == a {
        return Err(CheckError::BadRequest(
            "the peer must be a different device".into(),
        ));
    }
    let (ia, ib) = inspect::inspect_pair(remote, &a, &b, &req.opts);
    let ia = ia.map_err(CheckError::Remote)?;
    let ib = ib.map_err(CheckError::Remote)?;
    let act = req.active.then(|| {
        on_active(&a, &b);
        active::run(remote, &ia, &ib, b_ip)
    });
    let r = diagnose::diagnose(&Input {
        a: Side { ins: &ia, ip: a_ip },
        b: Some(Side { ins: &ib, ip: b_ip }),
        active: act.as_ref(),
        timeout_ms,
    });
    Ok((r, act))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(peer: Option<&str>, active: bool, graph: bool, topics: &[&str]) -> CheckRequest {
        CheckRequest {
            device: "a".into(),
            peer: peer.map(Into::into),
            active,
            opts: Options {
                graph,
                qos_topics: topics.iter().map(|t| t.to_string()).collect(),
                ..Options::default()
            },
        }
    }

    fn rejected(r: &CheckRequest) -> String {
        match validate(r) {
            Err(CheckError::BadRequest(m)) => m,
            other => panic!("expected a bad request, got {other:?}"),
        }
    }

    #[test]
    fn passive_checks_are_valid() {
        assert!(validate(&req(None, false, false, &[])).is_ok());
        assert!(validate(&req(Some("b"), false, true, &["/chatter"])).is_ok());
        assert!(validate(&req(Some("b"), true, true, &[])).is_ok());
    }

    #[test]
    fn the_active_test_needs_the_graph_and_a_peer() {
        assert!(rejected(&req(Some("b"), true, false, &[])).contains("graph"));
        assert!(rejected(&req(None, true, true, &[])).contains("peer"));
    }

    #[test]
    fn qos_topics_are_bounded_and_checked() {
        let six = ["/a", "/b", "/c", "/d", "/e", "/f"];
        assert!(rejected(&req(None, false, true, &six)).contains("at most 5"));
        let m = rejected(&req(None, false, true, &["/ok", "bad; rm -rf /"]));
        assert!(m.contains("invalid topic"), "{m}");
        let m = rejected(&req(None, false, true, &["/x\u{1b}[2J"]));
        assert!(
            !m.contains('\u{1b}'),
            "terminal escapes must not reach the message: {m:?}"
        );
    }
}
