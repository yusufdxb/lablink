//! Remote access in the CLI: choosing the path for `ssh`/`exec` (the LAN as
//! the daemon sees it, else a verified Tailscale endpoint), plus the
//! read-only `lablink remote status` and `lablink remote setup`.
//!
//! The selection runs here, at connect time, rather than in the daemon: the
//! daemon is Linux-only and must not send background traffic over a VPN, and
//! a client without a daemon (a laptop, a Mac) still needs the same checks.
//! Devices without a `remote:` block behave exactly as before.

use crate::{print_json, shown, Fail};
use lablink_core::client::{Client, ClientError};
use lablink_core::config::{Config, ConfigError, DeviceConfig, SiteConfig};
use lablink_core::exit;
use lablink_core::model::{IdentityState, NetworkState, ResolveResult, SCHEMA_VERSION};
use lablink_core::protocol::{Candidate, ErrorCode, Request};
use lablink_remote::select::{
    self, Attempt, DeviceSpec, LanHint, Mode, Net, Preference, Problem, Selection, Transport,
};
use lablink_remote::tailscale::{self, printable, TsState};
use lablink_remote::SystemNet;
use lablink_ssh::Target;
use serde_json::{json, Value};

/// `--transport`: which paths `ssh`, `exec` and `remote status` may use.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportArg {
    /// The LAN when it works, else Tailscale (for devices with `remote:`).
    Auto,
    /// Only the LAN (the behaviour of devices without `remote:`).
    Lan,
    /// Only Tailscale.
    Tailscale,
}

impl TransportArg {
    fn pref(self) -> Preference {
        match self {
            TransportArg::Auto => Preference::Auto,
            TransportArg::Lan => Preference::Lan,
            TransportArg::Tailscale => Preference::Tailscale,
        }
    }
}

/// A device ready to connect to.
pub struct Planned {
    pub name: String,
    pub id: String,
    pub shown: String,
    pub shared_name: bool,
    pub ip: String,
    pub port: u16,
    pub pinned: bool,
    pub transport: Transport,
    /// The LAN path as resolved by the daemon (its status explains failures).
    pub via_daemon: bool,
    pub notes: Vec<String>,
    pub target: Target,
}

fn load_config() -> Result<Option<Config>, String> {
    match Config::load(&lablink_core::paths::default_config_path()) {
        Ok(c) => Ok(Some(c)),
        Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The configured device `reference` names, when it has remote access.
/// A name that matches devices at several sites is ambiguous: remote access
/// never guesses across site boundaries.
fn remote_device<'a>(
    cfg: &'a Config,
    reference: &str,
) -> Result<Option<(&'a SiteConfig, &'a DeviceConfig)>, Fail> {
    let hits = cfg.find_devices(reference);
    match hits.as_slice() {
        [] => Ok(None),
        [(s, d)] => Ok(d.remote.is_some().then_some((*s, *d))),
        many => {
            let mut f = Fail::new(
                exit::AMBIGUOUS,
                "ambiguous",
                format!(
                    "ambiguous device '{reference}': it exists at {} sites; use site/name",
                    many.len()
                ),
            );
            f.candidates = many
                .iter()
                .map(|(s, d)| Candidate {
                    id: lablink_core::config::device_id(&s.id, &d.name),
                    site_name: s.name.clone(),
                    name: d.name.clone(),
                })
                .collect();
            Err(f)
        }
    }
}

fn check_user(user: &Option<String>) -> Result<(), Fail> {
    match user {
        Some(u) if !lablink_core::config::valid_username(u) => Err(Fail::new(
            exit::USAGE,
            "bad_request",
            format!("invalid username '{u}'"),
        )),
        _ => Ok(()),
    }
}

/// The LAN path exactly as before remote access existed.
fn lan_planned(r: ResolveResult, user: Option<String>, force: bool) -> Result<Planned, Fail> {
    if r.site_away && !force {
        return Err(Fail::new(
            exit::DEVICE_UNREACHABLE,
            "unreachable",
            format!(
                "'{}' belongs to {}, which is AWAY: you do not appear to be there, and its last address ({}) may belong to another machine here. Switch with `lablink site use {}`, or pass --force to try anyway",
                shown(&r),
                r.site_name,
                r.ip,
                r.id.split('/').next().unwrap_or_default()
            ),
        ));
    }
    if r.network == NetworkState::Offline && !force {
        return Err(Fail::new(
            exit::DEVICE_UNREACHABLE,
            "unreachable",
            format!("'{}' is offline (last known address {}); `lablink status {}` for details, or pass --force to try anyway", shown(&r), r.ip, shown(&r)),
        ));
    }
    let mut t = Target::from_resolve(&r)
        .map_err(|e| Fail::new(exit::IDENTITY_MISMATCH, "identity_mismatch", e))?;
    check_user(&user)?;
    if let Some(u) = user {
        t.username = Some(u);
    }
    Ok(Planned {
        shown: shown(&r),
        shared_name: r.shared_name,
        pinned: r.host_key_alias.is_some(),
        name: r.name,
        id: r.id,
        ip: r.ip,
        port: r.port,
        transport: Transport::Lan,
        via_daemon: true,
        notes: Vec::new(),
        target: t,
    })
}

fn lan_hints(d: &DeviceConfig) -> Vec<LanHint> {
    d.expected_ip_addrs()
        .into_iter()
        .map(LanHint::Ip)
        .chain(d.hostnames.iter().map(|h| LanHint::Name(h.clone())))
        .collect()
}

fn spec(d: &DeviceConfig, lan: Vec<LanHint>) -> DeviceSpec {
    DeviceSpec {
        port: d.ssh_port,
        pinned: d.host_key_fingerprints.clone(),
        lan,
        tailscale: d.remote.as_ref().and_then(|r| r.tailscale.clone()),
    }
}

fn attempt_line(a: &Attempt) -> String {
    let at = match a.ip {
        Some(ip) if ip.to_string() != a.target => format!("{} ({ip})", a.target),
        _ => a.target.clone(),
    };
    format!(
        "{} {at}: {}",
        a.transport.as_str(),
        a.problem
            .as_ref()
            .map(Problem::describe)
            .unwrap_or_else(|| "ok".into())
    )
}

/// The failure for a selection that found nothing usable.
fn selection_failure(label: &str, sel: &Selection) -> Fail {
    if let Some(a) = sel
        .attempts
        .iter()
        .find(|a| a.problem.as_ref().is_some_and(Problem::fatal))
    {
        let p = a.problem.as_ref().expect("fatal problem");
        let code = if matches!(p, Problem::HostKeyMismatch { .. }) {
            exit::IDENTITY_MISMATCH
        } else {
            exit::REFUSED
        };
        return Fail::new(
            code,
            p.kind(),
            format!("refusing to connect to '{label}': {}", attempt_line(a)),
        );
    }
    let kind = sel
        .attempts
        .last()
        .and_then(|a| a.problem.as_ref())
        .map(Problem::kind)
        .unwrap_or("unreachable");
    let tried = if sel.attempts.is_empty() {
        "no path to try".to_string()
    } else {
        sel.attempts
            .iter()
            .map(attempt_line)
            .collect::<Vec<_>>()
            .join("; ")
    };
    let mut msg = format!("'{label}' is not reachable: {tried}");
    for n in &sel.notes {
        msg.push_str(&format!(" (note: {n})"));
    }
    Fail::new(exit::DEVICE_UNREACHABLE, kind, msg)
}

/// Select and verify an endpoint over the LAN hints and/or Tailscale, then
/// build the ssh target pinned to the selected endpoint's verified keys.
fn remote_planned(
    cfg: &Config,
    site: &SiteConfig,
    dev: &DeviceConfig,
    user: Option<String>,
    lan: Vec<LanHint>,
    pref: Preference,
) -> Result<Planned, Fail> {
    check_user(&user)?;
    let id = lablink_core::config::device_id(&site.id, &dev.name);
    let shared = cfg.devices().filter(|(_, d)| d.name == dev.name).count() > 1;
    let label = if shared { id.clone() } else { dev.name.clone() };
    let net = SystemNet::new(&cfg.ssh.keyscan_binary);
    let sel = select::select(
        &spec(dev, lan),
        pref,
        &net,
        Mode::FirstUsable,
        &net.timeouts,
    );
    let Some(ep) = sel.endpoint.clone() else {
        return Err(selection_failure(&label, &sel));
    };
    let pin_file = lablink_remote::write_pin_file(
        &lablink_core::paths::default_state_dir(),
        &site.id,
        &dev.name,
        &ep.keys,
    )
    .map_err(|e| {
        Fail::new(
            exit::FAILURE,
            "state",
            format!("cannot write the pinned host keys for '{label}': {e}"),
        )
    })?;
    let target = Target {
        binary: cfg.ssh.binary.clone(),
        ip: ep.ip.to_string(),
        port: ep.port,
        ssh_host: dev.ssh_host.clone().unwrap_or_else(|| dev.name.clone()),
        username: user.or_else(|| dev.usernames.first().cloned()),
        host_key_alias: Some(lablink_remote::host_key_alias(&site.id, &dev.name)),
        known_hosts_file: Some(pin_file),
        connect_timeout_s: cfg.ssh.connect_timeout_s,
        options: cfg.ssh.options.clone(),
        proxy_command: None,
    };
    Ok(Planned {
        name: dev.name.clone(),
        id,
        shown: label,
        shared_name: shared,
        ip: ep.ip.to_string(),
        port: ep.port,
        pinned: true,
        transport: ep.transport,
        via_daemon: false,
        notes: sel.notes,
        target,
    })
}

fn no_remote(device: &str) -> Fail {
    Fail::new(
        exit::USAGE,
        "bad_request",
        format!("'{device}' has no `remote: tailscale:` configuration (see docs/REMOTE_ACCESS.md)"),
    )
}

/// Decide how to reach `device` for `ssh`/`exec`.
pub fn plan(
    client: &Client,
    device: &str,
    user: Option<String>,
    force: bool,
    transport: TransportArg,
) -> Result<Planned, Fail> {
    let pref = transport.pref();
    let cfg = load_config();
    match client.call_typed::<ResolveResult>(&Request::Resolve {
        device: device.into(),
    }) {
        Ok(r) => {
            // Only the configured device the daemon resolved, never a namesake.
            let remote = match cfg.as_ref().ok().and_then(Option::as_ref) {
                Some(c) if !r.id.is_empty() => remote_device(c, &r.id)?.map(|(s, d)| (c, s, d)),
                _ => None,
            };
            let lan_ok = !r.site_away
                && r.network != NetworkState::Offline
                && r.identity != IdentityState::Mismatch;
            match (pref, remote) {
                (Preference::Tailscale, None) => Err(no_remote(device)),
                // An identity mismatch is never routed around.
                (_, _) if r.identity == IdentityState::Mismatch => lan_planned(r, user, force),
                (Preference::Lan, _) | (Preference::Auto, None) => lan_planned(r, user, force),
                (Preference::Auto, Some(_)) if lan_ok => lan_planned(r, user, force),
                (_, Some((c, s, d))) => {
                    let user = user.or(r.username);
                    remote_planned(c, s, d, user, Vec::new(), Preference::Tailscale)
                }
            }
        }
        // The daemon knows the device but has no usable LAN address for it.
        Err(ClientError::Api(e)) if e.code == ErrorCode::Unreachable && pref != Preference::Lan => {
            match cfg.as_ref().ok().and_then(Option::as_ref) {
                Some(c) => match remote_device(c, device)? {
                    Some((s, d)) => {
                        remote_planned(c, s, d, user, Vec::new(), Preference::Tailscale)
                    }
                    None if pref == Preference::Tailscale => Err(no_remote(device)),
                    None => Err(ClientError::Api(e).into()),
                },
                None => Err(ClientError::Api(e).into()),
            }
        }
        // No daemon (not installed, stopped, or an OS it does not run on):
        // devices with remote access still work from the config file alone.
        Err(e @ ClientError::Unavailable { .. }) => {
            let original: Fail = e.into();
            match cfg {
                Ok(Some(c)) => match remote_device(&c, device)? {
                    Some((s, d)) => {
                        let lan = if pref == Preference::Tailscale {
                            Vec::new()
                        } else {
                            lan_hints(d)
                        };
                        remote_planned(&c, s, d, user, lan, pref)
                    }
                    None => Err(original),
                },
                Ok(None) => Err(original),
                Err(ce) => Err(Fail::new(
                    original.code,
                    original.kind,
                    format!(
                        "{} (the config file is also invalid: {ce})",
                        original.message
                    ),
                )),
            }
        }
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------------------
// lablink remote status

fn ts_view(s: &TsState) -> Value {
    match s {
        TsState::Missing => json!({
            "state": "missing",
            "detail": tailscale::missing_cli_hint(tailscale::Os::current()),
        }),
        TsState::Failed(why) => json!({ "state": "error", "detail": why }),
        TsState::NotRunning { state } => json!({
            "state": match *state {
                "NeedsLogin" | "NeedsMachineAuth" => "logged_out",
                "Stopped" => "stopped",
                _ => "not_ready",
            },
            "backend_state": state,
        }),
        TsState::Running(snap) => json!({
            "state": "running",
            "tailnet": snap.tailnet,
            "self_name": snap.self_node.as_ref().map(|n| n.dns_name.clone()),
            "self_node_id": snap.self_node.as_ref().map(|n| n.id.clone()),
            "self_ips": snap.self_node.as_ref().map(|n| n.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>()),
            "peers": snap.peers.len(),
        }),
    }
}

fn ts_line(v: &Value) -> String {
    match v["state"].as_str().unwrap_or("") {
        "running" => format!(
            "Tailscale: running, tailnet {}, this machine {}",
            v["tailnet"].as_str().unwrap_or("<unknown>"),
            v["self_name"]
                .as_str()
                .map(printable)
                .unwrap_or_else(|| "<unknown>".into())
        ),
        "missing" => format!("Tailscale: {}", v["detail"].as_str().unwrap_or("")),
        "error" => format!("Tailscale: {}", v["detail"].as_str().unwrap_or("")),
        "logged_out" => "Tailscale: installed, NOT logged in".into(),
        "stopped" => "Tailscale: installed, disconnected".into(),
        _ => format!(
            "Tailscale: not ready ({})",
            v["backend_state"].as_str().unwrap_or("?")
        ),
    }
}

fn attempt_json(a: &Attempt) -> Value {
    json!({
        "transport": a.transport.as_str(),
        "target": a.target,
        "ip": a.ip.map(|i| i.to_string()),
        "result": a.problem.as_ref().map(Problem::kind).unwrap_or("ok"),
        "message": a.problem.as_ref().map(Problem::describe),
    })
}

/// `lablink remote status [device]`.
pub fn cmd_status(
    client: &Client,
    device: Option<String>,
    transport: TransportArg,
    json_out: bool,
) -> crate::R {
    let cfg = load_config().map_err(|e| Fail::new(exit::USAGE, "config", e))?;
    let cfg = cfg.unwrap_or_default();
    let net = SystemNet::new(&cfg.ssh.keyscan_binary);
    let ts = ts_view(&net.tailscale());
    let Some(device) = device else {
        let devices: Vec<Value> = cfg
            .devices()
            .filter_map(|(s, d)| {
                let t = d.remote.as_ref()?.tailscale.as_ref()?;
                Some(json!({
                    "id": lablink_core::config::device_id(&s.id, &d.name),
                    "address": t.address,
                    "tailnet": t.tailnet,
                    "node_id": t.node_id,
                }))
            })
            .collect();
        if json_out {
            print_json(&json!({
                "schema_version": SCHEMA_VERSION,
                "tailscale": ts,
                "devices": devices,
            }));
        } else {
            println!("{}", ts_line(&ts));
            if devices.is_empty() {
                println!("No device has remote access configured (see `lablink remote setup` on the device).");
            }
            for d in &devices {
                println!(
                    "{}: tailscale {} (tailnet {})",
                    d["id"].as_str().unwrap_or(""),
                    d["address"].as_str().unwrap_or(""),
                    d["tailnet"].as_str().unwrap_or("")
                );
            }
        }
        return Ok(exit::OK);
    };

    let Some((site, dev)) = remote_device(&cfg, &device)? else {
        return Err(no_remote(&device));
    };
    let id = lablink_core::config::device_id(&site.id, &dev.name);
    let pref = transport.pref();
    // The daemon's view of the LAN, when there is a daemon.
    let (daemon, lan_view, lan_ip) =
        match client.call_typed::<ResolveResult>(&Request::Resolve { device: id.clone() }) {
            Ok(r) => {
                let v = if r.identity == IdentityState::Mismatch {
                    "identity_mismatch"
                } else if r.site_away {
                    "away"
                } else if r.network == NetworkState::Offline {
                    "offline"
                } else {
                    "online"
                };
                (true, v, Some(r.ip))
            }
            Err(ClientError::Unavailable { .. }) => (false, "no_daemon", None),
            Err(ClientError::Api(e)) if e.code == ErrorCode::IdentityMismatch => {
                (true, "identity_mismatch", None)
            }
            Err(_) => (true, "unknown", None),
        };
    // Without a daemon, LAN hints are probed like `ssh` would.
    let lan = if daemon || pref == Preference::Tailscale {
        Vec::new()
    } else {
        lan_hints(dev)
    };
    let sel = select::select(&spec(dev, lan), pref, &net, Mode::All, &net.timeouts);
    let daemon_lan_usable = daemon && lan_view == "online" && pref != Preference::Tailscale;
    let would_use = if lan_view == "identity_mismatch" {
        None
    } else if daemon_lan_usable {
        Some(json!({ "transport": "lan", "ip": lan_ip, "via": "daemon" }))
    } else {
        sel.endpoint
            .as_ref()
            .map(|e| json!({ "transport": e.transport.as_str(), "ip": e.ip.to_string() }))
    };
    let code = if lan_view == "identity_mismatch" {
        exit::IDENTITY_MISMATCH
    } else if would_use.is_some() {
        exit::OK
    } else {
        match sel.fatal() {
            Some(Problem::HostKeyMismatch { .. }) => exit::IDENTITY_MISMATCH,
            Some(_) => exit::REFUSED,
            None => exit::DEVICE_UNREACHABLE,
        }
    };
    if json_out {
        print_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "device": id,
            "tailscale": ts,
            "daemon": { "available": daemon, "lan": lan_view, "ip": lan_ip },
            "attempts": sel.attempts.iter().map(attempt_json).collect::<Vec<_>>(),
            "notes": sel.notes,
            "would_use": would_use,
            "exit_code": code,
        }));
    } else {
        println!("{}", ts_line(&ts));
        println!(
            "{id}: LAN per daemon: {}",
            match lan_view {
                "no_daemon" =>
                    "lablinkd is not running; LAN addresses from the config are probed instead"
                        .to_string(),
                "online" => format!("online at {}", lan_ip.as_deref().unwrap_or("?")),
                "identity_mismatch" => "HOST KEY MISMATCH (security stop)".to_string(),
                other => other.to_string(),
            }
        );
        for a in &sel.attempts {
            println!("  {}", attempt_line(a));
        }
        for n in &sel.notes {
            println!("  note: {n}");
        }
        match &would_use {
            Some(w) => println!(
                "lablink ssh would use: {} {}",
                w["transport"].as_str().unwrap_or(""),
                w["ip"].as_str().unwrap_or("")
            ),
            None => println!("lablink ssh would refuse or fail (exit {code})"),
        }
    }
    Ok(code)
}

// ---------------------------------------------------------------------------
// lablink remote setup

/// This machine's SSH host keys, read from the public key files.
fn local_host_keys() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for t in ["ed25519", "ecdsa", "rsa"] {
        let p = format!("/etc/ssh/ssh_host_{t}_key.pub");
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let f: Vec<&str> = text.split_whitespace().collect();
        if f.len() >= 2 {
            if let Ok(fp) = lablink_ssh::fingerprint_of_blob(f[0], f[1]) {
                v.push((f[0].to_string(), fp));
            }
        }
    }
    v
}

fn local_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // on success when the name fits.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let h = String::from_utf8_lossy(&buf[..end])
        .split('.')
        .next()?
        .to_ascii_lowercase();
    lablink_core::config::valid_name(&h).then_some(h)
}

fn setup_steps(os: tailscale::Os, ts: &Value, sshd_ok: bool) -> Vec<String> {
    let mut s = Vec::new();
    let state = ts["state"].as_str().unwrap_or("");
    if !sshd_ok {
        s.push(match os {
            tailscale::Os::MacOs => "Enable an SSH server: System Settings > General > Sharing > Remote Login (only if this machine should accept SSH)".to_string(),
            _ => "Install and start an SSH server (only if this machine should accept SSH): sudo apt install openssh-server".to_string(),
        });
    }
    match state {
        "missing" => s.push(match os {
            tailscale::Os::MacOs => "Install Tailscale from https://tailscale.com/download/mac (Mac App Store or standalone), then log in from the app".to_string(),
            _ => "Install Tailscale from its official package repository: https://tailscale.com/download/linux (review the script before running it)".to_string(),
        }),
        "logged_out" | "stopped" | "not_ready" => s.push(match os {
            tailscale::Os::MacOs => "Log in / connect in the Tailscale app".to_string(),
            _ => "Log in yourself: sudo tailscale up   (no --ssh, no --advertise-routes, no --advertise-exit-node: LabLink needs none of them)".to_string(),
        }),
        _ => {}
    }
    s.push("Restrict who can reach port 22 with a tailnet access policy (only your own devices); never forward port 22 on your router".to_string());
    s.push("Prefer key-only SSH logins on a machine reachable over the tailnet (PasswordAuthentication no), after confirming key login works".to_string());
    s.push("On each client: add the snippet below to ~/.config/lablink/config.yaml, then `lablink check-config` and `lablink remote status <name>`".to_string());
    s
}

/// `lablink remote setup`: read-only; prints what this machine needs and the
/// config snippet other machines use to reach it.
pub fn cmd_setup(json_out: bool) -> crate::R {
    let os = tailscale::Os::current();
    let net = SystemNet::new("ssh-keyscan");
    let ts = ts_view(&net.tailscale());
    let keys = local_host_keys();
    let localhost = "127.0.0.1".parse().expect("literal");
    let sshd_ok = net
        .tcp(localhost, 22, std::time::Duration::from_secs(1))
        .is_ok();
    let name = local_hostname();
    let user = std::env::var("USER")
        .ok()
        .filter(|u| lablink_core::config::valid_username(u));
    let fps: Vec<String> = keys.iter().map(|(_, f)| f.clone()).collect();
    let mut snippet = String::new();
    if let Some(n) = &name {
        snippet.push_str(&format!("  - name: {n}\n"));
    } else {
        snippet.push_str("  - name: <this-machine>\n");
    }
    if let Some(u) = &user {
        snippet.push_str(&format!("    usernames: [{u}]\n"));
    }
    if let Some(n) = &name {
        snippet.push_str(&format!(
            "    hostnames: [{n}.local]   # LAN name; only if mDNS runs here\n"
        ));
    }
    snippet.push_str(&format!(
        "    host_key_fingerprints: [{}]\n",
        fps.iter()
            .map(|f| format!("\"{f}\""))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let self_name = ts["self_name"].as_str().filter(|s| !s.is_empty());
    let tailnet = ts["tailnet"].as_str();
    snippet.push_str("    remote:\n      tailscale:\n");
    snippet.push_str(&format!(
        "        address: {}\n        tailnet: {}\n",
        self_name.unwrap_or("<this machine's MagicDNS name>"),
        tailnet.unwrap_or("<your tailnet's MagicDNS suffix>")
    ));
    if let Some(id) = ts["self_node_id"].as_str() {
        snippet.push_str(&format!("        node_id: {id}\n"));
    }
    let steps = setup_steps(os, &ts, sshd_ok);
    if json_out {
        print_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "tailscale": ts,
            "ssh_server_listening": sshd_ok,
            "host_keys": keys.iter().map(|(t, f)| json!({"type": t, "fingerprint": f})).collect::<Vec<_>>(),
            "steps": steps,
            "client_config_snippet": snippet,
        }));
    } else {
        println!("{}", ts_line(&ts));
        println!(
            "SSH server on this machine: {}",
            if sshd_ok {
                "listening on port 22"
            } else {
                "not listening on 127.0.0.1:22"
            }
        );
        if keys.is_empty() {
            println!("SSH host keys: none found in /etc/ssh");
        }
        for (t, f) in &keys {
            println!("SSH host key: {t} {f}");
        }
        println!("\nLabLink changed nothing. Steps that need you (each one is your decision):");
        for (i, s) in steps.iter().enumerate() {
            println!("  {}. {s}", i + 1);
        }
        println!("\nVerify these fingerprints on this machine's own console, then add to each client's config (under `devices:` or a site's `devices:`):\n");
        print!("{snippet}");
    }
    Ok(exit::OK)
}
