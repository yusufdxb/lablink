//! `lablink hotspot ...` (the Field Network) and `lablink feature ...`.
//!
//! The hotspot commands run on this machine through NetworkManager, not
//! through the daemon: the daemon has no privileges and no network-changing
//! API. They are opt-in (`lablink feature enable field-network`), except
//! the read-only `capabilities`. Every change is preceded by the read-only
//! preflight; warnings need `--yes` or a typed confirmation, and blockers
//! (such as cutting the SSH session that runs the command) refuse.

use crate::{print_json, Fail, R};
use clap::Subcommand;
use lablink_core::client::Client;
use lablink_core::exit;
use lablink_core::model::{AuthState, Color, IdentityState, PortState, StatusReport};
use lablink_core::protocol::Request;
use lablink_fieldnet::preflight::{self, Equipment, Level};
use lablink_fieldnet::state::Security;
use lablink_fieldnet::system::{RealSystem, System};
use lablink_fieldnet::{nm, Error};
use lablink_setup::{configfile, service};
use serde::Serialize;
use serde_json::json;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug, Clone)]
pub struct StartArgs {
    /// Wi-Fi adapter to host on [default: a free capable adapter, else the only one]
    #[arg(long)]
    interface: Option<String>,
    /// Network name [default: the previous one, else LabLink-XXXX]
    #[arg(long)]
    ssid: Option<String>,
    /// IPv4 subnet, private, /22 to /28 [default: the previous one, else the first free 10.77.x.0/24]
    #[arg(long)]
    subnet: Option<String>,
    /// wpa2 (default) or wpa3 (opt-in; support often cannot be verified). WEP and open are refused.
    #[arg(long, default_value = "wpa2")]
    security: String,
    /// Allow hotspot clients to reach the internet through another uplink of this machine
    /// (NetworkManager shared mode NATs them). Off by default.
    #[arg(long)]
    allow_internet_sharing: bool,
    /// [default: $XDG_CONFIG_HOME/lablink/config.yaml]
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum HotspotAction {
    /// What this machine can do: adapters, AP/WPA2/WPA3 support, NetworkManager
    /// permissions; on macOS, the guided Internet Sharing steps. Read-only.
    Capabilities {
        #[arg(long)]
        json: bool,
    },
    /// Check, without changing anything, whether starting is safe: what would
    /// disconnect, which devices would lose this machine, subnet conflicts.
    /// Exit 0 when it may start (perhaps with warnings), 7 when refused.
    Preflight {
        #[command(flatten)]
        args: StartArgs,
        #[arg(long)]
        json: bool,
    },
    /// Start the Field Network (or re-apply it when running).
    Start {
        #[command(flatten)]
        args: StartArgs,
        /// Accept the preflight warnings without asking.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Read the password from stdin (one line) instead of generating one.
        #[arg(long)]
        password_stdin: bool,
        /// Do not add or update the `field-network` site in the config.
        #[arg(long)]
        no_site: bool,
        #[arg(long)]
        json: bool,
    },
    /// Whether it runs, its settings and its clients.
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Devices on the Field Network and what LabLink knows about each:
    /// discovered-untrusted, registered, ssh-available, ssh-authenticated,
    /// ssh-unreachable, identity-mismatch, disconnected.
    Clients {
        #[arg(long)]
        json: bool,
    },
    /// Stop the Field Network and reconnect the adapter's previous network.
    Stop {
        /// Do not reconnect the previous network.
        #[arg(long)]
        no_restore: bool,
        #[arg(long)]
        json: bool,
    },
    /// Re-apply the running Field Network (after a password change).
    Restart {
        #[arg(long)]
        json: bool,
    },
    /// Print the password (read from NetworkManager), or set a new one.
    Password {
        /// Generate and store a new password (clients must rejoin after a restart).
        #[arg(long, conflicts_with = "stdin")]
        rotate: bool,
        /// Read a new password from stdin (one line) and store it.
        #[arg(long)]
        stdin: bool,
    },
    /// Delete LabLink's hotspot profile and password from NetworkManager.
    Forget {
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum FeatureAction {
    /// Optional features and whether they are on.
    List {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Turn a feature on (field-network, robotics).
    Enable {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Turn a feature off. Nothing is deleted.
    Disable {
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

pub fn json_mode(a: &HotspotAction) -> bool {
    matches!(
        a,
        HotspotAction::Capabilities { json: true }
            | HotspotAction::Preflight { json: true, .. }
            | HotspotAction::Start { json: true, .. }
            | HotspotAction::Status { json: true, .. }
            | HotspotAction::Clients { json: true }
            | HotspotAction::Stop { json: true, .. }
            | HotspotAction::Restart { json: true }
    )
}

pub(crate) fn config_path(p: Option<PathBuf>) -> PathBuf {
    p.unwrap_or_else(lablink_core::paths::default_config_path)
}

fn load(path: &Path) -> Result<lablink_core::Config, Fail> {
    configfile::load_or_default(path).map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))
}

fn fail(e: Error) -> Fail {
    match e {
        Error::Refused(m) => Fail::new(exit::REFUSED, "refused", m),
        Error::NotFound(m) => Fail::new(exit::FAILURE, "not_configured", m),
        Error::Failed(m) => Fail::new(exit::FAILURE, "hotspot_failed", m),
    }
}

fn require_feature(path: &Path) -> Result<lablink_core::Config, Fail> {
    let cfg = load(path)?;
    if !cfg.preferences.features.field_network {
        return Err(Fail::new(
            exit::REFUSED,
            "feature_disabled",
            "the Field Network is an optional feature and is off: turn it on with `lablink feature enable field-network`",
        ));
    }
    Ok(cfg)
}

fn state_dir() -> PathBuf {
    lablink_core::paths::default_state_dir()
}

fn read_secret_line() -> Result<String, Fail> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Fail::new(exit::FAILURE, "stdin", e.to_string()))?;
    let psk = line.trim_end_matches(['\n', '\r']).to_string();
    lablink_fieldnet::password::validate_user(&psk)
        .map_err(|e| Fail::new(exit::USAGE, "bad_request", format!("password {e}")))?;
    Ok(psk)
}

/// The networks of the other (non-roaming) sites, for subnet conflicts.
fn site_networks(cfg: &lablink_core::Config) -> Vec<(String, ipnet::Ipv4Net)> {
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

/// Registered devices this machine reaches now, from the daemon. `None`
/// when the daemon cannot be asked.
fn equipment(client: &Client) -> Option<Vec<Equipment>> {
    let r: StatusReport = client
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .ok()?;
    Some(
        r.devices
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

struct Planned {
    facts: lablink_fieldnet::host::HostFacts,
    pf: preflight::Preflight,
}

fn plan(
    sys: &dyn System,
    client: &Client,
    cfg: &lablink_core::Config,
    args: &StartArgs,
) -> Result<Planned, Fail> {
    let security =
        Security::parse(&args.security).map_err(|e| Fail::new(exit::USAGE, "bad_request", e))?;
    let old = lablink_fieldnet::state::load(&state_dir())
        .map_err(|e| Fail::new(exit::FAILURE, "state", e))?;
    let subnet = match &args.subnet {
        Some(s) => Some(s.parse().map_err(|_| {
            Fail::new(
                exit::USAGE,
                "bad_request",
                format!("'{s}' is not an IPv4 CIDR"),
            )
        })?),
        None => old.as_ref().and_then(|o| o.subnet.parse().ok()),
    };
    if let Some(i) = &args.interface {
        if !lablink_core::config::valid_interface(i) {
            return Err(Fail::new(
                exit::USAGE,
                "bad_request",
                format!("'{i}' is not an interface name"),
            ));
        }
    }
    let ssid = args
        .ssid
        .clone()
        .or_else(|| old.as_ref().map(|o| o.ssid.clone()))
        .unwrap_or_else(|| lablink_fieldnet::password::default_ssid(sys));
    let req = preflight::Request {
        interface: args.interface.clone(),
        ssid,
        subnet,
        security,
        allow_internet_sharing: args.allow_internet_sharing,
    };
    let facts = lablink_fieldnet::host::gather(sys);
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
            message: "lablinkd is not running, so LabLink cannot tell which registered devices use this link. Make sure no robot is moving or depending on it.".into(),
            override_flag: None,
        });
        pf.findings.sort_by_key(|f| f.level);
    }
    Ok(Planned { facts, pf })
}

fn print_findings(pf: &preflight::Preflight) {
    if let (Some(i), Some(n), Some(g)) = (&pf.interface, &pf.subnet, &pf.gateway) {
        println!(
            "Field Network '{}' on {i}: {n}, this machine {g}, {}",
            pf.ssid,
            pf.security.label()
        );
    }
    for f in &pf.findings {
        let tag = match f.level {
            Level::Block => "REFUSED",
            Level::Warn => "WARNING",
            Level::Info => "note",
        };
        match f.override_flag {
            Some(flag) => println!("  {tag}: {} (accept with {flag})", f.message),
            None => println!("  {tag}: {}", f.message),
        }
    }
}

fn confirm(pf: &preflight::Preflight, yes: bool) -> bool {
    if yes || !pf.needs_confirmation() {
        return true;
    }
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return false;
    }
    print!("Type 'start' to start the Field Network: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    answer.trim() == "start"
}

pub fn cmd_hotspot(client: &Client, action: HotspotAction) -> R {
    let sys = RealSystem;
    match action {
        HotspotAction::Capabilities { json } => {
            let c = lablink_fieldnet::capabilities(&sys);
            if json {
                print_json(&json!({ "schema_version": 1, "capabilities": c }));
            } else {
                print_capabilities(&c);
            }
            Ok(if c.can_host { exit::OK } else { exit::REFUSED })
        }
        HotspotAction::Preflight { args, json } => {
            let cfg = require_feature(&config_path(args.config.clone()))?;
            let p = plan(&sys, client, &cfg, &args)?;
            if json {
                print_json(
                    &json!({ "schema_version": 1, "preflight": p.pf, "may_start": !p.pf.blocked(), "needs_confirmation": p.pf.needs_confirmation() }),
                );
            } else {
                print_findings(&p.pf);
                println!(
                    "{}",
                    if p.pf.blocked() {
                        "Cannot start."
                    } else if p.pf.needs_confirmation() {
                        "May start after you accept the warnings (`lablink hotspot start`, or --yes)."
                    } else {
                        "May start."
                    }
                );
            }
            Ok(if p.pf.blocked() {
                exit::REFUSED
            } else {
                exit::OK
            })
        }
        HotspotAction::Start {
            args,
            yes,
            password_stdin,
            no_site,
            json,
        } => {
            let path = config_path(args.config.clone());
            let cfg = require_feature(&path)?;
            let psk = if password_stdin {
                Some(read_secret_line()?)
            } else {
                None
            };
            let p = plan(&sys, client, &cfg, &args)?;
            if !json {
                print_findings(&p.pf);
            }
            if p.pf.blocked() {
                return Err(fail(
                    nm::start(
                        &sys,
                        &state_dir(),
                        &p.facts,
                        &p.pf,
                        &nm::StartOptions {
                            psk: None,
                            confirmed: false,
                        },
                    )
                    .unwrap_err(),
                ));
            }
            let confirmed =
                !json && confirm(&p.pf, yes) || json && (yes || !p.pf.needs_confirmation());
            let r = nm::start(
                &sys,
                &state_dir(),
                &p.facts,
                &p.pf,
                &nm::StartOptions {
                    psk: psk.as_deref(),
                    confirmed,
                },
            )
            .map_err(fail)?;
            let site = if no_site {
                None
            } else {
                Some(update_field_site(&path, &r))
            };
            if json {
                print_json(&json!({ "schema_version": 1, "started": r, "site": site }));
            } else {
                println!(
                    "Field Network '{}' is up on {} ({}, {}). This machine is {}.",
                    r.ssid, r.interface, r.subnet, r.security, r.gateway
                );
                if let Some(prev) = &r.previous {
                    println!(
                        "'{}' is disconnected until `lablink hotspot stop`.",
                        prev.name
                    );
                }
                if r.ip_forward_after == Some(true) && r.ip_forward_before == Some(false) {
                    println!(
                        "NetworkManager turned on IPv4 forwarding for the hotspot (shared mode)."
                    );
                }
                println!("Show the password with `lablink hotspot password`; see who joined with `lablink hotspot clients`.");
                if let Some(s) = site {
                    println!("{s}");
                }
            }
            Ok(exit::OK)
        }
        HotspotAction::Status { json, config } => {
            require_feature(&config_path(config))?;
            let s = nm::status(&sys, &state_dir()).map_err(fail)?;
            if json {
                print_json(&json!({ "schema_version": 1, "status": s }));
            } else {
                print_status(&s);
            }
            Ok(exit::OK)
        }
        HotspotAction::Clients { json } => {
            require_feature(&config_path(None))?;
            let s = nm::status(&sys, &state_dir()).map_err(fail)?;
            if !s.active {
                return Err(Fail::new(
                    exit::REFUSED,
                    "not_running",
                    "the Field Network is not running",
                ));
            }
            let started = s.state.as_ref().and_then(|st| st.started_ms);
            let rows = classify_clients(client, &s.clients, started);
            if json {
                print_json(&json!({ "schema_version": 1, "clients": rows }));
            } else if rows.is_empty() {
                println!("no clients yet");
            } else {
                for r in &rows {
                    println!(
                        "{:<15}  {:<19}  {:<20}  {}{}",
                        r.ip,
                        crate::output::printable(r.mac.as_deref().unwrap_or("-")),
                        r.state,
                        crate::output::printable(
                            r.device.as_deref().or(r.hostname.as_deref()).unwrap_or("")
                        ),
                        if r.address_changed {
                            "  (address changed)"
                        } else {
                            ""
                        }
                    );
                }
                if rows.iter().any(|r| r.state == "discovered-untrusted") {
                    println!("\nUnknown clients are never trusted automatically: check one with `lablink inspect <ip>`, then `lablink adopt <ip> <name>`.");
                }
            }
            Ok(exit::OK)
        }
        HotspotAction::Stop { no_restore, json } => {
            require_feature(&config_path(None))?;
            let r = nm::stop(&sys, &state_dir(), !no_restore).map_err(fail)?;
            if json {
                print_json(&json!({ "schema_version": 1, "stopped": r }));
            } else {
                println!(
                    "{}",
                    if r.was_active {
                        "Field Network stopped."
                    } else {
                        "The Field Network was not running."
                    }
                );
                if let Some(m) = r.restored {
                    println!("{m}");
                }
            }
            Ok(exit::OK)
        }
        HotspotAction::Restart { json } => {
            require_feature(&config_path(None))?;
            nm::restart(&sys, &state_dir()).map_err(fail)?;
            if json {
                print_json(&json!({ "schema_version": 1, "restarted": true }));
            } else {
                println!("Field Network re-applied.");
            }
            Ok(exit::OK)
        }
        HotspotAction::Password { rotate, stdin } => {
            require_feature(&config_path(None))?;
            if rotate || stdin {
                let psk = if stdin {
                    read_secret_line()?
                } else {
                    lablink_fieldnet::password::generate(&sys)
                        .map_err(|e| Fail::new(exit::FAILURE, "random", e.to_string()))?
                };
                nm::set_new_password(&sys, &state_dir(), &psk).map_err(fail)?;
                println!("New password stored. Run `lablink hotspot restart` to apply it; clients must rejoin with `lablink hotspot password`.");
                return Ok(exit::OK);
            }
            let psk = nm::password(&sys, &state_dir()).map_err(fail)?;
            println!("{psk}");
            Ok(exit::OK)
        }
        HotspotAction::Forget { yes } => {
            require_feature(&config_path(None))?;
            if !yes {
                if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
                    return Err(Fail::new(
                        exit::REFUSED,
                        "refused",
                        "pass --yes to delete the hotspot profile and its password",
                    ));
                }
                print!(
                    "Delete LabLink's hotspot profile and its password from NetworkManager? [y/N] "
                );
                let _ = std::io::stdout().flush();
                let mut a = String::new();
                let _ = std::io::stdin().read_line(&mut a);
                if !matches!(a.trim(), "y" | "Y" | "yes") {
                    return Ok(exit::REFUSED);
                }
            }
            let removed = nm::forget(&sys, &state_dir()).map_err(fail)?;
            println!(
                "{}",
                if removed {
                    "Hotspot profile deleted."
                } else {
                    "There was no hotspot profile."
                }
            );
            Ok(exit::OK)
        }
    }
}

fn update_field_site(path: &Path, r: &nm::StartReport) -> String {
    let Ok(net) = r.subnet.parse::<ipnet::Ipv4Net>() else {
        return String::new();
    };
    let mut changed = false;
    match configfile::update(path, |cfg| {
        changed = lablink_fieldnet::field_site(cfg, &net, Some(&r.interface), Some(&r.ssid))?;
        if changed {
            Ok(())
        } else {
            Err("unchanged".into())
        }
    }) {
        Ok(_) => format!(
            "Field Network site set to {net} in {}. {}",
            path.display(),
            service::restart_if_active()
        ),
        Err(e) if e == "unchanged" => String::new(),
        Err(e) => format!("Could not update the field-network site: {e}"),
    }
}

#[derive(Debug, Serialize)]
struct ClientRow {
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    presence: lablink_fieldnet::clients::Presence,
    /// discovered-untrusted, registered, ssh-available, ssh-authenticated,
    /// ssh-unreachable, identity-mismatch or disconnected.
    state: &'static str,
    /// The registered device (`site/name`) at this address, proven by its
    /// pinned host key (never by name, MAC or address).
    device: Option<String>,
    address_changed: bool,
}

fn classify_clients(
    client: &Client,
    clients: &[lablink_fieldnet::clients::Client],
    started_ms: Option<u64>,
) -> Vec<ClientRow> {
    let status: Option<StatusReport> = client
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .ok();
    let devices = status.map(|s| s.devices).unwrap_or_default();
    let mut rows: Vec<ClientRow> = clients
        .iter()
        .map(|c| {
            let ip = c.ip.to_string();
            let d = devices
                .iter()
                .find(|d| d.ip.as_deref() == Some(ip.as_str()) && d.visiting.is_some());
            let state = match d {
                None => "discovered-untrusted",
                Some(d) if d.identity == IdentityState::Mismatch => "identity-mismatch",
                Some(d) if d.identity == IdentityState::Verified && d.ssh_auth == AuthState::Ok => {
                    "ssh-authenticated"
                }
                Some(d)
                    if d.identity == IdentityState::Verified && d.ssh_port == PortState::Open =>
                {
                    "ssh-available"
                }
                Some(d) if matches!(d.ssh_port, PortState::Closed | PortState::Filtered) => {
                    "ssh-unreachable"
                }
                Some(_) => "registered",
            };
            let address_changed = d.is_some_and(|d| changed_since(client, &d.id, started_ms));
            ClientRow {
                ip,
                mac: c.mac.clone(),
                hostname: c.hostname.clone(),
                presence: c.presence,
                state,
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
                presence: lablink_fieldnet::clients::Presence::Stale,
                state: "disconnected",
                device: Some(d.id.clone()),
                address_changed: false,
            });
        }
    }
    rows
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

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn print_capabilities(c: &lablink_fieldnet::Capabilities) {
    println!(
        "Field Network: {}",
        if c.can_host {
            "this machine can host one"
        } else {
            "this machine cannot host one"
        }
    );
    match &c.networkmanager {
        Some(nm) => println!(
            "NetworkManager {} ({}), network control: {}, checkpoint rollback: {}",
            nm.version,
            if nm.running { "running" } else { "not running" },
            yes_no(nm.allowed("network-control")),
            yes_no(c.checkpoint_rollback)
        ),
        None if c.backend != "macos-guided" => println!("NetworkManager: not found"),
        None => {}
    }
    for a in &c.adapters {
        println!(
            "  {} ({}): access point {}, WPA2 {}, WPA3 {}, 2.4 GHz {}, 5 GHz {}{}",
            a.interface,
            a.driver,
            yes_no(a.ap),
            yes_no(a.wpa2 && a.ccmp),
            match a.sae {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unverified",
            },
            yes_no(a.band_2ghz),
            yes_no(a.band_5ghz),
            if a.connection.is_empty() {
                String::new()
            } else {
                format!(
                    ", now connected to '{}'",
                    crate::output::printable(&a.connection)
                )
            }
        );
    }
    if c.single_adapter_in_use {
        println!("Only one capable adapter, and it is in use: its connection drops while the Field Network runs.");
    }
    for n in &c.notes {
        println!("note: {n}");
    }
    if let Some(m) = &c.macos {
        println!(
            "\nmacOS: LabLink cannot create a hotspot itself. To host one with Internet Sharing:"
        );
        for (i, s) in m.host_steps.iter().enumerate() {
            println!("  {}. {s}", i + 1);
        }
        if let Some(net) = &m.sharing_subnet {
            println!(
                "\nInternet Sharing is active on {net}. Add it as your Field Network site with:\n  lablink site add \"Field Network\" --id field-network --scan {net}   (then set `roaming: true` for it in the config)"
            );
        }
        println!("\nTo join a Field Network from this Mac:");
        for s in &m.join_steps {
            println!("  - {s}");
        }
        println!("\nLimits:");
        for s in &m.limits {
            println!("  - {s}");
        }
    }
}

fn print_status(s: &nm::Status) {
    let Some(st) = &s.state else {
        println!("No Field Network set up yet: `lablink hotspot preflight`, then `lablink hotspot start`.");
        return;
    };
    println!(
        "Field Network '{}': {}",
        st.ssid,
        if s.active { "running" } else { "stopped" }
    );
    if s.out_of_sync {
        println!(
            "  (it was {} outside LabLink)",
            if s.active { "started" } else { "stopped" }
        );
    }
    println!(
        "  adapter {}  subnet {}  this machine {}",
        st.interface,
        st.subnet,
        s.gateway.map(|g| g.to_string()).unwrap_or_default()
    );
    println!("  security {}", s.security.unwrap_or("?"));
    if let Some(p) = &st.previous {
        println!("  restores '{}' when stopped", p.name);
    }
    if let Some(f) = s.ip_forward {
        println!(
            "  IPv4 forwarding {}{}",
            if f { "on" } else { "off" },
            match st.ip_forward_before {
                Some(b) if b != f =>
                    format!(" (was {} before the hotspot)", if b { "on" } else { "off" }),
                _ => String::new(),
            }
        );
    }
    if s.active {
        println!(
            "  {} client(s) (details: `lablink hotspot clients`)",
            s.clients.len()
        );
    }
}

pub fn cmd_feature(action: FeatureAction) -> R {
    let names = lablink_core::config::Features::NAMES;
    match action {
        FeatureAction::List { json, config } => {
            let cfg = load(&config_path(config))?;
            let f = &cfg.preferences.features;
            if json {
                print_json(
                    &json!({ "schema_version": 1, "features": { "field-network": f.field_network, "robotics": f.robotics } }),
                );
            } else {
                for n in names {
                    println!(
                        "{n:<14} {}",
                        if f.get(n) == Some(true) { "on" } else { "off" }
                    );
                }
            }
            Ok(exit::OK)
        }
        FeatureAction::Enable { name, config } | FeatureAction::Disable { name, config }
            if !names.contains(&name.as_str()) =>
        {
            let _ = config;
            Err(Fail::new(
                exit::USAGE,
                "bad_request",
                format!("unknown feature '{name}' (features: {})", names.join(", ")),
            ))
        }
        FeatureAction::Enable { name, config } => set_feature(&name, true, config),
        FeatureAction::Disable { name, config } => set_feature(&name, false, config),
    }
}

fn set_feature(name: &str, on: bool, config: Option<PathBuf>) -> R {
    let path = config_path(config);
    let mut changed = false;
    configfile::update(&path, |cfg| {
        let f = &mut cfg.preferences.features;
        changed = f.get(name) != Some(on);
        f.set(name, on);
        Ok(())
    })
    .map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))?;
    println!(
        "{name} is {}{}",
        if on { "on" } else { "off" },
        if changed { "" } else { " (unchanged)" }
    );
    if on && name == "field-network" {
        println!("Next: `lablink hotspot capabilities`, then `lablink hotspot preflight`.");
    }
    Ok(exit::OK)
}
