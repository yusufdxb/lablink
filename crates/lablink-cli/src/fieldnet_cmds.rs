//! `lablink hotspot ...` (the Field Network) and `lablink feature ...`.
//!
//! The hotspot commands run on this machine through NetworkManager, not
//! through the daemon: the daemon has no privileges and no network-changing
//! API. They are opt-in (`lablink feature enable field-network`), except
//! the read-only `capabilities`. Every change is preceded by the read-only
//! preflight; warnings need `--yes` or a typed confirmation, and blockers
//! (such as cutting the SSH session that runs the command) refuse.

use crate::output::printable;
use crate::{print_json, Fail, R};
use clap::Subcommand;
use lablink_core::client::Client;
use lablink_core::exit;
use lablink_fieldnet::preflight::{self, Level};
use lablink_fieldnet::system::{RealSystem, System};
use lablink_fieldnet::{nm, ops, Error};
use lablink_setup::{configfile, service};
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
    /// Accept that hotspot clients can be routed to the other networks this machine reaches
    /// (VPN, containers, LAN): NetworkManager's shared mode turns on IPv4 forwarding. Off by
    /// default; without it such routes refuse the start.
    #[arg(long)]
    allow_routing: bool,
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

fn plan(
    sys: &dyn System,
    client: &Client,
    cfg: &lablink_core::Config,
    args: &StartArgs,
) -> Result<ops::Planned, Fail> {
    let a = ops::PlanArgs {
        interface: args.interface.clone(),
        ssid: args.ssid.clone(),
        subnet: args.subnet.clone(),
        security: args.security.clone(),
        allow_internet_sharing: args.allow_internet_sharing,
        allow_routing: args.allow_routing,
    };
    ops::plan(sys, client, cfg, &state_dir(), &a).map_err(|e| match e {
        ops::PlanError::BadRequest(m) => Fail::new(exit::USAGE, "bad_request", m),
        ops::PlanError::State(m) => Fail::new(exit::FAILURE, "state", m),
    })
}

fn print_findings(pf: &preflight::Preflight) {
    if let (Some(i), Some(n), Some(g)) = (&pf.interface, &pf.subnet, &pf.gateway) {
        println!(
            "Field Network '{}' on {i}: {n}, this machine {g}, {}",
            pf.ssid,
            pf.security.label()
        );
    }
    // Messages quote NetworkManager connection names, which can carry
    // whatever bytes a Wi-Fi network once advertised as its name.
    for f in &pf.findings {
        let tag = match f.level {
            Level::Block => "REFUSED",
            Level::Warn => "WARNING",
            Level::Info => "note",
        };
        let m = printable(&f.message);
        match f.override_flag {
            Some(flag) => println!("  {tag}: {m} (accept with {flag})"),
            None => println!("  {tag}: {m}"),
        }
    }
}

/// What a confirmation covers: every finding, by level, code and text.
fn findings_key(pf: &preflight::Preflight) -> Vec<(String, &'static str, String)> {
    pf.findings
        .iter()
        .map(|f| (format!("{:?}", f.level), f.code, f.message.clone()))
        .collect()
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
            let prompted = !json && !yes && p.pf.needs_confirmation();
            let confirmed =
                !json && confirm(&p.pf, yes) || json && (yes || !p.pf.needs_confirmation());
            // The answer may come minutes later: check again, and start only
            // if what the user accepted is still exactly what applies.
            let p = if confirmed && prompted {
                let again = plan(&sys, client, &cfg, &args)?;
                if findings_key(&again.pf) != findings_key(&p.pf) {
                    println!("\nThe checks changed while you were deciding:");
                    print_findings(&again.pf);
                    return Err(Fail::new(
                        exit::REFUSED,
                        "changed",
                        "not started: review the new checks and run `lablink hotspot start` again",
                    ));
                }
                again
            } else {
                p
            };
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
                        printable(&prev.name)
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
        // Status and stop work with the feature off, so turning it off
        // never strands a running network.
        HotspotAction::Status { json, config: _ } => {
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
            let rows = ops::classify_clients(client, &s.clients, started);
            if json {
                print_json(&json!({ "schema_version": 1, "clients": rows }));
            } else if rows.is_empty() {
                println!("no clients yet");
            } else {
                for r in &rows {
                    println!(
                        "{:<15}  {:<19}  {:<20}  {}{}{}",
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
                        },
                        if r.presence == lablink_fieldnet::clients::Presence::LeaseOnly {
                            "  (DHCP lease only: may have left)"
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
                    println!("{}", printable(&m));
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
    print!("{}", status_text(s));
}

/// What `hotspot status` prints, one line per fact.
fn status_text(s: &nm::Status) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let Some(st) = &s.state else {
        let _ = writeln!(o, "No Field Network set up yet: `lablink hotspot preflight`, then `lablink hotspot start`.");
        return o;
    };
    let _ = writeln!(
        o,
        "Field Network '{}': {}",
        printable(&st.ssid),
        if s.active { "running" } else { "stopped" }
    );
    if s.out_of_sync && s.active {
        // Also what an interrupted `lablink hotspot start` leaves behind.
        let _ = writeln!(o, "  (LabLink has no record of starting it: it was started elsewhere, or a LabLink start was interrupted, which NetworkManager rolls back within 2 minutes if LabLink took a checkpoint)");
    } else if s.out_of_sync {
        let _ = writeln!(o, "  (it was stopped outside LabLink)");
    }
    let _ = writeln!(
        o,
        "  adapter {}  subnet {}  this machine {}",
        st.interface,
        st.subnet,
        s.gateway.map(|g| g.to_string()).unwrap_or_default()
    );
    let _ = writeln!(o, "  security {}", s.security.unwrap_or("?"));
    if let (Some(p), true) = (&st.previous, s.active) {
        let _ = writeln!(o, "  restores '{}' when stopped", printable(&p.name));
    }
    if let Some(f) = s.ip_forward {
        let _ = writeln!(
            o,
            "  IPv4 forwarding {}{}",
            if f { "on" } else { "off" },
            match st.ip_forward_before {
                Some(b) if b != f =>
                    format!(" (was {} before the hotspot)", if b { "on" } else { "off" }),
                _ => String::new(),
            }
        );
    }
    if !s.uplinks.is_empty() {
        let _ = writeln!(o,
            "  WARNING: hotspot clients can reach the internet through {} (NetworkManager's shared mode NATs them). Stop the hotspot if that is not intended.",
            printable(&s.uplinks.join(", "))
        );
    }
    if !s.routed.is_empty() {
        let _ = writeln!(o,
            "  WARNING: hotspot clients can be routed to {} (NetworkManager's shared mode forwards and NATs them; LabLink does not change firewall rules). Stop the hotspot if that is not intended.",
            printable(&s.routed.join(", "))
        );
    }
    if s.active {
        let _ = writeln!(
            o,
            "  {} client(s) (details: `lablink hotspot clients`)",
            s.clients.len()
        );
    }
    o
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

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_fieldnet::state::{FieldState, Previous, Security};

    fn status(active: bool, recorded_active: bool) -> nm::Status {
        nm::Status {
            configured: true,
            active,
            out_of_sync: active != recorded_active,
            state: Some(FieldState {
                version: 1,
                profile_uuid: Some("u".into()),
                interface: "wlan0".into(),
                ssid: "LabLink-TEST".into(),
                subnet: "10.77.0.0/24".into(),
                security: Security::Wpa2,
                previous: Some(Previous {
                    uuid: "h".into(),
                    name: "home".into(),
                    device: "wlan0".into(),
                }),
                active: recorded_active,
                started_ms: None,
                ip_forward_before: Some(false),
            }),
            gateway: Some("10.77.0.1".parse().unwrap()),
            security: Some("WPA2-Personal (CCMP)"),
            ip_forward: Some(true),
            uplinks: Vec::new(),
            routed: Vec::new(),
            clients: Vec::new(),
        }
    }

    #[test]
    fn status_names_the_network_it_restores_only_while_running() {
        let t = status_text(&status(true, true));
        assert!(t.contains("'LabLink-TEST': running"), "{t}");
        assert!(t.contains("restores 'home' when stopped"), "{t}");
        assert!(
            t.contains("IPv4 forwarding on (was off before the hotspot)"),
            "{t}"
        );

        let t = status_text(&status(false, false));
        assert!(t.contains("': stopped"), "{t}");
        assert!(
            !t.contains("restores"),
            "nothing to restore while stopped: {t}"
        );
        assert!(!t.contains("outside LabLink"), "{t}");

        let t = status_text(&status(false, true));
        assert!(t.contains("(it was stopped outside LabLink)"), "{t}");
        assert!(!t.contains("restores"), "{t}");

        let t = status_text(&status(true, false));
        assert!(t.contains("a LabLink start was interrupted"), "{t}");
        assert!(t.contains("restores 'home'"), "{t}");
    }

    #[test]
    fn status_warns_about_late_routes_and_escapes_names() {
        let mut s = status(true, true);
        s.routed = vec!["100.64.0.0/10 (tailscale0)".into()];
        s.state.as_mut().unwrap().previous.as_mut().unwrap().name = "home\u{202e}x".into();
        let t = status_text(&s);
        assert!(
            t.contains("WARNING: hotspot clients can be routed to 100.64.0.0/10 (tailscale0)"),
            "{t}"
        );
        assert!(!t.contains('\u{202e}'), "bidi control escaped: {t}");
        assert!(status_text(&status(true, true))
            .lines()
            .all(|l| !l.contains("WARNING")));
    }
}
