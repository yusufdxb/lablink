//! `lablink`: command-line client for `lablinkd`.
//!
//! The CLI never discovers anything itself: every command asks the daemon,
//! which owns network state. Output is deterministic; every command that
//! returns data supports `--json`. Exit codes are documented in
//! `docs/AUTOMATION.md` and defined in `lablink_core::exit`.

mod complete;
mod output;
mod remote_cmds;
mod setup_cmds;

use clap::{Parser, Subcommand, ValueEnum};
use lablink_core::client::{Client, ClientError};
use lablink_core::exit;
use lablink_core::model::*;
use lablink_core::protocol::{DeviceChanges, ErrorCode, Request};
use lablink_ssh::{build_args, Mode, OutputMode};
use remote_cmds::TransportArg;
use serde_json::json;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "lablink", version, about = "LabLink: find lab machines and robots and SSH to them by name", long_about = None)]
struct Cli {
    /// Daemon socket [default: $LABLINK_SOCKET, else $XDG_RUNTIME_DIR/lablink/lablinkd.sock]
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Health of the devices at your current site, or of one device
    /// (`name` or `site/name`; the exit code reflects that device's color).
    Status {
        device: Option<String>,
        /// Only this site's devices.
        #[arg(long, conflicts_with = "all")]
        site: Option<String>,
        /// Every site's devices (AWAY sites are shown, never as failures).
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Full identity and health detail for the devices at your current site.
    Devices {
        /// Only this site's devices.
        #[arg(long, conflicts_with = "all")]
        site: Option<String>,
        /// Every site's devices.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Every site and whether you are there (ACTIVE, AWAY or UNKNOWN).
    Sites {
        #[arg(long)]
        json: bool,
    },
    /// The site you are at, the evidence for it, and site actions.
    Site {
        #[command(subcommand)]
        action: Option<SiteAction>,
        #[arg(long)]
        json: bool,
    },
    /// Full identity and health detail for one device.
    Inspect {
        device: String,
        #[arg(long)]
        json: bool,
    },
    /// Run staged discovery now and show the result.
    Discover {
        /// Deliberately scan one additional CIDR once (private, IPv4, <= /22 by default,
        /// and directly attached). Never added to the allowlist.
        #[arg(long, value_name = "CIDR")]
        scan_cidr: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Hosts seen on the network that are not tracked devices.
    Discovered {
        #[arg(long)]
        json: bool,
    },
    /// Connection history (state transitions only).
    History {
        device: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Print a device's current IP (e.g. `scp f user@$(lablink resolve jetson-a):`).
    Resolve {
        device: String,
        #[arg(long)]
        json: bool,
    },
    /// Open an interactive SSH session with the system OpenSSH client.
    Ssh {
        device: String,
        /// Login name (default: the one that last authenticated, else the first configured).
        #[arg(long, short = 'l')]
        user: Option<String>,
        /// Try even if the device is currently offline.
        #[arg(long)]
        force: bool,
        /// Do not print the connection line.
        #[arg(long, short)]
        quiet: bool,
        /// Which path to use: the LAN when it works, else Tailscale (only for
        /// devices with `remote:` in the config).
        #[arg(long, value_enum, default_value_t = TransportArg::Auto)]
        transport: TransportArg,
        /// Extra arguments passed to ssh after `--` (cannot override host-key checking).
        #[arg(last = true)]
        ssh_args: Vec<String>,
    },
    /// Run one command on a device; the remote exit code is preserved.
    Exec {
        device: String,
        /// Command line, interpreted by the remote login shell.
        command: String,
        #[arg(long, short = 'l')]
        user: Option<String>,
        /// Kill the command after this many seconds (exit 124).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        /// Capture output and print a JSON result.
        #[arg(long)]
        json: bool,
        /// Allow password/passphrase prompts on this terminal (disables BatchMode).
        #[arg(long)]
        interactive_auth: bool,
        /// Try even if the device is currently offline.
        #[arg(long)]
        force: bool,
        /// Which path to use (see `lablink ssh --help`).
        #[arg(long, value_enum, default_value_t = TransportArg::Auto)]
        transport: TransportArg,
    },
    /// Remote access over Tailscale: diagnostics and enrollment (read-only).
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
    /// Pin a device's current SSH host key after you have verified it.
    Trust {
        device: String,
        /// Pin without asking (only after verifying the fingerprint out of band).
        #[arg(long)]
        yes: bool,
        /// Replace existing pins (required after a legitimate reinstall).
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        json: bool,
    },
    /// Change runtime settings for a device (stored in the cache, not the config file).
    Set {
        device: String,
        /// Display label; empty string clears.
        #[arg(long)]
        label: Option<String>,
        /// SSH login name; empty string clears.
        #[arg(long)]
        user: Option<String>,
        /// on|off
        #[arg(long, value_parser = parse_on_off)]
        monitoring: Option<bool>,
        #[arg(long)]
        notes: Option<String>,
        /// generic_linux, jetson, gpu_workstation, ros2_host, network_only, or none.
        #[arg(long, value_parser = parse_profile_or_none)]
        profile: Option<String>,
        /// on|off: whether LabLink uses SSH on this device (adopted devices only).
        #[arg(long, value_parser = parse_on_off)]
        ssh: Option<bool>,
        /// Re-run the SSH login check now.
        #[arg(long, hide = true)]
        recheck: bool,
        #[arg(long)]
        json: bool,
    },
    /// Start tracking a discovered host under a logical name (never pins its host key).
    Adopt {
        ip: String,
        name: String,
        /// Display label.
        #[arg(long)]
        label: Option<String>,
        /// SSH login name.
        #[arg(long)]
        user: Option<String>,
        /// generic_linux, jetson, gpu_workstation, ros2_host or network_only.
        #[arg(long, value_parser = parse_profile)]
        profile: Option<String>,
        /// The host has no SSH server LabLink should use (robots, PLCs, switches).
        #[arg(long)]
        no_ssh: bool,
        /// Site the device belongs to [default: the site of its network, else the active site]
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Daemon resource usage and activity counters.
    Metrics {
        #[arg(long)]
        json: bool,
    },
    /// Check that the daemon is running.
    Ping {
        #[arg(long)]
        json: bool,
    },
    /// Read-only health checks (SSH, GPU, disk, ROS 2, DDS, reachability) of lab machines.
    /// Exit 0 when every device is GREEN, else 10 (yellow), 12 (gray) or 11 (red).
    /// Devices of AWAY sites never count as failures.
    Doctor {
        /// Devices to check (`name` or `site/name`) [default: the current site's devices
        /// with checks or a profile, else all its monitored devices]
        devices: Vec<String>,
        /// Check this site's devices.
        #[arg(long, conflicts_with = "all")]
        site: Option<String>,
        /// Check every site's devices.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        /// Overall time limit per device, in seconds.
        #[arg(long, default_value_t = 25)]
        timeout: u64,
        /// Config file holding the `checks:` section [default: $XDG_CONFIG_HOME/lablink/config.yaml]
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Validate a configuration file.
    CheckConfig {
        /// [default: $XDG_CONFIG_HOME/lablink/config.yaml]
        path: Option<PathBuf>,
    },
    /// First-run setup: name your site, choose networks, write the config, start the
    /// service, install completion. Run it again with --force at another site to add that site.
    Init {
        /// Name of the place you are setting up (e.g. "Robotics Lab").
        #[arg(long, value_name = "NAME")]
        site: Option<String>,
        /// Allow a network for passive monitoring (CIDR or NAME=CIDR); repeatable.
        #[arg(long = "network", value_name = "CIDR")]
        networks: Vec<String>,
        /// Allow a network and active scanning on it (private, at most /22); repeatable.
        #[arg(long = "scan", value_name = "CIDR")]
        scan: Vec<String>,
        /// Ask nothing; use only the options given (no networks unless --network/--scan).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Do not install or start the systemd user service.
        #[arg(long)]
        no_service: bool,
        /// Do not install bash completion.
        #[arg(long)]
        no_completions: bool,
        /// Replace an existing configuration (the old file is kept as a backup).
        #[arg(long)]
        force: bool,
        /// [default: $XDG_CONFIG_HOME/lablink/config.yaml]
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Version of this CLI and of the running daemon.
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Install your SSH public key on a device whose host key is pinned (runs ssh-copy-id).
    CopyId {
        device: String,
        #[arg(long, short = 'l')]
        user: Option<String>,
        /// Public key to install [default: ~/.ssh/id_ed25519.pub, id_ecdsa.pub, id_rsa.pub]
        #[arg(long, short = 'i')]
        identity: Option<PathBuf>,
    },
    /// Write a portable copy of the configuration and devices (no keys, passwords or secrets).
    Export {
        /// Write to this file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        /// Leave pinned host-key fingerprints out.
        #[arg(long)]
        no_fingerprints: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Merge an export into this machine's configuration (shows the changes first).
    Import {
        file: PathBuf,
        /// Also pin the host keys listed in the file (only for files you made yourself).
        #[arg(long)]
        trust_pins: bool,
        /// Also take service-check commands (shell commands run on devices) from the file.
        #[arg(long)]
        allow_commands: bool,
        /// Replace existing entries with the same name, and the daemon settings.
        #[arg(long)]
        replace: bool,
        /// Apply without asking.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Show what would change and write nothing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create a sanitized diagnostic archive for bug reports.
    SupportBundle {
        /// Directory for the archive [default: current directory]
        #[arg(long, short = 'o')]
        output_dir: Option<PathBuf>,
        /// Skip the read-only doctor run.
        #[arg(long)]
        no_doctor: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Install lablinkd as a systemd user service (runs as you, no root).
    InstallService {
        /// Print the unit file instead of installing it.
        #[arg(long)]
        print: bool,
        /// Write the unit but do not enable/start it.
        #[arg(long)]
        no_enable: bool,
        /// With --print: the daemon path to put in the unit (packaging).
        #[arg(long, hide = true)]
        daemon_path: Option<PathBuf>,
    },
    /// Stop, disable and remove the systemd user service.
    UninstallService,
    /// Print the shell completion script to stdout.
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Install shell completion for the current user (no root needed).
    InstallCompletions,
    /// Internal: print completion candidates (used by the completion script).
    #[command(hide = true, name = "__complete")]
    Complete {
        #[arg(long)]
        cword: Option<usize>,
        #[arg(last = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Shell {
    Bash,
}

#[derive(Subcommand, Debug)]
enum SiteAction {
    /// Use this site from now on (manual override), or `auto` to detect it again.
    Use {
        /// Site id, or `auto`.
        site: String,
    },
    /// Create a site for where you are now (records the attached networks'
    /// gateway and Wi-Fi name so LabLink can recognize the place later).
    Add {
        /// Display name, e.g. "Makerspace".
        name: String,
        /// Site id used in `site/device` references [default: derived from the name]
        #[arg(long)]
        id: Option<String>,
        /// Allow a network for passive monitoring (CIDR or NAME=CIDR); repeatable.
        #[arg(long = "network", value_name = "CIDR")]
        networks: Vec<String>,
        /// Allow a network and active scanning on it (private, at most /22); repeatable.
        #[arg(long = "scan", value_name = "CIDR")]
        scan: Vec<String>,
        /// Only use this site when chosen by hand, never by automatic detection.
        #[arg(long)]
        no_auto_detect: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Change a site's display name.
    Rename {
        site: String,
        name: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn parse_profile(s: &str) -> Result<String, String> {
    lablink_core::profile::Profile::parse(s)
        .map(|p| p.as_str().to_string())
        .ok_or_else(|| {
            let names: Vec<&str> = lablink_core::profile::Profile::ALL
                .iter()
                .map(|p| p.as_str())
                .collect();
            format!("expected one of: {}", names.join(", "))
        })
}

fn parse_profile_or_none(s: &str) -> Result<String, String> {
    if s == "none" || s.is_empty() {
        Ok(String::new())
    } else {
        parse_profile(s)
    }
}

fn parse_on_off(s: &str) -> Result<bool, String> {
    match s {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err("expected on or off".into()),
    }
}

#[derive(Subcommand, Debug)]
enum RemoteAction {
    /// This machine's Tailscale state and, for a device, every path `ssh`
    /// would try (TCP and host-key checks only; never logs in).
    Status {
        device: Option<String>,
        #[arg(long, value_enum, default_value_t = TransportArg::Auto)]
        transport: TransportArg,
        #[arg(long)]
        json: bool,
    },
    /// What this machine needs for remote access, and the config snippet
    /// other machines use to reach it. Changes nothing.
    Setup {
        #[arg(long)]
        json: bool,
    },
}

/// A failure with its exit code.
struct Fail {
    code: i32,
    kind: &'static str,
    message: String,
    /// For an ambiguous device name: what it could mean.
    candidates: Vec<lablink_core::protocol::Candidate>,
}

impl Fail {
    fn new(code: i32, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            candidates: Vec::new(),
        }
    }
}

impl From<ClientError> for Fail {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Unavailable { path, source } => Fail::new(
                exit::DAEMON_UNAVAILABLE,
                "daemon_unavailable",
                format!("lablinkd is not running (socket {path}: {source}). Start it with `systemctl --user start lablinkd` or run `lablinkd`."),
            ),
            ClientError::Protocol(m) => Fail::new(exit::FAILURE, "protocol", m),
            ClientError::Api(a) => {
                let kind = match a.code {
                    ErrorCode::BadRequest => "bad_request",
                    ErrorCode::DeviceNotFound => "device_not_found",
                    ErrorCode::Unreachable => "unreachable",
                    ErrorCode::IdentityMismatch => "identity_mismatch",
                    ErrorCode::Refused => "refused",
                    ErrorCode::Conflict => "conflict",
                    ErrorCode::Busy => "busy",
                    ErrorCode::Internal => "internal",
                    ErrorCode::Ambiguous => "ambiguous",
                };
                let mut f = Fail::new(a.code.exit_code(), kind, a.message);
                f.candidates = a.candidates;
                f
            }
        }
    }
}

type R = Result<i32, Fail>;

fn print_json<T: serde::Serialize>(v: &T) {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    let _ = std::io::stdout().write_all(s.as_bytes());
}

fn color_exit(c: Color) -> i32 {
    match c {
        Color::Green => exit::OK,
        Color::Yellow => exit::STATUS_YELLOW,
        Color::Red => exit::STATUS_RED,
        Color::Gray => exit::STATUS_GRAY,
    }
}

fn main() {
    // Behave like a normal Unix filter: `lablink status | head` must not panic.
    // SAFETY: restoring the default disposition of SIGPIPE before any I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Completion must never fail loudly, so it bypasses clap's error output.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "__complete")
    {
        complete::entry(
            std::env::args_os()
                .skip(2)
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
        );
        std::process::exit(0);
    }
    let cli = Cli::parse();
    let socket = cli
        .socket
        .clone()
        .unwrap_or_else(lablink_core::paths::default_socket_path);
    let client = Client::new(&socket);
    let command = command_name(&cli.cmd);
    let json_mode = matches!(
        &cli.cmd,
        Cmd::Status { json: true, .. }
            | Cmd::Devices { json: true, .. }
            | Cmd::Sites { json: true }
            | Cmd::Site { json: true, .. }
            | Cmd::Inspect { json: true, .. }
            | Cmd::Discover { json: true, .. }
            | Cmd::Discovered { json: true }
            | Cmd::History { json: true, .. }
            | Cmd::Resolve { json: true, .. }
            | Cmd::Exec { json: true, .. }
            | Cmd::Trust { json: true, .. }
            | Cmd::Set { json: true, .. }
            | Cmd::Adopt { json: true, .. }
            | Cmd::Metrics { json: true }
            | Cmd::Ping { json: true }
            | Cmd::Doctor { json: true, .. }
            | Cmd::Version { json: true }
            | Cmd::Remote {
                action: RemoteAction::Status { json: true, .. }
                    | RemoteAction::Setup { json: true }
            }
    );
    let code = match run(cli, &client) {
        Ok(c) => c,
        Err(f) => {
            if json_mode {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "status": "lablink_error",
                    "exit_code": f.code,
                    "error": { "code": f.kind, "message": f.message, "candidates": f.candidates },
                }));
            }
            let api = lablink_core::protocol::ApiError {
                code: ErrorCode::Ambiguous,
                message: f.message.clone(),
                candidates: f.candidates.clone(),
            };
            match api.ambiguity_text(command) {
                Some(t) => eprint!("{t}"),
                None => eprintln!("lablink: {}", f.message),
            }
            f.code
        }
    };
    std::process::exit(code);
}

/// The subcommand's name, for messages that suggest a command line.
fn command_name(c: &Cmd) -> &'static str {
    match c {
        Cmd::Status { .. } => "status",
        Cmd::Devices { .. } => "devices",
        Cmd::Sites { .. } => "sites",
        Cmd::Site { .. } => "site",
        Cmd::Inspect { .. } => "inspect",
        Cmd::Discover { .. } => "discover",
        Cmd::Discovered { .. } => "discovered",
        Cmd::History { .. } => "history",
        Cmd::Resolve { .. } => "resolve",
        Cmd::Ssh { .. } => "ssh",
        Cmd::Exec { .. } => "exec",
        Cmd::Remote { .. } => "remote",
        Cmd::Trust { .. } => "trust",
        Cmd::Set { .. } => "set",
        Cmd::Adopt { .. } => "adopt",
        Cmd::Metrics { .. } => "metrics",
        Cmd::Ping { .. } => "ping",
        Cmd::Doctor { .. } => "doctor",
        Cmd::CheckConfig { .. } => "check-config",
        Cmd::Init { .. } => "init",
        Cmd::Version { .. } => "version",
        Cmd::CopyId { .. } => "copy-id",
        Cmd::Export { .. } => "export",
        Cmd::Import { .. } => "import",
        Cmd::SupportBundle { .. } => "support-bundle",
        Cmd::InstallService { .. } => "install-service",
        Cmd::UninstallService => "uninstall-service",
        Cmd::Completions { .. } => "completions",
        Cmd::InstallCompletions => "install-completions",
        Cmd::Complete { .. } => "__complete",
    }
}

fn run(cli: Cli, client: &Client) -> R {
    let socket = client.socket_path().to_path_buf();
    match cli.cmd {
        Cmd::Status {
            device,
            site,
            all,
            json,
        } => {
            let r: StatusReport = client.call_typed(&Request::Status {
                device: device.clone(),
                site: site.clone(),
                all,
            })?;
            if json {
                print_json(&r);
            } else {
                let multi = r.sites.len() > 1;
                if device.is_none() {
                    print!("{}", output::scope_header(&r, site.as_deref(), all));
                }
                if !r.devices.is_empty() {
                    print!("{}", output::status_table(&r.devices));
                }
                if device.is_some() {
                    for d in &r.devices {
                        for reason in &d.reasons {
                            println!("  - {reason}");
                        }
                        if let Some(e) = lablink_core::explain::explain(d) {
                            println!();
                            print!("{}", lablink_core::explain::render_text(&e));
                        }
                    }
                } else if r.devices.is_empty() {
                    if r.sites.iter().all(|s| s.devices.total == 0) {
                        println!(
                            "no devices yet: run `lablink discover`, then `lablink adopt <ip> <name>`"
                        );
                    }
                } else if std::io::stdout().is_terminal()
                    && r.devices.iter().any(|d| {
                        d.color != Color::Green
                            && d.site_state != lablink_core::site::SiteState::Away
                    })
                {
                    println!(
                        "\n`lablink status <device>` explains what is wrong and what to do next."
                    );
                }
                if device.is_none() && multi && site.is_none() && !all {
                    print!("{}", output::other_sites(&r));
                }
            }
            Ok(match (&device, r.devices.first()) {
                (Some(_), Some(d)) => color_exit(d.color),
                _ => exit::OK,
            })
        }
        Cmd::Devices { site, all, json } => {
            let v = client.call(&Request::Devices { site, all })?;
            if json {
                print_json(&v);
            } else {
                let devices: Vec<DeviceDetail> = serde_json::from_value(v["devices"].clone())
                    .map_err(|e| Fail::new(exit::FAILURE, "protocol", e.to_string()))?;
                if devices.is_empty() {
                    println!(
                        "no devices configured (add them to {})",
                        lablink_core::paths::default_config_path().display()
                    );
                }
                for (i, d) in devices.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    print!("{}", output::device_detail(d));
                }
            }
            Ok(exit::OK)
        }
        Cmd::Inspect { device, json } => {
            let d: DeviceDetail = client.call_typed(&Request::Inspect { device })?;
            if json {
                print_json(&d);
            } else {
                print!("{}", output::device_detail(&d));
            }
            Ok(exit::OK)
        }
        Cmd::Discover { scan_cidr, json } => {
            if !json && std::io::stderr().is_terminal() {
                eprintln!("lablink: running staged discovery (this can take up to a minute)...");
            }
            let c = client.clone().with_timeout(Duration::from_secs(150));
            let r: DiscoverReport = c.call_typed(&Request::Discover { scan_cidr })?;
            if json {
                print_json(&r);
            } else {
                let rows: Vec<Vec<String>> = r
                    .stages
                    .iter()
                    .map(|s| {
                        vec![
                            s.stage.clone(),
                            s.result.to_uppercase(),
                            format!("{} ms", s.duration_ms),
                            s.detail.clone(),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    output::table(&["STAGE", "RESULT", "TIME", "DETAIL"], &rows)
                );
                println!();
                print!("{}", output::status_table(&r.devices));
                if !r.discovered.is_empty() {
                    println!("\nunmatched hosts (adopt with `lablink adopt <ip> <name>`):");
                    print!("{}", output::discovered_table(&r.discovered));
                }
            }
            Ok(exit::OK)
        }
        Cmd::Discovered { json } => {
            let v = client.call(&Request::Discovered)?;
            if json {
                print_json(&v);
            } else {
                let hosts: Vec<DiscoveredHost> = serde_json::from_value(v["discovered"].clone())
                    .map_err(|e| Fail::new(exit::FAILURE, "protocol", e.to_string()))?;
                if hosts.is_empty() {
                    println!("no unmatched hosts");
                } else {
                    print!("{}", output::discovered_table(&hosts));
                }
            }
            Ok(exit::OK)
        }
        Cmd::History {
            device,
            limit,
            json,
        } => {
            let v = client.call(&Request::History {
                device: device.clone(),
                limit,
            })?;
            if json {
                print_json(&v);
            } else {
                let events: Vec<HistoryEvent> = serde_json::from_value(v["events"].clone())
                    .map_err(|e| Fail::new(exit::FAILURE, "protocol", e.to_string()))?;
                print!("{}", output::history_lines(&events, device.is_none()));
            }
            Ok(exit::OK)
        }
        Cmd::Resolve { device, json } => {
            let r: ResolveResult = client.call_typed(&Request::Resolve { device })?;
            if json {
                print_json(&r);
            } else {
                println!("{}", r.ip);
            }
            Ok(exit::OK)
        }
        Cmd::Ssh {
            device,
            user,
            force,
            quiet,
            transport,
            ssh_args,
        } => cmd_ssh(client, &device, user, force, quiet, transport, &ssh_args),
        Cmd::Exec {
            device,
            command,
            user,
            timeout,
            json,
            interactive_auth,
            force,
            transport,
        } => cmd_exec(
            client,
            &device,
            &command,
            user,
            timeout,
            json,
            interactive_auth,
            force,
            transport,
        ),
        Cmd::Remote {
            action:
                RemoteAction::Status {
                    device,
                    transport,
                    json,
                },
        } => remote_cmds::cmd_status(client, device, transport, json),
        Cmd::Remote {
            action: RemoteAction::Setup { json },
        } => remote_cmds::cmd_setup(json),
        Cmd::Trust {
            device,
            yes,
            replace,
            json,
        } => cmd_trust(client, &device, yes, replace, json),
        Cmd::Set {
            device,
            label,
            user,
            monitoring,
            notes,
            profile,
            ssh,
            recheck,
            json,
        } => {
            let s: DeviceStatus = client.call_typed(&Request::Set {
                device,
                changes: DeviceChanges {
                    label,
                    username: user,
                    monitoring,
                    notes,
                    profile,
                    ssh,
                    recheck,
                },
            })?;
            if json {
                print_json(&s);
            } else {
                print!("{}", output::status_table(std::slice::from_ref(&s)));
            }
            Ok(exit::OK)
        }
        Cmd::Sites { json } => {
            let r: lablink_core::site::SitesReport = client.call_typed(&Request::Sites)?;
            if json {
                print_json(&r);
            } else {
                print!("{}", output::sites_table(&r));
            }
            Ok(exit::OK)
        }
        Cmd::Site { action: None, json } => {
            let r: lablink_core::site::SitesReport = client.call_typed(&Request::Sites)?;
            if json {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "mode": r.mode,
                    "active": r.active(),
                    "sites": r.sites,
                    "signals": r.signals,
                }));
            } else {
                print!("{}", output::site_detail(&r));
            }
            Ok(exit::OK)
        }
        Cmd::Site {
            action: Some(SiteAction::Use { site }),
            json,
        } => {
            let want = (!site.eq_ignore_ascii_case("auto")).then_some(site);
            let r: lablink_core::site::SitesReport =
                client.call_typed(&Request::SetSiteMode { site: want })?;
            if json {
                print_json(&r);
            } else {
                print!("{}", output::sites_table(&r));
            }
            Ok(exit::OK)
        }
        Cmd::Site {
            action:
                Some(SiteAction::Add {
                    name,
                    id,
                    networks,
                    scan,
                    no_auto_detect,
                    config,
                }),
            ..
        } => setup_cmds::cmd_site_add(&name, id, networks, scan, no_auto_detect, config),
        Cmd::Site {
            action: Some(SiteAction::Rename { site, name, config }),
            ..
        } => setup_cmds::cmd_site_rename(&site, &name, config),
        Cmd::Adopt {
            ip,
            name,
            label,
            user,
            profile,
            no_ssh,
            site,
            json,
        } => {
            let s: DeviceStatus = client.call_typed(&Request::Adopt {
                ip,
                name,
                label,
                username: user,
                profile,
                ssh: no_ssh.then_some(false),
                site,
            })?;
            if json {
                print_json(&s);
            } else {
                print!("{}", output::status_table(std::slice::from_ref(&s)));
                println!("site: {} ({})", s.site_name, s.site);
                if s.ssh_port == PortState::Disabled {
                    println!("tracking {} on the network only (no SSH)", s.name);
                } else {
                    println!(
                        "next: compare and pin its host key with `lablink trust {}`",
                        s.name
                    );
                }
            }
            Ok(exit::OK)
        }
        Cmd::Metrics { json } => {
            let m: MetricsReport = client.call_typed(&Request::Metrics)?;
            if json {
                print_json(&m);
            } else {
                let o = |v: Option<u64>| v.map(|x| x.to_string()).unwrap_or_else(|| "?".into());
                println!(
                    "lablinkd {} pid {} up {}s",
                    m.daemon.version, m.daemon.pid, m.daemon.uptime_s
                );
                println!(
                    "rss {} KiB, threads {}, fds {}, cpu user {} ms / sys {} ms",
                    o(m.rss_kib),
                    o(m.threads),
                    o(m.open_fds),
                    o(m.cpu_user_ms),
                    o(m.cpu_system_ms)
                );
                println!(
                    "tokio tasks {}, monitored devices {}",
                    m.tokio_alive_tasks, m.monitored_devices
                );
                for (k, v) in &m.counters {
                    println!("  {k:<22} {v}");
                }
            }
            Ok(exit::OK)
        }
        Cmd::Ping { json } => {
            let v = client.call(&Request::Ping)?;
            if json {
                print_json(&v);
            } else {
                println!(
                    "lablinkd {} (pid {}, up {}s) at {}",
                    v["version"].as_str().unwrap_or("?"),
                    v["pid"],
                    v["uptime_s"],
                    client.socket_path().display()
                );
            }
            Ok(exit::OK)
        }
        Cmd::Doctor {
            devices,
            site,
            all,
            json,
            timeout,
            config,
        } => {
            if timeout == 0 {
                return Err(Fail::new(
                    exit::USAGE,
                    "bad_request",
                    "--timeout must be at least 1 second",
                ));
            }
            let explicit = config.is_some();
            let path = config.unwrap_or_else(lablink_core::paths::default_config_path);
            let checks = match lablink_core::Config::load(&path) {
                Ok(c) => c.checks_by_id(),
                // No config at the default location: implicit checks only.
                Err(lablink_core::config::ConfigError::Io { .. }) if !explicit => {
                    Default::default()
                }
                Err(e) => return Err(Fail::new(exit::USAGE, "invalid_config", e.to_string())),
            };
            let opts = lablink_doctor::Options {
                devices,
                timeout: Duration::from_secs(timeout),
                site,
                all,
            };
            let report = lablink_doctor::run(client, &checks, &opts).map_err(|e| match e {
                lablink_doctor::DoctorError::Client(c) => Fail::from(c),
                lablink_doctor::DoctorError::UnknownDevice(n) => Fail::new(
                    exit::DEVICE_NOT_FOUND,
                    "device_not_found",
                    format!("unknown device '{n}'"),
                ),
                lablink_doctor::DoctorError::NoDevices => Fail::new(
                    exit::USAGE,
                    "bad_request",
                    "no devices to check at the current site: name devices, use --site or --all, add `checks:` to a site in the config, or monitor a device",
                ),
            })?;
            if json {
                print_json(&report);
            } else {
                print!(
                    "{}",
                    lablink_doctor::render_human(&report, output::use_color())
                );
            }
            Ok(report.exit_code())
        }
        Cmd::CheckConfig { path } => {
            let p = path.unwrap_or_else(lablink_core::paths::default_config_path);
            match lablink_core::Config::load(&p) {
                Ok(c) => {
                    println!(
                        "{}: OK ({} sites, {} networks, {} devices)",
                        p.display(),
                        c.sites.len(),
                        c.network_count(),
                        c.device_count()
                    );
                    let legacy = std::fs::read_to_string(&p)
                        .map(|t| lablink_core::config::uses_legacy_layout(&t))
                        .unwrap_or(false);
                    if legacy {
                        println!("  note: single-site layout, read as site '{}' ('{}'); LabLink writes the `sites:` layout the next time it saves this file", lablink_core::config::DEFAULT_SITE_ID, lablink_core::config::DEFAULT_SITE_NAME);
                    }
                    for site in &c.sites {
                        println!(
                            "  site {:<16} {}{}",
                            site.id,
                            site.name,
                            if site.auto_detect {
                                ""
                            } else {
                                "  (manual only)"
                            }
                        );
                        if site.networks.is_empty() && c.sites.len() > 1 && site.auto_detect {
                            println!("    warning: no networks, so automatic detection can only pick this site from its devices' MACs or host keys");
                        }
                        for n in &site.networks {
                            println!(
                                "    network {:<14} {:<20} {}",
                                n.name,
                                n.cidr,
                                if n.active_scan {
                                    "active scan"
                                } else {
                                    "passive only"
                                }
                            );
                        }
                        for (dev, specs) in &site.checks {
                            let known = site.device(dev).is_some();
                            println!(
                                "    checks {:<15} {} check(s){}",
                                dev,
                                specs.len(),
                                if known {
                                    ""
                                } else {
                                    "  (warning: not in devices; fine only for an adopted device)"
                                }
                            );
                        }
                    }
                    Ok(exit::OK)
                }
                Err(e) => Err(Fail::new(exit::USAGE, "invalid_config", e.to_string())),
            }
        }
        Cmd::InstallService {
            print,
            no_enable,
            daemon_path,
        } => {
            use lablink_setup::service;
            let svc = |e| Fail::new(exit::FAILURE, "service", e);
            if print {
                let daemon = match daemon_path {
                    Some(p) => p,
                    None => service::find_daemon().map_err(svc)?,
                };
                print!("{}", service::unit_text(&daemon));
                return Ok(exit::OK);
            }
            for line in service::install(!no_enable).map_err(svc)? {
                println!("{line}");
            }
            Ok(exit::OK)
        }
        Cmd::UninstallService => {
            for line in lablink_setup::service::uninstall()
                .map_err(|e| Fail::new(exit::FAILURE, "service", e))?
            {
                println!("{line}");
            }
            Ok(exit::OK)
        }
        Cmd::Init {
            site,
            networks,
            scan,
            yes,
            no_service,
            no_completions,
            force,
            config,
        } => setup_cmds::cmd_init(
            &socket,
            site,
            networks,
            scan,
            yes,
            no_service,
            no_completions,
            force,
            config,
        ),
        Cmd::Version { json } => setup_cmds::cmd_version(client, json),
        Cmd::CopyId {
            device,
            user,
            identity,
        } => setup_cmds::cmd_copy_id(client, &device, user, identity),
        Cmd::Export {
            output,
            no_fingerprints,
            config,
        } => setup_cmds::cmd_export(client, output, no_fingerprints, config),
        Cmd::Import {
            file,
            trust_pins,
            allow_commands,
            replace,
            yes,
            dry_run,
            config,
        } => setup_cmds::cmd_import(
            &file,
            lablink_setup::export::ImportOptions {
                trust_pins,
                allow_commands,
                replace,
            },
            yes,
            dry_run,
            config,
        ),
        Cmd::SupportBundle {
            output_dir,
            no_doctor,
            config,
        } => setup_cmds::cmd_support_bundle(&socket, output_dir, no_doctor, config),
        Cmd::Completions { shell: Shell::Bash } => {
            print!("{}", complete::bash_script());
            Ok(exit::OK)
        }
        Cmd::InstallCompletions => {
            complete::install().map_err(|e| Fail::new(exit::FAILURE, "completions", e))
        }
        Cmd::Complete { .. } => Ok(exit::OK),
    }
}

/// How to name the resolved device: `site/name` when another site has a
/// device of the same name (so the user sees which one was chosen).
fn shown(r: &ResolveResult) -> String {
    if r.shared_name && !r.id.is_empty() {
        r.id.clone()
    } else {
        r.name.clone()
    }
}

fn describe_identity(p: &remote_cmds::Planned) -> &'static str {
    if p.pinned {
        "host key pinned by LabLink"
    } else {
        "host key NOT pinned: OpenSSH's own known_hosts policy applies"
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_ssh(
    client: &Client,
    device: &str,
    user: Option<String>,
    force: bool,
    quiet: bool,
    transport: TransportArg,
    extra: &[String],
) -> R {
    use std::os::unix::process::CommandExt;
    let p = remote_cmds::plan(client, device, user, force, transport)?;
    let t = &p.target;
    let args = build_args(t, &Mode::Interactive, extra);
    if !quiet {
        let who = t
            .username
            .as_deref()
            .map(|u| format!("{u}@"))
            .unwrap_or_default();
        let via = if p.via_daemon {
            String::new()
        } else {
            format!(" via {}", p.transport.as_str())
        };
        eprintln!(
            "lablink: {} -> {who}{}:{}{via} ({})",
            p.shown,
            p.ip,
            p.port,
            describe_identity(&p)
        );
        for n in &p.notes {
            eprintln!("lablink: note: {n}");
        }
    }
    let err = std::process::Command::new(&t.binary).args(&args).exec();
    Err(Fail::new(
        exit::FAILURE,
        "exec",
        format!("cannot run {}: {err}", t.binary),
    ))
}

#[allow(clippy::too_many_arguments)]
fn cmd_exec(
    client: &Client,
    device: &str,
    command: &str,
    user: Option<String>,
    timeout: u64,
    json: bool,
    interactive: bool,
    force: bool,
    transport: TransportArg,
) -> R {
    if timeout == 0 {
        return Err(Fail::new(
            exit::USAGE,
            "bad_request",
            "--timeout must be at least 1 second",
        ));
    }
    if interactive && json {
        return Err(Fail::new(
            exit::USAGE,
            "bad_request",
            "--interactive-auth cannot be combined with --json",
        ));
    }
    let r = remote_cmds::plan(client, device, user, force, transport)?;
    let t = &r.target;
    let args = build_args(
        t,
        &Mode::Exec {
            command: command.into(),
            batch: !interactive,
        },
        &[],
    );
    let mode = if json {
        OutputMode::Capture
    } else {
        OutputMode::Inherit
    };
    let out = lablink_ssh::run_captured(
        &t.binary,
        &args,
        Duration::from_secs(timeout),
        mode,
        !interactive,
    )
    .map_err(|e| {
        Fail::new(
            exit::FAILURE,
            "exec",
            format!("cannot run {}: {e}", t.binary),
        )
    })?;
    let code = if out.timed_out {
        exit::EXEC_TIMEOUT
    } else if let Some(c) = out.exit_code {
        c
    } else {
        128 + out.signal.unwrap_or(0)
    };
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let failure = (code == exit::SSH_ERROR && !out.timed_out)
        .then(|| lablink_ssh::classify_ssh_failure(&stderr));
    let ssh_error = failure.as_ref().map(|f| f.describe());
    let advice = failure.as_ref().map(|f| f.advice(&r.name));
    if code == exit::SSH_ERROR && !out.timed_out && !json && !r.via_daemon {
        eprintln!(
            "lablink: ssh exited 255 (via {} {}). {}",
            r.transport.as_str(),
            r.ip,
            advice.clone().unwrap_or_default()
        );
    } else if code == exit::SSH_ERROR && !out.timed_out && !json {
        // stderr went to the terminal; the daemon's view explains the state.
        let hint = client
            .call_typed::<StatusReport>(&Request::Status {
                device: Some(if r.id.is_empty() {
                    r.name.clone()
                } else {
                    r.id.clone()
                }),
                site: None,
                all: false,
            })
            .ok()
            .and_then(|s| s.devices.first().and_then(lablink_core::explain::explain))
            .map(|e| format!("{}: {}", e.headline, e.next_step))
            .unwrap_or_else(|| {
                format!(
                    "run `lablink status {}` for what LabLink knows about it",
                    r.name
                )
            });
        eprintln!("lablink: ssh exited 255. {hint}");
    }
    if json {
        let status = if out.timed_out {
            "timeout"
        } else if code == 0 {
            "ok"
        } else if code == exit::SSH_ERROR {
            "ssh_error"
        } else {
            "remote_error"
        };
        print_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "device": r.name,
            "id": r.id,
            "ip": r.ip,
            "user": t.username,
            "command": command,
            "status": status,
            "exit_code": code,
            "timed_out": out.timed_out,
            "duration_ms": out.duration.as_millis() as u64,
            "stdout": String::from_utf8_lossy(&out.stdout),
            "stderr": stderr,
            "stdout_truncated": out.stdout_truncated,
            "stderr_truncated": out.stderr_truncated,
            "ssh_error": ssh_error,
            "advice": advice,
            "identity_pinned": r.pinned,
            "transport": r.transport.as_str(),
            "notes": r.notes,
        }));
    } else if out.timed_out {
        eprintln!(
            "lablink: command timed out after {timeout}s on {} and was killed",
            r.shown
        );
    } else if r.shared_name {
        eprintln!(
            "lablink: ran on {} (the device of that name at your current site)",
            r.id
        );
    }
    Ok(code)
}

fn cmd_trust(client: &Client, device: &str, yes: bool, replace: bool, json: bool) -> R {
    let preview: TrustReport = client.call_typed(&Request::Trust {
        device: device.into(),
        confirm: None,
        replace,
    })?;
    let fps: Vec<String> = preview
        .scanned
        .iter()
        .map(|k| k.fingerprint.clone())
        .collect();
    let render = |r: &TrustReport| {
        let mut s = format!("{} at {} presents:\n", r.device, r.ip);
        for k in &r.scanned {
            s.push_str(&format!("  {:<22} {}\n", k.key_type, k.fingerprint));
        }
        if !r.pinned_before.is_empty() {
            s.push_str("currently pinned:\n");
            for k in &r.pinned_before {
                s.push_str(&format!(
                    "  {:<22} {} [{}]\n",
                    k.key_type,
                    k.fingerprint,
                    k.source.clone().unwrap_or_default()
                ));
            }
        }
        s
    };
    if !yes {
        if json || !std::io::stdin().is_terminal() {
            if json {
                print_json(&preview);
            } else {
                print!("{}", render(&preview));
            }
            eprintln!("lablink: nothing pinned; verify the fingerprints (e.g. `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the device), then re-run with --yes");
            return Ok(exit::REFUSED);
        }
        print!("{}", render(&preview));
        print!(
            "Verify these fingerprints on the device itself. Pin them for '{}'? [y/N] ",
            preview.device
        );
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            eprintln!("lablink: nothing pinned");
            return Ok(exit::REFUSED);
        }
    }
    // Pin exactly the device that was previewed, even if the active site
    // changed in between.
    let r: TrustReport = client.call_typed(&Request::Trust {
        device: preview.device.clone(),
        confirm: Some(fps),
        replace,
    })?;
    if json {
        print_json(&r);
    } else {
        println!(
            "{}: {} ({} key(s) pinned)",
            r.device,
            r.action,
            r.pinned_now.len()
        );
    }
    Ok(exit::OK)
}
