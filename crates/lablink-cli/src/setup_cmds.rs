//! Setup and maintenance commands: `init`, `version`, `copy-id`, `export`,
//! `import`, `support-bundle`. The logic lives in `lablink-setup` (shared
//! with the GUI); this module only prompts and prints.

use crate::{print_json, Fail, R};
use lablink_core::client::Client;
use lablink_core::config::NetworkConfig;
use lablink_core::exit;
use lablink_core::model::{DeviceDetail, ResolveResult, SCHEMA_VERSION};
use lablink_core::protocol::{DeviceChanges, Request, PROTOCOL_VERSION};
use lablink_setup::ifaces::{self, LocalNetwork};
use lablink_setup::init::{self, InitOptions, StepStatus};
use lablink_setup::{bundle, configfile, export, service};
use serde_json::json;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

fn usage(m: impl Into<String>) -> Fail {
    Fail::new(exit::USAGE, "bad_request", m)
}

/// Reads answers from stdin (a terminal or a pipe). EOF answers "".
struct Prompt {
    lines: std::io::Lines<std::io::StdinLock<'static>>,
}

impl Prompt {
    fn new() -> Self {
        Self {
            lines: std::io::stdin().lock().lines(),
        }
    }
    fn ask(&mut self, q: &str) -> String {
        print!("{q} ");
        let _ = std::io::stdout().flush();
        let a = self
            .lines
            .next()
            .and_then(Result::ok)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !std::io::stdin().is_terminal() {
            println!("{a}");
        }
        a
    }
    fn yes_no(&mut self, q: &str, default: bool) -> bool {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            match self
                .ask(&format!("{q} {hint}"))
                .to_ascii_lowercase()
                .as_str()
            {
                "" => return default,
                "y" | "yes" => return true,
                "n" | "no" => return false,
                _ => println!("  please answer y or n"),
            }
        }
    }
}

/// `NAME=CIDR` or `CIDR`, named after the local interface when attached.
fn parse_network(
    arg: &str,
    active_scan: bool,
    local: &[LocalNetwork],
    taken: &mut Vec<String>,
) -> Result<NetworkConfig, Fail> {
    let (name, cidr) = match arg.split_once('=') {
        Some((n, c)) => (Some(n.trim().to_string()), c.trim()),
        None => (None, arg.trim()),
    };
    let net = lablink_core::net::parse_cidr(cidr).map_err(|e| usage(format!("{arg}: {e}")))?;
    if active_scan {
        lablink_core::net::validate_scan_range(
            &net.to_string(),
            lablink_core::net::DEFAULT_MAX_SCAN_HOSTS,
        )
        .map_err(|e| {
            usage(format!(
                "--scan {arg}: {e} (use --network for passive monitoring)"
            ))
        })?;
    }
    let attached = local.iter().find(|l| l.cidr() == net.to_string());
    let name = match name {
        Some(n) => n,
        None => {
            let iface = attached
                .map(|l| l.interface.clone())
                .unwrap_or_else(|| "net".into());
            ifaces::network_name(&iface, taken)
        }
    };
    if !lablink_core::config::valid_name(&name) {
        return Err(usage(format!(
            "network name '{name}' must match [A-Za-z0-9_.-]+"
        )));
    }
    taken.push(name.clone());
    // An attached network also records how to recognize the place again
    // (interface, gateway and its MAC, Wi-Fi name).
    Ok(match attached {
        Some(l) => l.to_network_config(&name, active_scan),
        None => NetworkConfig::new(&name, &net.to_string(), active_scan),
    })
}

/// `(id, display name)` for a site called `name`, reusing the id of an
/// existing site with that name.
fn site_identity(cfg: &lablink_core::Config, name: &str) -> (String, String) {
    let name = name.trim().to_string();
    if let Some(s) = cfg
        .sites
        .iter()
        .find(|s| s.name.trim().eq_ignore_ascii_case(&name) || s.id.eq_ignore_ascii_case(&name))
    {
        return (s.id.clone(), s.name.clone());
    }
    let base = lablink_core::config::site_id_from_name(&name);
    let mut id = base.clone();
    let mut n = 2;
    while cfg.site(&id).is_some() {
        id = format!("{base}-{n}");
        n += 1;
    }
    (id, name)
}

fn describe_local(n: &LocalNetwork) -> String {
    let scan = match &n.scan_refusal {
        None => format!("{} addresses, active scan possible", n.host_count()),
        Some(r) => format!("passive only: {r}"),
    };
    format!(
        "{:<18} {:<12} {:<8} {}",
        n.cidr(),
        n.interface,
        n.kind.word(),
        scan
    )
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_init(
    socket: &Path,
    site: Option<String>,
    networks: Vec<String>,
    scan: Vec<String>,
    yes: bool,
    no_service: bool,
    no_completions: bool,
    force: bool,
    config: Option<PathBuf>,
) -> R {
    let config_path = config.unwrap_or_else(lablink_core::paths::default_config_path);
    let local = ifaces::detect();
    let mut taken = Vec::new();
    let mut chosen = Vec::new();
    for a in &scan {
        chosen.push(parse_network(a, true, &local, &mut taken)?);
    }
    for a in &networks {
        chosen.push(parse_network(a, false, &local, &mut taken)?);
    }
    let mut force = force;
    let (mut want_service, mut want_completions) = (!no_service, !no_completions);
    let existing = lablink_setup::configfile::load_or_default(&config_path).unwrap_or_default();
    if let Some(n) = &site {
        if !lablink_core::config::valid_display_name(n) {
            return Err(usage("--site must be 1-64 printable characters"));
        }
    }
    let mut site_name = site
        .clone()
        .unwrap_or_else(|| match existing.sites.as_slice() {
            [one] => one.name.clone(),
            _ => lablink_core::config::DEFAULT_SITE_NAME.to_string(),
        });

    if !yes {
        let mut p = Prompt::new();
        println!("LabLink first-run setup\n");
        println!("A site is a place you work at (a lab, an office, a workshop). LabLink");
        println!("recognizes it from its networks and only checks its devices while you");
        println!("are there. You can add more sites later.\n");
        println!("LabLink only looks at networks you choose here. Nothing is selected until");
        println!("you pick it, and active scanning (a ping sweep) needs a separate yes.\n");
        let exists = config_path.exists();
        let mut ask_networks = chosen.is_empty();
        if exists && !force {
            println!(
                "A configuration already exists at {}.",
                config_path.display()
            );
            if p.yes_no("Keep it?", true) {
                ask_networks = false;
            } else {
                force = true;
                println!("  this site's networks will be set up again (a backup is kept)");
            }
        }
        if site.is_none() && (force || !exists) {
            let a = p.ask(&format!("What do you call this place? [{site_name}]"));
            if !a.is_empty() {
                if lablink_core::config::valid_display_name(&a) {
                    site_name = a;
                } else {
                    println!("  names are 1-64 printable characters; keeping '{site_name}'");
                }
            }
        }
        if ask_networks {
            if local.is_empty() {
                println!("No IPv4 networks are attached to this machine right now.");
                println!("You can add networks later in the GUI settings or with `lablink init --force --scan CIDR`.");
            } else {
                println!("Networks attached to this machine:");
                for (i, n) in local.iter().enumerate() {
                    println!("  {}) {}", i + 1, describe_local(n));
                }
                let picked: Vec<usize> = loop {
                    let a = p.ask(
                        "Networks LabLink may use, by number separated by commas (Enter for none):",
                    );
                    let parsed: Result<Vec<usize>, _> = a
                        .split([',', ' '])
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse::<usize>())
                        .collect();
                    match parsed {
                        Ok(v) if v.iter().all(|i| (1..=local.len()).contains(i)) => break v,
                        _ => println!("  enter numbers between 1 and {}", local.len()),
                    }
                };
                for i in picked {
                    let n = &local[i - 1];
                    if chosen.iter().any(|c: &NetworkConfig| c.cidr == n.cidr()) {
                        continue;
                    }
                    let active = match &n.scan_refusal {
                        None => p.yes_no(
                            &format!(
                                "  Allow active scanning of {} ({} addresses are pinged when you run discover, and every 2 minutes)?",
                                n.cidr(),
                                n.host_count()
                            ),
                            false,
                        ),
                        Some(r) => {
                            println!("  {}: passive monitoring only ({r})", n.cidr());
                            false
                        }
                    };
                    let name = ifaces::network_name(&n.interface, &taken);
                    taken.push(name.clone());
                    chosen.push(n.to_network_config(&name, active));
                }
                if chosen.is_empty() {
                    println!("  no networks chosen: LabLink will not discover anything until you add one");
                }
            }
        }
        if want_service {
            want_service = p.yes_no(
                "Install and start the background service (systemd user service, runs as you, no root)?",
                true,
            );
        }
        if want_completions {
            want_completions = p.yes_no("Install bash tab completion for your user?", true);
        }
        println!();
    }

    let steps = init::run(&InitOptions {
        config_path,
        socket: socket.to_path_buf(),
        site: site_identity(&existing, &site_name),
        networks: chosen,
        service: want_service,
        completions: want_completions,
        force,
    });
    let mut failed = false;
    for s in &steps {
        failed |= s.status == StepStatus::Failed;
        println!("{:<11} {:<8} {}", s.name, s.status.word(), s.detail);
    }
    println!("\n{}", init::WORKFLOW);
    Ok(if failed { exit::FAILURE } else { exit::OK })
}

pub fn cmd_version(client: &Client, json_out: bool) -> R {
    let daemon = client
        .clone()
        .with_timeout(std::time::Duration::from_secs(2))
        .call(&Request::Ping)
        .ok();
    let exe = std::env::current_exe().ok();
    let build_status = daemon.as_ref().map(|v| {
        if v["version"].as_str() != Some(lablink_core::VERSION)
            || v["protocol_version"].as_u64() != Some(PROTOCOL_VERSION as u64)
        {
            "different"
        } else {
            match (lablink_core::GIT_SHA, v["git_sha"].as_str()) {
                (Some(a), Some(b)) if a == b => "same",
                (Some(_), Some(_)) => "different",
                _ => "unknown",
            }
        }
    });
    let install = match exe.as_deref().and_then(Path::parent) {
        Some(d) if d == Path::new("/usr/bin") => "Debian package (/usr/bin)".to_string(),
        Some(d) => d.display().to_string(),
        None => "unknown".into(),
    };
    if json_out {
        print_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "version": lablink_core::VERSION,
            "git_sha": lablink_core::GIT_SHA,
            "protocol_version": PROTOCOL_VERSION,
            "install": install,
            "daemon": daemon,
            "daemon_build": build_status,
        }));
    } else {
        println!(
            "lablink {}{}",
            lablink_core::VERSION,
            lablink_core::GIT_SHA
                .map(|s| format!(" (commit {s})"))
                .unwrap_or_default()
        );
        match &daemon {
            Some(v) => println!(
                "lablinkd {} running (commit {}, pid {}, up {} s, protocol {})",
                v["version"].as_str().unwrap_or("?"),
                v["git_sha"].as_str().unwrap_or("unknown"),
                v["pid"],
                v["uptime_s"],
                v["protocol_version"]
            ),
            None => println!("lablinkd not running"),
        }
        println!("installed in {install}");
        match build_status {
            Some("different") => eprintln!("lablink: WARNING: client and daemon builds differ. Restart lablinkd using the installed build before connecting."),
            Some("unknown") => eprintln!("lablink: WARNING: client/daemon build identity could not be compared. Restart lablinkd after upgrading and check `lablink version` again."),
            _ => {}
        }
    }
    Ok(exit::OK)
}

fn find_pubkey(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let p = if p.extension().is_some_and(|e| e == "pub") {
            p
        } else {
            PathBuf::from(format!("{}.pub", p.display()))
        };
        return Some(p);
    }
    let ssh = lablink_core::paths::home().join(".ssh");
    ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"]
        .iter()
        .map(|n| ssh.join(n))
        .find(|p| p.is_file())
}

pub fn cmd_copy_id(
    client: &Client,
    device: &str,
    user: Option<String>,
    identity: Option<PathBuf>,
) -> R {
    let r: ResolveResult = client.call_typed(&Request::Resolve {
        device: device.into(),
        batch: false,
    })?;
    let id = if r.id.is_empty() {
        r.name.clone()
    } else {
        r.id.clone()
    };
    let mut t = lablink_ssh::Target::from_resolve(&r)
        .map_err(|e| Fail::new(exit::IDENTITY_MISMATCH, "identity_mismatch", e))?;
    if r.host_key_alias.is_none() {
        return Err(Fail::new(
            exit::REFUSED,
            "refused",
            format!("'{}' has no pinned host key yet. Pin it first with `lablink trust {}`, so the password you type can only reach the verified machine.", r.name, r.name),
        ));
    }
    if let Some(u) = user {
        if !lablink_core::config::valid_username(&u) {
            return Err(usage(format!("invalid username '{u}'")));
        }
        t.username = Some(u);
    }
    let pubkey = match find_pubkey(identity) {
        Some(p) if p.is_file() => p,
        Some(p) => return Err(usage(format!("{} does not exist", p.display()))),
        None => {
            let tty = std::io::stdin().is_terminal();
            if tty
                && Prompt::new().yes_no(
                    "You have no SSH key yet (~/.ssh/id_ed25519). Create one now with ssh-keygen?",
                    true,
                )
            {
                let st = lablink_core::program::command("ssh-keygen")
                    .and_then(|mut c| c.args(["-t", "ed25519"]).status())
                    .map_err(|e| {
                        Fail::new(exit::FAILURE, "exec", format!("cannot run ssh-keygen: {e}"))
                    })?;
                if !st.success() {
                    return Ok(exit::FAILURE);
                }
                find_pubkey(None).ok_or_else(|| usage("no public key was created"))?
            } else {
                return Err(usage(
                    "no SSH key found in ~/.ssh: create one with `ssh-keygen -t ed25519`, then run this again",
                ));
            }
        }
    };
    let args = lablink_ssh::copy_id_args(&t, &pubkey)
        .map_err(|e| Fail::new(exit::REFUSED, "refused", e))?;
    let who = t
        .username
        .as_deref()
        .map(|u| format!("{u}@"))
        .unwrap_or_default();
    eprintln!(
        "lablink: installing {} on {} ({who}{}, host key pinned by LabLink). You may be asked for the device password; LabLink never sees or stores it.",
        pubkey.display(),
        if r.shared_name { &id } else { &r.name },
        r.ip
    );
    let st = lablink_core::program::command("ssh-copy-id")
        .and_then(|mut c| c.args(&args).status())
        .map_err(|e| {
            Fail::new(
                exit::FAILURE,
                "exec",
                format!("cannot run ssh-copy-id ({e}); it is part of the openssh-client package"),
            )
        })?;
    if !st.success() {
        eprintln!("lablink: ssh-copy-id did not finish; nothing changed in LabLink");
        return Ok(st.code().unwrap_or(exit::FAILURE));
    }
    // Ask the daemon to re-check the login now rather than in 5 minutes.
    let _ = client.call(&Request::Set {
        device: id.clone(),
        changes: DeviceChanges {
            recheck: true,
            ..Default::default()
        },
    });
    eprintln!(
        "lablink: key installed; LabLink re-checks the login now (see `lablink status {}`)",
        r.name
    );
    Ok(exit::OK)
}

fn load_config(path: &Path) -> Result<lablink_core::Config, Fail> {
    configfile::load_or_default(path).map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))
}

pub fn cmd_export(
    client: &Client,
    output: Option<PathBuf>,
    no_fingerprints: bool,
    config: Option<PathBuf>,
) -> R {
    let path = config.unwrap_or_else(lablink_core::paths::default_config_path);
    let cfg = load_config(&path)?;
    let devices: Option<Vec<DeviceDetail>> = match client.call(&Request::Devices {
        site: None,
        all: true,
    }) {
        Ok(v) => serde_json::from_value(v["devices"].clone()).ok(),
        Err(_) => {
            eprintln!("lablink: lablinkd is not running: exporting the config file only (devices adopted at runtime and runtime settings are not included)");
            None
        }
    };
    let doc = export::build(
        &cfg,
        devices.as_deref(),
        !no_fingerprints,
        lablink_core::time::now_ms(),
    )
    .map_err(|e| Fail::new(exit::FAILURE, "export", e))?;
    let text = doc.to_yaml();
    match output {
        Some(p) => {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&p)
                .and_then(|mut f| f.write_all(text.as_bytes()))
                .map_err(|e| {
                    Fail::new(
                        exit::FAILURE,
                        "export",
                        format!("cannot write {}: {e}", p.display()),
                    )
                })?;
            eprintln!(
                "lablink: wrote {} ({} sites, {} networks, {} devices; no keys, passwords or secrets)",
                p.display(),
                doc.config.sites.len(),
                doc.config.network_count(),
                doc.config.device_count()
            );
        }
        None => print!("{text}"),
    }
    Ok(exit::OK)
}

pub fn cmd_import(
    file: &Path,
    opts: export::ImportOptions,
    yes: bool,
    dry_run: bool,
    config: Option<PathBuf>,
) -> R {
    let path = config.unwrap_or_else(lablink_core::paths::default_config_path);
    let meta = std::fs::metadata(file)
        .map_err(|e| usage(format!("cannot read {}: {e}", file.display())))?;
    if !meta.is_file() || meta.len() > lablink_core::config::MAX_CONFIG_BYTES {
        return Err(usage(format!(
            "{} is not a LabLink export (not a regular file, or larger than {} bytes)",
            file.display(),
            lablink_core::config::MAX_CONFIG_BYTES
        )));
    }
    let text = std::fs::read_to_string(file)
        .map_err(|e| usage(format!("cannot read {}: {e}", file.display())))?;
    let doc = export::parse(&text).map_err(usage)?;
    let current = load_config(&path)?;
    let plan = export::plan(&current, &doc, opts)
        .map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))?;
    println!(
        "Import from {} (exported {} by LabLink {}):",
        file.display(),
        if doc.exported_at.is_empty() {
            "?"
        } else {
            &doc.exported_at
        },
        if doc.lablink_version.is_empty() {
            "?"
        } else {
            &doc.lablink_version
        }
    );
    if plan.changes.is_empty() {
        println!("  nothing to change");
    }
    for c in &plan.changes {
        println!("  + {c}");
    }
    for s in &plan.skipped {
        println!("  = {s}");
    }
    if plan.dropped_pins > 0 {
        println!(
            "  {} pinned host key(s) in the file were NOT imported: pin each device yourself with `lablink trust <device>` (or re-run with --trust-pins if you made this file yourself)",
            plan.dropped_pins
        );
    }
    if !plan.kept_pins.is_empty() {
        println!("  WARNING: these host keys will be trusted without a fresh check:");
        for (d, f) in &plan.kept_pins {
            println!("    {d:<24} {f}");
        }
    }
    if !plan.dropped_commands.is_empty() {
        println!(
            "  {} service-check command(s) in the file were NOT imported (they would run on your devices); re-run with --allow-commands only if you trust the file:",
            plan.dropped_commands.len()
        );
        for (d, n, c) in &plan.dropped_commands {
            println!("    {d}/{n}: {c}");
        }
    }
    if !plan.kept_commands.is_empty() {
        println!("  WARNING: these commands will run on your devices over SSH:");
        for (d, n, c) in &plan.kept_commands {
            println!("    {d}/{n}: {c}");
        }
    }
    if !plan.scanned_networks.is_empty() && !plan.changes.is_empty() {
        println!(
            "  after this import, LabLink may actively scan (only while you are at that site):"
        );
        for (s, c) in &plan.scanned_networks {
            println!("    {s:<20} {c}");
        }
    }
    if dry_run || plan.changes.is_empty() {
        return Ok(exit::OK);
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("lablink: nothing written; re-run with --yes to apply");
            return Ok(exit::REFUSED);
        }
        if !Prompt::new().yes_no(
            &format!("Write these changes to {}?", path.display()),
            false,
        ) {
            eprintln!("lablink: nothing written");
            return Ok(exit::REFUSED);
        }
    }
    let backup = configfile::update(&path, |latest| {
        if latest != &current {
            return Err(
                "configuration changed while confirming the import; review it again".into(),
            );
        }
        *latest = plan.config.clone();
        Ok(())
    })
    .map_err(|e| Fail::new(exit::FAILURE, "import", e))?;
    println!("wrote {}", path.display());
    if let Some(b) = backup {
        println!("previous config saved as {}", b.display());
    }
    println!("{}", service::restart_if_active());
    Ok(exit::OK)
}

pub fn cmd_support_bundle(
    socket: &Path,
    output_dir: Option<PathBuf>,
    no_doctor: bool,
    config: Option<PathBuf>,
) -> R {
    let out_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    if !no_doctor {
        eprintln!(
            "lablink: collecting diagnostics (includes a read-only doctor run, up to ~15 s)..."
        );
    }
    let b = bundle::create(&bundle::BundleOptions {
        config_path: config.unwrap_or_else(lablink_core::paths::default_config_path),
        socket: socket.to_path_buf(),
        out_dir,
        doctor: !no_doctor,
    })
    .map_err(|e| Fail::new(exit::FAILURE, "support_bundle", e))?;
    println!("{}", b.path.display());
    eprintln!(
        "lablink: contains {}. Addresses, MACs, fingerprints, usernames, hostnames and labels are replaced by placeholders. Review it before sharing.",
        b.files.join(", ")
    );
    Ok(exit::OK)
}

/// `lablink site add`: create a site for where you are now.
pub fn cmd_site_add(
    name: &str,
    id: Option<String>,
    networks: Vec<String>,
    scan: Vec<String>,
    no_auto_detect: bool,
    config: Option<PathBuf>,
) -> R {
    let path = config.unwrap_or_else(lablink_core::paths::default_config_path);
    let cfg = load_config(&path)?;
    if !lablink_core::config::valid_display_name(name) {
        return Err(usage("the site name must be 1-64 printable characters"));
    }
    let id = match id {
        Some(i) => i,
        None => site_identity(&cfg, name).0,
    };
    if !lablink_core::config::valid_site_id(&id) {
        return Err(usage(format!(
            "site id '{id}' must be lower-case letters, digits and '-' (1-32 characters)"
        )));
    }
    if cfg.site(&id).is_some() {
        return Err(Fail::new(
            exit::USAGE,
            "conflict",
            format!("a site with id '{id}' already exists (`lablink sites`)"),
        ));
    }
    let local = ifaces::detect();
    let mut taken = Vec::new();
    let mut chosen = Vec::new();
    for a in &scan {
        chosen.push(parse_network(a, true, &local, &mut taken)?);
    }
    for a in &networks {
        chosen.push(parse_network(a, false, &local, &mut taken)?);
    }
    let mut site = lablink_core::config::SiteConfig::new(&id, name.trim());
    site.auto_detect = !no_auto_detect;
    site.networks = chosen;
    let backup = configfile::update(&path, |latest| {
        if latest.site(&id).is_some() {
            return Err(format!("a site with id '{id}' already exists"));
        }
        latest.sites.push(site);
        Ok(())
    })
    .map_err(|e| Fail::new(exit::USAGE, "invalid_config", e))?;
    println!(
        "added site '{}' ({id}) with {} network(s) to {}",
        name.trim(),
        networks.len() + scan.len(),
        path.display()
    );
    if let Some(b) = backup {
        println!("previous config saved as {}", b.display());
    }
    println!("{}", service::restart_if_active());
    Ok(exit::OK)
}

/// `lablink site rename`.
pub fn cmd_site_rename(site: &str, name: &str, config: Option<PathBuf>) -> R {
    let path = config.unwrap_or_else(lablink_core::paths::default_config_path);
    let mut old = String::new();
    configfile::update(&path, |cfg| {
        let s = cfg
            .site_mut(site)
            .ok_or_else(|| format!("unknown site '{site}' (see `lablink sites`)"))?;
        old = std::mem::replace(&mut s.name, name.trim().to_string());
        Ok(())
    })
    .map_err(|e| {
        if e.starts_with("unknown site '") {
            Fail::new(exit::DEVICE_NOT_FOUND, "device_not_found", e)
        } else {
            Fail::new(exit::USAGE, "invalid_config", e)
        }
    })?;
    println!("renamed site '{old}' to '{}' (id unchanged)", name.trim());
    println!("{}", service::restart_if_active());
    Ok(exit::OK)
}
