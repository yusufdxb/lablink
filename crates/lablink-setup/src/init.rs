//! First-run setup, shared by `lablink init` and the GUI wizard. The caller
//! decides which networks LabLink may use (nothing is selected by default);
//! this module writes the config, sets up the service and completion, and
//! verifies the daemon.

use crate::{completions, configfile, service};
use lablink_core::client::Client;
use lablink_core::config::{Config, NetworkConfig, SiteConfig};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub config_path: PathBuf,
    pub socket: PathBuf,
    /// The site being set up: `(id, display name)`.
    pub site: (String, String),
    /// Networks the user explicitly chose for this site. May be empty.
    pub networks: Vec<NetworkConfig>,
    /// Install, enable and start the systemd user service.
    pub service: bool,
    pub completions: bool,
    /// Replace an existing config (a backup is kept).
    pub force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Done,
    Skipped,
    Failed,
}

impl StepStatus {
    pub fn word(self) -> &'static str {
        match self {
            StepStatus::Done => "done",
            StepStatus::Skipped => "skipped",
            StepStatus::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub name: &'static str,
    pub status: StepStatus,
    pub detail: String,
}

fn step(name: &'static str, status: StepStatus, detail: impl Into<String>) -> Step {
    Step {
        name,
        status,
        detail: detail.into(),
    }
}

/// The config `init` writes for a first site with the chosen networks.
pub fn build_config(site_id: &str, site_name: &str, networks: &[NetworkConfig]) -> Config {
    let mut site = SiteConfig::new(site_id, site_name);
    site.networks = networks.to_vec();
    Config {
        sites: vec![site],
        ..Config::default()
    }
}

/// Add the site (or update its name and networks) in an existing config.
pub fn merge_site(cfg: &mut Config, site_id: &str, site_name: &str, networks: &[NetworkConfig]) {
    match cfg.site_mut(site_id) {
        Some(s) => {
            s.name = site_name.to_string();
            s.networks = networks.to_vec();
        }
        None => {
            let mut s = SiteConfig::new(site_id, site_name);
            s.networks = networks.to_vec();
            cfg.sites.push(s);
        }
    }
}

/// True when no config file exists yet (first run).
pub fn needs_setup(config_path: &Path) -> bool {
    !config_path.exists()
}

/// Wait up to `timeout` for the daemon to answer a ping.
pub fn wait_for_daemon(socket: &Path, timeout: Duration) -> Result<String, String> {
    let client = Client::new(socket).with_timeout(Duration::from_secs(2));
    let deadline = Instant::now() + timeout;
    loop {
        match client.call(&lablink_core::protocol::Request::Ping) {
            Ok(v) => {
                return Ok(format!(
                    "lablinkd {} is running (pid {})",
                    v["version"].as_str().unwrap_or("?"),
                    v["pid"]
                ))
            }
            Err(e) if Instant::now() >= deadline => return Err(e.to_string()),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Run every setup step and report each one. Never scans anything.
pub fn run(opts: &InitOptions) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut config_written = false;

    // 1. Configuration.
    let existed = opts.config_path.exists();
    if existed && !opts.force {
        match Config::load(&opts.config_path) {
            Ok(c) => steps.push(step(
                "config",
                StepStatus::Skipped,
                format!(
                    "kept the existing {} ({} sites, {} networks, {} devices); use --force to set up site '{}' again (a backup is kept)",
                    opts.config_path.display(),
                    c.sites.len(),
                    c.network_count(),
                    c.device_count(),
                    opts.site.1
                ),
            )),
            Err(e) => {
                steps.push(step(
                    "config",
                    StepStatus::Failed,
                    format!("the existing config is invalid: {e}"),
                ));
                return steps;
            }
        }
    } else {
        let mut cfg = if existed {
            configfile::load_or_default(&opts.config_path).unwrap_or_default()
        } else {
            Config::default()
        };
        merge_site(&mut cfg, &opts.site.0, &opts.site.1, &opts.networks);
        match configfile::write(&opts.config_path, &cfg) {
            Ok(backup) => {
                config_written = true;
                let scanned: Vec<&str> = opts
                    .networks
                    .iter()
                    .filter(|n| n.active_scan)
                    .map(|n| n.cidr.as_str())
                    .collect();
                let mut d = format!(
                    "wrote {} (site '{}', {} network(s); active scanning: {})",
                    opts.config_path.display(),
                    opts.site.1,
                    opts.networks.len(),
                    if scanned.is_empty() {
                        "none".to_string()
                    } else {
                        scanned.join(", ")
                    }
                );
                if let Some(b) = backup {
                    d.push_str(&format!("; previous file saved as {}", b.display()));
                }
                steps.push(step("config", StepStatus::Done, d));
            }
            Err(e) => {
                steps.push(step("config", StepStatus::Failed, e));
                return steps;
            }
        }
    }

    // 2. Service.
    let mut service_ok = false;
    if opts.service {
        let was_active = service::status().is_active();
        match service::install(true) {
            Ok(log) => {
                service_ok = true;
                let mut d = log.join("; ");
                if was_active && config_written {
                    match service::control("restart") {
                        Ok(()) => d.push_str("; restarted to load the new config"),
                        Err(e) => d.push_str(&format!("; restart failed: {e}")),
                    }
                }
                steps.push(step("service", StepStatus::Done, d));
            }
            Err(e) => steps.push(step("service", StepStatus::Failed, e)),
        }
    } else {
        steps.push(step(
            "service",
            StepStatus::Skipped,
            "not requested; start the daemon with `lablink install-service` or `lablinkd &`",
        ));
    }

    // 3. Shell completion.
    if opts.completions {
        match completions::install() {
            Ok(completions::Installed::User(p)) => steps.push(step(
                "completion",
                StepStatus::Done,
                format!("wrote {} (open a new shell to use it)", p.display()),
            )),
            Ok(completions::Installed::System(p)) => steps.push(step(
                "completion",
                StepStatus::Skipped,
                format!("already installed for all users at {}", p.display()),
            )),
            Err(e) => steps.push(step("completion", StepStatus::Failed, e)),
        }
    } else {
        steps.push(step("completion", StepStatus::Skipped, "not requested"));
    }

    // 4. Verify the daemon answers.
    let wait = if service_ok {
        Duration::from_secs(10)
    } else {
        Duration::from_millis(300)
    };
    match wait_for_daemon(&opts.socket, wait) {
        Ok(d) => steps.push(step("daemon", StepStatus::Done, d)),
        Err(e) if opts.service => steps.push(step(
            "daemon",
            StepStatus::Failed,
            format!(
                "lablinkd did not answer within 10 s ({e}); see `journalctl --user -u lablinkd`"
            ),
        )),
        Err(_) => steps.push(step(
            "daemon",
            StepStatus::Skipped,
            "not running; start it with `lablinkd &` or `lablink install-service`",
        )),
    }
    steps
}

/// The basic workflow, printed by `lablink init` and shown by the GUI.
pub const WORKFLOW: &str = "\
Site -> Discover -> Adopt -> Trust -> Connect

  lablink sites                  where LabLink thinks you are (Auto by default)
  lablink discover               find hosts on the networks you allowed
  lablink discovered             list hosts that are not tracked yet
  lablink adopt <ip> <name>      start tracking one (add --profile, --user, --no-ssh)
  lablink trust <name>           compare and pin its SSH host key
  lablink copy-id <name>         install your SSH key if login is not set up yet
  lablink ssh <name>             connect by name; the IP can change
  lablink status / lablink doctor";

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(dir: &Path) -> InitOptions {
        InitOptions {
            config_path: dir.join("cfg").join("config.yaml"),
            socket: dir.join("none.sock"),
            site: ("site-alpha".into(), "Site Alpha".into()),
            networks: vec![NetworkConfig::new("lab", "192.168.77.0/24", true)],
            service: false,
            completions: false,
            force: false,
        }
    }

    #[test]
    fn first_run_writes_config_and_reports_every_step() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        assert!(needs_setup(&o.config_path));
        let steps = run(&o);
        let names: Vec<_> = steps.iter().map(|s| (s.name, s.status)).collect();
        assert_eq!(
            names,
            [
                ("config", StepStatus::Done),
                ("service", StepStatus::Skipped),
                ("completion", StepStatus::Skipped),
                ("daemon", StepStatus::Skipped),
            ]
        );
        let c = Config::load(&o.config_path).unwrap();
        assert_eq!(c.sites.len(), 1);
        assert_eq!(c.sites[0].id, "site-alpha");
        assert_eq!(c.sites[0].networks, o.networks);
        assert!(!needs_setup(&o.config_path));
        // Second run keeps the file; --force replaces it with a backup.
        let steps = run(&o);
        assert_eq!(steps[0].status, StepStatus::Skipped);
        let mut f = o.clone();
        f.force = true;
        f.networks.clear();
        let steps = run(&f);
        assert_eq!(steps[0].status, StepStatus::Done);
        assert!(steps[0].detail.contains("previous file saved"));
        assert_eq!(Config::load(&o.config_path).unwrap().network_count(), 0);
        // A second site is added next to the first, not instead of it.
        let mut g = f.clone();
        g.site = ("site-beta".into(), "Site Beta".into());
        g.networks = vec![NetworkConfig::new("club", "10.20.30.0/24", true)];
        run(&g);
        let c = Config::load(&o.config_path).unwrap();
        assert_eq!(c.sites.len(), 2);
        assert_eq!(
            c.site("site-beta").unwrap().networks[0].cidr,
            "10.20.30.0/24"
        );
    }

    #[test]
    fn no_networks_means_no_scanning() {
        let c = build_config("default", "Default", &[]);
        assert_eq!(c.network_count(), 0);
        assert!(c.allowlist().networks.is_empty());
    }

    #[test]
    fn invalid_existing_config_stops_setup() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(dir.path());
        std::fs::create_dir_all(o.config_path.parent().unwrap()).unwrap();
        std::fs::write(&o.config_path, "daemon:\n  bogus: 1\n").unwrap();
        let steps = run(&o);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].status, StepStatus::Failed);
    }
}
