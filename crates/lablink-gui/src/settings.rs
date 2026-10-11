//! Settings and Sites tabs. Sites: create and rename sites, choose each
//! site's networks and active scanning, automatic detection, and the
//! detection signals (written to config.yaml after the same validation the
//! daemon applies). Settings: monitoring interval, history retention,
//! terminal preference, per-device runtime settings (sent to the daemon),
//! and the service.
//!
//! The config holds no secrets; the `ssh:` section (binary paths, extra
//! OpenSSH options) is advanced and stays YAML-only.

use crate::term;
use crate::view::{self, Level};
use eframe::egui::{self, RichText};
use lablink_core::config::{Config, NetworkConfig, SiteConfig};
use lablink_core::model::{DeviceStatus, PortState};
use lablink_core::profile::Profile;
use lablink_core::protocol::DeviceChanges;
use lablink_core::site::SitesReport;
use lablink_setup::ifaces::{self, LocalNetwork};
use lablink_setup::service::ServiceStatus;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Editable runtime settings of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEdit {
    pub label: String,
    pub username: String,
    pub monitoring: bool,
    pub profile: Option<Profile>,
    pub ssh: bool,
}

impl DeviceEdit {
    pub fn from_status(d: &DeviceStatus) -> Self {
        Self {
            label: d.label.clone().unwrap_or_default(),
            username: d.username.clone().unwrap_or_default(),
            monitoring: d.monitoring,
            profile: d.profile,
            ssh: d.ssh_port != PortState::Disabled,
        }
    }

    /// Only what changed; `None` when nothing did.
    pub fn changes(&self, from: &DeviceEdit) -> Option<DeviceChanges> {
        let c = DeviceChanges {
            label: (self.label != from.label).then(|| self.label.trim().to_string()),
            username: (self.username != from.username).then(|| self.username.trim().to_string()),
            monitoring: (self.monitoring != from.monitoring).then_some(self.monitoring),
            profile: (self.profile != from.profile).then(|| {
                self.profile
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default()
            }),
            ssh: (self.ssh != from.ssh).then_some(self.ssh),
            ..Default::default()
        };
        (c != DeviceChanges::default()).then_some(c)
    }
}

pub enum Action {
    Save(Box<Config>),
    Service(&'static str),
    RefreshService,
    ApplyDevice(String, DeviceChanges),
    Reload,
    /// Ask the daemon for the current detection signals.
    RefreshSites,
}

pub struct Settings {
    pub path: PathBuf,
    pub orig: Config,
    pub edit: Config,
    pub terminal: String,
    pub load_error: Option<String>,
    pub message: Option<(bool, String)>,
    pub saving: bool,
    pub service: Option<ServiceStatus>,
    pub service_busy: bool,
    pub detected: Vec<LocalNetwork>,
    pub new_cidr: String,
    pub new_scan: bool,
    pub devices: BTreeMap<String, DeviceEdit>,
    /// Site whose networks the "Add" row edits.
    pub site_ix: usize,
    pub new_site: String,
}

impl Settings {
    pub fn load(path: PathBuf) -> Self {
        let (cfg, err) = match lablink_setup::configfile::load_or_default(&path) {
            Ok(c) => (c, None),
            Err(e) => (Config::default(), Some(e)),
        };
        Self {
            terminal: cfg.preferences.terminal.clone().unwrap_or_default(),
            path,
            orig: cfg.clone(),
            edit: cfg,
            load_error: err,
            message: None,
            saving: false,
            service: None,
            service_busy: false,
            detected: ifaces::detect(),
            new_cidr: String::new(),
            new_scan: false,
            devices: BTreeMap::new(),
            site_ix: 0,
            new_site: String::new(),
        }
    }

    /// The config that would be written, and every validation problem.
    pub fn candidate(&self) -> (Config, Vec<String>) {
        let mut c = self.edit.clone();
        let t = self.terminal.trim();
        c.preferences.terminal = (!t.is_empty()).then(|| t.to_string());
        let errs = match c.validate() {
            Ok(()) => vec![],
            Err(lablink_core::config::ConfigError::Invalid(v)) => v,
            Err(e) => vec![e.to_string()],
        };
        (c, errs)
    }

    pub fn dirty(&self) -> bool {
        self.candidate().0 != self.orig
    }

    /// Add a network to site `ix`; scanning only if asked and allowed by
    /// the same rule the daemon enforces. An attached network also records
    /// its detection hints (interface, gateway and its MAC, Wi-Fi name).
    pub fn add_network(
        &mut self,
        ix: usize,
        cidr: &str,
        local: Option<&LocalNetwork>,
        scan: bool,
    ) -> Result<(), String> {
        let max = self.edit.daemon.max_scan_hosts;
        let site = self.edit.sites.get_mut(ix).ok_or("create a site first")?;
        let net = lablink_core::net::parse_cidr(cidr.trim()).map_err(|e| e.to_string())?;
        let cidr = net.to_string();
        if site.networks.iter().any(|n| n.cidr == cidr) {
            return Err(format!("{cidr} is already allowed at {}", site.name));
        }
        if scan {
            lablink_core::net::validate_scan_range(&cidr, max)
                .map_err(|e| format!("active scanning refused: {e}"))?;
        }
        let taken: Vec<String> = site.networks.iter().map(|n| n.name.clone()).collect();
        let name = ifaces::network_name(local.map_or("net", |l| l.interface.as_str()), &taken);
        site.networks.push(match local {
            Some(l) if l.cidr() == cidr => l.to_network_config(&name, scan),
            _ => NetworkConfig::new(&name, &cidr, scan),
        });
        Ok(())
    }

    /// Create a site from the name box.
    pub fn add_site(&mut self) -> Result<(), String> {
        let name = self.new_site.trim().to_string();
        if !lablink_core::config::valid_display_name(&name) {
            return Err("a site name is 1-64 printable characters".into());
        }
        if self
            .edit
            .sites
            .iter()
            .any(|s| s.name.trim().eq_ignore_ascii_case(&name))
        {
            return Err(format!("there is already a site called '{name}'"));
        }
        let base = lablink_core::config::site_id_from_name(&name);
        let mut id = base.clone();
        let mut n = 2;
        while self.edit.site(&id).is_some() {
            id = format!("{base}-{n}");
            n += 1;
        }
        self.edit.sites.push(SiteConfig::new(&id, &name));
        self.site_ix = self.edit.sites.len() - 1;
        self.new_site.clear();
        Ok(())
    }

    pub fn saved(&mut self, r: Result<String, String>) {
        self.saving = false;
        match r {
            Ok(m) => {
                self.orig = self.candidate().0;
                self.message = Some((true, m));
            }
            Err(e) => self.message = Some((false, e)),
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, live: &[DeviceStatus]) -> Vec<Action> {
        let mut actions = Vec::new();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(820.0);
            if let Some(e) = &self.load_error {
                ui.colored_label(view::RED, format!("The config file cannot be loaded, so it cannot be edited here: {e}"));
                ui.label(format!("Fix {} by hand (`lablink check-config` shows the problem), then press Reload.", self.path.display()));
                if ui.button("Reload").clicked() {
                    actions.push(Action::Reload);
                }
                return;
            }
            ui.weak("Sites and their networks are managed on the Sites tab.");
            ui.separator();
            self.monitoring_section(ui);
            ui.separator();
            self.preferences_section(ui);
            ui.separator();
            self.features_section(ui);
            ui.add_space(6.0);
            self.save_row(ui, &mut actions);
            ui.weak(format!(
                "Advanced: {} stays editable by hand and is validated before use. Saving here rewrites it without comments and keeps the previous file as a backup.",
                self.path.display()
            ));
            ui.separator();
            self.devices_section(ui, live, &mut actions);
            ui.separator();
            self.service_section(ui, &mut actions);
        });
        actions
    }

    /// Save / discard buttons and validation errors (shared by both tabs).
    fn save_row(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        let (_, errs) = self.candidate();
        for e in &errs {
            ui.colored_label(view::RED, e);
        }
        ui.horizontal(|ui| {
            let can = self.dirty() && errs.is_empty() && !self.saving;
            if ui
                .add_enabled(can, egui::Button::new("Save and apply"))
                .clicked()
            {
                self.saving = true;
                self.message = None;
                actions.push(Action::Save(Box::new(self.candidate().0)));
            }
            if ui
                .add_enabled(
                    self.dirty() && !self.saving,
                    egui::Button::new("Discard changes"),
                )
                .clicked()
            {
                self.edit = self.orig.clone();
                self.terminal = self.orig.preferences.terminal.clone().unwrap_or_default();
            }
            if self.saving {
                ui.spinner();
                ui.label("saving and restarting the daemon...");
            }
        });
        if let Some((ok, m)) = &self.message {
            ui.colored_label(if *ok { view::GREEN } else { view::RED }, m);
        }
    }

    /// The Sites tab: create, rename, networks, scanning, detection.
    pub fn sites_ui(&mut self, ui: &mut egui::Ui, report: Option<&SitesReport>) -> Vec<Action> {
        let mut actions = Vec::new();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width(860.0);
            if let Some(e) = &self.load_error {
                ui.colored_label(view::RED, format!("The config file cannot be loaded, so it cannot be edited here: {e}"));
                if ui.button("Reload").clicked() {
                    actions.push(Action::Reload);
                }
                return;
            }
            ui.label(RichText::new("Sites").strong().size(18.0));
            ui.label("A site is a place you work at. LabLink detects which one you are at (Auto) and only checks that site's devices; the others are AWAY, never failures. Detection never changes which host keys are trusted.");
            ui.add_space(4.0);
            if self.site_ix >= self.edit.sites.len() {
                self.site_ix = 0;
            }
            let max = self.edit.daemon.max_scan_hosts;
            let mut remove_net: Option<(usize, usize)> = None;
            for (si, site) in self.edit.sites.iter_mut().enumerate() {
                let live = report.and_then(|r| r.sites.iter().find(|x| x.id == site.id));
                egui::CollapsingHeader::new(RichText::new(format!("{}  ({})", site.name, site.id)).strong())
                    .id_salt(("site", si))
                    .default_open(true)
                    .show(ui, |ui| {
                        egui::Grid::new(("site_head", si)).num_columns(2).show(ui, |ui| {
                            ui.label("Name");
                            ui.add(egui::TextEdit::singleline(&mut site.name).desired_width(220.0));
                            ui.end_row();
                            ui.label("Automatic detection");
                            ui.checkbox(&mut site.auto_detect, "Auto may select this site from network signals");
                            ui.end_row();
                            if let Some(l) = live {
                                ui.label("Now");
                                ui.label(format!(
                                    "{} (confidence {}){}",
                                    l.state.as_str(),
                                    l.confidence.as_str(),
                                    l.scan.as_ref().map(|w| format!("; scanning paused: {w}")).unwrap_or_default()
                                ));
                                ui.end_row();
                            }
                        });
                        ui.label(RichText::new("Networks").strong());
                        egui::Grid::new(("site_nets", si)).striped(true).num_columns(5).show(ui, |ui| {
                            for h in ["Name", "Network", "Active scan", "Detection hints", ""] {
                                ui.strong(h);
                            }
                            ui.end_row();
                            for (ni, n) in site.networks.iter_mut().enumerate() {
                                ui.add(egui::TextEdit::singleline(&mut n.name).desired_width(110.0));
                                ui.monospace(&n.cidr);
                                let allowed = lablink_core::net::validate_scan_range(&n.cidr, max).is_ok();
                                ui.add_enabled_ui(allowed || n.active_scan, |ui| {
                                    ui.checkbox(&mut n.active_scan, if allowed { "" } else { "not allowed" });
                                });
                                let mut hints = Vec::new();
                                if let Some(i) = &n.interface {
                                    hints.push(format!("if {i}"));
                                }
                                if n.gateway_mac.is_some() {
                                    hints.push("gateway MAC".into());
                                } else if n.gateway.is_some() {
                                    hints.push("gateway".into());
                                }
                                if let Some(x) = &n.ssid {
                                    hints.push(format!("Wi-Fi \"{x}\""));
                                }
                                ui.weak(if hints.is_empty() { "subnet only".to_string() } else { hints.join(", ") });
                                if ui.small_button("Remove").clicked() {
                                    remove_net = Some((si, ni));
                                }
                                ui.end_row();
                            }
                        });
                        if let Some(l) = live {
                            if !l.evidence.is_empty() {
                                ui.label(RichText::new("Detection signals").strong());
                                for e in &l.evidence {
                                    ui.label(format!("{:?}: {}", e.strength, e.detail).to_lowercase());
                                }
                            }
                        }
                    });
            }
            if let Some((si, ni)) = remove_net {
                self.edit.sites[si].networks.remove(ni);
            }
            ui.separator();
            ui.strong("Add a network to a site");
            if self.edit.sites.is_empty() {
                ui.weak("Create a site first.");
            } else {
                ui.horizontal(|ui| {
                    ui.label("Site");
                    let names: Vec<String> = self.edit.sites.iter().map(|s| s.name.clone()).collect();
                    egui::ComboBox::from_id_salt("net_site")
                        .selected_text(names.get(self.site_ix).cloned().unwrap_or_default())
                        .show_ui(ui, |ui| {
                            for (i, n) in names.iter().enumerate() {
                                ui.selectable_value(&mut self.site_ix, i, n);
                            }
                        });
                });
                let ix = self.site_ix;
                let unlisted: Vec<LocalNetwork> = self
                    .detected
                    .iter()
                    .filter(|d| !self.edit.sites[ix].networks.iter().any(|n| n.cidr == d.cidr()))
                    .cloned()
                    .collect();
                if !unlisted.is_empty() {
                    ui.label("Attached to this computer now:");
                    for d in unlisted {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{:<18} {} ({})", d.cidr(), d.interface, d.kind.word()));
                            if ui.small_button("Allow (passive)").clicked() {
                                if let Err(e) = self.add_network(ix, &d.cidr(), Some(&d), false) {
                                    self.message = Some((false, e));
                                }
                            }
                            if d.scan_allowed() && ui.small_button("Allow with scanning").clicked() {
                                if let Err(e) = self.add_network(ix, &d.cidr(), Some(&d), true) {
                                    self.message = Some((false, e));
                                }
                            }
                        });
                    }
                }
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_cidr)
                            .hint_text("CIDR, e.g. 192.168.50.0/24")
                            .desired_width(200.0),
                    );
                    ui.checkbox(&mut self.new_scan, "active scan");
                    if ui.button("Add").clicked() {
                        let cidr = self.new_cidr.clone();
                        let local = self.detected.iter().find(|d| d.cidr() == cidr.trim()).cloned();
                        match self.add_network(ix, &cidr, local.as_ref(), self.new_scan) {
                            Ok(()) => {
                                self.new_cidr.clear();
                                self.message = None;
                            }
                            Err(e) => self.message = Some((false, e)),
                        }
                    }
                });
                ui.weak("Active scanning pings every address. It is limited to private networks of at most /22 that this computer is attached to, and only runs while you are at that site.");
            }
            ui.separator();
            ui.strong("New site");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_site)
                        .hint_text("e.g. Makerspace")
                        .desired_width(200.0),
                );
                if ui.button("Create").clicked() {
                    if let Err(e) = self.add_site() {
                        self.message = Some((false, e));
                    }
                }
            });
            ui.add_space(6.0);
            self.save_row(ui, &mut actions);
            if let Some(r) = report {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.strong("This computer sees");
                    if ui.small_button("Refresh").clicked() {
                        actions.push(Action::RefreshSites);
                    }
                });
                for a in &r.signals.attached {
                    ui.monospace(format!("network  {a}"));
                }
                for g in &r.signals.gateways {
                    ui.monospace(format!("gateway  {g}"));
                }
                for w in &r.signals.ssids {
                    ui.monospace(format!("Wi-Fi    {w}"));
                }
            }
        });
        actions
    }

    fn monitoring_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Monitoring");
        let d = &mut self.edit.daemon;
        egui::Grid::new("set_mon").num_columns(3).show(ui, |ui| {
            ui.label("Check interval");
            ui.add(
                egui::DragValue::new(&mut d.check_interval_s)
                    .range(1..=3600)
                    .suffix(" s"),
            );
            ui.weak("how often reachable devices are checked (ICMP, very cheap)");
            ui.end_row();
            ui.label("Background scan");
            ui.add(
                egui::DragValue::new(&mut d.scan_interval_s)
                    .range(0..=86_400)
                    .suffix(" s"),
            );
            ui.weak("0 = only at startup, on network changes and when you press Discover");
            ui.end_row();
            ui.label("History retention");
            ui.add(
                egui::DragValue::new(&mut d.history_retention)
                    .range(100..=1_000_000)
                    .suffix(" events"),
            );
            ui.weak("state transitions kept in the local cache");
            ui.end_row();
        });
        // Keep dependent limits consistent with the interval.
        d.offline_backoff_max_s = d.offline_backoff_max_s.max(d.check_interval_s);
        d.port_check_interval_s = d.port_check_interval_s.max(d.check_interval_s);
        d.via_check_interval_s = d.via_check_interval_s.max(d.check_interval_s);
    }

    fn preferences_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Preferences");
        ui.horizontal(|ui| {
            ui.label("Terminal for SSH sessions");
            ui.add(
                egui::TextEdit::singleline(&mut self.terminal)
                    .hint_text("automatic")
                    .desired_width(160.0),
            );
            for t in term::installed_terminals() {
                if ui.small_button(t).clicked() {
                    self.terminal = t.to_string();
                }
            }
        });
        ui.weak("Empty: $TERMINAL, then the first installed of the buttons shown.");
    }

    fn features_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Optional features");
        let f = &mut self.edit.preferences.features;
        ui.checkbox(&mut f.field_network, "Field Network");
        ui.weak("Lets this app and `lablink hotspot` start a temporary WPA2/WPA3 hotspot through NetworkManager. Off: the tab only shows what this machine could do.");
        ui.checkbox(&mut f.robotics, "Robotics mode");
        ui.weak("Adds the Robotics tab and `lablink ros`: read-only ROS 2 / DDS diagnostics of registered devices over SSH. Nothing is installed on them.");
    }

    fn devices_section(
        &mut self,
        ui: &mut egui::Ui,
        live: &[DeviceStatus],
        actions: &mut Vec<Action>,
    ) {
        ui.strong("Devices");
        ui.label("Applied immediately through the daemon (stored in its cache; config-file values stay as defaults).");
        if live.is_empty() {
            ui.weak("No devices yet (or the daemon is not running).");
            return;
        }
        egui::Grid::new("set_devs")
            .striped(true)
            .num_columns(7)
            .show(ui, |ui| {
                for h in ["Device", "Label", "SSH user", "Type", "SSH", "Monitor", ""] {
                    ui.strong(h);
                }
                ui.end_row();
                for d in live {
                    let base = DeviceEdit::from_status(d);
                    let e = self
                        .devices
                        .entry(d.id.clone())
                        .or_insert_with(|| base.clone());
                    ui.label(if d.site_name.is_empty() {
                        d.name.clone()
                    } else {
                        format!("{} ({})", d.name, d.site_name)
                    });
                    ui.add(egui::TextEdit::singleline(&mut e.label).desired_width(120.0));
                    ui.add_enabled(
                        e.ssh,
                        egui::TextEdit::singleline(&mut e.username).desired_width(90.0),
                    );
                    egui::ComboBox::from_id_salt(("profile", &d.id))
                        .selected_text(e.profile.map_or("(none)", |p| p.title()))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut e.profile, None, "(none)");
                            for p in Profile::ALL {
                                ui.selectable_value(&mut e.profile, Some(p), p.title())
                                    .on_hover_text(p.summary());
                            }
                        });
                    if e.profile == Some(Profile::NetworkOnly) {
                        e.ssh = false;
                    }
                    ui.checkbox(&mut e.ssh, "");
                    ui.checkbox(&mut e.monitoring, "");
                    match e.changes(&base) {
                        Some(c) => {
                            if ui.button("Apply").clicked() {
                                actions.push(Action::ApplyDevice(d.id.clone(), c));
                                self.devices.remove(&d.id);
                            }
                        }
                        None => {
                            // Follow the daemon while untouched.
                            *e = base;
                            ui.label("");
                        }
                    }
                    ui.end_row();
                }
            });
        ui.weak("The SSH switch can only be changed for adopted devices; devices from the config file take `ssh:` from the file.");
    }

    fn service_section(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.strong("Background service");
        match &self.service {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("checking...");
                });
            }
            Some(s) => {
                let (word, level) = if !s.systemd {
                    ("systemd not available", Level::Warn)
                } else if s.unit.is_none() {
                    ("not installed", Level::Warn)
                } else if s.is_active() {
                    ("running", Level::Good)
                } else {
                    ("stopped", Level::Bad)
                };
                ui.label(RichText::new(word).strong().color(view::level_color(level)));
                ui.weak(s.describe());
                let busy = self.service_busy;
                ui.horizontal(|ui| {
                    if s.unit.is_none() {
                        if ui
                            .add_enabled(s.systemd && !busy, egui::Button::new("Install and start"))
                            .clicked()
                        {
                            actions.push(Action::Service("install"));
                        }
                    } else {
                        if ui
                            .add_enabled(!busy && !s.is_active(), egui::Button::new("Start"))
                            .clicked()
                        {
                            actions.push(Action::Service("start"));
                        }
                        if ui
                            .add_enabled(!busy && s.is_active(), egui::Button::new("Stop"))
                            .clicked()
                        {
                            actions.push(Action::Service("stop"));
                        }
                        if ui
                            .add_enabled(!busy, egui::Button::new("Restart"))
                            .clicked()
                        {
                            actions.push(Action::Service("restart"));
                        }
                        let mut autostart = s.is_enabled();
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Checkbox::new(&mut autostart, "start at login"),
                            )
                            .changed()
                        {
                            actions.push(Action::Service(if autostart {
                                "enable"
                            } else {
                                "disable"
                            }));
                        }
                    }
                    if ui.small_button("Refresh").clicked() {
                        actions.push(Action::RefreshService);
                    }
                    if busy {
                        ui.spinner();
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(yaml: &str) -> Settings {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.yaml");
        std::fs::write(&p, yaml).unwrap();
        let s = Settings::load(p);
        drop(dir);
        s
    }

    #[test]
    fn optional_features_start_off_and_save_with_the_config() {
        let mut s = settings("networks:\n  - name: lab\n    cidr: 192.168.50.0/24\n");
        assert_eq!(s.edit.preferences.features, Default::default());
        s.edit.preferences.features.robotics = true;
        assert!(s.dirty());
        let (c, errs) = s.candidate();
        assert!(errs.is_empty());
        assert!(c.preferences.features.robotics && !c.preferences.features.field_network);
    }

    #[test]
    fn edits_are_validated_before_saving() {
        let mut s = settings("networks:\n  - name: lab\n    cidr: 192.168.50.0/24\n");
        assert!(!s.dirty());
        assert_eq!(s.edit.sites[0].id, "default", "single-site file migrated");
        s.edit.sites[0].networks[0].active_scan = true;
        assert!(s.dirty());
        assert!(s.candidate().1.is_empty());
        // A public range can be added passively but never scanned.
        assert!(s
            .add_network(0, "8.8.8.0/24", None, true)
            .unwrap_err()
            .contains("refused"));
        let local = ifaces::classify(
            "eth1",
            "10.0.3.4".parse().unwrap(),
            16,
            ifaces::LinkKind::Wired,
        )
        .unwrap();
        s.add_network(0, "10.0.0.0/16", Some(&local), false)
            .unwrap();
        assert_eq!(s.edit.sites[0].networks[1].name, "eth1");
        assert_eq!(
            s.edit.sites[0].networks[1].interface.as_deref(),
            Some("eth1")
        );
        assert!(
            s.add_network(0, "10.0.0.0/16", None, false).is_err(),
            "duplicate"
        );
        // Invalid edits surface the validator's message.
        s.edit.sites[0].networks[1].active_scan = true;
        assert!(s
            .candidate()
            .1
            .iter()
            .any(|e| e.contains("active_scan refused")));
        s.edit.sites[0].networks[1].active_scan = false;
        // A second site; the same subnet may exist at both sites.
        s.new_site = "Site Beta".into();
        s.add_site().unwrap();
        assert_eq!(s.edit.sites[1].id, "site-beta");
        s.add_network(1, "192.168.50.0/24", None, true).unwrap();
        assert!(s.candidate().1.is_empty(), "{:?}", s.candidate().1);
        s.new_site = "site beta".into();
        assert!(s.add_site().is_err(), "names are unique");
        s.terminal = "xterm -e".into();
        assert!(s.candidate().1.iter().any(|e| e.contains("terminal")));
        s.terminal = "kitty".into();
        let (c, errs) = s.candidate();
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(c.preferences.terminal.as_deref(), Some("kitty"));
    }

    #[test]
    fn device_edits_send_only_changes() {
        let mut d = crate::view::tests_support::dev();
        d.profile = None;
        let base = DeviceEdit::from_status(&d);
        assert_eq!(base.changes(&base), None);
        let mut e = base.clone();
        e.profile = Some(Profile::Jetson);
        e.label = " Bench ".into();
        let c = e.changes(&base).unwrap();
        assert_eq!(c.profile.as_deref(), Some("jetson"));
        assert_eq!(c.label.as_deref(), Some("Bench"));
        assert_eq!((c.username, c.monitoring, c.ssh), (None, None, None));
        e.profile = None;
        e.ssh = false;
        let c = e.changes(&base).unwrap();
        assert_eq!(c.ssh, Some(false));
        assert_eq!(c.profile, None);
    }

    #[test]
    fn unreadable_config_is_reported_not_overwritten() {
        let s = settings("daemon:\n  nonsense: 1\n");
        assert!(s.load_error.is_some());
    }
}
