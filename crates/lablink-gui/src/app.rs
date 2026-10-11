//! Application state and UI. All device data comes from `lablinkd` via the
//! worker; setup actions go through `lablink_setup` (also via the worker).

use crate::flow::{self, AdoptForm, StepState, TrustPlan};
use crate::health::{self, DoctorPanel};
use crate::settings::{self, DeviceEdit, Settings};
use crate::term;
use crate::view::{self, Level};
use crate::wizard::{self, Wizard};
use crate::worker::{Cmd, Event, Fail, RunResult, Worker, POLL_INTERVAL};
use eframe::egui::{self, Color32, RichText};
use lablink_core::explain::{self, Action as Fix};
use lablink_core::model::{
    Color, DeviceDetail, DeviceStatus, DiscoverReport, DiscoveredHost, HistoryEvent, IdentityState,
    PortState,
};
use lablink_core::profile::Profile;
use lablink_core::protocol::DeviceChanges;
use lablink_core::site::{SiteMode, SiteState, SiteStatus, SitesReport};
use lablink_core::time::{format_age, now_ms};
use lablink_setup::service::ServiceStatus;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Devices,
    Discovered,
    Health,
    Sites,
    Settings,
}

/// Which devices the Devices tab shows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SiteView {
    /// The site(s) you are at (not AWAY).
    Current,
    /// One site, whatever its state (browsing, not switching).
    Site(String),
    /// A summary of every site.
    All,
}

/// The Adopt dialog for one unmatched discovered host.
struct AdoptDialog {
    host: DiscoveredHost,
    form: AdoptForm,
    /// Site the device joins.
    site: Option<String>,
    busy: bool,
    error: Option<String>,
}

/// State of the two-step trust flow for one device.
struct TrustPanel {
    device: String,
    loading: bool,
    plan: Option<TrustPlan>,
    pinning: bool,
    error: Option<String>,
    done: Option<String>,
}

#[derive(Default)]
struct RunPanel {
    command: String,
    busy: bool,
    result: Option<Result<RunResult, Fail>>,
}

struct TestSsh {
    device: String,
    busy: bool,
    result: Option<Result<RunResult, Fail>>,
}

pub struct App {
    worker: Worker,
    rx: Receiver<Event>,
    socket: PathBuf,
    config_path: PathBuf,
    tab: Tab,
    view: SiteView,

    /// Every device of every site (the views filter).
    devices: Vec<DeviceStatus>,
    sites: Vec<SiteStatus>,
    site_mode: SiteMode,
    /// The latest `lablink sites` report (evidence and local signals).
    sites_report: Option<Result<SitesReport, Fail>>,
    daemon_version: Option<String>,
    daemon_build_warning: Option<String>,
    daemon_uptime_s: Option<u64>,
    poll_error: Option<Fail>,
    /// Service state, fetched when the daemon becomes unreachable (not polled).
    service: Option<ServiceStatus>,
    service_busy: bool,

    selected: Option<String>,
    detail: Option<DeviceDetail>,
    detail_error: Option<String>,
    edit: DeviceEdit,
    edit_orig: DeviceEdit,
    /// Device the edit fields were last loaded for; reset to reload them.
    edit_for: Option<String>,
    show_edit: bool,
    notice: Option<(bool, String)>,
    history: Option<Result<Vec<HistoryEvent>, Fail>>,
    history_loading: bool,
    run: RunPanel,
    test_ssh: Option<TestSsh>,

    discovered: Vec<DiscoveredHost>,
    discovered_error: Option<String>,
    discover_busy: bool,
    discover_report: Option<Result<DiscoverReport, Fail>>,
    show_discover: bool,

    /// One-line result of the last adopt / service action, under the top bar.
    banner: Option<(bool, String)>,
    adopt: Option<AdoptDialog>,
    trust: Option<TrustPanel>,
    doctor: DoctorPanel,
    wizard: Option<Wizard>,
    settings: Option<Settings>,
    /// Preferred terminal from the config's `preferences`.
    terminal: Option<String>,
}

fn load_terminal(path: &std::path::Path) -> Option<String> {
    lablink_core::Config::load(path)
        .ok()
        .and_then(|c| c.preferences.terminal)
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Cards are click targets; selectable label text would swallow the clicks.
        cc.egui_ctx
            .all_styles_mut(|s| s.interaction.selectable_labels = false);
        let socket = lablink_core::paths::default_socket_path();
        let config_path = lablink_core::paths::default_config_path();
        let (worker, rx) = Worker::spawn(socket.clone(), cc.egui_ctx.clone());
        let wizard = lablink_setup::init::needs_setup(&config_path)
            .then(|| Wizard::new(config_path.clone(), socket.clone()));
        Self {
            worker,
            rx,
            terminal: load_terminal(&config_path),
            socket,
            config_path,
            tab: Tab::Devices,
            view: SiteView::Current,
            devices: Vec::new(),
            sites: Vec::new(),
            site_mode: SiteMode::Auto,
            sites_report: None,
            daemon_version: None,
            daemon_build_warning: None,
            daemon_uptime_s: None,
            poll_error: None,
            service: None,
            service_busy: false,
            selected: None,
            detail: None,
            detail_error: None,
            edit: DeviceEdit::from_status(&placeholder()),
            edit_orig: DeviceEdit::from_status(&placeholder()),
            edit_for: None,
            show_edit: false,
            notice: None,
            history: None,
            history_loading: false,
            run: RunPanel::default(),
            test_ssh: None,
            discovered: Vec::new(),
            discovered_error: None,
            discover_busy: false,
            discover_report: None,
            show_discover: false,
            banner: None,
            adopt: None,
            trust: None,
            doctor: DoctorPanel::default(),
            wizard,
            settings: None,
        }
    }

    fn refresh(&mut self) {
        self.worker.refresh();
        if let Some(d) = self.selected.clone() {
            self.worker.send(Cmd::Inspect(d));
        }
        if self.tab == Tab::Discovered {
            self.worker.send(Cmd::Discovered);
        }
    }

    fn select(&mut self, name: String) {
        self.tab = Tab::Devices;
        if self.selected.as_deref() == Some(&name) {
            return;
        }
        self.detail = None;
        self.detail_error = None;
        self.history = None;
        self.history_loading = false;
        self.run = RunPanel::default();
        self.test_ssh = None;
        self.notice = None;
        self.trust = None;
        self.edit_for = None;
        self.show_edit = false;
        self.worker.send(Cmd::Inspect(name.clone()));
        self.selected = Some(name);
    }

    fn start_discover(&mut self) {
        self.discover_busy = true;
        self.worker.send(Cmd::Discover);
    }

    fn start_doctor(&mut self, scope: String, devices: Vec<String>) {
        self.doctor.scope = scope.clone();
        self.doctor.busy = true;
        self.doctor.result = None;
        self.worker.send(Cmd::Doctor { scope, devices });
    }

    /// Step 1 of trust: scan only. Nothing is pinned by this request.
    fn start_trust(&mut self, device: &str) {
        self.trust = Some(TrustPanel {
            device: device.to_string(),
            loading: true,
            plan: None,
            pinning: false,
            error: None,
            done: None,
        });
        self.worker.send(Cmd::TrustPreview(device.to_string()));
    }

    fn open_terminal(&mut self, args: &[&str]) {
        self.notice = Some(
            match term::open_lablink_in_terminal(args, self.terminal.as_deref()) {
                Ok(t) => (
                    true,
                    format!("opened {t} running lablink {}", args.join(" ")),
                ),
                Err(e) => (false, e),
            },
        );
    }

    fn apply_changes(&mut self, device: &str, changes: DeviceChanges) {
        self.worker.send(Cmd::Apply {
            device: device.to_string(),
            changes,
        });
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            self.handle(ev);
        }
    }

    fn handle(&mut self, ev: Event) {
        match ev {
            Event::Poll {
                status,
                version,
                build_warning,
            } => match status {
                Ok(report) => {
                    self.devices = report.devices;
                    self.sites = report.sites;
                    self.site_mode = report.site_mode;
                    if let SiteView::Site(id) = &self.view {
                        if !self.sites.iter().any(|s| &s.id == id) {
                            self.view = SiteView::Current;
                        }
                    }
                    self.daemon_version = version;
                    self.daemon_build_warning = build_warning;
                    self.daemon_uptime_s = Some(report.daemon.uptime_s);
                    self.poll_error = None;
                    if let Some(d) = self.selected.clone() {
                        self.worker.send(Cmd::Inspect(d));
                    }
                }
                Err(f) => {
                    // Never show stale green cards for a daemon we cannot reach.
                    self.devices.clear();
                    self.sites.clear();
                    self.daemon_version = None;
                    self.daemon_build_warning = None;
                    self.daemon_uptime_s = None;
                    if self.poll_error.is_none() && f.unavailable {
                        // Once per outage: how can the daemon be started?
                        self.worker.send(Cmd::Service);
                    }
                    self.poll_error = Some(f);
                }
            },
            Event::Detail(name, result) => {
                if self.selected.as_deref() != Some(&name) {
                    return;
                }
                match result {
                    Ok(d) => {
                        if self.edit_for.as_deref() != Some(&name) {
                            self.edit_orig = DeviceEdit::from_status(&d.status);
                            self.edit = self.edit_orig.clone();
                            self.edit_for = Some(name);
                        }
                        self.detail = Some(*d);
                        self.detail_error = None;
                    }
                    Err(f) => self.detail_error = Some(f.message),
                }
            }
            Event::History(name, result) => {
                if self.selected.as_deref() == Some(&name) {
                    self.history = Some(result);
                    self.history_loading = false;
                }
            }
            Event::Discovered(result) => match result {
                Ok(list) => {
                    self.discovered = list;
                    self.discovered_error = None;
                }
                Err(f) => self.discovered_error = Some(f.message),
            },
            Event::DiscoverDone(result) => {
                self.discover_busy = false;
                if let Ok(r) = &result {
                    self.discovered = r.discovered.clone();
                }
                self.discover_report = Some(result);
                self.show_discover = true;
                self.worker.refresh();
            }
            Event::Applied(name, result) => {
                let msg = match result {
                    Ok(()) => (true, format!("applied changes to {name}")),
                    Err(f) => (false, f.message),
                };
                if let Some(s) = self.settings.as_mut().filter(|_| self.tab == Tab::Settings) {
                    s.message = Some(msg.clone());
                }
                self.notice = Some(msg);
                self.edit_for = None; // reload fields from the daemon's answer
                self.worker.refresh();
                self.worker.send(Cmd::Inspect(name));
            }
            Event::Adopted(ip, name, result) => match result {
                Ok(id) => {
                    self.adopt = None;
                    self.banner = Some((
                        true,
                        format!(
                            "Adopted {ip} as '{name}'. Next: compare and trust its host key (nothing is trusted automatically)."
                        ),
                    ));
                    self.worker.refresh();
                    self.worker.send(Cmd::Discovered);
                    self.select(id);
                }
                Err(f) => {
                    if let Some(a) = self.adopt.as_mut().filter(|a| a.host.ip == ip) {
                        a.busy = false;
                        a.error = Some(f.message.clone());
                    }
                }
            },
            Event::Sites(r) => self.sites_report = Some(r),
            Event::SiteModeSet(r) => {
                match &r {
                    Ok(rep) => {
                        self.site_mode = rep.mode.clone();
                        self.sites = rep.sites.clone();
                        self.banner = Some((
                            true,
                            match &rep.mode {
                                SiteMode::Auto => "Site: automatic detection".to_string(),
                                SiteMode::Manual(id) => format!(
                                    "Site: {} (chosen by hand; Auto returns to detection)",
                                    self.site_name(id)
                                ),
                            },
                        ));
                    }
                    Err(f) => self.banner = Some((false, f.message.clone())),
                }
                self.sites_report = Some(r);
                self.worker.refresh();
            }
            Event::TrustPreview(name, result) => {
                let mismatch = self
                    .devices
                    .iter()
                    .any(|d| d.id == name && d.identity == IdentityState::Mismatch);
                if let Some(p) = self.trust.as_mut().filter(|p| p.device == name) {
                    p.loading = false;
                    match result {
                        Ok(r) => p.plan = Some(TrustPlan::from_preview(&r, mismatch)),
                        Err(f) => p.error = Some(f.message),
                    }
                }
            }
            Event::TrustPinned(name, result) => {
                if let Some(p) = self.trust.as_mut().filter(|p| p.device == name) {
                    p.pinning = false;
                    match result {
                        Ok(r) => {
                            p.done = Some(format!(
                                "{}: {} ({} key(s) pinned). Next: test the SSH login.",
                                r.device,
                                r.action,
                                r.pinned_now.len()
                            ));
                            p.plan = None;
                            p.error = None;
                        }
                        Err(f) => p.error = Some(f.message),
                    }
                }
                self.worker.refresh();
                self.worker.send(Cmd::Inspect(name));
            }
            Event::Doctor(scope, result) => self.doctor.finished(scope, result),
            Event::Ran(name, result) => {
                if self.selected.as_deref() == Some(&name) {
                    self.run.busy = false;
                    self.run.result = Some(result);
                }
            }
            Event::TestSsh(name, result) => {
                if let Some(t) = self.test_ssh.as_mut().filter(|t| t.device == name) {
                    t.busy = false;
                    t.result = Some(result);
                }
                self.worker.refresh();
            }
            Event::Setup(steps) => {
                if let Some(w) = self.wizard.as_mut() {
                    w.finished(steps);
                }
                self.terminal = load_terminal(&self.config_path);
                self.worker.refresh();
            }
            Event::Service(st) => {
                self.service_busy = false;
                if let Some(s) = self.settings.as_mut() {
                    s.service = Some(st.clone());
                    s.service_busy = false;
                }
                self.service = Some(st);
            }
            Event::ServiceDone(action, r) => {
                self.banner = Some(match r {
                    Ok(()) => (true, format!("service: {action} done")),
                    Err(e) => (false, format!("service: {action} failed: {e}")),
                });
                self.worker.send(Cmd::Service);
                self.worker.refresh();
            }
            Event::ConfigSaved(r) => {
                if let Some(s) = self.settings.as_mut() {
                    s.saved(r);
                }
                self.terminal = load_terminal(&self.config_path);
                self.worker.refresh();
            }
        }
    }

    // ---- top bar ---------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("LabLink");
            self.site_selector(ui);
            let here = self.visible_devices().len();
            for (tab, name) in [
                (Tab::Devices, format!("Devices ({here})")),
                (Tab::Discovered, "Discovered".to_string()),
                (Tab::Health, "Health".to_string()),
                (Tab::Sites, "Sites".to_string()),
                (Tab::Settings, "Settings".to_string()),
            ] {
                if ui.selectable_value(&mut self.tab, tab, name).clicked() {
                    match tab {
                        Tab::Discovered => self.worker.send(Cmd::Discovered),
                        Tab::Settings | Tab::Sites => {
                            if self.settings.is_none() {
                                self.settings = Some(Settings::load(self.config_path.clone()));
                            }
                            self.worker.send(Cmd::Service);
                            self.worker.send(Cmd::Sites);
                        }
                        _ => self.refresh(),
                    }
                }
            }
            ui.separator();
            if ui
                .add_enabled(
                    !self.discover_busy && self.poll_error.is_none(),
                    egui::Button::new("Discover"),
                )
                .on_hover_text("Look for hosts on the networks you allowed")
                .clicked()
            {
                self.start_discover();
            }
            if self.discover_busy {
                ui.spinner();
                ui.label("discovering (up to about 60 s)...");
            }
            if ui.button("Refresh").clicked() {
                self.refresh();
            }
            ui.with_layout(
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| match (&self.daemon_version, self.daemon_uptime_s) {
                    (Some(v), Some(up)) => {
                        ui.weak(format!("lablinkd {v}, up {}", format_age(up * 1000)));
                    }
                    _ => {
                        ui.weak("lablinkd: no data");
                    }
                },
            );
        });
        if let Some(warning) = &self.daemon_build_warning {
            ui.colored_label(view::YELLOW, warning);
        }
        if let Some(f) = self.poll_error.clone() {
            if f.unavailable {
                self.daemon_down(ui);
            } else {
                ui.colored_label(view::RED, format!("daemon error: {}", f.message));
            }
        }
        let mut dismiss = false;
        if let Some((ok, msg)) = &self.banner {
            ui.horizontal(|ui| {
                ui.colored_label(if *ok { view::GREEN } else { view::RED }, msg);
                dismiss = ui.small_button("dismiss").clicked();
            });
        }
        if dismiss {
            self.banner = None;
        }
        ui.add_space(2.0);
    }

    /// What failed, what still works, and the one button that fixes it.
    fn daemon_down(&mut self, ui: &mut egui::Ui) {
        let no_config = lablink_setup::init::needs_setup(&self.config_path);
        let mut act: Option<&'static str> = None;
        let mut setup = false;
        egui::Frame::new()
            .fill(Color32::from_rgb(150, 30, 40))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                let white = |t: String| RichText::new(t).color(Color32::WHITE);
                ui.label(white("The LabLink daemon is not running".into()).strong());
                ui.label(white(format!(
                    "Nothing is being monitored right now. Your devices, pinned keys and history are kept in {}.",
                    lablink_core::paths::default_state_dir().display()
                )));
                ui.horizontal(|ui| {
                    if no_config {
                        ui.label(white("LabLink is not set up yet.".into()));
                        setup = ui.button("Run setup").clicked();
                        return;
                    }
                    match &self.service {
                        Some(s) if !s.systemd => {
                            ui.label(white("No systemd user session here: start it with `lablinkd &` in a terminal.".into()));
                        }
                        Some(s) if s.unit.is_none() => {
                            ui.label(white("The background service is not installed.".into()));
                            if ui.add_enabled(!self.service_busy, egui::Button::new("Install and start")).clicked() {
                                act = Some("install");
                            }
                        }
                        Some(_) => {
                            ui.label(white("The service is installed but stopped (see `journalctl --user -u lablinkd`).".into()));
                            if ui.add_enabled(!self.service_busy, egui::Button::new("Start daemon")).clicked() {
                                act = Some("start");
                            }
                        }
                        None => {
                            ui.label(white("Checking the service...".into()));
                        }
                    }
                    if self.service_busy {
                        ui.spinner();
                    }
                });
            });
        if setup {
            self.wizard = Some(Wizard::new(self.config_path.clone(), self.socket.clone()));
        }
        if let Some(a) = act {
            self.service_busy = true;
            self.worker.send(Cmd::ServiceControl(a));
        }
    }

    // ---- device cards ----------------------------------------------------

    fn device_list(&mut self, ui: &mut egui::Ui) {
        if self.poll_error.is_some() {
            return;
        }
        if self.view == SiteView::All {
            self.all_sites_view(ui);
            return;
        }
        if self.devices.is_empty() && self.sites.iter().all(|s| s.devices.total == 0) {
            if self.sites.is_empty() {
                self.getting_started(ui);
            } else {
                self.site_header(ui);
                self.getting_started(ui);
            }
            return;
        }
        self.site_header(ui);
        let shown = self.visible_devices();
        let mut clicked = None;
        let mut goto: Option<SiteView> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if shown.is_empty() {
                    ui.weak("No devices here yet.");
                }
                for d in &shown {
                    if card(
                        ui,
                        d,
                        self.selected.as_deref() == Some(&d.id),
                        &self.devices,
                    ) {
                        clicked = Some(d.id.clone());
                    }
                }
                // Other sites: summarized, never as failures.
                let others: Vec<&SiteStatus> = self
                    .sites
                    .iter()
                    .filter(|s| match &self.view {
                        SiteView::Current => s.state == SiteState::Away,
                        SiteView::Site(id) => &s.id != id,
                        SiteView::All => false,
                    })
                    .collect();
                if !others.is_empty() {
                    ui.add_space(10.0);
                    ui.label(RichText::new("Other Sites").strong());
                    for s in others {
                        ui.horizontal(|ui| {
                            site_dot(ui, s);
                            if ui
                                .link(RichText::new(&s.name).strong())
                                .on_hover_text("Show this site's devices (does not switch sites)")
                                .clicked()
                            {
                                goto = Some(SiteView::Site(s.id.clone()));
                            }
                            ui.weak(site_state_text(s));
                            ui.weak(format!("{} device(s)", s.devices.total));
                        });
                    }
                }
            });
        if let Some(v) = goto {
            self.view = v;
        }
        if let Some(name) = clicked {
            self.select(name);
            // Lay out the details panel now, not at the next poll.
            ui.ctx().request_repaint();
        }
    }

    /// Devices of the current view.
    fn visible_devices(&self) -> Vec<DeviceStatus> {
        self.devices
            .iter()
            .filter(|d| match &self.view {
                SiteView::Current => d.site_state != SiteState::Away,
                SiteView::Site(id) => &d.site == id,
                SiteView::All => true,
            })
            .cloned()
            .collect()
    }

    fn site_name(&self, id: &str) -> String {
        self.sites
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    /// Top-level site selector: sites (choosing one = manual override),
    /// Auto, All Sites, Manage Sites.
    fn site_selector(&mut self, ui: &mut egui::Ui) {
        if self.sites.is_empty() {
            return;
        }
        let active: Vec<&SiteStatus> = self
            .sites
            .iter()
            .filter(|s| s.state == SiteState::Active)
            .collect();
        let current = match (&self.view, active.as_slice()) {
            (SiteView::All, _) => "All Sites".to_string(),
            (SiteView::Site(id), _) => format!("{} (viewing)", self.site_name(id)),
            (_, [one]) => one.name.clone(),
            (_, []) => "No active site".to_string(),
            (_, many) => many
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(" + "),
        };
        let mut choose: Option<Option<String>> = None;
        let mut view: Option<SiteView> = None;
        let mut manage = false;
        let all = self.view == SiteView::All;
        egui::ComboBox::from_id_salt("site_selector")
            .selected_text(current)
            .width(220.0)
            .show_ui(ui, |ui| {
                for s in &self.sites {
                    let text = format!("{}  ({})", s.name, site_state_text(s));
                    // One highlighted row: the view when showing all sites,
                    // otherwise the mode in effect.
                    let on = !all && self.site_mode == SiteMode::Manual(s.id.clone());
                    if ui
                        .selectable_label(on, text)
                        .on_hover_text("Use this site (manual override)")
                        .clicked()
                    {
                        choose = Some(Some(s.id.clone()));
                        view = Some(SiteView::Current);
                    }
                }
                ui.separator();
                if ui
                    .selectable_label(!all && self.site_mode == SiteMode::Auto, "Auto")
                    .on_hover_text("Detect the site from network signals (the default)")
                    .clicked()
                {
                    choose = Some(None);
                    view = Some(SiteView::Current);
                }
                if ui.selectable_label(all, "All Sites").clicked() {
                    view = Some(SiteView::All);
                }
                if ui.selectable_label(false, "Manage Sites...").clicked() {
                    manage = true;
                }
            });
        if let Some(c) = choose {
            self.worker.send(Cmd::SetSiteMode(c));
        }
        if let Some(v) = view {
            self.view = v;
            self.tab = Tab::Devices;
        }
        if manage {
            self.tab = Tab::Sites;
            if self.settings.is_none() {
                self.settings = Some(Settings::load(self.config_path.clone()));
            }
            self.worker.send(Cmd::Sites);
        }
    }

    /// "Site Alpha  READY" above the device cards.
    fn site_header(&mut self, ui: &mut egui::Ui) {
        let shown: Vec<SiteStatus> = match &self.view {
            SiteView::Current => self
                .sites
                .iter()
                .filter(|s| s.state != SiteState::Away)
                .cloned()
                .collect(),
            SiteView::Site(id) => self.sites.iter().filter(|s| &s.id == id).cloned().collect(),
            SiteView::All => return,
        };
        if shown.is_empty() && !self.sites.is_empty() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("No active site").strong().size(18.0));
                ui.label("LabLink does not recognize this place, so it checks no device and reports none as failed. Pick your site in the selector above if you are at one.");
            });
            return;
        }
        for s in shown {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&s.name).strong().size(20.0));
                let (word, color) = site_readiness(&s);
                ui.label(RichText::new(word).strong().color(color));
                ui.weak(format!(
                    "{}{}",
                    match s.selected_by {
                        lablink_core::site::SelectedBy::Manual => "chosen by hand".to_string(),
                        lablink_core::site::SelectedBy::OnlySite => "only site".to_string(),
                        lablink_core::site::SelectedBy::Auto =>
                            format!("auto, confidence {}", s.confidence.as_str()),
                    },
                    if s.contested {
                        "; another site matches too"
                    } else {
                        ""
                    }
                ));
                if let SiteView::Site(_) = self.view {
                    if s.state != SiteState::Active && ui.button("Use this site").clicked() {
                        self.worker.send(Cmd::SetSiteMode(Some(s.id.clone())));
                        self.view = SiteView::Current;
                    }
                    if ui.button("Back").clicked() {
                        self.view = SiteView::Current;
                    }
                }
            });
        }
        ui.add_space(4.0);
    }

    /// Every site at a glance; AWAY sites are listed, never as failures.
    fn all_sites_view(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("All Sites").strong().size(20.0));
        ui.weak(
            "AWAY sites are not checked while you are elsewhere, so they never count as failures.",
        );
        ui.add_space(6.0);
        let mut goto = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for s in &self.sites {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            site_dot(ui, s);
                            ui.label(RichText::new(&s.name).strong().size(16.0));
                            let (word, color) = site_readiness(s);
                            ui.label(RichText::new(word).strong().color(color));
                            ui.weak(&s.id);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Show devices").clicked() {
                                        goto = Some(SiteView::Site(s.id.clone()));
                                    }
                                },
                            );
                        });
                        let c = s.devices;
                        ui.label(if s.state == SiteState::Away {
                            format!("{} device(s), not checked while away", c.total)
                        } else {
                            format!(
                                "{} device(s): {} green, {} yellow, {} red, {} gray",
                                c.total, c.green, c.yellow, c.red, c.gray
                            )
                        });
                        let nets: Vec<String> = s
                            .networks
                            .iter()
                            .map(|n| {
                                format!(
                                    "{} {}{}",
                                    n.name,
                                    n.cidr,
                                    if n.attached { " (attached)" } else { "" }
                                )
                            })
                            .collect();
                        if !nets.is_empty() {
                            ui.weak(format!("networks: {}", nets.join(", ")));
                        }
                    });
                }
            });
        if let Some(v) = goto {
            self.view = v;
        }
    }

    fn getting_started(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.label(RichText::new("No devices yet").strong().size(18.0));
        ui.label(RichText::new("Discover  ->  Adopt  ->  Trust  ->  Connect").strong());
        ui.add_space(6.0);
        ui.label("1. Discover finds hosts on the networks you allowed in Settings.");
        ui.label("2. On the Discovered tab, Adopt the hosts you want and give each a name.");
        ui.label("3. Trust each one after comparing its host-key fingerprint with the device.");
        ui.label("4. Connect by name: Open SSH terminal, or `lablink ssh <name>`.");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.discover_busy, egui::Button::new("Discover now"))
                .clicked()
            {
                self.start_discover();
            }
            if ui.button("Settings").clicked() {
                self.tab = Tab::Settings;
                if self.settings.is_none() {
                    self.settings = Some(Settings::load(self.config_path.clone()));
                }
                self.worker.send(Cmd::Service);
            }
        });
    }

    // ---- details panel ---------------------------------------------------

    fn details(&mut self, ui: &mut egui::Ui) {
        let Some(name) = self.selected.clone() else {
            return;
        };
        let Some(d) = self.devices.iter().find(|d| d.id == name).cloned() else {
            ui.horizontal(|ui| {
                ui.heading(&name);
                if ui.button("Close").clicked() {
                    self.selected = None;
                }
            });
            ui.label("This device is no longer reported by the daemon.");
            return;
        };
        ui.horizontal(|ui| {
            ui.heading(view::title_text(&d));
            ui.label(
                RichText::new(d.color.as_str())
                    .strong()
                    .color(view::state_color(d.color)),
            );
            if let Some(p) = d.profile {
                ui.weak(p.title());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    self.selected = None;
                }
            });
        });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| self.details_body(ui, &d));
    }

    fn details_body(&mut self, ui: &mut egui::Ui, d: &DeviceStatus) {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        // Requests use the canonical site/name: names may repeat across sites.
        let name = d.id.clone();
        let ssh = d.ssh_port != PortState::Disabled;

        // Where the device is in Discover -> Adopt -> Trust -> Connect.
        ui.horizontal_wrapped(|ui| {
            for (i, s) in flow::lifecycle(d).iter().enumerate() {
                if i > 0 {
                    ui.weak("->");
                }
                let (c, l) = match s.state {
                    StepState::Done => (view::GREEN, Level::Good),
                    StepState::Next => (view::YELLOW, Level::Warn),
                    StepState::Later => (view::GRAY, Level::Neutral),
                    StepState::Stop => (view::RED, Level::Bad),
                };
                dot(ui, c, 5.0);
                ui.label(RichText::new(s.title).color(view::level_color(l)))
                    .on_hover_text(&s.hint);
            }
        });

        if let Some(e) = explain::explain(d) {
            self.explanation(ui, d, &e);
        }

        let ip = d.ip.clone();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    ssh && d.identity == IdentityState::Verified,
                    egui::Button::new("Open SSH terminal"),
                )
                .on_disabled_hover_text("Verify and trust the host key before opening SSH")
                .clicked()
            {
                self.open_terminal(&["ssh", &name]);
            }
            let testing = self.test_ssh.as_ref().is_some_and(|t| t.busy);
            if ui
                .add_enabled(
                    ssh && d.identity == IdentityState::Verified && ip.is_some() && !testing,
                    egui::Button::new("Test SSH"),
                )
                .on_hover_text("Log in once in batch mode (keys only) and report the result")
                .clicked()
            {
                self.test_ssh = Some(TestSsh {
                    device: name.clone(),
                    busy: true,
                    result: None,
                });
                self.worker.send(Cmd::TestSsh(name.clone()));
            }
            if ui
                .add_enabled(ip.is_some(), egui::Button::new("Copy IP"))
                .clicked()
            {
                if let Some(ip) = &ip {
                    ui.ctx().copy_text(ip.clone());
                }
            }
            if ssh && ui.button("Trust host key...").clicked() {
                self.start_trust(&name);
            }
            if ui
                .add_enabled(!self.doctor.busy, egui::Button::new("Doctor"))
                .clicked()
            {
                self.start_doctor(name.clone(), vec![name.clone()]);
            }
            if ui.button("History").clicked() {
                self.history_loading = true;
                self.worker.send(Cmd::History(name.clone()));
            }
            if ui.button("Edit settings").clicked() {
                self.show_edit = !self.show_edit;
            }
            let (word, on) = if d.monitoring {
                ("Disable monitoring", false)
            } else {
                ("Enable monitoring", true)
            };
            if ui.button(word).clicked() {
                self.apply_changes(
                    &name,
                    DeviceChanges {
                        monitoring: Some(on),
                        ..Default::default()
                    },
                );
            }
        });
        if let Some((ok, msg)) = &self.notice {
            ui.colored_label(if *ok { view::GREEN } else { view::RED }, msg);
        }
        if let Some(e) = &self.detail_error {
            ui.colored_label(view::RED, e);
        }
        self.trust_section(ui, &name);
        self.test_ssh_section(ui, &name);
        if self.show_edit {
            ui.separator();
            self.edit_section(ui, &name);
        }
        ui.separator();

        match &self.detail {
            Some(det) if det.status.id == name => info_grid(ui, det),
            _ if self.detail_error.is_none() => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("loading...");
                });
            }
            _ => {}
        }
        if let Some(rep) = self.doctor.device(&name) {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong("Doctor");
                ui.colored_label(view::state_color(rep.color), rep.color.as_str());
                ui.weak(format!("{} ms", rep.duration_ms));
            });
            health::check_rows(ui, rep, &name);
        } else if self.doctor.busy && self.doctor.scope == name {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("running read-only checks...");
            });
        }
        self.history_section(ui);
        ui.separator();
        egui::CollapsingHeader::new("Run a command")
            .id_salt(("run", &name))
            .show(ui, |ui| self.run_section(ui, &name));
    }

    fn explanation(&mut self, ui: &mut egui::Ui, d: &DeviceStatus, e: &explain::Explanation) {
        let color = view::state_color(e.color);
        let mut frame = egui::Frame::group(ui.style()).stroke(egui::Stroke::new(2.0, color));
        if e.security_stop {
            frame = frame.fill(Color32::from_rgb(90, 15, 20));
        }
        let mut fix: Option<Fix> = None;
        frame.show(ui, |ui| {
            ui.label(RichText::new(&e.headline).strong().size(16.0).color(color));
            ui.label(&e.summary);
            if !e.failed.is_empty() {
                ui.label(RichText::new("What failed").strong());
                for f in &e.failed {
                    ui.label(format!("  - {f}"));
                }
            }
            if !e.still_works.is_empty() {
                ui.label(RichText::new("What still works").strong());
                for w in &e.still_works {
                    ui.label(format!("  - {w}"));
                }
            }
            ui.label(format!("Likely cause: {}", e.likely_cause));
            ui.label(RichText::new(format!("Next: {}", e.next_step)).strong());
            ui.horizontal_wrapped(|ui| {
                for a in &e.actions {
                    if ui.button(a.label()).clicked() {
                        fix = Some(*a);
                    }
                }
            });
            ui.collapsing("Details", |ui| {
                for r in &d.reasons {
                    ui.monospace(r);
                }
                if let Some(err) = self.detail.as_ref().and_then(|x| x.last_error.clone()) {
                    ui.monospace(format!("last error: {err}"));
                }
                for a in &e.actions {
                    ui.monospace(a.command(d));
                }
            });
        });
        match fix {
            Some(Fix::SshSetup) => self.open_terminal(&["copy-id", &d.id]),
            Some(Fix::Trust) | Some(Fix::TrustReplace) => self.start_trust(&d.id),
            Some(Fix::Discover) => self.start_discover(),
            Some(Fix::SwitchSite) => {
                self.worker.send(Cmd::SetSiteMode(Some(d.site.clone())));
                self.view = SiteView::Current;
            }
            Some(Fix::EnableMonitoring) => self.apply_changes(
                &d.id,
                DeviceChanges {
                    monitoring: Some(true),
                    ..Default::default()
                },
            ),
            Some(Fix::EditSettings) => self.show_edit = true,
            Some(Fix::CheckGateway) => {
                if let Some(gw) = d.via.clone() {
                    self.select(lablink_core::config::device_id(&d.site, &gw));
                }
            }
            None => {}
        }
    }

    fn test_ssh_section(&mut self, ui: &mut egui::Ui, name: &str) {
        let Some(t) = self.test_ssh.as_ref().filter(|t| t.device == name) else {
            return;
        };
        if t.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("testing SSH login (batch mode, keys only)...");
            });
            return;
        }
        match &t.result {
            Some(Ok(r)) if r.exit_code == Some(0) => {
                ui.colored_label(
                    view::GREEN,
                    format!(
                        "SSH login works ({:.1} s). LabLink re-checks it now.",
                        r.duration.as_secs_f32()
                    ),
                );
            }
            Some(Ok(r)) => {
                let why = lablink_ssh::classify_ssh_failure(&r.stderr);
                ui.colored_label(view::RED, format!("SSH test failed: {}", why.describe()));
                ui.label(why.advice(name));
                if matches!(why, lablink_ssh::SshFailure::AuthFailed { .. })
                    && ui.button("SSH Setup").clicked()
                {
                    let n = name.to_string();
                    self.open_terminal(&["copy-id", &n]);
                }
            }
            Some(Err(f)) => {
                ui.colored_label(view::RED, format!("SSH test refused: {}", f.message));
            }
            None => {}
        }
    }

    /// Two explicit steps: the scan result is shown first; pinning is a
    /// separate click that confirms exactly the scanned fingerprints.
    fn trust_section(&mut self, ui: &mut egui::Ui, name: &str) {
        let Some(panel) = self.trust.as_mut().filter(|p| p.device == name) else {
            return;
        };
        ui.separator();
        ui.strong("Trust host key");
        if panel.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("scanning host keys (nothing is pinned yet)...");
            });
        }
        if let Some(e) = &panel.error {
            ui.colored_label(view::RED, e);
        }
        if let Some(d) = &panel.done {
            ui.colored_label(view::GREEN, d);
        }
        let mut pin: Option<(Vec<String>, bool)> = None;
        let mut close = false;
        let pinning = panel.pinning;
        if let Some(plan) = panel.plan.as_mut() {
            ui.label(format!("{} at {} presents:", plan.device, plan.ip));
            for k in &plan.scanned {
                ui.monospace(format!("  {} {}", k.key_type, k.fingerprint));
            }
            if plan.pinned_before.is_empty() {
                ui.label("currently pinned: nothing");
            } else {
                ui.label("currently pinned:");
                for k in &plan.pinned_before {
                    ui.monospace(format!(
                        "  {} {} [{}]",
                        k.key_type,
                        k.fingerprint,
                        k.source.as_deref().unwrap_or("")
                    ));
                }
            }
            ui.label("Compare with the device itself before pinning. On its console or a session you already trust, run:");
            ui.monospace("  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub");
            if plan.warn() {
                ui.colored_label(
                    view::RED,
                    "WARNING: the host key differs from what is pinned. This can mean a reinstalled machine or someone impersonating it.",
                );
            }
            if plan.replace_required {
                ui.checkbox(
                    &mut plan.verified_oob,
                    "I verified this host out of band; replace pinned keys",
                );
            }
            ui.horizontal(|ui| {
                let label = format!("Pin {} key(s)", plan.scanned.len());
                if ui
                    .add_enabled(plan.can_pin() && !pinning, egui::Button::new(label))
                    .clicked()
                {
                    pin = plan.request();
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        } else if !panel.loading && ui.button("Close").clicked() {
            close = true;
        }
        if let Some((confirm, replace)) = pin {
            panel.pinning = true;
            panel.error = None;
            self.worker.send(Cmd::TrustPin {
                device: name.to_string(),
                confirm,
                replace,
            });
        }
        if close {
            self.trust = None;
        }
    }

    fn history_section(&self, ui: &mut egui::Ui) {
        if self.history_loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("loading history...");
            });
        }
        match &self.history {
            Some(Ok(events)) => {
                ui.separator();
                ui.strong(format!("History ({} events)", events.len()));
                egui::ScrollArea::vertical()
                    .id_salt("history")
                    .max_height(220.0)
                    .show(ui, |ui| event_list(ui, events.iter().rev()));
            }
            Some(Err(f)) => {
                ui.colored_label(view::RED, &f.message);
            }
            None => {}
        }
    }

    fn edit_section(&mut self, ui: &mut egui::Ui, name: &str) {
        ui.strong("Device settings");
        let loaded = self.edit_for.as_deref() == Some(name);
        let adopted = self
            .detail
            .as_ref()
            .is_some_and(|d| d.status.id == name && !d.configured);
        ui.add_enabled_ui(loaded, |ui| {
            egui::Grid::new("edit").num_columns(2).show(ui, |ui| {
                ui.label("Label");
                ui.text_edit_singleline(&mut self.edit.label);
                ui.end_row();
                ui.label("SSH username");
                ui.add_enabled(
                    self.edit.ssh,
                    egui::TextEdit::singleline(&mut self.edit.username),
                );
                ui.end_row();
                ui.label("Type");
                egui::ComboBox::from_id_salt("edit_profile")
                    .selected_text(self.edit.profile.map_or("(none)", |p| p.title()))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.edit.profile, None, "(none)");
                        for p in Profile::ALL {
                            ui.selectable_value(&mut self.edit.profile, Some(p), p.title())
                                .on_hover_text(p.summary());
                        }
                    });
                ui.end_row();
                ui.label("SSH");
                ui.add_enabled(
                    adopted,
                    egui::Checkbox::new(&mut self.edit.ssh, "LabLink logs in over SSH"),
                )
                .on_disabled_hover_text("set `ssh:` in the config file for devices defined there");
                ui.end_row();
                ui.label("Monitoring");
                ui.checkbox(&mut self.edit.monitoring, "enabled");
                ui.end_row();
            });
            if self.edit.profile == Some(Profile::NetworkOnly) {
                self.edit.ssh = false;
            }
            if ui.button("Apply").clicked() {
                match self.edit.changes(&self.edit_orig) {
                    Some(changes) => self.apply_changes(name, changes),
                    None => self.notice = Some((true, "no changes to apply".into())),
                }
            }
        });
        ui.weak(
            "Empty text clears an override. Stored by the daemon; the config file is not changed.",
        );
    }

    fn run_section(&mut self, ui: &mut egui::Ui, name: &str) {
        let mut go = false;
        ui.horizontal(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.run.command)
                    .hint_text("one-line command, e.g. uname -a")
                    .desired_width(ui.available_width() - 70.0),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let can = !self.run.busy && !self.run.command.trim().is_empty();
            go = ui.add_enabled(can, egui::Button::new("Run")).clicked() || (enter && can);
        });
        if go {
            self.run.busy = true;
            self.run.result = None;
            self.worker.send(Cmd::Run {
                device: name.to_string(),
                command: self.run.command.trim().to_string(),
            });
        }
        if self.run.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("running (30 s limit)...");
            });
        }
        match &self.run.result {
            Some(Ok(r)) => {
                let status = if r.timed_out {
                    "timed out".to_string()
                } else if let Some(c) = r.exit_code {
                    format!("exit code {c}")
                } else if let Some(s) = r.signal {
                    format!("killed by signal {s}")
                } else {
                    "no exit status".to_string()
                };
                let color = if r.exit_code == Some(0) {
                    view::GREEN
                } else {
                    view::RED
                };
                ui.colored_label(
                    color,
                    format!("{status} ({:.1} s)", r.duration.as_secs_f32()),
                );
                if r.truncated {
                    ui.colored_label(view::YELLOW, "output truncated");
                }
                egui::ScrollArea::both()
                    .id_salt("run_out")
                    .max_height(260.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.strong("stdout");
                        ui.monospace(&r.stdout);
                        ui.strong("stderr");
                        ui.monospace(&r.stderr);
                    });
            }
            Some(Err(f)) => {
                ui.colored_label(view::RED, format!("refused: {}", f.message));
            }
            None => {}
        }
    }

    // ---- discovered hosts + discovery report -----------------------------

    fn discovered_view(&mut self, ui: &mut egui::Ui) {
        if let Some(e) = &self.discovered_error {
            ui.colored_label(view::RED, e);
        }
        let (unmatched, matched) = flow::split_discovered(&self.discovered);
        let mut adopt_req: Option<DiscoveredHost> = None;
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.strong(format!(
                    "Not tracked ({}): inspect a host, then adopt it to start monitoring",
                    unmatched.len()
                ));
                if unmatched.is_empty() {
                    ui.weak("Nothing new. Press Discover to look again, or check the allowed networks in Settings.");
                }
                egui::Grid::new("discovered")
                    .striped(true)
                    .num_columns(8)
                    .show(ui, |ui| {
                        for h in [
                            "IP", "MAC", "Hostname", "SSH", "Network", "Sources", "Note", "",
                        ] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for h in &unmatched {
                            host_cells(ui, h);
                            if ui.button("Inspect / Adopt...").clicked() {
                                adopt_req = Some((*h).clone());
                            }
                            ui.end_row();
                        }
                    });
                if !matched.is_empty() {
                    ui.add_space(8.0);
                    ui.strong(format!("Already tracked ({})", matched.len()));
                    egui::Grid::new("discovered_matched")
                        .striped(true)
                        .num_columns(8)
                        .show(ui, |ui| {
                            for h in [
                                "IP", "MAC", "Hostname", "SSH", "Network", "Sources", "Note",
                                "Device",
                            ] {
                                ui.strong(h);
                            }
                            ui.end_row();
                            for h in &matched {
                                host_cells(ui, h);
                                ui.label(h.matched_device.as_deref().unwrap_or("-"));
                                ui.end_row();
                            }
                        });
                }
            });
        if let Some(h) = adopt_req {
            // Default site: the one whose network the host is on, else the
            // active site.
            let site = h.site.clone().or_else(|| {
                let active: Vec<&SiteStatus> = self
                    .sites
                    .iter()
                    .filter(|s| s.state == SiteState::Active)
                    .collect();
                match active.as_slice() {
                    [one] => Some(one.id.clone()),
                    _ => self.sites.first().map(|s| s.id.clone()),
                }
            });
            self.adopt = Some(AdoptDialog {
                form: AdoptForm::for_host(&h),
                host: h,
                site,
                busy: false,
                error: None,
            });
        }
    }

    fn adopt_window(&mut self, ctx: &egui::Context) {
        let Some(dlg) = self.adopt.as_mut() else {
            return;
        };
        // Names only need to be unique within the chosen site.
        let existing: Vec<String> = self
            .devices
            .iter()
            .filter(|d| Some(&d.site) == dlg.site.as_ref())
            .map(|d| d.name.clone())
            .collect();
        let form_err = dlg.form.error(&existing);
        let sites: Vec<(String, String)> = self
            .sites
            .iter()
            .map(|s| (s.id.clone(), s.name.clone()))
            .collect();
        let mut send = false;
        let mut cancel = false;
        egui::Window::new("Inspect and adopt host")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                let h = &dlg.host;
                egui::Grid::new("adopt_info").num_columns(2).show(ui, |ui| {
                    ui.label("IP");
                    ui.monospace(&h.ip);
                    ui.end_row();
                    ui.label("MAC");
                    ui.monospace(h.mac.as_deref().unwrap_or("-"));
                    ui.end_row();
                    ui.label("Hostname");
                    ui.label(h.hostname.as_deref().unwrap_or("-"));
                    ui.end_row();
                    ui.label("Network");
                    ui.label(format!(
                        "{} {}",
                        h.network_name.as_deref().unwrap_or("-"),
                        h.interface.as_deref().map(|i| format!("({i})")).unwrap_or_default()
                    ));
                    ui.end_row();
                    ui.label("Seen by");
                    ui.label(h.sources.join(", "));
                    ui.end_row();
                    ui.label("SSH port");
                    ui.label(view::port_word(h.ssh_port));
                    ui.end_row();
                    ui.label("SSH fingerprints");
                    ui.vertical(|ui| {
                        if h.fingerprints.is_empty() {
                            ui.label("-");
                        }
                        for f in &h.fingerprints {
                            ui.monospace(f);
                        }
                    });
                    ui.end_row();
                });
                ui.separator();
                let f = &mut dlg.form;
                let site = &mut dlg.site;
                egui::Grid::new("adopt_form").num_columns(2).show(ui, |ui| {
                    if !sites.is_empty() {
                        ui.label("Site");
                        let shown = site
                            .as_ref()
                            .and_then(|id| sites.iter().find(|(i, _)| i == id))
                            .map_or("(choose)".to_string(), |(_, n)| n.clone());
                        egui::ComboBox::from_id_salt("adopt_site")
                            .selected_text(shown)
                            .show_ui(ui, |ui| {
                                for (id, n) in &sites {
                                    ui.selectable_value(site, Some(id.clone()), n);
                                }
                            });
                        ui.end_row();
                    }
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut f.name).hint_text("e.g. bench-pc"));
                    ui.end_row();
                    ui.label("Label");
                    ui.add(egui::TextEdit::singleline(&mut f.label).hint_text("optional"));
                    ui.end_row();
                    ui.label("Type");
                    egui::ComboBox::from_id_salt("adopt_profile")
                        .selected_text(f.profile.map_or("(none)", |p| p.title()))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut f.profile, None, "(none)");
                            for p in Profile::ALL {
                                ui.selectable_value(&mut f.profile, Some(p), p.title())
                                    .on_hover_text(p.summary());
                            }
                        });
                    ui.end_row();
                    if f.profile == Some(Profile::NetworkOnly) {
                        f.ssh = false;
                    }
                    ui.label("SSH");
                    ui.add_enabled(
                        f.profile.is_none_or(|p| p.uses_ssh()),
                        egui::Checkbox::new(&mut f.ssh, "this host runs an SSH server LabLink may log in to"),
                    );
                    ui.end_row();
                    ui.label("SSH username");
                    ui.add_enabled(
                        f.ssh,
                        egui::TextEdit::singleline(&mut f.username)
                            .hint_text("optional; your ~/.ssh/config decides otherwise"),
                    );
                    ui.end_row();
                });
                if !dlg.form.name.is_empty() {
                    if let Some(e) = &form_err {
                        ui.colored_label(view::RED, e);
                    }
                }
                ui.weak("Adopting only starts tracking. It never trusts the host key: you compare and pin it in the next step.");
                if let Some(e) = &dlg.error {
                    ui.colored_label(view::RED, e);
                }
                if dlg.busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("adopting...");
                    });
                }
                ui.horizontal(|ui| {
                    let ok = form_err.is_none() && !dlg.busy;
                    if ui.add_enabled(ok, egui::Button::new("Adopt")).clicked() {
                        send = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if send {
            dlg.busy = true;
            dlg.error = None;
            let (label, username, profile, ssh) = dlg.form.request();
            self.worker.send(Cmd::Adopt {
                ip: dlg.host.ip.clone(),
                name: dlg.form.name.trim().to_string(),
                label,
                username,
                profile,
                ssh,
                site: dlg.site.clone(),
            });
        }
        if cancel {
            self.adopt = None;
        }
    }

    fn discover_window(&mut self, ctx: &egui::Context) {
        if !self.show_discover {
            return;
        }
        let mut open = true;
        let mut go_discovered = false;
        egui::Window::new("Discovery result")
            .open(&mut open)
            .default_size([560.0, 320.0])
            .show(ctx, |ui| match &self.discover_report {
                Some(Ok(r)) => {
                    let new = r
                        .discovered
                        .iter()
                        .filter(|h| h.matched_device.is_none())
                        .count();
                    ui.label(format!(
                        "probed {} host(s), {} responsive, {} not tracked yet",
                        r.probed_hosts, r.responsive_hosts, new
                    ));
                    if new > 0 && ui.button(format!("Show the {new} new host(s)")).clicked() {
                        go_discovered = true;
                    }
                    egui::Grid::new("stages").striped(true).show(ui, |ui| {
                        for h in ["Stage", "Result", "Time", "Detail"] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for s in &r.stages {
                            ui.label(&s.stage);
                            let c = match s.result.as_str() {
                                "ok" => view::GREEN,
                                "skipped" => view::GRAY,
                                _ => view::RED,
                            };
                            ui.colored_label(c, &s.result);
                            ui.label(format!("{} ms", s.duration_ms));
                            ui.label(&s.detail);
                            ui.end_row();
                        }
                    });
                }
                Some(Err(f)) => {
                    ui.colored_label(view::RED, &f.message);
                }
                None => {}
            });
        self.show_discover = open && !go_discovered;
        if go_discovered {
            self.tab = Tab::Discovered;
            self.worker.send(Cmd::Discovered);
        }
    }

    fn sites_tab(&mut self, ui: &mut egui::Ui) {
        if self.settings.is_none() {
            self.settings = Some(Settings::load(self.config_path.clone()));
            self.worker.send(Cmd::Service);
        }
        let report = self
            .sites_report
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .cloned();
        let actions = self
            .settings
            .as_mut()
            .map(|s| s.sites_ui(ui, report.as_ref()))
            .unwrap_or_default();
        self.settings_actions(actions);
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        if self.settings.is_none() {
            self.settings = Some(Settings::load(self.config_path.clone()));
            self.worker.send(Cmd::Service);
        }
        let devices = self.devices.clone();
        let actions = self
            .settings
            .as_mut()
            .map(|s| s.ui(ui, &devices))
            .unwrap_or_default();
        self.settings_actions(actions);
    }

    fn settings_actions(&mut self, actions: Vec<settings::Action>) {
        for a in actions {
            match a {
                settings::Action::Save(cfg) => {
                    if let Some(settings) = &self.settings {
                        self.worker.send(Cmd::SaveConfig {
                            cfg,
                            expected: Box::new(settings.orig.clone()),
                            path: self.config_path.clone(),
                        });
                    }
                }
                settings::Action::Service(a) => {
                    if let Some(s) = self.settings.as_mut() {
                        s.service_busy = true;
                    }
                    self.worker.send(Cmd::ServiceControl(a));
                }
                settings::Action::RefreshService => self.worker.send(Cmd::Service),
                settings::Action::ApplyDevice(n, c) => self.apply_changes(&n, c),
                settings::Action::Reload => {
                    self.settings = Some(Settings::load(self.config_path.clone()));
                    self.worker.send(Cmd::Service);
                }
                settings::Action::RefreshSites => self.worker.send(Cmd::Sites),
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Idle cost: one repaint per poll interval (and one per worker result).
        ctx.request_repaint_after(POLL_INTERVAL);
        if let Some(w) = self.wizard.as_mut() {
            let mut action = None;
            egui::CentralPanel::default_margins().show(ui, |ui| action = w.ui(ui));
            match action {
                Some(wizard::Action::Apply(opts)) => self.worker.send(Cmd::Setup(Box::new(opts))),
                Some(wizard::Action::Discover) => {
                    self.wizard = None;
                    self.settings = None;
                    self.start_discover();
                }
                Some(wizard::Action::Close) => {
                    self.wizard = None;
                    self.settings = None;
                }
                None => {}
            }
            return;
        }
        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        if self.selected.is_some() && self.tab == Tab::Devices {
            let max_width = (ui.available_width() * 0.65).max(240.0);
            egui::Panel::right("details")
                .resizable(true)
                .default_size(460.0_f32.min(max_width))
                .max_size(max_width)
                .show(ui, |ui| self.details(ui));
        }
        egui::CentralPanel::default_margins().show(ui, |ui| match self.tab {
            Tab::Devices => self.device_list(ui),
            Tab::Discovered => self.discovered_view(ui),
            Tab::Health => {
                // The site(s) you are at: AWAY devices are not checked.
                let devices: Vec<DeviceStatus> = self
                    .devices
                    .iter()
                    .filter(|d| d.site_state != SiteState::Away)
                    .cloned()
                    .collect();
                match health::ui(ui, &self.doctor, &devices) {
                    Some(health::Action::RunAll) => self.start_doctor("all".into(), Vec::new()),
                    Some(health::Action::RunOne(n)) => self.start_doctor(n.clone(), vec![n]),
                    Some(health::Action::Select(n)) => self.select(n),
                    None => {}
                }
            }
            Tab::Settings => self.settings_tab(ui),
            Tab::Sites => self.sites_tab(ui),
        });
        self.discover_window(&ctx);
        self.adopt_window(&ctx);
    }
}

// ---- free drawing helpers ------------------------------------------------

/// Stand-in until the first detail arrives.
fn placeholder() -> DeviceStatus {
    DeviceStatus {
        name: String::new(),
        id: String::new(),
        site: "default".into(),
        site_name: "Default".into(),
        site_state: lablink_core::site::SiteState::Active,
        label: None,
        color: Color::Gray,
        ip: None,
        discovery: lablink_core::model::DiscoveryState::NeverSeen,
        network: lablink_core::model::NetworkState::Unknown,
        ssh_port: PortState::Unknown,
        ssh_auth: lablink_core::model::AuthState::Unknown,
        identity: IdentityState::Unknown,
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

fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(radius * 2.0, radius * 2.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius, color);
}

fn site_state_text(s: &SiteStatus) -> String {
    match s.state {
        SiteState::Active => "Active".into(),
        SiteState::Away => "Away".into(),
        SiteState::Unknown => "Not confirmed".into(),
    }
}

fn site_dot(ui: &mut egui::Ui, s: &SiteStatus) {
    let c = match s.state {
        SiteState::Active => view::GREEN,
        SiteState::Unknown => view::YELLOW,
        SiteState::Away => view::GRAY,
    };
    if s.state == SiteState::Away {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
        ui.painter()
            .circle_stroke(rect.center(), 5.0, egui::Stroke::new(1.5, c));
    } else {
        dot(ui, c, 6.0);
    }
}

/// READY / DEGRADED / NOT READY for a site the user is at; AWAY is neutral.
fn site_readiness(s: &SiteStatus) -> (String, Color32) {
    let c = s.devices;
    match s.state {
        SiteState::Away => ("AWAY".into(), view::GRAY),
        SiteState::Unknown => ("NOT CONFIRMED".into(), view::YELLOW),
        SiteState::Active if c.red > 0 => ("NOT READY".into(), view::RED),
        SiteState::Active if c.yellow > 0 || c.gray > 0 => ("DEGRADED".into(), view::YELLOW),
        SiteState::Active => ("READY".into(), view::GREEN),
    }
}

/// One device card. Returns true when clicked. `all` is used to show
/// `site/name` when a name exists at several sites.
fn card(ui: &mut egui::Ui, d: &DeviceStatus, selected: bool, all: &[DeviceStatus]) -> bool {
    let mut frame = egui::Frame::group(ui.style());
    if selected {
        frame = frame.stroke(egui::Stroke::new(2.0, ui.visuals().selection.bg_fill));
    }
    let inner = frame.show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        if !d.monitoring {
            ui.set_opacity(0.5);
        }
        ui.horizontal(|ui| {
            dot(ui, view::state_color(d.color), 14.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let dup = all.iter().filter(|o| o.name == d.name).count() > 1;
                    let title = if dup {
                        format!("{} ({})", view::title_text(d), d.site_name)
                    } else {
                        view::title_text(d)
                    };
                    ui.label(RichText::new(title).strong().size(16.0));
                    let away = d.site_state == SiteState::Away && d.color == Color::Gray;
                    ui.label(
                        RichText::new(if away { "AWAY" } else { d.color.as_str() })
                            .strong()
                            .color(view::state_color(d.color)),
                    );
                    if let Some(p) = d.profile {
                        ui.weak(p.title());
                    }
                    if !d.monitoring {
                        ui.weak("monitoring off");
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(d.ip.as_deref().unwrap_or("no address"));
                    if let Some(gw) = &d.via {
                        ui.weak(format!("via {gw}"));
                    }
                    ui.label(view::latency_text(d.latency_ms));
                    ui.label(view::last_seen_text(d.last_seen_ms));
                });
                ui.horizontal_wrapped(|ui| {
                    for ind in view::indicators(d) {
                        dot(ui, view::level_color(ind.level), 5.0);
                        ui.small(format!("{}: {}", ind.name, ind.word));
                        ui.add_space(6.0);
                    }
                });
                if let Some(e) = explain::explain(d) {
                    ui.colored_label(
                        view::state_color(e.color),
                        format!("{}: {}", e.headline, e.next_step),
                    );
                }
            });
        });
    });
    let id = ui.id().with(("card", &d.id));
    ui.interact(inner.response.rect, id, egui::Sense::click())
        .clicked()
}

fn host_cells(ui: &mut egui::Ui, h: &DiscoveredHost) {
    ui.label(&h.ip);
    ui.label(h.mac.as_deref().unwrap_or("-"));
    ui.label(h.hostname.as_deref().unwrap_or("-"));
    ui.label(view::port_word(h.ssh_port));
    ui.label(h.network_name.as_deref().unwrap_or("-"));
    ui.label(h.sources.join(","));
    ui.label(h.note.as_deref().unwrap_or(""));
}

fn event_list<'a>(ui: &mut egui::Ui, events: impl Iterator<Item = &'a HistoryEvent>) {
    let now = now_ms();
    for e in events {
        ui.monospace(format!(
            "{:>4} ago  {:<12} {}",
            format_age(now.saturating_sub(e.ts_ms)),
            e.kind,
            e.message
        ));
    }
}

fn info_grid(ui: &mut egui::Ui, d: &DeviceDetail) {
    let s = &d.status;
    let or_dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
    let keys = |ui: &mut egui::Ui, list: &[lablink_core::model::KeyView]| {
        if list.is_empty() {
            ui.label("-");
        }
        ui.vertical(|ui| {
            for k in list {
                let src = k
                    .source
                    .as_deref()
                    .map(|s| format!(" [{s}]"))
                    .unwrap_or_default();
                ui.monospace(format!("{} {}{src}", k.key_type, k.fingerprint));
            }
        });
    };
    egui::Grid::new("info")
        .num_columns(2)
        .max_col_width((ui.available_width() - 112.0).max(80.0))
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("Name");
            ui.monospace(&s.name);
            ui.end_row();
            ui.label("Label");
            ui.label(or_dash(&s.label));
            ui.end_row();
            ui.label("State");
            ui.colored_label(view::state_color(s.color), s.color.as_str());
            ui.end_row();
            ui.label("Hostname");
            let mut names: Vec<&str> = Vec::new();
            for n in d
                .hostnames
                .iter()
                .chain(&d.learned_hostnames)
                .chain(&d.mdns_names)
            {
                if !names.contains(&n.as_str()) {
                    names.push(n);
                }
            }
            ui.label(if names.is_empty() {
                "-".into()
            } else {
                names.join(", ")
            });
            ui.end_row();
            ui.label("Current IP");
            ui.monospace(or_dash(&s.ip));
            ui.end_row();
            ui.label("MAC");
            ui.monospace(if d.macs.is_empty() {
                "-".into()
            } else {
                d.macs.join(", ")
            });
            ui.end_row();
            ui.label("Network");
            ui.label(format!(
                "{} / {}",
                or_dash(&s.network_name),
                or_dash(&s.interface)
            ));
            ui.end_row();
            if let Some(g) = &s.via {
                ui.label("Via");
                ui.label(g);
                ui.end_row();
            }
            ui.label("Identity");
            let (iw, il) = view::identity_word(s.identity);
            ui.colored_label(view::level_color(il), iw);
            ui.end_row();
            ui.label("SSH");
            if s.ssh_port == PortState::Disabled {
                ui.label("not used (network-only)");
            } else {
                ui.label(format!(
                    "port {}, login {}",
                    view::port_word(s.ssh_port),
                    view::auth_word(s.ssh_auth)
                ));
            }
            ui.end_row();
            ui.label("SSH username");
            ui.monospace(
                d.active_username
                    .as_deref()
                    .or(s.username.as_deref())
                    .unwrap_or("(from ~/.ssh/config)"),
            );
            ui.end_row();
            ui.label("SSH target");
            ui.monospace(format!(
                "Host {} -> {}:{}",
                d.ssh_host,
                s.ip.as_deref().unwrap_or("?"),
                d.ssh_port
            ));
            ui.end_row();
            ui.label("Latency");
            ui.label(view::latency_text(s.latency_ms));
            ui.end_row();
            ui.label("Last seen");
            ui.label(view::last_seen_text(s.last_seen_ms));
            ui.end_row();
            ui.label("Type");
            ui.label(s.profile.map_or("(none)", |p| p.title()));
            ui.end_row();
            ui.label("Capabilities");
            ui.label(
                s.capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            ui.end_row();
            ui.label("Monitoring");
            ui.label(if s.monitoring { "enabled" } else { "off" });
            ui.end_row();
            ui.label("Pinned keys");
            keys(ui, &d.pinned_keys);
            ui.end_row();
            ui.label("Observed keys");
            keys(ui, &d.observed_keys);
            ui.end_row();
            ui.label("Services");
            ui.vertical(|ui| {
                if s.services.is_empty() {
                    ui.label("-");
                }
                for sv in &s.services {
                    let (w, l) = view::service_word(sv.state);
                    ui.horizontal(|ui| {
                        ui.label(&sv.name);
                        ui.colored_label(view::level_color(l), w);
                        if let Some(dt) = &sv.detail {
                            ui.weak(dt);
                        }
                    });
                }
            });
            ui.end_row();
            ui.label("Addresses");
            ui.vertical(|ui| {
                for a in &d.addresses {
                    let mark = if a.current { " (current)" } else { "" };
                    ui.monospace(format!(
                        "{}{mark}  {}  {}  last seen {} ago",
                        a.ip,
                        a.network_name.as_deref().unwrap_or("-"),
                        a.mac.as_deref().unwrap_or("-"),
                        format_age(a.last_seen_ms_ago)
                    ));
                }
            });
            ui.end_row();
            ui.label("Last error");
            ui.label(or_dash(&d.last_error));
            ui.end_row();
        });
    ui.add_space(4.0);
    ui.strong("Recent events");
    egui::ScrollArea::vertical()
        .id_salt("recent")
        .max_height(140.0)
        .show(ui, |ui| event_list(ui, d.recent_events.iter().rev()));
}
