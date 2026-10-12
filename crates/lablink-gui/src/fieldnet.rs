//! Field Network tab: the app's face of `lablink hotspot`. Every change
//! goes through the same read-only preflight as the CLI first; Start is
//! only offered for the exact settings that were checked, with each
//! warning accepted by hand, and blockers (such as cutting the session
//! this app runs over) cannot be overridden here.

use crate::view::{self, Level};
use crate::worker::{FieldEvent, FieldSnapshot};
use eframe::egui::{self, RichText};
use lablink_core::printable;
use lablink_fieldnet::ops::PlanArgs;
use lablink_fieldnet::preflight::{self, Preflight};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Form {
    pub interface: String,
    pub ssid: String,
    pub subnet: String,
    pub wpa3: bool,
    pub internet: bool,
    pub routing: bool,
}

impl Form {
    pub fn args(&self) -> PlanArgs {
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        PlanArgs {
            interface: opt(&self.interface),
            ssid: opt(&self.ssid),
            subnet: opt(&self.subnet),
            security: if self.wpa3 { "wpa3" } else { "wpa2" }.into(),
            allow_internet_sharing: self.internet,
            allow_routing: self.routing,
        }
    }
}

pub struct FieldPanel {
    pub loading: bool,
    pub snap: Option<Box<FieldSnapshot>>,
    pub form: Form,
    /// The last preflight and the form it was run for.
    pub checked: Option<(Form, Result<Box<Preflight>, String>)>,
    /// Warnings ticked by the user for the current preflight, by their full
    /// text: a warning whose content changes (another connection, more
    /// devices) must be accepted again.
    pub accepted: Vec<String>,
    pub busy: Option<&'static str>,
    pub message: Option<(bool, String)>,
    /// Shown on request only, never logged; dropped on Hide or refresh.
    pub password: Option<String>,
    pub restore: bool,
}

impl Default for FieldPanel {
    fn default() -> Self {
        Self {
            loading: false,
            snap: None,
            form: Form::default(),
            checked: None,
            accepted: Vec::new(),
            busy: None,
            message: None,
            password: None,
            restore: true,
        }
    }
}

pub enum Action {
    Refresh,
    Preflight(PlanArgs),
    Start {
        args: PlanArgs,
        accepted: Vec<String>,
    },
    Stop {
        restore: bool,
    },
    Password,
    OpenSettings,
}

/// The tab's headline state, in the words the spec's GUI uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Headline {
    Connected,
    Warning,
    Failed,
    NotTested,
    Unsupported,
    Off,
}

impl Headline {
    pub fn word(self) -> &'static str {
        match self {
            Headline::Connected => "RUNNING",
            Headline::Warning => "WARNING",
            Headline::Failed => "FAILED",
            Headline::NotTested => "NOT RUNNING",
            Headline::Unsupported => "UNSUPPORTED",
            Headline::Off => "FEATURE OFF",
        }
    }
    pub fn level(self) -> Level {
        match self {
            Headline::Connected => Level::Good,
            Headline::Warning => Level::Warn,
            Headline::Failed => Level::Bad,
            _ => Level::Neutral,
        }
    }
}

pub fn headline(s: &FieldSnapshot) -> Headline {
    if !s.caps.can_host && s.caps.backend != "macos-guided" {
        return Headline::Unsupported;
    }
    if !s.feature_on {
        return Headline::Off;
    }
    match &s.status {
        None => Headline::NotTested,
        Some(Err(_)) => Headline::Failed,
        Some(Ok(st)) if st.out_of_sync => Headline::Warning,
        Some(Ok(st)) if st.active => Headline::Connected,
        Some(Ok(_)) => Headline::NotTested,
    }
}

/// May Start be pressed: a preflight for exactly this form, no blocker,
/// and every warning accepted.
pub fn may_start(p: &FieldPanel) -> bool {
    let Some((form, Ok(pf))) = &p.checked else {
        return false;
    };
    *form == p.form
        && !pf.blocked()
        && pf
            .warnings()
            .iter()
            .all(|w| p.accepted.contains(&w.message))
}

impl FieldPanel {
    pub fn event(&mut self, e: FieldEvent) {
        match e {
            FieldEvent::Snapshot(s) => {
                self.loading = false;
                self.snap = Some(s);
            }
            FieldEvent::Preflight(args, r) => {
                self.busy = None;
                if args == self.form.args() {
                    self.accepted.clear();
                    self.checked = Some((self.form.clone(), r));
                }
            }
            FieldEvent::Started(r) | FieldEvent::Stopped(r) => {
                self.busy = None;
                self.checked = None;
                self.accepted.clear();
                self.password = None;
                self.message = Some(match r {
                    Ok(m) => (true, m),
                    Err(m) => (false, m),
                });
            }
            FieldEvent::Password(r) => match r {
                Ok(p) => self.password = Some(p),
                Err(m) => self.message = Some((false, m)),
            },
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Vec<Action> {
        let mut actions = Vec::new();
        // Wrap to the window, not to the widest row seen inside the scroll area.
        let width = ui.available_width().min(860.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width(width);
                self.body(ui, &mut actions);
            });
        actions
    }

    fn body(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("FIELD NETWORK").strong().size(18.0));
            if let Some(s) = &self.snap {
                let h = headline(s);
                ui.colored_label(view::level_color(h.level()), h.word());
            }
            if ui
                .add_enabled(!self.loading, egui::Button::new("Refresh"))
                .clicked()
            {
                self.loading = true;
                self.password = None;
                actions.push(Action::Refresh);
            }
            if self.loading {
                ui.spinner();
            }
        });
        ui.weak("A temporary WPA2/WPA3 Wi-Fi network this machine hosts through NetworkManager, for places with no usable network. It does not share this machine's internet unless you allow it, opens no service, and never trusts a client that joins.");
        if let Some((ok, m)) = &self.message {
            ui.colored_label(if *ok { view::GREEN } else { view::RED }, m);
        }
        let Some(snap) = self.snap.take() else {
            if !self.loading {
                ui.label("Press Refresh to read this machine's Wi-Fi capabilities (read-only).");
            }
            return;
        };
        self.with_snapshot(ui, &snap, actions);
        self.snap = Some(snap);
    }

    fn with_snapshot(
        &mut self,
        ui: &mut egui::Ui,
        snap: &FieldSnapshot,
        actions: &mut Vec<Action>,
    ) {
        ui.separator();
        capabilities(ui, snap);
        if let Some(g) = &snap.caps.macos {
            ui.separator();
            mac_guide(ui, g);
            return;
        }
        if !snap.caps.can_host {
            return;
        }
        ui.separator();
        if !snap.feature_on {
            ui.label("The Field Network is an optional feature and is off.");
            // Turning the feature off never strands a running network.
            if let Some(Ok(s)) = &snap.status {
                if s.active {
                    ui.colored_label(
                        view::YELLOW,
                        "It is still running: it was started before the feature was turned off.",
                    );
                    status(ui, s);
                    self.stop_controls(ui, actions);
                }
            }
            if ui.button("Turn it on in Settings").clicked() {
                actions.push(Action::OpenSettings);
            }
            return;
        }
        let running = matches!(&snap.status, Some(Ok(s)) if s.active);
        match &snap.status {
            Some(Err(e)) => {
                ui.colored_label(view::RED, format!("Status unavailable: {e}"));
            }
            Some(Ok(s)) => status(ui, s),
            None => {}
        }
        if running {
            self.running_controls(ui, snap, actions);
        } else {
            ui.separator();
            self.start_form(ui, actions);
        }
    }

    fn running_controls(
        &mut self,
        ui: &mut egui::Ui,
        snap: &FieldSnapshot,
        actions: &mut Vec<Action>,
    ) {
        ui.horizontal_wrapped(|ui| match &self.password {
            Some(p) => {
                ui.label("Password:");
                ui.label(RichText::new(p).monospace().strong());
                if ui.button("Hide").clicked() {
                    self.password = None;
                }
            }
            None => {
                if ui.button("Show password").clicked() {
                    actions.push(Action::Password);
                }
            }
        });
        ui.separator();
        ui.strong(format!("Clients ({})", snap.clients.len()));
        clients(ui, snap);
        ui.separator();
        self.stop_controls(ui, actions);
    }

    fn stop_controls(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.restore, "Reconnect the previous network");
            if ui
                .add_enabled(self.busy.is_none(), egui::Button::new("Stop Field Network"))
                .clicked()
            {
                self.busy = Some("stopping");
                self.message = None;
                actions.push(Action::Stop {
                    restore: self.restore,
                });
            }
            if let Some(b) = self.busy {
                ui.spinner();
                ui.label(b);
            }
        });
        ui.weak("Devices on the Field Network lose this machine when it stops. Make sure no robot depends on this link before stopping.");
    }

    fn start_form(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.strong("Start");
        egui::Grid::new("field_form").num_columns(2).show(ui, |ui| {
            ui.label("Adapter");
            ui.add(
                egui::TextEdit::singleline(&mut self.form.interface)
                    .hint_text("automatic")
                    .desired_width(160.0),
            );
            ui.end_row();
            ui.label("Network name");
            ui.add(
                egui::TextEdit::singleline(&mut self.form.ssid)
                    .hint_text("previous, else LabLink-XXXX")
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("Subnet");
            ui.add(
                egui::TextEdit::singleline(&mut self.form.subnet)
                    .hint_text("previous, else first free 10.77.x.0/24")
                    .desired_width(220.0),
            );
            ui.end_row();
            ui.label("Security");
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.form.wpa3, false, "WPA2 (default)");
                ui.radio_value(&mut self.form.wpa3, true, "WPA3 (opt-in)");
            });
            ui.end_row();
            ui.label("Internet sharing");
            ui.checkbox(
                &mut self.form.internet,
                "Let clients reach the internet through this machine (NAT)",
            );
            ui.end_row();
            ui.label("Routing");
            ui.checkbox(
                &mut self.form.routing,
                "Let clients reach the other networks this machine routes to (VPN, containers, LAN)",
            );
            ui.end_row();
        });
        ui.weak("WEP and open networks are not offered. A password is generated and stored in NetworkManager; Show password reveals it once the network runs.");
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.busy.is_none(),
                    egui::Button::new("Check (changes nothing)"),
                )
                .clicked()
            {
                self.busy = Some("checking");
                self.message = None;
                actions.push(Action::Preflight(self.form.args()));
            }
            if ui
                .add_enabled(
                    self.busy.is_none() && may_start(self),
                    egui::Button::new("Start Field Network"),
                )
                .on_disabled_hover_text(
                    "Run the check for these settings and accept each warning first",
                )
                .clicked()
            {
                self.busy = Some("starting (NetworkManager rolls back if it fails)");
                self.message = None;
                actions.push(Action::Start {
                    args: self.form.args(),
                    accepted: self.accepted.clone(),
                });
            }
            if let Some(b) = self.busy {
                ui.spinner();
                ui.label(b);
            }
        });
        let stale = self
            .checked
            .as_ref()
            .is_some_and(|(form, _)| *form != self.form);
        if stale {
            ui.colored_label(
                view::YELLOW,
                "The settings changed since the check: check again.",
            );
        }
        let Some((_, result)) = &self.checked else {
            return;
        };
        match result {
            Err(e) => {
                ui.colored_label(view::RED, e);
            }
            Ok(pf) => findings(ui, pf, &mut self.accepted),
        }
    }
}

fn capabilities(ui: &mut egui::Ui, snap: &FieldSnapshot) {
    let c = &snap.caps;
    ui.strong("This machine");
    egui::Grid::new("field_caps").num_columns(2).show(ui, |ui| {
        ui.label("Backend");
        ui.label(c.backend);
        ui.end_row();
        ui.label("Can host");
        ui.colored_label(
            if c.can_host { view::GREEN } else { view::RED },
            if c.can_host { "yes" } else { "no" },
        );
        ui.end_row();
        ui.label("Rollback");
        ui.label(if c.checkpoint_rollback {
            "NetworkManager checkpoint"
        } else {
            "not available"
        });
        ui.end_row();
    });
    egui::ScrollArea::horizontal()
        .id_salt("field_adapters")
        .show(ui, |ui| {
            egui::Grid::new("field_adapter_rows")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    for h in ["Adapter", "State", "AP", "WPA2", "WPA3"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for a in &c.adapters {
                        ui.monospace(&a.interface);
                        let state = adapter_state(&a.state);
                        ui.label(if a.connection.is_empty() {
                            state.to_string()
                        } else {
                            format!("{state} ({})", a.connection)
                        });
                        ui.label(yes_no(a.ap));
                        ui.label(yes_no(a.can_host_wpa2()));
                        ui.label(match a.sae {
                            Some(true) => "yes",
                            Some(false) => "no",
                            None => "cannot verify",
                        });
                        ui.end_row();
                    }
                });
        });
    if c.single_adapter_in_use {
        ui.colored_label(
            view::YELLOW,
            "Only one Wi-Fi adapter, and it is connected now: that connection drops while the Field Network runs.",
        );
    }
    for n in &c.notes {
        ui.weak(format!("- {n}"));
    }
}

fn mac_guide(ui: &mut egui::Ui, g: &lablink_fieldnet::macos::MacGuide) {
    ui.strong("macOS: guided Internet Sharing");
    ui.weak("LabLink cannot start a hotspot on macOS itself. These are the steps in System Settings; LabLink then detects the shared network.");
    if let Some(n) = &g.sharing_subnet {
        ui.colored_label(view::GREEN, format!("Internet Sharing is up on {n}."));
    }
    for (i, s) in g.host_steps.iter().enumerate() {
        ui.label(format!("{}. {s}", i + 1));
    }
    ui.strong("On each device");
    for s in &g.join_steps {
        ui.label(format!("- {s}"));
    }
    ui.strong("Limits");
    for s in &g.limits {
        ui.weak(format!("- {s}"));
    }
}

fn status(ui: &mut egui::Ui, s: &lablink_fieldnet::nm::Status) {
    if s.out_of_sync {
        ui.colored_label(
            view::YELLOW,
            "LabLink's record disagrees with NetworkManager (stopped or started elsewhere). Refresh after fixing it there.",
        );
    }
    let Some(st) = &s.state else {
        ui.label("No Field Network has been set up yet.");
        return;
    };
    egui::Grid::new("field_status")
        .num_columns(2)
        .show(ui, |ui| {
            ui.label("Network");
            ui.monospace(&st.ssid);
            ui.end_row();
            ui.label("Adapter");
            ui.monospace(&st.interface);
            ui.end_row();
            ui.label("Subnet");
            ui.monospace(match s.gateway {
                Some(g) => format!("{} (this machine {g})", st.subnet),
                None => st.subnet.clone(),
            });
            ui.end_row();
            ui.label("Security");
            ui.label(s.security.unwrap_or("-"));
            ui.end_row();
            if let Some(p) = &st.previous {
                ui.label("Replaced");
                ui.label(format!("{} (reconnected on stop)", p.name));
                ui.end_row();
            }
            ui.label("IPv4 forwarding");
            ui.label(match s.ip_forward {
                Some(true) => "on",
                Some(false) => "off",
                None => "unknown",
            });
            ui.end_row();
            if !s.uplinks.is_empty() {
                ui.label("Internet");
                ui.colored_label(
                    view::YELLOW,
                    format!(
                        "clients can reach the internet through {} (NAT); stop the network if that is not intended",
                        printable(&s.uplinks.join(", "))
                    ),
                );
                ui.end_row();
            }
            if !s.routed.is_empty() {
                ui.label("Other networks");
                ui.colored_label(
                    view::YELLOW,
                    format!(
                        "clients can be routed to {} (forwarding and NAT); stop the network if that is not intended",
                        printable(&s.routed.join(", "))
                    ),
                );
                ui.end_row();
            }
        });
}

/// Client state words, matching `lablink hotspot clients`.
pub fn client_level(state: &str) -> Level {
    match state {
        "ssh-authenticated" | "ssh-available" => Level::Good,
        "identity-mismatch" => Level::Bad,
        "ssh-unreachable" | "discovered-untrusted" => Level::Warn,
        _ => Level::Neutral,
    }
}

fn clients(ui: &mut egui::Ui, snap: &FieldSnapshot) {
    if snap.clients.is_empty() {
        ui.weak("No clients yet.");
        return;
    }
    egui::ScrollArea::horizontal()
        .id_salt("field_clients")
        .show(ui, |ui| {
            egui::Grid::new("field_client_rows")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    for h in ["Address", "State", "Device / name hint", "MAC"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for r in &snap.clients {
                        ui.monospace(&r.ip);
                        ui.colored_label(view::level_color(client_level(r.state)), r.state);
                        let who = match (&r.device, &r.hostname) {
                            (Some(d), _) => printable(d),
                            (None, Some(h)) => {
                                format!("asks to be called '{}' (unverified)", printable(h))
                            }
                            (None, None) => String::new(),
                        };
                        let who = if r.address_changed {
                            format!("{who} (address changed)")
                        } else {
                            who
                        };
                        ui.label(
                            if r.presence == lablink_fieldnet::clients::Presence::LeaseOnly {
                                format!("{who} (DHCP lease only: may have left)")
                            } else {
                                who
                            },
                        );
                        ui.monospace(printable(r.mac.as_deref().unwrap_or("-")));
                        ui.end_row();
                    }
                });
        });
    if snap
        .clients
        .iter()
        .any(|r| r.state == "discovered-untrusted")
    {
        ui.weak("Unknown clients are never trusted automatically. Use Discovered and Adopt, then compare the host key, to register one.");
    }
}

fn findings(ui: &mut egui::Ui, pf: &Preflight, accepted: &mut Vec<String>) {
    if let (Some(i), Some(n), Some(g)) = (&pf.interface, &pf.subnet, &pf.gateway) {
        ui.label(format!(
            "'{}' on {i}: {n}, this machine {g}, {}",
            pf.ssid,
            pf.security.label()
        ));
    }
    for f in &pf.findings {
        match f.level {
            preflight::Level::Block => {
                let how = match f.override_flag {
                    Some("--allow-internet-sharing") => {
                        " (tick Internet sharing above only if you mean to share it)"
                    }
                    Some("--allow-routing") => {
                        " (tick Routing above only if clients may reach those networks)"
                    }
                    _ => "",
                };
                ui.colored_label(view::RED, format!("Refused: {}{how}", f.message));
            }
            preflight::Level::Warn => {
                let mut on = accepted.contains(&f.message);
                if ui
                    .checkbox(&mut on, RichText::new(&f.message).color(view::YELLOW))
                    .changed()
                {
                    accepted.retain(|a| *a != f.message);
                    if on {
                        accepted.push(f.message.clone());
                    }
                }
            }
            preflight::Level::Info => {
                ui.weak(format!("note: {}", f.message));
            }
        }
    }
    if pf.blocked() {
        ui.colored_label(view::RED, "Cannot start with these settings.");
    } else if pf.needs_confirmation() {
        ui.label("Tick each warning to accept it, then Start.");
    } else {
        ui.colored_label(view::GREEN, "May start.");
    }
}

/// NetworkManager's "100 (connected)" as "connected".
pub fn adapter_state(s: &str) -> &str {
    match s.split_once(" (") {
        Some((n, rest)) if n.chars().all(|c| c.is_ascii_digit()) => rest.trim_end_matches(')'),
        _ => s,
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_fieldnet::preflight::{Finding, Level as PLevel};
    use lablink_fieldnet::state::Security;

    fn pf(findings: Vec<Finding>) -> Box<Preflight> {
        Box::new(Preflight {
            interface: Some("wlan0".into()),
            ssid: "LabLink-TEST".into(),
            security: Security::Wpa2,
            subnet: "10.77.0.0/24".parse().ok(),
            gateway: "10.77.0.1".parse().ok(),
            would_disconnect: None,
            already_running: false,
            findings,
        })
    }

    fn finding(level: PLevel, code: &'static str) -> Finding {
        Finding {
            level,
            code,
            message: code.into(),
            override_flag: None,
        }
    }

    #[test]
    fn start_needs_a_check_of_the_same_settings_and_every_warning_accepted() {
        let mut p = FieldPanel::default();
        assert!(!may_start(&p), "no check yet");
        p.checked = Some((
            p.form.clone(),
            Ok(pf(vec![finding(PLevel::Warn, "disconnect")])),
        ));
        assert!(!may_start(&p), "warning not accepted");
        p.accepted.push("disconnect".into());
        assert!(may_start(&p));
        p.form.ssid = "Other".into();
        assert!(!may_start(&p), "settings changed since the check");
    }

    #[test]
    fn an_accepted_warning_whose_content_changed_must_be_accepted_again() {
        let mut p = FieldPanel::default();
        let mut w = finding(PLevel::Warn, "equipment");
        w.message = "1 registered device(s) are reached over wlan0: orin".into();
        p.checked = Some((p.form.clone(), Ok(pf(vec![w.clone()]))));
        p.accepted.push(w.message.clone());
        assert!(may_start(&p));
        w.message = "2 registered device(s) are reached over wlan0: orin, go2".into();
        p.checked = Some((p.form.clone(), Ok(pf(vec![w]))));
        assert!(!may_start(&p), "same code, different content");
    }

    #[test]
    fn a_blocker_cannot_be_accepted() {
        let mut p = FieldPanel::default();
        p.checked = Some((
            p.form.clone(),
            Ok(pf(vec![finding(PLevel::Block, "session")])),
        ));
        p.accepted.push("session".into());
        assert!(!may_start(&p));
    }

    #[test]
    fn a_preflight_for_old_settings_is_dropped() {
        let mut p = FieldPanel::default();
        let old = p.form.args();
        p.form.ssid = "New".into();
        p.event(FieldEvent::Preflight(old, Ok(pf(vec![]))));
        assert!(p.checked.is_none());
        p.event(FieldEvent::Preflight(p.form.args(), Ok(pf(vec![]))));
        assert!(may_start(&p));
    }

    #[test]
    fn adapter_state_drops_the_numeric_code() {
        assert_eq!(adapter_state("100 (connected)"), "connected");
        assert_eq!(adapter_state("30 (disconnected)"), "disconnected");
        assert_eq!(adapter_state("unavailable"), "unavailable");
    }

    #[test]
    fn results_drop_the_shown_password() {
        let mut p = FieldPanel {
            password: Some("secret-psk".into()),
            ..Default::default()
        };
        p.event(FieldEvent::Stopped(Ok("Field Network stopped.".into())));
        assert!(p.password.is_none());
    }
}
