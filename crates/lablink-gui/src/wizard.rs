//! First-run setup wizard, shown instead of an empty window when there is
//! no configuration file. It drives the same `lablink_setup::init` steps as
//! `lablink init`; nothing is selected or scanned until the user says so.

use crate::view::{self, Level};
use eframe::egui::{self, RichText};
use lablink_core::config::NetworkConfig;
use lablink_setup::ifaces::{self, LocalNetwork};
use lablink_setup::init::{InitOptions, Step, StepStatus};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Welcome,
    Networks,
    Background,
    Result,
}

/// One detected network and the user's choices for it.
#[derive(Debug, Clone)]
pub struct Choice {
    pub net: LocalNetwork,
    pub selected: bool,
    pub scan: bool,
}

pub struct Wizard {
    pub page: Page,
    /// Name of the place being set up (the first site).
    pub site_name: String,
    pub choices: Vec<Choice>,
    pub manual_cidr: String,
    pub manual_error: Option<String>,
    pub manual: Vec<NetworkConfig>,
    pub service: bool,
    pub completions: bool,
    pub running: bool,
    pub result: Option<Vec<Step>>,
    config_path: PathBuf,
    socket: PathBuf,
}

/// What the wizard asks the app to do.
/// A large button for the main step action.
fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).size(15.0).strong())
        .min_size(egui::vec2(140.0, 30.0))
}

pub enum Action {
    Apply(InitOptions),
    Discover,
    Close,
}

impl Wizard {
    pub fn new(config_path: PathBuf, socket: PathBuf) -> Self {
        Self::with_networks(config_path, socket, ifaces::detect())
    }

    pub fn with_networks(config_path: PathBuf, socket: PathBuf, nets: Vec<LocalNetwork>) -> Self {
        Self {
            page: Page::Welcome,
            site_name: String::new(),
            // Nothing is preselected: the user opts in to every network.
            choices: nets
                .into_iter()
                .map(|net| Choice {
                    net,
                    selected: false,
                    scan: false,
                })
                .collect(),
            manual_cidr: String::new(),
            manual_error: None,
            manual: Vec::new(),
            service: true,
            completions: true,
            running: false,
            result: None,
            config_path,
            socket,
        }
    }

    /// The networks the user chose, named after their interfaces.
    pub fn networks(&self) -> Vec<NetworkConfig> {
        let mut taken: Vec<String> = self.manual.iter().map(|n| n.name.clone()).collect();
        let mut out = Vec::new();
        for c in self.choices.iter().filter(|c| c.selected) {
            let name = ifaces::network_name(&c.net.interface, &taken);
            taken.push(name.clone());
            // Records the interface, gateway (and its MAC) and Wi-Fi name so
            // LabLink can recognize this site later. They grant nothing.
            out.push(
                c.net
                    .to_network_config(&name, c.scan && c.net.scan_allowed()),
            );
        }
        out.extend(self.manual.iter().cloned());
        out
    }

    /// `(id, name)` of the site being set up.
    pub fn site(&self) -> (String, String) {
        let name = self.site_name.trim();
        if name.is_empty() || !lablink_core::config::valid_display_name(name) {
            (
                lablink_core::config::DEFAULT_SITE_ID.into(),
                lablink_core::config::DEFAULT_SITE_NAME.into(),
            )
        } else {
            (
                lablink_core::config::site_id_from_name(name),
                name.to_string(),
            )
        }
    }

    pub fn options(&self) -> InitOptions {
        InitOptions {
            config_path: self.config_path.clone(),
            socket: self.socket.clone(),
            site: self.site(),
            networks: self.networks(),
            service: self.service,
            completions: self.completions,
            force: false,
        }
    }

    /// Add a typed CIDR as a passive network (scanning is a separate tick).
    pub fn add_manual(&mut self) {
        let text = self.manual_cidr.trim().to_string();
        match lablink_core::net::parse_cidr(&text) {
            Err(e) => self.manual_error = Some(e.to_string()),
            Ok(n) => {
                let cidr = n.to_string();
                if self.networks().iter().any(|x| x.cidr == cidr) {
                    self.manual_error = Some(format!("{cidr} is already in the list"));
                    return;
                }
                let taken: Vec<String> = self.networks().into_iter().map(|n| n.name).collect();
                self.manual.push(NetworkConfig::new(
                    &ifaces::network_name("net", &taken),
                    &cidr,
                    false,
                ));
                self.manual_cidr.clear();
                self.manual_error = None;
            }
        }
    }

    pub fn finished(&mut self, steps: Vec<Step>) {
        self.running = false;
        self.result = Some(steps);
        self.page = Page::Result;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let mut action = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width(760.0);
                ui.add_space(16.0);
                let (n, of) = match self.page {
                    Page::Welcome => (1, "Welcome"),
                    Page::Networks => (2, "Networks"),
                    Page::Background => (3, "Service"),
                    Page::Result => (4, "Done"),
                };
                ui.label(RichText::new("Set up LabLink").size(24.0).strong());
                ui.weak(format!("Step {n} of 4: {of}"));
                ui.add_space(10.0);
                match self.page {
                    Page::Welcome => self.welcome(ui),
                    Page::Networks => self.networks_page(ui),
                    Page::Background => {
                        if let Some(a) = self.background(ui) {
                            action = Some(a);
                        }
                    }
                    Page::Result => {
                        if let Some(a) = self.result_page(ui) {
                            action = Some(a);
                        }
                    }
                }
            });
        action
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.label("LabLink finds lab machines and robots on networks you allow, checks that each one is really the machine you trusted (by its SSH host key), and lets you connect by name even when its IP changes.");
        ui.add_space(8.0);
        ui.label(
            RichText::new("Site  ->  Discover  ->  Adopt  ->  Trust  ->  Connect")
                .strong()
                .size(16.0),
        );
        ui.add_space(8.0);
        ui.label("A site is the place you work at (a lab, an office, a workshop). LabLink recognizes it from its networks and checks its devices only while you are there; you can add more sites later.");
        ui.horizontal(|ui| {
            ui.label("What do you call this place?");
            ui.add(
                egui::TextEdit::singleline(&mut self.site_name)
                    .hint_text("e.g. Robotics Lab")
                    .desired_width(220.0),
            );
        });
        if !self.site_name.trim().is_empty()
            && !lablink_core::config::valid_display_name(self.site_name.trim())
        {
            ui.colored_label(view::RED, "1-64 printable characters");
        }
        ui.add_space(8.0);
        ui.label("This takes about a minute:");
        ui.label("  1. choose which networks of this site LabLink may look at (nothing is chosen for you)");
        ui.label("  2. start the background service (runs as you, no root)");
        ui.label("  3. done: discover devices and adopt the ones you want");
        ui.add_space(12.0);
        if ui.add(primary("Start")).clicked() {
            self.page = Page::Networks;
        }
    }

    fn networks_page(&mut self, ui: &mut egui::Ui) {
        ui.strong("Which networks may LabLink use?");
        ui.label("LabLink only looks at networks you tick. Active scanning pings every address of a small private network to find devices; without it LabLink still sees devices your computer already talks to.");
        ui.add_space(6.0);
        if self.choices.is_empty() {
            ui.colored_label(view::YELLOW, "No IPv4 networks are attached to this computer right now. Connect to your lab network, or type one below.");
        }
        egui::Grid::new("wizard_nets")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for h in ["Use", "Network", "Interface", "Active scan"] {
                    ui.strong(h);
                }
                ui.end_row();
                for c in &mut self.choices {
                    ui.checkbox(&mut c.selected, "");
                    ui.monospace(c.net.cidr());
                    ui.label(format!("{} ({})", c.net.interface, c.net.kind.word()));
                    match &c.net.scan_refusal {
                        None => {
                            ui.add_enabled_ui(c.selected, |ui| {
                                ui.checkbox(
                                    &mut c.scan,
                                    format!("ping {} addresses", c.net.host_count()),
                                );
                            });
                        }
                        Some(r) => {
                            c.scan = false;
                            ui.weak(format!("passive only: {r}"));
                        }
                    }
                    ui.end_row();
                }
                for n in &self.manual {
                    ui.label("yes");
                    ui.monospace(&n.cidr);
                    ui.label("(typed)");
                    ui.weak("passive");
                    ui.end_row();
                }
            });
        ui.horizontal(|ui| {
            ui.label("Other network:");
            ui.add(
                egui::TextEdit::singleline(&mut self.manual_cidr)
                    .hint_text("e.g. 192.168.50.0/24")
                    .desired_width(180.0),
            );
            if ui.button("Add").clicked() {
                self.add_manual();
            }
        });
        if let Some(e) = &self.manual_error {
            ui.colored_label(view::RED, e);
        }
        ui.add_space(10.0);
        let n = self.networks().len();
        ui.horizontal(|ui| {
            if ui.button("Back").clicked() {
                self.page = Page::Welcome;
            }
            let label = if n == 0 {
                "Continue without networks".to_string()
            } else {
                format!("Continue with {n} network(s)")
            };
            if ui.add(primary(&label)).clicked() {
                self.page = Page::Background;
            }
        });
        if n == 0 {
            ui.weak("Without a network LabLink cannot discover anything. You can add networks later in Settings.");
        }
    }

    fn background(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        ui.strong("Background service and shell");
        ui.checkbox(&mut self.service, "Install and start the LabLink service (systemd user service; runs as you, no root, starts at login)");
        ui.checkbox(
            &mut self.completions,
            "Install bash tab completion for the lablink command",
        );
        ui.add_space(8.0);
        ui.label("Summary:");
        let (id, name) = self.site();
        ui.monospace(format!("  site: {name} ({id})"));
        for n in self.networks() {
            ui.monospace(format!(
                "  {:<18} {:<12} {}",
                n.cidr,
                n.name,
                if n.active_scan {
                    "active scan"
                } else {
                    "passive"
                }
            ));
        }
        ui.monospace(format!("  config: {}", self.config_path.display()));
        ui.add_space(8.0);
        let mut action = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.running, egui::Button::new("Back"))
                .clicked()
            {
                self.page = Page::Networks;
            }
            if ui
                .add_enabled(!self.running, primary("Set up LabLink"))
                .clicked()
            {
                self.running = true;
                action = Some(Action::Apply(self.options()));
            }
            if self.running {
                ui.spinner();
                ui.label("setting up...");
            }
        });
        action
    }

    fn result_page(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let steps = self.result.clone().unwrap_or_default();
        let failed = steps.iter().any(|s| s.status == StepStatus::Failed);
        ui.label(
            RichText::new(if failed {
                "Setup finished with problems"
            } else {
                "LabLink is set up"
            })
            .strong()
            .size(18.0)
            .color(view::level_color(if failed {
                Level::Warn
            } else {
                Level::Good
            })),
        );
        for s in &steps {
            let l = match s.status {
                StepStatus::Done => Level::Good,
                StepStatus::Skipped => Level::Neutral,
                StepStatus::Failed => Level::Bad,
            };
            ui.horizontal(|ui| {
                ui.label(RichText::new(s.name).strong());
                ui.colored_label(view::level_color(l), s.status.word());
            });
            ui.add(egui::Label::new(RichText::new(&s.detail).weak()).wrap());
            ui.add_space(4.0);
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Next: Discover  ->  Adopt  ->  Trust  ->  Connect").strong());
        ui.label("Discover finds hosts on your networks. On the Discovered tab, Adopt the ones you want, then Trust each one's host key after comparing it with the device.");
        let mut action = None;
        ui.horizontal(|ui| {
            let daemon_ok = steps
                .iter()
                .any(|s| s.name == "daemon" && s.status == StepStatus::Done);
            if ui.add_enabled(daemon_ok, primary("Discover now")).clicked() {
                action = Some(Action::Discover);
            }
            if ui.button("Close").clicked() {
                action = Some(Action::Close);
            }
        });
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_setup::ifaces::{classify, LinkKind};

    fn wiz() -> Wizard {
        let a = |s: &str| s.parse().unwrap();
        Wizard::with_networks(
            "/tmp/c.yaml".into(),
            "/tmp/s.sock".into(),
            vec![
                classify("wlan0", a("192.168.10.42"), 24, LinkKind::Wireless).unwrap(),
                classify("docker0", a("172.17.0.1"), 16, LinkKind::Virtual).unwrap(),
            ],
        )
    }

    #[test]
    fn nothing_is_selected_or_scanned_by_default() {
        let w = wiz();
        assert!(w.networks().is_empty());
        assert!(w.choices.iter().all(|c| !c.selected && !c.scan));
        assert!(w.options().networks.is_empty());
    }

    #[test]
    fn scanning_needs_both_ticks_and_an_allowed_range() {
        let mut w = wiz();
        w.choices[0].scan = true; // ticked scan but not "use": ignored
        assert!(w.networks().is_empty());
        w.choices[0].selected = true;
        w.choices[1].selected = true;
        w.choices[1].scan = true; // a /16 can never be scanned
        let n = w.networks();
        assert_eq!(n.len(), 2);
        assert_eq!(
            (n[0].cidr.as_str(), n[0].active_scan),
            ("192.168.10.0/24", true)
        );
        assert_eq!(
            (n[1].cidr.as_str(), n[1].active_scan),
            ("172.17.0.0/16", false)
        );
        assert_eq!(n[0].name, "wlan0");
    }

    #[test]
    fn manual_networks_are_validated_and_passive() {
        let mut w = wiz();
        w.manual_cidr = "192.168.50.7/24".into();
        w.add_manual();
        assert!(w.manual_error.as_deref().unwrap().contains("did you mean"));
        w.manual_cidr = "192.168.50.0/24".into();
        w.add_manual();
        assert_eq!(w.networks().len(), 1);
        assert!(!w.networks()[0].active_scan);
        w.manual_cidr = "192.168.50.0/24".into();
        w.add_manual();
        assert!(w.manual_error.is_some(), "duplicates refused");
        let (id, name) = w.site();
        assert_eq!((id.as_str(), name.as_str()), ("default", "Default"));
        let cfg = lablink_setup::init::build_config(&id, &name, &w.networks());
        cfg.validate().unwrap();
    }

    #[test]
    fn site_name_becomes_the_site() {
        let mut w = wiz();
        w.site_name = "  Makerspace ".into();
        assert_eq!(
            w.site(),
            ("makerspace".to_string(), "Makerspace".to_string())
        );
        assert_eq!(w.options().site.0, "makerspace");
        w.choices[0].selected = true;
        // A wireless network records its interface as a detection hint.
        assert_eq!(w.networks()[0].interface.as_deref(), Some("wlan0"));
    }
}
