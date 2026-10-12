//! Robotics tab: the app's face of `lablink ros dds-check`. The default
//! check is read-only (files, `/proc`, `ip`, and a short hidden graph
//! query). The active test is a separate, explicit choice: it needs a
//! peer and a second confirmation, and only ever publishes on a unique
//! probe topic of its own.

use crate::view::{self, Level};
use crate::worker::RosResult;
use eframe::egui::{self, RichText};
use lablink_core::printable;
use lablink_ros::check::CheckRequest;
use lablink_ros::diagnose::{Check, Report, Verdict};
use lablink_ros::inspect::Options;
use std::time::Duration;

pub struct RosPanel {
    pub device: String,
    /// Empty: no peer.
    pub peer: String,
    pub graph: bool,
    pub active: bool,
    /// The second confirmation for the active test.
    pub active_ack: bool,
    pub details: bool,
    pub busy: bool,
    /// What the running or last check asked for.
    pub label: String,
    pub result: Option<RosResult>,
}

impl Default for RosPanel {
    fn default() -> Self {
        Self {
            device: String::new(),
            peer: String::new(),
            graph: true,
            active: false,
            active_ack: false,
            details: false,
            busy: false,
            label: String::new(),
            result: None,
        }
    }
}

pub enum Action {
    Check(Box<CheckRequest>),
    OpenSettings,
}

/// Words for a verdict, matching the GUI states (Connected/OK, Warning,
/// Failed, Not Tested, Unsupported).
pub fn verdict_word(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "OK",
        Verdict::Warn => "WARNING",
        Verdict::Fail => "FAILED",
        Verdict::NotTested => "NOT TESTED",
        Verdict::Unavailable => "UNSUPPORTED",
    }
}

pub fn verdict_level(v: Verdict) -> Level {
    match v {
        Verdict::Pass => Level::Good,
        Verdict::Warn => Level::Warn,
        Verdict::Fail => Level::Bad,
        Verdict::NotTested | Verdict::Unavailable => Level::Neutral,
    }
}

impl RosPanel {
    /// The request for the current form, or why it cannot run.
    pub fn request(&self) -> Result<CheckRequest, &'static str> {
        if self.device.is_empty() {
            return Err("Choose a device");
        }
        let peer = Some(self.peer.clone()).filter(|p| !p.is_empty());
        if peer.as_deref() == Some(self.device.as_str()) {
            return Err("The peer must be a different device");
        }
        let active = self.active && peer.is_some();
        if active && !self.active_ack {
            return Err("Confirm the active test first");
        }
        Ok(CheckRequest {
            device: self.device.clone(),
            peer,
            active,
            opts: Options {
                graph: self.graph || active,
                qos_topics: vec![],
                spin_s: 5,
                timeout: Duration::from_secs(30),
            },
        })
    }

    pub fn finished(&mut self, r: RosResult) {
        self.busy = false;
        self.result = Some(r);
    }

    /// `devices`: registered device ids (`site/name`).
    pub fn ui(&mut self, ui: &mut egui::Ui, feature_on: bool, devices: &[String]) -> Vec<Action> {
        let mut actions = Vec::new();
        // Wrap to the window, not to the widest row seen inside the scroll area.
        let width = ui.available_width().min(980.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width(width);
                ui.label(RichText::new("ROBOTICS").strong().size(18.0));
                ui.weak("Read-only ROS 2 and DDS diagnostics over LabLink's pinned-key SSH. Nothing is installed on the device and no ROS is needed here. LabLink never changes ROS configuration, restarts nodes, or commands a robot.");
                if !feature_on {
                    ui.label("Robotics mode is an optional feature and is off.");
                    if ui.button("Turn it on in Settings").clicked() {
                        actions.push(Action::OpenSettings);
                    }
                    return;
                }
                ui.separator();
                self.form(ui, devices, &mut actions);
                ui.separator();
                self.results(ui);
            });
        actions
    }

    fn form(&mut self, ui: &mut egui::Ui, devices: &[String], actions: &mut Vec<Action>) {
        if devices.is_empty() {
            ui.label("No registered devices yet. Discover and adopt devices first.");
            return;
        }
        egui::Grid::new("ros_form").num_columns(2).show(ui, |ui| {
            ui.label("Device");
            pick(ui, "ros_device", &mut self.device, devices, false);
            ui.end_row();
            ui.label("Peer (optional)");
            pick(ui, "ros_peer", &mut self.peer, devices, true);
            ui.end_row();
        });
        ui.checkbox(
            &mut self.graph,
            "Query the ROS graph (joins the domain for 5 s as a hidden node; publishes nothing)",
        );
        let has_peer = !self.peer.is_empty();
        ui.add_enabled_ui(has_peer, |ui| {
            ui.checkbox(&mut self.active, "Active test between the two devices")
                .on_disabled_hover_text("Needs a peer");
        });
        if self.active && has_peer {
            ui.indent("ros_active", |ui| {
                ui.colored_label(view::YELLOW, "The active test pings each way, sends one ROS 2 multicast packet each way, and publishes a few short messages on a unique /lablink_probe_* topic each way (about 50 s). It never touches existing topics, nodes or robot motion, and checks that its own processes are gone afterwards.");
                ui.checkbox(&mut self.active_ack, "I understand; run it");
            });
        } else {
            self.active_ack = false;
        }
        ui.horizontal_wrapped(|ui| {
            let req = self.request();
            let ready = req.is_ok() && !self.busy;
            let mut b = ui.add_enabled(ready, egui::Button::new("Run DDS check"));
            if let Err(why) = &req {
                b = b.on_disabled_hover_text(*why);
            }
            if b.clicked() {
                if let Ok(r) = req {
                    self.label = match (&r.peer, r.active) {
                        (Some(p), true) => format!("{} and {p}, active", r.device),
                        (Some(p), false) => format!("{} and {p}", r.device),
                        (None, _) => r.device.clone(),
                    };
                    self.busy = true;
                    self.result = None;
                    actions.push(Action::Check(Box::new(r)));
                }
            }
            if self.busy {
                ui.spinner();
                ui.label(format!("checking {}...", self.label));
            }
            ui.checkbox(&mut self.details, "Show evidence");
        });
    }

    fn results(&self, ui: &mut egui::Ui) {
        match &self.result {
            None => {
                if !self.busy {
                    ui.weak("No check run yet.");
                }
            }
            Some(Err(e)) => {
                ui.colored_label(view::RED, e);
            }
            Some(Ok(b)) => {
                let (r, act) = b.as_ref();
                report(ui, r, self.details);
                if let Some(a) = act {
                    ui.separator();
                    ui.strong(format!(
                        "Active test (topic {}, domain {})",
                        a.topic, a.domain
                    ));
                    for p in [
                        &a.ping_ab,
                        &a.ping_ba,
                        &a.multicast_ab,
                        &a.multicast_ba,
                        &a.pubsub_ab,
                        &a.pubsub_ba,
                    ] {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(
                                view::level_color(verdict_level(p.verdict)),
                                verdict_word(p.verdict),
                            );
                            ui.label(printable(&format!(
                                "{} {} -> {}: {}",
                                p.name, p.from, p.to, p.summary
                            )));
                        });
                        if self.details {
                            ui.indent(("probe", &p.name, &p.from), |ui| {
                                ui.weak(format!(
                                    "method: {}; interface: {}; timeout {} ms",
                                    p.method,
                                    p.interface.as_deref().unwrap_or("-"),
                                    p.timeout_ms
                                ));
                                for e in &p.evidence {
                                    ui.monospace(printable(e));
                                }
                            });
                        }
                    }
                    if a.leftover.is_empty() {
                        ui.weak("No probe processes left behind.");
                    } else {
                        ui.colored_label(
                            view::RED,
                            format!("Probe processes still running: {}", a.leftover.join(", ")),
                        );
                    }
                }
            }
        }
    }
}

fn pick(ui: &mut egui::Ui, id: &str, value: &mut String, devices: &[String], optional: bool) {
    let shown = if value.is_empty() {
        if optional {
            "none"
        } else {
            "choose"
        }
    } else {
        value.as_str()
    }
    .to_string();
    egui::ComboBox::from_id_salt(id)
        .selected_text(shown)
        .width(240.0)
        .show_ui(ui, |ui| {
            if optional {
                ui.selectable_value(value, String::new(), "none");
            }
            for d in devices {
                ui.selectable_value(value, d.clone(), d);
            }
        });
}

fn report(ui: &mut egui::Ui, r: &Report, details: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(match &r.peer {
            Some(p) => format!("{} and {p}", r.device),
            None => r.device.clone(),
        });
        if let Some(l) = r.level {
            let level = if l >= 3 {
                Level::Good
            } else if l >= 1 {
                Level::Warn
            } else {
                Level::Bad
            };
            ui.colored_label(view::level_color(level), format!("Level {l} of 4"));
        }
    });
    if let Some(p) = &r.path {
        ui.weak(format!(
            "Shared network {}: {} on {}, {} on {}",
            p.net, p.a_addr, p.a_interface, p.b_addr, p.b_interface
        ));
    }
    if !r.levels.is_empty() {
        egui::Grid::new("ros_levels").num_columns(3).show(ui, |ui| {
            for s in &r.levels {
                ui.label(format!("L{} {}", s.level, s.name));
                ui.colored_label(
                    view::level_color(verdict_level(s.verdict)),
                    verdict_word(s.verdict),
                );
                ui.label(printable(&s.detail));
                ui.end_row();
            }
        });
        if !r.active {
            ui.weak("Level 4 (messages delivered) is only proven by the active test, never by a node list.");
        }
        ui.add_space(4.0);
    }
    for c in &r.checks {
        check_row(ui, c, details);
    }
}

fn check_row(ui: &mut egui::Ui, c: &Check, details: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.colored_label(
            view::level_color(verdict_level(c.verdict)),
            RichText::new(format!("{:<11}", verdict_word(c.verdict))).monospace(),
        );
        ui.strong(c.title);
        ui.label(printable(&c.summary));
    });
    if let Some(h) = c.hint.as_ref().filter(|_| c.verdict != Verdict::Pass) {
        ui.indent(("hint", c.id), |ui| {
            ui.weak(format!("fix: {}", printable(h)));
        });
    }
    if details {
        ui.indent(("ev", c.id), |ui| {
            ui.weak(format!(
                "method: {}; endpoints: {}; interfaces: {}; domain: {}; timeout: {}",
                printable(&c.method),
                printable(&list(&c.endpoints)),
                printable(&list(&c.interfaces)),
                c.domain.map_or("-".to_string(), |d| d.to_string()),
                c.timeout_ms.map_or("-".to_string(), |t| format!("{t} ms"))
            ));
            for e in &c.evidence {
                ui.monospace(printable(e));
            }
        });
    }
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel(device: &str, peer: &str) -> RosPanel {
        RosPanel {
            device: device.into(),
            peer: peer.into(),
            ..Default::default()
        }
    }

    #[test]
    fn default_check_is_passive() {
        let r = panel("lab/orin", "").request().unwrap();
        assert!(!r.active);
        assert!(r.peer.is_none());
        assert!(r.opts.graph);
    }

    #[test]
    fn active_needs_a_peer_and_a_second_confirmation() {
        let mut p = panel("lab/orin", "lab/5080");
        p.active = true;
        assert!(p.request().is_err(), "not confirmed");
        p.active_ack = true;
        let r = p.request().unwrap();
        assert!(r.active && r.opts.graph);
        // Without a peer the active flag is ignored, never run.
        let mut q = panel("lab/orin", "");
        q.active = true;
        q.active_ack = true;
        assert!(!q.request().unwrap().active);
    }

    #[test]
    fn peer_must_differ_and_device_is_required() {
        assert!(panel("", "").request().is_err());
        assert!(panel("lab/orin", "lab/orin").request().is_err());
    }

    #[test]
    fn verdict_words_match_gui_states() {
        assert_eq!(verdict_word(Verdict::Unavailable), "UNSUPPORTED");
        assert_eq!(verdict_word(Verdict::NotTested), "NOT TESTED");
        assert_eq!(verdict_level(Verdict::Fail), Level::Bad);
    }
}
