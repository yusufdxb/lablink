//! Health tab: the `lablink doctor` dashboard. Results come from the shared
//! `lablink_doctor` crate (the same read-only checks as the CLI); this module
//! only lays them out, next to the daemon's live colors.

use crate::flow;
use crate::view::Level;
use crate::worker::Fail;
use eframe::egui::{self, Color32, RichText};
use lablink_core::model::DeviceStatus;

/// The latest doctor run (all devices or one).
#[derive(Default)]
pub struct DoctorPanel {
    /// "all" or a device id (`site/name`).
    pub scope: String,
    pub busy: bool,
    pub result: Option<Result<Box<lablink_doctor::Report>, Fail>>,
    /// Keeps the last full run while a single device is re-checked.
    pub last_all: Option<Box<lablink_doctor::Report>>,
}

impl DoctorPanel {
    /// The latest result row for `device`: the newest run first, then the
    /// last full run.
    /// `id` is the device's `site/name`.
    pub fn device(&self, id: &str) -> Option<&lablink_doctor::DeviceReport> {
        self.result
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .and_then(|r| r.devices.iter().find(|d| d.id == id))
            .or_else(|| {
                self.last_all
                    .as_ref()
                    .and_then(|r| r.devices.iter().find(|d| d.id == id))
            })
    }

    pub fn finished(&mut self, scope: String, r: Result<Box<lablink_doctor::Report>, Fail>) {
        if scope != self.scope {
            return;
        }
        self.busy = false;
        if let (Ok(rep), "all") = (&r, scope.as_str()) {
            self.last_all = Some(rep.clone());
        }
        self.result = Some(r);
    }
}

pub enum Action {
    RunAll,
    RunOne(String),
    Select(String),
}

fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(radius * 2.0, radius * 2.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), radius, color);
}

/// Render one device's check rows.
pub fn check_rows(ui: &mut egui::Ui, d: &lablink_doctor::DeviceReport, id: &str) {
    let v = flow::doctor_device(d);
    egui::Grid::new(("doctor_rows", id))
        .num_columns(3)
        .show(ui, |ui| {
            for row in &v.rows {
                ui.label(&row.label);
                ui.colored_label(crate::theme::level_color(ui, row.level), row.word);
                ui.label(&row.detail);
                ui.end_row();
            }
        });
}

pub fn ui(ui: &mut egui::Ui, panel: &DoctorPanel, live: &[DeviceStatus]) -> Option<Action> {
    let mut action = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new("LABLINK HEALTH").strong().size(18.0));
        let sites: Vec<&str> = {
            let mut v: Vec<&str> = live.iter().map(|d| d.site_name.as_str()).collect();
            v.sort();
            v.dedup();
            v
        };
        if !sites.is_empty() {
            ui.weak(sites.join(" + "));
        }
        if ui
            .add_enabled(!panel.busy, egui::Button::new("Run all checks"))
            .clicked()
        {
            action = Some(Action::RunAll);
        }
        if panel.busy {
            ui.spinner();
            ui.label(format!(
                "running read-only checks on {} (up to ~25 s per device, in parallel)...",
                panel.scope
            ));
        }
    });
    ui.weak("Live state comes from the daemon every 2 s. Checks log in over SSH with LabLink's pinned host keys and run fixed read-only commands (disk, GPU, temperature, ROS 2, ...) chosen by each device's profile or the config's `checks:`.");
    let report = panel
        .result
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .filter(|r| panel.scope == "all" || r.devices.len() > 1)
        .map(|r| r.as_ref())
        .or(panel.last_all.as_deref());
    if let Some(Err(f)) = &panel.result {
        ui.colored_label(crate::theme::error(ui), &f.message);
    }
    if let Some(r) = report {
        let v = flow::doctor_view(r);
        ui.label(
            RichText::new(v.header)
                .strong()
                .color(crate::theme::level_color(ui, v.level)),
        );
    }
    ui.add_space(4.0);
    if live.is_empty() {
        ui.label("No devices yet. Discover and adopt devices first.");
        return action;
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for d in live {
                let checked = panel.device(&d.id);
                let id = ui.make_persistent_id(("health", &d.id));
                let open = checked.is_some_and(|c| c.color != lablink_core::model::Color::Green);
                egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    id,
                    open,
                )
                .show_header(ui, |ui| {
                    dot(ui, crate::theme::state_color(ui, d.color), 6.0);
                    ui.label(
                        RichText::new(format!("{:<12}", d.name))
                            .monospace()
                            .strong(),
                    );
                    ui.colored_label(crate::theme::state_color(ui, d.color), d.color.as_str());
                    match checked {
                        Some(c) => {
                            ui.weak("  checks");
                            ui.colored_label(
                                crate::theme::state_color(ui, c.color),
                                c.color.as_str(),
                            );
                            let (bad, warn) = c.checks.iter().fold((0, 0), |(b, w), x| {
                                match flow::check_level(x.status) {
                                    Level::Bad => (b + 1, w),
                                    Level::Warn => (b, w + 1),
                                    _ => (b, w),
                                }
                            });
                            if bad + warn > 0 {
                                ui.weak(format!("({bad} failed, {warn} warning)"));
                            }
                        }
                        None => {
                            ui.weak("  checks not run");
                        }
                    }
                })
                .body(|ui| {
                    match checked {
                        Some(c) => check_rows(ui, c, &d.id),
                        None => {
                            ui.weak("Press Run all checks, or Check.");
                        }
                    }
                    if d.color != lablink_core::model::Color::Green {
                        for r in &d.reasons {
                            ui.colored_label(
                                crate::theme::level_color(ui, Level::Warn),
                                format!("- {r}"),
                            );
                        }
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!panel.busy, egui::Button::new("Check"))
                            .clicked()
                        {
                            action = Some(Action::RunOne(d.id.clone()));
                        }
                        if ui.button("Open device").clicked() {
                            action = Some(Action::Select(d.id.clone()));
                        }
                    });
                });
            }
        });
    action
}
