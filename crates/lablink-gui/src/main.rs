//! lablink-gui: native desktop client for the `lablinkd` daemon.
//!
//! A thin client: every fact on screen comes from the daemon over its Unix
//! socket. There is no network discovery or probing code in this crate.

mod app;
mod flow;
mod health;
mod onboarding;
mod settings;
mod term;
mod view;
mod wizard;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LabLink")
            .with_app_id("lablink-gui")
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([560.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "LabLink",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
