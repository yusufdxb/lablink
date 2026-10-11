//! lablink-gui: native desktop client for the `lablinkd` daemon.
//!
//! A thin client: every device fact on screen comes from the daemon over
//! its Unix socket. There is no network discovery or probing code in this
//! crate; the optional Field Network and Robotics tabs call the same
//! shared crates (`lablink-fieldnet`, `lablink-ros`) as the CLI.

mod app;
mod fieldnet;
mod flow;
mod health;
mod robotics;
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
