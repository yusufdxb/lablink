//! lablink-gui: native desktop client for the `lablinkd` daemon.
//!
//! A thin client: every fact on screen comes from the daemon over its Unix
//! socket. There is no network discovery or probing code in this crate.

mod app;
mod files;
mod flow;
mod health;
mod onboarding;
mod scan;
mod settings;
mod term;
mod theme;
mod view;
mod wizard;
mod worker;

use eframe::egui;

/// The logo every LabLink surface uses, built from packaging/app-icon.png
/// by scripts/build-icons.sh.
pub const LOGO_PNG: &[u8] = include_bytes!("../../../packaging/icons/lablink-256.png");

/// "LabLink 0.4.0" plus the commit when the build recorded one.
pub fn version_line() -> String {
    format!(
        "LabLink {}{}",
        lablink_core::VERSION,
        lablink_core::GIT_SHA
            .map(|s| format!(" (commit {s})"))
            .unwrap_or_default()
    )
}

fn main() -> eframe::Result {
    // Answer informational flags without opening a window, so scripts and
    // installers can check the binary on headless machines.
    if let Some(a) = std::env::args().nth(1) {
        match a.as_str() {
            "--version" | "-V" => {
                println!(
                    "lablink-gui {}",
                    version_line().trim_start_matches("LabLink ")
                );
                return Ok(());
            }
            "--help" | "-h" => {
                println!("{}\n\nUsage: lablink-gui\n\nOpens the LabLink desktop app. It needs a graphical session and talks to lablinkd; use `lablink` for the command line.", version_line());
                return Ok(());
            }
            other => {
                eprintln!("lablink-gui: unknown argument '{other}' (try --help)");
                std::process::exit(2);
            }
        }
    }
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("LabLink")
        .with_app_id("lablink-gui")
        .with_inner_size([1120.0, 850.0])
        .with_min_inner_size([560.0, 400.0]);
    match eframe::icon_data::from_png_bytes(LOGO_PNG) {
        Ok(icon) => viewport = viewport.with_icon(icon),
        Err(e) => eprintln!("lablink-gui: window icon not loaded: {e}"),
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "LabLink",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
