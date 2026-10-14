//! One visual system for the desktop shell and Files workspace.
use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke, TextStyle};

pub const ACCENT: Color32 = Color32::from_rgb(79, 140, 255);
pub const SUCCESS: Color32 = Color32::from_rgb(61, 204, 133);
pub const WARNING: Color32 = Color32::from_rgb(242, 184, 75);
pub const ERROR: Color32 = Color32::from_rgb(241, 107, 112);
pub const MUTED: Color32 = Color32::from_rgb(113, 113, 122);

pub fn install(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.interaction.selectable_labels = false;
        style.spacing.item_spacing = egui::vec2(12.0, 10.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.interact_size.y = 30.0;
        style.spacing.window_margin = egui::Margin::same(16);
        style
            .text_styles
            .insert(TextStyle::Body, FontId::proportional(15.0));
        style
            .text_styles
            .insert(TextStyle::Button, FontId::proportional(15.0));
        style
            .text_styles
            .insert(TextStyle::Small, FontId::proportional(12.0));
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(24.0));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::monospace(13.0));
        let v = &mut style.visuals;
        let dark = v.dark_mode;
        let text = if dark {
            Color32::from_rgb(245, 245, 247)
        } else {
            Color32::from_rgb(24, 24, 30)
        };
        let border = if dark {
            Color32::from_rgb(41, 41, 46)
        } else {
            Color32::from_rgb(210, 213, 221)
        };
        v.panel_fill = if dark {
            Color32::BLACK
        } else {
            Color32::from_rgb(247, 248, 250)
        };
        v.window_fill = if dark {
            Color32::from_rgb(21, 21, 24)
        } else {
            Color32::WHITE
        };
        v.extreme_bg_color = if dark {
            Color32::from_rgb(13, 13, 15)
        } else {
            Color32::WHITE
        };
        v.faint_bg_color = if dark {
            Color32::from_rgb(8, 8, 8)
        } else {
            Color32::from_rgb(238, 240, 245)
        };
        v.text_edit_bg_color = Some(if dark {
            Color32::from_rgb(16, 16, 19)
        } else {
            Color32::WHITE
        });
        v.code_bg_color = v.extreme_bg_color;
        v.weak_text_color = Some(if dark {
            Color32::from_rgb(161, 161, 170)
        } else {
            Color32::from_rgb(86, 90, 103)
        });
        v.warn_fg_color = if dark {
            WARNING
        } else {
            Color32::from_rgb(146, 99, 0)
        };
        v.error_fg_color = if dark {
            ERROR
        } else {
            Color32::from_rgb(187, 49, 58)
        };
        v.hyperlink_color = if dark {
            ACCENT
        } else {
            Color32::from_rgb(34, 91, 183)
        };
        v.selection.bg_fill = if dark {
            Color32::from_rgb(24, 48, 85)
        } else {
            Color32::from_rgb(218, 232, 255)
        };
        v.selection.stroke = Stroke::new(
            1.5,
            if dark {
                Color32::from_rgb(116, 165, 255)
            } else {
                Color32::from_rgb(34, 91, 183)
            },
        );
        v.window_stroke = Stroke::new(1.0, border);
        v.window_corner_radius = CornerRadius::same(10);
        v.menu_corner_radius = CornerRadius::same(8);
        v.window_shadow = egui::epaint::Shadow::NONE;
        v.popup_shadow = egui::epaint::Shadow::NONE;
        v.disabled_alpha = 0.65;
        for widget in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            widget.bg_fill = if dark {
                Color32::from_rgb(21, 21, 24)
            } else {
                Color32::WHITE
            };
            widget.weak_bg_fill = widget.bg_fill;
            widget.bg_stroke = Stroke::new(1.0, border);
            widget.fg_stroke = Stroke::new(1.0, text);
            widget.corner_radius = CornerRadius::same(6);
            widget.expansion = 0.0;
        }
        v.widgets.noninteractive.bg_fill = v.extreme_bg_color;
        v.widgets.noninteractive.weak_bg_fill = v.extreme_bg_color;
        v.widgets.hovered.bg_fill = if dark {
            Color32::from_rgb(30, 36, 48)
        } else {
            Color32::from_rgb(235, 241, 253)
        };
        v.widgets.hovered.weak_bg_fill = v.widgets.hovered.bg_fill;
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
        v.widgets.active.bg_stroke = Stroke::new(2.0, ACCENT);
        v.widgets.open.bg_stroke = Stroke::new(1.5, ACCENT);
    });
    ctx.set_theme(egui::ThemePreference::Dark);
}

pub fn apply(ctx: &egui::Context, name: &str) {
    ctx.set_theme(match name {
        "Light" => egui::ThemePreference::Light,
        "System Default" => egui::ThemePreference::System,
        _ => egui::ThemePreference::Dark,
    });
}

/// Semantic colors keep the same meaning with sufficient contrast in light mode.
pub fn success(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        SUCCESS
    } else {
        Color32::from_rgb(17, 112, 68)
    }
}
pub fn warning(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        WARNING
    } else {
        Color32::from_rgb(146, 99, 0)
    }
}
pub fn error(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        ERROR
    } else {
        Color32::from_rgb(187, 49, 58)
    }
}
pub fn level_color(ui: &egui::Ui, level: crate::view::Level) -> Color32 {
    if ui.visuals().dark_mode {
        return crate::view::level_color(level);
    }
    match level {
        crate::view::Level::Good => success(ui),
        crate::view::Level::Warn => warning(ui),
        crate::view::Level::Bad => error(ui),
        crate::view::Level::Neutral => ui.visuals().weak_text_color(),
    }
}
pub fn state_color(ui: &egui::Ui, state: lablink_core::model::Color) -> Color32 {
    if ui.visuals().dark_mode {
        return crate::view::state_color(state);
    }
    match state {
        lablink_core::model::Color::Green => success(ui),
        lablink_core::model::Color::Yellow => warning(ui),
        lablink_core::model::Color::Red => error(ui),
        lablink_core::model::Color::Gray => ui.visuals().weak_text_color(),
    }
}

pub fn muted(ui: &egui::Ui) -> Color32 {
    ui.visuals().weak_text_color()
}

pub fn danger_fill(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(50, 10, 15)
    } else {
        Color32::from_rgb(255, 230, 233)
    }
}
pub fn danger_text(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::WHITE
    } else {
        error(ui)
    }
}
