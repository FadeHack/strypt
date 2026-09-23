//! Paper and ink, with the icon's teal. egui picks light or dark from the system.

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Theme};

pub struct Palette {
    pub paper: Color32,
    pub card: Color32,
    pub ink: Color32,
    pub muted: Color32,
    pub line: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub accent_soft: Color32,
    pub direct: Color32,
    pub correlating: Color32,
    pub incidental: Color32,
    pub success: Color32,
    pub failure: Color32,
    pub caution: Color32,
}

const fn hex(rgb: u32) -> Color32 {
    let [_, r, g, b] = rgb.to_be_bytes();
    Color32::from_rgb(r, g, b)
}

const LIGHT: Palette = Palette {
    paper: hex(0xF6_F3_EC),
    card: hex(0xFF_FE_FB),
    ink: hex(0x1D_26_2B),
    muted: hex(0x66_6F_75),
    line: hex(0xE2_DD_D2),
    accent: hex(0x0F_76_6E),
    on_accent: hex(0xFF_FF_FF),
    accent_soft: hex(0xD7_ED_E9),
    direct: hex(0xB9_3A_14),
    correlating: hex(0xA0_62_08),
    incidental: hex(0x5F_6B_77),
    success: hex(0x17_7A_3C),
    failure: hex(0xB4_23_18),
    caution: hex(0x8A_5A_00),
};

const DARK: Palette = Palette {
    paper: hex(0x12_16_18),
    card: hex(0x1B_21_24),
    ink: hex(0xE8_E6_E1),
    muted: hex(0x9A_A2_A7),
    line: hex(0x2C_34_38),
    accent: hex(0x3C_CF_BC),
    on_accent: hex(0x06_2A_26),
    accent_soft: hex(0x16_3A_36),
    direct: hex(0xFF_8A_5C),
    correlating: hex(0xF2_BD_4B),
    incidental: hex(0x9B_A8_B4),
    success: hex(0x5F_D3_8A),
    failure: hex(0xFF_7B_70),
    caution: hex(0xF2_BD_4B),
};

pub fn of(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode {
        &DARK
    } else {
        &LIGHT
    }
}

/// Applied to both themes once; the system's setting chooses between them.
pub fn install(ctx: &egui::Context) {
    for (theme, p) in [(Theme::Light, &LIGHT), (Theme::Dark, &DARK)] {
        ctx.style_mut_of(theme, |style| {
            let radius = CornerRadius::same(8);
            let v = &mut style.visuals;
            v.panel_fill = p.paper;
            v.window_fill = p.card;
            v.faint_bg_color = p.card;
            v.extreme_bg_color = p.card;
            v.override_text_color = Some(p.ink);
            v.weak_text_color = Some(p.muted);
            v.hyperlink_color = p.accent;
            v.warn_fg_color = p.caution;
            v.error_fg_color = p.failure;
            v.selection.bg_fill = p.accent_soft;
            v.selection.stroke = Stroke::new(1.5, p.accent);
            for w in [
                &mut v.widgets.noninteractive,
                &mut v.widgets.inactive,
                &mut v.widgets.hovered,
                &mut v.widgets.active,
                &mut v.widgets.open,
            ] {
                w.corner_radius = radius;
                w.fg_stroke.color = p.ink;
            }
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
            v.widgets.inactive.weak_bg_fill = p.card;
            v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.line);
            v.widgets.hovered.weak_bg_fill = p.accent_soft;
            v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);
            v.widgets.active.weak_bg_fill = p.accent_soft;
            v.widgets.active.bg_stroke = Stroke::new(1.5, p.accent);

            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            let size = |points| FontId::new(points, FontFamily::Proportional);
            style.text_styles = [
                (TextStyle::Heading, size(22.0)),
                (TextStyle::Body, size(15.0)),
                (TextStyle::Button, size(15.0)),
                (TextStyle::Small, size(12.5)),
                (
                    TextStyle::Monospace,
                    FontId::new(13.0, FontFamily::Monospace),
                ),
            ]
            .into();
        });
    }
}
