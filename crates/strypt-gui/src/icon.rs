//! The window and dock icon, drawn here: no image file ships, and nothing is decoded at startup.

use eframe::egui;

const SIZE: u16 = 256;
const BACKGROUND: [f32; 3] = [0.06, 0.46, 0.43];
const PAGE: [f32; 3] = [0.97, 0.98, 0.99];
const INK: [f32; 3] = [0.20, 0.25, 0.33];

/// A page whose lines are half struck away, on a rounded teal square.
pub fn icon() -> egui::IconData {
    // (length, opacity): the faint lines are the ones strypt took out.
    const LINES: [(f32, f32); 5] = [
        (88.0, 1.0),
        (64.0, 0.22),
        (80.0, 1.0),
        (56.0, 0.22),
        (72.0, 1.0),
    ];
    let mut rgba = Vec::with_capacity(usize::from(SIZE) * usize::from(SIZE) * 4);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let p = (f32::from(x) + 0.5, f32::from(y) + 0.5);
            let mut px = [0.0; 4];
            over(
                &mut px,
                BACKGROUND,
                cover(rounded_rect(p, (128.0, 128.0), (120.0, 120.0), 48.0)),
            );
            over(
                &mut px,
                PAGE,
                cover(rounded_rect(p, (128.0, 128.0), (64.0, 84.0), 10.0)),
            );
            for (row, (length, alpha)) in (0u8..).zip(LINES) {
                let centre = (84.0 + length / 2.0, 80.0 + 24.0 * f32::from(row));
                let ink = cover(rounded_rect(p, centre, (length / 2.0, 5.0), 5.0));
                over(&mut px, INK, ink * alpha);
            }
            rgba.extend(px.map(byte));
        }
    }
    egui::IconData {
        width: u32::from(SIZE),
        height: u32::from(SIZE),
        rgba,
    }
}

/// Signed distance from `p` to a rounded rectangle; negative inside.
fn rounded_rect(p: (f32, f32), centre: (f32, f32), half: (f32, f32), radius: f32) -> f32 {
    let qx = (p.0 - centre.0).abs() - half.0 + radius;
    let qy = (p.1 - centre.1).abs() - half.1 + radius;
    qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0) - radius
}

/// How much of a pixel a shape covers: one pixel of anti-aliasing at the edge.
fn cover(distance: f32) -> f32 {
    (0.5 - distance).clamp(0.0, 1.0)
}

/// Paint `colour` at opacity `alpha` over `px`, straight (not premultiplied) alpha.
fn over(px: &mut [f32; 4], colour: [f32; 3], alpha: f32) {
    let below = px[3] * (1.0 - alpha);
    let out = alpha + below;
    if out > 0.0 {
        for (c, src) in px.iter_mut().zip(colour) {
            *c = (src * alpha + *c * below) / out;
        }
    }
    px[3] = out;
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to 0..=255 first"
)]
fn byte(channel: f32) -> u8 {
    (channel * 255.0).round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_icon_is_square_with_transparent_corners_and_an_opaque_middle() {
        let icon = icon();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
        let alpha = |x: usize, y: usize| icon.rgba[(y * 256 + x) * 4 + 3];
        assert_eq!(alpha(0, 0), 0);
        assert_eq!(alpha(255, 255), 0);
        assert_eq!(alpha(128, 128), 255);
    }
}
