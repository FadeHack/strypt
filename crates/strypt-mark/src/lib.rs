//! strypt's mark, drawn in code so no image file is committed, and the icon files each platform
//! wants made from it (ADR-0062). Plain `std`, so the GUI's build script can use it too.

#![forbid(unsafe_code)]

mod files;

pub use files::{icns, ico, png};

/// The side of the square the mark is designed on, in units.
pub const SIZE: u16 = 256;
const BACKGROUND: [f32; 3] = [0.06, 0.46, 0.43];
const PAGE: [f32; 3] = [0.97, 0.98, 0.99];
const INK: [f32; 3] = [0.20, 0.25, 0.33];

/// One rounded rectangle of the mark, on the [`SIZE`]-unit square.
pub struct Part {
    /// Centre, in units.
    pub centre: (f32, f32),
    /// Half the width and height, in units.
    pub half: (f32, f32),
    /// Corner radius, in units.
    pub radius: f32,
    /// Straight RGB, 0 to 1.
    pub colour: [f32; 3],
    /// Opacity, 0 to 1.
    pub alpha: f32,
}

/// A page whose lines are half struck away, on a rounded teal square, back to front.
pub fn parts() -> impl Iterator<Item = Part> {
    // (length, opacity): the faint lines are the ones strypt took out.
    const LINES: [(f32, f32); 5] = [
        (88.0, 1.0),
        (64.0, 0.22),
        (80.0, 1.0),
        (56.0, 0.22),
        (72.0, 1.0),
    ];
    let square = Part {
        centre: (128.0, 128.0),
        half: (120.0, 120.0),
        radius: 48.0,
        colour: BACKGROUND,
        alpha: 1.0,
    };
    let page = Part {
        centre: (128.0, 128.0),
        half: (64.0, 84.0),
        radius: 10.0,
        colour: PAGE,
        alpha: 1.0,
    };
    let lines = (0u8..).zip(LINES).map(|(row, (length, alpha))| Part {
        centre: (84.0 + length / 2.0, 80.0 + 24.0 * f32::from(row)),
        half: (length / 2.0, 5.0),
        radius: 5.0,
        colour: INK,
        alpha,
    });
    [square, page].into_iter().chain(lines)
}

/// The mark as `size` × `size` straight-alpha RGBA, row by row from the top.
pub fn pixels(size: u16) -> Vec<u8> {
    // Units of the design square per pixel.
    let unit = f32::from(SIZE) / f32::from(size);
    let mut rgba = Vec::with_capacity(usize::from(size) * usize::from(size) * 4);
    for y in 0..size {
        for x in 0..size {
            let p = ((f32::from(x) + 0.5) * unit, (f32::from(y) + 0.5) * unit);
            let mut px = [0.0; 4];
            for part in parts() {
                let distance = rounded_rect(p, part.centre, part.half, part.radius) / unit;
                over(&mut px, part.colour, cover(distance) * part.alpha);
            }
            rgba.extend(px.map(byte));
        }
    }
    rgba
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

/// A 0-to-1 channel as a byte.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to 0..=255 first"
)]
#[must_use]
pub fn byte(channel: f32) -> u8 {
    (channel * 255.0).round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_are_transparent_and_the_middle_opaque_at_every_size() {
        for size in [16u16, 256] {
            let px = pixels(size);
            let side = usize::from(size);
            assert_eq!(px.len(), side * side * 4);
            let alpha = |x: usize, y: usize| px[(y * side + x) * 4 + 3];
            assert_eq!(alpha(0, 0), 0);
            assert_eq!(alpha(side - 1, side - 1), 0);
            assert_eq!(alpha(side / 2, side / 2), 255);
        }
    }
}
