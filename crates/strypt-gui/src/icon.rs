//! The window and dock icon, drawn here: no image file ships, and nothing is decoded at startup.

use eframe::egui;

use strypt_mark::{self as mark, SIZE, byte};

/// The mark as window and dock icon pixels.
pub fn icon() -> egui::IconData {
    egui::IconData {
        width: u32::from(SIZE),
        height: u32::from(SIZE),
        rgba: mark::pixels(SIZE),
    }
}

/// The same mark as vector shapes, sharp at any scale, filling the square `rect`.
pub fn paint(painter: &egui::Painter, rect: egui::Rect) {
    let scale = rect.width() / f32::from(SIZE);
    for part in mark::parts() {
        let [r, g, b] = part.colour.map(byte);
        let shape = egui::Rect::from_center_size(
            rect.min + egui::vec2(part.centre.0, part.centre.1) * scale,
            egui::vec2(part.half.0, part.half.1) * 2.0 * scale,
        );
        painter.rect_filled(
            shape,
            part.radius * scale,
            egui::Color32::from_rgba_unmultiplied(r, g, b, byte(part.alpha)),
        );
    }
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
