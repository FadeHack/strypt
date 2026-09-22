//! Phase 5 spike: drop one file, strip it in memory, list what was removed. Writes nothing.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use eframe::egui;
use strypt_core::report::StripReport;

#[derive(Default)]
struct Spike {
    last: Option<(PathBuf, Result<StripReport, String>)>,
}

impl eframe::App for Spike {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.first().cloned());
        if let Some(file) = dropped {
            let path = file.path().to_path_buf();
            let outcome = strypt_gui::clean(&path)
                .map(|s| s.report)
                .map_err(|e| e.to_string());
            self.last = Some((path, outcome));
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Drop one file here");
            let Some((path, outcome)) = &self.last else {
                return;
            };
            ui.label(path.display().to_string());
            match outcome {
                Ok(report) => {
                    ui.label(format!(
                        "{:?}: {} removed, {} kept",
                        report.format,
                        report.removed.len(),
                        report.retained.len()
                    ));
                    // Field names only: StripOptions::default() never carries values.
                    for f in &report.removed {
                        ui.label(format!(
                            "{:?} · {} {}",
                            f.kind,
                            f.location,
                            f.field.as_deref().unwrap_or("")
                        ));
                    }
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
            }
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "strypt",
        options,
        Box::new(|_cc| Ok(Box::<Spike>::default())),
    )
}
