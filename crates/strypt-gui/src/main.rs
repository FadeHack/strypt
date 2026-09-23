//! Drop files, get a `*.stripped.*` copy of each beside it, one row per file.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui;
use strypt_gui::{Status, Tone};

struct App {
    rows: Vec<(PathBuf, Status)>,
    jobs: Sender<(usize, PathBuf)>,
    results: Receiver<(usize, Status)>,
}

impl App {
    /// One worker, files in drop order: overlapping batches never race for an output name.
    fn new(ctx: egui::Context) -> Self {
        let (jobs, inbox) = channel::<(usize, PathBuf)>();
        let (outbox, results) = channel();
        std::thread::spawn(move || {
            for (row, path) in inbox {
                if outbox
                    .send((row, strypt_gui::process(&path, None)))
                    .is_err()
                {
                    return;
                }
                ctx.request_repaint();
            }
        });
        Self {
            rows: Vec::new(),
            jobs,
            results,
        }
    }

    fn enqueue(&mut self, path: PathBuf) {
        let row = self.rows.len();
        let status = match self.jobs.send((row, path.clone())) {
            Ok(()) => Status::Working,
            Err(_) => Status::Refused("strypt's worker stopped; restart strypt".into()),
        };
        self.rows.push((path, status));
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            self.enqueue(file.path().to_path_buf());
        }
        while let Ok((row, status)) = self.results.try_recv() {
            if let Some(slot) = self.rows.get_mut(row) {
                slot.1 = status;
            }
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Drop files here");
            ui.label("Each cleaned copy is saved beside its original as NAME.stripped.EXT.");
            if self.rows.is_empty() {
                return;
            }
            let failed = self
                .rows
                .iter()
                .filter(|(_, s)| s.tone() == Tone::Failure)
                .count();
            let cleaned = self
                .rows
                .iter()
                .filter(|(_, s)| s.tone() == Tone::Success)
                .count();
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(format!("{cleaned} cleaned"));
                if failed > 0 {
                    ui.colored_label(ui.visuals().error_fg_color, format!("{failed} not cleaned"));
                }
                let busy = self.rows.iter().any(|(_, s)| s.tone() == Tone::Pending);
                if !busy && ui.button("Clear list").clicked() {
                    self.rows.clear();
                }
            });
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (path, status) in &self.rows {
                    row(ui, path, status);
                }
            });
        });
    }
}

fn row(ui: &mut egui::Ui, path: &std::path::Path, status: &Status) {
    let colour = match status.tone() {
        Tone::Success if ui.visuals().dark_mode => egui::Color32::from_rgb(0x81, 0xc7, 0x84),
        Tone::Success => egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
        Tone::Failure => ui.visuals().error_fg_color,
        Tone::Pending => ui.visuals().weak_text_color(),
    };
    ui.separator();
    ui.horizontal(|ui| {
        ui.colored_label(colour, egui::RichText::new(status.headline()).strong());
        ui.label(path.file_name().unwrap_or_default().to_string_lossy());
    });
    let detail = status.detail();
    if !detail.is_empty() {
        ui.label(detail);
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
        Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone())))),
    )
}
