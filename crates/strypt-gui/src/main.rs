//! Drop or choose files, get a `*.stripped.*` copy of each beside it, one row per file.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui;
use strypt_gui::{Backend, Status, Tone};

struct App {
    rows: Vec<(PathBuf, Status)>,
    jobs: Sender<(usize, PathBuf)>,
    results: Receiver<(usize, Status)>,
    picked: Option<Receiver<Option<Vec<PathBuf>>>>,
    nothing_chosen: bool,
    backend: Backend,
}

impl App {
    /// One worker, files in arrival order: overlapping batches never race for an output name.
    fn new(ctx: egui::Context, backend: Backend) -> Self {
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
            picked: None,
            nothing_chosen: false,
            backend,
        }
    }

    fn enqueue(&mut self, path: PathBuf) {
        self.nothing_chosen = false;
        let row = self.rows.len();
        let status = match self.jobs.send((row, path.clone())) {
            Ok(()) => Status::Working,
            Err(_) => Status::Refused("strypt's worker stopped; restart strypt".into()),
        };
        self.rows.push((path, status));
    }

    /// macOS requires its open panel on the main thread; elsewhere the dialog blocks, so it
    /// gets its own thread to keep the window drawing.
    fn open_files(&mut self, ctx: &egui::Context) {
        let dialog = rfd::FileDialog::new().set_title("Choose files to clean");
        if cfg!(target_os = "macos") {
            self.chosen(dialog.pick_files());
            return;
        }
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(dialog.pick_files());
            ctx.request_repaint();
        });
        self.picked = Some(rx);
    }

    /// rfd returns nothing both on Cancel and when no dialog could be shown, so say only what
    /// is certain.
    fn chosen(&mut self, files: Option<Vec<PathBuf>>) {
        match files {
            Some(files) if !files.is_empty() => files.into_iter().for_each(|f| self.enqueue(f)),
            _ => self.nothing_chosen = true,
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            self.enqueue(file.path().to_path_buf());
        }
        if let Some(rx) = &self.picked
            && let Ok(files) = rx.try_recv()
        {
            self.picked = None;
            self.chosen(files);
        }
        while let Ok((row, status)) = self.results.try_recv() {
            if let Some(slot) = self.rows.get_mut(row) {
                slot.1 = status;
            }
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Drop files here, or choose them");
            ui.label("Each cleaned copy is saved beside its original as NAME.stripped.EXT.");
            if self.backend == Backend::WaylandWithoutDrops {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "Dragging files onto this window does not work on this desktop. \
                     Use Open files… instead.",
                );
            }
            ui.horizontal(|ui| {
                let open = ui.add_enabled(self.picked.is_none(), egui::Button::new("Open files…"));
                if open.clicked() {
                    self.open_files(ui.ctx());
                }
                if self.nothing_chosen {
                    ui.label("No files were chosen.");
                }
            });
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

#[cfg(target_os = "linux")]
fn backend() -> Backend {
    let set = |name| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    Backend::choose(
        set("DISPLAY"),
        set("WAYLAND_DISPLAY") || set("WAYLAND_SOCKET"),
    )
}

#[cfg(not(target_os = "linux"))]
const fn backend() -> Backend {
    Backend::Default
}

#[cfg(target_os = "linux")]
fn event_loop(backend: Backend) -> Option<eframe::EventLoopBuilderHook> {
    use winit::platform::x11::EventLoopBuilderExtX11 as _;
    (backend == Backend::X11).then(|| -> eframe::EventLoopBuilderHook {
        Box::new(|builder| {
            builder.with_x11();
        })
    })
}

#[cfg(not(target_os = "linux"))]
fn event_loop(_: Backend) -> Option<eframe::EventLoopBuilderHook> {
    None
}

fn main() -> eframe::Result {
    let backend = backend();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_drag_and_drop(true),
        event_loop_builder: event_loop(backend),
        ..Default::default()
    };
    eframe::run_native(
        "strypt",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc.egui_ctx.clone(), backend)))),
    )
}
