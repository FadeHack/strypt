//! Drop or choose files, get a `*.stripped.*` copy of each beside it, one row per file.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui;
use strypt_gui::{Backend, Diff, Status, Tone};

mod icon;

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
            ui.heading("strypt");
            ui.label(
                "Saves a copy of each file beside the original, as NAME.stripped.EXT, without \
                 the hidden metadata strypt knows about: location, device and author names, \
                 timestamps, editing history. The original is not changed.",
            );
            ui.add_space(8.0);
            if self.backend == Backend::WaylandWithoutDrops {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    "Dragging files onto this window does not work on this desktop. \
                     Use Open files… instead.",
                );
            }
            self.drop_zone(ui);
            if self.rows.is_empty() {
                return;
            }
            ui.add_space(8.0);
            self.summary(ui);
            // Many files at once: start them closed, so the list stays scannable.
            let open = self.rows.len() <= 3;
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (index, (path, status)) in self.rows.iter().enumerate() {
                    row(ui, index, path, status, open);
                }
            });
        });
    }
}

impl App {
    /// The window's main target. It lights up while files are held over it.
    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let visuals = ui.visuals();
        let (stroke, fill) = if hovering {
            (
                egui::Stroke::new(2.5, visuals.selection.stroke.color),
                visuals.selection.bg_fill.gamma_multiply(0.35),
            )
        } else {
            (
                egui::Stroke::new(1.5, visuals.widgets.inactive.bg_stroke.color),
                visuals.faint_bg_color,
            )
        };
        let height = if self.rows.is_empty() { 220.0 } else { 120.0 };
        egui::Frame::new()
            .fill(fill)
            .stroke(stroke)
            .corner_radius(12.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.set_min_size(egui::vec2(ui.available_width(), height));
                ui.vertical_centered(|ui| {
                    ui.add_space(height / 2.0 - 48.0);
                    if hovering {
                        ui.heading("Release to clean");
                        return;
                    }
                    ui.heading("Drop files here");
                    ui.label("or");
                    let button = egui::Button::new(egui::RichText::new("Open files…").size(16.0))
                        .min_size(egui::vec2(140.0, 32.0));
                    if ui.add_enabled(self.picked.is_none(), button).clicked() {
                        self.open_files(ui.ctx());
                    }
                    if self.nothing_chosen {
                        ui.label("No files were chosen.");
                    }
                });
            });
    }

    fn summary(&mut self, ui: &mut egui::Ui) {
        let count = |tone| self.rows.iter().filter(|(_, s)| s.tone() == tone).count();
        let (cleaned, failed, busy) = (
            count(Tone::Success),
            count(Tone::Failure),
            count(Tone::Pending),
        );
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("{cleaned} cleaned")).strong());
            if failed > 0 {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    egui::RichText::new(format!("{failed} not cleaned")).strong(),
                );
            }
            if busy > 0 {
                ui.spinner();
                ui.label(format!("{busy} working"));
            } else if ui.button("Clear list").clicked() {
                self.rows.clear();
            }
        });
        ui.add_space(4.0);
    }
}

fn row(ui: &mut egui::Ui, index: usize, path: &std::path::Path, status: &Status, open: bool) {
    let colour = match status.tone() {
        Tone::Success if ui.visuals().dark_mode => egui::Color32::from_rgb(0x81, 0xc7, 0x84),
        Tone::Success => egui::Color32::from_rgb(0x2e, 0x7d, 0x32),
        Tone::Failure => ui.visuals().error_fg_color,
        Tone::Pending => ui.visuals().weak_text_color(),
    };
    egui::Frame::group(ui.style())
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(8.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                if status.tone() == Tone::Pending {
                    ui.spinner();
                } else {
                    let (dot, _) =
                        ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 6.0, colour);
                }
                ui.colored_label(colour, egui::RichText::new(status.headline()).strong());
                ui.label(
                    egui::RichText::new(path.file_name().unwrap_or_default().to_string_lossy())
                        .strong(),
                );
            });
            let detail = status.detail();
            if !detail.is_empty() {
                ui.label(detail);
            }
            if let Status::Cleaned { diff, .. } = status {
                egui::CollapsingHeader::new(diff.summary())
                    .id_salt(index)
                    .default_open(open)
                    .show(ui, |ui| show_diff(ui, diff));
            }
        });
    ui.add_space(6.0);
}

fn show_diff(ui: &mut egui::Ui, diff: &Diff) {
    ui.weak(strypt_gui::SENSITIVITY_KEY);
    for section in diff.sections() {
        ui.add_space(4.0);
        ui.label(egui::RichText::new(section.title).strong());
        if section.lines.is_empty() {
            ui.label(section.empty);
        }
        for line in section.lines {
            ui.horizontal_wrapped(|ui| {
                ui.add_sized(
                    [18.0, 0.0],
                    egui::Label::new(egui::RichText::new(line.mark).strong()),
                );
                let text = ui.label(line.text);
                if let Some(words) = line.sensitivity {
                    text.on_hover_text(words);
                }
            });
        }
    }
    ui.add_space(4.0);
    for caveat in Diff::caveats() {
        ui.colored_label(ui.visuals().warn_fg_color, caveat);
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
        viewport: egui::ViewportBuilder::default()
            .with_title("strypt")
            .with_inner_size([720.0, 720.0])
            .with_min_inner_size([480.0, 420.0])
            .with_icon(icon::icon())
            .with_drag_and_drop(true),
        event_loop_builder: event_loop(backend),
        ..Default::default()
    };
    eframe::run_native(
        "strypt",
        options,
        Box::new(move |cc| {
            // The theme follows the system's, but winit 0.30 reports none on X11, where Linux
            // starts (ADR-0059); most desktops default to light.
            cc.egui_ctx
                .options_mut(|o| o.fallback_theme = egui::Theme::Light);
            Ok(Box::new(App::new(cc.egui_ctx.clone(), backend)))
        }),
    )
}
