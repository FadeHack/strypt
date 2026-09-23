//! Drop or choose files, get a `*.stripped.*` copy of each, one card per file.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, Align, Color32, Layout, Margin, RichText, Sense, Stroke, vec2};
use strypt_core::Walk;
use strypt_core::report::Sensitivity;
use strypt_gui::{Backend, Diff, Group, Status, Tone};

mod icon;
mod theme;

/// Seconds for a strike to cross one label, and between one label's strike and the next.
const STRIKE: f32 = 0.4;
const STAGGER: f32 = 0.16;

struct Row {
    /// The file's name, or its path from the dropped folder.
    label: String,
    status: Status,
    /// When the result arrived, in egui's clock; the strike-through starts here.
    done_at: f64,
    /// The folder drop this row came from, whose unsupported files share one card.
    batch: Option<usize>,
}

/// A dropped folder, walked and waiting to be confirmed.
struct Survey {
    root: PathBuf,
    walk: Walk,
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

enum Picked {
    Files(Option<Vec<PathBuf>>),
    Folder(Option<PathBuf>),
}

type Job = (usize, PathBuf, Option<PathBuf>);

struct App {
    rows: Vec<Row>,
    jobs: Sender<Job>,
    results: Receiver<(usize, Status)>,
    picked: Option<Receiver<Picked>>,
    nothing_chosen: bool,
    /// `None` saves each copy beside its original, as the CLI does.
    output_dir: Option<PathBuf>,
    backend: Backend,
    /// Folder names by batch.
    batches: Vec<String>,
    surveys: (Sender<Survey>, Receiver<Survey>),
    /// Folders still being walked.
    looking: Vec<String>,
    /// Walked folders waiting for the user's yes, first shown first.
    asking: VecDeque<Survey>,
}

impl App {
    /// One worker, files in arrival order: overlapping batches never race for an output name.
    fn new(ctx: egui::Context, backend: Backend) -> Self {
        let (jobs, inbox) = channel::<Job>();
        let (outbox, results) = channel();
        std::thread::spawn(move || {
            for (row, path, output_dir) in inbox {
                let status = strypt_gui::process(&path, output_dir.as_deref());
                if outbox.send((row, status)).is_err() {
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
            output_dir: None,
            backend,
            batches: Vec::new(),
            surveys: channel(),
            looking: Vec::new(),
            asking: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, path: PathBuf, label: String, batch: Option<usize>) {
        self.nothing_chosen = false;
        let row = self.rows.len();
        let status = match self.jobs.send((row, path, self.output_dir.clone())) {
            Ok(()) => Status::Working,
            Err(_) => Status::Refused("strypt's worker stopped; restart strypt".into()),
        };
        self.rows.push(Row {
            label,
            status,
            done_at: 0.0,
            batch,
        });
    }

    /// A folder is walked off the window's thread, then confirmed before anything is written.
    fn add(&mut self, ctx: &egui::Context, path: PathBuf) {
        if !path.is_dir() {
            let label = name_of(&path);
            self.enqueue(path, label, None);
            return;
        }
        self.nothing_chosen = false;
        self.looking.push(name_of(&path));
        let tx = self.surveys.0.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let walk = strypt_core::walk(&path);
            let _ = tx.send(Survey { root: path, walk });
            ctx.request_repaint();
        });
    }

    fn surveyed(&mut self, survey: Survey, now: f64) {
        let name = name_of(&survey.root);
        if let Some(at) = self.looking.iter().position(|n| *n == name) {
            self.looking.remove(at);
        }
        if survey.walk.files.is_empty() {
            self.accept(survey, now);
        } else {
            self.asking.push_back(survey);
        }
    }

    /// One row per file and per skipped entry, labelled from the dropped folder down.
    fn accept(&mut self, survey: Survey, now: f64) {
        let Survey { root, walk } = survey;
        let batch = self.batches.len();
        self.batches.push(name_of(&root));
        let base = root.parent().unwrap_or(&root).to_path_buf();
        let label = |path: &Path| {
            path.strip_prefix(&base)
                .unwrap_or(path)
                .display()
                .to_string()
        };
        if walk.files.is_empty() && walk.skipped.is_empty() {
            self.rows.push(Row {
                label: label(&root),
                status: Status::Refused("This folder holds no files".into()),
                done_at: now,
                batch: Some(batch),
            });
        }
        for file in walk.files {
            let text = label(&file);
            self.enqueue(file, text, Some(batch));
        }
        for entry in &walk.skipped {
            self.rows.push(Row {
                label: label(&entry.path),
                status: strypt_gui::skipped(entry),
                done_at: now,
                batch: Some(batch),
            });
        }
    }

    /// Where copies will go, in the confirmation's words.
    fn destination(&self) -> String {
        match &self.output_dir {
            None => "Each cleaned copy will be saved next to its original.".into(),
            Some(dir) => format!("Cleaned copies will be saved in {}.", name_of(dir)),
        }
    }

    fn confirm(&mut self, ctx: &egui::Context, now: f64) {
        let Some(survey) = self.asking.front() else {
            return;
        };
        let name = name_of(&survey.root);
        let count = survey.walk.files.len();
        let summary = strypt_gui::folder_summary(&survey.walk);
        let destination = self.destination();
        let mut answer = None;
        let modal = egui::Modal::new(egui::Id::new("confirm-folder")).show(ctx, |ui| {
            let p = theme::of(ui);
            ui.set_max_width(420.0);
            ui.label(
                RichText::new(format!("Clean the files in {name}?"))
                    .size(20.0)
                    .color(p.ink),
            );
            ui.add_space(6.0);
            ui.label(RichText::new(summary).color(p.ink));
            ui.label(RichText::new(destination).color(p.muted));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let files = if count == 1 { "file" } else { "files" };
                let clean = egui::Button::new(
                    RichText::new(format!("Clean {count} {files}")).color(p.on_accent),
                )
                .fill(p.accent)
                .corner_radius(8.0);
                if ui.add(clean).clicked() {
                    answer = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    answer = Some(false);
                }
            });
        });
        // Escape or a click outside is a Cancel.
        if answer.is_none() && modal.should_close() {
            answer = Some(false);
        }
        if let Some(yes) = answer
            && let Some(survey) = self.asking.pop_front()
            && yes
        {
            self.accept(survey, now);
        }
    }

    /// macOS requires its dialogs on the main thread; elsewhere a dialog blocks, so it gets its
    /// own thread to keep the window drawing.
    fn ask(&mut self, ctx: &egui::Context, folder: bool) {
        if self.picked.is_some() {
            return;
        }
        let dialog = rfd::FileDialog::new();
        let pick = move || {
            if folder {
                Picked::Folder(
                    dialog
                        .set_title("Choose where to save cleaned copies")
                        .pick_folder(),
                )
            } else {
                Picked::Files(dialog.set_title("Choose files to clean").pick_files())
            }
        };
        if cfg!(target_os = "macos") {
            self.receive(pick());
            return;
        }
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(pick());
            ctx.request_repaint();
        });
        self.picked = Some(rx);
    }

    /// rfd returns nothing both on Cancel and when no dialog could be shown, so say only what
    /// is certain.
    fn receive(&mut self, picked: Picked) {
        match picked {
            Picked::Files(Some(files)) if !files.is_empty() => {
                for file in files {
                    let label = name_of(&file);
                    self.enqueue(file, label, None);
                }
            }
            Picked::Files(_) => self.nothing_chosen = true,
            Picked::Folder(Some(dir)) => self.output_dir = Some(dir),
            Picked::Folder(None) => {}
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);
        for file in ctx.input(|i| i.raw.dropped_files.clone()) {
            self.add(&ctx, file.path().to_path_buf());
        }
        while let Ok(survey) = self.surveys.1.try_recv() {
            self.surveyed(survey, now);
        }
        self.confirm(&ctx, now);
        if let Some(rx) = &self.picked
            && let Ok(picked) = rx.try_recv()
        {
            self.picked = None;
            self.receive(picked);
        }
        while let Ok((row, status)) = self.results.try_recv() {
            if let Some(slot) = self.rows.get_mut(row) {
                slot.status = status;
                slot.done_at = now;
            }
        }

        let p = theme::of(ui);
        egui::Panel::bottom("caveats")
            .frame(
                egui::Frame::new()
                    .fill(p.paper)
                    .inner_margin(Margin::symmetric(24, 12)),
            )
            .show(ui, caveats);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(p.paper)
                    .inner_margin(Margin::symmetric(24, 20)),
            )
            .show(ui, |ui| {
                header(ui, now);
                ui.add_space(18.0);
                if self.backend == Backend::WaylandWithoutDrops {
                    ui.colored_label(
                        p.caution,
                        "Dragging files onto this window does not work on this desktop. \
                         Use Open files… instead.",
                    );
                    ui.add_space(6.0);
                }
                self.drop_zone(ui);
                ui.add_space(10.0);
                self.save_location(ui);
                for name in &self.looking {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(format!("Looking inside {name}…")).color(p.muted));
                    });
                }
                if self.rows.is_empty() {
                    return;
                }
                ui.add_space(18.0);
                self.summary(ui);
                ui.add_space(6.0);
                let mut last = vec![0; self.batches.len()];
                for (index, row) in self.rows.iter().enumerate() {
                    if let Some(slot) = row.batch.and_then(|b| last.get_mut(b)) {
                        *slot = index;
                    }
                }
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        for (index, row) in self.rows.iter().enumerate() {
                            let folded =
                                row.batch.is_some() && matches!(row.status, Status::Unsupported(_));
                            if !folded {
                                card(ui, index, row, now);
                            }
                            if let Some(batch) = row.batch
                                && last.get(batch) == Some(&index)
                            {
                                self.unsupported_card(ui, batch);
                            }
                        }
                    });
            });

        let animating = now < 1.2
            || self.rows.iter().any(|row| match &row.status {
                Status::Cleaned { diff, .. } => now - row.done_at < strike_time(diff),
                _ => false,
            });
        if animating {
            ctx.request_repaint();
        }
    }
}

/// How long a card's strike-through runs.
fn strike_time(diff: &Diff) -> f64 {
    let groups = u16::try_from(diff.removed_groups().len()).unwrap_or(u16::MAX);
    f64::from(STAGGER * f32::from(groups) + STRIKE)
}

/// Eases 0..1 in and out, so a strike starts gently and lands softly.
fn ease(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a few seconds since launch"
)]
fn seconds(t: f64) -> f32 {
    t as f32
}

/// The mark, the wordmark underlined once at launch, and one line on what strypt does.
fn header(ui: &mut egui::Ui, now: f64) {
    let p = theme::of(ui);
    ui.horizontal(|ui| {
        let (mark, _) = ui.allocate_exact_size(vec2(52.0, 52.0), Sense::hover());
        icon::paint(ui.painter(), mark);
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.add_space(-2.0);
            let word = ui.label(RichText::new("strypt").size(34.0).color(p.ink));
            // An underline, not a strike: a struck-through name reads as cancelled.
            let t = ease((seconds(now) - 0.25) / 0.7);
            if t > 0.0 {
                let r = word.rect;
                let y = r.bottom() + 1.0;
                let end = r.left() + r.width() * t;
                ui.painter().line_segment(
                    [egui::pos2(r.left(), y), egui::pos2(end, y)],
                    Stroke::new(3.0, p.accent),
                );
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new("Take hidden details out of your files before you share them.")
                    .color(p.muted),
            );
        });
    });
}

/// A dashed outline around `rect`'s rounded corners.
fn dashed_outline(painter: &egui::Painter, rect: egui::Rect, radius: f32, stroke: Stroke) {
    let mut points = Vec::new();
    let corners = [
        (rect.right_top() + vec2(-radius, radius), -90.0_f32),
        (rect.right_bottom() + vec2(-radius, -radius), 0.0),
        (rect.left_bottom() + vec2(radius, -radius), 90.0),
        (rect.left_top() + vec2(radius, radius), 180.0),
    ];
    for (centre, start) in corners {
        for step in 0..=8u8 {
            let angle = (start + f32::from(step) * 90.0 / 8.0).to_radians();
            points.push(centre + radius * vec2(angle.cos(), angle.sin()));
        }
    }
    if let Some(&first) = points.first() {
        points.push(first);
    }
    painter.extend(egui::Shape::dashed_line(&points, stroke, 8.0, 6.0));
}

/// A small page with struck lines; `strike` 0..1 draws the strike across its lighter lines.
fn page(painter: &egui::Painter, centre: egui::Pos2, strike: f32, p: &theme::Palette) {
    let body = egui::Rect::from_center_size(centre, vec2(46.0, 58.0));
    painter.rect(
        body,
        6.0,
        p.card,
        Stroke::new(1.5, p.muted.gamma_multiply(0.6)),
        egui::StrokeKind::Inside,
    );
    for (row, (length, struck)) in
        (0u8..).zip([(26.0, false), (20.0, true), (24.0, false), (16.0, true)])
    {
        let y = body.top() + 14.0 + 10.0 * f32::from(row);
        let left = body.left() + 10.0;
        let colour = if struck {
            p.ink.lerp_to_gamma(p.line, strike)
        } else {
            p.ink.gamma_multiply(0.75)
        };
        painter.line_segment(
            [egui::pos2(left, y), egui::pos2(left + length, y)],
            Stroke::new(3.0, colour),
        );
        if struck && strike > 0.0 {
            painter.line_segment(
                [
                    egui::pos2(left - 4.0, y),
                    egui::pos2(left - 4.0 + (length + 8.0) * strike, y),
                ],
                Stroke::new(2.0, p.accent),
            );
        }
    }
}

impl App {
    /// The window's main target. It lights up, and its page's lines are struck, while files
    /// are held over it; clicking anywhere in it opens the file dialog.
    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let p = theme::of(ui);
        let ctx = ui.ctx().clone();
        let files_over = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let height = if self.rows.is_empty() {
            (ui.available_height() - 60.0).clamp(230.0, 380.0)
        } else {
            120.0
        };
        let (rect, zone) =
            ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
        let zone = zone.on_hover_cursor(egui::CursorIcon::PointingHand);
        zone.widget_info(|| {
            egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Choose files to clean")
        });
        let lit = ctx.animate_bool_with_time(zone.id.with("lit"), files_over, 0.2);
        let hover = ctx.animate_bool_with_time(zone.id.with("hover"), zone.hovered(), 0.15);

        let painter = ui.painter_at(rect.expand(2.0));
        painter.rect_filled(rect, 16.0, p.card.lerp_to_gamma(p.accent_soft, lit));
        let edge = p
            .muted
            .gamma_multiply(0.55)
            .lerp_to_gamma(p.accent, lit.max(hover * 0.6));
        dashed_outline(
            &painter,
            rect.shrink(1.0),
            16.0,
            Stroke::new(1.5 + lit, edge),
        );

        let clicked_button = if self.rows.is_empty() {
            let top = rect.center().y - 100.0;
            page(&painter, egui::pos2(rect.center().x, top + 30.0), lit, p);
            let inner = egui::Rect::from_min_max(
                egui::pos2(rect.left() + 16.0, top + 74.0),
                rect.right_bottom() - vec2(16.0, 12.0),
            );
            // Detached, so the zone's words do not move the cursor back inside it.
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(inner)
                    .layout(Layout::top_down(Align::Center)),
            );
            self.zone_text(&mut child, files_over, "Drop files or folders here")
        } else {
            page(&painter, rect.left_center() + vec2(56.0, 0.0), lit, p);
            let inner = egui::Rect::from_min_max(
                rect.left_top() + vec2(104.0, 16.0),
                rect.right_bottom() - vec2(16.0, 16.0),
            );
            // Detached, so the zone's words do not move the cursor back inside it.
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(inner)
                    .layout(Layout::top_down(Align::Min)),
            );
            self.zone_text(&mut child, files_over, "Drop more files or folders here")
        };
        if zone.clicked() && !clicked_button {
            self.ask(&ctx, false);
        }
    }

    /// The words and button inside the drop zone. Returns whether the button was clicked.
    fn zone_text(&mut self, ui: &mut egui::Ui, files_over: bool, prompt: &str) -> bool {
        let p = theme::of(ui);
        if files_over {
            ui.add_space(8.0);
            ui.label(
                RichText::new("Let go to clean them")
                    .size(22.0)
                    .color(p.accent),
            );
            return false;
        }
        ui.label(RichText::new(prompt).size(22.0).color(p.ink));
        ui.label(RichText::new("or").color(p.muted));
        let button = egui::Button::new(RichText::new("Open files…").color(p.on_accent))
            .fill(p.accent)
            .corner_radius(8.0)
            .min_size(vec2(132.0, 34.0));
        let clicked = ui.add_enabled(self.picked.is_none(), button).clicked();
        if clicked {
            self.ask(ui.ctx(), false);
        }
        if self.nothing_chosen {
            ui.label(RichText::new("No files were chosen.").color(p.muted));
        }
        clicked
    }

    /// Where copies go, as a choice between two places, so it cannot read as a folder to clean.
    /// It applies to files added from now on.
    fn save_location(&mut self, ui: &mut egui::Ui) {
        let p = theme::of(ui);
        let ctx = ui.ctx().clone();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Save cleaned copies").color(p.muted));
            if ui
                .radio(self.output_dir.is_none(), "next to each original")
                .clicked()
            {
                self.output_dir = None;
            }
            match &self.output_dir {
                None => {
                    if ui.radio(false, "in a folder I choose…").clicked() {
                        self.ask(&ctx, true);
                    }
                }
                Some(dir) => {
                    let name = dir.file_name().unwrap_or(dir.as_os_str()).to_string_lossy();
                    ui.radio(true, format!("in {name}"))
                        .on_hover_text(dir.display().to_string());
                    if ui.link("Change…").clicked() {
                        self.ask(&ctx, true);
                    }
                }
            }
        });
    }

    fn summary(&mut self, ui: &mut egui::Ui) {
        let p = theme::of(ui);
        let count = |tone| self.rows.iter().filter(|r| r.status.tone() == tone).count();
        let (cleaned, failed, busy) = (
            count(Tone::Success),
            count(Tone::Failure),
            count(Tone::Pending),
        );
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{cleaned} cleaned")).color(p.success));
            if failed > 0 {
                ui.label(RichText::new("·").color(p.muted));
                ui.label(RichText::new(format!("{failed} not cleaned")).color(p.failure));
            }
            if busy > 0 {
                ui.label(RichText::new("·").color(p.muted));
                ui.spinner();
                ui.label(RichText::new(format!("{busy} working")).color(p.muted));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if busy == 0 && ui.button("Clear list").clicked() {
                    self.rows.clear();
                    self.batches.clear();
                }
            });
        });
    }
}

impl App {
    /// A folder drop's unsupported files, as one card that lists them on request.
    fn unsupported_card(&self, ui: &mut egui::Ui, batch: usize) {
        let files: Vec<(&str, &str)> = self
            .rows
            .iter()
            .filter(|row| row.batch == Some(batch))
            .filter_map(|row| match &row.status {
                Status::Unsupported(reason) => Some((row.label.as_str(), reason.as_str())),
                _ => None,
            })
            .collect();
        if files.is_empty() {
            return;
        }
        let p = theme::of(ui);
        let folder = self.batches.get(batch).map_or("", String::as_str);
        let count = if files.len() == 1 {
            "1 file strypt does not support".to_string()
        } else {
            format!("{} files strypt does not support", files.len())
        };
        egui::Frame::new()
            .fill(p.card)
            .stroke(Stroke::new(1.0, p.line))
            .corner_radius(14.0)
            .inner_margin(Margin::same(18))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(count).size(18.0).color(p.ink));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        pill(ui, "Not cleaned: unsupported", Tone::Failure);
                    });
                });
                ui.label(
                    RichText::new(format!("In {folder}. No file was written for them."))
                        .size(13.0)
                        .color(p.muted),
                );
                ui.add_space(6.0);
                egui::CollapsingHeader::new(RichText::new("Which files").color(p.muted))
                    .id_salt(("unsupported", batch))
                    .default_open(false)
                    .show(ui, |ui| {
                        for (label, reason) in files {
                            ui.label(RichText::new(label).color(p.ink));
                            ui.label(RichText::new(reason).size(13.0).color(p.muted));
                        }
                    });
            });
        ui.add_space(10.0);
    }
}

fn tone_colour(tone: Tone, p: &theme::Palette) -> Color32 {
    match tone {
        Tone::Success => p.success,
        Tone::Failure => p.failure,
        Tone::Pending => p.muted,
    }
}

fn sensitivity_colour(sensitivity: Sensitivity, p: &theme::Palette) -> Color32 {
    match sensitivity {
        Sensitivity::Direct => p.direct,
        Sensitivity::Correlating => p.correlating,
        _ => p.incidental,
    }
}

fn card(ui: &mut egui::Ui, index: usize, row: &Row, now: f64) {
    let p = theme::of(ui);
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(14.0)
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(&row.label).size(18.0).color(p.ink));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    pill(ui, row.status.headline(), row.status.tone());
                });
            });
            let detail = row.status.detail();
            if !detail.is_empty() {
                ui.label(RichText::new(detail).size(13.0).color(p.muted));
            }
            if let Status::Cleaned { diff, .. } = &row.status {
                results(ui, index, diff, seconds(now - row.done_at));
            }
        });
    ui.add_space(10.0);
}

fn pill(ui: &mut egui::Ui, headline: &str, tone: Tone) {
    let p = theme::of(ui);
    let colour = tone_colour(tone, p);
    egui::Frame::new()
        .fill(colour.gamma_multiply(0.14))
        .corner_radius(99.0)
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            // Laid out right to left, so the dot is added after the words to sit before them.
            ui.horizontal(|ui| {
                ui.label(RichText::new(headline).color(colour));
                if tone == Tone::Pending {
                    ui.spinner();
                } else {
                    let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                    ui.painter().circle_filled(dot.center(), 4.0, colour);
                }
            });
        });
}

/// What came out, struck through one kind at a time; then what stayed and why.
fn results(ui: &mut egui::Ui, index: usize, diff: &Diff, elapsed: f32) {
    let p = theme::of(ui);
    ui.add_space(12.0);
    let groups = diff.removed_groups();
    if groups.is_empty() {
        ui.label(
            RichText::new("strypt found nothing it knows to look for, so nothing was removed.")
                .color(p.ink),
        );
    } else {
        let kinds = if groups.len() == 1 {
            "1 kind".to_string()
        } else {
            format!("{} kinds", groups.len())
        };
        ui.label(
            RichText::new(format!("Removed {kinds} of hidden detail"))
                .size(13.0)
                .color(p.muted),
        );
        ui.add_space(2.0);
        for (step, group) in (0u16..).zip(&groups) {
            let t = ease((elapsed - STAGGER * f32::from(step)) / STRIKE);
            struck(ui, group, t);
        }
    }
    let [_, _, kept, notes] = diff.sections();
    if !kept.lines.is_empty() {
        ui.add_space(8.0);
        ui.label(RichText::new("Kept on purpose").size(13.0).color(p.muted));
        for line in kept.lines {
            ui.label(RichText::new(line.text).color(p.ink));
        }
    }
    for line in notes.lines {
        ui.add_space(6.0);
        note(ui, &line.text);
    }
    ui.add_space(6.0);
    egui::CollapsingHeader::new(RichText::new("Technical details").color(p.muted))
        .id_salt(index)
        .default_open(false)
        .show(ui, |ui| technical(ui, diff));
}

/// One removed kind: its mark, its name with a strike drawn `t` of the way across, its count.
fn struck(ui: &mut egui::Ui, group: &Group, t: f32) {
    let p = theme::of(ui);
    let colour = sensitivity_colour(group.sensitivity, p);
    ui.horizontal(|ui| {
        ui.add_sized(
            [22.0, 22.0],
            egui::Label::new(RichText::new(group.mark).color(colour)),
        );
        let label = ui
            .label(
                RichText::new(group.label)
                    .size(16.0)
                    .color(p.ink.lerp_to_gamma(p.muted, t * 0.35)),
            )
            .on_hover_text(strypt_gui::sensitivity_words(group.sensitivity));
        if t > 0.0 {
            let r = label.rect;
            let y = r.center().y + 1.0;
            let end = r.left() - 2.0 + (r.width() + 4.0) * t;
            ui.painter().line_segment(
                [egui::pos2(r.left() - 2.0, y), egui::pos2(end, y)],
                Stroke::new(1.6, colour.gamma_multiply(0.8)),
            );
        }
        let fields = if group.fields == 1 {
            "1 field".to_string()
        } else {
            format!("{} fields", group.fields)
        };
        ui.label(RichText::new(fields).size(13.0).color(p.muted));
    });
}

/// A caveat from core, with a bar down its left edge.
fn note(ui: &mut egui::Ui, text: &str) {
    let p = theme::of(ui);
    let response = egui::Frame::new()
        .inner_margin(Margin {
            left: 12,
            right: 0,
            top: 2,
            bottom: 2,
        })
        .show(ui, |ui| ui.label(RichText::new(text).color(p.ink)));
    let r = response.response.rect;
    ui.painter()
        .line_segment([r.left_top(), r.left_bottom()], Stroke::new(3.0, p.caution));
}

/// The field-level list, in the CLI's words and marks.
fn technical(ui: &mut egui::Ui, diff: &Diff) {
    let p = theme::of(ui);
    ui.label(
        RichText::new(strypt_gui::SENSITIVITY_KEY)
            .size(13.0)
            .color(p.muted),
    );
    for section in diff.sections() {
        ui.add_space(4.0);
        ui.label(RichText::new(section.title).color(p.ink));
        if section.lines.is_empty() {
            ui.label(RichText::new(section.empty).color(p.muted));
        }
        for line in section.lines {
            ui.horizontal_wrapped(|ui| {
                ui.add_sized(
                    [18.0, 0.0],
                    egui::Label::new(RichText::new(line.mark).color(p.muted)),
                );
                let text = ui.label(RichText::new(line.text).size(13.0).color(p.muted));
                if let Some(words) = line.sensitivity {
                    text.on_hover_text(words);
                }
            });
        }
    }
}

/// Always on screen: what strypt does not touch, and what an empty result does not mean.
fn caveats(ui: &mut egui::Ui) {
    let p = theme::of(ui);
    ui.separator();
    for caveat in Diff::caveats() {
        ui.label(RichText::new(caveat).size(13.0).color(p.muted));
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
            theme::install(&cc.egui_ctx);
            Ok(Box::new(App::new(cc.egui_ctx.clone(), backend)))
        }),
    )
}
