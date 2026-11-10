//! The request window: QR code (or "check your phone"), a status line, and
//! request-scoped Cancel / explicit selection buttons.
//!
//! eframe owns the main thread while a window exists. [`show`] blocks until
//! the window closes, which the app does itself once the request reaches a
//! terminal state (after a short linger so the user sees the outcome) or when
//! the user closes the window (cancelling only a still-active original request).
//! eframe reuses one winit event loop across calls, so `show` can be called
//! once per request on the main thread.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Color32, ColorImage, RichText, TextureHandle, TextureOptions, ViewportCommand,
};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::ctaphid::RequestId;
use crate::hybrid::{Hint, Status};

/// An explicit user action, bound to the request that opened the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Cancel { request: RequestId },
    Select { request: RequestId },
}

const WINDOW_SIZE: [f32; 2] = [380.0, 560.0];
const CORNER_RADIUS: f32 = 12.0;
const HEADER_HEIGHT: f32 = 46.0;
const QR_PIXELS: f32 = 272.0;
/// How long the window stays after a successful request.
const DONE_LINGER: Duration = Duration::from_millis(1200);
/// How long an error message stays before the window closes.
const FAILED_LINGER: Duration = Duration::from_secs(4);

/// Block the calling (main) thread showing the window for the supplied request.
/// The caller must pass the same ID it recorded as shown, not reread a newer ID.
pub fn show(
    status_rx: watch::Receiver<Status>,
    action_tx: mpsc::UnboundedSender<Action>,
    request_rx: watch::Receiver<Option<RequestId>>,
    request: RequestId,
) -> Result<(), eframe::Error> {
    // The caller may have observed A just before B replaced it. Never adopt B:
    // doing so would leave the caller believing it had only displayed A, and
    // could reopen B after its window closes. Keep the supplied identity for
    // the entire window lifetime, including races during eframe startup.
    if *request_rx.borrow() != Some(request) {
        return Ok(());
    }
    let screenshots = std::env::var_os("POCKETKEY_UI_SCREENSHOT_DIR").and_then(|dir| {
        match Screenshots::new(Path::new(&dir)) {
            Ok(shots) => Some(shots),
            Err(error) => {
                warn!(%error, "screenshots disabled: directory must be private and contain no symlinks");
                None
            }
        }
    });
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pocketkey")
            .with_app_id("pocketkey")
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(WINDOW_SIZE)
            .with_resizable(false)
            // GNOME draws no title bar for non-GTK windows on Wayland and the
            // toolkit's imitation looks foreign, so the dialog draws its own
            // header (see `draw_header`). Transparent so the corners can be
            // rounded like a native dialog.
            .with_decorations(false)
            .with_transparent(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "pocketkey",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(App {
                status_rx,
                action_tx,
                request_rx,
                actions: RequestActions::new(request),
                qr: None,
                terminal_since: None,
                closing: false,
                screenshots,
                last_shot_status: None,
                shot_count: 0,
            }))
        }),
    )
}

struct App {
    status_rx: watch::Receiver<Status>,
    action_tx: mpsc::UnboundedSender<Action>,
    request_rx: watch::Receiver<Option<RequestId>>,
    actions: RequestActions,
    /// Cached QR texture for the payload currently displayed.
    qr: Option<(String, TextureHandle)>,
    /// When the request reached Done/Failed, for the linger timer.
    terminal_since: Option<(Status, Instant)>,
    closing: bool,
    /// Debug captures are private, never overwrite files, and redact the QR
    /// region before encoding. Raw QR pixels are never written to disk.
    screenshots: Option<Screenshots>,
    last_shot_status: Option<String>,
    shot_count: u32,
}

impl App {
    fn maybe_capture(&mut self, ctx: &egui::Context, shown: &Status, qr_rect: Option<egui::Rect>) {
        if self.screenshots.is_none() {
            return;
        }
        let label = match shown {
            Status::Idle => "Idle",
            Status::Starting => "Starting",
            Status::Selecting => "Selecting",
            Status::ShowQr { .. } => "ShowQr",
            Status::LinkedWaitingForPhone { .. } => "LinkedWaitingForPhone",
            Status::PhoneFound => "PhoneFound",
            Status::Connected => "Connected",
            Status::WaitingForUser => "WaitingForUser",
            Status::Done => "Done",
            Status::Failed(_) => "Failed",
        };
        if self.last_shot_status.as_deref() == Some(label) {
            return;
        }
        self.last_shot_status = Some(label.to_string());
        self.shot_count += 1;
        // The backend captures the frame just drawn. Keep its redaction bounds
        // with the event: the live status may have changed before it arrives.
        ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::new(
            Screenshot {
                name: format!("{:02}-{label}.ppm", self.shot_count),
                redaction: qr_rect.map(|rect| rect.expand(2.0)),
                pixels_per_point: ctx.pixels_per_point(),
            },
        )));
    }

    fn save_screenshots(&self, ctx: &egui::Context) {
        let Some(screenshots) = &self.screenshots else {
            return;
        };
        ctx.input(|i| {
            for event in &i.events {
                let egui::Event::Screenshot {
                    user_data, image, ..
                } = event
                else {
                    continue;
                };
                let Some(shot) = user_data
                    .data
                    .as_ref()
                    .and_then(|d| d.downcast_ref::<Screenshot>())
                else {
                    continue;
                };
                if let Err(error) = screenshots.write_new(&shot.name, &shot.encode(image)) {
                    warn!(%error, name = shot.name, "could not write screenshot");
                }
            }
        });
    }

    fn close(&mut self, ctx: &egui::Context) {
        self.closing = true;
        ctx.send_viewport_cmd(ViewportCommand::Close);
    }

    fn act(&mut self, ctx: &egui::Context, input: Input) {
        if self.closing {
            return;
        }
        let current = *self.request_rx.borrow();
        if self.actions.superseded(current) {
            self.close(ctx);
            return;
        }
        let status = self.status_rx.borrow().clone();
        // A terminal window (including an Idle linger) never cancels anything.
        if self.terminal_since.is_none() {
            if let Some(action) = self.actions.action(input, current, &status) {
                let _ = self.action_tx.send(action);
            }
        }
        if matches!(input, Input::Close) {
            self.close(ctx);
        }
    }

    fn qr_texture(&mut self, ctx: &egui::Context, payload: &str) -> Option<TextureHandle> {
        if let Some((cached, tex)) = &self.qr {
            if cached == payload {
                return Some(tex.clone());
            }
        }
        let image = match qr_image(payload) {
            Some(img) => img,
            None => {
                warn!("could not render QR code");
                return None;
            }
        };
        let tex = ctx.load_texture("qr", image, TextureOptions::NEAREST);
        self.qr = Some((payload.to_string(), tex.clone()));
        Some(tex)
    }
}

impl App {
    fn update_window(&mut self, ctx: &egui::Context) {
        // Poll the daemon's status; cheap, and avoids cross-thread wakeups.
        ctx.request_repaint_after(Duration::from_millis(100));

        if self.closing || self.actions.superseded(*self.request_rx.borrow()) {
            self.close(ctx);
            return;
        }
        self.save_screenshots(ctx);

        let status = self.status_rx.borrow().clone();
        match &status {
            Status::Done | Status::Failed(_) => {
                if self.terminal_since.as_ref().map(|(s, _)| s) != Some(&status) {
                    self.terminal_since = Some((status.clone(), Instant::now()));
                }
            }
            Status::Idle => {}
            _ => self.terminal_since = None,
        }

        if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
            self.act(ctx, Input::Close);
            return;
        }

        // Clearing the ID does not close this window: completion publishes
        // Done/Failed before clearing it, and those statuses get their linger.

        // Decide whether it is time to go.
        let should_close = match (&status, &self.terminal_since) {
            (Status::Idle, None) => true,
            (Status::Idle, Some((Status::Done, at))) => at.elapsed() >= DONE_LINGER,
            (Status::Idle, Some((Status::Failed(_), at))) => at.elapsed() >= FAILED_LINGER,
            (Status::Done, Some((_, at))) => at.elapsed() >= DONE_LINGER,
            (Status::Failed(_), Some((_, at))) => at.elapsed() >= FAILED_LINGER,
            _ => false,
        };
        if should_close {
            self.close(ctx);
            return;
        }

        // What to show: the live status, or the terminal one we are lingering on.
        let shown = match (&status, &self.terminal_since) {
            (Status::Idle, Some((terminal, _))) => terminal.clone(),
            _ => status,
        };

        let mut qr_rect = None;
        let palette = Palette::from(ctx.style().visuals.dark_mode);
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ctx, |ui| {
                let card = ui.max_rect();
                ui.painter().rect(
                    card,
                    CORNER_RADIUS,
                    palette.background,
                    egui::Stroke::new(1.0_f32, palette.border),
                    egui::StrokeKind::Inside,
                );
                if draw_header(ui, &palette, card) {
                    self.act(ctx, Input::Close);
                }
                let content = egui::Rect::from_min_max(
                    card.min + egui::vec2(28.0, HEADER_HEIGHT + 4.0),
                    card.max - egui::vec2(28.0, 24.0),
                );
                let mut ui = ui.new_child(egui::UiBuilder::new().max_rect(content));
                let ui = &mut ui;
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
                ui.vertical_centered(|ui| {
                    let (headline, body, show_cancel) = match &shown {
                        Status::ShowQr { payload, hint } => {
                            ui.label(
                                RichText::new(qr_heading(*hint))
                                    .size(20.0)
                                    .strong()
                                    .color(palette.text),
                            );
                            ui.add_space(14.0);
                            let payload = payload.clone();
                            if let Some(tex) = self.qr_texture(ctx, &payload) {
                                egui::Frame::new()
                                    .fill(Color32::WHITE)
                                    .corner_radius(14.0)
                                    .inner_margin(10.0)
                                    .shadow(egui::epaint::Shadow {
                                        offset: [0, 4],
                                        blur: 16,
                                        spread: 0,
                                        color: Color32::from_black_alpha(40),
                                    })
                                    .show(ui, |ui| {
                                        qr_rect = Some(
                                            ui.image((tex.id(), egui::vec2(QR_PIXELS, QR_PIXELS)))
                                                .rect,
                                        );
                                    });
                            }
                            ui.add_space(14.0);
                            (None, qr_body(*hint).to_string(), true)
                        }
                        Status::LinkedWaitingForPhone { name, hint } => {
                            draw_phone(ui, &palette, true);
                            (
                                Some("Check your phone".to_string()),
                                linked_body(name, *hint),
                                true,
                            )
                        }
                        Status::Selecting => {
                            draw_phone(ui, &palette, false);
                            (
                                Some("Choose this security key?".to_string()),
                                "Use your phone as the security key for this request.".to_string(),
                                true,
                            )
                        }
                        Status::PhoneFound => {
                            draw_phone(ui, &palette, true);
                            (
                                Some("Phone found".to_string()),
                                "Setting up a secure connection…".to_string(),
                                true,
                            )
                        }
                        Status::Connected => {
                            draw_phone(ui, &palette, true);
                            (
                                Some("Connected".to_string()),
                                "Sending the request to your phone…".to_string(),
                                true,
                            )
                        }
                        Status::WaitingForUser => {
                            draw_phone(ui, &palette, true);
                            (
                                Some("Confirm on your phone".to_string()),
                                "Use your fingerprint, face or PIN on the phone to continue."
                                    .to_string(),
                                true,
                            )
                        }
                        Status::Done => {
                            draw_badge(ui, palette.success, Glyph::Check);
                            (
                                Some("Done".to_string()),
                                "You can return to your browser.".to_string(),
                                false,
                            )
                        }
                        Status::Failed(msg) => {
                            draw_badge(ui, palette.danger, Glyph::Cross);
                            (Some("Something went wrong".to_string()), msg.clone(), false)
                        }
                        Status::Idle | Status::Starting => {
                            draw_phone(ui, &palette, true);
                            (Some("Starting…".to_string()), String::new(), true)
                        }
                    };

                    if let Some(h) = headline {
                        ui.add_space(6.0);
                        ui.label(RichText::new(h).size(20.0).strong().color(palette.text));
                    }
                    ui.add_space(4.0);
                    ui.label(RichText::new(body).size(14.0).color(palette.muted));

                    ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                        ui.add_space(4.0);
                        if show_cancel {
                            let button = egui::Button::new(
                                RichText::new("Cancel").size(15.0).color(palette.text),
                            )
                            .fill(palette.button)
                            .stroke(egui::Stroke::new(1.0_f32, palette.button_border))
                            .corner_radius(10.0)
                            .min_size(egui::vec2(ui.available_width(), 40.0));
                            if ui.add(button).clicked() {
                                self.act(ctx, Input::Close);
                            }
                        }
                        if matches!(shown, Status::Selecting) {
                            let button = egui::Button::new(
                                RichText::new("Use this phone-backed key")
                                    .size(15.0)
                                    .color(Color32::WHITE),
                            )
                            .fill(palette.accent)
                            .corner_radius(10.0)
                            .min_size(egui::vec2(ui.available_width(), 40.0));
                            if ui.add_enabled(!self.actions.selected, button).clicked() {
                                self.act(ctx, Input::Select);
                            }
                        }
                    });
                });
            });
        if !self.closing {
            self.maybe_capture(ctx, &shown, qr_rect);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_window(ctx);
    }
}

#[derive(Clone, Copy)]
enum Input {
    Close,
    Select,
}

/// Pure action mapping, separate from drawing so repainting cannot select a key.
struct RequestActions {
    request: RequestId,
    cancelled: bool,
    selected: bool,
}

impl RequestActions {
    fn new(request: RequestId) -> Self {
        Self {
            request,
            cancelled: false,
            selected: false,
        }
    }

    fn superseded(&self, current: Option<RequestId>) -> bool {
        current.is_some_and(|request| request != self.request)
    }

    fn action(
        &mut self,
        input: Input,
        current: Option<RequestId>,
        status: &Status,
    ) -> Option<Action> {
        if current != Some(self.request)
            || self.cancelled
            || matches!(status, Status::Idle | Status::Done | Status::Failed(_))
        {
            return None;
        }
        match input {
            Input::Close => {
                self.cancelled = true;
                Some(Action::Cancel {
                    request: self.request,
                })
            }
            Input::Select if matches!(status, Status::Selecting) && !self.selected => {
                self.selected = true;
                Some(Action::Select {
                    request: self.request,
                })
            }
            Input::Select => None,
        }
    }
}

fn qr_heading(hint: Hint) -> &'static str {
    match hint {
        Hint::MakeCredential => "Create a passkey on your phone",
        Hint::GetAssertion => "Sign in with your phone",
    }
}

fn qr_body(hint: Hint) -> &'static str {
    match hint {
        Hint::MakeCredential => "Open your phone's camera and scan the code,\nthen approve creating a passkey on the phone.",
        Hint::GetAssertion => "Open your phone's camera and scan the code,\nthen approve the sign-in on the phone.",
    }
}

fn linked_body(name: &str, hint: Hint) -> String {
    let approval = match hint {
        Hint::MakeCredential => "Approve creating a passkey there.",
        Hint::GetAssertion => "Approve the sign-in there.",
    };
    format!("We sent a notification to {name}.\n{approval}")
}

struct Screenshot {
    name: String,
    redaction: Option<egui::Rect>,
    pixels_per_point: f32,
}

impl Screenshot {
    fn encode(&self, image: &ColorImage) -> Vec<u8> {
        let [w, h] = image.size;
        let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
        for (i, pixel) in image.pixels.iter().enumerate() {
            let point = egui::pos2(
                (i % w) as f32 / self.pixels_per_point,
                (i / w) as f32 / self.pixels_per_point,
            );
            let pixel = if self.redaction.is_some_and(|rect| rect.contains(point)) {
                Color32::from_gray(128)
            } else {
                *pixel
            };
            out.extend_from_slice(&[pixel.r(), pixel.g(), pixel.b()]);
        }
        out
    }
}

/// Hold the private directory open so replacing its path cannot redirect writes.
struct Screenshots {
    dir: File,
}

impl Screenshots {
    fn new(path: &Path) -> io::Result<Self> {
        let mut dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            })?;
        // Walk each component using directory-relative, no-follow operations.
        // Missing directories are created private; existing permissions are
        // never changed, and a public destination is rejected rather than used.
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => CString::new(name.as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "NUL in screenshot directory")
                })?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "parent traversal in screenshot directory",
                    ))
                }
            };
            // SAFETY: dir is live and name is a NUL-terminated component.
            if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            // SAFETY: same live directory and valid component as above.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned a fresh owned descriptor.
            dir = unsafe { File::from_raw_fd(fd) };
        }
        let metadata = dir.metadata()?;
        // SAFETY: geteuid has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "screenshot directory must be owned by this user and private (0700)",
            ));
        }
        Ok(Self { dir })
    }

    fn write_new(&self, name: &str, contents: &[u8]) -> io::Result<()> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid screenshot filename",
            ));
        }
        let name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "NUL in screenshot filename")
        })?;
        // O_CREAT | O_EXCL is create_new, not truncate: neither existing files
        // nor symlinks can be opened. The initial mode is private even with a
        // permissive umask; O_NOFOLLOW additionally makes intent explicit.
        // SAFETY: dir is live, name is NUL-terminated, and mode is supplied.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(contents)
    }
}

struct Palette {
    background: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    success: Color32,
    danger: Color32,
    button: Color32,
    button_border: Color32,
    border: Color32,
    close_button: Color32,
    close_button_hover: Color32,
}

impl Palette {
    fn from(dark: bool) -> Self {
        if dark {
            Self {
                background: Color32::from_rgb(0x1e, 0x1f, 0x24),
                text: Color32::from_rgb(0xf2, 0xf2, 0xf5),
                muted: Color32::from_rgb(0xa0, 0xa4, 0xad),
                accent: Color32::from_rgb(0x5b, 0x9c, 0xff),
                success: Color32::from_rgb(0x3d, 0xc2, 0x6b),
                danger: Color32::from_rgb(0xe5, 0x53, 0x5a),
                button: Color32::from_rgb(0x2b, 0x2d, 0x34),
                button_border: Color32::from_rgb(0x3d, 0x40, 0x49),
                border: Color32::from_rgb(0x3a, 0x3c, 0x44),
                close_button: Color32::from_rgb(0x34, 0x36, 0x3e),
                close_button_hover: Color32::from_rgb(0x46, 0x49, 0x52),
            }
        } else {
            Self {
                background: Color32::from_rgb(0xfa, 0xfa, 0xfb),
                text: Color32::from_rgb(0x1c, 0x1e, 0x24),
                muted: Color32::from_rgb(0x66, 0x6b, 0x75),
                accent: Color32::from_rgb(0x1a, 0x73, 0xe8),
                success: Color32::from_rgb(0x1e, 0x8e, 0x3e),
                danger: Color32::from_rgb(0xd9, 0x30, 0x25),
                button: Color32::WHITE,
                button_border: Color32::from_rgb(0xd0, 0xd3, 0xd9),
                border: Color32::from_rgb(0xd6, 0xd8, 0xde),
                close_button: Color32::from_rgb(0xe6, 0xe7, 0xeb),
                close_button_hover: Color32::from_rgb(0xd4, 0xd6, 0xdc),
            }
        }
    }
}

enum Glyph {
    Check,
    Cross,
}

/// Header bar replacing the window decorations: wordmark on the left, a
/// GNOME-style round close button on the right, draggable to move the
/// window. Returns true when the close button was clicked.
fn draw_header(ui: &mut egui::Ui, palette: &Palette, card: egui::Rect) -> bool {
    let header = egui::Rect::from_min_size(card.min, egui::vec2(card.width(), HEADER_HEIGHT));
    let drag = ui.interact(header, ui.id().with("header-drag"), egui::Sense::drag());
    if drag.drag_started() {
        ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
    }

    let painter = ui.painter();
    painter.text(
        egui::pos2(header.min.x + 20.0, header.center().y),
        egui::Align2::LEFT_CENTER,
        "POCKETKEY",
        egui::FontId::proportional(11.0),
        palette.muted,
    );

    let button_rect = egui::Rect::from_center_size(
        egui::pos2(header.max.x - 12.0 - 12.0, header.center().y),
        egui::vec2(24.0, 24.0),
    );
    let button = ui.interact(button_rect, ui.id().with("close"), egui::Sense::click());
    let fill = if button.hovered() {
        palette.close_button_hover
    } else {
        palette.close_button
    };
    painter.circle_filled(button_rect.center(), 12.0, fill);
    let c = button_rect.center();
    let stroke = egui::Stroke::new(1.6_f32, palette.text);
    painter.line_segment(
        [c + egui::vec2(-4.0, -4.0), c + egui::vec2(4.0, 4.0)],
        stroke,
    );
    painter.line_segment(
        [c + egui::vec2(-4.0, 4.0), c + egui::vec2(4.0, -4.0)],
        stroke,
    );
    button.on_hover_text("Close").clicked()
}

/// A phone outline drawn with the painter, optionally with a spinner on screen.
fn draw_phone(ui: &mut egui::Ui, palette: &Palette, busy: bool) {
    ui.add_space(26.0);
    let size = egui::vec2(96.0, 170.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter();
    let stroke = egui::Stroke::new(3.0_f32, palette.accent);
    painter.rect_stroke(rect, 16.0, stroke, egui::StrokeKind::Inside);
    // Screen.
    let screen = rect.shrink2(egui::vec2(10.0, 18.0));
    painter.rect_stroke(
        screen,
        6.0,
        egui::Stroke::new(1.5_f32, palette.muted),
        egui::StrokeKind::Inside,
    );
    // Speaker and home indicator.
    painter.line_segment(
        [
            rect.center_top() + egui::vec2(-12.0, 9.0),
            rect.center_top() + egui::vec2(12.0, 9.0),
        ],
        egui::Stroke::new(2.0_f32, palette.muted),
    );
    painter.line_segment(
        [
            rect.center_bottom() + egui::vec2(-16.0, -9.0),
            rect.center_bottom() + egui::vec2(16.0, -9.0),
        ],
        egui::Stroke::new(2.5_f32, palette.muted),
    );
    if busy {
        let spinner_rect = egui::Rect::from_center_size(screen.center(), egui::vec2(28.0, 28.0));
        egui::Spinner::new()
            .size(28.0)
            .color(palette.accent)
            .paint_at(ui, spinner_rect);
    }
    ui.add_space(26.0);
}

/// A filled circle with a check mark or a cross.
fn draw_badge(ui: &mut egui::Ui, color: Color32, glyph: Glyph) {
    ui.add_space(56.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(110.0, 110.0), egui::Sense::hover());
    let painter = ui.painter();
    let c = rect.center();
    painter.circle_filled(c, 52.0, color);
    let stroke = egui::Stroke::new(7.0_f32, Color32::WHITE);
    match glyph {
        Glyph::Check => {
            painter.line_segment(
                [c + egui::vec2(-22.0, 2.0), c + egui::vec2(-7.0, 17.0)],
                stroke,
            );
            painter.line_segment(
                [c + egui::vec2(-7.0, 17.0), c + egui::vec2(24.0, -16.0)],
                stroke,
            );
        }
        Glyph::Cross => {
            painter.line_segment(
                [c + egui::vec2(-18.0, -18.0), c + egui::vec2(18.0, 18.0)],
                stroke,
            );
            painter.line_segment(
                [c + egui::vec2(-18.0, 18.0), c + egui::vec2(18.0, -18.0)],
                stroke,
            );
        }
    }
    ui.add_space(56.0);
}

/// Render the QR code with a 4-module quiet zone, one pixel per module.
fn qr_image(payload: &str) -> Option<ColorImage> {
    let code = qrcode::QrCode::new(payload.as_bytes()).ok()?;
    let width = code.width();
    let quiet = 4;
    let size = width + 2 * quiet;
    let colors = code.to_colors();
    let mut pixels = vec![Color32::WHITE; size * size];
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                pixels[(y + quiet) * size + (x + quiet)] = Color32::BLACK;
            }
        }
    }
    Some(ColorImage::new([size, size], pixels))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_ids() -> [RequestId; 2] {
        use crate::ctaphid::{cmd, fragment, Transport, BROADCAST_CID};
        let mut transport = Transport::new();
        let init = transport.handle_report(
            &fragment(BROADCAST_CID, cmd::INIT, &[0; 8])[0],
            Instant::now(),
        );
        let cid = u32::from_be_bytes(init.reports[0][15..19].try_into().unwrap());
        let mut next = || {
            transport.handle_report(&fragment(cid, cmd::CBOR, &[0x04])[0], Instant::now());
            let request = transport.in_flight().unwrap();
            transport.respond(request, &[0]);
            request
        };
        [next(), next()]
    }

    #[test]
    fn show_rejects_request_replaced_after_caller_captured_its_id() {
        let [original, next] = request_ids();
        let (_status_tx, status_rx) = watch::channel(Status::Selecting);
        let (requests, request_rx) = watch::channel(Some(original));
        let (action_tx, mut actions) = mpsc::unbounded_channel();
        let shown_request = request_rx.borrow().expect("original request");

        // Main records A, but B arrives before show starts. This must return
        // before initializing eframe, not open B under main's record of A.
        requests.send(Some(next)).unwrap();
        show(
            status_rx.clone(),
            action_tx.clone(),
            request_rx.clone(),
            shown_request,
        )
        .unwrap();
        assert_eq!(*request_rx.borrow(), Some(next));
        assert!(actions.try_recv().is_err());

        // Completion in that same interval must also avoid opening a window.
        requests.send(None).unwrap();
        show(status_rx, action_tx, request_rx, shown_request).unwrap();
        assert!(actions.try_recv().is_err());
    }

    fn test_app(
        request: RequestId,
        status: Status,
    ) -> (
        App,
        watch::Sender<Status>,
        watch::Sender<Option<RequestId>>,
        mpsc::UnboundedReceiver<Action>,
    ) {
        let (status_tx, status_rx) = watch::channel(status);
        let (request_tx, request_rx) = watch::channel(Some(request));
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        (
            App {
                status_rx,
                action_tx,
                request_rx,
                actions: RequestActions::new(request),
                qr: None,
                terminal_since: None,
                closing: false,
                screenshots: None,
                last_shot_status: None,
                shot_count: 0,
            },
            status_tx,
            request_tx,
            action_rx,
        )
    }

    #[test]
    fn rendering_does_not_select_and_replaced_request_closes_without_actions() {
        let [request, next] = request_ids();
        let (mut app, status, requests, mut actions) = test_app(request, Status::Starting);
        let ctx = egui::Context::default();
        let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
        assert!(
            !app.closing,
            "Starting must survive until the transport publishes progress"
        );
        status.send(Status::Selecting).unwrap();
        for _ in 0..3 {
            let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
            assert!(
                actions.try_recv().is_err(),
                "rendering must never imply consent"
            );
        }
        requests.send(Some(next)).unwrap();
        let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
        assert!(app.closing);
        app.act(&ctx, Input::Close);
        app.act(&ctx, Input::Select);
        assert!(actions.try_recv().is_err());
    }

    #[test]
    fn completed_request_lingers_without_id_and_closes_without_cancel() {
        let [request, _] = request_ids();
        for terminal in [Status::Done, Status::Failed("failed".into())] {
            let (mut app, _status, requests, mut actions) = test_app(request, terminal);
            requests.send(None).unwrap();
            let ctx = egui::Context::default();
            let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
            assert!(!app.closing);
            assert!(app.terminal_since.is_some());
            app.act(&ctx, Input::Close);
            assert!(app.closing);
            assert!(actions.try_recv().is_err());
        }
    }

    #[test]
    fn clearing_request_between_status_reads_still_allows_terminal_linger() {
        let [request, _] = request_ids();
        let (mut app, statuses, requests, mut actions) = test_app(request, Status::Connected);
        let ctx = egui::Context::default();
        // Model a frame that has read the old status while the completion
        // updates are arriving on two independent watch channels.
        requests.send(None).unwrap();
        let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
        assert!(!app.closing);
        statuses.send(Status::Done).unwrap();
        let _ = ctx.run(Default::default(), |ctx| app.update_window(ctx));
        assert!(app.terminal_since.is_some());
        assert!(!app.closing);
        assert!(actions.try_recv().is_err());
    }

    #[test]
    fn actions_are_explicit_once_only_and_bound_to_original_request() {
        let [original, next] = request_ids();
        let mut actions = RequestActions::new(original);
        assert!(!actions.selected);
        assert_eq!(
            actions.action(Input::Select, Some(original), &Status::Starting),
            None
        );
        assert_eq!(
            actions.action(Input::Select, Some(original), &Status::Selecting),
            Some(Action::Select { request: original })
        );
        assert_eq!(
            actions.action(Input::Select, Some(original), &Status::Selecting),
            None
        );
        assert_eq!(
            actions.action(Input::Close, Some(original), &Status::Connected),
            Some(Action::Cancel { request: original })
        );
        assert_eq!(
            actions.action(Input::Close, Some(original), &Status::Connected),
            None
        );

        let mut stale = RequestActions::new(original);
        assert!(stale.superseded(Some(next)));
        assert_eq!(
            stale.action(Input::Close, Some(next), &Status::Selecting),
            None
        );
        assert_eq!(
            stale.action(Input::Select, Some(next), &Status::Selecting),
            None
        );
        assert!(
            !stale.superseded(None),
            "completion must allow terminal linger"
        );
        assert_eq!(stale.action(Input::Close, None, &Status::Connected), None);
        assert_eq!(stale.action(Input::Select, None, &Status::Selecting), None);
    }

    #[test]
    fn terminal_and_idle_close_never_cancel() {
        let [request, _] = request_ids();
        for status in [Status::Done, Status::Failed("failed".into()), Status::Idle] {
            let mut actions = RequestActions::new(request);
            assert_eq!(actions.action(Input::Close, Some(request), &status), None);
            assert_eq!(actions.action(Input::Select, Some(request), &status), None);
        }
    }

    #[test]
    fn registration_and_sign_in_have_distinct_wording() {
        let registration = Hint::MakeCredential;
        let sign_in = Hint::GetAssertion;
        assert_eq!(qr_heading(registration), "Create a passkey on your phone");
        assert_eq!(qr_heading(sign_in), "Sign in with your phone");
        for text in [
            qr_body(registration).to_string(),
            linked_body("Pixel", registration),
        ] {
            assert!(text.contains("creating a passkey"));
            assert!(!text.contains("sign-in"));
        }
        for text in [qr_body(sign_in).to_string(), linked_body("Pixel", sign_in)] {
            assert!(text.contains("sign-in"));
            assert!(!text.contains("creating a passkey"));
        }
        assert!(linked_body("Pixel", registration).contains("Pixel"));
    }

    #[test]
    fn screenshot_encoding_redacts_qr_pixels_at_hidpi() {
        let image = ColorImage::new([4, 4], vec![Color32::BLACK; 16]);
        let shot = Screenshot {
            name: "qr.ppm".into(),
            redaction: Some(egui::Rect::from_min_max(
                egui::pos2(0.5, 0.5),
                egui::pos2(1.0, 1.0),
            )),
            pixels_per_point: 2.0,
        };
        let bytes = shot.encode(&image);
        let pixels = &bytes[b"P6\n4 4\n255\n".len()..];
        assert_eq!(&pixels[0..3], &[0, 0, 0]);
        assert_eq!(&pixels[15..18], &[128, 128, 128]);
        assert_eq!(&pixels[30..33], &[128, 128, 128]);
    }

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let parent = if Path::new("/tmp/opencode").is_dir() {
                std::path::PathBuf::from("/tmp/opencode")
            } else {
                std::env::temp_dir()
            };
            loop {
                let path = parent.join(format!(
                    "pocketkey-ui-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn screenshots_are_private_create_new_and_no_follow() {
        use std::os::unix::fs::symlink;
        let root = TestDir::new();
        let path = root.0.join("nested/shots");
        let screenshots = Screenshots::new(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        screenshots.write_new("01-Done.ppm", b"original").unwrap();
        assert_eq!(
            std::fs::metadata(path.join("01-Done.ppm")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            screenshots
                .write_new("01-Done.ppm", b"replacement")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            std::fs::read(path.join("01-Done.ppm")).unwrap(),
            b"original"
        );
        symlink("01-Done.ppm", path.join("link.ppm")).unwrap();
        assert!(screenshots.write_new("link.ppm", b"replacement").is_err());
        assert_eq!(
            std::fs::read(path.join("01-Done.ppm")).unwrap(),
            b"original"
        );
        symlink("missing.ppm", path.join("dangling.ppm")).unwrap();
        assert!(screenshots.write_new("dangling.ppm", b"new").is_err());
        assert!(!path.join("missing.ppm").exists());
        assert!(screenshots.write_new("../escape.ppm", b"new").is_err());
        symlink(&path, root.0.join("alias")).unwrap();
        assert!(Screenshots::new(&root.0.join("alias")).is_err());
        assert!(Screenshots::new(&root.0.join("alias/child")).is_err());
    }

    #[test]
    fn screenshots_reject_public_directory_without_changing_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = TestDir::new();
        let path = root.0.join("public");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Screenshots::new(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn replacing_directory_path_cannot_redirect_screenshot_writes() {
        use std::os::unix::fs::symlink;
        let root = TestDir::new();
        let path = root.0.join("shots");
        let screenshots = Screenshots::new(&path).unwrap();
        std::fs::rename(&path, root.0.join("original")).unwrap();
        std::fs::create_dir(root.0.join("replacement")).unwrap();
        symlink(root.0.join("replacement"), &path).unwrap();
        screenshots.write_new("test.ppm", b"private").unwrap();
        assert_eq!(
            std::fs::read(root.0.join("original/test.ppm")).unwrap(),
            b"private"
        );
        assert!(!root.0.join("replacement/test.ppm").exists());
    }

    #[test]
    fn qr_image_has_quiet_zone_and_dark_modules() {
        let img = qr_image("FIDO:/0123456789").unwrap();
        let [w, h] = img.size;
        assert_eq!(w, h);
        // Quiet zone is white all around.
        assert!(img.pixels[..w * 4].iter().all(|p| *p == Color32::WHITE));
        // Finder pattern corner (module 0,0) is dark.
        assert_eq!(img.pixels[4 * w + 4], Color32::BLACK);
    }
}
