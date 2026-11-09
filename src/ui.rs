//! The request window: QR code (or "check your phone"), one status line and
//! a Cancel button. Shown only while a request is in flight.
//!
//! eframe owns the main thread while a window exists. [`show`] blocks until
//! the window closes, which the app does itself once the request reaches a
//! terminal state (after a short linger so the user sees the outcome) or when
//! the user clicks Cancel / closes the window (which cancels the request).
//! eframe reuses one winit event loop across calls, so `show` can be called
//! once per request on the main thread.

use std::time::{Duration, Instant};

use eframe::egui::{
    self, Color32, ColorImage, RichText, TextureHandle, TextureOptions, ViewportCommand,
};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::hybrid::Status;

const WINDOW_SIZE: [f32; 2] = [380.0, 560.0];
const QR_PIXELS: f32 = 272.0;
/// How long the window stays after a successful request.
const DONE_LINGER: Duration = Duration::from_millis(1200);
/// How long an error message stays before the window closes.
const FAILED_LINGER: Duration = Duration::from_secs(4);

/// Block the calling (main) thread showing the window for the current request.
pub fn show(
    status_rx: watch::Receiver<Status>,
    cancel_tx: mpsc::UnboundedSender<()>,
) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pocketkey")
            .with_app_id("pocketkey")
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(WINDOW_SIZE)
            .with_resizable(false),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "pocketkey",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(App {
                status_rx,
                cancel_tx,
                qr: None,
                terminal_since: None,
                cancelled: false,
                screenshot_dir: std::env::var_os("POCKETKEY_UI_SCREENSHOT_DIR").map(Into::into),
                last_shot_status: None,
                shot_count: 0,
            }))
        }),
    )
}

struct App {
    status_rx: watch::Receiver<Status>,
    cancel_tx: mpsc::UnboundedSender<()>,
    /// Cached QR texture for the payload currently displayed.
    qr: Option<(String, TextureHandle)>,
    /// When the request reached Done/Failed, for the linger timer.
    terminal_since: Option<(Status, Instant)>,
    cancelled: bool,
    /// Debug aid: when `POCKETKEY_UI_SCREENSHOT_DIR` is set, every status
    /// change is captured to `<dir>/<n>-<status>.ppm`.
    screenshot_dir: Option<std::path::PathBuf>,
    last_shot_status: Option<String>,
    shot_count: u32,
}

impl App {
    fn maybe_capture(&mut self, ctx: &egui::Context, shown: &Status) {
        let Some(dir) = &self.screenshot_dir else {
            return;
        };
        let label = format!("{shown:?}")
            .split([' ', '{'])
            .next()
            .unwrap_or("state")
            .to_string();
        if self.last_shot_status.as_deref() == Some(label.as_str()) {
            return;
        }
        self.last_shot_status = Some(label.clone());
        self.shot_count += 1;
        let path = dir.join(format!("{:02}-{label}.ppm", self.shot_count));
        // Give the new state one frame to render, then capture.
        ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::new(
            path.to_string_lossy().to_string(),
        )));
    }

    fn save_screenshots(&self, ctx: &egui::Context) {
        if self.screenshot_dir.is_none() {
            return;
        }
        let shots: Vec<(String, std::sync::Arc<ColorImage>)> = ctx.input(|i| {
            i.events
                .iter()
                .filter_map(|e| match e {
                    egui::Event::Screenshot {
                        user_data, image, ..
                    } => user_data
                        .data
                        .as_ref()
                        .and_then(|d| d.downcast_ref::<String>().cloned())
                        .map(|p| (p, image.clone())),
                    _ => None,
                })
                .collect()
        });
        for (path, image) in shots {
            let [w, h] = image.size;
            let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
            for px in image.pixels.iter() {
                out.extend_from_slice(&[px.r(), px.g(), px.b()]);
            }
            if let Err(e) = std::fs::write(&path, out) {
                warn!(error = %e, path, "could not write screenshot");
            }
        }
    }

    fn cancel(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            let _ = self.cancel_tx.send(());
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

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll the daemon's status; cheap, and avoids cross-thread wakeups.
        ctx.request_repaint_after(Duration::from_millis(100));

        if ctx.input(|i| i.viewport().close_requested()) {
            // Closing the window cancels the request; the window then goes away.
            self.cancel();
        }

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
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }

        // What to show: the live status, or the terminal one we are lingering on.
        let shown = match (&status, &self.terminal_since) {
            (Status::Idle, Some((terminal, _))) => terminal.clone(),
            _ => status,
        };

        self.save_screenshots(ctx);
        self.maybe_capture(ctx, &shown);

        let palette = Palette::from(ctx.style().visuals.dark_mode);
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(palette.background).inner_margin(egui::Margin::symmetric(28, 24)))
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("POCKETKEY")
                            .size(11.0)
                            .color(palette.muted)
                            .extra_letter_spacing(2.0),
                    );
                    ui.add_space(6.0);

                    let (headline, body, show_cancel) = match &shown {
                        Status::ShowQr { payload } => {
                            ui.label(RichText::new("Sign in with your phone").size(20.0).strong().color(palette.text));
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
                                        ui.image((tex.id(), egui::vec2(QR_PIXELS, QR_PIXELS)));
                                    });
                            }
                            ui.add_space(14.0);
                            (
                                None,
                                "Open your phone's camera and scan the code,\nthen approve the sign-in on the phone."
                                    .to_string(),
                                true,
                            )
                        }
                        Status::LinkedWaitingForPhone { name } => {
                            draw_phone(ui, &palette, true);
                            (
                                Some("Check your phone".to_string()),
                                format!("We sent a notification to {name}.\nApprove the sign-in there."),
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
                                "Use your fingerprint, face or PIN on the phone to continue.".to_string(),
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
                        Status::Idle => {
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
                            let button = egui::Button::new(RichText::new("Cancel").size(15.0).color(palette.text))
                                .fill(palette.button)
                                .stroke(egui::Stroke::new(1.0_f32, palette.button_border))
                                .corner_radius(10.0)
                                .min_size(egui::vec2(ui.available_width(), 40.0));
                            if ui.add(button).clicked() {
                                self.cancel();
                            }
                        }
                    });
                });
            });
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
            }
        }
    }
}

enum Glyph {
    Check,
    Cross,
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
