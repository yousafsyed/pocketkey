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

const WINDOW_SIZE: [f32; 2] = [380.0, 500.0];
const QR_PIXELS: f32 = 300.0;
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
            .with_title("pocketkey: sign in with your phone")
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
}

impl App {
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

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(12.0);
                ui.heading("Sign in with your phone");
                ui.add_space(12.0);

                let (line, show_cancel) = match &shown {
                    Status::ShowQr { payload } => {
                        let payload = payload.clone();
                        if let Some(tex) = self.qr_texture(ctx, &payload) {
                            ui.image((tex.id(), egui::vec2(QR_PIXELS, QR_PIXELS)));
                        }
                        ui.add_space(10.0);
                        (
                            "Scan this QR code with your phone's camera".to_string(),
                            true,
                        )
                    }
                    Status::LinkedWaitingForPhone { name } => {
                        phone_glyph(ui);
                        (format!("Check your phone ({name})"), true)
                    }
                    Status::PhoneFound => {
                        phone_glyph(ui);
                        ("Phone found, connecting…".to_string(), true)
                    }
                    Status::Connected => {
                        phone_glyph(ui);
                        ("Connected, sending request…".to_string(), true)
                    }
                    Status::WaitingForUser => {
                        phone_glyph(ui);
                        ("Confirm on your phone".to_string(), true)
                    }
                    Status::Done => {
                        ui.add_space(60.0);
                        ui.label(
                            RichText::new("✓")
                                .size(72.0)
                                .color(Color32::from_rgb(0x2e, 0xa0, 0x43)),
                        );
                        ("Done".to_string(), false)
                    }
                    Status::Failed(msg) => {
                        ui.add_space(60.0);
                        ui.label(
                            RichText::new("✕")
                                .size(72.0)
                                .color(Color32::from_rgb(0xc0, 0x1c, 0x28)),
                        );
                        (format!("Failed: {msg}"), false)
                    }
                    Status::Idle => ("Starting…".to_string(), true),
                };

                ui.add_space(8.0);
                ui.label(RichText::new(line).size(15.0));
                ui.add_space(16.0);
                if show_cancel && ui.button(RichText::new("  Cancel  ").size(15.0)).clicked() {
                    self.cancel();
                }
            });
        });
    }
}

fn phone_glyph(ui: &mut egui::Ui) {
    ui.add_space(60.0);
    ui.label(RichText::new("📱").size(96.0));
    ui.add_space(30.0);
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
