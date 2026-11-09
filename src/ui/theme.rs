//! Desktop light/dark preference.
//!
//! On Wayland winit does not report the system theme (there is no protocol
//! for it), so egui would fall back to dark regardless of the desktop
//! setting. Every toolkit on a modern Linux desktop reads the XDG settings
//! portal instead: `org.freedesktop.portal.Settings`, namespace
//! `org.freedesktop.appearance`, key `color-scheme` (0 no preference,
//! 1 prefer dark, 2 prefer light). We read it once on the session bus and
//! subscribe to `SettingChanged` so a toggle while the window is open is
//! picked up on the next frame.

use std::sync::mpsc;
use std::time::Duration;

use dbus::arg::{RefArg, Variant};
use dbus::blocking::Connection;
use dbus::message::MatchRule;
use eframe::egui;
use tracing::debug;

const DEST: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const IFACE: &str = "org.freedesktop.portal.Settings";
const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";

/// Map the portal's `color-scheme` value onto egui's theme.
pub fn scheme_to_theme(value: u32) -> Option<egui::Theme> {
    match value {
        1 => Some(egui::Theme::Dark),
        2 => Some(egui::Theme::Light),
        _ => None,
    }
}

fn unwrap_variant(v: &dyn RefArg) -> Option<u32> {
    // `Read` returns `v(v(u))`: a variant wrapping the setting's own variant.
    let mut inner: &dyn RefArg = v;
    for _ in 0..3 {
        if let Some(n) = inner.as_u64() {
            return u32::try_from(n).ok();
        }
        inner = inner.as_iter()?.next()?;
    }
    None
}

/// Read the current preference. `None` when the portal is unavailable or
/// reports no preference.
fn read(conn: &Connection) -> Option<egui::Theme> {
    let proxy = conn.with_proxy(DEST, PATH, Duration::from_millis(500));
    let (value,): (Variant<Box<dyn RefArg>>,) = proxy
        .method_call(IFACE, "Read", (NAMESPACE, KEY))
        .ok()?;
    unwrap_variant(&value.0).and_then(scheme_to_theme)
}

/// Watch the desktop preference. Returns the current value and a receiver
/// that yields each change until the watcher thread exits.
pub fn watch() -> (Option<egui::Theme>, mpsc::Receiver<egui::Theme>) {
    let (tx, rx) = mpsc::channel();
    let Ok(conn) = Connection::new_session() else {
        debug!("no session bus; using egui's default theme");
        return (None, rx);
    };
    let current = read(&conn);
    debug!(?current, "desktop color-scheme from the settings portal");

    let rule = MatchRule::new_signal(IFACE, "SettingChanged")
        .with_sender(DEST)
        .with_path(PATH);
    if conn
        .add_match(rule, move |(ns, key, value): (String, String, Variant<Box<dyn RefArg>>), _, _| {
            if ns == NAMESPACE && key == KEY {
                if let Some(theme) = unwrap_variant(&value.0).and_then(scheme_to_theme) {
                    let _ = tx.send(theme);
                }
            }
            true
        })
        .is_ok()
    {
        std::thread::Builder::new()
            .name("theme-watch".into())
            .spawn(move || loop {
                if conn.process(Duration::from_secs(60)).is_err() {
                    break;
                }
            })
            .ok();
    }
    (current, rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_values_map_to_themes() {
        assert_eq!(scheme_to_theme(0), None);
        assert_eq!(scheme_to_theme(1), Some(egui::Theme::Dark));
        assert_eq!(scheme_to_theme(2), Some(egui::Theme::Light));
        assert_eq!(scheme_to_theme(7), None);
    }

    #[test]
    fn nested_variants_are_unwrapped() {
        let v = Variant(Box::new(Variant(Box::new(2u32))) as Box<dyn RefArg>);
        assert_eq!(unwrap_variant(&v), Some(2));
        let flat: Box<dyn RefArg> = Box::new(1u32);
        assert_eq!(unwrap_variant(&*flat), Some(1));
        let text: Box<dyn RefArg> = Box::new("dark".to_string());
        assert_eq!(unwrap_variant(&*text), None);
    }
}
