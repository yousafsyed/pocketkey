//! Detect the snap-packaged Firefox, which cannot see pocketkey's device.
//!
//! The snap's `u2f-devices` interface exposes only security keys from a
//! vendor-id allow-list, so a snap Firefox silently never finds the virtual
//! key. On Ubuntu that package is the default, so without a hint the first
//! experience is "nothing happens". This check is purely informational: it
//! only inspects the filesystem and never changes behaviour.

use std::path::Path;

/// Paths that exist when Firefox is installed as a snap.
const SNAP_MARKERS: [&str; 2] = ["/snap/bin/firefox", "/var/lib/snapd/snap/firefox"];

/// Paths that indicate a non-snap Firefox (deb, tarball, Flatpak).
const NATIVE_MARKERS: [&str; 3] = [
    "/usr/lib/firefox/firefox",
    "/opt/firefox/firefox",
    "/var/lib/flatpak/app/org.mozilla.firefox",
];

/// Whether the snap-packaged Firefox appears to be installed.
pub fn snap_firefox_present() -> bool {
    snap_firefox_present_at(Path::new("/"))
}

/// Whether a non-snap Firefox also appears to be installed. Used to soften
/// the warning when the user has both and may already use the right one.
pub fn native_firefox_present() -> bool {
    native_firefox_present_at(Path::new("/"))
}

fn snap_firefox_present_at(root: &Path) -> bool {
    SNAP_MARKERS
        .iter()
        .any(|marker| root.join(marker.trim_start_matches('/')).exists())
}

fn native_firefox_present_at(root: &Path) -> bool {
    NATIVE_MARKERS
        .iter()
        .any(|marker| root.join(marker.trim_start_matches('/')).exists())
}

/// A user-facing message explaining the snap limitation, or `None` when no
/// snap Firefox is installed.
pub fn advice() -> Option<String> {
    advice_for(snap_firefox_present(), native_firefox_present())
}

fn advice_for(snap: bool, native: bool) -> Option<String> {
    if !snap {
        return None;
    }
    let mut message = String::from(
        "the snap-packaged Firefox is installed; its u2f-devices interface only exposes \
         security keys from a fixed vendor allow-list, so that Firefox will never see \
         pocketkey's virtual key. Install Firefox from packages.mozilla.org (deb) instead: \
         https://support.mozilla.org/kb/install-firefox-linux",
    );
    if native {
        message.push_str(
            ". A non-snap Firefox is also installed; make sure passkey sign-ins use that one",
        );
    }
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root_with(paths: &[&str]) -> tempfile_dir::TempDir {
        let dir = tempfile_dir::TempDir::new();
        for path in paths {
            let full = dir.path().join(path.trim_start_matches('/'));
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, b"").unwrap();
        }
        dir
    }

    mod tempfile_dir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "pocketkey-snapcheck-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn detects_snap_and_native_markers() {
        let none = root_with(&[]);
        assert!(!snap_firefox_present_at(none.path()));
        assert!(!native_firefox_present_at(none.path()));

        let snap = root_with(&["/snap/bin/firefox"]);
        assert!(snap_firefox_present_at(snap.path()));
        assert!(!native_firefox_present_at(snap.path()));

        let both = root_with(&["/var/lib/snapd/snap/firefox", "/usr/lib/firefox/firefox"]);
        assert!(snap_firefox_present_at(both.path()));
        assert!(native_firefox_present_at(both.path()));
    }

    #[test]
    fn advice_only_when_snap_is_present() {
        assert_eq!(advice_for(false, false), None);
        assert_eq!(advice_for(false, true), None);
        let snap_only = advice_for(true, false).unwrap();
        assert!(snap_only.contains("snap-packaged Firefox"));
        assert!(snap_only.contains("packages.mozilla.org"));
        assert!(!snap_only.contains("also installed"));
        let both = advice_for(true, true).unwrap();
        assert!(both.contains("also installed"));
    }
}
