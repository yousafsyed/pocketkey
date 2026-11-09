//! Drives the request window through every state with a fake QR payload, so
//! the UI can be checked without a phone or /dev/uhid access.
//!
//! ```sh
//! cargo run --example ui_demo --features vendored-dbus
//! ```

use std::time::Duration;

use pocketkey::hybrid::Status;
use tokio::sync::{mpsc, watch};

fn main() {
    tracing_subscriber::fmt().init();
    let (status_tx, status_rx) = watch::channel(Status::ShowQr {
        payload: "FIDO:/0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789".into(),
    });
    let (cancel_tx, mut cancel_rx) = mpsc::unbounded_channel::<()>();

    std::thread::spawn(move || {
        let steps = [
            (Duration::from_secs(4), Status::PhoneFound),
            (Duration::from_secs(2), Status::Connected),
            (Duration::from_secs(1), Status::WaitingForUser),
            (Duration::from_secs(3), Status::Done),
            (Duration::from_millis(200), Status::Idle),
        ];
        for (delay, status) in steps {
            std::thread::sleep(delay);
            if cancel_rx.try_recv().is_ok() {
                println!("cancel received from the window");
                let _ = status_tx.send(Status::Failed("cancelled".into()));
                std::thread::sleep(Duration::from_millis(200));
                let _ = status_tx.send(Status::Idle);
                return;
            }
            println!("-> {status:?}");
            let _ = status_tx.send(status);
        }
    });

    pocketkey::ui::show(status_rx, cancel_tx).expect("window");
    println!("window closed");
}
