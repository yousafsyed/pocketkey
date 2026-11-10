//! Drives the request window with a fake QR payload, without a phone or UHID.
//!
//! ```sh
//! cargo run --example ui_demo --features vendored-dbus
//! cargo run --example ui_demo --features vendored-dbus -- --register --linked
//! cargo run --example ui_demo --features vendored-dbus -- --select --fail
//! ```
//!
//! `--select` waits for the explicit selection button; it never auto-selects.
//! For screenshots, set `POCKETKEY_UI_SCREENSHOT_DIR` to a new directory (or an
//! existing private 0700 directory). Captures use private 0600 files, never
//! overwrite, and redact the QR region, including this demo's fake QR code.

use std::time::{Duration, Instant};

use pocketkey::ctaphid::{self, RequestId};
use pocketkey::hybrid::{Hint, Status};
use pocketkey::ui::Action;
use tokio::sync::{mpsc, watch};

const PAYLOAD: &str = "FIDO:/0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

fn main() {
    tracing_subscriber::fmt().init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let selection = args.iter().any(|arg| arg == "--select");
    let linked = args.iter().any(|arg| arg == "--linked");
    let fail = args.iter().any(|arg| arg == "--fail");
    let hint = if args.iter().any(|arg| arg == "--register") {
        Hint::MakeCredential
    } else {
        Hint::GetAssertion
    };
    let request = demo_request();
    let (request_tx, request_rx) = watch::channel(Some(request));
    let (status_tx, status_rx) = watch::channel(if selection {
        Status::Selecting
    } else {
        Status::Starting
    });
    let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

    std::thread::spawn(move || {
        if selection {
            loop {
                match action_rx.blocking_recv() {
                    Some(Action::Select { request: id }) if id == request => {
                        println!("explicit selection received for {id:?}");
                        break;
                    }
                    Some(Action::Cancel { request: id }) if id == request => {
                        println!("cancel received for {id:?}");
                        return;
                    }
                    None => return,
                    _ => {}
                }
            }
        }
        let first = if linked {
            Status::LinkedWaitingForPhone {
                name: "Demo phone".into(),
                hint,
            }
        } else {
            Status::ShowQr {
                payload: PAYLOAD.into(),
                hint,
            }
        };
        let terminal = if fail {
            Status::Failed("Demo: the phone did not respond. Please try again.".into())
        } else {
            Status::Done
        };
        let steps = [
            (Duration::from_millis(700), first),
            (Duration::from_secs(4), Status::PhoneFound),
            (Duration::from_secs(2), Status::Connected),
            (Duration::from_secs(1), Status::WaitingForUser),
            (Duration::from_secs(3), terminal),
        ];
        for (delay, status) in steps {
            if !wait_for_step(delay, &mut action_rx, request) {
                let _ = status_tx.send(Status::Failed("cancelled".into()));
                let _ = request_tx.send(None);
                return;
            }
            // Do not log QR payloads, even though this demo uses a fake one.
            println!("advancing demo");
            if status_tx.send(status).is_err() {
                return;
            }
        }
        // Keep the terminal status while clearing the active request, just as
        // the daemon does. The window still lingers to show its outcome.
        let _ = request_tx.send(None);
    });

    pocketkey::ui::show(status_rx, action_tx, request_rx, request).expect("window");
    println!("window closed");
}

fn wait_for_step(
    delay: Duration,
    actions: &mut mpsc::UnboundedReceiver<Action>,
    request: RequestId,
) -> bool {
    let deadline = Instant::now() + delay;
    loop {
        match actions.try_recv() {
            Ok(Action::Cancel { request: id }) if id == request => {
                println!("cancel received for {id:?}");
                return false;
            }
            Err(mpsc::error::TryRecvError::Disconnected) => return false,
            _ => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

/// Allocate a real transport ID without making its private representation public.
fn demo_request() -> RequestId {
    let mut transport = ctaphid::Transport::new();
    let init = transport.handle_report(
        &ctaphid::fragment(ctaphid::BROADCAST_CID, ctaphid::cmd::INIT, &[0; 8])[0],
        Instant::now(),
    );
    let cid = u32::from_be_bytes(init.reports[0][15..19].try_into().expect("INIT channel"));
    transport.handle_report(
        &ctaphid::fragment(cid, ctaphid::cmd::CBOR, &[0x04])[0],
        Instant::now(),
    );
    transport.in_flight().expect("demo request allocated")
}
