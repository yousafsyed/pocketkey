//! pocketkey: a virtual FIDO2 USB security key that proxies CTAP2 requests to
//! a phone over the WebAuthn hybrid transport.
//!
//! Data flow: `/dev/uhid` reports -> [`ctaphid::Transport`] -> CTAP2 payload
//! -> answered locally by [`ctap2`] or forwarded through [`hybrid`] -> back
//! out as CTAPHID reports. Exactly one forwarded request is in flight at a
//! time; while it runs, the daemon emits `CTAPHID_KEEPALIVE` every 100 ms.
//!
//! Threads: the tokio runtime (uhid loop, hybrid connection) runs on
//! background threads; the main thread is reserved for the request window,
//! which winit requires.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use pocketkey::ctaphid::{self, Event, KeepaliveStatus, RequestId};
use pocketkey::hybrid::pxp_transport::PxpTransport;
use pocketkey::hybrid::store::FileStore;
use pocketkey::hybrid::{HybridError, HybridTransport, Status};
use pocketkey::uhid::{self, UhidDevice, UhidEvent};
use pocketkey::{ctap2, ui};

const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

/// A forwarded request currently running on the hybrid transport.
struct Active {
    id: RequestId,
    task: JoinHandle<Result<Vec<u8>, HybridError>>,
    cancel: CancellationToken,
}

fn main() -> anyhow::Result<()> {
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("pocketkey {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("pocketkey-rt")
        .build()
        .context("starting tokio runtime")?;

    let store_path = FileStore::default_path().context("locating the linked device store")?;
    let store =
        Arc::new(FileStore::open(store_path.clone()).context("opening the linked device store")?);
    info!(path = %store_path.display(), linked_phones = store.list().len(), "linked device store");
    let transport: Arc<dyn HybridTransport> = Arc::new(PxpTransport::new(store));

    // Create the device before anything else so permission problems surface
    // immediately. Must run inside the runtime: AsyncFd registers with it.
    let device = runtime
        .block_on(async { UhidDevice::create() })
        .context("creating the virtual FIDO device")?;
    info!(name = uhid::DEVICE_NAME, "virtual FIDO2 key ready");

    let (status_tx, status_rx) = watch::channel(Status::Idle);
    let (ui_cancel_tx, ui_cancel_rx) = mpsc::unbounded_channel();
    let mut daemon = runtime.spawn(run(device, transport, status_tx, ui_cancel_rx));

    // Main thread: show the window whenever a request leaves Idle.
    let mut ui_available =
        std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    if !ui_available {
        warn!("no WAYLAND_DISPLAY/DISPLAY: running without a window; QR flows cannot be shown");
    }
    let mut ui_status = status_rx.clone();
    let result = loop {
        // Wait for a request to start, or for the daemon to end.
        let finished = runtime.block_on(async {
            loop {
                tokio::select! {
                    res = &mut daemon => return Some(res),
                    changed = ui_status.changed() => {
                        // The sender lives in the daemon task; a closed channel means it is exiting.
                        if changed.is_err() { return Some((&mut daemon).await); }
                        if !matches!(*ui_status.borrow_and_update(), Status::Idle) { return None; }
                    }
                }
            }
        });
        if let Some(res) = finished {
            break res;
        }
        if ui_available {
            if let Err(e) = ui::show(status_rx.clone(), ui_cancel_tx.clone()) {
                error!(error = %e, "could not open the request window; continuing without one");
                ui_available = false;
            }
        }
        // Do not reopen until this request is over.
        let finished = runtime.block_on(async {
            loop {
                tokio::select! {
                    res = &mut daemon => return Some(res),
                    changed = ui_status.changed() => {
                        if changed.is_err() { return Some((&mut daemon).await); }
                        if matches!(*ui_status.borrow_and_update(), Status::Idle) { return None; }
                    }
                }
            }
        });
        if let Some(res) = finished {
            break res;
        }
    };

    match result {
        Ok(r) => r,
        Err(e) => Err(anyhow::anyhow!("daemon task failed: {e}")),
    }
}

async fn run(
    mut device: UhidDevice,
    transport: Arc<dyn HybridTransport>,
    status_tx: watch::Sender<Status>,
    mut ui_cancel_rx: mpsc::UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    let result = event_loop(&mut device, transport, &status_tx, &mut ui_cancel_rx).await;
    // Always tear the device down so clients do not see a stale hidraw node.
    if let Err(e) = device.destroy() {
        warn!(error = %e, "destroying uhid device");
    }
    result
}

async fn event_loop(
    device: &mut UhidDevice,
    transport: Arc<dyn HybridTransport>,
    status_tx: &watch::Sender<Status>,
    ui_cancel_rx: &mut mpsc::UnboundedReceiver<()>,
) -> anyhow::Result<()> {
    let mut hid = ctaphid::Transport::new().with_version(crate_version_bytes());
    let mut ctap = ctap2::Ctap2::new();
    let mut ticker = tokio::time::interval(KEEPALIVE_INTERVAL);
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut active: Option<Active> = None;

    loop {
        tokio::select! {
            event = device.next_event() => {
                match event.context("reading from /dev/uhid")? {
                    UhidEvent::Output(report) => {
                        let out = hid.handle_report(&report, Instant::now());
                        send_all(device, &out.reports)?;
                        for ev in out.events {
                            handle_event(ev, &mut hid, &mut ctap, &mut active, &transport, status_tx, device)?;
                        }
                    }
                    UhidEvent::Open => debug!("hidraw node opened by a client"),
                    UhidEvent::Close => debug!("hidraw node closed"),
                    UhidEvent::Stop => {
                        warn!("kernel stopped the uhid device");
                        break;
                    }
                }
            }

            _ = ticker.tick() => {
                send_all(device, &hid.tick(Instant::now()))?;
                if let Some(a) = &active {
                    let status = if status_tx.borrow().user_action_pending() {
                        KeepaliveStatus::UpNeeded
                    } else {
                        KeepaliveStatus::Processing
                    };
                    if let Some(report) = hid.keepalive(a.id, status) {
                        device.send_report(&report)?;
                    }
                }
            }

            result = async { (&mut active.as_mut().expect("guarded by `if`").task).await },
                if active.is_some() =>
            {
                let a = active.take().expect("checked");
                let payload = match result {
                    Ok(Ok(bytes)) => {
                        info!(status = bytes.first().copied().unwrap_or(0), "phone replied");
                        bytes
                    }
                    Ok(Err(e)) => {
                        info!(error = %e, "hybrid request failed");
                        vec![ctap2::status_for_hybrid_error(&e)]
                    }
                    Err(join_err) => {
                        error!(error = %join_err, "hybrid task panicked");
                        vec![ctap2::status::CTAP1_ERR_OTHER]
                    }
                };
                send_all(device, &hid.respond(a.id, &payload))?;
                let _ = status_tx.send(Status::Idle);
            }

            Some(()) = ui_cancel_rx.recv() => {
                if let Some(a) = &active {
                    info!("request cancelled from the window");
                    a.cancel.cancel();
                }
            }

            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); break; }
            _ = sigint.recv() => { info!("SIGINT received, shutting down"); break; }
        }
    }

    if let Some(a) = active {
        a.cancel.cancel();
        a.task.abort();
    }
    let _ = status_tx.send(Status::Idle);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    ev: Event,
    hid: &mut ctaphid::Transport,
    ctap: &mut ctap2::Ctap2,
    active: &mut Option<Active>,
    transport: &Arc<dyn HybridTransport>,
    status_tx: &watch::Sender<Status>,
    device: &mut UhidDevice,
) -> anyhow::Result<()> {
    match ev {
        Event::CborRequest { id, payload } => {
            debug!(
                cmd = payload.first().copied().unwrap_or(0),
                len = payload.len(),
                "CTAP2 request"
            );
            match ctap.dispatch(&payload) {
                ctap2::Disposition::Respond(bytes) => send_all(device, &hid.respond(id, &bytes))?,
                ctap2::Disposition::Forward { hint, frame } => {
                    if active.is_some() {
                        // ctaphid serialises requests, so this cannot happen; be defensive.
                        error!("forwarded request while another is active");
                        send_all(device, &hid.respond(id, &[ctap2::status::CTAP1_ERR_OTHER]))?;
                        return Ok(());
                    }
                    info!(?hint, "forwarding request to the phone");
                    let cancel = CancellationToken::new();
                    let task = tokio::spawn({
                        let transport = Arc::clone(transport);
                        let cancel = cancel.clone();
                        let status_tx = status_tx.clone();
                        async move { transport.ctap(frame, hint, status_tx, cancel).await }
                    });
                    *active = Some(Active { id, task, cancel });
                }
            }
        }
        Event::Cancel { id } => match active {
            Some(a) if a.id == id => {
                info!("client cancelled the request");
                a.cancel.cancel();
            }
            _ => debug!("cancel for a request that is not active"),
        },
    }
    Ok(())
}

fn send_all(device: &mut UhidDevice, reports: &[ctaphid::Report]) -> anyhow::Result<()> {
    for r in reports {
        device
            .send_report(r)
            .context("writing report to /dev/uhid")?;
    }
    Ok(())
}

/// (major, minor, patch) of this crate, reported in the CTAPHID INIT response.
fn crate_version_bytes() -> [u8; 3] {
    let parse = |s: &str| s.parse::<u8>().unwrap_or(0);
    [
        parse(env!("CARGO_PKG_VERSION_MAJOR")),
        parse(env!("CARGO_PKG_VERSION_MINOR")),
        parse(env!("CARGO_PKG_VERSION_PATCH")),
    ]
}
