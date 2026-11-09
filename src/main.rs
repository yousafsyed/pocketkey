//! hybridkey: a virtual FIDO2 USB security key that proxies CTAP2 requests to
//! a phone over the WebAuthn hybrid transport.
//!
//! Data flow: `/dev/uhid` reports -> [`ctaphid::Transport`] -> CTAP2 payload
//! -> answered locally by [`ctap2`] or forwarded through [`hybrid`] -> back
//! out as CTAPHID reports. Exactly one forwarded request is in flight at a
//! time; while it runs, this loop emits `CTAPHID_KEEPALIVE` every 100 ms.

mod ctap2;
mod ctaphid;
mod hybrid;
mod uhid;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::ctaphid::{Event, KeepaliveStatus, RequestId};
use crate::hybrid::{HybridError, HybridTransport, Status};
use crate::uhid::{UhidDevice, UhidEvent};

const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

/// A forwarded request currently running on the hybrid transport.
struct Active {
    id: RequestId,
    task: JoinHandle<Result<Vec<u8>, HybridError>>,
    status_rx: watch::Receiver<Status>,
    cancel: CancellationToken,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let transport: Arc<dyn HybridTransport> = Arc::new(hybrid::UnavailableTransport);

    let mut device = UhidDevice::create().context("creating the virtual FIDO device")?;
    info!(name = uhid::DEVICE_NAME, "virtual FIDO2 key ready");

    let result = run(&mut device, transport).await;

    // Always tear the device down so clients do not see a stale hidraw node.
    if let Err(e) = device.destroy() {
        warn!(error = %e, "destroying uhid device");
    }
    result
}

async fn run(device: &mut UhidDevice, transport: Arc<dyn HybridTransport>) -> anyhow::Result<()> {
    let mut hid = ctaphid::Transport::new().with_version(crate_version_bytes());
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
                            handle_event(ev, &mut hid, &mut active, &transport, device)?;
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
                    let status = if a.status_rx.borrow().user_action_pending() {
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
                        debug!(status = bytes.first().copied().unwrap_or(0), len = bytes.len(), "phone replied");
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
            }

            _ = sigterm.recv() => { info!("SIGTERM received, shutting down"); break; }
            _ = sigint.recv() => { info!("SIGINT received, shutting down"); break; }
        }
    }

    if let Some(a) = active {
        a.cancel.cancel();
        a.task.abort();
    }
    Ok(())
}

fn handle_event(
    ev: Event,
    hid: &mut ctaphid::Transport,
    active: &mut Option<Active>,
    transport: &Arc<dyn HybridTransport>,
    device: &mut UhidDevice,
) -> anyhow::Result<()> {
    match ev {
        Event::CborRequest { id, payload } => {
            debug!(
                cmd = payload.first().copied().unwrap_or(0),
                len = payload.len(),
                "CTAP2 request"
            );
            match ctap2::dispatch(&payload) {
                ctap2::Disposition::Respond(bytes) => send_all(device, &hid.respond(id, &bytes))?,
                ctap2::Disposition::Forward { hint } => {
                    if active.is_some() {
                        // ctaphid serialises requests, so this cannot happen; be defensive.
                        error!("forwarded request while another is active");
                        send_all(device, &hid.respond(id, &[ctap2::status::CTAP1_ERR_OTHER]))?;
                        return Ok(());
                    }
                    info!(?hint, "forwarding request to the phone");
                    let (status_tx, status_rx) = watch::channel(Status::Idle);
                    let cancel = CancellationToken::new();
                    let task = tokio::spawn({
                        let transport = Arc::clone(transport);
                        let cancel = cancel.clone();
                        async move { transport.ctap(payload, hint, status_tx, cancel).await }
                    });
                    *active = Some(Active {
                        id,
                        task,
                        status_rx,
                        cancel,
                    });
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
