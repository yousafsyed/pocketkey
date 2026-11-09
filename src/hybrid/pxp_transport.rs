//! [`HybridTransport`] implementation over the `pxp` crate.
//!
//! One request = one PXP connection. Linked phones are tried first (the
//! tunnel service pushes a notification to the phone, no QR); if none answers
//! within [`LINKED_TIMEOUT`] we fall back to a QR code. Either way: wait for
//! the phone's BLE advertisement and tunnel connection, run the Noise
//! handshake, send the CTAP frame, wait for the reply, send the tunnel
//! Shutdown so the phone shows "success", done. Cancellation drops the
//! [`pxp::TunnelHandle`], which aborts the connection task and stops the BLE
//! scan.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use btleplug::api::Manager as _;
use pxp::known_devices::{ClientPayloadHint, PxpKnownDevice, PxpKnownDeviceId};
use pxp::qr_code_device::{PxpQrCodeDevice, PxpTransports, QrCodeOperationHint};
use pxp::{PxpUpdate, TunnelHandle, UpdateSink};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::store::FileStore;
use super::{Hint, HybridError, HybridTransport, Status};

/// How long the QR code stays valid before the request fails. Browsers
/// usually cancel sooner (their own WebAuthn timeout); this is the backstop.
pub const QR_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a linked phone gets to answer the push before we fall back to a QR code.
pub const LINKED_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the phone's reply once the request has been sent.
/// Covers the user unlocking the phone and doing biometrics.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);

pub struct PxpTransport {
    store: Arc<FileStore>,
}

impl PxpTransport {
    pub fn new(store: Arc<FileStore>) -> Self {
        Self { store }
    }

    /// Fail early with a clear message when BLE scanning is impossible.
    async fn ensure_bluetooth() -> Result<(), HybridError> {
        let manager = btleplug::platform::Manager::new()
            .await
            .map_err(|e| HybridError::Transport(format!("bluetooth manager: {e}")))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|e| HybridError::Transport(format!("listing bluetooth adapters: {e}")))?;
        if adapters.is_empty() {
            return Err(HybridError::NoBluetooth);
        }
        Ok(())
    }

    /// Try each linked phone, most recently used first. Returns the connected
    /// tunnel and the id of the phone that answered, or `None` if none did.
    async fn connect_linked(
        &self,
        hint: Hint,
        status: &watch::Sender<Status>,
        cancel: &CancellationToken,
    ) -> Result<Option<(TunnelHandle, PxpKnownDeviceId)>, HybridError> {
        for (id, stored) in self.store.list() {
            let Some(info) = stored.to_info() else {
                warn!(name = %stored.name, "linked phone record is malformed; skipping");
                continue;
            };
            info!(name = %info.name, "contacting linked phone");
            let _ = status.send(Status::LinkedWaitingForPhone {
                name: info.name.clone(),
            });
            let device = PxpKnownDevice::new(hint.into(), &info, self.store.clone())
                .await
                .map_err(|e| HybridError::Transport(format!("preparing linked connection: {e}")))?;
            let tunnel = pxp::connect(device, StatusSink(status.clone()));
            match wait_connected(tunnel, LINKED_TIMEOUT, cancel).await {
                Ok(tunnel) => return Ok(Some((tunnel, id))),
                Err(HybridError::Cancelled) => return Err(HybridError::Cancelled),
                Err(e) => {
                    info!(name = %info.name, error = %e, "linked phone did not answer; trying next option")
                }
            }
        }
        Ok(None)
    }

    /// QR-initiated connection. Returns a connected tunnel.
    async fn connect_qr(
        &self,
        hint: Hint,
        status: &watch::Sender<Status>,
        cancel: &CancellationToken,
    ) -> Result<TunnelHandle, HybridError> {
        let device = PxpQrCodeDevice::new_persistent(
            hint.into(),
            self.store.clone(),
            // caBLE v2 QR without the CTAP 2.3 transports key: Google Play
            // services before CTAP 2.3 rejects QR key 6.
            PxpTransports::CloudAssistedOnly,
        )
        .map_err(|e| HybridError::Transport(format!("creating QR code: {e}")))?;

        let payload = device.qr_code.to_string();
        debug!(len = payload.len(), "QR code generated");
        let _ = status.send(Status::ShowQr { payload });

        let tunnel = pxp::connect(device, StatusSink(status.clone()));
        wait_connected(tunnel, QR_TIMEOUT, cancel).await
    }
}

#[async_trait]
impl HybridTransport for PxpTransport {
    async fn ctap(
        &self,
        frame: Vec<u8>,
        hint: Hint,
        status: watch::Sender<Status>,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, HybridError> {
        let result = self.run(frame, hint, &status, &cancel).await;
        let _ = status.send(match &result {
            Ok(_) => Status::Done,
            Err(HybridError::Cancelled) => Status::Idle,
            Err(e) => Status::Failed(e.to_string()),
        });
        result
    }
}

impl PxpTransport {
    async fn run(
        &self,
        frame: Vec<u8>,
        hint: Hint,
        status: &watch::Sender<Status>,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, HybridError> {
        Self::ensure_bluetooth().await?;
        if cancel.is_cancelled() {
            return Err(HybridError::Cancelled);
        }

        let (mut tunnel, linked_id) = match self.connect_linked(hint, status, cancel).await? {
            Some((tunnel, id)) => (tunnel, Some(id)),
            None => (self.connect_qr(hint, status, cancel).await?, None),
        };
        let _ = status.send(Status::Connected);

        // Send the request. The phone will now prompt the user.
        tokio::select! {
            _ = cancel.cancelled() => return Err(HybridError::Cancelled),
            sent = tunnel.ctap_sender.send(frame) => {
                sent.map_err(|_| HybridError::Transport("tunnel closed before the request was sent".into()))?;
            }
        }
        let _ = status.send(Status::WaitingForUser);
        info!("request sent to the phone, waiting for the user");

        let reply = tokio::select! {
            _ = cancel.cancelled() => {
                // Drop the handle: aborts the connection task and tells the phone nothing;
                // the phone shows its own "cancelled" state when the tunnel drops.
                drop(tunnel);
                return Err(HybridError::Cancelled);
            }
            recv = timeout(RESPONSE_TIMEOUT, tunnel.ctap_receiver.recv()) => match recv {
                Ok(Some(frame)) => frame,
                Ok(None) => return Err(HybridError::Transport("phone closed the connection without replying".into())),
                Err(_) => return Err(HybridError::Timeout),
            }
        };

        if reply.is_empty() {
            return Err(HybridError::Transport(
                "empty CTAP response from the phone".into(),
            ));
        }
        debug!(
            status = reply[0],
            len = reply.len(),
            "reply received from the phone"
        );

        // Graceful shutdown so the phone shows success rather than an error.
        tunnel.close().await;
        if let Some(id) = linked_id {
            self.store.touch(&id);
        }
        Ok(reply)
    }
}

/// Wait for the tunnel to be connected and authenticated, with a deadline and
/// cancellation. On any failure the handle is dropped (aborting the task).
async fn wait_connected(
    tunnel: TunnelHandle,
    deadline: Duration,
    cancel: &CancellationToken,
) -> Result<TunnelHandle, HybridError> {
    tokio::select! {
        _ = cancel.cancelled() => Err(HybridError::Cancelled),
        connected = timeout(deadline, tunnel.wait_for_connection()) => match connected {
            Ok(Ok(())) => Ok(tunnel),
            Ok(Err(e)) => {
                warn!(error = %e, "hybrid connection failed");
                Err(HybridError::Transport(e.to_string()))
            }
            Err(_) => Err(HybridError::Timeout),
        }
    }
}

/// Forwards pxp connection progress to the daemon's status channel.
struct StatusSink(watch::Sender<Status>);

impl UpdateSink for StatusSink {
    fn send_update(&self, update: PxpUpdate) {
        debug!(?update, "pxp update");
        let next = match update {
            // We already show the QR (or "check your phone") at this point.
            PxpUpdate::ProximityCheck => return,
            PxpUpdate::Connecting | PxpUpdate::Authenticating => Status::PhoneFound,
            PxpUpdate::Connected => Status::Connected,
            // Errors are reported through the request result; the status
            // channel gets the final Failed state from `ctap`.
            PxpUpdate::Error(_) => return,
        };
        let _ = self.0.send(next);
    }
}

impl From<Hint> for ClientPayloadHint {
    fn from(hint: Hint) -> Self {
        match hint {
            Hint::MakeCredential => ClientPayloadHint::MakeCredential,
            Hint::GetAssertion => ClientPayloadHint::GetAssertion,
        }
    }
}

impl From<Hint> for QrCodeOperationHint {
    fn from(hint: Hint) -> Self {
        match hint {
            Hint::MakeCredential => QrCodeOperationHint::MakeCredential,
            Hint::GetAssertion => QrCodeOperationHint::GetAssertionRequest,
        }
    }
}
