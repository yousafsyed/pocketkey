//! Hybrid (caBLE / PXP) transport to the phone.
//!
//! The daemon talks to this module through the [`HybridTransport`] trait so
//! the request lifecycle in `main` can be exercised with a fake. The real
//! implementation over the `pxp` crate lives in `pxp.rs` (milestone M3).

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Which CTAP operation the request is for. Sent to the phone ahead of the
/// request (QR key 5 / linked-flow hint) so it can show the right guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    MakeCredential,
    GetAssertion,
}

/// User-visible progress of a request. Drives the UI window and the
/// CTAPHID keepalive status (`WaitingForUser` is status 2, everything else
/// while active is status 1).
// Variants are constructed by the real transport (M3).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Idle,
    /// Contacting a linked phone via the tunnel service (no QR needed).
    LinkedWaitingForPhone {
        name: String,
    },
    /// Show this `FIDO:/...` payload as a QR code and wait for the scan.
    ShowQr {
        payload: String,
    },
    /// BLE advertisement seen, tunnel being set up.
    PhoneFound,
    /// Encrypted channel established, request sent.
    Connected,
    /// The phone is prompting the user (biometrics / confirmation).
    WaitingForUser,
    Done,
    Failed(String),
}

impl Status {
    /// Whether the user is expected to act on the phone right now.
    pub fn user_action_pending(&self) -> bool {
        matches!(self, Status::WaitingForUser)
    }
}

// Variants are constructed by the real transport (M3).
#[allow(dead_code)]
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum HybridError {
    #[error("request cancelled")]
    Cancelled,
    #[error("timed out waiting for the phone")]
    Timeout,
    #[error("the phone reported no matching credentials")]
    NoCredentials,
    #[error("no Bluetooth adapter available")]
    NoBluetooth,
    #[error("hybrid transport error: {0}")]
    Transport(String),
    #[error("hybrid transport not available in this build")]
    Unavailable,
}

#[async_trait]
pub trait HybridTransport: Send + Sync {
    /// Send one CTAP frame (`cmd ++ cbor`) to the phone and return its reply
    /// (`status ++ cbor`). Progress goes to `status`; `cancel` aborts the
    /// request at any stage, releasing the BLE scan and the tunnel.
    async fn ctap(
        &self,
        frame: Vec<u8>,
        hint: Hint,
        status: watch::Sender<Status>,
        cancel: CancellationToken,
    ) -> Result<Vec<u8>, HybridError>;
}

/// Placeholder used until the real transport lands: every forwarded request
/// fails immediately with `CTAP1_ERR_OTHER`.
pub struct UnavailableTransport;

#[async_trait]
impl HybridTransport for UnavailableTransport {
    async fn ctap(
        &self,
        _frame: Vec<u8>,
        _hint: Hint,
        status: watch::Sender<Status>,
        _cancel: CancellationToken,
    ) -> Result<Vec<u8>, HybridError> {
        let _ = status.send(Status::Failed(HybridError::Unavailable.to_string()));
        Err(HybridError::Unavailable)
    }
}
