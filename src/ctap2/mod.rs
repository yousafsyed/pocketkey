//! CTAP2 command layer: everything inside a `CTAPHID_CBOR` message.
//!
//! The payload of a CTAPHID_CBOR request is `command_byte ++ cbor_map`; the
//! response is `status_byte ++ cbor_map`. We answer `authenticatorGetInfo`,
//! `authenticatorSelection`, `authenticatorReset` and Firefox's silent
//! pre-flight probes (see [`preflight`]) locally, and forward `makeCredential`
//! and `getAssertion` to the phone via [`crate::hybrid`] after strict decoding,
//! canonical encoding and the narrowly scoped phone compatibility fill-ins.

pub mod canonical;
pub mod compat;
pub mod describe;
pub mod preflight;

#[cfg(test)]
mod security_tests;

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ciborium::Value;

use crate::hybrid::{Hint, HybridError};

/// CTAP2 command bytes.
pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const SELECTION: u8 = 0x0B;
}

/// CTAP2 status codes we emit ourselves.
#[allow(dead_code)]
pub mod status {
    pub const OK: u8 = 0x00;
    pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
    pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
    pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
    pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
    pub const CTAP2_ERR_LIMIT_EXCEEDED: u8 = 0x15;
    pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
    pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
    pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
    pub const CTAP2_ERR_REQUEST_TOO_LARGE: u8 = 0x39;
    pub const CTAP1_ERR_OTHER: u8 = 0x7F;
}

/// Fixed AAGUID for this virtual authenticator (generated once, never changes).
pub const AAGUID: [u8; 16] = [
    0x95, 0xe3, 0x54, 0xb3, 0x94, 0x09, 0x46, 0x96, 0xbd, 0x03, 0xb8, 0x7e, 0xd8, 0x06, 0xef, 0x7a,
];

/// Largest CTAP message we accept, advertised in getInfo.
pub const MAX_MSG_SIZE: u64 = 2048;

/// Separate from the byte limit: even a one-byte CBOR item occupies a byte,
/// so no request fitting MAX_MSG_SIZE can be count-chunked at this bound.
/// Omission is unsafe: Mozilla falls back to a count of 1 (see preflight).
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = MAX_MSG_SIZE;
/// Advertised ID-length bound: the two-byte length in attested credential data
/// permits IDs up to 65535 bytes. Chromium needs a positive value here or it
/// ignores our list-count bound and probes one ID at a time. Using MAX_MSG_SIZE
/// instead would silently filter oversized exclusions before we could reject
/// their request. The independent 2048-byte frame limit still applies.
pub const MAX_CREDENTIAL_ID_LENGTH: u64 = u16::MAX as u64;
pub const ASSERTION_SEQUENCE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TRACKED_CHANNELS: usize = crate::ctaphid::MAX_CHANNELS;

/// What to do with a CTAPHID_CBOR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Answer immediately with these bytes (`status ++ cbor`).
    Respond(Vec<u8>),
    /// Forward this payload (`cmd ++ cbor`, canonically re-encoded) to the phone.
    Forward { hint: Hint, frame: Vec<u8> },
    /// Main must await explicit user confirmation (or cancellation/timeout).
    /// Never answer success merely because this virtual device is available.
    Select,
}

/// A sequence is channel-owned and expires without refreshing on reads.
#[derive(Default)]
struct ChannelState {
    pending_assertions: VecDeque<Vec<u8>>,
    expires: Option<Instant>,
    probe_seen: bool,
    probe_request: Option<Value>,
    // A rejected probe must not turn into an unchecked empty excludeList when
    // the client ignores the error. Explicit CANCEL clears this soft latch.
    blocked: bool,
    // HID rejected/abandoned CBOR before dispatch, or a CTAP frame exceeded
    // the byte limit. Oversized continuation tails can resemble CANCEL, so
    // only a genuine new channel lifecycle clears this.
    rejected_cbor: bool,
}

/// Bounded per-channel state; never evict a failure latch to accept a request.
#[derive(Default)]
pub struct Ctap2 {
    channels: HashMap<u32, ChannelState>,
    // Should be unreachable with synchronized HID lifecycle events. If a hard
    // rejection cannot be recorded, fail all credential operations closed for
    // this Ctap2 instance: freeing a different channel cannot erase that failure.
    rejection_overflow: bool,
}

impl Ctap2 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience for single-channel callers. The HID loop must use the
    /// explicit channel API and map Reset, Reinitialized and RejectedCbor to
    /// their respective lifecycle methods below (including events from ticks).
    pub fn dispatch(&mut self, payload: &[u8]) -> Disposition {
        self.dispatch_on_channel(0, payload, Instant::now())
    }

    /// Discard normal preflight state on CANCEL, preserving transport rejection.
    /// Oversized continuation sequence 145 can look like zero-length CANCEL;
    /// accepting it as cancellation must not permit an unchecked registration.
    pub fn reset_channel(&mut self, cid: u32) {
        if self
            .channels
            .get(&cid)
            .is_some_and(|state| state.rejected_cbor)
        {
            self.channels.insert(
                cid,
                ChannelState {
                    rejected_cbor: true,
                    ..ChannelState::default()
                },
            );
        } else {
            self.channels.remove(&cid);
        }
    }

    /// Clear all per-channel state only for HID's validated INIT/new lifecycle
    /// or channel reclamation event, never for malformed INIT or CHANNEL_BUSY.
    pub fn reinitialize_channel(&mut self, cid: u32) {
        self.channels.remove(&cid);
    }

    /// Latch a CBOR request rejected/abandoned by HID before CTAP could inspect
    /// it. Main must call this only for RejectedCbor, NOT ordinary CHANNEL_BUSY.
    /// Repeated rejections are idempotent and never refresh or drop the latch.
    pub fn reject_channel(&mut self, cid: u32) {
        // Empty states hold no security decision and may be discarded. Never
        // evict a live sequence, soft failure or hard rejection to make room.
        self.channels.retain(|_, state| {
            state.rejected_cbor
                || state.blocked
                || state.probe_seen
                || !state.pending_assertions.is_empty()
        });
        if !self.channels.contains_key(&cid) && self.channels.len() >= MAX_TRACKED_CHANNELS {
            self.rejection_overflow = true;
            return;
        }
        self.channels.insert(
            cid,
            ChannelState {
                rejected_cbor: true,
                ..ChannelState::default()
            },
        );
    }

    pub fn dispatch_on_channel(&mut self, cid: u32, payload: &[u8], now: Instant) -> Disposition {
        // Retain failed or unfinished preflights: silently evicting those could
        // let a delayed makeCredential bypass a failed exclusion probe.
        self.channels.retain(|_, state| {
            if state.expires.is_some_and(|deadline| now >= deadline) {
                state.pending_assertions.clear();
                state.probe_request = None;
                state.expires = None;
                state.blocked |= state.probe_seen;
            }
            state.rejected_cbor
                || state.blocked
                || state.probe_seen
                || !state.pending_assertions.is_empty()
        });
        if self.rejection_overflow
            && matches!(
                payload.first(),
                Some(&command::MAKE_CREDENTIAL)
                    | Some(&command::GET_ASSERTION)
                    | Some(&command::GET_NEXT_ASSERTION)
            )
        {
            return Disposition::Respond(vec![status::CTAP2_ERR_OPERATION_DENIED]);
        }
        if !self.channels.contains_key(&cid) && self.channels.len() >= MAX_TRACKED_CHANNELS {
            return Disposition::Respond(vec![status::CTAP2_ERR_LIMIT_EXCEEDED]);
        }
        let state = self.channels.entry(cid).or_default();
        let Some((&cmd, cbor)) = payload.split_first() else {
            state.pending_assertions.clear();
            state.blocked |= state.probe_seen;
            return Disposition::Respond(vec![status::CTAP1_ERR_INVALID_LENGTH]);
        };
        if cmd != command::GET_NEXT_ASSERTION {
            state.pending_assertions.clear();
        }
        if payload.len() > MAX_MSG_SIZE as usize {
            *state = ChannelState {
                rejected_cbor: true,
                ..ChannelState::default()
            };
            return Disposition::Respond(vec![status::CTAP2_ERR_REQUEST_TOO_LARGE]);
        }
        if matches!(
            cmd,
            command::GET_INFO | command::GET_NEXT_ASSERTION | command::SELECTION | command::RESET
        ) && !cbor.is_empty()
        {
            state.pending_assertions.clear();
            state.blocked |= state.probe_seen;
            return Disposition::Respond(vec![status::CTAP1_ERR_INVALID_LENGTH]);
        }
        match cmd {
            command::GET_INFO => Disposition::Respond(get_info_response()),
            command::MAKE_CREDENTIAL | command::GET_ASSERTION
                if state.blocked || state.rejected_cbor =>
            {
                Disposition::Respond(vec![status::CTAP2_ERR_OPERATION_DENIED])
            }
            command::MAKE_CREDENTIAL => {
                if state
                    .probe_request
                    .as_ref()
                    .is_some_and(|probe| !preserves_exclusions(probe, cbor))
                {
                    state.blocked = true;
                    return Disposition::Respond(vec![status::CTAP2_ERR_OPERATION_DENIED]);
                }
                describe::log_make_credential_request(cbor);
                let result = forwardable(cmd, cbor);
                state.blocked |= state.probe_seen && result.is_err();
                state.rejected_cbor |= result == Err(status::CTAP2_ERR_REQUEST_TOO_LARGE);
                state.probe_seen = false;
                state.probe_request = None;
                state.expires = None;
                forward_disposition(result, Hint::MakeCredential)
            }
            command::GET_ASSERTION => match preflight::inspect(cbor) {
                preflight::Probe::NotSilent => {
                    describe::trace_get_assertion_request(cbor);
                    let result = forwardable(cmd, cbor);
                    state.blocked |= state.probe_seen && result.is_err();
                    state.rejected_cbor |= result == Err(status::CTAP2_ERR_REQUEST_TOO_LARGE);
                    state.probe_seen = false;
                    state.probe_request = None;
                    state.expires = None;
                    forward_disposition(result, Hint::GetAssertion)
                }
                preflight::Probe::Error(code) => {
                    state.blocked = true;
                    state.rejected_cbor |= code == status::CTAP2_ERR_REQUEST_TOO_LARGE;
                    Disposition::Respond(vec![code])
                }
                preflight::Probe::Assertions(mut responses) => {
                    // A second probe before the real operation is observable
                    // chunking (or an ambiguous abandoned operation). Fail closed.
                    if state.probe_seen {
                        state.blocked = true;
                        return Disposition::Respond(vec![status::CTAP2_ERR_OPERATION_DENIED]);
                    }
                    state.probe_seen = true;
                    state.probe_request = canonical::decode_map(cbor);
                    state.expires = Some(now + ASSERTION_SEQUENCE_TIMEOUT);
                    let first = responses.remove(0);
                    if first.first() != Some(&status::OK) {
                        state.blocked = true;
                    }
                    tracing::info!(
                        credentials = responses.len() + 1,
                        "answering silent pre-flight getAssertion locally"
                    );
                    state.pending_assertions = responses.into();
                    Disposition::Respond(first)
                }
            },
            command::GET_NEXT_ASSERTION => match state.pending_assertions.pop_front() {
                Some(response) if !state.blocked && !state.rejected_cbor => {
                    Disposition::Respond(response)
                }
                _ => Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED]),
            },
            command::SELECTION => Disposition::Select,
            command::RESET => Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED]),
            command::CLIENT_PIN => Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND]),
            _ => Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND]),
        }
    }
}

/// Check everything we actually saw survives Firefox's exclusion filtering.
fn preserves_exclusions(probe: &Value, cbor: &[u8]) -> bool {
    fn field(map: &Value, key: i64) -> Option<&Value> {
        map.as_map()?
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    }
    fn text_field<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
        map.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }
    let Some(request) = canonical::decode_map(cbor) else {
        return false;
    };
    let Some(rp) = field(&request, 2) else {
        return false;
    };
    if field(probe, 1) != text_field(rp, "id") {
        return false;
    }
    let Some(allow) = field(probe, 3).and_then(Value::as_array) else {
        return false;
    };
    let Some(exclude) = field(&request, 5).and_then(Value::as_array) else {
        return false;
    };
    allow.iter().all(|credential| {
        exclude.iter().any(|excluded| {
            text_field(credential, "id") == text_field(excluded, "id")
                && text_field(credential, "type") == text_field(excluded, "type")
        })
    })
}

fn forward_disposition(result: Result<Vec<u8>, u8>, hint: Hint) -> Disposition {
    match result {
        Ok(frame) => Disposition::Forward { hint, frame },
        Err(code) => Disposition::Respond(vec![code]),
    }
}

/// Strict single-map decode before any edits, canonical re-encoding, and a
/// second size check after compatibility defaults may have grown the frame.
fn forwardable(cmd: u8, cbor: &[u8]) -> Result<Vec<u8>, u8> {
    let mut value = canonical::decode_map(cbor).ok_or(status::CTAP2_ERR_INVALID_CBOR)?;
    if cmd == command::MAKE_CREDENTIAL {
        let edits = compat::complete_make_credential(&mut value);
        if !edits.is_empty() {
            tracing::debug!(
                rp_name_added = edits.rp_name_added,
                display_name_added = edits.display_name_added,
                false_extensions_removed = edits.false_extensions_removed,
                "completed makeCredential request for the phone"
            );
        }
    }
    let body = canonical::encode_canonical(value);
    if body.len() + 1 > MAX_MSG_SIZE as usize {
        return Err(status::CTAP2_ERR_REQUEST_TOO_LARGE);
    }
    let mut frame = Vec::with_capacity(1 + body.len());
    frame.push(cmd);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// `authenticatorGetInfo` response, `0x00 ++ cbor`.
///
/// Deliberately minimal so clients never attempt PIN, credential management
/// or extension flows: no `clientPin`, no `pinUvAuthProtocols`, no
/// `extensions`. `maxCredentialCountInList` exceeds every encodable list's
/// count, paired with a positive `maxCredentialIdLength` covering the entire
/// attested-ID range so both Chromium and Firefox retain exclusions together.
/// These browser batching hints do NOT relax the independent frame byte limit.
pub fn get_info_response() -> Vec<u8> {
    let info = Value::Map(vec![
        (
            Value::Integer(0x01.into()),
            Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("FIDO_2_1".into()),
            ]),
        ),
        (Value::Integer(0x03.into()), Value::Bytes(AAGUID.to_vec())),
        (
            Value::Integer(0x04.into()),
            // Canonical CBOR orders text keys by length, then bytewise.
            Value::Map(vec![
                (Value::Text("rk".into()), Value::Bool(true)),
                (Value::Text("up".into()), Value::Bool(true)),
                (Value::Text("uv".into()), Value::Bool(true)),
                (Value::Text("plat".into()), Value::Bool(false)),
            ]),
        ),
        (
            Value::Integer(0x05.into()),
            Value::Integer(MAX_MSG_SIZE.into()),
        ),
        (
            Value::Integer(0x07.into()),
            Value::Integer(MAX_CREDENTIAL_COUNT_IN_LIST.into()),
        ),
        (
            Value::Integer(0x08.into()),
            Value::Integer(MAX_CREDENTIAL_ID_LENGTH.into()),
        ),
        (
            Value::Integer(0x09.into()),
            Value::Array(vec![Value::Text("usb".into())]),
        ),
    ]);
    let mut out = vec![status::OK];
    ciborium::into_writer(&info, &mut out).expect("encoding a static map into a Vec cannot fail");
    out
}

/// Map a failure of the hybrid module to the status byte returned to the client.
pub fn status_for_hybrid_error(err: &HybridError) -> u8 {
    match err {
        HybridError::Cancelled => status::CTAP2_ERR_KEEPALIVE_CANCEL,
        HybridError::Timeout => status::CTAP2_ERR_USER_ACTION_TIMEOUT,
        HybridError::NotAllowed => status::CTAP2_ERR_NOT_ALLOWED,
        HybridError::NoBluetooth | HybridError::Transport(_) => status::CTAP1_ERR_OTHER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn decode(bytes: &[u8]) -> Value {
        ciborium::from_reader(bytes).expect("valid cbor")
    }

    fn get(map: &Value, key: i64) -> Option<&Value> {
        let Value::Map(entries) = map else {
            panic!("not a map")
        };
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    }

    fn dispatch(payload: &[u8]) -> Disposition {
        Ctap2::new().dispatch(payload)
    }

    #[test]
    fn get_info_is_answered_locally_and_well_formed() {
        let Disposition::Respond(resp) = dispatch(&[command::GET_INFO]) else {
            panic!("getInfo must not be forwarded");
        };
        assert_eq!(resp[0], status::OK);
        let info = decode(&resp[1..]);
        assert_eq!(
            get(&info, 1),
            Some(&Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("FIDO_2_1".into())
            ]))
        );
        assert_eq!(get(&info, 3), Some(&Value::Bytes(AAGUID.to_vec())));
        assert_eq!(get(&info, 5), Some(&Value::Integer(2048.into())));
        assert_eq!(
            get(&info, 9),
            Some(&Value::Array(vec![Value::Text("usb".into())]))
        );
        // No clientPin, no pinUvAuthProtocols, no extensions.
        assert_eq!(get(&info, 2), None, "extensions");
        assert_eq!(get(&info, 6), None, "pinUvAuthProtocols");
        let Some(Value::Map(options)) = get(&info, 4) else {
            panic!("options")
        };
        let keys: Vec<&str> = options.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, ["rk", "up", "uv", "plat"]);
        assert!(!options
            .iter()
            .any(|(k, _)| k.as_text() == Some("clientPin")));
        assert_eq!(options[3].1, Value::Bool(false), "plat");
        assert!(resp.len() <= MAX_MSG_SIZE as usize);
    }

    #[test]
    fn aaguid_matches_documented_uuid() {
        assert_eq!(hex::encode(AAGUID), "95e354b394094696bd03b87ed806ef7a");
    }

    #[test]
    fn credential_commands_are_forwarded_with_hint() {
        assert_eq!(
            dispatch(&[command::MAKE_CREDENTIAL, 0xA0]),
            Disposition::Forward {
                hint: Hint::MakeCredential,
                frame: vec![command::MAKE_CREDENTIAL, 0xA0]
            }
        );
        assert_eq!(
            dispatch(&[command::GET_ASSERTION, 0xA0]),
            Disposition::Forward {
                hint: Hint::GetAssertion,
                frame: vec![command::GET_ASSERTION, 0xA0]
            }
        );
        // Undecodable CBOR must not reach the phone.
        assert_eq!(
            dispatch(&[command::MAKE_CREDENTIAL, 0xFF]),
            Disposition::Respond(vec![status::CTAP2_ERR_INVALID_CBOR])
        );
        assert_eq!(
            dispatch(&[command::GET_NEXT_ASSERTION]),
            Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED]),
            "no pre-flight in progress"
        );
    }

    #[test]
    fn silent_preflight_is_served_locally_with_get_next_assertion() {
        let allow: Vec<Value> = ["a", "b"]
            .iter()
            .map(|id| {
                Value::Map(vec![
                    (
                        Value::Text("id".into()),
                        Value::Bytes(id.as_bytes().to_vec()),
                    ),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])
            })
            .collect();
        let req = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("example.com".into())),
            (
                Value::Integer(2.into()),
                Value::Bytes({
                    use sha2::{Digest, Sha256};
                    Sha256::digest(b"").to_vec()
                }),
            ),
            (Value::Integer(3.into()), Value::Array(allow)),
            (
                Value::Integer(5.into()),
                Value::Map(vec![(Value::Text("up".into()), Value::Bool(false))]),
            ),
        ]);
        let mut payload = vec![command::GET_ASSERTION];
        ciborium::into_writer(&req, &mut payload).unwrap();

        let mut ctap = Ctap2::new();
        let Disposition::Respond(first) = ctap.dispatch(&payload) else {
            panic!("must be local")
        };
        assert_eq!(first[0], status::OK);
        let Disposition::Respond(second) = ctap.dispatch(&[command::GET_NEXT_ASSERTION]) else {
            panic!()
        };
        assert_eq!(second[0], status::OK);
        assert_ne!(first, second);
        assert_eq!(
            ctap.dispatch(&[command::GET_NEXT_ASSERTION]),
            Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED]),
            "queue exhausted"
        );
        // A new pre-flight followed by an unrelated command drops the queue.
        ctap.reset_channel(0);
        ctap.dispatch(&payload);
        ctap.dispatch(&[command::GET_INFO]);
        assert_eq!(
            ctap.dispatch(&[command::GET_NEXT_ASSERTION]),
            Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED])
        );
    }

    #[test]
    fn local_answers_for_selection_reset_pin_unknown_empty() {
        assert_eq!(dispatch(&[command::SELECTION]), Disposition::Select);
        assert_eq!(
            dispatch(&[command::RESET]),
            Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED])
        );
        assert_eq!(
            dispatch(&[command::CLIENT_PIN, 0xA0]),
            Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND])
        );
        assert_eq!(
            dispatch(&[0x0A, 0xA0]),
            Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND])
        );
        assert_eq!(
            dispatch(&[]),
            Disposition::Respond(vec![status::CTAP1_ERR_INVALID_LENGTH])
        );
        let big = vec![command::GET_ASSERTION; MAX_MSG_SIZE as usize + 1];
        assert_eq!(
            dispatch(&big),
            Disposition::Respond(vec![status::CTAP2_ERR_REQUEST_TOO_LARGE])
        );
    }

    #[test]
    fn hybrid_errors_map_to_ctap2_statuses() {
        assert_eq!(status_for_hybrid_error(&HybridError::Cancelled), 0x2D);
        assert_eq!(status_for_hybrid_error(&HybridError::Timeout), 0x2F);
        assert_eq!(status_for_hybrid_error(&HybridError::NoBluetooth), 0x7F);
        assert_eq!(status_for_hybrid_error(&HybridError::NotAllowed), 0x30);
        assert_eq!(
            status_for_hybrid_error(&HybridError::Transport("x".into())),
            0x7F
        );
    }
}
