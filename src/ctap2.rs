//! CTAP2 command layer: everything inside a `CTAPHID_CBOR` message.
//!
//! The payload of a CTAPHID_CBOR request is `command_byte ++ cbor_map`; the
//! response is `status_byte ++ cbor_map`. We answer `authenticatorGetInfo`,
//! `authenticatorSelection` and `authenticatorReset` locally and forward
//! `makeCredential`, `getAssertion` and `getNextAssertion` to the phone
//! byte-for-byte via the [`crate::hybrid`] module.

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
    pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
    pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
    pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
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

/// What to do with a CTAPHID_CBOR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Answer immediately with these bytes (`status ++ cbor`).
    Respond(Vec<u8>),
    /// Forward the whole payload (`cmd ++ cbor`) to the phone.
    Forward { hint: Hint },
}

/// Decide how a CTAPHID_CBOR payload is handled.
pub fn dispatch(payload: &[u8]) -> Disposition {
    let Some((&cmd, _cbor)) = payload.split_first() else {
        return Disposition::Respond(vec![status::CTAP1_ERR_INVALID_LENGTH]);
    };
    if payload.len() > MAX_MSG_SIZE as usize {
        return Disposition::Respond(vec![status::CTAP2_ERR_REQUEST_TOO_LARGE]);
    }
    match cmd {
        command::GET_INFO => Disposition::Respond(get_info_response()),
        command::MAKE_CREDENTIAL => Disposition::Forward {
            hint: Hint::MakeCredential,
        },
        command::GET_ASSERTION | command::GET_NEXT_ASSERTION => Disposition::Forward {
            hint: Hint::GetAssertion,
        },
        // We are the only "key" the client can pick, so selection succeeds at once.
        command::SELECTION => Disposition::Respond(vec![status::OK]),
        command::RESET => Disposition::Respond(vec![status::CTAP2_ERR_NOT_ALLOWED]),
        // No PIN support is advertised; a client that asks anyway gets the
        // same answer a PIN-less key would give for an unsupported command.
        command::CLIENT_PIN => Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND]),
        _ => Disposition::Respond(vec![status::CTAP1_ERR_INVALID_COMMAND]),
    }
}

/// `authenticatorGetInfo` response, `0x00 ++ cbor`.
///
/// Deliberately minimal so clients never attempt PIN, credential management
/// or extension flows: no `clientPin`, no `pinUvAuthProtocols`, no
/// `extensions`. `maxCredentialCountInList`/`maxCredentialIdLength` are
/// generous so Firefox sends an allowList in one batch instead of probing
/// credential by credential.
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
        (Value::Integer(0x07.into()), Value::Integer(64.into())),
        (Value::Integer(0x08.into()), Value::Integer(1024.into())),
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
        HybridError::NoCredentials => status::CTAP2_ERR_NO_CREDENTIALS,
        HybridError::NoBluetooth | HybridError::Transport(_) | HybridError::Unavailable => {
            status::CTAP1_ERR_OTHER
        }
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
                hint: Hint::MakeCredential
            }
        );
        assert_eq!(
            dispatch(&[command::GET_ASSERTION, 0xA0]),
            Disposition::Forward {
                hint: Hint::GetAssertion
            }
        );
        assert_eq!(
            dispatch(&[command::GET_NEXT_ASSERTION]),
            Disposition::Forward {
                hint: Hint::GetAssertion
            }
        );
    }

    #[test]
    fn local_answers_for_selection_reset_pin_unknown_empty() {
        assert_eq!(
            dispatch(&[command::SELECTION]),
            Disposition::Respond(vec![status::OK])
        );
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
        assert_eq!(status_for_hybrid_error(&HybridError::NoCredentials), 0x2E);
        assert_eq!(status_for_hybrid_error(&HybridError::NoBluetooth), 0x7F);
        assert_eq!(
            status_for_hybrid_error(&HybridError::Transport("x".into())),
            0x7F
        );
    }
}
