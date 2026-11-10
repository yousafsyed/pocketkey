//! Local answer to Firefox's silent "pre-flight" `getAssertion`.
//!
//! Whenever a site supplies an allowList (login) or excludeList (registration),
//! Firefox's authenticator-rs first probes the key with `getAssertion`
//! carrying `options.up = false` and a dummy clientDataHash, keeps only the
//! credentials the key "confirms". No matches fails a login, but may leave a
//! registration with an empty exclusion list (which is why probe errors latch).
//! A phone over the hybrid transport cannot answer a silent request (it closes
//! the tunnel), so we answer the probe here instead: we confirm every
//! credential the site itself listed. Nothing is invented, no key material is
//! involved; the real `getAssertion` that follows is forwarded to the phone,
//! which makes the actual decision. These placeholders are NOT assertions.
//!
//! Security depends on the client sending the entire list. Mozilla's
//! `third_party/rust/authenticator/src/ctap2/preflight.rs`
//! (`do_credential_list_filtering_ctap2`, gecko-dev/master inspected 2026-11-10)
//! stops after the FIRST successful count-based chunk. Missing/zero advertised
//! count means a chunk size of 1, not unlimited. Its transport/hid.rs sends the
//! serialized command whole (HID packet fragmentation is not list chunking).
//! We advertise MAX_MSG_SIZE as the count bound: no list fitting our byte limit
//! can exceed it. The old count of 64 was unsafe for tiny IDs.
//! See https://github.com/mozilla/gecko-dev/blob/master/third_party/rust/authenticator/src/ctap2/preflight.rs
//!
//! Chromium's FilterAndBatchCredentialDescriptors (142.0.7444.59 and main,
//! inspected 2026-11-10) ignores that count unless maxCredentialIdLength is
//! positive; omission/zero forces singleton probes. On registration it stops
//! at the first successful batch too, while login probes keep the REAL hash.
//! We therefore advertise 65535, the full two-byte attested-ID length range,
//! not 2048: a smaller advertised bound can silently drop a genuine exclusion.
//! The actual independent request/frame byte limit remains MAX_MSG_SIZE=2048;
//! oversized lists/IDs fail, rather than getting filtered into a usable subset.
//! With both positive hints, ordinary fitting Chromium registrations/logins
//! take its direct single-batch path, without synthetic probes. Credential-
//! specific PRF flows can still force silent login probes; real-hash silent
//! assertions remain unsupported, not replaced with synthetic signatures.
//! See https://github.com/chromium/chromium/blob/142.0.7444.59/device/fido/make_credential_task.cc
//! and https://github.com/chromium/chromium/blob/main/device/fido/get_assertion_task.cc
//!
//! We reject unexpected silent requests and latch failed/repeated probes in
//! Ctap2 so Firefox cannot discard a failed probe then create with no exclusions.
//! HID must also report rejected/abandoned CBOR (including timeouts) through
//! Ctap2::reject_channel: a 7610..65535-byte probe is rejected before dispatch.
//! Oversized frames received by CTAP (2049..7609 bytes) and compatibility edits
//! exceeding the byte limit set the same hard latch. It survives CANCEL
//! (oversized tails can encode one) and clears only on validated INIT/new
//! lifecycle via Ctap2::reinitialize_channel.
//! CHANNEL_BUSY does not reject the active request and must not set this latch.
//! The compatibility tests exercise the Firefox and Chromium request sequences
//! described above, including explicit channel reinitialization after errors.
//!
//! The synthetic response carries authData `SHA-256(rpId) || flags=0 ||
//! counter=0` and an empty signature, so it is recognisably not a real
//! assertion to anything that would try to verify it.

use ciborium::Value;
use sha2::{Digest, Sha256};

use super::{
    canonical, status, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_CREDENTIAL_ID_LENGTH, MAX_MSG_SIZE,
};

/// Outcome of inspecting a getAssertion request.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    /// A normal request (user presence wanted): forward it to the phone.
    NotSilent,
    /// Malformed CBOR: answer with this status byte.
    Error(u8),
    /// A silent probe: answer locally with these encoded responses
    /// (`status ++ cbor`), first one now, the rest via getNextAssertion.
    Assertions(Vec<Vec<u8>>),
}

/// Inspect the CBOR map of a getAssertion request (without the command byte).
pub fn inspect(cbor: &[u8]) -> Probe {
    if cbor.len() >= MAX_MSG_SIZE as usize {
        return Probe::Error(status::CTAP2_ERR_REQUEST_TOO_LARGE);
    }
    let Some(Value::Map(entries)) = canonical::decode_map(cbor) else {
        return Probe::Error(status::CTAP2_ERR_INVALID_CBOR);
    };
    let field = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    };

    let options = match field(5) {
        Some(Value::Map(options)) => Some(options),
        None => None,
        _ => return Probe::Error(status::CTAP2_ERR_INVALID_CBOR),
    };
    if options.is_some_and(|options| {
        options
            .iter()
            .any(|(k, v)| k.as_text().is_none() || !matches!(v, Value::Bool(_)))
    }) {
        return Probe::Error(status::CTAP2_ERR_INVALID_CBOR);
    }
    let silent = options.is_some_and(|options| {
        options
            .iter()
            .any(|(k, v)| k.as_text() == Some("up") && *v == Value::Bool(false))
    });
    if !silent {
        return Probe::NotSilent;
    }

    // Only the known Mozilla no-PIN, no-UV, no-extension probe is synthetic.
    // Ordinary silent assertions must never be answered with placeholders.
    if entries
        .iter()
        .any(|(key, _)| !matches!(key, Value::Integer(i) if (1..=5).contains(&i128::from(*i))))
        || options.is_some_and(|options| {
            options
                .iter()
                .any(|(k, v)| !matches!(k.as_text(), Some("up" | "uv")) || *v != Value::Bool(false))
        })
        || field(4).is_some_and(|ext| !matches!(ext, Value::Map(m) if m.is_empty()))
    {
        return Probe::Error(status::CTAP2_ERR_OPERATION_DENIED);
    }
    let Some(Value::Text(rp_id)) = field(1) else {
        return Probe::Error(status::CTAP2_ERR_MISSING_PARAMETER);
    };
    if rp_id.is_empty() || rp_id.len() > 253 || rp_id.chars().any(char::is_control) {
        return Probe::Error(status::CTAP2_ERR_INVALID_CBOR);
    }
    let Some(Value::Bytes(hash)) = field(2) else {
        return Probe::Error(status::CTAP2_ERR_MISSING_PARAMETER);
    };
    if hash.as_slice() != Sha256::digest(b"").as_slice() {
        return Probe::Error(status::CTAP2_ERR_OPERATION_DENIED);
    }
    let allow_list = match field(3) {
        Some(Value::Array(items)) => items.as_slice(),
        None => &[],
        _ => return Probe::Error(status::CTAP2_ERR_INVALID_CBOR),
    };
    if allow_list.len() > MAX_CREDENTIAL_COUNT_IN_LIST as usize {
        return Probe::Error(status::CTAP2_ERR_LIMIT_EXCEEDED);
    }
    if let Err(code) = validate_descriptors(allow_list) {
        return Probe::Error(code);
    }
    if allow_list.is_empty() {
        // Silent discovery of resident credentials: we have none to report.
        return Probe::Assertions(vec![vec![status::CTAP2_ERR_NO_CREDENTIALS]]);
    }

    let auth_data = placeholder_auth_data(rp_id);
    let total = allow_list.len();
    let responses: Vec<Vec<u8>> = allow_list
        .iter()
        .enumerate()
        .map(|(i, credential)| {
            let mut map = vec![
                (
                    Value::Integer(0x01.into()),
                    credential_descriptor(credential),
                ),
                (
                    Value::Integer(0x02.into()),
                    Value::Bytes(auth_data.to_vec()),
                ),
                (Value::Integer(0x03.into()), Value::Bytes(Vec::new())),
            ];
            if i == 0 && total > 1 {
                map.push((
                    Value::Integer(0x05.into()),
                    Value::Integer((total as u64).into()),
                ));
            }
            let mut out = vec![status::OK];
            ciborium::into_writer(&Value::Map(map), &mut out)
                .expect("encoding into a Vec cannot fail");
            out
        })
        .collect();
    if responses
        .iter()
        .any(|response| response.len() > MAX_MSG_SIZE as usize)
    {
        return Probe::Error(status::CTAP2_ERR_REQUEST_TOO_LARGE);
    }
    Probe::Assertions(responses)
}

/// Validate before echoing anything. Do not invent missing IDs or types, and
/// do not echo arbitrary descriptor fields into synthetic responses.
fn validate_descriptors(items: &[Value]) -> Result<(), u8> {
    for item in items {
        let Value::Map(fields) = item else {
            return Err(status::CTAP2_ERR_INVALID_CBOR);
        };
        let get = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        if !matches!(get("type"), Some(Value::Text(ty)) if ty == "public-key") {
            return Err(status::CTAP2_ERR_INVALID_CBOR);
        }
        let Some(Value::Bytes(id)) = get("id") else {
            return Err(status::CTAP2_ERR_INVALID_CBOR);
        };
        if id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LENGTH as usize {
            return Err(status::CTAP2_ERR_LIMIT_EXCEEDED);
        }
        for (key, value) in fields {
            match key.as_text() {
                Some("id" | "type") => {}
                Some("transports") if matches!(value, Value::Array(items) if items.len() <= 8 && items.iter().all(|item| matches!(item.as_text(), Some("usb" | "nfc" | "ble" | "internal" | "hybrid" | "cable" | "smart-card")))) =>
                    {}
                _ => return Err(status::CTAP2_ERR_INVALID_CBOR),
            }
        }
    }
    Ok(())
}

/// `rpIdHash || flags || signCount` with no flags set and a zero counter.
fn placeholder_auth_data(rp_id: &str) -> [u8; 37] {
    let mut out = [0u8; 37];
    out[..32].copy_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out
}

/// Echo the site's credential descriptor back with just `id` and `type`.
fn credential_descriptor(descriptor: &Value) -> Value {
    let fields = descriptor.as_map().expect("descriptor was validated");
    let id = fields
        .iter()
        .find(|(key, _)| key.as_text() == Some("id"))
        .expect("descriptor ID was validated")
        .1
        .clone();
    Value::Map(vec![
        (Value::Text("id".into()), id),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(rp_id: &str, allow: &[&[u8]], up: Option<bool>) -> Vec<u8> {
        let mut map = vec![
            (Value::Integer(0x01.into()), Value::Text(rp_id.into())),
            (
                Value::Integer(0x02.into()),
                Value::Bytes(Sha256::digest(b"").to_vec()),
            ),
        ];
        if !allow.is_empty() {
            map.push((
                Value::Integer(0x03.into()),
                Value::Array(
                    allow
                        .iter()
                        .map(|id| {
                            Value::Map(vec![
                                (Value::Text("id".into()), Value::Bytes(id.to_vec())),
                                (Value::Text("type".into()), Value::Text("public-key".into())),
                                (
                                    Value::Text("transports".into()),
                                    Value::Array(vec![Value::Text("usb".into())]),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(up) = up {
            map.push((
                Value::Integer(0x05.into()),
                Value::Map(vec![(Value::Text("up".into()), Value::Bool(up))]),
            ));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    fn decode(resp: &[u8]) -> Vec<(Value, Value)> {
        assert_eq!(resp[0], status::OK);
        let Value::Map(m) = ciborium::from_reader(&resp[1..]).unwrap() else {
            panic!("map")
        };
        m
    }

    fn get(m: &[(Value, Value)], key: i64) -> Option<&Value> {
        m.iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    }

    #[test]
    fn normal_requests_are_forwarded() {
        assert_eq!(
            inspect(&request("example.com", &[b"c1"], None)),
            Probe::NotSilent
        );
        assert_eq!(
            inspect(&request("example.com", &[b"c1"], Some(true))),
            Probe::NotSilent
        );
        assert_eq!(
            inspect(&request("example.com", &[], Some(true))),
            Probe::NotSilent
        );
    }

    #[test]
    fn silent_probe_echoes_single_credential() {
        let Probe::Assertions(responses) =
            inspect(&request("example.com", &[b"cred-1"], Some(false)))
        else {
            panic!("expected local answer");
        };
        assert_eq!(responses.len(), 1);
        let m = decode(&responses[0]);
        let Some(Value::Map(cred)) = get(&m, 1) else {
            panic!("credential")
        };
        assert_eq!(
            cred[0],
            (Value::Text("id".into()), Value::Bytes(b"cred-1".to_vec()))
        );
        assert_eq!(
            cred[1],
            (Value::Text("type".into()), Value::Text("public-key".into()))
        );
        let Some(Value::Bytes(auth_data)) = get(&m, 2) else {
            panic!("authData")
        };
        assert_eq!(auth_data.len(), 37);
        assert_eq!(&auth_data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth_data[32], 0, "no UP/UV flags");
        assert_eq!(
            get(&m, 3),
            Some(&Value::Bytes(Vec::new())),
            "empty signature"
        );
        assert_eq!(get(&m, 5), None, "numberOfCredentials omitted for one");
    }

    #[test]
    fn silent_probe_with_many_credentials_uses_number_of_credentials() {
        let Probe::Assertions(responses) =
            inspect(&request("rp", &[b"a", b"b", b"c"], Some(false)))
        else {
            panic!("expected local answer");
        };
        assert_eq!(responses.len(), 3);
        assert_eq!(
            get(&decode(&responses[0]), 5),
            Some(&Value::Integer(3.into()))
        );
        assert_eq!(get(&decode(&responses[1]), 5), None);
        for (resp, id) in responses.iter().zip([b"a", b"b", b"c"]) {
            let m = decode(resp);
            let Some(Value::Map(cred)) = get(&m, 1) else {
                panic!()
            };
            assert_eq!(cred[0].1, Value::Bytes(id.to_vec()));
        }
    }

    #[test]
    fn silent_probe_without_allow_list_reports_no_credentials() {
        assert_eq!(
            inspect(&request("rp", &[], Some(false))),
            Probe::Assertions(vec![vec![status::CTAP2_ERR_NO_CREDENTIALS]])
        );
    }

    #[test]
    fn garbage_is_invalid_cbor() {
        assert_eq!(
            inspect(&[0xFF, 0x00]),
            Probe::Error(status::CTAP2_ERR_INVALID_CBOR)
        );
        assert_eq!(
            inspect(&[0x01]),
            Probe::Error(status::CTAP2_ERR_INVALID_CBOR),
            "not a map"
        );
    }
}
