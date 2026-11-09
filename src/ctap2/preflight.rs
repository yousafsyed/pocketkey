//! Local answer to Firefox's silent "pre-flight" `getAssertion`.
//!
//! Whenever a site supplies an allowList (login) or excludeList (registration),
//! Firefox's authenticator-rs first probes the key with `getAssertion`
//! carrying `options.up = false` and a dummy clientDataHash, keeps only the
//! credentials the key "confirms", and fails outright if none are confirmed.
//! A phone over the hybrid transport cannot answer a silent request (it closes
//! the tunnel), so we answer the probe here instead: we confirm every
//! credential the site itself listed. Nothing is invented, no key material is
//! involved, and no browser treats a `up=false` assertion as proof of
//! anything; the real `getAssertion` that follows is forwarded to the phone,
//! which makes the actual decision. For an excludeList this is the
//! conservative answer too: Firefox keeps the entry and the phone enforces it.
//!
//! The synthetic response carries authData `SHA-256(rpId) || flags=0 ||
//! counter=0` and an empty signature, so it is recognisably not a real
//! assertion to anything that would try to verify it.

use ciborium::Value;
use sha2::{Digest, Sha256};

use super::status;

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
    let Ok(Value::Map(entries)) = ciborium::from_reader::<Value, _>(cbor) else {
        return Probe::Error(status::CTAP2_ERR_INVALID_CBOR);
    };
    let field = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    };

    let up_requested = match field(0x05) {
        Some(Value::Map(options)) => options
            .iter()
            .find(|(k, _)| k.as_text() == Some("up"))
            .map(|(_, v)| v.as_bool().unwrap_or(true))
            .unwrap_or(true),
        _ => true,
    };
    if up_requested {
        describe_request(&entries, &|k| field(k));
        return Probe::NotSilent;
    }

    let Some(Value::Text(rp_id)) = field(0x01) else {
        return Probe::Error(status::CTAP2_ERR_MISSING_PARAMETER);
    };
    let allow_list: Vec<&Value> = match field(0x03) {
        Some(Value::Array(items)) => items.iter().collect(),
        _ => Vec::new(),
    };
    if allow_list.is_empty() {
        // Silent discovery of resident credentials: we have none to report.
        return Probe::Assertions(vec![vec![status::CTAP2_ERR_NO_CREDENTIALS]]);
    }

    let auth_data = placeholder_auth_data(rp_id);
    let total = allow_list.len();
    let responses = allow_list
        .into_iter()
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
    Probe::Assertions(responses)
}

/// Debug-log the shape of a request we are about to forward: enough to see
/// what a phone might object to, without the clientDataHash or credential ids.
fn describe_request<'a>(entries: &'a [(Value, Value)], field: &dyn Fn(i64) -> Option<&'a Value>) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let rp_id = field(0x01).and_then(|v| v.as_text()).unwrap_or("?");
    let allow: Vec<usize> = match field(0x03) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|c| match c {
                Value::Map(f) => f
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("id"))
                    .and_then(|(_, v)| v.as_bytes())
                    .map_or(0, |b| b.len()),
                _ => 0,
            })
            .collect(),
        _ => Vec::new(),
    };
    let transports: Vec<String> = match field(0x03) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|c| match c {
                Value::Map(f) => f
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("transports"))
                    .map(|(_, v)| format!("{v:?}")),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let extensions: Vec<String> = match field(0x04) {
        Some(Value::Map(f)) => f
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let options = field(0x05).map(|v| format!("{v:?}")).unwrap_or_default();
    let keys: Vec<String> = entries.iter().map(|(k, _)| format!("{k:?}")).collect();
    tracing::debug!(
        rp_id,
        allow_list_id_lengths = ?allow,
        allow_list_transports = ?transports,
        ?extensions,
        %options,
        has_pin_uv_auth = field(0x06).is_some(),
        ?keys,
        "getAssertion request to forward"
    );
}

/// `rpIdHash || flags || signCount` with no flags set and a zero counter.
fn placeholder_auth_data(rp_id: &str) -> [u8; 37] {
    let mut out = [0u8; 37];
    out[..32].copy_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out
}

/// Echo the site's credential descriptor back with just `id` and `type`.
fn credential_descriptor(descriptor: &Value) -> Value {
    let (id, ty) = match descriptor {
        Value::Map(fields) => {
            let get = |name: &str| {
                fields
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(name))
                    .map(|(_, v)| v.clone())
            };
            (
                get("id").unwrap_or(Value::Bytes(Vec::new())),
                get("type").unwrap_or(Value::Text("public-key".into())),
            )
        }
        _ => (Value::Bytes(Vec::new()), Value::Text("public-key".into())),
    };
    Value::Map(vec![
        (Value::Text("id".into()), id),
        (Value::Text("type".into()), ty),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(rp_id: &str, allow: &[&[u8]], up: Option<bool>) -> Vec<u8> {
        let mut map = vec![
            (Value::Integer(0x01.into()), Value::Text(rp_id.into())),
            (Value::Integer(0x02.into()), Value::Bytes(vec![0xAA; 32])),
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
