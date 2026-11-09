//! Debug-level description of CTAP2 responses coming back from the phone.
//! Logs structure only (keys, lengths, flags, transports), never signatures,
//! credential ids or user data.

use ciborium::Value;

/// Small integer value of a CBOR key, or -1 for anything else.
fn key_index(k: &Value) -> i64 {
    match k {
        Value::Integer(i) => i64::try_from(*i).unwrap_or(-1),
        _ => -1,
    }
}

/// Log the shape of a makeCredential request map at debug level, and the raw
/// frame at trace level (trace includes clientDataHash and user fields; use
/// only while debugging interop).
pub fn log_make_credential_request(cbor: &[u8]) {
    tracing::trace!(request_hex = %hex_of(cbor), "makeCredential request (raw)");
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let Ok(Value::Map(entries)) = ciborium::from_reader::<Value, _>(cbor) else {
        tracing::debug!("makeCredential request did not decode as a map");
        return;
    };
    let field = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    };
    let map_keys = |v: Option<&Value>| match v {
        Some(Value::Map(f)) => f
            .iter()
            .map(|(k, v)| format!("{}:{}", key_name(k), type_name(v)))
            .collect::<Vec<_>>(),
        Some(other) => vec![type_name(other)],
        None => vec![],
    };
    let algs: Vec<String> = match field(4) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|p| match p {
                Value::Map(f) => f
                    .iter()
                    .map(|(k, v)| format!("{}={v:?}", key_name(k)))
                    .collect::<Vec<_>>()
                    .join(","),
                other => format!("{other:?}"),
            })
            .collect(),
        _ => vec![],
    };
    tracing::debug!(
        keys = ?entries.iter().map(|(k, _)| key_name(k)).collect::<Vec<_>>(),
        client_data_hash_len = field(1).and_then(|v| v.as_bytes()).map(|b| b.len()),
        rp = ?map_keys(field(2)),
        user = ?map_keys(field(3)),
        ?algs,
        exclude_list_len = field(5).and_then(|v| v.as_array()).map(|a| a.len()),
        extensions = ?map_keys(field(6)),
        options = ?field(7),
        has_pin_uv_auth = field(8).is_some(),
        pin_protocol = ?field(9),
        enterprise_attestation = ?field(10),
        attestation_formats = ?field(11),
        "makeCredential request to forward"
    );
}

/// Trace-level hex dump of a getAssertion request.
pub fn trace_get_assertion_request(cbor: &[u8]) {
    tracing::trace!(request_hex = %hex_of(cbor), "getAssertion request (raw)");
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key_name(k: &Value) -> String {
    match k {
        Value::Integer(i) => format!("{}", i128::from(*i)),
        Value::Text(t) => t.clone(),
        other => format!("{other:?}"),
    }
}

fn type_name(v: &Value) -> String {
    match v {
        Value::Integer(i) => format!("int({})", i128::from(*i)),
        Value::Bytes(b) => format!("bytes[{}]", b.len()),
        Value::Text(t) => format!("text[{}]", t.len()),
        Value::Bool(b) => format!("{b}"),
        Value::Array(a) => format!("array[{}]", a.len()),
        Value::Map(m) => format!("map[{}]", m.len()),
        other => format!("{other:?}"),
    }
}

/// Log the shape of a getAssertion/makeCredential response (`status ++ cbor`).
pub fn log_response(frame: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let Some((&status, cbor)) = frame.split_first() else {
        return;
    };
    if status != 0 || cbor.is_empty() {
        tracing::debug!(status, len = frame.len(), "phone response");
        return;
    }
    let value: Value = match ciborium::from_reader(cbor) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, len = cbor.len(), "phone response CBOR did not decode");
            return;
        }
    };
    let Value::Map(entries) = &value else {
        tracing::debug!("phone response is not a CBOR map");
        return;
    };
    let keys: Vec<String> = entries.iter().map(|(k, _)| format!("{k:?}")).collect();
    let field = |key: i64| {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .map(|(_, v)| v)
    };
    let auth_data = field(2).and_then(|v| v.as_bytes()).map(|b| {
        let flags = b.get(32).copied().unwrap_or(0);
        format!(
            "len={} flags=0x{flags:02x}(up={} uv={} be={} bs={} at={} ed={}) counter={}",
            b.len(),
            flags & 0x01 != 0,
            flags & 0x04 != 0,
            flags & 0x08 != 0,
            flags & 0x10 != 0,
            flags & 0x40 != 0,
            flags & 0x80 != 0,
            b.get(33..37)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .unwrap_or(0)
        )
    });
    let credential = field(1).map(|v| match v {
        Value::Map(f) => f
            .iter()
            .map(|(k, v)| match (k.as_text(), v) {
                (Some("id"), Value::Bytes(b)) => format!("id[{}]", b.len()),
                (Some(k), v) => format!("{k}={v:?}"),
                (None, _) => "?".into(),
            })
            .collect::<Vec<_>>()
            .join(","),
        other => format!("{other:?}"),
    });
    let user_keys = field(4).map(|v| match v {
        Value::Map(f) => f
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_string))
            .collect::<Vec<_>>(),
        _ => vec!["(not a map)".into()],
    });
    tracing::debug!(
        ?keys,
        credential = credential.as_deref().unwrap_or("-"),
        auth_data = auth_data.as_deref().unwrap_or("-"),
        signature_len = field(3).and_then(|v| v.as_bytes()).map(|b| b.len()),
        ?user_keys,
        number_of_credentials = ?field(5),
        user_selected = ?field(6),
        extra = ?entries
            .iter()
            .filter(|(k, _)| !(1..=6).contains(&key_index(k)))
            .map(|(k, _)| format!("{k:?}"))
            .collect::<Vec<_>>(),
        "phone response"
    );
}
