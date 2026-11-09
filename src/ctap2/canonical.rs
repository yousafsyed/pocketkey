//! CTAP2 canonical CBOR re-encoding for forwarded requests.
//!
//! Firefox's authenticator-rs writes some maps with keys out of canonical
//! order (`getAssertion` options come out as `{"uv": .., "up": ..}`), and the
//! Android hybrid authenticator decodes with a strict canonical CBOR reader
//! that rejects out-of-order keys, dropping the request as invalid CTAP. Real
//! USB keys mostly do not care, which is why Firefox never noticed.
//!
//! [`canonicalize`] decodes a CBOR item and re-encodes it with every map's
//! keys sorted per CTAP2 canonical rules (major type, then encoded length,
//! then bytewise). Values are untouched: clientDataHash, credential ids and
//! all other bytes are preserved exactly; only key order can change.

use std::cmp::Ordering;

use ciborium::Value;

/// Re-encode `cbor` canonically. Returns `None` if it is not valid CBOR, in
/// which case callers should forward the original bytes unchanged.
pub fn canonicalize(cbor: &[u8]) -> Option<Vec<u8>> {
    let mut value: Value = ciborium::from_reader(cbor).ok()?;
    sort_maps(&mut value);
    let mut out = Vec::with_capacity(cbor.len());
    ciborium::into_writer(&value, &mut out).ok()?;
    Some(out)
}

fn sort_maps(value: &mut Value) {
    match value {
        Value::Map(entries) => {
            for (_, v) in entries.iter_mut() {
                sort_maps(v);
            }
            let mut keyed: Vec<(Vec<u8>, (Value, Value))> = entries
                .drain(..)
                .map(|(k, v)| {
                    let mut enc = Vec::new();
                    ciborium::into_writer(&k, &mut enc).expect("encoding into a Vec cannot fail");
                    (enc, (k, v))
                })
                .collect();
            keyed.sort_by(|(a, _), (b, _)| canonical_key_order(a, b));
            entries.extend(keyed.into_iter().map(|(_, kv)| kv));
        }
        Value::Array(items) => items.iter_mut().for_each(sort_maps),
        Value::Tag(_, inner) => sort_maps(inner),
        _ => {}
    }
}

/// CTAP2 canonical ordering of two encoded keys.
fn canonical_key_order(a: &[u8], b: &[u8]) -> Ordering {
    let major = |k: &[u8]| k.first().map_or(0, |b| b >> 5);
    major(a)
        .cmp(&major(b))
        .then(a.len().cmp(&b.len()))
        .then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn encode(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    #[test]
    fn firefox_get_assertion_options_are_reordered() {
        let request = Value::Map(vec![
            (Value::Integer(1.into()), text("webauthn.io")),
            (Value::Integer(2.into()), Value::Bytes(vec![0xAB; 32])),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (text("type"), text("public-key")),
                    (text("id"), Value::Bytes(vec![1, 2, 3])),
                ])]),
            ),
            (
                Value::Integer(5.into()),
                Value::Map(vec![
                    (text("uv"), Value::Bool(true)),
                    (text("up"), Value::Bool(true)),
                ]),
            ),
        ]);
        let out = canonicalize(&encode(&request)).unwrap();
        let Value::Map(entries) = ciborium::from_reader::<Value, _>(out.as_slice()).unwrap() else {
            panic!("map")
        };
        let Value::Map(options) = &entries[3].1 else {
            panic!("options")
        };
        assert_eq!(options[0].0, text("up"));
        assert_eq!(options[1].0, text("uv"));
        let Value::Array(allow) = &entries[2].1 else {
            panic!("allowList")
        };
        let Value::Map(desc) = &allow[0] else {
            panic!("descriptor")
        };
        assert_eq!(desc[0].0, text("id"), "shorter key first");
        assert_eq!(desc[1].0, text("type"));
        // Values are byte-identical.
        assert_eq!(entries[1].1, Value::Bytes(vec![0xAB; 32]));
        assert_eq!(desc[0].1, Value::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn integer_keys_sort_numerically_and_before_text() {
        let m = Value::Map(vec![
            (text("a"), Value::Bool(true)),
            (Value::Integer(10.into()), Value::Bool(true)),
            (Value::Integer(2.into()), Value::Bool(true)),
            (Value::Integer((-1).into()), Value::Bool(true)),
        ]);
        let out = canonicalize(&encode(&m)).unwrap();
        let Value::Map(entries) = ciborium::from_reader::<Value, _>(out.as_slice()).unwrap() else {
            panic!("map")
        };
        let keys: Vec<&Value> = entries.iter().map(|(k, _)| k).collect();
        // Major type 0 (unsigned) before major type 1 (negative) before text.
        assert_eq!(
            keys,
            [
                &Value::Integer(2.into()),
                &Value::Integer(10.into()),
                &Value::Integer((-1).into()),
                &text("a")
            ]
        );
    }

    #[test]
    fn already_canonical_input_is_unchanged() {
        let m = Value::Map(vec![
            (Value::Integer(1.into()), text("x")),
            (Value::Integer(2.into()), Value::Bytes(vec![9; 4])),
            (
                Value::Integer(4.into()),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("uv"), Value::Bool(true)),
                ]),
            ),
        ]);
        let bytes = encode(&m);
        assert_eq!(canonicalize(&bytes).unwrap(), bytes);
    }

    #[test]
    fn invalid_cbor_yields_none() {
        assert_eq!(canonicalize(&[0xFF, 0x00]), None);
        assert_eq!(canonicalize(&[]), None);
    }
}
