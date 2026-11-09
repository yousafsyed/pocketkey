//! Fill-ins for makeCredential requests that strict phone authenticators
//! reject but the CTAP2 spec allows.
//!
//! Firefox's authenticator-rs sends the smallest legal entities: `rp` is
//! `{id}` and `user` is `{id, name}`, with no `rp.name` and no
//! `user.displayName`. CTAP 2.1 permits that, Android accepts it, but the
//! iPhone's hybrid authenticator drops the request without a reply. Firefox
//! also sends `hmac-secret: false` as an extension input, which is a request
//! for nothing and not a value the spec defines.
//!
//! [`complete_make_credential`] applies the smallest edits that make such a
//! request well-formed for every phone: `rp.name` defaults to `rp.id`,
//! `user.displayName` defaults to `user.name`, and extension entries whose
//! input is `false` are removed. These are display labels and no-ops; the
//! clientDataHash, ids, algorithms and options are never touched.

use ciborium::Value;

/// Edits applied to a decoded makeCredential map, for the debug log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Edits {
    pub rp_name_added: bool,
    pub display_name_added: bool,
    pub false_extensions_removed: usize,
}

impl Edits {
    pub fn is_empty(&self) -> bool {
        *self == Edits::default()
    }
}

/// Complete the `rp` (0x02) and `user` (0x03) entities and prune `false`
/// extension inputs (0x06) in place.
pub fn complete_make_credential(request: &mut Value) -> Edits {
    let mut edits = Edits::default();
    let Value::Map(entries) = request else {
        return edits;
    };
    for (key, value) in entries.iter_mut() {
        let Value::Integer(key) = key else { continue };
        match i128::from(*key) {
            0x02 => edits.rp_name_added = default_text_field(value, "name", "id"),
            0x03 => edits.display_name_added = default_text_field(value, "displayName", "name"),
            0x06 => {
                if let Value::Map(extensions) = value {
                    let before = extensions.len();
                    extensions.retain(|(_, v)| *v != Value::Bool(false));
                    edits.false_extensions_removed = before - extensions.len();
                }
            }
            _ => {}
        }
    }
    edits
}

/// If `entity` is a map with a text `source` field and no `field`, add
/// `field` with the same text. Returns whether anything was added.
fn default_text_field(entity: &mut Value, field: &str, source: &str) -> bool {
    let Value::Map(fields) = entity else {
        return false;
    };
    let has = |name: &str| fields.iter().any(|(k, _)| k.as_text() == Some(name));
    if has(field) {
        return false;
    }
    let Some(text) = fields
        .iter()
        .find(|(k, _)| k.as_text() == Some(source))
        .and_then(|(_, v)| v.as_text())
        .map(str::to_owned)
    else {
        return false;
    };
    fields.push((Value::Text(field.into()), Value::Text(text)));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_map(pairs: &[(&str, &str)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| (Value::Text((*k).into()), Value::Text((*v).into())))
                .collect(),
        )
    }

    fn field(map: &Value, key: i64) -> &Value {
        let Value::Map(entries) = map else {
            panic!("map")
        };
        &entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(key.into()))
            .expect("field present")
            .1
    }

    fn firefox_request() -> Value {
        Value::Map(vec![
            (Value::Integer(0x01.into()), Value::Bytes(vec![0xAA; 32])),
            (
                Value::Integer(0x02.into()),
                text_map(&[("id", "webauthn.io")]),
            ),
            (
                Value::Integer(0x03.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(b"uid".to_vec())),
                    (Value::Text("name".into()), Value::Text("yousaf".into())),
                ]),
            ),
            (
                Value::Integer(0x06.into()),
                Value::Map(vec![
                    (Value::Text("hmac-secret".into()), Value::Bool(false)),
                    (Value::Text("credProtect".into()), Value::Integer(2.into())),
                ]),
            ),
        ])
    }

    #[test]
    fn firefox_request_is_completed() {
        let mut req = firefox_request();
        let edits = complete_make_credential(&mut req);
        assert_eq!(
            edits,
            Edits {
                rp_name_added: true,
                display_name_added: true,
                false_extensions_removed: 1
            }
        );
        assert_eq!(
            field(&req, 2),
            &text_map(&[("id", "webauthn.io"), ("name", "webauthn.io")])
        );
        let Value::Map(user) = field(&req, 3) else {
            panic!()
        };
        assert_eq!(
            user[2],
            (
                Value::Text("displayName".into()),
                Value::Text("yousaf".into())
            )
        );
        assert_eq!(
            field(&req, 6),
            &Value::Map(vec![(
                Value::Text("credProtect".into()),
                Value::Integer(2.into())
            )])
        );
        assert_eq!(field(&req, 1), &Value::Bytes(vec![0xAA; 32]));
    }

    #[test]
    fn complete_request_is_left_alone() {
        let mut req = Value::Map(vec![
            (
                Value::Integer(0x02.into()),
                text_map(&[("id", "example.com"), ("name", "Example")]),
            ),
            (
                Value::Integer(0x03.into()),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1])),
                    (Value::Text("name".into()), Value::Text("a".into())),
                    (Value::Text("displayName".into()), Value::Text("A".into())),
                ]),
            ),
            (
                Value::Integer(0x06.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]),
            ),
        ]);
        let before = req.clone();
        assert!(complete_make_credential(&mut req).is_empty());
        assert_eq!(req, before);
    }

    #[test]
    fn user_without_name_gets_no_display_name() {
        let mut req = Value::Map(vec![(
            Value::Integer(0x03.into()),
            Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![1]))]),
        )]);
        let before = req.clone();
        assert!(complete_make_credential(&mut req).is_empty());
        assert_eq!(req, before);
    }

    #[test]
    fn non_map_is_ignored() {
        let mut v = Value::Integer(1.into());
        assert!(complete_make_credential(&mut v).is_empty());
    }
}
