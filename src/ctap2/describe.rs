//! Allowlisted, typed CTAP diagnostics. No level (including TRACE) logs raw
//! CBOR, dynamic map keys, strings, byte values or decoder error text.
//!
//! Responses deliberately use operation-independent metadata only: e.g. fields
//! 5/6 are counts/flags for getAssertion but can contain secrets for
//! makeCredential. They must never be formatted as generic `Value`s.

use ciborium::Value;

use super::canonical;

fn field(map: &Value, key: i64) -> Option<&Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| *k == Value::Integer(key.into()))
        .map(|(_, v)| v)
}

fn array_len(value: Option<&Value>) -> Option<usize> {
    value.and_then(Value::as_array).map(Vec::len)
}

fn map_len(value: Option<&Value>) -> Option<usize> {
    value.and_then(Value::as_map).map(Vec::len)
}

fn option(map: Option<&Value>, name: &str) -> Option<bool> {
    map?.as_map()?
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))?
        .1
        .as_bool()
}

pub fn log_make_credential_request(cbor: &[u8]) {
    log_request(cbor, true);
}

/// Retains the original public API, but never dumps a frame, even at TRACE.
pub fn trace_get_assertion_request(cbor: &[u8]) {
    log_request(cbor, false);
}

fn log_request(cbor: &[u8], make_credential: bool) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let Some(map) = canonical::decode_map(cbor) else {
        tracing::debug!(len = cbor.len(), "request is not a valid CTAP map");
        return;
    };
    let (hash, list, extensions, options, pin) = if make_credential {
        (1, 5, 6, 7, 8)
    } else {
        (2, 3, 4, 5, 6)
    };
    tracing::debug!(
        make_credential,
        len = cbor.len(),
        fields = map_len(Some(&map)),
        client_data_hash_len = field(&map, hash).and_then(|v| v.as_bytes()).map(Vec::len),
        credential_list_len = array_len(field(&map, list)),
        extension_count = map_len(field(&map, extensions)),
        option_count = map_len(field(&map, options)),
        up = option(field(&map, options), "up"),
        uv = option(field(&map, options), "uv"),
        rk = option(field(&map, options), "rk"),
        has_pin_uv_auth = field(&map, pin).is_some(),
        "CTAP request metadata"
    );
}

/// Log only operation-independent metadata for `status ++ cbor`.
/// In particular, do not interpret or log response fields 5/6 without knowing
/// the operation: these may be largeBlobKey and unsigned extension outputs.
pub fn log_response(frame: &[u8]) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let Some((&status, cbor)) = frame.split_first() else {
        return;
    };
    let map = canonical::decode_map(cbor);
    tracing::debug!(
        status,
        len = frame.len(),
        valid_map = map.is_some(),
        fields = map_len(map.as_ref()),
        "phone response metadata"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const CAPTURE_CHILD: &str = "ctap2::describe::tests::trace_capture_isolated_child";
    const CAPTURE_COMPLETE: &str = "CTAP trace capture assertions completed";

    #[test]
    fn trace_capture_never_contains_request_or_response_secrets() {
        // tracing's callsite interest cache is process-global. With only one
        // registered subscriber, tracing-core can initialize a new callsite's
        // interest from the registering thread's default dispatcher. Other
        // tests invoking these loggers without our thread-local subscriber can
        // therefore cache `never` while a scoped capture is running.
        // Run only the capture body in a fresh process, not under a mutex that
        // unrelated tests do not acquire. No production logging changes needed.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CAPTURE_CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("start isolated CTAP trace capture test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "isolated CTAP trace capture failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        // A mistyped --exact filter runs zero tests and still exits successfully.
        // Require a marker emitted only after every capture assertion passed.
        assert!(
            stdout.contains(CAPTURE_COMPLETE),
            "capture child did not complete:\n{stdout}\n{stderr}"
        );
    }

    #[test]
    #[ignore = "run in its own process by trace_capture_never_contains_request_or_response_secrets"]
    fn trace_capture_isolated_child() {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        // Keep the repeated nested fixture below MAX_MSG_SIZE so it exercises
        // the metadata path (especially options), not only decode rejection.
        let secret = "SECRET_7c8125";
        let bytes = secret.as_bytes().to_vec();
        let opaque = Value::Map(vec![
            (Value::Text(secret.into()), Value::Text(secret.into())),
            (Value::Text("id".into()), Value::Bytes(bytes.clone())),
            (Value::Text("type".into()), Value::Text(secret.into())),
            (Value::Text("up".into()), Value::Text(secret.into())),
            (Value::Text("uv".into()), Value::Bytes(bytes.clone())),
            (
                Value::Text("transports".into()),
                Value::Array(vec![Value::Text(secret.into())]),
            ),
        ]);
        tracing::subscriber::set_global_default(subscriber)
            .expect("capture child owns its process-global subscriber");
        // Exercise each field with unexpected types, including options,
        // algorithms, unknown keys and the operation-dependent fields 5/6.
        for value in [
            opaque,
            Value::Bytes(bytes.clone()),
            Value::Text(secret.into()),
        ] {
            let mut entries: Vec<_> = (1..=12)
                .map(|key| (Value::Integer(key.into()), value.clone()))
                .collect();
            entries.push((Value::Text(secret.into()), value));
            let cbor = canonical::encode_canonical(Value::Map(entries));
            assert!(
                canonical::decode_map(&cbor).is_some(),
                "capture fixture must be a valid bounded map"
            );
            log_make_credential_request(&cbor);
            trace_get_assertion_request(&cbor);
            let mut frame = vec![0];
            frame.extend_from_slice(&cbor);
            log_response(&frame);
        }
        // Decoding failures must not leak error messages with input text.
        log_response(&[0, 0xff]);
        log_make_credential_request(&[0xff]);
        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            output.matches("CTAP request metadata").count(),
            6,
            "{output}"
        );
        assert_eq!(
            output.matches("phone response metadata").count(),
            4,
            "{output}"
        );
        assert_eq!(
            output.matches("make_credential=true").count(),
            3,
            "{output}"
        );
        assert_eq!(
            output.matches("make_credential=false").count(),
            3,
            "{output}"
        );
        assert_eq!(
            output.matches("request is not a valid CTAP map").count(),
            1,
            "{output}"
        );
        assert!(!output.contains(secret), "{output}");
        assert!(!output.contains(&hex::encode(&bytes)), "{output}");
        assert!(!output.contains(&format!("{bytes:?}")), "{output}");
        assert!(!output.contains("request_hex"), "{output}");
        println!("{CAPTURE_COMPLETE}");
    }
}
