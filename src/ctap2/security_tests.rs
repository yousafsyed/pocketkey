use super::*;
use sha2::{Digest, Sha256};

fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn int(i: i64) -> Value {
    Value::Integer(i.into())
}
fn descriptor(id: Vec<u8>) -> Value {
    Value::Map(vec![
        (text("id"), Value::Bytes(id)),
        (text("type"), text("public-key")),
    ])
}
fn probe(count: usize) -> Value {
    Value::Map(vec![
        (int(1), text("example.com")),
        (int(2), Value::Bytes(Sha256::digest(b"").to_vec())),
        (
            int(3),
            Value::Array((0..count).map(|i| descriptor(vec![i as u8])).collect()),
        ),
        (int(5), Value::Map(vec![(text("up"), Value::Bool(false))])),
    ])
}
fn frame(cmd: u8, value: &Value) -> Vec<u8> {
    let mut out = vec![cmd];
    ciborium::into_writer(value, &mut out).unwrap();
    out
}
fn set(value: &mut Value, key: i64, replacement: Value) {
    let Value::Map(entries) = value else { panic!() };
    if let Some((_, v)) = entries.iter_mut().find(|(k, _)| *k == int(key)) {
        *v = replacement;
    } else {
        entries.push((int(key), replacement));
    }
}
fn get(value: &Value, key: i64) -> &Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| *k == int(key))
        .unwrap()
        .1
}
fn create_from(probe: &Value) -> Value {
    Value::Map(vec![
        (int(1), Value::Bytes(vec![42; 32])),
        (
            int(2),
            Value::Map(vec![(text("id"), get(probe, 1).clone())]),
        ),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![1])),
                (text("name"), text("user")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(5), get(probe, 3).clone()),
    ])
}
fn assert_error(result: Disposition, code: u8) {
    assert_eq!(result, Disposition::Respond(vec![code]));
}

#[test]
fn malformed_cbor_never_forwarded_and_duplicate_keys_rejected_recursively() {
    let duplicate = Value::Map(vec![
        (text("up"), Value::Bool(false)),
        (text("up"), Value::Bool(true)),
    ]);
    let cases = vec![
        vec![],
        vec![0xff],
        vec![0xa0, 0xa0],
        vec![0xa0, 0x00],
        vec![0x80],
        // Same integer key using distinct CBOR representations.
        vec![0xa2, 0x01, 0x00, 0x18, 0x01, 0x01],
        frame(0, &Value::Map(vec![(int(7), duplicate.clone())]))[1..].to_vec(),
        frame(
            0,
            &Value::Map(vec![(int(5), Value::Array(vec![duplicate]))]),
        )[1..]
            .to_vec(),
        frame(0, &Value::Map(vec![(Value::Array(vec![int(1)]), int(2))]))[1..].to_vec(),
        frame(
            0,
            &Value::Map(vec![(int(1), Value::Tag(1, Box::new(text("tagged"))))]),
        )[1..]
            .to_vec(),
    ];
    for cbor in cases {
        assert!(canonical::decode_map(&cbor).is_none());
        assert!(canonical::canonicalize(&cbor).is_none());
        for cmd in [command::GET_ASSERTION, command::MAKE_CREDENTIAL] {
            let mut input = vec![cmd];
            input.extend(&cbor);
            assert_error(
                Ctap2::new().dispatch(&input),
                status::CTAP2_ERR_INVALID_CBOR,
            );
        }
    }
    let mut deeply_nested = vec![0xa1, 1];
    deeply_nested.extend(vec![0x81; 40]);
    deeply_nested.push(0);
    assert!(canonical::decode_map(&deeply_nested).is_none());
}

#[test]
fn unknown_false_extensions_are_preserved_and_iphone_defaults_survive() {
    let mut create = create_from(&probe(1));
    let extensions = Value::Map(vec![
        (text("hmac-secret"), Value::Bool(false)),
        (text("unknown-extension"), Value::Bool(false)),
        (text("credProtect"), int(2)),
    ]);
    set(&mut create, 6, extensions);
    let original_hash = get(&create, 1).clone();
    let original_exclusions = get(&create, 5).clone();
    let Disposition::Forward { frame, .. } =
        Ctap2::new().dispatch(&frame(command::MAKE_CREDENTIAL, &create))
    else {
        panic!()
    };
    let result = canonical::decode_map(&frame[1..]).unwrap();
    assert_eq!(get(&result, 1), &original_hash);
    assert_eq!(get(&result, 5), &original_exclusions);
    assert_eq!(
        get(&result, 6),
        &Value::Map(vec![
            (text("credProtect"), int(2)),
            (text("unknown-extension"), Value::Bool(false))
        ])
    );
    assert!(get(&result, 2)
        .as_map()
        .unwrap()
        .contains(&(text("name"), text("example.com"))));
    assert!(get(&result, 3)
        .as_map()
        .unwrap()
        .contains(&(text("displayName"), text("user"))));
}

#[test]
fn compatibility_growth_is_bounded_and_boundary_frames_work() {
    let mut create = create_from(&probe(1));
    set(
        &mut create,
        2,
        Value::Map(vec![(text("id"), text(&"a".repeat(1100)))]),
    );
    let input = frame(command::MAKE_CREDENTIAL, &create);
    assert!(input.len() < MAX_MSG_SIZE as usize);
    assert_error(
        Ctap2::new().dispatch(&input),
        status::CTAP2_ERR_REQUEST_TOO_LARGE,
    );
    // An exact-size frame without growing compatibility edits is accepted.
    let mut exact = Value::Map(vec![(int(99), Value::Bytes(Vec::new()))]);
    let length = (0..MAX_MSG_SIZE as usize)
        .find(|len| {
            set(&mut exact, 99, Value::Bytes(vec![0; *len]));
            frame(command::MAKE_CREDENTIAL, &exact).len() == MAX_MSG_SIZE as usize
        })
        .unwrap();
    set(&mut exact, 99, Value::Bytes(vec![0; length]));
    assert!(matches!(
        Ctap2::new().dispatch(&frame(command::MAKE_CREDENTIAL, &exact)),
        Disposition::Forward { .. }
    ));
    set(&mut exact, 99, Value::Bytes(vec![0; length + 1]));
    assert_error(
        Ctap2::new().dispatch(&frame(command::MAKE_CREDENTIAL, &exact)),
        status::CTAP2_ERR_REQUEST_TOO_LARGE,
    );
}

#[test]
fn silent_probe_requires_known_dummy_hash_no_uv_pin_or_extensions() {
    let mut invalid = Vec::new();
    for (key, value) in [
        (1, text("")),
        (1, int(5)),
        (1, text("rp\nforged")),
        (2, Value::Bytes(vec![0; 32])),
        (2, Value::Bytes(vec![0; 31])),
        (2, int(5)),
        (3, text("not-an-array")),
        (
            4,
            Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
        ),
        (
            5,
            Value::Map(vec![
                (text("up"), Value::Bool(false)),
                (text("uv"), Value::Bool(true)),
            ]),
        ),
        (5, Value::Map(vec![(text("up"), text("false"))])),
        (
            5,
            Value::Map(vec![
                (text("up"), Value::Bool(false)),
                (text("rk"), Value::Bool(false)),
            ]),
        ),
        (5, int(1)),
        (6, Value::Bytes(vec![0; 16])),
        (7, int(1)),
        (8, Value::Bool(false)),
    ] {
        let mut request = probe(1);
        set(&mut request, key, value);
        invalid.push(request);
    }
    for request in invalid {
        let bytes = frame(command::GET_ASSERTION, &request);
        assert!(matches!(
            preflight::inspect(&bytes[1..]),
            preflight::Probe::Error(_)
        ));
        // None of these requests may be forwarded or synthesized.
        assert!(
            matches!(Ctap2::new().dispatch(&bytes), Disposition::Respond(result) if result != [0])
        );
    }
    let mut known = probe(1);
    set(&mut known, 4, Value::Map(vec![]));
    set(
        &mut known,
        5,
        Value::Map(vec![
            (text("uv"), Value::Bool(false)),
            (text("up"), Value::Bool(false)),
        ]),
    );
    assert!(matches!(
        preflight::inspect(&frame(2, &known)[1..]),
        preflight::Probe::Assertions(_)
    ));
}

#[test]
fn descriptors_are_typed_and_not_invented_or_unbounded() {
    for descriptor in [
        Value::Null,
        Value::Map(vec![]),
        Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
        Value::Map(vec![(text("type"), text("public-key"))]),
        Value::Map(vec![
            (text("id"), text("secret")),
            (text("type"), text("public-key")),
        ]),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![1])),
            (text("type"), text("invalid")),
        ]),
        descriptor(vec![]),
        descriptor(vec![0; MAX_CREDENTIAL_ID_LENGTH as usize + 1]),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![1])),
            (text("type"), text("public-key")),
            (text("transports"), text("usb")),
        ]),
    ] {
        let mut request = probe(1);
        set(&mut request, 3, Value::Array(vec![descriptor]));
        assert!(matches!(
            preflight::inspect(&frame(2, &request)[1..]),
            preflight::Probe::Error(_)
        ));
    }
    let mut too_many = probe(0);
    set(
        &mut too_many,
        3,
        Value::Array(vec![Value::Null; MAX_CREDENTIAL_COUNT_IN_LIST as usize + 1]),
    );
    assert!(matches!(
        preflight::inspect(&frame(2, &too_many)[1..]),
        preflight::Probe::Error(_)
    ));
}

#[test]
fn channel_ownership_expiry_reset_and_malformed_next_are_enforced() {
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    let request = frame(2, &probe(3));
    assert!(
        matches!(ctap.dispatch_on_channel(1, &request, now), Disposition::Respond(r) if r[0] == 0)
    );
    assert_error(
        ctap.dispatch_on_channel(2, &[8], now),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
    ctap.dispatch_on_channel(2, &[4], now);
    assert!(matches!(ctap.dispatch_on_channel(1, &[8], now), Disposition::Respond(r) if r[0] == 0));
    assert_error(
        ctap.dispatch_on_channel(1, &[8], now + ASSERTION_SEQUENCE_TIMEOUT),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
    // Expiry drops secret-bearing continuations but cannot erase failed exclusions.
    assert_error(
        ctap.dispatch_on_channel(1, &[1, 0xa0], now + ASSERTION_SEQUENCE_TIMEOUT),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    ctap.reset_channel(1);
    ctap.dispatch_on_channel(1, &request, now);
    assert_error(
        ctap.dispatch_on_channel(1, &[8, 0xa0], now),
        status::CTAP1_ERR_INVALID_LENGTH,
    );
    assert_error(
        ctap.dispatch_on_channel(1, &[8], now),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
    ctap.reset_channel(1);
    ctap.dispatch_on_channel(1, &request, now);
    ctap.reset_channel(2);
    assert!(matches!(ctap.dispatch_on_channel(1, &[8], now), Disposition::Respond(r) if r[0] == 0));
    ctap.reset_channel(1);
    assert_error(
        ctap.dispatch_on_channel(1, &[8], now),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
}

#[test]
fn observed_chunking_failed_probes_and_dropped_exclusions_fail_closed() {
    let now = Instant::now();
    for bad_probe in [
        vec![2, 0xff],
        vec![2; MAX_MSG_SIZE as usize + 1],
        frame(2, &probe(0)),
    ] {
        let mut ctap = Ctap2::new();
        ctap.dispatch_on_channel(1, &bad_probe, now);
        assert_error(
            ctap.dispatch_on_channel(1, &[1, 0xa0], now),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
        ctap.dispatch_on_channel(1, &[4], now);
        assert_error(
            ctap.dispatch_on_channel(1, &[1, 0xa0], now),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
        ctap.reset_channel(1);
        if bad_probe.len() > MAX_MSG_SIZE as usize {
            assert_error(
                ctap.dispatch_on_channel(1, &[1, 0xa0], now),
                status::CTAP2_ERR_OPERATION_DENIED,
            );
            ctap.reinitialize_channel(1);
        }
        assert!(matches!(
            ctap.dispatch_on_channel(1, &[1, 0xa0], now),
            Disposition::Forward { .. }
        ));
    }
    let request = probe(3);
    let mut ctap = Ctap2::new();
    ctap.dispatch_on_channel(1, &frame(2, &request), now);
    assert_error(
        ctap.dispatch_on_channel(1, &frame(2, &probe(1)), now),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    assert_error(
        ctap.dispatch_on_channel(1, &frame(1, &create_from(&request)), now),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    ctap.reset_channel(1);
    ctap.dispatch_on_channel(1, &frame(2, &request), now);
    let mut shortened = create_from(&request);
    set(&mut shortened, 5, Value::Array(vec![descriptor(vec![0])]));
    assert_error(
        ctap.dispatch_on_channel(1, &frame(1, &shortened), now),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
}

#[test]
fn mozilla_count_chunking_cannot_drop_65th_tiny_excluded_id() {
    let response = get_info_response();
    let info = canonical::decode_map(&response[1..]).unwrap();
    let count = u64::try_from(get(&info, 7).as_integer().unwrap()).unwrap() as usize;
    assert!(count >= MAX_MSG_SIZE as usize);
    let id_length = u64::try_from(get(&info, 8).as_integer().unwrap()).unwrap() as usize;
    assert_eq!(id_length, 65535);
    let request = probe(65);
    let create = create_from(&request);
    assert!(frame(1, &create).len() <= MAX_MSG_SIZE as usize);
    assert!(frame(2, &request).len() <= MAX_MSG_SIZE as usize);
    let credentials = get(&request, 3).as_array().unwrap();
    // Model Mozilla's ID-length filter, chunks(count), then first-success break.
    let retained: Vec<_> = credentials
        .iter()
        .filter(|credential| descriptor_id(credential).len() <= id_length)
        .cloned()
        .collect();
    assert_eq!(&retained, credentials);
    assert_eq!(retained.chunks(64).next().unwrap().len(), 64);
    assert_eq!(retained.chunks(count).next().unwrap().len(), 65);
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    let Disposition::Respond(first) = ctap.dispatch_on_channel(1, &frame(2, &request), now) else {
        panic!()
    };
    let first = canonical::decode_map(&first[1..]).unwrap();
    assert_eq!(get(&first, 5), &int(65));
    let mut last = Vec::new();
    for _ in 1..65 {
        let Disposition::Respond(response) = ctap.dispatch_on_channel(1, &[8], now) else {
            panic!()
        };
        last = response;
    }
    let last = canonical::decode_map(&last[1..]).unwrap();
    assert_eq!(get(&last, 1), &descriptor(vec![64]));
    let Disposition::Forward { frame, .. } = ctap.dispatch_on_channel(1, &frame(1, &create), now)
    else {
        panic!()
    };
    let forwarded = canonical::decode_map(&frame[1..]).unwrap();
    assert_eq!(get(&forwarded, 5).as_array().unwrap(), credentials);
}

fn descriptor_id(descriptor: &Value) -> &[u8] {
    descriptor
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_text() == Some("id"))
        .unwrap()
        .1
        .as_bytes()
        .unwrap()
}

/// Model Chromium 142/current FilterAndBatchCredentialDescriptors' USB path,
/// including its coupled ID-length/count fallback (not just slice::chunks).
fn chromium_batches(info: &Value, credentials: &[Value]) -> Vec<Vec<Value>> {
    let limit = |key| {
        info.as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| *k == int(key))
            .map(|(_, v)| u64::try_from(v.as_integer().unwrap()).unwrap() as usize)
    };
    let max_id = limit(8).unwrap_or(0);
    let count = if max_id > 0 {
        limit(7).unwrap_or(1).max(1)
    } else {
        1
    };
    let mut batches = vec![Vec::new()];
    for credential in credentials {
        if max_id > 0 && descriptor_id(credential).len() > max_id {
            continue;
        }
        if batches.last().unwrap().len() == count {
            batches.push(Vec::new());
        }
        batches.last_mut().unwrap().push(credential.clone());
    }
    batches
}

#[test]
fn chromium_two_exclusions_stay_together_without_first_success_probe() {
    let info = canonical::decode_map(&get_info_response()[1..]).unwrap();
    let mut request = create_from(&probe(2));
    let exclusions = get(&request, 5).as_array().unwrap().clone();
    // The genuine phone credential is the SECOND ID. With the omitted hint,
    // Chromium would probe just the first and narrow on synthetic success.
    let mut omitted = info.clone();
    let Value::Map(fields) = &mut omitted else {
        panic!()
    };
    fields.retain(|(key, _)| *key != int(8));
    assert_eq!(
        chromium_batches(&omitted, &exclusions),
        vec![vec![exclusions[0].clone()], vec![exclusions[1].clone()]]
    );
    set(&mut omitted, 8, int(0));
    assert_eq!(chromium_batches(&omitted, &exclusions).len(), 2);

    let batches = chromium_batches(&info, &exclusions);
    assert_eq!(batches, vec![exclusions.clone()]);
    // MakeCredential() sends one batch directly, with no NextSilentRequest().
    set(&mut request, 5, Value::Array(batches[0].clone()));
    let Disposition::Forward { hint, frame } =
        Ctap2::new().dispatch(&frame(command::MAKE_CREDENTIAL, &request))
    else {
        panic!("Chrome must forward the full exclusion list")
    };
    assert_eq!(hint, Hint::MakeCredential);
    let forwarded = canonical::decode_map(&frame[1..]).unwrap();
    assert_eq!(get(&forwarded, 5), &Value::Array(exclusions));
}

#[test]
fn chromium_two_allowed_ids_use_real_hash_direct_request_not_synthetic() {
    let info = canonical::decode_map(&get_info_response()[1..]).unwrap();
    let mut request = probe(2);
    let allowed = get(&request, 3).as_array().unwrap().clone();
    let batches = chromium_batches(&info, &allowed);
    assert_eq!(batches, vec![allowed.clone()]);
    // Ordinary GetAssertion() takes the direct branch when there is one
    // batch and no U2F appId fallback or credential-specific PRF inputs.
    set(
        &mut request,
        2,
        Value::Bytes(Sha256::digest(b"real Chrome clientDataJSON").to_vec()),
    );
    set(&mut request, 3, Value::Array(batches[0].clone()));
    set(
        &mut request,
        5,
        Value::Map(vec![
            (text("up"), Value::Bool(true)),
            (text("uv"), Value::Bool(true)),
        ]),
    );
    let input = frame(command::GET_ASSERTION, &request);
    assert_eq!(preflight::inspect(&input[1..]), preflight::Probe::NotSilent);
    let Disposition::Forward {
        hint,
        frame: forwarded,
    } = Ctap2::new().dispatch(&input)
    else {
        panic!("Chrome login must be forwarded, not synthesized")
    };
    assert_eq!(hint, Hint::GetAssertion);
    let forwarded = canonical::decode_map(&forwarded[1..]).unwrap();
    assert_eq!(get(&forwarded, 2), get(&request, 2));
    assert_eq!(get(&forwarded, 3), &Value::Array(allowed));
    assert_eq!(get(&forwarded, 5), get(&request, 5));
    // Do not broaden the dummy-only workaround if a browser still forces
    // silent real-hash probes (for example credential-specific PRF flows).
    set(
        &mut request,
        5,
        Value::Map(vec![(text("up"), Value::Bool(false))]),
    );
    assert_error(
        Ctap2::new().dispatch(&frame(command::GET_ASSERTION, &request)),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
}

#[test]
fn chromium_retains_oversized_exclusions_then_byte_limit_fails_closed() {
    let info = canonical::decode_map(&get_info_response()[1..]).unwrap();
    assert_eq!(get(&info, 5), &int(2048));
    assert_eq!(get(&info, 8), &int(65535));
    // Cover both an oversized aggregate of individually small IDs and IDs
    // beyond the message bound, through the attested encoding maximum.
    for id_length in [1000, MAX_MSG_SIZE as usize + 1, u16::MAX as usize] {
        let exclusions = vec![
            descriptor(vec![1; id_length]),
            descriptor(vec![2; id_length]),
        ];
        let batches = chromium_batches(&info, &exclusions);
        assert_eq!(
            batches,
            vec![exclusions.clone()],
            "do not filter before rejection"
        );
        let mut request = create_from(&probe(0));
        set(&mut request, 5, Value::Array(batches[0].clone()));
        let input = frame(command::MAKE_CREDENTIAL, &request);
        assert!(input.len() > MAX_MSG_SIZE as usize);
        let mut ctap = Ctap2::new();
        assert_error(ctap.dispatch(&input), status::CTAP2_ERR_REQUEST_TOO_LARGE);
        // A client retrying with cleared exclusions must not turn this failure
        // into a successful creation on the same transaction/channel.
        assert_error(
            ctap.dispatch(&frame(command::MAKE_CREDENTIAL, &create_from(&probe(0)))),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
    }
    // The tempting 2048 hint would silently delete a valid-sized attested ID.
    let mut short_hint = info.clone();
    set(&mut short_hint, 8, int(MAX_MSG_SIZE as i64));
    let exclusions = vec![
        descriptor(vec![1]),
        descriptor(vec![2; MAX_MSG_SIZE as usize + 1]),
    ];
    assert_eq!(
        chromium_batches(&short_hint, &exclusions),
        vec![vec![exclusions[0].clone()]]
    );
    assert_eq!(chromium_batches(&info, &exclusions), vec![exclusions]);
}

#[test]
fn every_fitting_tiny_descriptor_list_is_below_advertised_count() {
    let count = MAX_CREDENTIAL_COUNT_IN_LIST as usize;
    let mut largest = 0;
    for n in 1..=count {
        let request = probe(n);
        let bytes = frame(2, &request);
        if bytes.len() > MAX_MSG_SIZE as usize {
            break;
        }
        largest = n;
        assert_eq!(
            get(&request, 3).as_array().unwrap().chunks(count).count(),
            1
        );
        let preflight::Probe::Assertions(responses) = preflight::inspect(&bytes[1..]) else {
            panic!()
        };
        assert_eq!(responses.len(), n);
        assert!(responses
            .iter()
            .all(|response| response.len() <= MAX_MSG_SIZE as usize));
    }
    assert!(
        largest > 64,
        "old advertised count split valid small-ID lists"
    );
    let mut request = probe(1);
    set(
        &mut request,
        3,
        Value::Array(vec![descriptor(vec![
            7;
            MAX_CREDENTIAL_ID_LENGTH as usize + 1
        ])]),
    );
    let mut ctap = Ctap2::new();
    assert_error(
        ctap.dispatch(&frame(2, &request)),
        status::CTAP2_ERR_REQUEST_TOO_LARGE,
    );
    assert_error(
        ctap.dispatch(&frame(1, &create_from(&probe(0)))),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
}

#[test]
fn local_commands_reject_extra_bytes_and_selection_requires_ui() {
    for command in [
        command::GET_INFO,
        command::GET_NEXT_ASSERTION,
        command::RESET,
        command::SELECTION,
    ] {
        assert_error(
            Ctap2::new().dispatch(&[command, 0xa0]),
            status::CTAP1_ERR_INVALID_LENGTH,
        );
    }
    assert_eq!(
        Ctap2::new().dispatch(&[command::SELECTION]),
        Disposition::Select
    );
}

#[test]
fn transport_rejection_survives_cancel_tail_expiry_and_unrelated_commands() {
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    ctap.dispatch_on_channel(1, &frame(command::GET_ASSERTION, &probe(3)), now);
    // Simulate RejectedCbor after a 7610..65535-byte header: no payload reaches
    // dispatch, but the client may ignore the HID error and clear exclusions.
    ctap.reject_channel(1);
    assert_error(
        ctap.dispatch_on_channel(1, &[command::GET_NEXT_ASSERTION], now),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
    for _ in 0..3 {
        // A wrapped continuation sequence 145 plus zero data resembles CANCEL.
        ctap.reset_channel(1);
        ctap.dispatch_on_channel(1, &[command::GET_INFO], now);
        ctap.dispatch_on_channel(1, &[command::SELECTION], now);
        assert_error(
            ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
        assert_error(
            ctap.dispatch_on_channel(1, &[command::GET_ASSERTION, 0xa0], now),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
    }
    let later = now + ASSERTION_SEQUENCE_TIMEOUT + Duration::from_secs(1);
    assert_error(
        ctap.dispatch_on_channel(1, &[], later),
        status::CTAP1_ERR_INVALID_LENGTH,
    );
    assert_error(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], later),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    // Malformed INIT must never call reinitialize_channel. Repeated rejection
    // and unrelated channels cannot remove the recorded failure either.
    ctap.reject_channel(1);
    ctap.reinitialize_channel(2);
    assert!(matches!(
        ctap.dispatch_on_channel(2, &[command::MAKE_CREDENTIAL, 0xa0], later),
        Disposition::Forward { .. }
    ));
    assert_error(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], later),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    ctap.reinitialize_channel(1);
    assert!(matches!(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], later),
        Disposition::Forward { .. }
    ));
}

#[test]
fn oversized_ctap_and_transformed_frames_require_reinitialization_not_cancel() {
    let now = Instant::now();
    for size in [MAX_MSG_SIZE as usize + 1, crate::ctaphid::MAX_PAYLOAD_LEN] {
        for command in [command::MAKE_CREDENTIAL, command::GET_ASSERTION] {
            let mut input = vec![0; size];
            input[0] = command;
            let mut ctap = Ctap2::new();
            assert_error(
                ctap.dispatch_on_channel(1, &input, now),
                status::CTAP2_ERR_REQUEST_TOO_LARGE,
            );
            ctap.reset_channel(1);
            assert_error(
                ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
                status::CTAP2_ERR_OPERATION_DENIED,
            );
            ctap.reinitialize_channel(1);
            assert!(matches!(
                ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
                Disposition::Forward { .. }
            ));
        }
    }
    let mut create = create_from(&probe(1));
    set(
        &mut create,
        2,
        Value::Map(vec![(text("id"), text(&"a".repeat(1100)))]),
    );
    let input = frame(command::MAKE_CREDENTIAL, &create);
    assert!(
        input.len() <= MAX_MSG_SIZE as usize,
        "only the compatibility expansion is oversized"
    );
    let mut ctap = Ctap2::new();
    assert_error(
        ctap.dispatch_on_channel(1, &input, now),
        status::CTAP2_ERR_REQUEST_TOO_LARGE,
    );
    ctap.reset_channel(1);
    assert_error(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    ctap.reinitialize_channel(1);
    assert!(matches!(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
        Disposition::Forward { .. }
    ));
}

#[test]
fn cancel_still_clears_normal_preflight_and_soft_failure() {
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    for input in [
        frame(command::GET_ASSERTION, &probe(3)),
        vec![command::GET_ASSERTION, 0xff],
    ] {
        ctap.dispatch_on_channel(1, &input, now);
        ctap.reset_channel(1);
        assert_error(
            ctap.dispatch_on_channel(1, &[command::GET_NEXT_ASSERTION], now),
            status::CTAP2_ERR_NOT_ALLOWED,
        );
        assert!(matches!(
            ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
            Disposition::Forward { .. }
        ));
    }
    // Valid reinitialization clears ordinary sequences too, not only hard ones.
    ctap.dispatch_on_channel(1, &frame(command::GET_ASSERTION, &probe(3)), now);
    ctap.reinitialize_channel(1);
    assert_error(
        ctap.dispatch_on_channel(1, &[command::GET_NEXT_ASSERTION], now),
        status::CTAP2_ERR_NOT_ALLOWED,
    );
}

#[test]
fn hard_latches_match_hid_capacity_and_overflow_cannot_be_forgotten() {
    assert_eq!(MAX_TRACKED_CHANNELS, crate::ctaphid::MAX_CHANNELS);
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    for cid in 1..=MAX_TRACKED_CHANNELS as u32 {
        ctap.reject_channel(cid);
        ctap.reset_channel(cid);
    }
    assert_eq!(ctap.channels.len(), MAX_TRACKED_CHANNELS);
    assert!(!ctap.rejection_overflow);
    for cid in 1..=MAX_TRACKED_CHANNELS as u32 {
        assert_error(
            ctap.dispatch_on_channel(cid, &[command::MAKE_CREDENTIAL, 0xa0], now),
            status::CTAP2_ERR_OPERATION_DENIED,
        );
    }
    // Reinitializing one known lifecycle frees exactly that slot and recovers it.
    ctap.reinitialize_channel(1);
    assert!(matches!(
        ctap.dispatch_on_channel(1, &[command::MAKE_CREDENTIAL, 0xa0], now),
        Disposition::Forward { .. }
    ));
    ctap.reject_channel(1);
    assert!(
        !ctap.rejection_overflow,
        "empty non-security states can be reused"
    );

    // An inconsistent caller exceeding HID's capacity must not lose the new
    // rejection and later accept it when some unrelated channel frees a slot.
    let overflow_cid = MAX_TRACKED_CHANNELS as u32 + 1;
    ctap.reject_channel(overflow_cid);
    assert_eq!(ctap.channels.len(), MAX_TRACKED_CHANNELS);
    assert!(ctap.rejection_overflow);
    ctap.reset_channel(overflow_cid);
    ctap.reinitialize_channel(1);
    ctap.reinitialize_channel(overflow_cid);
    for cid in [1, overflow_cid] {
        for command in [
            command::MAKE_CREDENTIAL,
            command::GET_ASSERTION,
            command::GET_NEXT_ASSERTION,
        ] {
            assert_error(
                ctap.dispatch_on_channel(cid, &[command], now),
                status::CTAP2_ERR_OPERATION_DENIED,
            );
        }
    }
}

#[test]
fn channel_failure_latches_are_bounded_not_silently_evicted() {
    let mut ctap = Ctap2::new();
    let now = Instant::now();
    for cid in 0..MAX_TRACKED_CHANNELS as u32 {
        ctap.dispatch_on_channel(cid, &[2, 0xff], now);
    }
    assert_error(
        ctap.dispatch_on_channel(1000, &[1, 0xa0], now),
        status::CTAP2_ERR_LIMIT_EXCEEDED,
    );
    assert_error(
        ctap.dispatch_on_channel(0, &[1, 0xa0], now),
        status::CTAP2_ERR_OPERATION_DENIED,
    );
    ctap.reset_channel(0);
    assert!(matches!(
        ctap.dispatch_on_channel(1000, &[1, 0xa0], now),
        Disposition::Forward { .. }
    ));
}
