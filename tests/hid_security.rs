//! Exercise the HID/CTAP lifecycle wiring without UHID, Bluetooth, or a phone.
//! These tests model received reports, not browser failures before transmission.

use std::time::{Duration, Instant};

use ciborium::Value;
use pocketkey::ctap2::{self, canonical, command, status, Ctap2, Disposition};
use pocketkey::ctaphid::{self, cmd, err, Event, Output, Report, RequestId, Transport};
use pocketkey::hybrid::Hint;
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Bridge {
    hid: Transport,
    ctap: Ctap2,
    decisions: Vec<(RequestId, u32, Disposition)>,
}

impl Bridge {
    /// Match the daemon's event routing. Forward/Select are recorded and left
    /// in flight; tests explicitly finish them, without running a transport/UI.
    fn route(&mut self, mut output: Output, now: Instant) -> Output {
        for event in &output.events {
            match event {
                Event::RejectedCbor { cid } => self.ctap.reject_channel(*cid),
                Event::Reinitialized { cid } => self.ctap.reinitialize_channel(*cid),
                Event::Reset { cid } => self.ctap.reset_channel(*cid),
                Event::Cancel { id } => output
                    .reports
                    .extend(self.hid.respond(*id, &[status::CTAP2_ERR_KEEPALIVE_CANCEL])),
                Event::CborRequest { id, cid, payload } => {
                    let decision = self.ctap.dispatch_on_channel(*cid, payload, now);
                    if let Disposition::Respond(bytes) = &decision {
                        output.reports.extend(self.hid.respond(*id, bytes));
                    }
                    self.decisions.push((*id, *cid, decision));
                }
            }
        }
        output
    }

    fn report(&mut self, report: &Report, now: Instant) -> Output {
        let output = self.hid.handle_report(report, now);
        self.route(output, now)
    }

    fn tick(&mut self, now: Instant) -> Output {
        let output = self.hid.tick_output(now);
        self.route(output, now)
    }

    fn reports(&mut self, reports: &[Report], now: Instant) -> Output {
        let mut all = Output::default();
        for report in reports {
            let output = self.report(report, now);
            all.reports.extend(output.reports);
            all.events.extend(output.events);
        }
        all
    }

    fn cbor(&mut self, cid: u32, frame: &[u8], now: Instant) -> Output {
        self.reports(&ctaphid::fragment(cid, cmd::CBOR, frame), now)
    }

    fn open_channel(&mut self, now: Instant) -> u32 {
        let output = self.reports(
            &ctaphid::fragment(ctaphid::BROADCAST_CID, cmd::INIT, &[11; 8]),
            now,
        );
        assert!(output.events.is_empty());
        assert_eq!(output.reports.len(), 1);
        let report = &output.reports[0];
        assert_eq!(report[4], cmd::INIT | 0x80);
        u32::from_be_bytes(report[15..19].try_into().unwrap())
    }

    fn resync(&mut self, cid: u32, now: Instant) {
        let output = self.reports(&ctaphid::fragment(cid, cmd::INIT, &[22; 8]), now);
        assert!(output.events.contains(&Event::Reinitialized { cid }));
        assert!(output
            .reports
            .iter()
            .any(|report| { report[..4] == cid.to_be_bytes() && report[4] == cmd::INIT | 0x80 }));
    }

    fn finish_forward(&mut self, cid: u32, hint: Hint) -> Vec<u8> {
        let (id, actual_cid, decision) = self.decisions.last().expect("CTAP dispatched");
        assert_eq!(*actual_cid, cid);
        let Disposition::Forward {
            hint: actual_hint,
            frame,
        } = decision
        else {
            panic!("expected forwarding, got {decision:?}");
        };
        assert_eq!(*actual_hint, hint);
        let frame = frame.clone();
        assert!(!self.hid.respond(*id, &[status::OK]).is_empty());
        frame
    }

    fn assert_denied_creation(&mut self, cid: u32, now: Instant) {
        let before = self.decisions.len();
        let output = self.cbor(cid, &creation(&[]), now);
        assert_eq!(self.decisions.len(), before + 1);
        assert_eq!(
            self.decisions.last().unwrap().2,
            Disposition::Respond(vec![status::CTAP2_ERR_OPERATION_DENIED])
        );
        assert_wire_status(&output, cid, cmd::CBOR, status::CTAP2_ERR_OPERATION_DENIED);
        assert!(self.hid.in_flight().is_none());
    }
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn descriptor(id: &[u8]) -> Value {
    Value::Map(vec![
        (text("id"), Value::Bytes(id.to_vec())),
        (text("type"), text("public-key")),
    ])
}

fn encode(command: u8, value: Value) -> Vec<u8> {
    let mut frame = vec![command];
    frame.extend(canonical::encode_canonical(value));
    frame
}

fn creation(ids: &[&[u8]]) -> Vec<u8> {
    encode(
        command::MAKE_CREDENTIAL,
        Value::Map(vec![
            (int(1), Value::Bytes(vec![42; 32])),
            (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
            (
                int(3),
                Value::Map(vec![
                    (text("id"), Value::Bytes(vec![7])),
                    (text("name"), text("alice")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (
                int(5),
                Value::Array(ids.iter().map(|id| descriptor(id)).collect()),
            ),
        ]),
    )
}

fn assertion(ids: &[&[u8]], silent: bool) -> Vec<u8> {
    encode(
        command::GET_ASSERTION,
        Value::Map(vec![
            (int(1), text("example.com")),
            (
                int(2),
                Value::Bytes(if silent {
                    Sha256::digest(b"").to_vec()
                } else {
                    vec![42; 32]
                }),
            ),
            (
                int(3),
                Value::Array(ids.iter().map(|id| descriptor(id)).collect()),
            ),
            (int(5), Value::Map(vec![(text("up"), Value::Bool(!silent))])),
        ]),
    )
}

/// Use a real assertion-shaped map with an opaque ID, not invalid padding.
fn assertion_of_length(length: usize) -> Vec<u8> {
    let overhead = assertion(&[&vec![7; length]], false).len() - length;
    let frame = assertion(&[&vec![7; length - overhead]], false);
    assert_eq!(frame.len(), length);
    frame
}

fn field(map: &Value, key: i64) -> &Value {
    &map.as_map()
        .unwrap()
        .iter()
        .find(|(candidate, _)| *candidate == int(key))
        .unwrap()
        .1
}

fn assert_wire_status(output: &Output, cid: u32, command: u8, status: u8) {
    assert!(
        output.reports.iter().any(|report| {
            report[..4] == cid.to_be_bytes()
                && report[4] == command | 0x80
                && report[5..7] == [0, 1]
                && report[7] == status
        }),
        "missing status 0x{status:02x} on HID command 0x{command:02x}"
    );
}

fn rejected(output: &Output, cid: u32) -> bool {
    output.events.contains(&Event::RejectedCbor { cid })
}

fn raw_header(cid: u32, command: u8, length: usize, data: &[u8]) -> Report {
    assert!(data.len() <= ctaphid::INIT_DATA_LEN);
    let mut report = [0; ctaphid::REPORT_SIZE];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = command | 0x80;
    report[5..7].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    report
}

/// Deliberately bypass fragment()'s safe size guard to model an oversized host
/// writer. Mozilla's writer emits sequence bytes verbatim past 127.
fn unchecked_host_reports(cid: u32, frame: &[u8]) -> Vec<Report> {
    let first = frame.len().min(ctaphid::INIT_DATA_LEN);
    let mut reports = vec![raw_header(cid, cmd::CBOR, frame.len(), &frame[..first])];
    for (sequence, chunk) in frame[first..].chunks(ctaphid::CONT_DATA_LEN).enumerate() {
        let mut report = [0; ctaphid::REPORT_SIZE];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = u8::try_from(sequence).unwrap();
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    reports
}

#[test]
fn received_message_boundaries_dispatch_or_latch_at_the_correct_layer() {
    assert_eq!(ctap2::MAX_MSG_SIZE, 2048);
    assert_eq!(ctaphid::MAX_PAYLOAD_LEN, 7609);
    for length in [2048, 2049, 7609, 7610] {
        let mut bridge = Bridge::default();
        let now = Instant::now();
        let cid = bridge.open_channel(now);
        let frame = assertion_of_length(length);
        let output = bridge.reports(&unchecked_host_reports(cid, &frame), now);
        match length {
            2048 => {
                assert!(!rejected(&output, cid));
                assert_eq!(bridge.decisions.len(), 1);
                assert_eq!(bridge.finish_forward(cid, Hint::GetAssertion), frame);
            }
            2049 | 7609 => {
                assert!(!rejected(&output, cid));
                assert_eq!(bridge.decisions.len(), 1);
                assert_wire_status(&output, cid, cmd::CBOR, status::CTAP2_ERR_REQUEST_TOO_LARGE);
                bridge.assert_denied_creation(cid, now);
            }
            7610 => {
                assert!(rejected(&output, cid));
                assert!(
                    bridge.decisions.is_empty(),
                    "HID must not dispatch oversized CBOR"
                );
                assert_wire_status(&output, cid, cmd::ERROR, err::INVALID_LEN);
                bridge.assert_denied_creation(cid, now);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn overlength_header_blocks_empty_exclusions_even_without_any_continuations() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    let output = bridge.report(
        &raw_header(
            cid,
            cmd::CBOR,
            ctaphid::MAX_PAYLOAD_LEN + 1,
            &[command::GET_ASSERTION],
        ),
        now,
    );
    assert!(rejected(&output, cid));
    assert_wire_status(&output, cid, cmd::ERROR, err::INVALID_LEN);
    assert!(bridge.decisions.is_empty());
    bridge.assert_denied_creation(cid, now);
    // Unrelated local commands and elapsed time must not evict a hard latch.
    bridge.cbor(cid, &[command::GET_INFO], now);
    bridge.assert_denied_creation(cid, now + ctap2::ASSERTION_SEQUENCE_TIMEOUT);
}

#[test]
fn bad_partial_cbor_sequence_blocks_empty_exclusions() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    let mut reports = ctaphid::fragment(cid, cmd::CBOR, &assertion_of_length(2048));
    assert!(bridge.report(&reports[0], now).events.is_empty());
    reports[1][4] = 1; // The first continuation must be sequence zero.
    let output = bridge.report(&reports[1], now);
    assert!(rejected(&output, cid));
    assert_wire_status(&output, cid, cmd::ERROR, err::INVALID_SEQ);
    assert!(bridge.decisions.is_empty());
    bridge.assert_denied_creation(cid, now);
}

#[test]
fn replacing_partial_cbor_with_another_message_latches_the_abandoned_request() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    let reports = ctaphid::fragment(cid, cmd::CBOR, &assertion_of_length(2048));
    bridge.report(&reports[0], now);
    let output = bridge.reports(&ctaphid::fragment(cid, cmd::PING, b"replacement"), now);
    assert!(rejected(&output, cid));
    assert_wire_status(&output, cid, cmd::ERROR, err::INVALID_SEQ);
    bridge.assert_denied_creation(cid, now);
}

#[test]
fn periodic_and_report_driven_reassembly_timeouts_both_latch_before_dispatch() {
    for periodic in [false, true] {
        let mut bridge = Bridge::default();
        let now = Instant::now();
        let cid = bridge.open_channel(now);
        let reports = ctaphid::fragment(cid, cmd::CBOR, &assertion_of_length(2048));
        bridge.report(&reports[0], now);
        let expired = now + ctaphid::REASSEMBLY_TIMEOUT;
        if periodic {
            let output = bridge.tick(expired);
            assert!(rejected(&output, cid));
            assert_wire_status(&output, cid, cmd::ERROR, err::MSG_TIMEOUT);
            assert!(
                bridge.tick(expired).events.is_empty(),
                "expiry is emitted only once"
            );
            bridge.assert_denied_creation(cid, expired);
        } else {
            // No timer tick: the next request itself expires the old assembly.
            // Its Output may contain both RejectedCbor and CborRequest; order
            // must latch the failure before dispatching the new registration.
            let output = bridge.cbor(cid, &creation(&[]), expired);
            assert!(rejected(&output, cid));
            assert_wire_status(&output, cid, cmd::ERROR, err::MSG_TIMEOUT);
            assert_wire_status(&output, cid, cmd::CBOR, status::CTAP2_ERR_OPERATION_DENIED);
            assert_eq!(bridge.decisions.len(), 1);
            assert!(matches!(bridge.decisions[0].2, Disposition::Respond(_)));
        }
    }
}

#[test]
fn absolute_reassembly_deadline_also_latches_a_slow_partial_probe() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    let reports = ctaphid::fragment(cid, cmd::CBOR, &assertion_of_length(2048));
    bridge.report(&reports[0], now);
    let gap = ctaphid::REASSEMBLY_TIMEOUT / 2;
    let mut last = now;
    for (index, report) in reports.iter().enumerate().skip(1) {
        let next = now + gap * index as u32;
        if next >= now + ctaphid::REASSEMBLY_MAX_DURATION {
            break;
        }
        assert!(bridge.report(report, next).events.is_empty());
        last = next;
    }
    let expired = now + ctaphid::REASSEMBLY_MAX_DURATION;
    assert!(expired.duration_since(last) < ctaphid::REASSEMBLY_TIMEOUT);
    let output = bridge.tick(expired);
    assert!(rejected(&output, cid));
    assert_wire_status(&output, cid, cmd::ERROR, err::MSG_TIMEOUT);
    bridge.assert_denied_creation(cid, expired);
}

#[test]
fn oversized_zero_tails_through_sequence_145_cannot_cancel_away_the_latch() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    let mut frame = vec![0; ctaphid::INIT_DATA_LEN + 146 * ctaphid::CONT_DATA_LEN];
    frame[0] = command::GET_ASSERTION;
    let reports = unchecked_host_reports(cid, &frame);
    assert_eq!(reports.last().unwrap()[4], cmd::CANCEL | 0x80);
    assert_eq!(&reports.last().unwrap()[5..7], &[0, 0]);
    let output = bridge.reports(&reports, now);
    assert!(rejected(&output, cid));
    assert!(
        output.events.contains(&Event::Reset { cid }),
        "sequence 145 resembles CANCEL"
    );
    assert!(!output.events.contains(&Event::Reinitialized { cid }));
    assert!(bridge.decisions.is_empty());
    bridge.assert_denied_creation(cid, now);
    bridge.reports(&ctaphid::fragment(cid, cmd::CANCEL, &[]), now);
    bridge.assert_denied_creation(cid, now);
}

#[test]
fn explicit_init_restores_chrome_operations_and_firefox_preflight() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let cid = bridge.open_channel(now);
    bridge.report(
        &raw_header(cid, cmd::CBOR, 7610, &[command::GET_ASSERTION]),
        now,
    );
    bridge.assert_denied_creation(cid, now);
    let malformed = bridge.reports(&ctaphid::fragment(cid, cmd::INIT, &[0; 7]), now);
    assert!(!malformed.events.contains(&Event::Reinitialized { cid }));
    bridge.assert_denied_creation(cid, now);
    bridge.resync(cid, now);

    // Positive maxCredentialIdLength makes Chromium honor the list count.
    bridge.cbor(cid, &[command::GET_INFO], now);
    let Disposition::Respond(info) = &bridge.decisions.last().unwrap().2 else {
        panic!("getInfo must be local");
    };
    let info = canonical::decode_map(&info[1..]).unwrap();
    let id_limit = i128::from(field(&info, 8).as_integer().unwrap());
    assert_eq!(id_limit, 65535);
    let chromium_count = if id_limit > 0 {
        i128::from(field(&info, 7).as_integer().unwrap()).max(1)
    } else {
        1
    };
    assert!(chromium_count >= 2048);
    let ids: &[&[u8]] = &[&[1], &[2]];
    let descriptors = Value::Array(ids.iter().map(|id| descriptor(id)).collect());
    bridge.cbor(cid, &creation(ids), now);
    let forwarded = bridge.finish_forward(cid, Hint::MakeCredential);
    let created = canonical::decode_map(&forwarded[1..]).unwrap();
    assert_eq!(field(&created, 5), &descriptors);
    assert!(field(&created, 2)
        .as_map()
        .unwrap()
        .contains(&(text("name"), text("example.com"))));
    assert!(field(&created, 3)
        .as_map()
        .unwrap()
        .contains(&(text("displayName"), text("alice"))));
    let normal = assertion(ids, false);
    bridge.cbor(cid, &normal, now);
    assert_eq!(bridge.finish_forward(cid, Hint::GetAssertion), normal);

    // Firefox gets both synthetic descriptors, then forwards both exclusions.
    bridge.cbor(cid, &assertion(ids, true), now);
    let Disposition::Respond(first) = &bridge.decisions.last().unwrap().2 else {
        panic!("Firefox silent probe must be local");
    };
    assert_eq!(first[0], status::OK);
    let first = canonical::decode_map(&first[1..]).unwrap();
    assert_eq!(field(&first, 5), &int(2));
    assert_eq!(field(&first, 1), &descriptor(ids[0]));
    bridge.cbor(cid, &[command::GET_NEXT_ASSERTION], now);
    let Disposition::Respond(next) = &bridge.decisions.last().unwrap().2 else {
        panic!("continuation must be local");
    };
    assert_eq!(next[0], status::OK);
    assert_eq!(
        field(&canonical::decode_map(&next[1..]).unwrap(), 1),
        &descriptor(ids[1])
    );
    bridge.cbor(cid, &creation(ids), now);
    let forwarded = bridge.finish_forward(cid, Hint::MakeCredential);
    assert_eq!(
        field(&canonical::decode_map(&forwarded[1..]).unwrap(), 5),
        &descriptors
    );
    bridge.cbor(cid, &assertion(ids, true), now);
    bridge.cbor(cid, &[command::GET_NEXT_ASSERTION], now);
    bridge.cbor(cid, &normal, now);
    assert_eq!(bridge.finish_forward(cid, Hint::GetAssertion), normal);
}

#[test]
fn other_channel_rejection_is_isolated_and_ping_failures_do_not_poison_cbor() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let good = bridge.open_channel(now);
    let bad = bridge.open_channel(now);
    let output = bridge.report(&raw_header(bad, cmd::CBOR, 7610, &[2]), now);
    assert!(rejected(&output, bad));
    assert!(!rejected(&output, good));
    bridge.assert_denied_creation(bad, now);
    let output = bridge.report(&raw_header(good, cmd::PING, 7610, &[]), now);
    assert!(output.events.is_empty());
    assert_wire_status(&output, good, cmd::ERROR, err::INVALID_LEN);
    let mut ping = ctaphid::fragment(good, cmd::PING, &[0; 100]);
    bridge.report(&ping[0], now);
    ping[1][4] = 1;
    let output = bridge.report(&ping[1], now);
    assert!(output.events.is_empty());
    assert_wire_status(&output, good, cmd::ERROR, err::INVALID_SEQ);
    bridge.report(&ping[0], now);
    let expired = now + ctaphid::REASSEMBLY_TIMEOUT;
    assert!(bridge.tick(expired).events.is_empty());
    bridge.cbor(good, &creation(&[]), expired);
    bridge.finish_forward(good, Hint::MakeCredential);
    bridge.assert_denied_creation(bad, expired);
}

#[test]
fn malformed_and_busy_traffic_leave_an_intact_request_and_retry_usable() {
    let mut bridge = Bridge::default();
    let now = Instant::now();
    let owner = bridge.open_channel(now);
    let other = bridge.open_channel(now);
    let normal = assertion(&[&[1]], false);
    let reports = ctaphid::fragment(owner, cmd::CBOR, &normal);
    assert!(reports.len() > 1);
    bridge.report(&reports[0], now);
    // Neither a malformed same-channel INIT nor an oversized foreign CBOR
    // consumes the accepted partial request or installs a rejection latch.
    let malformed = bridge.reports(&ctaphid::fragment(owner, cmd::INIT, &[0; 7]), now);
    assert!(malformed.events.is_empty());
    let oversized = bridge.report(&raw_header(other, cmd::CBOR, 7610, &[2]), now);
    assert!(oversized.events.is_empty());
    let busy = bridge.cbor(other, &creation(&[]), now);
    assert!(busy.events.is_empty());
    assert_wire_status(&busy, other, cmd::ERROR, err::CHANNEL_BUSY);
    bridge.reports(&reports[1..], now);
    let active = bridge
        .hid
        .in_flight()
        .expect("normal assertion is in flight");
    let busy = bridge.cbor(other, &creation(&[]), now);
    assert!(busy.events.is_empty());
    assert_wire_status(&busy, other, cmd::ERROR, err::CHANNEL_BUSY);
    for cid in [owner, other] {
        let malformed = bridge.report(&raw_header(cid, cmd::CBOR, 7610, &[2]), now);
        assert!(malformed.events.is_empty());
        assert_eq!(bridge.hid.in_flight(), Some(active));
    }
    assert_eq!(bridge.finish_forward(owner, Hint::GetAssertion), normal);
    let retry = now + Duration::from_millis(100);
    bridge.cbor(other, &creation(&[]), retry);
    bridge.finish_forward(other, Hint::MakeCredential);
    bridge.cbor(owner, &creation(&[]), retry);
    bridge.finish_forward(owner, Hint::MakeCredential);
}
