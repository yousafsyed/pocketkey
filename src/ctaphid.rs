//! CTAPHID transport state machine (FIDO CTAP 2.2, "USB Human Interface
//! Device (USB HID)" section).
//!
//! This module is pure: it consumes 64-byte HID reports and produces 64-byte
//! HID reports plus [`Event`]s for the layer above. It never performs IO and
//! it does not own timers; the caller passes `Instant`s in and polls
//! [`Transport::tick`] periodically so reassembly timeouts can fire.
//!
//! Wire format recap:
//!
//! ```text
//! init packet:          CID(4) | CMD|0x80 (1) | BCNT (2, big endian) | data (57)
//! continuation packet:  CID(4) | SEQ (1, 0..=127)                     | data (59)
//! ```
//!
//! Exactly one CTAP request can be in flight at a time (the spec requires an
//! authenticator to serialise transactions). While one is in flight, requests
//! on any other channel are answered with `ERR_CHANNEL_BUSY`; the in-flight
//! channel may only send `CANCEL` (or `INIT`, which resynchronises and aborts).

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Size of every HID report on the wire.
pub const REPORT_SIZE: usize = 64;
/// Payload bytes carried by an init packet.
pub const INIT_DATA_LEN: usize = REPORT_SIZE - 7;
/// Payload bytes carried by a continuation packet.
pub const CONT_DATA_LEN: usize = REPORT_SIZE - 5;
/// Largest message the transport can carry: one init + 128 continuation packets.
pub const MAX_PAYLOAD_LEN: usize = INIT_DATA_LEN + 128 * CONT_DATA_LEN;
/// Channel id used by clients to request a channel of their own.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
/// How long we wait for the next continuation packet before giving up.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);
/// CTAPHID protocol version reported in the INIT response.
pub const PROTOCOL_VERSION: u8 = 2;

pub type Report = [u8; REPORT_SIZE];

/// CTAPHID command byte values (without the 0x80 init-packet marker).
#[allow(dead_code)]
pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const MSG: u8 = 0x03;
    pub const LOCK: u8 = 0x04;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3B;
    pub const ERROR: u8 = 0x3F;
}

/// Error codes carried in a `CTAPHID_ERROR` response.
#[allow(dead_code)]
pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const MSG_TIMEOUT: u8 = 0x05;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const LOCK_REQUIRED: u8 = 0x0A;
    pub const INVALID_CHANNEL: u8 = 0x0B;
    pub const OTHER: u8 = 0x7F;
}

/// Capability flags in the INIT response.
pub mod cap {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    pub const NMSG: u8 = 0x08;
}

/// Status byte of a `CTAPHID_KEEPALIVE` packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    /// The authenticator is still processing the request.
    Processing = 1,
    /// The authenticator is waiting for user presence / verification.
    UpNeeded = 2,
}

/// Identifies one CBOR request handed to the upper layer. A response carrying
/// a stale id (because the channel was reset by INIT in the meantime) is
/// silently dropped instead of being sent to a client that no longer expects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

/// Something the layer above has to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete `CTAPHID_CBOR` message arrived. `payload` is
    /// `cmd_byte ++ cbor`, exactly as the client sent it.
    CborRequest { id: RequestId, payload: Vec<u8> },
    /// The client asked to cancel the in-flight request. The upper layer must
    /// still call [`Transport::respond`] (normally with
    /// `CTAP2_ERR_KEEPALIVE_CANCEL`) to finish the transaction.
    Cancel { id: RequestId },
}

/// Result of feeding one report into the transport.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub reports: Vec<Report>,
    pub events: Vec<Event>,
}

impl Output {
    fn report(&mut self, r: Report) {
        self.reports.push(r);
    }
    fn error(&mut self, cid: u32, code: u8) {
        self.reports.extend(fragment(cid, cmd::ERROR, &[code]));
    }
}

/// A message currently being reassembled from several packets.
#[derive(Debug)]
struct Reassembly {
    cid: u32,
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
    last_packet_at: Instant,
}

/// The CBOR request currently being processed by the upper layer.
#[derive(Debug, Clone, Copy)]
struct InFlight {
    id: RequestId,
    cid: u32,
}

#[derive(Debug)]
pub struct Transport {
    channels: HashSet<u32>,
    next_cid: u32,
    reassembly: Option<Reassembly>,
    in_flight: Option<InFlight>,
    next_request_id: u64,
    reassembly_timeout: Duration,
    /// Major/minor/build bytes reported in the INIT response.
    version: [u8; 3],
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport {
    pub fn new() -> Self {
        Self {
            channels: HashSet::new(),
            next_cid: 1,
            reassembly: None,
            in_flight: None,
            next_request_id: 1,
            reassembly_timeout: REASSEMBLY_TIMEOUT,
            version: [0, 1, 0],
        }
    }

    /// Set the device version bytes (major, minor, build) reported by INIT.
    pub fn with_version(mut self, version: [u8; 3]) -> Self {
        self.version = version;
        self
    }

    /// Whether a CBOR request is currently being processed.
    #[allow(dead_code)]
    pub fn in_flight(&self) -> Option<RequestId> {
        self.in_flight.map(|f| f.id)
    }

    /// Feed one 64-byte report received from the host.
    pub fn handle_report(&mut self, report: &Report, now: Instant) -> Output {
        let mut out = Output::default();
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let marker = report[4];

        if marker & 0x80 != 0 {
            let command = marker & 0x7F;
            let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;
            self.handle_init_packet(cid, command, bcnt, &report[7..], now, &mut out);
        } else {
            self.handle_cont_packet(cid, marker, &report[5..], now, &mut out);
        }
        out
    }

    fn handle_init_packet(
        &mut self,
        cid: u32,
        command: u8,
        bcnt: usize,
        data: &[u8],
        now: Instant,
        out: &mut Output,
    ) {
        // CANCEL is special: it is never reassembled, and it is the one
        // command allowed on the in-flight channel. It has no response of its
        // own; the cancelled request answers with CTAP2_ERR_KEEPALIVE_CANCEL.
        if command == cmd::CANCEL {
            if self.reassembly.as_ref().is_some_and(|r| r.cid == cid) {
                self.reassembly = None;
            }
            if let Some(f) = self.in_flight.filter(|f| f.cid == cid) {
                out.events.push(Event::Cancel { id: f.id });
            }
            return;
        }

        // Channel validity.
        if cid == 0 || (cid == BROADCAST_CID && command != cmd::INIT) {
            out.error(cid, err::INVALID_CHANNEL);
            return;
        }
        if cid != BROADCAST_CID && !self.channels.contains(&cid) {
            out.error(cid, err::INVALID_CHANNEL);
            return;
        }

        // A request is being processed. Only INIT on the same channel may
        // interrupt it (resynchronisation); everything else is busy.
        if let Some(f) = self.in_flight {
            let resync = command == cmd::INIT && f.cid == cid;
            if !resync {
                out.error(cid, err::CHANNEL_BUSY);
                return;
            }
        }

        // A message is being reassembled.
        if let Some(r) = &self.reassembly {
            if r.cid != cid {
                // Another channel must wait.
                out.error(cid, err::CHANNEL_BUSY);
                return;
            }
            // Same channel: INIT resynchronises, any other init packet is a
            // protocol error (the client should have sent a continuation).
            self.reassembly = None;
            if command != cmd::INIT {
                out.error(cid, err::INVALID_SEQ);
                return;
            }
        }

        if bcnt > MAX_PAYLOAD_LEN {
            out.error(cid, err::INVALID_LEN);
            return;
        }

        if bcnt <= INIT_DATA_LEN {
            let payload = data[..bcnt].to_vec();
            self.dispatch(cid, command, payload, out);
        } else {
            self.reassembly = Some(Reassembly {
                cid,
                cmd: command,
                total: bcnt,
                buf: data.to_vec(),
                next_seq: 0,
                last_packet_at: now,
            });
        }
    }

    fn handle_cont_packet(
        &mut self,
        cid: u32,
        seq: u8,
        data: &[u8],
        now: Instant,
        out: &mut Output,
    ) {
        let Some(r) = self.reassembly.as_mut() else {
            // Spurious continuation packet: ignored per spec.
            return;
        };
        if r.cid != cid {
            // Continuation from a channel that is not reassembling: ignored.
            return;
        }
        if seq != r.next_seq {
            self.reassembly = None;
            out.error(cid, err::INVALID_SEQ);
            return;
        }
        r.next_seq = r.next_seq.wrapping_add(1);
        r.last_packet_at = now;
        let remaining = r.total - r.buf.len();
        r.buf.extend_from_slice(&data[..remaining.min(data.len())]);

        if r.buf.len() >= r.total {
            let r = self.reassembly.take().expect("checked above");
            self.dispatch(r.cid, r.cmd, r.buf, out);
        }
    }

    /// Act on a fully reassembled message.
    fn dispatch(&mut self, cid: u32, command: u8, payload: Vec<u8>, out: &mut Output) {
        match command {
            cmd::INIT => {
                if payload.len() != 8 {
                    out.error(cid, err::INVALID_LEN);
                    return;
                }
                let assigned = if cid == BROADCAST_CID {
                    self.allocate_cid()
                } else {
                    // Resync on an existing channel: abort whatever it was doing.
                    if let Some(f) = self.in_flight.filter(|f| f.cid == cid) {
                        out.events.push(Event::Cancel { id: f.id });
                        self.in_flight = None;
                    }
                    cid
                };
                let mut resp = Vec::with_capacity(17);
                resp.extend_from_slice(&payload); // nonce
                resp.extend_from_slice(&assigned.to_be_bytes());
                resp.push(PROTOCOL_VERSION);
                resp.extend_from_slice(&self.version);
                resp.push(cap::CBOR | cap::NMSG | cap::WINK);
                out.reports.extend(fragment(cid, cmd::INIT, &resp));
            }
            cmd::PING => out.reports.extend(fragment(cid, cmd::PING, &payload)),
            cmd::WINK => {
                if !payload.is_empty() {
                    out.error(cid, err::INVALID_LEN);
                    return;
                }
                out.report(fragment(cid, cmd::WINK, &[])[0]);
            }
            cmd::CBOR => {
                if payload.is_empty() {
                    out.error(cid, err::INVALID_LEN);
                    return;
                }
                let id = RequestId(self.next_request_id);
                self.next_request_id += 1;
                self.in_flight = Some(InFlight { id, cid });
                out.events.push(Event::CborRequest { id, payload });
            }
            // U2F/CTAP1 is not supported (NMSG capability set), LOCK is optional
            // and we do not implement it.
            cmd::MSG | cmd::LOCK => out.error(cid, err::INVALID_CMD),
            _ => out.error(cid, err::INVALID_CMD),
        }
    }

    fn allocate_cid(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if cid != 0 && cid != BROADCAST_CID && self.channels.insert(cid) {
                return cid;
            }
        }
    }

    /// Expire a stalled reassembly. Call this every ~100 ms.
    pub fn tick(&mut self, now: Instant) -> Vec<Report> {
        match &self.reassembly {
            Some(r) if now.duration_since(r.last_packet_at) >= self.reassembly_timeout => {
                let cid = r.cid;
                self.reassembly = None;
                fragment(cid, cmd::ERROR, &[err::MSG_TIMEOUT])
            }
            _ => Vec::new(),
        }
    }

    /// Finish the in-flight request with a `CTAPHID_CBOR` response whose
    /// payload is `status ++ cbor`. Returns nothing if `id` is stale.
    pub fn respond(&mut self, id: RequestId, payload: &[u8]) -> Vec<Report> {
        match self.in_flight {
            Some(f) if f.id == id => {
                self.in_flight = None;
                fragment(f.cid, cmd::CBOR, payload)
            }
            _ => Vec::new(),
        }
    }

    /// Build a keepalive for the in-flight request, if `id` is still current.
    pub fn keepalive(&self, id: RequestId, status: KeepaliveStatus) -> Option<Report> {
        match self.in_flight {
            Some(f) if f.id == id => Some(fragment(f.cid, cmd::KEEPALIVE, &[status as u8])[0]),
            _ => None,
        }
    }
}

/// Split `payload` into an init packet followed by continuation packets.
/// `payload` must be at most [`MAX_PAYLOAD_LEN`] bytes.
pub fn fragment(cid: u32, command: u8, payload: &[u8]) -> Vec<Report> {
    debug_assert!(payload.len() <= MAX_PAYLOAD_LEN);
    let mut reports =
        Vec::with_capacity(1 + payload.len().saturating_sub(INIT_DATA_LEN) / CONT_DATA_LEN);

    let mut init = [0u8; REPORT_SIZE];
    init[..4].copy_from_slice(&cid.to_be_bytes());
    init[4] = command | 0x80;
    init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(INIT_DATA_LEN);
    init[7..7 + first].copy_from_slice(&payload[..first]);
    reports.push(init);

    for (seq, chunk) in payload[first..].chunks(CONT_DATA_LEN).enumerate() {
        let mut cont = [0u8; REPORT_SIZE];
        cont[..4].copy_from_slice(&cid.to_be_bytes());
        cont[4] = seq as u8;
        cont[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(cont);
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn now() -> Instant {
        Instant::now()
    }

    /// Reassemble `reports` (as a client would) into (cid, cmd, payload).
    fn reassemble(reports: &[Report]) -> (u32, u8, Vec<u8>) {
        let init = &reports[0];
        let cid = u32::from_be_bytes([init[0], init[1], init[2], init[3]]);
        assert!(init[4] & 0x80 != 0, "first report must be an init packet");
        let cmd = init[4] & 0x7F;
        let total = u16::from_be_bytes([init[5], init[6]]) as usize;
        let mut payload = init[7..].to_vec();
        for (i, r) in reports[1..].iter().enumerate() {
            assert_eq!(u32::from_be_bytes([r[0], r[1], r[2], r[3]]), cid);
            assert_eq!(r[4] as usize, i, "sequence number");
            payload.extend_from_slice(&r[5..]);
        }
        payload.truncate(total);
        (cid, cmd, payload)
    }

    /// Feed all `reports` into `t`, collecting the output.
    fn feed(t: &mut Transport, reports: &[Report]) -> Output {
        let mut out = Output::default();
        for r in reports {
            let o = t.handle_report(r, now());
            out.reports.extend(o.reports);
            out.events.extend(o.events);
        }
        out
    }

    fn open_channel(t: &mut Transport) -> u32 {
        let out = feed(t, &fragment(BROADCAST_CID, cmd::INIT, &NONCE));
        assert!(out.events.is_empty());
        let (rcid, rcmd, payload) = reassemble(&out.reports);
        assert_eq!(
            rcid, BROADCAST_CID,
            "INIT response goes out on the broadcast CID"
        );
        assert_eq!(rcmd, cmd::INIT);
        assert_eq!(payload.len(), 17);
        assert_eq!(&payload[..8], &NONCE);
        assert_eq!(payload[12], PROTOCOL_VERSION);
        assert_eq!(payload[16] & cap::CBOR, cap::CBOR);
        assert_eq!(payload[16] & cap::NMSG, cap::NMSG);
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]])
    }

    fn error_code(out: &Output) -> Option<(u32, u8)> {
        let r = out.reports.last()?;
        if r[4] == cmd::ERROR | 0x80 {
            Some((u32::from_be_bytes([r[0], r[1], r[2], r[3]]), r[7]))
        } else {
            None
        }
    }

    #[test]
    fn fragment_round_trip_at_boundaries() {
        for len in [
            0usize,
            1,
            56,
            57,
            58,
            64,
            116,
            117,
            1000,
            2048,
            MAX_PAYLOAD_LEN,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let reports = fragment(0x1234_5678, cmd::CBOR, &payload);
            let expected_count = if len <= INIT_DATA_LEN {
                1
            } else {
                1 + (len - INIT_DATA_LEN).div_ceil(CONT_DATA_LEN)
            };
            assert_eq!(reports.len(), expected_count, "len {len}");
            let (cid, c, back) = reassemble(&reports);
            assert_eq!(cid, 0x1234_5678);
            assert_eq!(c, cmd::CBOR);
            assert_eq!(back, payload, "len {len}");
        }
    }

    #[test]
    fn max_payload_fits_in_128_continuations() {
        assert_eq!(MAX_PAYLOAD_LEN, 7609);
        assert_eq!(fragment(1, cmd::PING, &vec![0; MAX_PAYLOAD_LEN]).len(), 129);
    }

    #[test]
    fn init_allocates_distinct_channels() {
        let mut t = Transport::new();
        let a = open_channel(&mut t);
        let b = open_channel(&mut t);
        assert_ne!(a, 0);
        assert_ne!(a, BROADCAST_CID);
        assert_ne!(a, b);
    }

    #[test]
    fn init_requires_8_byte_nonce() {
        let mut t = Transport::new();
        let out = feed(&mut t, &fragment(BROADCAST_CID, cmd::INIT, &NONCE[..4]));
        assert_eq!(error_code(&out), Some((BROADCAST_CID, err::INVALID_LEN)));
    }

    #[test]
    fn init_on_existing_channel_keeps_cid() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::INIT, &NONCE));
        let (rcid, rcmd, payload) = reassemble(&out.reports);
        assert_eq!((rcid, rcmd), (cid, cmd::INIT));
        assert_eq!(&payload[8..12], &cid.to_be_bytes());
    }

    #[test]
    fn non_init_on_broadcast_is_invalid_channel() {
        let mut t = Transport::new();
        let out = feed(&mut t, &fragment(BROADCAST_CID, cmd::PING, b"hi"));
        assert_eq!(
            error_code(&out),
            Some((BROADCAST_CID, err::INVALID_CHANNEL))
        );
    }

    #[test]
    fn unknown_and_zero_cid_are_invalid_channel() {
        let mut t = Transport::new();
        let out = feed(&mut t, &fragment(0x42, cmd::PING, b"hi"));
        assert_eq!(error_code(&out), Some((0x42, err::INVALID_CHANNEL)));
        let out = feed(&mut t, &fragment(0, cmd::PING, b"hi"));
        assert_eq!(error_code(&out), Some((0, err::INVALID_CHANNEL)));
    }

    #[test]
    fn ping_echoes_multi_packet_payload() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let out = feed(&mut t, &fragment(cid, cmd::PING, &payload));
        assert!(out.events.is_empty());
        let (rcid, rcmd, back) = reassemble(&out.reports);
        assert_eq!((rcid, rcmd), (cid, cmd::PING));
        assert_eq!(back, payload);
    }

    #[test]
    fn wink_is_acknowledged_with_empty_wink() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::WINK, &[]));
        let (rcid, rcmd, back) = reassemble(&out.reports);
        assert_eq!((rcid, rcmd, back.len()), (cid, cmd::WINK, 0));
    }

    #[test]
    fn msg_and_unknown_commands_are_invalid_cmd() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::MSG, &[0, 1, 0, 0]));
        assert_eq!(error_code(&out), Some((cid, err::INVALID_CMD)));
        let out = feed(&mut t, &fragment(cid, 0x55, &[]));
        assert_eq!(error_code(&out), Some((cid, err::INVALID_CMD)));
    }

    #[test]
    fn cbor_request_and_response_round_trip() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let req: Vec<u8> = std::iter::once(0x02)
            .chain((0..300u32).map(|i| i as u8))
            .collect();
        let out = feed(&mut t, &fragment(cid, cmd::CBOR, &req));
        assert!(
            out.reports.is_empty(),
            "no reports until the upper layer responds"
        );
        let [Event::CborRequest { id, payload }] = out.events.as_slice() else {
            panic!("expected one CborRequest, got {:?}", out.events);
        };
        assert_eq!(payload, &req);
        assert_eq!(t.in_flight(), Some(*id));

        let ka = t
            .keepalive(*id, KeepaliveStatus::UpNeeded)
            .expect("in flight");
        assert_eq!(ka[4], cmd::KEEPALIVE | 0x80);
        assert_eq!(ka[7], 2);

        let resp: Vec<u8> = std::iter::once(0x00)
            .chain((0..500u32).map(|i| i as u8))
            .collect();
        let reports = t.respond(*id, &resp);
        let (rcid, rcmd, back) = reassemble(&reports);
        assert_eq!((rcid, rcmd), (cid, cmd::CBOR));
        assert_eq!(back, resp);
        assert_eq!(t.in_flight(), None);

        // A second respond with the same id is stale and produces nothing.
        assert!(t.respond(*id, &resp).is_empty());
        assert!(t.keepalive(*id, KeepaliveStatus::Processing).is_none());
    }

    #[test]
    fn empty_cbor_is_invalid_len() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::CBOR, &[]));
        assert_eq!(error_code(&out), Some((cid, err::INVALID_LEN)));
        assert!(out.events.is_empty());
    }

    #[test]
    fn other_channel_is_busy_while_request_in_flight() {
        let mut t = Transport::new();
        let a = open_channel(&mut t);
        let b = open_channel(&mut t);
        let out = feed(&mut t, &fragment(a, cmd::CBOR, &[0x04]));
        let Event::CborRequest { id, .. } = out.events[0] else {
            panic!()
        };

        let out = feed(&mut t, &fragment(b, cmd::CBOR, &[0x04]));
        assert_eq!(error_code(&out), Some((b, err::CHANNEL_BUSY)));
        assert!(out.events.is_empty());
        // Even a PING or a broadcast INIT is refused while busy.
        let out = feed(&mut t, &fragment(b, cmd::PING, b"x"));
        assert_eq!(error_code(&out), Some((b, err::CHANNEL_BUSY)));
        let out = feed(&mut t, &fragment(BROADCAST_CID, cmd::INIT, &NONCE));
        assert_eq!(error_code(&out), Some((BROADCAST_CID, err::CHANNEL_BUSY)));
        // The same channel sending another request is also busy.
        let out = feed(&mut t, &fragment(a, cmd::CBOR, &[0x04]));
        assert_eq!(error_code(&out), Some((a, err::CHANNEL_BUSY)));

        // After the response, b can proceed.
        t.respond(id, &[0x00]);
        let out = feed(&mut t, &fragment(b, cmd::CBOR, &[0x04]));
        assert!(matches!(out.events.as_slice(), [Event::CborRequest { .. }]));
    }

    #[test]
    fn cancel_mid_request_emits_cancel_once_and_only_for_that_channel() {
        let mut t = Transport::new();
        let a = open_channel(&mut t);
        let b = open_channel(&mut t);
        let out = feed(&mut t, &fragment(a, cmd::CBOR, &[0x02, 0xA0]));
        let Event::CborRequest { id, .. } = out.events[0] else {
            panic!()
        };

        // Cancel from another channel is ignored.
        let out = feed(&mut t, &fragment(b, cmd::CANCEL, &[]));
        assert!(out.reports.is_empty() && out.events.is_empty());

        let out = feed(&mut t, &fragment(a, cmd::CANCEL, &[]));
        assert!(out.reports.is_empty(), "CANCEL has no response of its own");
        assert_eq!(out.events, vec![Event::Cancel { id }]);

        // The request is still in flight until the upper layer responds.
        assert_eq!(t.in_flight(), Some(id));
        let reports = t.respond(id, &[0x2D]);
        let (_, rcmd, back) = reassemble(&reports);
        assert_eq!((rcmd, back), (cmd::CBOR, vec![0x2D]));
    }

    #[test]
    fn cancel_with_nothing_in_flight_is_ignored() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::CANCEL, &[]));
        assert_eq!(out, Output::default());
    }

    #[test]
    fn init_on_in_flight_channel_aborts_request_and_drops_late_response() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x02, 0xA0]));
        let Event::CborRequest { id, .. } = out.events[0] else {
            panic!()
        };

        let out = feed(&mut t, &fragment(cid, cmd::INIT, &NONCE));
        assert_eq!(out.events, vec![Event::Cancel { id }]);
        let (_, rcmd, _) = reassemble(&out.reports);
        assert_eq!(rcmd, cmd::INIT);
        assert_eq!(t.in_flight(), None);
        // The late response must not reach the client.
        assert!(t.respond(id, &[0x2D]).is_empty());
    }

    #[test]
    fn bad_sequence_number_is_invalid_seq_and_drops_message() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let mut reports = fragment(cid, cmd::PING, &[7u8; 200]);
        assert!(reports.len() >= 3);
        reports[2][4] = 5; // should be 1
        let out = feed(&mut t, &reports[..3]);
        assert_eq!(error_code(&out), Some((cid, err::INVALID_SEQ)));
        // The rest of the message is now spurious and ignored.
        let out = feed(&mut t, &reports[3..]);
        assert_eq!(out, Output::default());
        // The channel is usable again.
        let out = feed(&mut t, &fragment(cid, cmd::PING, b"ok"));
        assert_eq!(reassemble(&out.reports).2, b"ok");
    }

    #[test]
    fn spurious_continuation_is_ignored() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let mut cont = [0u8; REPORT_SIZE];
        cont[..4].copy_from_slice(&cid.to_be_bytes());
        cont[4] = 0;
        assert_eq!(t.handle_report(&cont, now()), Output::default());
    }

    #[test]
    fn init_packet_while_reassembling_same_channel_is_invalid_seq() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let reports = fragment(cid, cmd::PING, &[1u8; 200]);
        let out = feed(&mut t, &reports[..1]);
        assert_eq!(out, Output::default());
        let out = feed(&mut t, &fragment(cid, cmd::PING, b"x"));
        assert_eq!(error_code(&out), Some((cid, err::INVALID_SEQ)));
    }

    #[test]
    fn init_resyncs_a_stuck_reassembly() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let reports = fragment(cid, cmd::PING, &[1u8; 200]);
        feed(&mut t, &reports[..1]);
        let out = feed(&mut t, &fragment(cid, cmd::INIT, &NONCE));
        assert_eq!(reassemble(&out.reports).1, cmd::INIT);
        let out = feed(&mut t, &fragment(cid, cmd::PING, b"after"));
        assert_eq!(reassemble(&out.reports).2, b"after");
    }

    #[test]
    fn other_channel_is_busy_while_reassembling() {
        let mut t = Transport::new();
        let a = open_channel(&mut t);
        let b = open_channel(&mut t);
        let reports = fragment(a, cmd::PING, &[1u8; 200]);
        feed(&mut t, &reports[..1]);
        let out = feed(&mut t, &fragment(b, cmd::PING, b"x"));
        assert_eq!(error_code(&out), Some((b, err::CHANNEL_BUSY)));
        // Continuation from b is ignored, a's message still completes.
        let mut stray = [0u8; REPORT_SIZE];
        stray[..4].copy_from_slice(&b.to_be_bytes());
        assert_eq!(t.handle_report(&stray, now()), Output::default());
        let out = feed(&mut t, &reports[1..]);
        assert_eq!(reassemble(&out.reports).2, vec![1u8; 200]);
    }

    #[test]
    fn oversize_payload_is_invalid_len() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let mut init = fragment(cid, cmd::PING, &[])[0];
        init[5..7].copy_from_slice(&((MAX_PAYLOAD_LEN + 1) as u16).to_be_bytes());
        let out = t.handle_report(&init, now());
        assert_eq!(error_code(&out), Some((cid, err::INVALID_LEN)));
    }

    #[test]
    fn reassembly_times_out() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let reports = fragment(cid, cmd::PING, &[1u8; 200]);
        let start = now();
        t.handle_report(&reports[0], start);
        assert!(t.tick(start + Duration::from_millis(100)).is_empty());
        let out = t.tick(start + REASSEMBLY_TIMEOUT);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][4], cmd::ERROR | 0x80);
        assert_eq!(out[0][7], err::MSG_TIMEOUT);
        // Nothing left to time out.
        assert!(t.tick(start + Duration::from_secs(10)).is_empty());
        // Late continuation packets are now spurious.
        let out = feed(&mut t, &reports[1..]);
        assert_eq!(out, Output::default());
    }

    #[test]
    fn two_rapid_requests_on_one_channel_serialise() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out1 = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x04]));
        let Event::CborRequest { id: id1, .. } = out1.events[0] else {
            panic!()
        };
        let out2 = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x04]));
        assert_eq!(error_code(&out2), Some((cid, err::CHANNEL_BUSY)));
        t.respond(id1, &[0]);
        let out3 = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x04]));
        let Event::CborRequest { id: id2, .. } = out3.events[0] else {
            panic!()
        };
        assert_ne!(id1, id2);
    }
}
