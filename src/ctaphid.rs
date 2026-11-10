//! CTAPHID transport state machine (FIDO CTAP 2.2, "USB Human Interface
//! Device (USB HID)" section).
//!
//! This module is pure: it consumes 64-byte HID reports and produces 64-byte
//! HID reports plus [`Event`]s for the layer above. It never performs IO and
//! it does not own timers; the caller passes `Instant`s in and polls
//! [`Transport::tick_output`] periodically so reassembly timeouts can fire
//! and rejected CBOR requests can be latched by the upper layer.
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
/// Absolute limit on a message, even when continuations keep arriving.
pub const REASSEMBLY_MAX_DURATION: Duration = Duration::from_secs(5);
/// Bound channel bookkeeping independently of how many INIT requests arrive.
pub const MAX_CHANNELS: usize = 256;
/// Only reclaim idle channels under allocation pressure. Merely leaving a
/// client connected overnight must not invalidate its channel.
pub const CHANNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
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
    CborRequest {
        id: RequestId,
        cid: u32,
        payload: Vec<u8>,
    },
    /// The client asked to cancel the in-flight request. The upper layer must
    /// still call [`Transport::respond`] (normally with
    /// `CTAP2_ERR_KEEPALIVE_CANCEL`) to finish the transaction. After INIT,
    /// that response is stale and is dropped.
    Cancel { id: RequestId },
    /// Discard transient upper-layer state on valid CANCEL, even without an
    /// in-flight request. This must NOT clear a rejected-CBOR failure latch:
    /// an oversized sender's sequence byte 145 looks like a zero-length CANCEL.
    Reset { cid: u32 },
    /// A valid existing-channel INIT or idle channel reclamation starts a new
    /// channel lifecycle. Unlike CANCEL, this may clear persistent failure
    /// latches after validating the INIT command and nonce length.
    Reinitialized { cid: u32 },
    /// A CBOR request was rejected or abandoned before reaching the upper
    /// layer. Latch failure for this channel so a client ignoring the transport
    /// error cannot turn a failed exclusion probe into an unchecked creation.
    /// Busy traffic and ignored packets that leave a request intact do not emit
    /// this event. Only Reinitialized, not Reset, may clear this hard latch.
    RejectedCbor { cid: u32 },
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
    started_at: Instant,
    last_packet_at: Instant,
}

/// Allocated channels are retained indefinitely unless the bounded table is
/// full and a channel has been idle long enough to reclaim. A Vec keeps both
/// storage and lookup/reclamation work strictly bounded without hash-table
/// tombstone growth under allocation churn.
#[derive(Debug)]
struct Channel {
    cid: u32,
    last_used: Instant,
}

/// The CBOR request currently being processed by the upper layer.
#[derive(Debug, Clone, Copy)]
struct InFlight {
    id: RequestId,
    cid: u32,
    cancelled: bool,
}

#[derive(Debug)]
pub struct Transport {
    channels: Vec<Channel>,
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
            channels: Vec::with_capacity(MAX_CHANNELS),
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
        // Do not depend solely on timer scheduling: a busy reader must not
        // revive a timed-out message with another continuation.
        let mut out = self.tick_output(now);
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
        // Validate the channel and command's advertised length before any
        // resynchronisation, cancellation, or reassembly allocation. In
        // particular, broadcast INIT must always fit in this one packet.
        if cid == 0 || (cid == BROADCAST_CID && command != cmd::INIT) {
            out.error(cid, err::INVALID_CHANNEL);
            return;
        }
        if cid != BROADCAST_CID && !self.channels.iter().any(|ch| ch.cid == cid) {
            out.error(cid, err::INVALID_CHANNEL);
            return;
        }
        // Invalid lengths on an otherwise idle allocated channel are failed
        // CBOR requests, not merely wire errors. Do not poison a request that
        // remains intact, or traffic which would only have received BUSY.
        let reject_cbor =
            command == cmd::CBOR && self.in_flight.is_none() && self.reassembly.is_none();
        if bcnt > MAX_PAYLOAD_LEN {
            out.error(cid, err::INVALID_LEN);
            if reject_cbor {
                out.events.push(Event::RejectedCbor { cid });
            }
            return;
        }
        let valid_len = match command {
            cmd::INIT => bcnt == 8,
            cmd::WINK | cmd::CANCEL => bcnt == 0,
            cmd::CBOR => bcnt != 0,
            cmd::PING => true,
            _ => {
                out.error(cid, err::INVALID_CMD);
                return;
            }
        };
        if !valid_len {
            out.error(cid, err::INVALID_LEN);
            if reject_cbor {
                out.events.push(Event::RejectedCbor { cid });
            }
            return;
        }
        self.touch_channel(cid, now);

        // CANCEL has no response of its own. Notify the upper layer even if
        // only channel-owned preflight state remains, not an in-flight request.
        if command == cmd::CANCEL {
            if self.reassembly.as_ref().is_some_and(|r| r.cid == cid) {
                self.abandon_reassembly(out);
            }
            if let Some(f) = self.in_flight.as_mut().filter(|f| f.cid == cid) {
                if !f.cancelled {
                    f.cancelled = true;
                    out.events.push(Event::Cancel { id: f.id });
                }
            }
            out.events.push(Event::Reset { cid });
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
            self.abandon_reassembly(out);
            if command != cmd::INIT {
                out.error(cid, err::INVALID_SEQ);
                return;
            }
        }

        if bcnt <= INIT_DATA_LEN {
            let payload = data[..bcnt].to_vec();
            self.dispatch(cid, command, payload, now, out);
        } else {
            self.reassembly = Some(Reassembly {
                cid,
                cmd: command,
                total: bcnt,
                buf: data.to_vec(),
                next_seq: 0,
                started_at: now,
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
            self.abandon_reassembly(out);
            out.error(cid, err::INVALID_SEQ);
            return;
        }
        r.next_seq = r.next_seq.wrapping_add(1);
        r.last_packet_at = now;
        let remaining = r.total - r.buf.len();
        r.buf.extend_from_slice(&data[..remaining.min(data.len())]);

        if r.buf.len() >= r.total {
            let r = self.reassembly.take().expect("checked above");
            self.dispatch(r.cid, r.cmd, r.buf, now, out);
        }
        self.touch_channel(cid, now);
    }

    /// Losing an incomplete CBOR request must be visible above the transport.
    /// Otherwise an ignored HID error could bypass a failed exclusion probe.
    fn abandon_reassembly(&mut self, out: &mut Output) {
        if let Some(r) = self.reassembly.take() {
            if r.cmd == cmd::CBOR {
                out.events.push(Event::RejectedCbor { cid: r.cid });
            }
        }
    }

    /// Act on a fully reassembled message.
    fn dispatch(
        &mut self,
        cid: u32,
        command: u8,
        payload: Vec<u8>,
        now: Instant,
        out: &mut Output,
    ) {
        match command {
            cmd::INIT => {
                if payload.len() != 8 {
                    out.error(cid, err::INVALID_LEN);
                    return;
                }
                let assigned = if cid == BROADCAST_CID {
                    let Some(assigned) = self.allocate_cid(now, out) else {
                        out.error(cid, err::CHANNEL_BUSY);
                        return;
                    };
                    assigned
                } else {
                    // Resync on an existing channel: abort whatever it was doing.
                    if let Some(f) = self.in_flight.filter(|f| f.cid == cid) {
                        // Emit again after a prior CANCEL so the upper layer
                        // can distinguish a hard reset from cooperative cancel
                        // by checking in_flight() and abort any lingering task.
                        out.events.push(Event::Cancel { id: f.id });
                        self.in_flight = None;
                    }
                    out.events.push(Event::Reinitialized { cid });
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
                self.next_request_id = self.next_request_id.wrapping_add(1);
                self.in_flight = Some(InFlight {
                    id,
                    cid,
                    cancelled: false,
                });
                out.events.push(Event::CborRequest { id, cid, payload });
            }
            // U2F/CTAP1 is not supported (NMSG capability set), LOCK is optional
            // and we do not implement it.
            cmd::MSG | cmd::LOCK => out.error(cid, err::INVALID_CMD),
            _ => out.error(cid, err::INVALID_CMD),
        }
    }

    fn touch_channel(&mut self, cid: u32, now: Instant) {
        if let Some(channel) = self.channels.iter_mut().find(|ch| ch.cid == cid) {
            channel.last_used = channel.last_used.max(now);
        }
    }

    fn allocate_cid(&mut self, now: Instant, out: &mut Output) -> Option<u32> {
        if self.channels.len() == MAX_CHANNELS {
            let reclaim = self
                .channels
                .iter()
                .enumerate()
                .filter(|(_, ch)| {
                    now.saturating_duration_since(ch.last_used) >= CHANNEL_IDLE_TIMEOUT
                        && !self.in_flight.is_some_and(|f| f.cid == ch.cid)
                        && !self.reassembly.as_ref().is_some_and(|r| r.cid == ch.cid)
                })
                .min_by_key(|(_, ch)| ch.last_used)
                .map(|(index, _)| index)?;
            let channel = self.channels.swap_remove(reclaim);
            out.events.push(Event::Reinitialized { cid: channel.cid });
        }

        // At most MAX_CHANNELS allocated ids plus the two reserved ids can
        // be skipped. Allocate a fresh id rather than reusing the evicted one.
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if cid != 0 && cid != BROADCAST_CID && !self.channels.iter().any(|ch| ch.cid == cid) {
                self.channels.push(Channel {
                    cid,
                    last_used: now,
                });
                return Some(cid);
            }
        }
    }

    /// Legacy report-only timeout API. Callers with upper-layer CBOR state
    /// MUST use [`Self::tick_output`] and process its events instead: this
    /// compatibility wrapper discards rejected-CBOR notifications.
    #[allow(dead_code)]
    pub fn tick(&mut self, now: Instant) -> Vec<Report> {
        self.tick_output(now).reports
    }

    /// Expire a stalled or excessively slow reassembly. Call every ~100 ms
    /// and process both reports and events, just like [`Self::handle_report`].
    /// Idle channels are retained until allocation pressure requires space.
    pub fn tick_output(&mut self, now: Instant) -> Output {
        let mut out = Output::default();
        // Waiting for user presence is activity, not an idle channel lease.
        if let Some(f) = self.in_flight {
            self.touch_channel(f.cid, now);
        }
        if let Some(r) = &self.reassembly {
            if now.saturating_duration_since(r.last_packet_at) >= self.reassembly_timeout
                || now.saturating_duration_since(r.started_at) >= REASSEMBLY_MAX_DURATION
            {
                let cid = r.cid;
                self.abandon_reassembly(&mut out);
                out.error(cid, err::MSG_TIMEOUT);
            }
        }
        out
    }

    /// Finish the in-flight request with a `CTAPHID_CBOR` response whose
    /// payload is `status ++ cbor`. Returns nothing if `id` is stale.
    /// Oversized payloads finish the transaction with `ERR_INVALID_LEN`
    /// instead of emitting a truncated length or invalid continuation sequence.
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
/// Payloads exceeding [`MAX_PAYLOAD_LEN`] produce a single `CTAPHID_ERROR`
/// report with `ERR_INVALID_LEN`, in both debug and release builds.
pub fn fragment(cid: u32, command: u8, payload: &[u8]) -> Vec<Report> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return fragment(cid, cmd::ERROR, &[err::INVALID_LEN]);
    }
    let mut reports = Vec::with_capacity(
        1 + payload
            .len()
            .saturating_sub(INIT_DATA_LEN)
            .div_ceil(CONT_DATA_LEN),
    );

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
        assert_eq!(out.events, vec![Event::Reinitialized { cid }]);
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
        let [Event::CborRequest {
            id,
            cid: request_cid,
            payload,
        }] = out.events.as_slice()
        else {
            panic!("expected one CborRequest, got {:?}", out.events);
        };
        assert_eq!(*request_cid, cid);
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
        assert_eq!(out.events, vec![Event::RejectedCbor { cid }]);
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

        // Cancel from another channel cannot cancel this request, but clears
        // upper-layer state owned by the cancelling channel.
        let out = feed(&mut t, &fragment(b, cmd::CANCEL, &[]));
        assert!(out.reports.is_empty());
        assert_eq!(out.events, vec![Event::Reset { cid: b }]);

        let out = feed(&mut t, &fragment(a, cmd::CANCEL, &[]));
        assert!(out.reports.is_empty(), "CANCEL has no response of its own");
        assert_eq!(
            out.events,
            vec![Event::Cancel { id }, Event::Reset { cid: a }]
        );
        let out = feed(&mut t, &fragment(a, cmd::CANCEL, &[]));
        assert_eq!(out.events, vec![Event::Reset { cid: a }]);

        // The request is still in flight until the upper layer responds.
        assert_eq!(t.in_flight(), Some(id));
        let reports = t.respond(id, &[0x2D]);
        let (_, rcmd, back) = reassemble(&reports);
        assert_eq!((rcmd, back), (cmd::CBOR, vec![0x2D]));
    }

    #[test]
    fn cancel_with_nothing_in_flight_resets_upper_layer_channel_state() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::CANCEL, &[]));
        assert!(out.reports.is_empty());
        assert_eq!(out.events, vec![Event::Reset { cid }]);
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
        assert_eq!(
            out.events,
            vec![Event::Cancel { id }, Event::Reinitialized { cid }]
        );
        let (_, rcmd, _) = reassemble(&out.reports);
        assert_eq!(rcmd, cmd::INIT);
        assert_eq!(t.in_flight(), None);
        // The late response must not reach the client.
        assert!(t.respond(id, &[0x2D]).is_empty());
    }

    #[test]
    fn init_after_cancel_notifies_upper_layer_to_abort_lingering_task() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let out = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x02]));
        let Event::CborRequest { id, .. } = out.events[0] else {
            panic!()
        };
        let out = feed(&mut t, &fragment(cid, cmd::CANCEL, &[]));
        assert_eq!(out.events, vec![Event::Cancel { id }, Event::Reset { cid }]);
        assert_eq!(t.in_flight(), Some(id));
        let out = feed(&mut t, &fragment(cid, cmd::INIT, &NONCE));
        assert_eq!(
            out.events,
            vec![Event::Cancel { id }, Event::Reinitialized { cid }]
        );
        assert_eq!(t.in_flight(), None);
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
    fn channel_exhaustion_never_grows_the_table_or_evicts_recent_clients() {
        let mut t = Transport::new();
        let start = now();
        let capacity = t.channels.capacity();
        let mut out = Output::default();
        let first = t.allocate_cid(start, &mut out).unwrap();
        for _ in 1..MAX_CHANNELS {
            assert!(t.allocate_cid(start, &mut out).is_some());
        }
        let next_cid = t.next_cid;
        let init = fragment(BROADCAST_CID, cmd::INIT, &NONCE)[0];
        for _ in 0..10_000 {
            let out = t.handle_report(&init, start + Duration::from_secs(1));
            assert_eq!(error_code(&out), Some((BROADCAST_CID, err::CHANNEL_BUSY)));
            assert!(out.events.is_empty());
        }
        assert_eq!(t.channels.len(), MAX_CHANNELS);
        assert_eq!(t.channels.capacity(), capacity);
        assert_eq!(t.next_cid, next_cid);
        let out = t.handle_report(&fragment(first, cmd::PING, b"still here")[0], start);
        assert_eq!(reassemble(&out.reports).2, b"still here");
    }

    #[test]
    fn idle_clients_survive_without_allocation_pressure() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let later = now() + Duration::from_secs(7 * 24 * 60 * 60);
        assert!(t.tick(later).is_empty());
        // Time passing alone does not evict channels, even when a new client arrives.
        let out = t.handle_report(&fragment(BROADCAST_CID, cmd::INIT, &NONCE)[0], later);
        assert_eq!(reassemble(&out.reports).1, cmd::INIT);
        assert!(out.events.is_empty());
        let out = t.handle_report(&fragment(cid, cmd::PING, b"old client")[0], later);
        assert_eq!(reassemble(&out.reports).2, b"old client");
    }

    #[test]
    fn allocation_reclaims_only_idle_channels_and_stays_bounded_under_churn() {
        let mut t = Transport::new();
        let start = now();
        let mut out = Output::default();
        let active = t.allocate_cid(start, &mut out).unwrap();
        let oldest = t.allocate_cid(start, &mut out).unwrap();
        for _ in 2..MAX_CHANNELS {
            t.allocate_cid(start + Duration::from_secs(1), &mut out)
                .unwrap();
        }
        let later = start + CHANNEL_IDLE_TIMEOUT;
        t.handle_report(&fragment(active, cmd::PING, &[])[0], later);
        let out = t.handle_report(&fragment(BROADCAST_CID, cmd::INIT, &NONCE)[0], later);
        assert_eq!(reassemble(&out.reports).1, cmd::INIT);
        assert_eq!(out.events, vec![Event::Reinitialized { cid: oldest }]);
        assert!(!t.channels.iter().any(|ch| ch.cid == oldest));
        assert!(t.channels.iter().any(|ch| ch.cid == active));
        let out = t.handle_report(&fragment(oldest, cmd::PING, &[])[0], later);
        assert_eq!(error_code(&out), Some((oldest, err::INVALID_CHANNEL)));

        let capacity = t.channels.capacity();
        for i in 1..=1_000 {
            let time = later + CHANNEL_IDLE_TIMEOUT * i;
            let out = t.handle_report(&fragment(BROADCAST_CID, cmd::INIT, &NONCE)[0], time);
            assert_eq!(reassemble(&out.reports).1, cmd::INIT);
            assert!(matches!(
                out.events.as_slice(),
                [Event::Reinitialized { .. }]
            ));
            assert_eq!(t.channels.len(), MAX_CHANNELS);
            assert_eq!(t.channels.capacity(), capacity);
        }
    }

    #[test]
    fn allocator_protects_in_flight_and_reassembling_channels() {
        let mut t = Transport::new();
        let start = now();
        let mut out = Output::default();
        let active = t.allocate_cid(start, &mut out).unwrap();
        let assembling = t.allocate_cid(start, &mut out).unwrap();
        for _ in 2..MAX_CHANNELS {
            t.allocate_cid(start, &mut out).unwrap();
        }
        t.in_flight = Some(InFlight {
            id: RequestId(42),
            cid: active,
            cancelled: false,
        });
        t.reassembly = Some(Reassembly {
            cid: assembling,
            cmd: cmd::PING,
            total: 100,
            buf: vec![0; INIT_DATA_LEN],
            next_seq: 0,
            started_at: start,
            last_packet_at: start,
        });
        // Exercise the allocator's own protection independently of busy checks.
        assert!(t
            .allocate_cid(start + CHANNEL_IDLE_TIMEOUT, &mut out)
            .is_some());
        assert!(t.channels.iter().any(|ch| ch.cid == active));
        assert!(t.channels.iter().any(|ch| ch.cid == assembling));
    }

    #[test]
    fn channel_allocator_wraps_without_reserved_or_duplicate_ids() {
        let mut t = Transport::new();
        let first = open_channel(&mut t);
        t.next_cid = BROADCAST_CID - 1;
        assert_eq!(open_channel(&mut t), BROADCAST_CID - 1);
        assert_eq!(open_channel(&mut t), first + 1);
    }

    #[test]
    fn malformed_broadcast_init_never_reassembles_or_allocates() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for len in [
            0,
            7,
            9,
            INIT_DATA_LEN,
            INIT_DATA_LEN + 1,
            MAX_PAYLOAD_LEN,
            65535,
        ] {
            let mut init = fragment(BROADCAST_CID, cmd::INIT, &NONCE)[0];
            init[5..7].copy_from_slice(&(len as u16).to_be_bytes());
            let out = t.handle_report(&init, now());
            assert_eq!(error_code(&out), Some((BROADCAST_CID, err::INVALID_LEN)));
            assert!(out.events.is_empty());
            assert!(t.reassembly.is_none());
            assert_eq!(t.channels.len(), 1);
            assert_eq!(t.next_cid, cid + 1);
        }
        let out = feed(&mut t, &fragment(cid, cmd::PING, b"not blocked"));
        assert_eq!(reassemble(&out.reports).2, b"not blocked");
        assert_ne!(open_channel(&mut t), cid);
    }

    #[test]
    fn malformed_commands_cannot_reset_reassembly_or_in_flight_requests() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let invalid = [
            (cmd::INIT, 9, err::INVALID_LEN),
            (cmd::INIT, 200, err::INVALID_LEN),
            (cmd::CANCEL, 1, err::INVALID_LEN),
            (cmd::WINK, 200, err::INVALID_LEN),
            (cmd::CBOR, 0, err::INVALID_LEN),
            (cmd::PING, MAX_PAYLOAD_LEN + 1, err::INVALID_LEN),
            (cmd::MSG, 200, err::INVALID_CMD),
            (cmd::LOCK, 200, err::INVALID_CMD),
            (0x55, 200, err::INVALID_CMD),
        ];
        let reports = fragment(cid, cmd::PING, &[42; 200]);
        feed(&mut t, &reports[..1]);
        for &(command, len, error) in &invalid {
            let mut report = fragment(cid, command, &[])[0];
            report[5..7].copy_from_slice(&(len as u16).to_be_bytes());
            let out = t.handle_report(&report, now());
            assert_eq!(error_code(&out), Some((cid, error)));
            assert!(out.events.is_empty());
            assert_eq!(t.reassembly.as_ref().unwrap().buf.len(), INIT_DATA_LEN);
        }
        let out = feed(&mut t, &reports[1..]);
        assert_eq!(reassemble(&out.reports).2, vec![42; 200]);
        let out = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x04]));
        let Event::CborRequest { id, .. } = out.events[0] else {
            panic!()
        };
        for &(command, len, error) in &invalid {
            let mut report = fragment(cid, command, &[])[0];
            report[5..7].copy_from_slice(&(len as u16).to_be_bytes());
            let out = t.handle_report(&report, now());
            assert_eq!(error_code(&out), Some((cid, error)));
            assert!(out.events.is_empty());
            assert_eq!(t.in_flight(), Some(id));
            assert!(!t.in_flight.unwrap().cancelled);
            assert!(t.reassembly.is_none());
        }
        assert_eq!(reassemble(&t.respond(id, &[0])).2, vec![0]);
    }

    #[test]
    fn invalid_cancel_channel_cannot_reset_any_state() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for invalid in [0, BROADCAST_CID, cid + 1] {
            let out = feed(&mut t, &fragment(invalid, cmd::CANCEL, &[]));
            assert_eq!(error_code(&out), Some((invalid, err::INVALID_CHANNEL)));
            assert!(out.events.is_empty());
        }
    }

    #[test]
    fn unsupported_long_commands_are_rejected_before_reassembly() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for command in [cmd::MSG, cmd::LOCK, cmd::KEEPALIVE, cmd::ERROR, 0x55] {
            let out = feed(&mut t, &fragment(cid, command, &[0; 200])[..1]);
            assert_eq!(error_code(&out), Some((cid, err::INVALID_CMD)));
            assert!(t.reassembly.is_none());
        }
    }

    #[test]
    fn oversized_fragment_returns_error_without_panicking_or_wrapping() {
        for len in [
            MAX_PAYLOAD_LEN + 1,
            u16::MAX as usize,
            u16::MAX as usize + 1,
            100_000,
        ] {
            let reports = fragment(123, cmd::CBOR, &vec![0xA5; len]);
            assert_eq!(reports.len(), 1);
            assert_eq!(
                reassemble(&reports),
                (123, cmd::ERROR, vec![err::INVALID_LEN])
            );
        }
    }

    #[test]
    fn oversized_response_finishes_request_and_keeps_channel_usable() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for len in [MAX_PAYLOAD_LEN + 1, 65536] {
            let out = feed(&mut t, &fragment(cid, cmd::CBOR, &[0x04]));
            let Event::CborRequest { id, .. } = out.events[0] else {
                panic!()
            };
            let payload = vec![0xAA; len];
            let reports = t.respond(id, &payload);
            assert_eq!(reports.len(), 1);
            assert_eq!(
                reassemble(&reports),
                (cid, cmd::ERROR, vec![err::INVALID_LEN])
            );
            assert_eq!(t.in_flight(), None);
            assert!(t.respond(id, &payload).is_empty());
        }
    }

    #[test]
    fn continuations_cannot_extend_absolute_reassembly_deadline() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let start = now();
        let reports = fragment(cid, cmd::PING, &vec![0; MAX_PAYLOAD_LEN]);
        t.handle_report(&reports[0], start);
        for (i, report) in reports[1..13].iter().enumerate() {
            let time = start + Duration::from_millis(400 * (i as u64 + 1));
            assert_eq!(t.handle_report(report, time), Output::default());
        }
        let out = t.handle_report(&reports[13], start + REASSEMBLY_MAX_DURATION);
        assert_eq!(error_code(&out), Some((cid, err::MSG_TIMEOUT)));
        assert!(t.reassembly.is_none());
        let out = t.handle_report(
            &fragment(cid, cmd::PING, b"after timeout")[0],
            start + REASSEMBLY_MAX_DURATION,
        );
        assert_eq!(reassemble(&out.reports).2, b"after timeout");
    }

    #[test]
    fn late_continuation_cannot_revive_reassembly_before_tick() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let start = now();
        let reports = fragment(cid, cmd::PING, &[0; 100]);
        t.handle_report(&reports[0], start);
        let out = t.handle_report(&reports[1], start + REASSEMBLY_TIMEOUT);
        assert_eq!(error_code(&out), Some((cid, err::MSG_TIMEOUT)));
        assert!(t.reassembly.is_none());
    }

    /// Construct a host header without the output fragmenter's size guard.
    fn advertised_init(cid: u32, command: u8, len: usize) -> Report {
        let mut report = [0u8; REPORT_SIZE];
        report[..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = command | 0x80;
        report[5..7].copy_from_slice(&(len as u16).to_be_bytes());
        report
    }

    #[test]
    fn rejected_cbor_lengths_notify_upper_layer_for_every_wire_length() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for len in std::iter::once(0).chain(MAX_PAYLOAD_LEN + 1..=u16::MAX as usize) {
            let out = t.handle_report(&advertised_init(cid, cmd::CBOR, len), now());
            assert_eq!(error_code(&out), Some((cid, err::INVALID_LEN)));
            assert_eq!(out.events, vec![Event::RejectedCbor { cid }]);
            assert!(t.reassembly.is_none());
            assert!(t.in_flight.is_none());
        }
        for invalid in [0, BROADCAST_CID, cid + 1] {
            let out = t.handle_report(&advertised_init(invalid, cmd::CBOR, 65535), now());
            assert_eq!(error_code(&out), Some((invalid, err::INVALID_CHANNEL)));
            assert!(out.events.is_empty());
        }
    }

    #[test]
    fn oversized_zero_tail_cannot_reinitialize_rejected_channel() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let len = u16::MAX as usize;
        let out = t.handle_report(&advertised_init(cid, cmd::CBOR, len), now());
        assert_eq!(out.events, vec![Event::RejectedCbor { cid }]);
        // Model a broken sender that ignores ERR_INVALID_LEN and keeps writing
        // zero-filled continuations, wrapping its sequence byte past 127.
        for seq in 0..(len - INIT_DATA_LEN).div_ceil(CONT_DATA_LEN) {
            let mut report = [0u8; REPORT_SIZE];
            report[..4].copy_from_slice(&cid.to_be_bytes());
            report[4] = seq as u8;
            let out = t.handle_report(&report, now());
            assert!(!out
                .events
                .iter()
                .any(|event| matches!(event, Event::Reinitialized { .. })));
            if seq == 145 {
                assert_eq!(out.events, vec![Event::Reset { cid }]);
                assert!(
                    out.reports.is_empty(),
                    "zero-filled sequence 145 encodes CANCEL"
                );
            }
        }
        // No draining state blocks a real resynchronisation afterward.
        let out = feed(&mut t, &fragment(cid, cmd::INIT, &NONCE));
        assert_eq!(out.events, vec![Event::Reinitialized { cid }]);
        assert_eq!(reassemble(&out.reports).1, cmd::INIT);
    }

    #[test]
    fn cbor_bad_sequence_and_abandonment_notify_but_ping_does_not() {
        for command in [cmd::CBOR, cmd::PING] {
            for abandon in [None, Some(cmd::PING), Some(cmd::CANCEL), Some(cmd::INIT)] {
                let mut t = Transport::new();
                let cid = open_channel(&mut t);
                let packets = fragment(cid, command, &[0x02; 200]);
                feed(&mut t, &packets[..1]);
                let report = match abandon {
                    None => {
                        let mut continuation = packets[1];
                        continuation[4] = 1; // expected sequence zero
                        continuation
                    }
                    Some(cmd::INIT) => fragment(cid, cmd::INIT, &NONCE)[0],
                    Some(next) => fragment(cid, next, &[])[0],
                };
                let out = t.handle_report(&report, now());
                let mut expected = Vec::new();
                if command == cmd::CBOR {
                    expected.push(Event::RejectedCbor { cid });
                }
                match abandon {
                    Some(cmd::CANCEL) => expected.push(Event::Reset { cid }),
                    Some(cmd::INIT) => expected.push(Event::Reinitialized { cid }),
                    _ => assert_eq!(error_code(&out), Some((cid, err::INVALID_SEQ))),
                }
                assert_eq!(out.events, expected);
                assert!(t.reassembly.is_none());
                // Remaining tail packets cannot resurrect the request or repeat rejection.
                assert_eq!(feed(&mut t, &packets[1..]), Output::default());
            }
        }
    }

    #[test]
    fn cbor_timeout_events_work_through_timer_and_report_entrypoints() {
        for command in [cmd::CBOR, cmd::PING] {
            for expire_via_report in [false, true] {
                let mut t = Transport::new();
                let cid = open_channel(&mut t);
                let start = now();
                let packets = fragment(cid, command, &[0x02; 100]);
                t.handle_report(&packets[0], start);
                assert_eq!(t.tick_output(start), Output::default());
                let deadline = start + REASSEMBLY_TIMEOUT;
                let out = if expire_via_report {
                    t.handle_report(&packets[1], deadline)
                } else {
                    t.tick_output(deadline)
                };
                assert_eq!(error_code(&out), Some((cid, err::MSG_TIMEOUT)));
                assert_eq!(
                    out.events,
                    if command == cmd::CBOR {
                        vec![Event::RejectedCbor { cid }]
                    } else {
                        vec![]
                    }
                );
                assert_eq!(t.tick_output(deadline), Output::default());
                assert_eq!(t.handle_report(&packets[1], deadline), Output::default());
            }
        }
    }

    #[test]
    fn cbor_absolute_deadline_also_notifies_upper_layer() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let start = now();
        let packets = fragment(cid, cmd::CBOR, &vec![0x02; MAX_PAYLOAD_LEN]);
        t.handle_report(&packets[0], start);
        for (i, report) in packets[1..13].iter().enumerate() {
            let time = start + Duration::from_millis(400 * (i as u64 + 1));
            assert_eq!(t.handle_report(report, time), Output::default());
        }
        let out = t.tick_output(start + REASSEMBLY_MAX_DURATION);
        assert_eq!(error_code(&out), Some((cid, err::MSG_TIMEOUT)));
        assert_eq!(out.events, vec![Event::RejectedCbor { cid }]);
    }

    #[test]
    fn busy_and_ignored_malformed_packets_do_not_poison_intact_cbor() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        let other = open_channel(&mut t);
        let packets = fragment(cid, cmd::CBOR, &[0x02; 200]);
        feed(&mut t, &packets[..1]);
        for channel in [cid, other] {
            for (command, len) in [
                (cmd::CBOR, 0),
                (cmd::CBOR, MAX_PAYLOAD_LEN + 1),
                (cmd::INIT, 0),
                (cmd::CANCEL, 1),
                (cmd::WINK, 1),
                (0x55, 100),
            ] {
                let out = t.handle_report(&advertised_init(channel, command, len), now());
                assert!(out.events.is_empty());
                assert_eq!(t.reassembly.as_ref().unwrap().buf.len(), INIT_DATA_LEN);
            }
        }
        let out = feed(&mut t, &fragment(other, cmd::CBOR, &[0x04]));
        assert_eq!(error_code(&out), Some((other, err::CHANNEL_BUSY)));
        assert!(out.events.is_empty());
        let mut stray = packets[1];
        stray[..4].copy_from_slice(&other.to_be_bytes());
        assert_eq!(t.handle_report(&stray, now()), Output::default());

        let out = feed(&mut t, &packets[1..]);
        let [Event::CborRequest { id, .. }] = out.events.as_slice() else {
            panic!("intact request must complete: {:?}", out.events);
        };
        for channel in [cid, other] {
            for len in [0, 1, MAX_PAYLOAD_LEN + 1] {
                let out = t.handle_report(&advertised_init(channel, cmd::CBOR, len), now());
                assert!(out.events.is_empty());
                assert_eq!(t.in_flight(), Some(*id));
            }
        }
    }

    #[test]
    fn malformed_ping_and_broadcast_do_not_emit_rejection_or_reinitialization() {
        let mut t = Transport::new();
        let cid = open_channel(&mut t);
        for (channel, command, len) in [
            (cid, cmd::PING, MAX_PAYLOAD_LEN + 1),
            (BROADCAST_CID, cmd::INIT, MAX_PAYLOAD_LEN),
            (BROADCAST_CID, cmd::CBOR, MAX_PAYLOAD_LEN + 1),
        ] {
            let out = t.handle_report(&advertised_init(channel, command, len), now());
            assert!(error_code(&out).is_some());
            assert!(out.events.is_empty());
        }
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
