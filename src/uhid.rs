//! Virtual HID device over `/dev/uhid`, reached through the privileged helper.
//!
//! The uhid ABI (`linux/uhid.h`) is a single packed `struct uhid_event`
//! (`u32 type` followed by a union of request structs) written to and read
//! from the character device. We lay the few events we need out by hand so
//! the build needs no bindgen or system headers. Layout constants are checked
//! by unit tests against the values from the kernel header.
//!
//! Only `pocketkey-uhid-helper` (root) opens `/dev/uhid`. It writes
//! `UHID_CREATE2` and keeps that descriptor; the daemon gets one end of a
//! `SOCK_SEQPACKET` socketpair on which the helper relays events in both
//! directions, forwarding to the kernel only `UHID_INPUT2` and the two report
//! replies. Record boundaries on the socketpair match event boundaries on the
//! character device, so the daemon reads and writes `struct uhid_event` as if
//! it held the device itself. Closing the daemon's end makes the helper close
//! `/dev/uhid`, which destroys the device; no `UHID_DESTROY` is ever sent.
//!
//! Lifecycle as seen by the daemon: the kernel sends `UHID_START`, `UHID_OPEN`
//! when a program opens the hidraw node, `UHID_OUTPUT` for each report the host
//! writes, `UHID_CLOSE`/`UHID_STOP` on the way down. We send `UHID_INPUT2` for
//! each report to the host.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use tokio::io::unix::AsyncFd;
use tracing::{debug, trace, warn};

use crate::ctaphid::{Report, REPORT_SIZE};

/// FIDO HID report descriptor (HID Usage Tables, FIDO Alliance page):
/// usage page 0xF1D0, usage 0x01, one 64-byte input and one 64-byte output
/// report, no report ids.
pub const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (U2F HID Authenticator Device)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Variable, Absolute)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Variable, Absolute)
    0xC0, //             End Collection
];

pub const DEVICE_NAME: &str = "pocketkey virtual FIDO key";
/// pid.codes test VID/PID. Not a registered product id; fine for a virtual
/// device that never leaves the machine.
pub const VENDOR_ID: u32 = 0x1209;
pub const PRODUCT_ID: u32 = 0x0001;

// struct uhid_event layout -------------------------------------------------

/// Never sent by the daemon; the helper refuses it (see `helper::relay`).
#[cfg_attr(not(test), allow(dead_code))]
const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const UHID_DATA_MAX: usize = 4096;
const BUS_USB: u16 = 0x03;

/// `sizeof(struct uhid_event)`: 4-byte type plus the largest union member,
/// `struct uhid_create2_req` (128 + 64 + 64 + 2 + 2 + 4*4 + 4096 bytes).
const UHID_EVENT_SIZE: usize = 4 + 128 + 64 + 64 + 2 + 2 + 16 + HID_MAX_DESCRIPTOR_SIZE;

// Offsets inside the union (all relative to the start of the event).
mod create2 {
    pub const NAME: usize = 4;
    pub const PHYS: usize = NAME + 128;
    pub const UNIQ: usize = PHYS + 64;
    pub const RD_SIZE: usize = UNIQ + 64;
    pub const BUS: usize = RD_SIZE + 2;
    pub const VENDOR: usize = BUS + 2;
    pub const PRODUCT: usize = VENDOR + 4;
    pub const VERSION: usize = PRODUCT + 4;
    pub const COUNTRY: usize = VERSION + 4;
    pub const RD_DATA: usize = COUNTRY + 4;
}
mod input2 {
    pub const SIZE: usize = 4;
    pub const DATA: usize = 6;
}
mod output {
    pub const DATA: usize = 4;
    pub const SIZE: usize = DATA + super::UHID_DATA_MAX;
    pub const RTYPE: usize = SIZE + 2;
}
mod get_report {
    pub const ID: usize = 4;
}
mod get_report_reply {
    pub const ID: usize = 4;
    pub const ERR: usize = 8;
    pub const SIZE: usize = 10;
}
mod set_report {
    pub const ID: usize = 4;
    pub const RTYPE: usize = 9;
    pub const SIZE: usize = 10;
    pub const DATA: usize = 12;
}
mod set_report_reply {
    pub const ID: usize = 4;
    pub const ERR: usize = 8;
}

/// `rtype` value for output reports in `UHID_OUTPUT` / `UHID_SET_REPORT`.
const UHID_OUTPUT_REPORT: u8 = 1;

/// Bound each polling turn even when the fd stays readable with events that
/// are discarded or answered internally. AsyncFd readiness alone is not a
/// guaranteed scheduling point for timers and cancellation.
const EVENTS_PER_YIELD: usize = 16;

/// Events from the kernel that the caller cares about.
#[derive(Debug)]
pub enum UhidEvent {
    /// The host wrote a 64-byte report to the device.
    Output(Report),
    /// A program opened the hidraw node.
    Open,
    /// The last program closed the hidraw node.
    Close,
    /// The device was torn down by the kernel.
    Stop,
}

pub struct UhidDevice {
    /// The daemon's end of the helper's socketpair, not `/dev/uhid` itself.
    fd: AsyncFd<File>,
}

impl UhidDevice {
    /// Obtain the virtual FIDO device from the privileged helper (see
    /// `pocketkey-uhid-helper`). The helper creates the device with the fixed
    /// FIDO report descriptor, keeps the `/dev/uhid` descriptor, and relays
    /// events over the returned channel, so the user session can neither reach
    /// `/dev/uhid` nor re-create the device as something else.
    pub fn create() -> io::Result<Self> {
        let socket = Path::new(helper::SOCKET_PATH);
        let channel = helper::request_device(socket).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                e.kind(),
                format!(
                    "{}: the pocketkey-uhid helper socket is not present. Install it with \
                     `sudo make install` (or the .deb) and check \
                     `systemctl status pocketkey-uhid.socket`",
                    socket.display()
                ),
            ),
            io::ErrorKind::PermissionDenied => io::Error::new(
                e.kind(),
                format!(
                    "{}: permission denied. Only members of the pocketkey group may \
                     request a virtual FIDO device; run `sudo usermod -aG pocketkey $USER` \
                     and log in again",
                    socket.display()
                ),
            ),
            _ => e,
        })?;
        debug!(socket = %socket.display(), "device channel received from helper");
        Self::from_channel(channel)
    }

    /// Wrap the daemon's end of the helper's event channel.
    pub fn from_channel(channel: OwnedFd) -> io::Result<Self> {
        let file = File::from(channel);
        set_nonblocking_cloexec(&file)?;
        // SAFETY: `file` owns the descriptor for the lifetime of the AsyncFd
        // and nothing else closes or duplicates it (the I/O-safety contract
        // `register` asks the caller to uphold).
        let fd = unsafe { AsyncFd::register(file)? };
        Ok(Self { fd })
    }

    /// Wait for the next event that matters to the caller. `UHID_START` and
    /// report queries are handled internally.
    pub async fn next_event(&mut self) -> io::Result<UhidEvent> {
        let mut processed = 0;
        loop {
            if processed == EVENTS_PER_YIELD {
                tokio::task::yield_now().await;
                processed = 0;
            }
            processed += 1;
            let mut buf = [0u8; UHID_EVENT_SIZE];
            let n = loop {
                let mut guard = self.fd.readable_mut().await?;
                match guard.try_io(|inner| inner.get_mut().read(&mut buf)) {
                    Ok(result) => break result?,
                    Err(_would_block) => continue,
                }
            };
            if n < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("short uhid event ({n} bytes)"),
                ));
            }
            let ty = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            match ty {
                UHID_START => {
                    let flags = u64::from_le_bytes(buf[4..12].try_into().expect("8 bytes"));
                    debug!(dev_flags = flags, "uhid START");
                    if flags != 0 {
                        warn!(
                            dev_flags = flags,
                            "kernel reports numbered reports; descriptor has none"
                        );
                    }
                }
                UHID_STOP => return Ok(UhidEvent::Stop),
                UHID_OPEN => return Ok(UhidEvent::Open),
                UHID_CLOSE => return Ok(UhidEvent::Close),
                UHID_OUTPUT => {
                    let size =
                        u16::from_le_bytes([buf[output::SIZE], buf[output::SIZE + 1]]) as usize;
                    let rtype = buf[output::RTYPE];
                    let data = &buf[output::DATA..output::DATA + size.min(UHID_DATA_MAX)];
                    if rtype != UHID_OUTPUT_REPORT {
                        trace!(rtype, size, "ignoring non-output report");
                        continue;
                    }
                    if let Some(report) = report_from_output(data) {
                        return Ok(UhidEvent::Output(report));
                    }
                    warn!(size, "ignoring output report of unexpected size");
                }
                UHID_SET_REPORT => {
                    // hidraw ioctl path (HIDIOCSOUTPUT). Acknowledge and treat the
                    // payload like an output report.
                    let id = u32::from_le_bytes(
                        buf[set_report::ID..set_report::ID + 4]
                            .try_into()
                            .expect("4 bytes"),
                    );
                    let rtype = buf[set_report::RTYPE];
                    let size =
                        u16::from_le_bytes([buf[set_report::SIZE], buf[set_report::SIZE + 1]])
                            as usize;
                    let data = &buf[set_report::DATA..set_report::DATA + size.min(UHID_DATA_MAX)];
                    let report = if rtype == UHID_OUTPUT_REPORT {
                        report_from_output(data)
                    } else {
                        None
                    };
                    let mut reply = [0u8; UHID_EVENT_SIZE];
                    reply[..4].copy_from_slice(&UHID_SET_REPORT_REPLY.to_le_bytes());
                    reply[set_report_reply::ID..set_report_reply::ID + 4]
                        .copy_from_slice(&id.to_le_bytes());
                    let err: u16 = if report.is_some() {
                        0
                    } else {
                        libc::EINVAL as u16
                    };
                    reply[set_report_reply::ERR..set_report_reply::ERR + 2]
                        .copy_from_slice(&err.to_le_bytes());
                    self.write_event(&reply)?;
                    if let Some(report) = report {
                        return Ok(UhidEvent::Output(report));
                    }
                }
                UHID_GET_REPORT => {
                    // We have no feature reports and input reports are pushed, not
                    // polled. Fail the request so the caller gets EIO.
                    let id = u32::from_le_bytes(
                        buf[get_report::ID..get_report::ID + 4]
                            .try_into()
                            .expect("4 bytes"),
                    );
                    let mut reply = [0u8; UHID_EVENT_SIZE];
                    reply[..4].copy_from_slice(&UHID_GET_REPORT_REPLY.to_le_bytes());
                    reply[get_report_reply::ID..get_report_reply::ID + 4]
                        .copy_from_slice(&id.to_le_bytes());
                    reply[get_report_reply::ERR..get_report_reply::ERR + 2]
                        .copy_from_slice(&(libc::EIO as u16).to_le_bytes());
                    reply[get_report_reply::SIZE..get_report_reply::SIZE + 2]
                        .copy_from_slice(&0u16.to_le_bytes());
                    self.write_event(&reply)?;
                }
                other => trace!(ty = other, "ignoring uhid event"),
            }
        }
    }

    /// Send one 64-byte input report to the host.
    pub fn send_report(&mut self, report: &Report) -> io::Result<()> {
        let mut ev = [0u8; UHID_EVENT_SIZE];
        ev[..4].copy_from_slice(&UHID_INPUT2.to_le_bytes());
        ev[input2::SIZE..input2::SIZE + 2].copy_from_slice(&(REPORT_SIZE as u16).to_le_bytes());
        ev[input2::DATA..input2::DATA + REPORT_SIZE].copy_from_slice(report);
        self.write_event(&ev)
    }

    /// Tear the device down: shut the channel so the helper closes
    /// `/dev/uhid` and the kernel removes the hidraw node. Idempotent;
    /// dropping the device has the same effect.
    pub fn destroy(&mut self) -> io::Result<()> {
        // SAFETY: shutdown on a socket descriptor we own; ENOTCONN after a
        // previous shutdown is the idempotent case.
        let rc = unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOTCONN) {
                return Err(err);
            }
        }
        debug!("uhid device channel closed");
        Ok(())
    }

    /// The helper drains the channel promptly and relays to `/dev/uhid`,
    /// whose writes never block, so a plain send on the non-blocking end is
    /// fine. A full socket buffer means the helper is gone or wedged.
    fn write_event(&mut self, ev: &[u8; UHID_EVENT_SIZE]) -> io::Result<()> {
        let n = self.fd.get_mut().write(ev)?;
        if n != ev.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short uhid write: {n} of {} bytes", ev.len()),
            ));
        }
        Ok(())
    }
}

/// Output reports written through hidraw arrive with a leading report-id byte
/// (0x00, since the descriptor has no report ids): 65 bytes. Some paths hand
/// us the bare 64 bytes. Accept both.
fn report_from_output(data: &[u8]) -> Option<Report> {
    let bytes = match data.len() {
        REPORT_SIZE => data,
        n if n == REPORT_SIZE + 1 && data[0] == 0 => &data[1..],
        _ => return None,
    };
    let mut report = [0u8; REPORT_SIZE];
    report.copy_from_slice(bytes);
    Some(report)
}

fn set_nonblocking_cloexec(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: fcntl on a descriptor we own; flags are plain integers.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 || libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The privileged helper protocol. The daemon connects to the helper's Unix
/// socket, sends one request byte and receives, via `SCM_RIGHTS`, one end of
/// a `SOCK_SEQPACKET` socketpair. The helper keeps the `/dev/uhid` descriptor
/// and relays events between the two for as long as the daemon holds its end.
/// Both sides of the protocol live here so the helper binary and the daemon
/// cannot drift apart.
pub mod helper {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// Where the system helper listens (socket-activated by systemd).
    pub const SOCKET_PATH: &str = "/run/pocketkey/uhid.sock";
    /// Single-byte request/response codes. Deliberately tiny: no parsing of
    /// untrusted structured data happens in the privileged process.
    ///
    /// `0x01` was the v1.0 request for a raw `/dev/uhid` descriptor and is no
    /// longer served; a mismatched daemon/helper pair fails loudly instead
    /// of half-working.
    pub const REQUEST_CHANNEL: u8 = 0x02;
    pub const REPLY_DEVICE: u8 = 0x01;
    pub const REPLY_BUSY: u8 = 0x02;
    pub const REPLY_ERROR: u8 = 0x03;
    const IO_TIMEOUT: Duration = Duration::from_secs(5);

    /// Client side: ask the helper for a device and receive the daemon's end
    /// of the event channel.
    pub fn request_device(socket: &Path) -> io::Result<OwnedFd> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        send_byte(&stream, REQUEST_CHANNEL, None)?;
        let (code, fd) = recv_byte(&stream)?;
        match (code, fd) {
            (REPLY_DEVICE, Some(fd)) => Ok(fd),
            (REPLY_DEVICE, None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the uhid helper replied without a channel descriptor",
            )),
            (REPLY_BUSY, _) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the uhid helper reports a virtual FIDO device already exists for this user",
            )),
            (REPLY_ERROR, _) => Err(io::Error::other(
                "the uhid helper could not create the virtual FIDO device (see its journal); \
                 if it was just upgraded, both daemon and helper must be the same version",
            )),
            (code, _) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected reply {code:#04x} from the uhid helper"),
            )),
        }
    }

    /// Helper side: open `/dev/uhid` and create the device. The helper keeps
    /// this descriptor for the device's lifetime; it is never passed out.
    pub fn create_device(uhid_path: &Path) -> io::Result<File> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(uhid_path)?;
        let ev = create2_event();
        let n = file.write(&ev)?;
        if n != ev.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short uhid write: {n} of {} bytes", ev.len()),
            ));
        }
        Ok(file)
    }

    /// Helper side: the event channel. `SOCK_SEQPACKET` keeps one
    /// `struct uhid_event` per record, matching the character device.
    /// Returns `(helper_end, daemon_end)`.
    pub fn channel_pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [-1 as libc::c_int; 2];
        // SAFETY: socketpair writes two descriptors into the array.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                fds.as_mut_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are fresh and owned by nothing else.
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// Event types the daemon may send to the kernel. Everything else,
    /// `UHID_DESTROY` and `UHID_CREATE2` in particular, ends the session.
    pub const DAEMON_ALLOWED_EVENTS: [u32; 3] =
        [UHID_INPUT2, UHID_GET_REPORT_REPLY, UHID_SET_REPORT_REPLY];

    /// Why a relay session ended.
    #[derive(Debug, PartialEq, Eq)]
    pub enum RelayEnd {
        /// The daemon closed its end of the channel (normal shutdown).
        DaemonClosed,
        /// The daemon sent an event type outside `DAEMON_ALLOWED_EVENTS`.
        DaemonViolation(u32),
        /// The kernel side closed or failed.
        KernelClosed,
        Io(io::ErrorKind),
    }

    /// Helper side: shuttle events between `/dev/uhid` and the daemon's
    /// channel until one side ends. Runs on a dedicated thread per device.
    /// Kernel events go to the daemon unchanged. Daemon events are forwarded
    /// only when their 4-byte type is in `DAEMON_ALLOWED_EVENTS`; nothing
    /// beyond the type is inspected. On return the caller drops `uhid`, which
    /// destroys the device.
    pub fn relay(uhid: &File, channel: &OwnedFd) -> RelayEnd {
        let mut fds = [
            libc::pollfd {
                fd: uhid.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: channel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let mut buf = [0u8; UHID_EVENT_SIZE];
        loop {
            // SAFETY: fds is a valid two-element array for the call.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return RelayEnd::Io(err.kind());
            }
            let hangup = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;

            if fds[0].revents & libc::POLLIN != 0 {
                match read_fd(uhid.as_raw_fd(), &mut buf) {
                    Ok(0) => return RelayEnd::KernelClosed,
                    Ok(n) => {
                        if let Err(e) = write_all_fd(channel.as_raw_fd(), &buf[..n]) {
                            return match e.kind() {
                                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
                                    RelayEnd::DaemonClosed
                                }
                                kind => RelayEnd::Io(kind),
                            };
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return RelayEnd::Io(e.kind()),
                }
            } else if fds[0].revents & hangup != 0 {
                return RelayEnd::KernelClosed;
            }

            if fds[1].revents & libc::POLLIN != 0 {
                match read_fd(channel.as_raw_fd(), &mut buf) {
                    Ok(0) => return RelayEnd::DaemonClosed,
                    Ok(n) => {
                        if n < 4 {
                            return RelayEnd::DaemonViolation(u32::MAX);
                        }
                        let ty = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        if !DAEMON_ALLOWED_EVENTS.contains(&ty) {
                            return RelayEnd::DaemonViolation(ty);
                        }
                        if let Err(e) = write_all_fd(uhid.as_raw_fd(), &buf[..n]) {
                            return RelayEnd::Io(e.kind());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        return RelayEnd::DaemonClosed
                    }
                    Err(e) => return RelayEnd::Io(e.kind()),
                }
            } else if fds[1].revents & hangup != 0 {
                return RelayEnd::DaemonClosed;
            }
        }
    }

    fn read_fd(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: buf is valid for buf.len() bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// A `struct uhid_event` is written whole or not at all on both the
    /// character device and a seqpacket socket, so a short write is an error.
    /// Rust's runtime ignores SIGPIPE, so a closed peer surfaces as EPIPE.
    fn write_all_fd(fd: libc::c_int, data: &[u8]) -> io::Result<()> {
        // SAFETY: data is valid for data.len() bytes.
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short write: {n} of {} bytes", data.len()),
            ));
        }
        Ok(())
    }

    /// Send one code byte, optionally with a descriptor attached.
    pub fn send_byte(stream: &UnixStream, code: u8, fd: Option<&File>) -> io::Result<()> {
        let data = [code];
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = [0u8; CMSG_SPACE_FD];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(file) = fd {
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = CMSG_SPACE_FD as _;
            // SAFETY: the control buffer is large enough for one fd and
            // msg_control points at it.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(cmsg) as *mut libc::c_int,
                    file.as_raw_fd(),
                );
            }
        }
        // SAFETY: msg and all buffers it references are valid for the call.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent != 1 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to uhid helper socket",
            ));
        }
        Ok(())
    }

    /// Receive one code byte and, if attached, exactly one descriptor. Any
    /// additional descriptors are closed, never leaked into the process.
    pub fn recv_byte(stream: &UnixStream) -> io::Result<(u8, Option<OwnedFd>)> {
        let mut data = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = [0u8; CMSG_SPACE_FD * 4];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;
        // SAFETY: msg and all buffers it references are valid for the call.
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "uhid helper closed the connection",
            ));
        }
        let mut fd: Option<OwnedFd> = None;
        // SAFETY: iterating the control messages the kernel filled in.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let header = libc::CMSG_LEN(0) as usize;
                    let count =
                        ((*cmsg).cmsg_len as usize - header) / std::mem::size_of::<libc::c_int>();
                    let base = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                    for i in 0..count {
                        let raw = std::ptr::read_unaligned(base.add(i));
                        let owned = OwnedFd::from_raw_fd(raw);
                        if fd.is_none() {
                            fd = Some(owned);
                        }
                        // Extra descriptors drop (close) here.
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated control message from uhid helper",
            ));
        }
        Ok((data[0], fd))
    }

    const CMSG_SPACE_FD: usize = 24;

    /// Credentials of the peer process, used by the helper for authorization
    /// and per-user limits.
    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `cred`.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read;

        #[test]
        fn cmsg_space_matches_libc() {
            // SAFETY: pure arithmetic macro.
            let expected = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
            assert_eq!(CMSG_SPACE_FD, expected as usize);
        }

        #[test]
        fn passes_a_descriptor_and_code_over_a_socketpair() {
            let (a, b) = UnixStream::pair().unwrap();
            let mut payload = tempfile();
            payload.write_all(b"hello").unwrap();
            send_byte(&a, REPLY_DEVICE, Some(&payload)).unwrap();
            let (code, fd) = recv_byte(&b).unwrap();
            assert_eq!(code, REPLY_DEVICE);
            let mut received = File::from(fd.expect("descriptor attached"));
            use std::io::Seek;
            received.seek(std::io::SeekFrom::Start(0)).unwrap();
            let mut text = String::new();
            received.read_to_string(&mut text).unwrap();
            assert_eq!(text, "hello");
        }

        #[test]
        fn plain_codes_carry_no_descriptor() {
            let (a, b) = UnixStream::pair().unwrap();
            send_byte(&a, REPLY_BUSY, None).unwrap();
            let (code, fd) = recv_byte(&b).unwrap();
            assert_eq!(code, REPLY_BUSY);
            assert!(fd.is_none());
        }

        #[test]
        fn peer_uid_is_our_own_on_a_socketpair() {
            let (a, _b) = UnixStream::pair().unwrap();
            // SAFETY: geteuid has no preconditions.
            assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
        }

        #[test]
        fn request_device_reports_a_missing_socket_as_not_found() {
            let err = request_device(Path::new("/nonexistent/pocketkey/uhid.sock")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }

        /// A seqpacket pair stands in for `/dev/uhid`: `kernel` is what the
        /// kernel would hold, `uhid` what the helper opened.
        fn relay_fixture() -> (File, OwnedFd, OwnedFd, OwnedFd) {
            let (uhid, kernel) = channel_pair().unwrap();
            let (helper_end, daemon_end) = channel_pair().unwrap();
            (File::from(uhid), kernel, helper_end, daemon_end)
        }

        fn event(ty: u32) -> [u8; UHID_EVENT_SIZE] {
            let mut ev = [0u8; UHID_EVENT_SIZE];
            ev[..4].copy_from_slice(&ty.to_le_bytes());
            ev
        }

        fn send(fd: &OwnedFd, data: &[u8]) {
            write_all_fd(fd.as_raw_fd(), data).unwrap();
        }

        fn recv_blocking(fd: &OwnedFd) -> Vec<u8> {
            let mut pfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: single valid pollfd.
            assert!(unsafe { libc::poll(&mut pfd, 1, 5000) } > 0, "timed out");
            let mut buf = vec![0u8; UHID_EVENT_SIZE];
            let n = read_fd(fd.as_raw_fd(), &mut buf).unwrap();
            buf.truncate(n);
            buf
        }

        fn spawn_relay(uhid: File, helper_end: OwnedFd) -> std::thread::JoinHandle<RelayEnd> {
            std::thread::spawn(move || relay(&uhid, &helper_end))
        }

        #[test]
        fn relay_forwards_kernel_events_to_the_daemon_unchanged() {
            let (uhid, kernel, helper_end, daemon_end) = relay_fixture();
            let handle = spawn_relay(uhid, helper_end);

            let mut ev = event(UHID_OUTPUT);
            ev[output::DATA..output::DATA + 4].copy_from_slice(b"ping");
            send(&kernel, &ev);
            assert_eq!(recv_blocking(&daemon_end), ev.to_vec());

            // Short events (the kernel sends sizeof(uhid_event), but be lenient).
            send(&kernel, &UHID_STOP.to_le_bytes());
            assert_eq!(recv_blocking(&daemon_end), UHID_STOP.to_le_bytes());

            drop(daemon_end);
            assert_eq!(handle.join().unwrap(), RelayEnd::DaemonClosed);
        }

        #[test]
        fn relay_forwards_allowed_daemon_events_to_the_kernel() {
            let (uhid, kernel, helper_end, daemon_end) = relay_fixture();
            let handle = spawn_relay(uhid, helper_end);

            for ty in DAEMON_ALLOWED_EVENTS {
                let mut ev = event(ty);
                ev[4..8].copy_from_slice(&[1, 2, 3, 4]);
                send(&daemon_end, &ev);
                assert_eq!(recv_blocking(&kernel), ev.to_vec(), "type {ty}");
            }

            drop(daemon_end);
            assert_eq!(handle.join().unwrap(), RelayEnd::DaemonClosed);
        }

        #[test]
        fn relay_drops_the_session_on_any_other_daemon_event() {
            for ty in [
                UHID_DESTROY,
                UHID_CREATE2,
                UHID_START,
                UHID_OUTPUT,
                0xdead_beef,
            ] {
                let (uhid, kernel, helper_end, daemon_end) = relay_fixture();
                let handle = spawn_relay(uhid, helper_end);

                send(&daemon_end, &event(ty));
                assert_eq!(handle.join().unwrap(), RelayEnd::DaemonViolation(ty));

                // Nothing reached the kernel side: the relay dropped its uhid
                // end, so the only thing left to read is EOF.
                let mut buf = [0u8; UHID_EVENT_SIZE];
                assert_eq!(
                    read_fd(kernel.as_raw_fd(), &mut buf).unwrap(),
                    0,
                    "type {ty} leaked"
                );
            }
        }

        #[test]
        fn relay_rejects_a_truncated_type_field() {
            let (uhid, _kernel, helper_end, daemon_end) = relay_fixture();
            let handle = spawn_relay(uhid, helper_end);
            send(&daemon_end, &[0x0c, 0x00]);
            assert_eq!(handle.join().unwrap(), RelayEnd::DaemonViolation(u32::MAX));
        }

        #[test]
        fn relay_ends_when_the_kernel_side_closes() {
            let (uhid, kernel, helper_end, _daemon_end) = relay_fixture();
            let handle = spawn_relay(uhid, helper_end);
            drop(kernel);
            assert_eq!(handle.join().unwrap(), RelayEnd::KernelClosed);
        }

        #[test]
        fn daemon_shutdown_ends_the_relay() {
            let (uhid, _kernel, helper_end, daemon_end) = relay_fixture();
            let handle = spawn_relay(uhid, helper_end);
            // SAFETY: shutdown on a socket we own.
            assert_eq!(
                unsafe { libc::shutdown(daemon_end.as_raw_fd(), libc::SHUT_RDWR) },
                0
            );
            assert_eq!(handle.join().unwrap(), RelayEnd::DaemonClosed);
        }

        fn tempfile() -> File {
            let path = std::env::temp_dir().join(format!(
                "pocketkey-uhid-helper-test-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            let _ = std::fs::remove_file(&path);
            file
        }
    }
}

fn create2_event() -> [u8; UHID_EVENT_SIZE] {
    let mut ev = [0u8; UHID_EVENT_SIZE];
    ev[..4].copy_from_slice(&UHID_CREATE2.to_le_bytes());
    let name = DEVICE_NAME.as_bytes();
    ev[create2::NAME..create2::NAME + name.len()].copy_from_slice(name);
    let phys = b"pocketkey";
    ev[create2::PHYS..create2::PHYS + phys.len()].copy_from_slice(phys);
    ev[create2::RD_SIZE..create2::RD_SIZE + 2]
        .copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_le_bytes());
    ev[create2::BUS..create2::BUS + 2].copy_from_slice(&BUS_USB.to_le_bytes());
    ev[create2::VENDOR..create2::VENDOR + 4].copy_from_slice(&VENDOR_ID.to_le_bytes());
    ev[create2::PRODUCT..create2::PRODUCT + 4].copy_from_slice(&PRODUCT_ID.to_le_bytes());
    ev[create2::VERSION..create2::VERSION + 4].copy_from_slice(&0u32.to_le_bytes());
    ev[create2::COUNTRY..create2::COUNTRY + 4].copy_from_slice(&0u32.to_le_bytes());
    ev[create2::RD_DATA..create2::RD_DATA + FIDO_REPORT_DESCRIPTOR.len()]
        .copy_from_slice(&FIDO_REPORT_DESCRIPTOR);
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_linux_uhid_h() {
        // sizeof(struct uhid_event) with a packed 4372-byte uhid_create2_req.
        assert_eq!(UHID_EVENT_SIZE, 4376);
        assert_eq!(create2::RD_DATA, 280);
        assert_eq!(create2::RD_DATA + HID_MAX_DESCRIPTOR_SIZE, UHID_EVENT_SIZE);
        assert_eq!(output::RTYPE, 4102);
        assert_eq!(input2::DATA, 6);
    }

    #[test]
    fn create2_event_fields() {
        let ev = create2_event();
        assert_eq!(
            u32::from_le_bytes(ev[..4].try_into().unwrap()),
            UHID_CREATE2
        );
        assert_eq!(
            &ev[create2::NAME..create2::NAME + DEVICE_NAME.len()],
            DEVICE_NAME.as_bytes()
        );
        assert_eq!(
            u16::from_le_bytes([ev[create2::RD_SIZE], ev[create2::RD_SIZE + 1]]),
            34
        );
        assert_eq!(
            u16::from_le_bytes([ev[create2::BUS], ev[create2::BUS + 1]]),
            BUS_USB
        );
        assert_eq!(
            u32::from_le_bytes(ev[create2::VENDOR..create2::VENDOR + 4].try_into().unwrap()),
            VENDOR_ID
        );
        assert_eq!(
            &ev[create2::RD_DATA..create2::RD_DATA + 34],
            &FIDO_REPORT_DESCRIPTOR
        );
    }

    #[tokio::test]
    async fn next_event_yields_when_discarding_or_answering_queries() {
        use std::future::Future;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;
        use std::task::{Context, Waker};

        // Datagrams preserve the event boundaries of /dev/uhid without needing
        // a real device, kernel module, elevated privileges, or system changes.
        for event_type in [UHID_OUTPUT, UHID_GET_REPORT, UHID_SET_REPORT] {
            let (reader, writer) = UnixDatagram::pair().unwrap();
            reader.set_nonblocking(true).unwrap();
            let owned: OwnedFd = reader.into();
            let file = File::from(owned);
            // SAFETY: this AsyncFd exclusively owns the open descriptor.
            let fd = unsafe { AsyncFd::register(file).unwrap() };
            let mut device = UhidDevice { fd };

            let mut event = [0u8; UHID_EVENT_SIZE];
            event[..4].copy_from_slice(&event_type.to_le_bytes());
            // OUTPUT has the wrong type; SET_REPORT has no valid report.
            // Keep the outgoing request datagrams short where possible.
            let len = match event_type {
                UHID_OUTPUT => output::RTYPE + 1,
                UHID_GET_REPORT => get_report::ID + 4,
                _ => set_report::DATA,
            };
            writer.set_nonblocking(true).unwrap();
            for _ in 0..EVENTS_PER_YIELD {
                writer.send(&event[..len]).unwrap();
            }
            writer.send(&UHID_STOP.to_le_bytes()).unwrap();

            // Preload all events and wait for readiness first, so the only
            // scheduling point is the explicit budget, not an empty socket.
            // A no-op waker lets us observe Pending, then await normally again.
            let mut cx = Context::from_waker(Waker::noop());
            drop(device.fd.readable().await.unwrap());
            let mut next = Box::pin(device.next_event());
            let first_poll = next.as_mut().poll(&mut cx);
            assert!(
                first_poll.is_pending(),
                "must yield before the trailing STOP"
            );
            assert!(matches!(next.await.unwrap(), UhidEvent::Stop));
            if event_type != UHID_OUTPUT {
                for _ in 0..EVENTS_PER_YIELD {
                    let mut reply = [0u8; UHID_EVENT_SIZE];
                    assert_eq!(writer.recv(&mut reply).unwrap(), UHID_EVENT_SIZE);
                    let reply_type = u32::from_le_bytes(reply[..4].try_into().unwrap());
                    assert_eq!(
                        reply_type,
                        if event_type == UHID_GET_REPORT {
                            UHID_GET_REPORT_REPLY
                        } else {
                            UHID_SET_REPORT_REPLY
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn output_report_accepts_64_and_65_bytes() {
        let bare = [7u8; 64];
        assert_eq!(report_from_output(&bare), Some(bare));
        let mut prefixed = vec![0u8];
        prefixed.extend_from_slice(&bare);
        assert_eq!(report_from_output(&prefixed), Some(bare));
        assert_eq!(report_from_output(&[1u8; 65]), None, "non-zero report id");
        assert_eq!(report_from_output(&[1u8; 10]), None);
    }
}
