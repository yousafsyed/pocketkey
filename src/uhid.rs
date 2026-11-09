//! Virtual HID device over `/dev/uhid`.
//!
//! The uhid ABI (`linux/uhid.h`) is a single packed `struct uhid_event`
//! (`u32 type` followed by a union of request structs) written to and read
//! from the character device. We lay the few events we need out by hand so
//! the build needs no bindgen or system headers. Layout constants are checked
//! by unit tests against the values from the kernel header.
//!
//! Lifecycle: write `UHID_CREATE2`, then the kernel sends `UHID_START`,
//! `UHID_OPEN` when a program opens the hidraw node, `UHID_OUTPUT` for each
//! report the host writes, `UHID_CLOSE`/`UHID_STOP` on the way down. We send
//! `UHID_INPUT2` for each report to the host and `UHID_DESTROY` on shutdown.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
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
    fd: AsyncFd<File>,
    destroyed: bool,
}

impl UhidDevice {
    /// Open `/dev/uhid` and create the virtual FIDO device.
    pub fn create() -> io::Result<Self> {
        Self::create_at(Path::new("/dev/uhid"))
    }

    pub fn create_at(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "{}: permission denied. Run `sudo make install` (installs the udev rule \
                             and loads the uhid module), then `sudo modprobe uhid && sudo udevadm \
                             trigger --action=add /sys/class/misc/uhid`; log out and in if needed",
                            path.display()
                        ),
                    )
                } else {
                    e
                }
            })?;

        // SAFETY: `file` owns the descriptor for the lifetime of the AsyncFd
        // and nothing else closes or duplicates it (the I/O-safety contract
        // `register` asks the caller to uphold).
        let fd = unsafe { AsyncFd::register(file)? };
        let mut dev = Self {
            fd,
            destroyed: false,
        };
        dev.write_event(&create2_event())?;
        debug!(
            name = DEVICE_NAME,
            vid = VENDOR_ID,
            pid = PRODUCT_ID,
            "uhid device created"
        );
        Ok(dev)
    }

    /// Wait for the next event that matters to the caller. `UHID_START` and
    /// report queries are handled internally.
    pub async fn next_event(&mut self) -> io::Result<UhidEvent> {
        loop {
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

    /// Tear the device down. Idempotent; also called from `Drop`.
    pub fn destroy(&mut self) -> io::Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        let mut ev = [0u8; UHID_EVENT_SIZE];
        ev[..4].copy_from_slice(&UHID_DESTROY.to_le_bytes());
        self.write_event(&ev)?;
        debug!("uhid device destroyed");
        Ok(())
    }

    /// uhid writes never block (the kernel copies the event synchronously),
    /// so a plain write on the non-blocking fd is fine.
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

impl Drop for UhidDevice {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            warn!(error = %e, "failed to destroy uhid device");
        }
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
