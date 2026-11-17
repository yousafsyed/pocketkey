//! Privileged helper: the only part of pocketkey that touches `/dev/uhid`.
//!
//! systemd socket-activates this as root on `/run/pocketkey/uhid.sock`. A
//! connecting user daemon sends one request byte; the helper creates the
//! virtual FIDO device (fixed report descriptor, fixed VID/PID), keeps the
//! `/dev/uhid` descriptor, and passes the daemon one end of a seqpacket
//! socketpair. A relay thread then shuttles `struct uhid_event`s between the
//! two: everything from the kernel goes to the daemon; from the daemon only
//! `UHID_INPUT2`, `UHID_GET_REPORT_REPLY` and `UHID_SET_REPORT_REPLY` reach
//! the kernel, and anything else ends the session.
//!
//! The daemon therefore never holds a `/dev/uhid` descriptor. It cannot send
//! `UHID_DESTROY` + `UHID_CREATE2` to turn the device into a keyboard or
//! anything else (the kernel performs no credential check on those; see
//! issue #4). When the daemon closes its end the helper closes `/dev/uhid`
//! and the kernel removes the device.
//!
//! Policy: members of the `pocketkey` group (enforced by the socket unit's
//! `0660 root:pocketkey`) may request a device, one per uid at a time. The
//! helper inspects only the 4-byte event type of daemon traffic; it does no
//! parsing of report contents, no networking and no CTAP.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pocketkey::uhid::helper::{
    self, RelayEnd, REPLY_BUSY, REPLY_DEVICE, REPLY_ERROR, REQUEST_CHANNEL, SOCKET_PATH,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const UHID_PATH: &str = "/dev/uhid";
/// Idle exit so the privileged process is not resident between logins;
/// systemd restarts it on the next connection. Only taken when no device is
/// alive, since the helper now holds every device's `/dev/uhid` descriptor.
const IDLE_EXIT: Duration = Duration::from_secs(60);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound concurrent handling so a flood of connections cannot exhaust the helper.
const MAX_ACTIVE_CLIENTS: usize = 16;

fn main() {
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("pocketkey-uhid-helper {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listener = match activated_listener() {
        Ok(Some(listener)) => listener,
        Ok(None) => {
            eprintln!("pocketkey-uhid-helper must be socket-activated by systemd ({SOCKET_PATH})");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("pocketkey-uhid-helper: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = serve(listener) {
        warn!(error = %e, "helper exiting on error");
        std::process::exit(1);
    }
}

/// Devices currently alive, keyed by uid. A device is released when its
/// relay ends, i.e. when the daemon closes its channel (exit or crash) or
/// misbehaves, so a crashed daemon does not lock its user out.
type Active = Arc<Mutex<HashMap<u32, ()>>>;

fn serve(listener: UnixListener) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let active: Active = Arc::new(Mutex::new(HashMap::new()));
    let in_flight = Arc::new(Mutex::new(0usize));
    let mut idle_since = std::time::Instant::now();
    info!(socket = SOCKET_PATH, "pocketkey uhid helper ready");
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                idle_since = std::time::Instant::now();
                let mut count = in_flight.lock().unwrap_or_else(|p| p.into_inner());
                if *count >= MAX_ACTIVE_CLIENTS {
                    drop(count);
                    let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
                    let _ = helper::send_byte(&stream, REPLY_BUSY, None);
                    continue;
                }
                *count += 1;
                drop(count);
                let active = Arc::clone(&active);
                let in_flight = Arc::clone(&in_flight);
                std::thread::spawn(move || {
                    handle_client(stream, &active);
                    let mut count = in_flight.lock().unwrap_or_else(|p| p.into_inner());
                    *count = count.saturating_sub(1);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let busy = *in_flight.lock().unwrap_or_else(|p| p.into_inner()) > 0;
                if !busy && idle_since.elapsed() >= IDLE_EXIT {
                    info!("idle; exiting until the next connection");
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(e),
        }
    }
}

/// One thread per client, alive for as long as its device. The request
/// socket is only used for the handshake; the device's lifetime is tied to
/// the channel.
fn handle_client(stream: UnixStream, active: &Active) {
    let _ = stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
    let uid = match helper::peer_uid(&stream) {
        Ok(uid) => uid,
        Err(e) => {
            warn!(error = %e, "could not read peer credentials; refusing");
            return;
        }
    };
    let request = match helper::recv_byte(&stream) {
        Ok((code, extra_fd)) => {
            // Clients never send descriptors; close anything attached.
            drop(extra_fd);
            code
        }
        Err(e) => {
            warn!(uid, error = %e, "bad request from client");
            return;
        }
    };
    if request != REQUEST_CHANNEL {
        warn!(
            uid,
            request, "unknown request code (daemon and helper versions must match)"
        );
        let _ = helper::send_byte(&stream, REPLY_ERROR, None);
        return;
    }

    {
        let mut map = active.lock().unwrap_or_else(|p| p.into_inner());
        if map.contains_key(&uid) {
            info!(uid, "device already active for this user");
            let _ = helper::send_byte(&stream, REPLY_BUSY, None);
            return;
        }
        map.insert(uid, ());
    }

    let (uhid, helper_end) = match set_up_device(&stream, uid) {
        Some(pair) => pair,
        None => {
            release(active, uid);
            return;
        }
    };
    // The handshake is over; the request socket plays no further part.
    drop(stream);
    info!(uid, "virtual FIDO device created; relaying for user daemon");

    let end = helper::relay(&uhid, &helper_end);
    match end {
        RelayEnd::DaemonClosed => info!(uid, "user daemon disconnected"),
        RelayEnd::DaemonViolation(ty) => {
            warn!(
                uid,
                event_type = ty,
                "daemon sent a forbidden uhid event; disconnecting"
            )
        }
        RelayEnd::KernelClosed => warn!(uid, "kernel closed the uhid device"),
        RelayEnd::Io(kind) => warn!(uid, error = ?kind, "relay failed"),
    }
    // Closing /dev/uhid destroys the device.
    drop(uhid);
    drop(helper_end);
    release(active, uid);
    info!(uid, "device destroyed; slot released");
}

/// Create the device and hand the daemon its channel end. Returns what the
/// relay needs, or `None` after telling the client why.
fn set_up_device(stream: &UnixStream, uid: u32) -> Option<(File, OwnedFd)> {
    let uhid = match helper::create_device(Path::new(UHID_PATH)) {
        Ok(file) => file,
        Err(e) => {
            warn!(uid, error = %e, "creating the uhid device failed");
            let _ = helper::send_byte(stream, REPLY_ERROR, None);
            return None;
        }
    };
    let (helper_end, daemon_end) = match helper::channel_pair() {
        Ok(pair) => pair,
        Err(e) => {
            warn!(uid, error = %e, "creating the event channel failed");
            let _ = helper::send_byte(stream, REPLY_ERROR, None);
            return None;
        }
    };
    let daemon_file = File::from(daemon_end);
    if let Err(e) = helper::send_byte(stream, REPLY_DEVICE, Some(&daemon_file)) {
        warn!(uid, error = %e, "could not pass the channel to the client");
        return None;
    }
    // Our copy of the daemon's end closes here so that the daemon dropping
    // its descriptor is seen as EOF by the relay.
    drop(daemon_file);
    Some((uhid, helper_end))
}

fn release(active: &Active, uid: u32) {
    active
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&uid);
}

/// systemd passes activated sockets starting at fd 3 with LISTEN_FDS set.
fn activated_listener() -> io::Result<Option<UnixListener>> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p == std::process::id());
    let count = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    if !pid_ok || count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("expected exactly one activated socket, got {count}"),
        ));
    }
    // SAFETY: systemd guarantees fd 3 is the activated listening socket and
    // nothing else in this process owns it.
    let owned = unsafe { OwnedFd::from_raw_fd(3) };
    let as_file = File::from(owned);
    let fd = as_file.as_raw_fd();
    std::mem::forget(as_file);
    // SAFETY: ownership of fd 3 transfers exactly once into the listener.
    Ok(Some(unsafe { UnixListener::from_raw_fd(fd) }))
}
