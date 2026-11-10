//! Privileged helper: the only part of pocketkey that touches `/dev/uhid`.
//!
//! systemd socket-activates this as root on `/run/pocketkey/uhid.sock`. A
//! connecting user daemon sends one request byte; the helper creates the
//! virtual FIDO device (fixed report descriptor, fixed VID/PID) and passes the
//! `/dev/uhid` descriptor back over the socket, then closes its own copy. The
//! user session therefore never gets access to `/dev/uhid` and cannot create
//! arbitrary input devices: a uhid descriptor only emits input reports for the
//! device it already created, and that device is a FIDO key.
//!
//! Policy: any local user may request a device, one device per uid at a time.
//! The helper does no parsing of structured data, no networking and no CTAP.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pocketkey::uhid::helper::{
    self, REPLY_BUSY, REPLY_DEVICE, REPLY_ERROR, REQUEST_DEVICE, SOCKET_PATH,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const UHID_PATH: &str = "/dev/uhid";
/// Idle exit so the privileged process is not resident between logins;
/// systemd restarts it on the next connection.
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

/// Devices currently handed out, keyed by uid. A device is released when the
/// client's socket closes (the daemon exited) so a crashed daemon does not
/// lock its user out.
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
    if request != REQUEST_DEVICE {
        warn!(uid, request, "unknown request code");
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

    let outcome = helper::create_device_for_client(Path::new(UHID_PATH));
    match outcome {
        Ok(device) => {
            if let Err(e) = helper::send_byte(&stream, REPLY_DEVICE, Some(&device)) {
                warn!(uid, error = %e, "could not pass the device to the client");
                release(active, uid);
                return;
            }
            // Our copy closes here; the client's descriptor keeps the device alive.
            drop(device);
            info!(uid, "virtual FIDO device handed to user daemon");
            // Hold the per-uid slot until the client's socket closes (its exit),
            // then let the user request a fresh device.
            wait_for_close(&stream);
            release(active, uid);
            info!(uid, "user daemon disconnected; device slot released");
        }
        Err(e) => {
            warn!(uid, error = %e, "creating the uhid device failed");
            let _ = helper::send_byte(&stream, REPLY_ERROR, None);
            release(active, uid);
        }
    }
}

fn release(active: &Active, uid: u32) {
    active
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&uid);
}

/// Block until the peer closes. The client sends nothing further, so any
/// readable event means EOF (or an error), both of which end the session.
fn wait_for_close(stream: &UnixStream) {
    let _ = stream.set_read_timeout(None);
    let mut pollfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
    loop {
        // SAFETY: pollfd is a valid single-element array for the call.
        let rc = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if rc > 0 {
            return;
        }
    }
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
