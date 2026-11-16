//! End-to-end check of the privileged-helper handshake and relay without
//! `/dev/uhid` or root: a seqpacket socketpair stands in for the device node,
//! with one end playing the kernel.

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use pocketkey::uhid::helper::{self, RelayEnd, REPLY_DEVICE, REQUEST_CHANNEL};
use pocketkey::uhid::UhidDevice;

const UHID_EVENT_SIZE: usize = 4376;
const UHID_DESTROY: u32 = 1;
const UHID_STOP: u32 = 3;
const UHID_OUTPUT: u32 = 6;
const UHID_INPUT2: u32 = 12;

fn send(fd: &impl AsRawFd, data: &[u8]) {
    // SAFETY: data is valid for its length; fd is open.
    let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr() as *const _, data.len()) };
    assert_eq!(n as usize, data.len());
}

fn recv(fd: &impl AsRawFd) -> Vec<u8> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: single valid pollfd.
    assert!(unsafe { libc::poll(&mut pfd, 1, 5000) } > 0, "timed out");
    let mut buf = vec![0u8; UHID_EVENT_SIZE];
    // SAFETY: buf is valid for its length.
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
    assert!(n >= 0);
    buf.truncate(n as usize);
    buf
}

fn event(ty: u32) -> [u8; UHID_EVENT_SIZE] {
    let mut ev = [0u8; UHID_EVENT_SIZE];
    ev[..4].copy_from_slice(&ty.to_le_bytes());
    ev
}

/// Run the helper side of the protocol exactly as the binary does, with
/// `uhid` standing in for the just-created device. Returns the relay's
/// outcome once the session ends.
fn helper_side(server: UnixStream, uhid: File) -> std::thread::JoinHandle<RelayEnd> {
    std::thread::spawn(move || {
        let (code, extra) = helper::recv_byte(&server).unwrap();
        assert_eq!(code, REQUEST_CHANNEL);
        assert!(extra.is_none(), "clients never send descriptors");
        let (helper_end, daemon_end) = helper::channel_pair().unwrap();
        let daemon_file = File::from(daemon_end);
        helper::send_byte(&server, REPLY_DEVICE, Some(&daemon_file)).unwrap();
        drop(daemon_file);
        drop(server);
        helper::relay(&uhid, &helper_end)
    })
}

fn client_side(client: &UnixStream) -> OwnedFd {
    helper::send_byte(client, REQUEST_CHANNEL, None).unwrap();
    let (reply, fd) = helper::recv_byte(client).unwrap();
    assert_eq!(reply, REPLY_DEVICE);
    fd.expect("channel descriptor")
}

#[test]
fn daemon_exchanges_reports_through_the_helper() {
    let (uhid, kernel) = helper::channel_pair().unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    let helper = helper_side(server, File::from(uhid));
    let channel = client_side(&client);

    // Kernel -> daemon: an output report arrives unchanged.
    let mut out = event(UHID_OUTPUT);
    out[4..8].copy_from_slice(b"host");
    send(&kernel, &out);
    assert_eq!(recv(&channel), out.to_vec());

    // Daemon -> kernel: an input report passes the allowlist.
    let mut inp = event(UHID_INPUT2);
    inp[6..10].copy_from_slice(b"ctap");
    send(&channel, &inp);
    assert_eq!(recv(&kernel), inp.to_vec());

    drop(channel);
    assert_eq!(helper.join().unwrap(), RelayEnd::DaemonClosed);
}

#[test]
fn daemon_cannot_destroy_or_recreate_the_device() {
    let (uhid, kernel) = helper::channel_pair().unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    let helper = helper_side(server, File::from(uhid));
    let channel = client_side(&client);

    send(&channel, &event(UHID_DESTROY));
    assert_eq!(
        helper.join().unwrap(),
        RelayEnd::DaemonViolation(UHID_DESTROY)
    );

    // The relay dropped its uhid end without forwarding anything, so the
    // kernel side reads straight to EOF.
    assert!(recv(&kernel).is_empty(), "DESTROY reached the kernel");
}

#[tokio::test]
async fn uhid_device_runs_on_the_channel_and_closes_it_on_destroy() {
    use pocketkey::uhid::UhidEvent;

    let (uhid, kernel) = helper::channel_pair().unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    let helper = helper_side(server, File::from(uhid));
    let channel = client_side(&client);
    let mut device = UhidDevice::from_channel(channel).unwrap();

    let mut out = event(UHID_OUTPUT);
    out[4..68].copy_from_slice(&[0xAB; 64]);
    out[4100..4102].copy_from_slice(&64u16.to_le_bytes());
    out[4102] = 1;
    send(&kernel, &out);
    match device.next_event().await.unwrap() {
        UhidEvent::Output(report) => assert_eq!(report, [0xAB; 64]),
        other => panic!("unexpected {other:?}"),
    }

    device.send_report(&[0xCD; 64]).unwrap();
    let got = recv(&kernel);
    assert_eq!(
        u32::from_le_bytes(got[..4].try_into().unwrap()),
        UHID_INPUT2
    );
    assert_eq!(&got[6..70], &[0xCD; 64]);

    send(&kernel, &event(UHID_STOP));
    assert!(matches!(
        device.next_event().await.unwrap(),
        UhidEvent::Stop
    ));

    device.destroy().unwrap();
    device.destroy().unwrap();
    assert_eq!(helper.join().unwrap(), RelayEnd::DaemonClosed);
}

#[test]
fn client_request_fails_cleanly_when_helper_is_absent() {
    let err = helper::request_device(Path::new("/run/pocketkey-definitely-missing/uhid.sock"))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
