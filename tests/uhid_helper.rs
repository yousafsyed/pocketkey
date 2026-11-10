//! End-to-end check of the privileged-helper handshake without `/dev/uhid`
//! or root: a stand-in for the device node records what the helper writes.

use std::fs::File;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;

use pocketkey::uhid::helper::{self, REPLY_DEVICE, REQUEST_DEVICE};

/// A regular file stands in for `/dev/uhid`: the helper's `UHID_CREATE2`
/// write lands in it, so the test can verify exactly what a client's
/// descriptor refers to.
fn fake_uhid() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pocketkey-fake-uhid-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    File::create(&path).unwrap();
    path
}

#[test]
fn helper_creates_device_and_hands_descriptor_to_client() {
    let node = fake_uhid();
    let (client, server) = UnixStream::pair().unwrap();

    // Client side, as the daemon does it.
    helper::send_byte(&client, REQUEST_DEVICE, None).unwrap();

    // Helper side.
    let (code, extra) = helper::recv_byte(&server).unwrap();
    assert_eq!(code, REQUEST_DEVICE);
    assert!(extra.is_none(), "clients never send descriptors");
    let device = helper::create_device_for_client(&node).unwrap();
    helper::send_byte(&server, REPLY_DEVICE, Some(&device)).unwrap();
    drop(device);

    // Client receives a descriptor to a node where CREATE2 was already issued.
    let (reply, fd) = helper::recv_byte(&client).unwrap();
    assert_eq!(reply, REPLY_DEVICE);
    let _received = File::from(fd.expect("device descriptor"));

    let mut written = Vec::new();
    File::open(&node)
        .unwrap()
        .read_to_end(&mut written)
        .unwrap();
    assert_eq!(written.len(), 4376, "exactly one struct uhid_event");
    assert_eq!(
        u32::from_le_bytes(written[..4].try_into().unwrap()),
        11,
        "UHID_CREATE2"
    );
    // The report descriptor is the fixed FIDO one and nothing else: a client
    // cannot turn this device into a keyboard.
    let rd_data = 280;
    assert_eq!(
        &written[rd_data..rd_data + 34],
        &pocketkey::uhid::FIDO_REPORT_DESCRIPTOR
    );
    // rd_size follows name(128) + phys(64) + uniq(64) after the 4-byte type.
    let rd_size = 4 + 128 + 64 + 64;
    assert_eq!(
        u16::from_le_bytes([written[rd_size], written[rd_size + 1]]),
        34,
        "rd_size"
    );
    let _ = std::fs::remove_file(&node);
}

#[test]
fn client_request_fails_cleanly_when_helper_is_absent() {
    let err = helper::request_device(Path::new("/run/pocketkey-definitely-missing/uhid.sock"))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
