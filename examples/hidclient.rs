//! Minimal CTAPHID client for checking the daemon without libfido2.
//!
//! Finds the hybridkey hidraw node (or takes a path as argument), sends
//! `CTAPHID_INIT` on the broadcast channel, then `authenticatorGetInfo`, and
//! prints the decoded replies.
//!
//! ```sh
//! cargo run --example hidclient [/dev/hidrawN]
//! ```

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const REPORT: usize = 64;
const BROADCAST: [u8; 4] = [0xFF; 4];

fn find_device() -> Option<PathBuf> {
    for entry in fs::read_dir("/sys/class/hidraw").ok()?.flatten() {
        let uevent = fs::read_to_string(entry.path().join("device/uevent")).unwrap_or_default();
        // HID_ID=0003:00001209:00000001
        if uevent
            .lines()
            .any(|l| l.starts_with("HID_ID=") && l.ends_with(":00001209:00000001"))
        {
            return Some(PathBuf::from("/dev").join(entry.file_name()));
        }
    }
    None
}

fn write_report(f: &mut fs::File, report: &[u8; REPORT]) {
    // hidraw write: leading report id byte (0 = no report ids), then the report.
    let mut buf = vec![0u8];
    buf.extend_from_slice(report);
    f.write_all(&buf).expect("write report");
}

fn read_message(f: &mut fs::File, cid: &[u8; 4]) -> (u8, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut r = [0u8; REPORT];
        f.read_exact(&mut r).expect("read report");
        if &r[..4] != cid || r[4] & 0x80 == 0 {
            continue;
        }
        let cmd = r[4] & 0x7F;
        let total = u16::from_be_bytes([r[5], r[6]]) as usize;
        if cmd == 0x3B {
            println!("  keepalive status {}", r[7]);
            assert!(Instant::now() < deadline, "timed out waiting for response");
            continue;
        }
        let mut payload = r[7..].to_vec();
        let mut seq = 0u8;
        while payload.len() < total {
            let mut c = [0u8; REPORT];
            f.read_exact(&mut c).expect("read continuation");
            assert_eq!(&c[..4], cid);
            assert_eq!(c[4], seq, "sequence");
            seq += 1;
            payload.extend_from_slice(&c[5..]);
        }
        payload.truncate(total);
        return (cmd, payload);
    }
}

fn main() {
    let path = std::env::args().nth(1).map(PathBuf::from).or_else(find_device).unwrap_or_else(|| {
        eprintln!("hybridkey hidraw device not found; is the daemon running? (pass /dev/hidrawN explicitly)");
        std::process::exit(1);
    });
    println!("device: {}", path.display());
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open hidraw");

    // CTAPHID_INIT
    let nonce = [0xA5, 0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let mut init = [0u8; REPORT];
    init[..4].copy_from_slice(&BROADCAST);
    init[4] = 0x86;
    init[6] = 8;
    init[7..15].copy_from_slice(&nonce);
    write_report(&mut f, &init);
    let (cmd, payload) = read_message(&mut f, &BROADCAST);
    assert_eq!(cmd, 0x06, "expected INIT response");
    assert_eq!(&payload[..8], &nonce, "nonce mismatch");
    let cid: [u8; 4] = payload[8..12].try_into().unwrap();
    println!(
        "INIT ok: cid={:02x?} protocol={} version={}.{}.{} caps=0x{:02x}",
        cid, payload[12], payload[13], payload[14], payload[15], payload[16]
    );

    // authenticatorGetInfo
    let mut req = [0u8; REPORT];
    req[..4].copy_from_slice(&cid);
    req[4] = 0x90; // CBOR
    req[6] = 1;
    req[7] = 0x04;
    write_report(&mut f, &req);
    let (cmd, payload) = read_message(&mut f, &cid);
    assert_eq!(cmd, 0x10, "expected CBOR response");
    println!("getInfo status=0x{:02x}", payload[0]);
    let info: ciborium::Value = ciborium::from_reader(&payload[1..]).expect("cbor");
    println!("{info:#?}");

    // PING round trip with a multi-packet payload
    let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let mut ping = [0u8; REPORT];
    ping[..4].copy_from_slice(&cid);
    ping[4] = 0x81;
    ping[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    ping[7..].copy_from_slice(&data[..57]);
    write_report(&mut f, &ping);
    for (seq, chunk) in data[57..].chunks(59).enumerate() {
        let mut c = [0u8; REPORT];
        c[..4].copy_from_slice(&cid);
        c[4] = seq as u8;
        c[5..5 + chunk.len()].copy_from_slice(chunk);
        write_report(&mut f, &c);
    }
    let (cmd, payload) = read_message(&mut f, &cid);
    assert_eq!((cmd, payload), (0x01, data));
    println!("PING ok (200 bytes, 4 packets)");
}
