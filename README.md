# pocketkey

A virtual FIDO2 USB security key for Linux whose "key" is your phone.

pocketkey creates a virtual USB HID security key via `/dev/uhid`. Browsers
and tools see an ordinary CTAP2 key. When one asks it to sign in or register,
pocketkey forwards the request to your phone over the WebAuthn **hybrid**
transport (the "use a passkey from a nearby device" flow: QR code, Bluetooth
LE proximity check, encrypted tunnel), and hands the phone's answer back.

The point: Firefox on Linux has no hybrid support
([Mozilla bug 1543674](https://bugzilla.mozilla.org/show_bug.cgi?id=1543674)),
so passkeys stored in Google Password Manager on an Android phone (or in
iCloud Keychain) cannot be used from Firefox. With pocketkey, Firefox's
"use your security key" path works with them. Anything else that talks to USB
security keys (Chrome, `libfido2`, `ssh-sk`) works too.

**Mental model:** wrap the transport Firefox lacks (hybrid) inside the
transport Firefox already supports (CTAPHID over USB HID).

## How it works

```
Firefox ──hidraw──▶ /dev/uhid ──▶ pocketkey ──BLE + wss tunnel──▶ phone
            CTAPHID              CTAP2 CBOR        hybrid/caBLE      (authenticator)
```

1. pocketkey registers a HID device with the FIDO usage page. Firefox finds it
   like any security key and performs `CTAPHID_INIT` and `authenticatorGetInfo`.
   Both are answered locally.
2. When `getAssertion` or `makeCredential` arrives, a small window opens. If a
   phone was linked before, it gets a push notification ("check your phone");
   otherwise a QR code is shown. The phone scans it, advertises over BLE to
   prove it is nearby, and both sides connect through a tunnel server with
   end-to-end encryption (Noise). This is the `pxp` crate from the
   [libwebauthn](https://github.com/linux-credentials/libwebauthn) project.
3. The CTAP2 request is forwarded to the phone, which prompts for biometrics
   and returns the assertion / attestation. The response bytes go back to
   Firefox unchanged. The only change made to a request is re-encoding its
   CBOR in canonical key order: Firefox writes some maps out of order and
   Android's hybrid authenticator rejects those outright; values such as
   `clientDataHash` and credential ids are preserved exactly. pocketkey never
   sees or stores a private key.
4. If the phone sends linking data after a QR session, pocketkey stores it so
   the next request needs no QR. Several phones can be linked. (Current
   Android/Google Password Manager phones do not send it; see "Use".)

## Requirements

- Ubuntu 24.04 or newer, x86_64, a desktop session (Wayland or X11).
- A working **Bluetooth adapter** (BlueZ). The hybrid protocol requires a BLE
  proximity check; pocketkey refuses requests if no adapter is present.
- **Firefox from the `.deb` on packages.mozilla.org, not the snap.** The snap's
  `u2f-devices` interface only exposes security keys from an allow-list of
  vendor IDs, so a snap Firefox never sees pocketkey's device. See
  [Mozilla's instructions](https://support.mozilla.org/kb/install-firefox-linux#w_install-firefox-deb-package-for-debian-based-distributions)
  for switching.
- An Android phone with passkeys in Google Password Manager (tested), or an
  iPhone with iCloud Keychain (should work, untested).

## Install

From source:

```sh
sudo apt install build-essential pkg-config libdbus-1-dev     # build deps
sudo apt install fido2-tools                                   # optional, for testing
cargo build --release    # as your user
sudo make install        # /usr/local/bin/pocketkey + udev rule for /dev/uhid
make install-user        # systemd user service, enabled and started
```

Or build a `.deb`: `make deb` (needs `devscripts`, `debhelper`, `cargo`), then
`sudo apt install ../pocketkey_*.deb` and `systemctl --user enable --now pocketkey`.

On a machine without `libdbus-1-dev`, `cargo build --features vendored-dbus`
compiles libdbus from source instead.

Check it is alive:

```sh
systemctl --user status pocketkey
fido2-token -L                     # should list "pocketkey virtual FIDO key"
fido2-token -I /dev/hidrawN        # getInfo: FIDO_2_0/2_1, rk/up/uv, no clientPin
```

## Use

In Firefox, on a site that offers passkeys, choose "security key" / "use a
different device" if asked. The pocketkey window appears:

- **First time:** scan the QR code with the phone's camera, approve on the
  phone. The phone is now linked.
- **Afterwards:** if the phone sent linking data, it gets a notification
  instead and the QR is only a fallback after 10 seconds. **Android with
  Google Password Manager currently does not send linking data** (Google
  retired phone linking in 2024 in favour of passkey sync), so expect a QR
  code every time with such phones.

Cancel from the window, from Firefox's dialog, or on the phone.

## Security notes

- pocketkey is a **proxy**. Origin and RP ID checks, challenge binding and
  user verification happen in the browser and on the phone exactly as with a
  real security key plus a real hybrid session. pocketkey does not parse or
  modify credentials, `clientDataHash`, or attestation.
- Nothing secret about your accounts is stored on the PC. The **linking data**
  (`~/.local/share/pocketkey/linked_devices.cbor`, mode 0600) is sensitive in
  a different way: whoever holds it can make your phone pop up a passkey
  prompt without a QR scan. The phone still requires your biometrics. Delete
  the file to unlink all phones (or unlink from the phone's passkey settings).
- The install loads the `uhid` kernel module at boot and the udev rule grants
  the active desktop session access to `/dev/uhid`, i.e.
  any program in your session may create virtual input devices. That is
  the trade-off for running without root.
- Logs never include request payloads, credential IDs or linking secrets at
  `info` level. `RUST_LOG=debug` adds lengths and state transitions, not data.

## Limitations

- **Firefox pre-flight is answered locally.** When a site supplies an
  allowList (or excludeList), Firefox first sends a *silent* `getAssertion`
  (`up: false`) to learn which of those credentials the key holds, and gives
  up if none are confirmed. A phone cannot answer silent requests, so
  pocketkey confirms every credential the site listed (placeholder authData,
  empty signature, nothing signed or invented) and the phone then decides on
  the real request. Consequence: if none of the listed credentials is on your
  phone, you find out on the phone instead of Firefox saying so up front.
- No U2F/CTAP1, no PIN, no credential management, no NFC. `getNextAssertion`
  is only served for the local pre-flight answer above; phones return a
  single assertion.
- Only the cloud-assisted tunnel (caBLE v2) is advertised in the QR for
  compatibility with current Android builds; direct BLE L2CAP is not used.

## Troubleshooting

```sh
journalctl --user -u pocketkey -f        # daemon log; RUST_LOG=debug for more
fido2-token -L                           # is the virtual key visible?
bluetoothctl show                        # is an adapter present and Powered: yes?
getfacl /dev/uhid                        # should list your user after `make install`
cargo run --example hidclient            # INIT + getInfo + PING through hidraw
```

- *"permission denied: /dev/uhid"*: the `uhid` kernel module must be loaded
  (`lsmod | grep uhid`; `sudo make install` adds it to `modules-load.d` and
  loads it) and the udev rule applied:
  `sudo udevadm trigger --action=add /sys/class/misc/uhid`. The ACL is given
  to the active desktop session, so log out and in if it still fails.
- *Firefox shows nothing*: confirm Firefox is not the snap (`snap list firefox`
  must be empty) and that `fido2-token -L` lists the device.
- *QR never completes*: both devices need internet access (tunnel server) and
  the PC needs Bluetooth on. Check `bluetoothctl show` for `Powered: yes`.
- *Phone says "something went wrong" after success*: pocketkey sends a tunnel
  shutdown after each request; if you see this, please file an issue with
  `RUST_LOG=debug` logs.

## Development

```sh
cargo test                                  # unit tests (CTAPHID state machine, getInfo, store, uhid layout)
cargo clippy --all-targets -- -D warnings
cargo run --example ui_demo                 # exercise the window without a phone
```

Layout: `src/uhid.rs` (kernel interface), `src/ctaphid.rs` (pure transport
state machine), `src/ctap2.rs` (command dispatch and getInfo),
`src/hybrid/` (phone transport over `pxp`, linked-device store), `src/ui.rs`
(egui window), `src/main.rs` (wiring). See `PLAN.md` for design decisions and
`TESTING.md` for the manual test plan.

## License

MIT or Apache-2.0, at your option.
