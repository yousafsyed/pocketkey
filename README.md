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
3. The CTAP2 request bytes are forwarded **unchanged** to the phone, which
   prompts for biometrics and returns the assertion / attestation. Those bytes
   go back to Firefox unchanged. pocketkey never sees or stores a private key.
4. The phone sends linking data after a QR session; pocketkey stores it so the
   next request needs no QR. Several phones can be linked.

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
- **Afterwards:** the phone gets a notification; approve there. If the phone
  does not answer within 10 seconds, the QR code appears as a fallback.

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
- The udev rule grants the active desktop session access to `/dev/uhid`, i.e.
  any program in your session may create virtual input devices. That is
  the trade-off for running without root.
- Logs never include request payloads, credential IDs or linking secrets at
  `info` level. `RUST_LOG=debug` adds lengths and state transitions, not data.

## Limitations

- **allowList pre-flight in Firefox.** Firefox probes security keys with a
  silent `getAssertion` (`up: false`) when a site supplies an allowList.
  Phones cannot answer silently, so the probe is forwarded as a normal request
  and the phone prompts twice on such sites. Passkey (discoverable credential)
  logins, the common case, prompt once.
- No U2F/CTAP1, no PIN, no credential management, no NFC. `getNextAssertion`
  returns `CTAP2_ERR_NOT_ALLOWED` (phones return a single assertion).
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

- *"permission denied: /dev/uhid"*: install the udev rule (`sudo make install`)
  and run `sudo udevadm trigger --name-match=uhid`, or log out and in.
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
