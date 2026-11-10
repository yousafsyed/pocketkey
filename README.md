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
            CTAPHID        ▲     CTAP2 CBOR        hybrid/caBLE      (authenticator)
                           │ fd (SCM_RIGHTS)
              pocketkey-uhid-helper (root, socket-activated, creates the device)
```

1. A tiny root helper (`pocketkey-uhid-helper`, socket-activated by systemd)
   creates the virtual HID device with the FIDO usage page and passes the
   `/dev/uhid` descriptor to the user daemon. The user session never gets
   access to `/dev/uhid` itself, so nothing in it can create other virtual
   input devices. Firefox finds the key like any security key and performs
   `CTAPHID_INIT` and `authenticatorGetInfo`. Both are answered locally.
2. When `getAssertion` or `makeCredential` arrives, a small window opens. If a
   phone was linked before, it gets a push notification ("check your phone");
   otherwise a QR code is shown. The phone scans it, advertises over BLE to
   prove it is nearby, and both sides connect through a tunnel server with
   end-to-end encryption (Noise). This is the `pxp` crate from the
   [libwebauthn](https://github.com/linux-credentials/libwebauthn) project.
3. The CTAP2 request is forwarded to the phone, which prompts for biometrics
   and returns the assertion / attestation. The response bytes go back to
   Firefox unchanged. Requests are forwarded with two small adjustments
   that strict phones need: the CBOR is re-encoded in canonical key order
   (Firefox writes some maps out of order and Android rejects those), and
   for registration the display labels Firefox leaves out are filled in
   (`rp.name` = `rp.id`, `user.displayName` = `user.name`; iPhones reject a
   request without them) while the legacy `hmac-secret: false` input is dropped.
   Other extension values, `clientDataHash`, ids, algorithms and options are
   preserved exactly. pocketkey never sees or stores a passkey private key.
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
- An Android phone with passkeys in Google Password Manager, or an iPhone
  with iCloud Keychain. Both are tested with Firefox and Chrome for
  registration and sign-in.

## Install

From source:

```sh
sudo apt install build-essential pkg-config libdbus-1-dev     # build deps
sudo apt install fido2-tools                                   # optional, for testing
cargo build --release    # as your user
sudo make install        # binaries + root uhid helper (socket-activated)
make install-user        # systemd user service, enabled and started
```

Or install the `.deb` from the [latest release](https://github.com/yousafsyed/pocketkey/releases/latest)
(built on Ubuntu 24.04, works on 24.04 and newer):

```sh
sudo apt install ./pocketkey_*_amd64.deb
systemctl --user start pocketkey      # starts automatically at your next login
```

To build the package yourself: `make deb` (needs `debhelper`, `dpkg-dev`,
`libdbus-1-dev` and a rustup toolchain ≥ 1.88); the result lands in the
parent directory. Releases are automated: every push to `main` bumps the
version from the commit messages (`feat:` → minor, `feat!:`/`BREAKING CHANGE`
→ major, otherwise patch), tags it, and publishes the `.deb` on GitHub.

On a machine without `libdbus-1-dev`, `cargo build --features vendored-dbus`
compiles libdbus from source instead.

Check it is alive:

```sh
systemctl status pocketkey-uhid.socket   # root helper socket, listening
systemctl --user status pocketkey
fido2-token -L                     # should list "pocketkey virtual FIDO key"
fido2-token -I /dev/hidrawN        # getInfo: FIDO_2_0/2_1, rk/up/uv, no clientPin
```

If you use the snap-packaged Firefox, pocketkey logs a warning at startup:
the snap cannot see the virtual key (see Requirements).

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

Cancel from the window, from Firefox's dialog, or on the phone. If the browser
asks you to select an authenticator, click **Use this phone-backed key** in the
pocketkey window; selection no longer happens automatically.

## Security notes

- pocketkey is a **proxy**. Origin and RP ID checks, challenge binding and
  user verification happen in the browser and on the phone exactly as with a
  real security key plus a real hybrid session. pocketkey validates CTAP
  structure but does not alter credential IDs, `clientDataHash`, signatures or
  attestation values in forwarded operations.
- Passkey private keys stay on the phone. The **linking data**
  (`~/.local/share/pocketkey/linked_devices.cbor`, mode 0600) is sensitive in
  a different way: whoever holds it can make your phone pop up a passkey
  prompt without a QR scan. The phone still requires your biometrics. To
  reliably unlink all phones, **stop pocketkey, delete the file, then start
  pocketkey** (or unlink from the phone's passkey settings). Deletion is also
  noticed by a running daemon before subsequent lookups and old records are
  not rewritten. However, deletion cannot revoke an already-running connection
  or reliably prevent an in-flight callback from linking a phone again.
  Corrupt or unsafe stores fail startup rather than being overwritten; limits
  are 128 phones and 1 MiB. The store directory must be owned by your user and
  private (0700), with the file private (0600).
- Only the root helper (`pocketkey-uhid-helper`) opens `/dev/uhid`. It is
  socket-activated, hardened with systemd sandboxing, creates exactly one
  device per user with a fixed FIDO report descriptor, and passes the
  descriptor to the user daemon. A `uhid` descriptor can only emit reports
  for the device it already created, so the user session cannot turn it
  into a keyboard or any other input device. Earlier versions granted the
  whole desktop session access to `/dev/uhid` via a udev rule; upgrading
  removes that rule.
- Pocketkey's own request/response diagnostics use allowlisted metadata rather
  than raw CBOR values. Detailed logging is scoped to Pocketkey; dependency
  logs stay at `info` or below even with `RUST_LOG=trace`. Treat logs as private
  and review diagnostic bundles before sharing them.
- Local programs with access to the virtual hidraw device can submit requests.
  HID channel IDs multiplex clients; they are not an authorization boundary.
  Resource limits prevent unbounded channel allocation, but a malicious local
  client can still compete with legitimate requests.
- Any local user can ask the helper for a virtual FIDO key (one per user).
  That only lets them present a FIDO device to their own session, which
  they could do with real hardware anyway.

## Limitations

- **Firefox pre-flight is answered locally.** When a site supplies an
  allowList (or excludeList), Firefox first sends a *silent* `getAssertion`
  (`up: false`) to learn which of those credentials the key holds, and gives
  up if none are confirmed. A phone cannot answer silent requests, so
  pocketkey confirms every credential the site listed (placeholder authData,
  empty signature, nothing signed or invented) and the phone then decides on
  the real request. Consequence: if none of the listed credentials is on your
  phone, you find out on the phone instead of Firefox saying so up front.
  The workaround recognizes Firefox's specific dummy-challenge probe, prevents
  count-based list splitting for requests within the 2048-byte limit, and
  rejects observed incomplete/failed exclusion sequences. The advertised
  credential-ID bound prevents Chromium from switching to singleton probes;
  the actual request-byte limit remains 2048. Oversized/incomplete CBOR
  received by the proxy blocks credential operations until channel
  reinitialization. This compatibility behavior is tested against Firefox and
  Chromium; other clients may behave differently.
- No U2F/CTAP1, no PIN, no credential management, no NFC. `getNextAssertion`
  is only served for the local pre-flight answer above; phones return a
  single assertion.
- Only the cloud-assisted tunnel (caBLE v2) is advertised in the QR for
  compatibility with current Android builds.

## Troubleshooting

```sh
journalctl --user -u pocketkey -f        # daemon log; RUST_LOG=debug for more
journalctl -u pocketkey-uhid -f          # root helper log
fido2-token -L                           # is the virtual key visible?
bluetoothctl show                        # is an adapter present and Powered: yes?
systemctl status pocketkey-uhid.socket   # helper socket must be listening
cargo run --example hidclient            # INIT + getInfo + PING through hidraw
```

- *"creating the virtual FIDO device" fails*: check that
  `pocketkey-uhid.socket` is enabled and the `uhid` kernel module is loaded
  (`lsmod | grep uhid`; `sudo modprobe uhid`). The helper logs to
  `journalctl -u pocketkey-uhid`. If the helper reports the device "already
  exists for this user", another pocketkey instance is running for you.
- *Firefox shows nothing*: confirm Firefox is not the snap (`snap list firefox`
  must be empty) and that `fido2-token -L` lists the device.
- *QR never completes*: both devices need internet access (tunnel server) and
  the PC needs Bluetooth on. Check `bluetoothctl show` for `Powered: yes`.
- *Phone says "something went wrong" after success*: pocketkey sends a tunnel
  shutdown after each request; if you see this, please file an issue with
  `RUST_LOG=debug` logs.

## Development

```sh
cargo test --locked                         # application and security regressions
cargo test --locked --release               # optimized-build regressions
cargo clippy --locked --all-targets -- -D warnings
cargo run --example ui_demo                 # exercise the window without a phone
```

Dependencies come from upstream Git/crates.io sources and are resolved in
`Cargo.lock`. CI runs Pocketkey's application tests, including optimized-build
regressions. Dependency updates should be reviewed and tested with both phone
platforms before release.

Layout: `src/uhid.rs` (kernel interface and helper fd-passing protocol),
`src/bin/pocketkey-uhid-helper.rs` (root helper), `src/ctaphid.rs` (pure transport
state machine), `src/ctap2/` (command dispatch and getInfo),
`src/hybrid/` (phone transport over `pxp`, linked-device store), `src/ui.rs`
(egui window), `src/main.rs` (wiring). See `PLAN.md` for design decisions and
`TESTING.md` for the manual test plan.

## License

pocketkey is open source under the [MIT License](LICENSE.md).
Copyright (c) 2026 S. Yousaf Ali.

pocketkey builds on the LGPL-2.1 `pxp` crate from
[libwebauthn](https://github.com/linux-credentials/libwebauthn); its terms
continue to apply to that component (see the notes at the end of
[LICENSE.md](LICENSE.md)).
