# Manual test plan

Automated tests (`cargo test`) cover the CTAPHID state machine, getInfo
encoding, the uhid event layout and the linked-device store. Everything that
touches the kernel, Bluetooth, a phone or a browser is manual. Record the
result and the relevant `journalctl --user -u pocketkey` lines for each item.

Setup for all tests: `sudo make install && make install-user`, Firefox `.deb`
(not snap), Bluetooth on, phone with at least one passkey on
<https://webauthn.io> (register it from the phone's browser or from Chrome on
the phone first). Watch logs in a second terminal:
`journalctl --user -u pocketkey -f`.

## M1: device appears

| # | Step | Expect |
|---|------|--------|
| 1.1 | `ls -l /dev/hidraw*` before and after `systemctl --user restart pocketkey` | one new hidraw node |
| 1.2 | `fido2-token -L` | lists `pocketkey virtual FIDO key` (vendor 0x1209, product 0x0001) |
| 1.3 | `cargo run --example hidclient` | `INIT ok ... caps=0x0d`, getInfo map printed, `PING ok` |
| 1.4 | `systemctl --user stop pocketkey` | hidraw node disappears (clean `UHID_DESTROY`) |

## M2: getInfo

| # | Step | Expect |
|---|------|--------|
| 2.1 | `fido2-token -I /dev/hidrawN` | versions FIDO_2_0, FIDO_2_1; options rk/up/uv true, plat false; **no** clientPin; maxmsgsiz 2048; aaguid `95e354b394094696bd03b87ed806ef7a` |
| 2.2 | Firefox → <https://webauthn.io> → Authenticate → "security key" | Firefox shows its "insert/touch your security key" prompt (not an instant error); pocketkey window opens |

## M3: getAssertion via QR

| # | Step | Expect |
|---|------|--------|
| 3.1 | webauthn.io, username of a passkey that exists on the phone, Authenticate | window with QR; log `forwarding request to the phone` |
| 3.2 | Scan QR with the phone camera, approve, fingerprint | window shows "Phone found" → "Confirm on your phone" → ✓; webauthn.io logged in; log `phone replied status=0` |
| 3.3 | Repeat on a site with a short WebAuthn timeout (GitHub security key login) | completes within the site's timeout; Firefox keeps waiting while keepalives flow |

## M4: makeCredential via QR

Verified 2026-11-09 with Android (Google Password Manager) and iPhone
(iCloud Keychain), from Firefox and Chrome. The iPhone needs the
`rp.name`/`user.displayName` fill-in in `src/ctap2/compat.rs`; without it the
phone closes the tunnel without replying.

| # | Step | Expect |
|---|------|--------|
| 4.1 | webauthn.io, new username, Register, choose security key | QR; phone offers to save the passkey in Google Password Manager |
| 4.2 | Approve on phone | webauthn.io shows success; the passkey appears in the phone's password manager |
| 4.3 | Authenticate with the new passkey (3.1–3.2) | success |

## M5: linking

Observed 2026-11-09 with a Fairphone / Google Password Manager: the phone
sends **no** linking update after the handshake even though the QR advertises
state-assisted support, so 5.1–5.5 cannot pass with that phone. The code path
is kept for phones that do send linking data; the tests below apply to those.

| # | Step | Expect |
|---|------|--------|
| 5.1 | After any successful QR session: `ls -l ~/.local/share/pocketkey/` | `linked_devices.cbor` mode `-rw-------`; log `phone linked` |
| 5.2 | Authenticate again | window says "Check your phone (<name>)", **no QR**; phone shows a notification; approve → success |
| 5.3 | Phone in airplane mode, Authenticate | after ~10 s the QR appears as fallback; log `linked phone did not answer` |
| 5.4 | Link a second phone via QR; both listed in the store; most recently used is tried first | |
| 5.5 | Remove the passkey link on the phone (or wait for tunnel 410); Authenticate | pocketkey logs `phone unlinked`, falls back to QR |

## M6: keepalive and cancel robustness

| # | Step | Expect |
|---|------|--------|
| 6.1 | Start Authenticate, cancel in Firefox's dialog | window closes; log `client cancelled the request`; Firefox returns to the page; next attempt works |
| 6.2 | Start Authenticate, click Cancel in the pocketkey window | Firefox dialog reports cancellation (`CTAP2_ERR_KEEPALIVE_CANCEL`); next attempt works |
| 6.3 | Start Authenticate, close the window with the title-bar X | same as 6.2 |
| 6.4 | Start Authenticate, never scan | Firefox's own timeout fires first (it sends CANCEL); if it does not, pocketkey fails after 180 s with `USER_ACTION_TIMEOUT` |
| 6.5 | Bluetooth off (`bluetoothctl power off`), Authenticate | request fails quickly; window shows a failure line; Firefox shows an error; log mentions bluetooth/transport |
| 6.6 | Two tabs, start Authenticate in both quickly | second gets `CHANNEL_BUSY` and Firefox retries or errors; first completes normally |
| 6.7 | `systemctl --user restart pocketkey` while Firefox has the dialog open | Firefox dialog errors out; after restart `fido2-token -L` shows the device again |
| 6.8 | Google account sign-in with a passkey from the phone (short timeout, allowList present) | works; note whether the phone prompted twice (pre-flight, see README) |

## M7: packaging

| # | Step | Expect |
|---|------|--------|
| 7.1 | `make deb` on a clean checkout | produces `../pocketkey_0.1.0-1_amd64.deb` containing `/usr/bin/pocketkey`, the udev rule and the user unit |
| 7.2 | `sudo apt install ../pocketkey_*.deb && systemctl --user enable --now pocketkey` | 1.2 passes |
| 7.3 | CI workflow on GitHub | fmt, clippy, test, build green |

## Also worth a run

- Chrome (`.deb`) on the same machine: Chrome has native hybrid support, so
  pick "USB security key" explicitly; it should list pocketkey and work.
- `ssh-keygen -t ecdsa-sk` (needs `libfido2`): registers a non-discoverable
  credential through pocketkey; `ssh` with it prompts the phone.
