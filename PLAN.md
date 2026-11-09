# pocketkey: implementation plan

Status: approved 2026-11-09 (pxp-only, forward up:false, eframe, hand-rolled uhid, VID/PID 0x1209/0x0001). Project renamed to pocketkey (repo yousafsyed/pocketkey).

## 0. Findings from reading the dependencies

### libwebauthn (linux-credentials/libwebauthn)

Workspace at tag `libwebauthn-v0.11.0` (commit `e5f01db3445a8854479786aae66b94844974020d`, 2026-11-01).
It is now split into two crates:

- **`pxp`** (v0.1.0, `pxp/`): the hybrid transport itself ("Proximity Exchange
  Protocol", formerly caBLE/CTAP hybrid). QR generation, BLE advertisement
  scan (btleplug), WebSocket tunnel (tokio-tungstenite + rustls) or BLE L2CAP
  (bluer), Noise handshake (snow), encrypted framing, linking-info updates.
  **It carries CTAP messages as opaque byte frames.** Its own docs say: "CTAP
  messages are carried as opaque frames. The only CTAP this crate knows is
  what PXP itself requires: the getInfo command byte and the getInfo response
  structure."
- **`libwebauthn`** (v0.11.0): the WebAuthn client layer on top (structured
  `MakeCredentialRequest`/`GetAssertionRequest`, origin/RP-ID validation
  against the public suffix list, PIN/UV protocols, HID/BLE/NFC transports,
  hidapi, dbus, publicsuffix, ...). Its `HybridChannel` is a thin wrapper
  around `pxp::TunnelHandle`: `cbor_send` does
  `tunnel.ctap_sender.send(request.ctap_hid_data())` where `ctap_hid_data()`
  is `[cmd_byte] ++ cbor`, and `cbor_recv` reads `[status_byte] ++ cbor`.

How hybrid is driven in `pxp`:

```rust
// QR-initiated
let device = PxpQrCodeDevice::new_persistent(QrCodeOperationHint::GetAssertionRequest,
                                              store /* Arc<dyn PxpKnownDeviceInfoStore> */,
                                              PxpTransports::CloudAssistedOnly)?;
let payload = device.qr_code.to_string();            // "FIDO:/0123..."  (digit-encoded CBOR)
let mut tunnel: TunnelHandle = pxp::connect(device, sink /* impl UpdateSink */);
tunnel.wait_for_connection().await?;                 // BLE advert -> tunnel -> Noise handshake
tunnel.ctap_sender.send(vec![0x02, /* CBOR */]).await?;   // raw CTAP frame: cmd ++ cbor
let frame = tunnel.ctap_receiver.recv().await;            // raw CTAP frame: status ++ cbor
tunnel.close().await;                                 // sends tunnel Shutdown so the phone shows success

// Linked / state-assisted
let known = PxpKnownDevice::new(ClientPayloadHint::GetAssertion, &info, store).await?;
let mut tunnel = pxp::connect(known, sink);          // tunnel first (push to phone), then BLE advert, then handshake
```

- **State updates**: `UpdateSink::send_update(PxpUpdate)` with
  `ProximityCheck` (QR shown / waiting for BLE advert), `Connecting`
  (tunnel), `Authenticating` (Noise), `Connected`, `Error(PxpError)`. Also a
  `watch::Receiver<ConnectionState>` (`Connecting`/`Connected`/`Terminated`)
  used by `wait_for_connection()`.
- **Linking data**: on a QR connection, when the phone sends an `Update`
  frame with linking info, pxp verifies its handshake signature and calls
  `PxpKnownDeviceInfoStore::put_known_device(id, PxpKnownDeviceInfo)`.
  `PxpKnownDeviceInfo { contact_id: Vec<u8>, link_id: [u8;8], link_secret:
  [u8;32], public_key: [u8;65], name: String, tunnel_domain: String }`. On
  tunnel HTTP 410 Gone, pxp calls `delete_known_device(id)`. The trait has
  only put/delete; **listing is our job** (we own the store).
- **Cancellation**: `TunnelHandle` aborts the task on drop; the BLE scan is
  wrapped in a `ScanGuard` whose `Drop` stops scanning. So dropping the
  handle is a clean cancel. `pxp` has **no built-in timeout** for the BLE
  advertisement wait; we wrap it in `tokio::time::timeout`.
- **getInfo**: pxp caches the phone's getInfo from the post-handshake message
  and answers `0x04` locally over `ctap_sender`. We never need it (we answer
  getInfo ourselves before any phone contact).
- **BLE availability**: `libwebauthn::transport::hybrid::is_available()` is
  just "btleplug finds an adapter"; in pxp there's no public equivalent, so
  we call `btleplug::platform::Manager::new().adapters()` ourselves (btleplug
  is already a pxp dependency, no new dep).

### Decision: raw CTAP2 passthrough, depending on `pxp` only

`pxp` exposes exactly a raw CTAP2 CBOR channel over the hybrid tunnel, so we
take the **raw path**: the bytes Firefox sends inside `CTAPHID_CBOR` for
makeCredential/getAssertion are forwarded to the phone byte-for-byte
(`cmd ++ cbor`), and the phone's `status ++ cbor` is returned byte-for-byte.
`clientDataHash`, extensions, allowList, options, etc. are preserved exactly
and we never parse the credential or attestation. getNextAssertion (`0x08`)
is **also just forwarded** while a tunnel is open (the phone implements it;
Chromium's hybrid authenticator handles `0x08` natively), so no buffering is
needed on our side.

This also means we depend on **`pxp` alone, not `libwebauthn`**: the top-level
crate pulls in hidapi, dbus, publicsuffix, idna, icu, x509-parser, PIN
protocols, etc., none of which a byte proxy needs. Both crates live in the
same repo at the same pinned commit; the task said "use the libwebauthn
crate", and `pxp` is libwebauthn's hybrid implementation factored out, so I
believe this honours the intent. **Please confirm** or I'll depend on
`libwebauthn` and use `HybridChannel` + its `CborRequest`/`CborResponse`
types instead (same raw bytes, heavier build).

Pin: `pxp = { git = "https://github.com/linux-credentials/libwebauthn", tag = "pxp-v0.1.0" }`
(equivalently rev `e5f01db3…`). Note pxp's `[patch.crates-io]` for trussed in
the workspace only matters for libwebauthn's own virtual-device tests, not for
pxp, so no patch section needed on our side (will verify at first build).

### Interop notes gathered from authenticator-rs and Chromium

These shape the local getInfo answer:

1. **Pre-flight / silent getAssertion.** Firefox (authenticator-rs
   `preflight.rs`) runs `do_credential_list_filtering_ctap2` before every
   getAssertion/makeCredential that has a non-empty allowList/excludeList:
   it sends `getAssertion` with `up: false` and a dummy clientDataHash,
   chunked by `maxCredentialCountInList` (default 1 if absent). A phone
   through hybrid will **not** answer silent requests (Chromium marks hybrid
   devices `NoSilentRequests()` and sends everything in a single batch).
   Consequence for us: a getAssertion with `options.up == false` must be
   **short-circuited locally**, never shown to the user or the phone.
   - If `up:false` on getAssertion -> answer `CTAP2_ERR_NO_CREDENTIALS` (0x2E)
     without contacting the phone. Firefox then treats the chunk as "none of
     these are on the device" and, because the original list was non-empty,
     ends with NoCredentials for sites that use an allowList... which would
     break password-manager-style logins with allowLists.
   - **Better**: advertise `maxCredentialCountInList` large (e.g. 64) and
     `maxCredentialIdLength` 1024 so Firefox puts the whole allowList in one
     chunk, then on the `up:false` probe reply `CTAP2_OK` with... no, we
     cannot fabricate an assertion. So: reply `CTAP2_ERR_NO_CREDENTIALS` and
     accept that Firefox drops allowList entries.
   - Actually re-reading `do_credential_list_filtering_ctap2`: on an `Err`
     for the single chunk, `final_list` stays empty, and the caller then
     sends a dummy makeCredential "to make the token blink" and fails with
     NoCredentials when the original list was non-empty. **That would break
     every allowList login.** The fix is the CTAP 2.1 route: the probe is
     only an error if the authenticator *knows* the credential isn't there;
     the spec-sanctioned answer when an authenticator cannot do silent
     requests is to treat `up:false` like a normal request. Chromium's own
     hybrid authenticator (`v2_authenticator.cc`) does exactly that: it
     passes `up:false` requests to the platform and the phone prompts.
   - **Plan**: forward `up:false` getAssertion to the phone as a normal
     request (bytes untouched). The phone prompts, the user approves once,
     Firefox's probe succeeds and yields the matching credential, and
     Firefox then sends the real getAssertion -> **a second prompt on the
     phone** for allowList sites. Discoverable (passkey, empty allowList)
     logins, which is the webauthn.io / Google / GitHub passkey flow, are
     unaffected: no allowList, no pre-flight, one prompt. To make the
     allowList case a single prompt I'd have to rewrite the probe response,
     which crosses the "we are a proxy" line; I'll document this in README
     as a known limitation and we can revisit after M3. Flagging this as
     **decision point 2** for you.
   - To keep Firefox from chunking into many probes, getInfo will include
     `maxCredentialCountInList: 64` and `maxCredentialIdLength: 1024`
     (beyond the minimal list in the spec; small additions, say no if you
     prefer the strictly minimal set).

2. **UV / PIN.** authenticator-rs `get_pin_uv_auth_param`: with
   `uv: true`, no `clientPin`, no `pinUvAuthToken`, it takes the "CTAP 2.0
   internal UV" branch and sets `uv: true` on the request, no PIN dialogs.
   Exactly the getInfo you specified. Good.

3. **Device selection.** With only one HID authenticator present,
   authenticator-rs selects it without sending `authenticatorSelection`;
   with several it sends `0x0B` and waits for a touch. We answer `0x0B`
   with `CTAP2_OK` immediately (as specced). Chromium does the same probing
   via a dummy makeCredential with empty pinAuth, which we cannot answer
   locally without contacting the phone; we'll forward it (Chromium is not
   the primary target; noted in TESTING.md).

4. **Keepalive/cancel.** authenticator-rs loops reading while it receives
   `CTAPHID_KEEPALIVE`, checks its `alive()` callback each time, and on
   cancel writes `CTAPHID_CANCEL` and expects a `CTAPHID_CBOR` response
   containing `CTAP2_ERR_KEEPALIVE_CANCEL` (0x2D). We will do exactly that.

5. **transports** in getInfo: `["usb"]` as specced. (Firefox stores
   transports in the credential it returns; "usb" is correct from its view.)

### tpm-fido (psanford)

Go: uhid device via `github.com/psanford/uhid` (ChromeOS `uhid` package),
report descriptor is the standard FIDO one (usage page 0xF1D0, usage 0x01,
64-byte IN/OUT), bus USB, VID 0x15d9 / PID 0x0a37. Its packet loop is
simple and we copy the structure: a reader goroutine turns `UHID_OUTPUT`
events into 64-byte packets, a state machine reassembles, a writer
fragments responses. We'll do the same with tokio tasks and channels, with
the CTAPHID state machine kept pure.

### uhid crate choice

`uhid-virt` 0.0.8 (Jan 2025) is thin and fine, but it pulls `uhidrs-sys`
which runs **bindgen at build time** (needs libclang, present here as
llvm-21 but it's a build dependency for packagers too). The whole uhid ABI
is one `struct uhid_event` (4380 bytes) with a handful of event types. I
propose **writing the ~150 lines ourselves** in `src/uhid.rs` (fixed layouts
for `UHID_CREATE2`, `UHID_INPUT2`, `UHID_DESTROY`, parse `UHID_START/STOP/
OPEN/CLOSE/OUTPUT`), using `tokio::io::unix::AsyncFd` on the non-blocking
fd. No bindgen, no extra crate. Needs `libc` (already a transitive dep).

### GUI choice: egui/eframe

GTK4 is not installed on this machine (`gtk4.pc` missing), gtk4-rs needs
the dev headers at build time and adds a long dependency chain. `eframe`
(winit + wgpu/glow) is pure Rust, builds without system headers, and does
Wayland and X11. It renders a QR code trivially (we draw the `qrcode` module
matrix as filled rects) and the window is simple: QR or "Check your phone",
a status line, Cancel. Downsides: ~2-4 MB binary growth, no native GNOME
look. Given the scope (one transient window), eframe is the lighter choice.
I'll use the `glow` backend (smaller than wgpu). Window is created on demand
on the main thread when a request arrives and closed when it completes
(eframe needs the main thread; tokio runtime runs in a background thread).

## 1. Crate layout

```
pocketkey/
├── Cargo.toml
├── PLAN.md  README.md  TESTING.md  Justfile
├── src/
│   ├── main.rs        wiring, tokio runtime (background thread), tracing, SIGTERM
│   ├── uhid.rs        /dev/uhid: create device, AsyncFd read/write of 64-byte reports
│   ├── ctaphid.rs     pure CTAPHID state machine (bytes in -> events/packets out)
│   ├── ctap2.rs       local getInfo, command dispatch, status codes, error mapping
│   ├── hybrid/
│   │   ├── mod.rs     `HybridTransport` async trait + `Status` enum
│   │   ├── pxp.rs     real impl over pxp: linked-first, QR fallback, timeouts
│   │   └── store.rs   `PxpKnownDeviceInfoStore` impl: JSON file, 0600, list()
│   └── ui.rs          eframe window: QR / "Check your phone" / status / Cancel
├── packaging/
│   ├── 99-pocketkey.rules
│   └── pocketkey.service
├── debian/            control, rules, changelog, install, copyright, source/format
└── .github/workflows/ci.yml
```

Dependencies (all listed by you or already transitive via pxp):
`tokio`, `tracing`, `tracing-subscriber` (env-filter), `pxp` (git), `ciborium`
(getInfo encoding + decoding the `options.up` flag for the pre-flight rule),
`qrcode`, `eframe` (glow), `serde`/`serde_json` (store file), `libc`,
`async-trait` (hybrid trait, already a pxp dep), `thiserror` (already a pxp
dep), `rand` (CID allocation, already a pxp dep), `directories` **or** hand-
rolled `$XDG_DATA_HOME` lookup (I'll hand-roll; 10 lines, no new dep).

## 2. Module designs

### uhid

- Open `/dev/uhid` `O_RDWR|O_NONBLOCK|O_CLOEXEC`, write `UHID_CREATE2`
  with name "pocketkey virtual FIDO key", bus USB (0x03), VID/PID
  (I'll use 0x1209/0x0001 pid.codes test range unless you have a preference;
  tpm-fido's are 0x15d9/0x0a37), the FIDO report descriptor (rdesc identical
  to tpm-fido / CTAP spec: Usage Page F1D0, Usage 01, Collection App, 64-byte
  input report, 64-byte output report).
- Wait for `UHID_START`, then loop: `UHID_OUTPUT` -> strip report-id byte if
  the kernel prefixed one (it does not for unnumbered reports; `UHID_OUTPUT`
  data for a 64-byte unnumbered report is 65 bytes with a leading 0x00 in
  practice on hidraw -> we handle both lengths), deliver 64-byte packet to
  ctaphid. `UHID_OPEN`/`UHID_CLOSE` logged at debug.
- `send(packet: [u8;64])` -> `UHID_INPUT2`.
- `Drop`/shutdown -> `UHID_DESTROY`.
- Error on `EACCES` with the exact udev hint in the message.

### ctaphid (pure, heavily tested)

```rust
pub struct Ctaphid { channels: HashMap<u32, ChannelState>, next_cid: u32, inflight: Option<Inflight>, ... }
pub enum Event { Request { cid: u32, cmd: Cmd, payload: Vec<u8> }, Cancel { cid: u32 } }
impl Ctaphid {
  pub fn handle_packet(&mut self, pkt: &[u8;64], now: Instant) -> Vec<Action>;
  pub fn tick(&mut self, now: Instant) -> Vec<Action>;      // reassembly timeouts
  pub fn respond(&mut self, cid: u32, cmd: Cmd, payload: &[u8]) -> Vec<[u8;64]>;  // fragmenter
  pub fn error(&self, cid: u32, code: u8) -> [u8;64];
  pub fn keepalive(&self, cid: u32, status: u8) -> [u8;64];
}
pub enum Action { Send([u8;64]), Emit(Event) }
```

- INIT on broadcast CID: allocate CID (sequential from 1, never 0 or
  0xFFFFFFFF), respond nonce ++ CID ++ version 2 ++ major/minor/build ++
  caps `CBOR|NMSG` (0x04|0x08). INIT on an existing CID: resync/abort that
  channel's in-flight reassembly, reply with the same CID.
- One reassembly buffer per channel; a second channel's init packet while
  another channel is mid-reassembly -> `ERR_CHANNEL_BUSY` to the newcomer;
  init packet on the same channel mid-reassembly -> `ERR_INVALID_SEQ`
  (spec) unless it is INIT (resync) or CANCEL.
- Continuation on wrong SEQ -> `ERR_INVALID_SEQ`, drop buffer. Continuation
  with no init -> ignore (spec: "spurious continuation packets are
  ignored"). BCNT > 7609 -> `ERR_INVALID_LEN`. Reassembly idle > 500 ms ->
  `ERR_MSG_TIMEOUT`, drop buffer.
- A CBOR request while another CBOR request is in flight (any CID) ->
  `ERR_CHANNEL_BUSY` on the new CID (the spec allows one transaction at a
  time; keepalives continue on the in-flight CID).
- PING -> echo. WINK -> empty WINK response. CANCEL -> `Event::Cancel`
  (only if that CID has a request in flight; otherwise ignored). Unknown
  command -> `ERR_INVALID_CMD`. CID 0 or unknown CID -> `ERR_INVALID_CHANNEL`.
- Tests: fragmentation round-trip at 0, 57, 58, 64, 1000, 7609 bytes;
  oversize; INIT allocation and resync; bad SEQ; spurious continuation;
  timeout; busy; cancel mid-reassembly and mid-request; PING; WINK;
  invalid CID.

### ctap2

- `Request::parse(cmd_byte, cbor)`; `GET_INFO` answered locally with the
  map you specified (+ `maxCredentialCountInList`/`maxCredentialIdLength`,
  pending your OK). AAGUID fixed, generated once now:
  `95e354b3-9409-4696-bd03-b87ed806ef7a` (from the kernel RNG just now).
- `MAKE_CREDENTIAL` / `GET_ASSERTION` / `GET_NEXT_ASSERTION` -> forwarded via
  `HybridTransport::ctap(bytes)`; hint (`mc`/`ga`) derived from the command.
  getNextAssertion only forwards if a tunnel is still open from the previous
  getAssertion (we keep the tunnel for ~2 s after a getAssertion response
  exactly for this, then close); otherwise `CTAP2_ERR_NOT_ALLOWED`.
- `SELECTION` -> `CTAP2_OK`. `RESET` -> `CTAP2_ERR_NOT_ALLOWED`. Unknown ->
  `CTAP1_ERR_INVALID_COMMAND`.
- Error mapping from `HybridError`: `Cancelled` -> 0x2D
  `KEEPALIVE_CANCEL`; `Timeout` -> 0x2F `USER_ACTION_TIMEOUT`;
  `NoBluetooth`/transport -> 0x7F `OTHER` (and a UI message); phone status
  bytes pass through unchanged (so the phone's own `NO_CREDENTIALS` etc.
  reach Firefox as-is).

### hybrid

```rust
#[async_trait]
pub trait HybridTransport: Send + Sync {
    /// Send one CTAP frame (cmd ++ cbor), get back (status ++ cbor).
    /// `status` receives UI/keepalive state transitions. `cancel` aborts.
    async fn ctap(&self, frame: Vec<u8>, hint: Hint, status: watch::Sender<Status>,
                  cancel: CancellationToken) -> Result<Vec<u8>, HybridError>;
}
pub enum Status { Idle, LinkedWaitingForPhone { name }, ShowQr { payload }, PhoneFound, Connected, WaitingForUser, Done, Failed(String) }
```

Real impl (`PxpTransport`):
1. `ensure_bluetooth()` -> `HybridError::NoBluetooth` if no adapter.
2. If the store has linked devices: for each (most recently used first),
   `pxp::connect(PxpKnownDevice)`, `timeout(10 s, wait_for_connection)`.
   Status `LinkedWaitingForPhone`. On success go to 4.
3. QR: `PxpQrCodeDevice::new_persistent(hint, store, CloudAssistedOnly)`
   (CloudAssistedOnly: Android Play Services pre-CTAP-2.3 hard-rejects key 6;
   we can flip to `CloudAssistedOrLocal` later). Status `ShowQr{payload}`.
   `timeout(QR_TIMEOUT = 120 s, wait_for_connection)`; pxp updates
   `ProximityCheck -> Connecting -> Authenticating -> Connected` are mapped
   onto our `Status` and onto keepalive status 1.
4. Send frame; switch keepalive to status 2 (`WaitingForUser`); await reply
   (bounded by the request's own timeout, default 120 s); map to `Status::Done`.
5. Keep the tunnel for a short grace window for getNextAssertion, then
   `tunnel.close()` (sends Shutdown so the phone shows success).
Cancel token -> drop handle (aborts the task, stops the scan) at any stage.

Store: `$XDG_DATA_HOME/pocketkey/linked_devices.json` (fallback
`~/.local/share`), dir 0700, file 0600, atomic write via temp+rename, fields
hex/base64 encoded, `last_used` timestamp for ordering. Implements
`PxpKnownDeviceInfoStore` (put/delete) plus `list()`.

### ui

eframe on the main thread, driven by a `watch::Receiver<Status>` and a
cancel sender. Window appears when status leaves `Idle`, hides on `Done`/
`Failed`(after 2 s)/`Idle`. Content: title, QR (drawn from `qrcode` matrix)
or phone glyph + "Check your phone: <name>", one status line, Cancel. No
`always_on_top`, no forced focus; on Wayland the compositor decides. Viewport
created fresh per request (eframe `run_native` per request, since the event
loop must own the main thread); the tokio runtime and uhid loop live on a
background thread so the daemon keeps answering INIT/getInfo while idle
with no window.

### main

`tracing_subscriber` with `RUST_LOG`-style env filter (default `info`);
secrets only at `trace` and never the raw CBOR at info. SIGTERM/SIGINT ->
cancel in-flight request, `UHID_DESTROY`, exit 0.

## 3. Milestone mapping

| Milestone | Modules | Verification (needs you) |
| --- | --- | --- |
| M1 | uhid, ctaphid, main (no hybrid) | `ls /dev/hidraw*`, `fido2-token -L` (needs `libfido2-tools`), I'll also add a tiny `cargo run --example ctaphid_init` using hidraw directly so M1 doesn't depend on libfido2 being installed |
| M2 | ctap2 getInfo | `fido2-token -I /dev/hidrawN`; Firefox webauthn.io prompt |
| M3 | hybrid (QR), ui | webauthn.io login via QR |
| M4 | makeCredential | webauthn.io register via QR |
| M5 | store, linked-first | second login without QR |
| M6 | timeouts, cancel paths | manual matrix in TESTING.md |
| M7 | packaging, docs, CI | `dpkg-buildpackage`, clippy, tests |

## 4. Things I need from you

1. **Decision point 1**: depend on `pxp` only (recommended) vs. the full
   `libwebauthn` crate.
2. **Decision point 2**: forward `up:false` pre-flight getAssertions to the
   phone (correct, but a second prompt on allowList sites) — yes/no; and OK to
   add `maxCredentialCountInList`/`maxCredentialIdLength` to getInfo.
3. **GUI**: eframe/glow OK?
4. **uhid**: hand-rolled (no bindgen) OK?
5. **VID/PID**: 0x1209/0x0001 (pid.codes test) or something else?
6. **Toolchain**: there is no `cargo`/`rustc` on this machine. Please install
   (I can't run installers):
   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
   ```
   and the build/test tooling (one-time, system packages):
   ```sh
   sudo apt install build-essential pkg-config libdbus-1-dev libudev-dev libfido2-tools
   ```
   (`libdbus-1-dev` is needed by btleplug/bluer inside pxp; `libudev-dev` by
   bluer's dependency; `libfido2-tools` for `fido2-token`.) Also note
   `/usr/share/publicsuffix` is present but we won't need it (pxp doesn't).
7. **Firefox**: `which firefox` resolves to `/snap/bin/firefox` here. For the
   M2+ tests you'll need the `.deb` from packages.mozilla.org (or Firefox
   from another non-snap source), as in the spec.
