# OSDP-Embedded — Phased Plan

This document captures the iteration roadmap. Architectural rules and the
locked decisions that constrain every iteration live in
[../CLAUDE.md](../CLAUDE.md); this file focuses on **what gets built when**.

## Iteration 1 — Decoder

**Goal:** consume raw OSDP bytes (from captures or live serial) and produce
typed message structs. Foundation for both PD and ACU work later.

### Deliverables

1. **Repo skeleton** matching the layout in `CLAUDE.md`. Top-level `CMakeLists.txt`,
   `core/CMakeLists.txt`, `tests/CMakeLists.txt`. Builds clean on Windows
   (MSVC, clang, MinGW).
2. **Integrity primitives** in `core/src/shared/`:
   - `crc16.c` — OSDP CRC-16 per spec (verify polynomial, init, reflection
     against `docs/spec/SIA-OSDP-2.2-2.txt`).
   - `checksum.c` — 8-bit two's-complement checksum.
3. **Layer 1 framing** in `core/src/shared/frame.c`:
   - One-shot `osdp_frame_decode(buf, len, &frame)` returning header fields
     (SOM, address, length, control byte), payload slice, and integrity status.
   - Auto-detect CRC vs checksum from the control byte (CTRL bit 2).
   - Reject malformed frames with rich error info (error code + offset +
     offending bytes).
4. **Streaming decoder** in `core/src/shared/stream.c`:
   - `osdp_stream_init`, `osdp_stream_feed(byte)`, `osdp_stream_poll(&event)`.
   - Resync on garbage bytes; emit diagnostic events for bad-frame cases.
5. **Per-message codecs** for the v2.2 baseline set. Each TU contains model
   struct + decoder + builder, even though iteration 1 only exercises the
   decoder side. Builders are added in the same TU because the spec layout
   is symmetric and it avoids a churn-y refactor in iteration 2.
   - Commands: `osdp_POLL`, `osdp_ID`, `osdp_CAP`, `osdp_LED`, `osdp_BUZ`,
     `osdp_TEXT`, `osdp_OUT`, `osdp_COMSET`.
   - Replies: `osdp_ACK`, `osdp_NAK`, `osdp_PDID`, `osdp_PDCAP`, `osdp_RAW`,
     `osdp_KEYPAD`, `osdp_COM`.
6. **Dispatch helpers** in `core/src/dispatch/`:
   - `osdp_dispatch_command(&frame, &any_command)` and the reply equivalent.
   - Tagged-union output type. References every codec — opt-in only.
7. **Unity-based unit tests** under `tests/`:
   - CRC and checksum spec vectors.
   - Frame decode round-trip and negative cases (truncated, bad integrity,
     impossible length).
   - Stream resync behavior.
   - Per-message decode + re-build round-trip with byte-compare.
8. **README + CLAUDE + PLAN** docs (this set).
9. **OSDPCAP support** (added late in iteration 1):
   - `tools/osdp-parser/` — host-side CLI that reads OSDPCAP-format
     captures and prints decoded frames via the streaming decoder +
     dispatch classifier. Functions as the canonical Monitor consumer.
   - `tests/captures/` — drop-in directory for OSDPCAP files; CMake
     globs them at configure time and registers a CTest entry per
     capture, backed by `test_captures.c`.
   - `test_osdpcap.c` — unit tests for the OSDPCAP reader itself.

### Out of scope for Iteration 1

- Rust crates (directories may be scaffolded, but no code yet).
- PD, ACU, or Monitor application code (state machines, transports).
- Secure Channel.

### Definition of done

- All Unity tests pass on Windows host (MSVC + clang + MinGW).
- Decoder correctly round-trips every captured sample we have, including
  any traffic logs the user provides.
- A consumer can write `target_link_libraries(myapp PRIVATE osdp::core osdp::messages)`
  and successfully decode a baseline OSDP frame in fewer than 20 lines of
  code.

## Iteration 2 — Encoder TX paths and applications (in progress)

- ☑ **Encoder promotion to first-class.** `osdp_frame_build` and every
  per-message builder are now validated by a real-world Secure Channel
  capture (`tests/captures/sc-monitor-current.osdpcap`): all 592 frames
  decode → rebuild → byte-compare without any mismatches.
- ☑ **PD peer tree** (`pd/`). Role-specific state machine, transport HAL,
  application command handler, sequence number management, online/
  offline tracking, address filtering. Builds on top of `osdp::core`.
  *Remaining nice-to-haves: inter-character timeout policing (spec 5.8)
  and multi-record reply convenience helpers.*
- ☑ **ACU peer tree** (`acu/`). Multi-PD registration via caller-allocated
  slots, explicit `osdp_acu_send_command` API with one outstanding
  command per PD, sequence-number progression (0 → 1 → 2 → 3 → 1 → ...),
  per-PD reply timeout (200 ms) with retry-friendly SQN retention, per-PD
  online tracking. *Remaining nice-to-haves: auto-poll scheduling, in-
  process PD↔ACU integration tests.*
- ☐ First end-to-end PD example on host (loopback) and on a target MCU
  (TBD — likely STM32 or Nordic).
- ☐ Extend `osdp-parser` (or add a sibling tool) to drive synthetic
  capture playback for testing PD/ACU state machines.

## Iteration 3 — Secure Channel (done)

- ☑ **Phase 1: Crypto HAL** (`osdp_sc_crypto.h`). Single-block AES-128
  ECB encrypt + optional decrypt + optional `rand_bytes`, supplied by
  the consumer (mbedTLS on host, hardware AES on MCU, tiny-AES-c for
  tests). Per CLAUDE.md the core never vendors a crypto implementation.
- ☑ **Phase 1: SC primitives** (`osdp_sc.h` + `core/src/sc/keys.c`,
  `mac.c`, `cbc.c`). Built on top of the HAL: session key derivation
  per spec D.4.1; client/server cryptograms per D.4.3-4; initial
  R-MAC per D.3.2; custom CBC-MAC per D.5 (S-MAC1 for blocks 1..n-1,
  S-MAC2 for block n, 0x80-pad only when needed); AES-128 CBC
  encrypt/decrypt with arbitrary IV.
- ☑ **Phase 2a: Payload encryption** (`core/src/sc/payload.c`).
  SCS_17/18 encrypt/decrypt with the always-pads 0x80 || 0x00* rule
  per spec D.4.5, IV = ones-complement of the chain MAC per D.5.1-2.
- ☑ **Phase 2b: Frame MAC fields + session state struct.**
  `osdp_frame_t` gained `mac` / `mac_len`, decoder splits the
  trailing 4 bytes for SCS_15..18, builder appends them. Capture
  round-trip still byte-identical. `osdp_sc_session_t` added with
  the rolling MAC chain entries.
- ☑ **Phase 2c: Frame wrap/unwrap helpers** (`core/src/sc/wrap.c`).
  End-to-end build of an outbound SCS_15..18 frame; verify-and-decrypt
  of an inbound one; both update the session's rolling MAC chain.
- ☑ **Phase 3a: PD handshake.** PD now responds to inbound CHLNG
  (SCS_11) and SCRYPT (SCS_13) with correctly-derived CCRYPT
  (SCS_12) and RMAC_I (SCS_14). Optional via the
  `osdp_pd_set_sc_*` API; un-configured PDs continue to NAK 0x05.
- ☑ **Phase 3b: PD operational SC.** SCS_15..18 commands are
  unwrapped, dispatched to the existing `osdp_pd_command_cb` with
  plaintext, and replies are wrapped back as SCS_16/SCS_18.
- ☑ **Phase 4a: Capture-replay validation** (BUMPED FORWARD from the
  original phase 6 slot). Drives our PD with the SCS_11 / SCS_13
  frames extracted from `tests/captures/sc-monitor-current.osdpcap`
  (recorded by `libosdp-conformance 1.38-4`) and asserts the PD's
  CCRYPT and RMAC_I replies are byte-identical to the captured
  PD→ACU bytes. Configured with SCBK-D (the spec's well-known default
  install key, now exposed as `OSDP_SCBK_DEFAULT` from `osdp_sc.h`),
  the captured cUID, and a PRNG pinned to emit the captured
  RND.B = `"abcdefgh"`. Validates phases 1-3 against an independent,
  hardware-validated OSDP stack before we add ACU-side SC code. Test:
  `tests/test_capture_replay.c`.
- ☑ **Phase 4b: Live interop tool** (`tools/osdp-pd-mock/`). Host CLI
  that runs an `osdp::pd` instance on a real (or virtual) serial
  port, configurable via CLI flags or `OSDP_INTEROP_PD_PORT`.
  Pluggable Win32 (`serial_win.c`) and POSIX (`serial_posix.c`)
  serial adapters selected by CMake; the `pd/` library itself stays
  freestanding. SC mode (`--sc=scbkd` / `--sc=scbk:HEX32`) is wired
  through a tiny tools-side AES adapter that links the shared
  `vendor/tiny-aes/` static library. **Validated live against
  Z-bit Systems' OSDP.Net `ACUConsole`** over a com0com pair: full
  POLL/ID/CAP exchange, SC handshake, operational SCS_15..18
  traffic. Two real-world bugs surfaced and fixed during that
  testing:
  - The PD's SQN cache was matching on SQN alone, replaying a stale
    reply when the ACU sent two consecutive commands with the same
    SQN (an OSDP.Net error-recovery quirk). Fixed by comparing wire
    bytes per spec 5.9 ("byte-identical" retransmits).
  - The PD was wrapping empty replies as SCS_18 (all-padding
    ciphertext); OSDP.Net's depad logic rejected this. Fixed by
    centralizing the "empty payload uses SCS_15/16" rule in
    `osdp_sc_wrap_frame`. Live captures saved as regression
    fixtures in `tests/captures/acuconsole-*.osdpcap`.
- ☑ **Phase 5a: ACU handshake.** `osdp::acu` initiates SCS_11..14 via
  `osdp_acu_start_sc_handshake(pd_addr, use_default_key)` — fire-and-
  forget. The ACU sends CHLNG, consumes CCRYPT (validates the Client
  Cryptogram), sends SCRYPT, consumes RMAC_I (validates Initial R-MAC
  + status byte), and fires `osdp_acu_sc_event_cb` with either
  `OSDP_ACU_SC_EVENT_ESTABLISHED` or `OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED`.
  CCRYPT and RMAC_I are consumed by the internal state machine and
  never surface in the application's reply_cb. One shared crypto
  vtable per ACU; per-PD SCBK / SCBK-D state lives in the slot.
- ☑ **Phase 5b: ACU operational SC.** Once a slot's session is
  ESTABLISHED, every `osdp_acu_send_command` is automatically wrapped
  — SCS_17 by default, coerced to SCS_15 for empty payloads. Inbound
  SCS_16 / SCS_18 replies are unwrapped before being delivered via
  `reply_cb` (plaintext). The application sees plaintext throughout;
  encryption / MAC are transparent. Session-loss detection covers all
  spec-mandated termination conditions:
    - MAC verification fails on an inbound SCS_16/18 (D.1.4).
    - Non-BUSY plaintext reply during ESTABLISHED (D.1.4).
    - PD reply with SQN=0 during ESTABLISHED (5.9 reset signal).
    - PD goes silent for 8 s during ESTABLISHED or mid-handshake (5.7).
  Each fires either `OSDP_ACU_SC_EVENT_SESSION_LOST` or
  `OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED` (depending on prior phase) and
  the slot returns to IDLE; the application may re-handshake at will.
- ☑ **Phase 6: PD↔ACU SC loopback integration test.** Both real state
  machines wired together via a shared in-memory wire (`tests/test_loopback_sc.c`).
  Verifies the four-frame handshake (CHLNG / CCRYPT / SCRYPT / RMAC_I)
  completes with both peers reporting "established"; POLL→ACK round-trips
  under SCS_15/16; ID→PDID and CAP→PDCAP round-trip under SCS_17/18 with
  encrypted payloads; an 8-command POLL/CAP mix advances the rolling MAC
  chain without drift; tampering one MAC byte in flight tears the ACU's
  session down and fires SESSION_LOST; offline-during-established and
  post-loss plaintext fallback both behave per spec. This is the
  strongest correctness check we have for SC: any disagreement between
  our PD and our ACU on cryptogram inputs, key derivation, frame layout,
  or MAC chain advancement shows up here.

## Iteration 4 — Rust adapter (in progress)

- ☑ **Single-crate Rust wrapper, `osdp-embedded`.** The C library is
  exposed through one published crate at `rust/osdp/`, no companion
  `-sys` crate. The FFI bindings live in a private `mod sys` and
  `build.rs` compiles the C tree via the [`cc`
  crate](https://crates.io/crates/cc) so `cargo build --target …`
  cross-compiles to any target the C library compiles on. Earlier
  iterations split into `osdp-sys` + safe wrapper; collapsed for
  simpler publishing (single `cargo publish`, single Cargo.toml to
  bump per release).
- ☑ **Cargo features for role selection.** `pd` and `acu` features
  gate both the Rust modules and the corresponding `.c` file
  compilation in `build.rs`. A PD-only firmware build
  (`--no-default-features --features pd`) genuinely doesn't compile
  any ACU code. Default features: `["std", "pd", "acu"]`. All four
  feature combos are clippy-clean and tested.
- ☑ **Plaintext API.** Typed `Error` / `Result`; `frame::decode` /
  `frame::build` with a borrowed `Frame<'a>`; one shared
  `osdp_embedded::Transport` trait used by both `pd::Pd` and
  `acu::Acu`; role-specific `CommandHandler` / `ReplyHandler` /
  `TimeoutHandler` traits. `examples/loopback.rs` demonstrates a full
  Pd↔Acu round-trip in-process (POLL→ACK and ID→PDID, byte-identical
  end to end).
- ☑ **Secure Channel API.** `osdp_embedded::sc::ScCrypto` trait
  (AES-128 encrypt + decrypt + RNG) plus PD-side `set_sc_crypto` /
  `set_sc_scbk` / `set_sc_scbk_d` / `set_sc_cuid` / `sc_established`;
  ACU-side `set_sc_crypto` / `set_pd_scbk*` / `start_sc_handshake` /
  `set_sc_event_handler` / `is_pd_sc_established` with an
  `ScEventKind` enum (`Established` / `HandshakeFailed` /
  `SessionLost`). The ACU-only event types are gated behind the `acu`
  feature. Validated via `examples/loopback_sc.rs` which runs the full
  SCS_11..14 handshake and POLL→ACK + ID→PDID under SCS_15..18
  in-process, with the `aes` crate as the AES backend.
- ☑ **Per-message codec wrappers.** `osdp_embedded::messages` provides
  typed `decode` / `build` for every command (`Poll`, `IdRequest`,
  `CapRequest`, `Out`, `Led`, `BuzCmd`, `Text<'a>`, `ComsetCmd`) and
  every reply (`Ack`, `Nak<'a>`, `Pdid`, `Pdcap`, `Raw<'a>`,
  `Keypad<'a>`, `Com`) in the v2.2.2 baseline set, on top of the
  matching `osdp_*_decode` / `osdp_*_build` FFI. Variable-length
  payloads (`Pdcap`, `Out`, `Led`) are exposed as `Vec<...>`;
  borrowed-slice payloads (`Nak`, `Text`, `Raw`, `Keypad`) carry a
  lifetime back to the input. Eight unit tests cover round-trip plus
  a representative truncated-decode negative.
- ☑ **Publish-ready packaging.** `scripts/Stage-Crate.ps1` mirrors the
  C tree into `rust/osdp/vendor-c/` (gitignored) so `cargo package`
  produces a tarball that compiles standalone from inside the
  archive. CI verifies this via `cargo package` (with verify) on
  every tagged build. See [PUBLISHING.md](PUBLISHING.md) for the
  manual `cargo publish` recipe.
- ☐ **Publishing** to crates.io. Pending the first release tag.

## Iteration 5 — osdp-mcp virtual reader web UI (planned)

**Goal:** a browser-based visual display of the virtual PD reader in
`tools/osdp-mcp`, so a human can watch the reader's outputs (LEDs,
buzzer, text, relays) update in real time while an agent drives the MCP
server. Agreed 2026-06-06.

**Why:** osdp-mcp is PD-side. LED/BUZ/TEXT/OUT commands from the ACU
control the reader, but today `DefaultHandler` blind-ACKs them without
decoding, so nothing captures "what the reader is showing." The `/mcp`
HTTP endpoint is JSON-RPC/SSE (not browser-consumable) and stdio is the
dominant transport, so the UI needs its own independent HTTP surface
(plain REST + SSE) running alongside either MCP transport.

**Decisions:** start view-only, add interactivity incrementally. Enable
via a `--ui-bind 127.0.0.1:8088` flag + `OSDP_MCP_UI_BIND` env var (off
by default, loopback-only, mirroring the existing `--bind` /
`OSDP_MCP_*` pattern), spawned in both stdio and http transports.

**LED handler lives in the C core, not in Rust (revised 2026-06-10).**
The reader-state logic that decodes LED commands and tracks "what colour
is the reader showing right now" belongs in the freestanding C library so
*both* a PD firmware app and an ACU controller app get it for free, not
just the MCP tool. The Rust/MCP visual is a thin consumer of that C API.

### Deliverables (build order)

- ☑ **Core LED state resolver** (`core/src/shared/led_state.c`,
  `osdp_led_state.h`). A pure, caller-owned `osdp_led_t` value type: fold
  an `osdp_led_record_t` in with `osdp_led_apply(rec, now_ms)`, ask for
  the displayed colour with `osdp_led_color(now_ms)`. Resolves the
  temporary-vs-permanent split, the temporary countdown timer, and the
  flash on/off phase — all from the timestamp passed at query time, so no
  background timer / no OS tick. Steady when `on+off == 0`; a 0-length
  temp timer expires immediately (never masks permanent). 8 unit tests in
  `tests/test_led_state.c` (steady, flash phases, temp expiry, cancel,
  perm-NOP, 32-bit clock wrap).
- ☑ **Baked into `pd/` and `acu/` with a change callback.** Both state
  machines transparently decode inbound (PD) / outbound (ACU) `osdp_LED`
  commands into an internal LED bank keyed by `(reader_no, led_no)` —
  plus `pd_address` on the ACU. A consumer registers
  `osdp_pd_set_led_handler` / `osdp_acu_set_led_handler` and is called
  back whenever a tracked LED's *resolved* colour changes — on a new
  command, on temporary-timer expiry, and on each flash transition (the
  time-driven ones detected inside `tick()`, so they need a `now_ms`
  transport clock). Direct query via `osdp_pd_led_color` /
  `osdp_acu_led_color`. The wire reply is unchanged (the app still
  ACKs LED), so this is observe-only with zero interop impact. The PD
  path covers Secure Channel too (folds the unwrapped plaintext). Two
  PD↔ACU loopback tests in `tests/test_loopback.c` drive a real LED
  command end to end (steady colour mirrored on both peers; temporary
  timer expiring back to permanent purely from the wire clock).
- ☑ **Rust + MCP wiring.** The `osdp-embedded` wrapper exposes the PD
  LED API — a typed `LedColor`, an `LedHandler` trait,
  `Pd::set_led_handler`, and `Pd::led_color` (`rust/osdp/src/pd.rs`),
  over FFI bindings whose `osdp_pd_t` / `osdp_acu_t` struct mirrors were
  grown to match the new C LED-bank fields. osdp-mcp's `pd_actor`
  registers an `LedHandler` (`reader_state.rs::ReaderLedHandler`) on the
  PD that folds colour changes into a shared `ReaderState`, exposed via
  the new `pd_reader_state` MCP tool (and cleared when a PD is
  (re)opened). Tested end to end: `rust/osdp/tests/led_tracking.rs`
  (wrapper) and `tools/osdp-mcp/tests/actor_loopback.rs`
  (`led_command_updates_reader_state`).
  (Future deliverables below still cover BUZ/TEXT/OUT and link status,
  which can follow the same C-core pattern or stay Rust-side as plain
  decode-into-state.)
- ☑ **UI server** (`ui.rs`). An axum server independent of the MCP
  transport: `GET /` serves a self-contained embedded HTML page
  (`include_str!("ui_index.html")` — inline CSS/JS, renders each reader
  LED as a glowing circle), `GET /api/state` returns the
  `ReaderStateView` JSON snapshot; the page polls it ~3×/s. Enabled via
  `--ui-bind <addr>` / `OSDP_MCP_UI_BIND` (off by default), spawned as a
  `tokio` task alongside either MCP transport and sharing the one
  `PdHandle`. Tested with `tower::oneshot` over the router
  (`tests/ui_server.rs`) and smoke-checked against a live binary.
- ☑ **SSE push.** A `tokio::sync::broadcast` channel lives inside
  `ReaderState`; every `set_led` / `clear` fans the new snapshot out to
  subscribers. `GET /api/events` streams a snapshot on connect then one
  `state` event per LED change (with keep-alive comments). The page uses
  `EventSource` for instant updates, keeping a slow (10 s) polling
  backstop so it degrades gracefully if a proxy buffers the stream. The
  SSE builder is shared (`ui::reader_sse`) so the `reader_demo` example
  serves the identical stream. (Built per-change-snapshot rather than the
  originally-sketched `LogInner` deltas — simpler and the payload is
  tiny.)
- ☑ **Reader buzzer (beep) — full stack.** Same shape as the LED but the
  buzzer is modelled as a *sounding state*, not a colour: a core resolver
  (`osdp_buz_state`) folds an `osdp_BUZ` command's tone / on-time /
  off-time / count into an on/off pattern, and the PD/ACU fire a
  change callback (`osdp_pd_set_buzzer_handler` /
  `osdp_acu_set_buzzer_handler`) on every beep↔silence edge — including
  the final silence when the `count` cycles complete — resolved on
  `tick()`. Query via `osdp_pd_buzzer_sounding`. Exposed through the Rust
  `BuzzerHandler` trait + `Pd::set_buzzer_handler` / `buzzer_sounding`;
  osdp-mcp folds it into `ReaderState.buzzers` (per-reader `sounding` +
  `tone`) so `pd_reader_state` and the SSE stream carry it. The page
  shows a speaker icon beside the LED bar that pulses while sounding and
  plays the beep via the Web Audio API behind a one-click "enable sound"
  gesture (browser autoplay policy). Tested at every layer:
  `tests/test_loopback.c` (beep→silence over the wire clock),
  `rust/osdp/tests/led_tracking.rs`, and
  `tools/osdp-mcp/tests/actor_loopback.rs`.
- ☑ **Interactive keypad.** The page's keypad digits (1-9, ✱, 0, #) are
  buttons; tapping one POSTs `/api/keypad`, which enqueues a one-key
  `osdp_KEYPAD` event on the PD (same `enqueue_event` path as the
  `inject_keypad` MCP tool, ASCII key byte per spec Table 35). The ACU
  under test receives the digit on its next POLL — the reader's keypad
  driven from the browser. The only write the UI surface performs;
  everything else stays read-only. The `reader_demo` example turns a
  press into a confirmation beep. Tested:
  `tools/osdp-mcp/tests/ui_server.rs::keypad_press_enqueues_a_pd_event`.
- ☑ **Interactive card read.** A card-number input + "Tap card" button on
  the page POST `/api/card`; the value is packed MSB-aligned into a
  (default 26-bit Wiegand) `osdp_RAW` event and enqueued on the PD, so the
  ACU under test sees the presented card on its next POLL. `card_event()`
  is shared with the demo, where a tap becomes an "access granted" green
  pulse + beep. Tested:
  `tools/osdp-mcp/tests/ui_server.rs::card_tap_enqueues_a_pd_event`.
- ☐ **Live wire-log panel** on the page, reusing the `code_name` labels.

### Deferred

- Multi-reader support beyond reader 0.
- Temporary-LED / temporary-text timer accuracy.
- Card-read format/parity options (today the value is sent MSB-aligned as
  Wiegand without computed parity, matching the `inject_raw` tool).

## Iteration 7 — Secure Channel 2 (in progress)

**Goal:** OSDP-SC2, the quantum-resistant secure channel (AES-256-GCM
message protection + KMAC256-derived session keys), as a **parallel**
implementation to SC1 in the SCS_21..28 security-block range. Agreed
2026-07-01. Verified against the OSDP.Net `feature/osdp-sc2` reference
and the OSDP-SC2 annex sample-session vectors.

Locked decisions: AES-256-GCM is a **HAL callback** (the core never
implements GHASH); KMAC256 + AES-256 block are HAL callbacks too;
**separate `osdp_sc2_*` types** (not extensions of the SC1 vtable/
session); device-specific-key only (no SCBK-D install mode); no SC1/SC2
negotiation (the ACU picks via the CHLNG SCB type).

- ☑ **Phase 0: Frame layer.** `OSDP_SCS_21..28`; `osdp_scb_mac_len()`
  returns the trailing-tag size per SCB type (4 B SC1 / 16 B SC2 GCM
  tag); `osdp_scb_is_encrypted` covers SCS_27/28. For SCS_27/28 the
  command/reply CODE byte is inside the ciphertext.
- ☑ **Phase 1: Crypto HAL + primitives.** `osdp_sc2_crypto.h`
  (kmac256 / aes256_gcm_encrypt+decrypt / aes256_ecb_encrypt / rand),
  `osdp_sc2.h`, `core/src/sc2/{keys,crypto,session}.c`: KMAC256 session
  keys, AES-256-CBC (chained) client/server cryptograms, nonce from
  cUID + shared counter. Test/tool backend: vendored `vendor/tiny-kmac`
  (Keccak-f1600 + cSHAKE256 + KMAC256), `vendor/tiny-gcm` (AES-256-GCM
  over `tiny_aes256`; the AES-256 build renames its symbols so one
  binary can link both AES sizes). Known-answer tests match the annex
  (S-ENC, S-NONCE, both cryptograms, nonce@0).
- ☑ **Phase 2: GCM wrap/unwrap + session.** `core/src/sc2/wrap.c`:
  AAD = the 7-byte header incl. security block; shared message counter
  advances on both wrap and unwrap. Reproduces both annex operational
  frames (POLL@0, ACK@1) byte-for-byte incl. GCM tag and CRC.
- ☑ **Phase 3: PD side.** `pd/src/pd_sc2.c` (SCS_21..24 handshake +
  SCS_25..28 operational), `osdp_pd_set_sc2_*` API, KEYSET KeyType 0x02
  (32-byte SCBK). **Live-validated against OSDP.Net's SC2 ACU** over a
  serial pair via `osdp-pd-mock --sc=scbk2:HEX64`.
- ☑ **Phase 4: ACU side.** `acu/src/acu_sc2.c`,
  `osdp_acu_start_sc2_handshake`, transparent SCS_27 wrap of every
  command once ESTABLISHED, SC2 session-loss (GCM auth fail / plaintext
  during established / SQN=0 reset / offline timeout). `osdp-acu-mock
  --sc=scbk2:HEX64` for live interop against OSDP.Net PDConsole.
- ☑ **Phase 5: PD↔ACU SC2 loopback.** `tests/test_loopback_sc2.c`:
  both real state machines complete the handshake, round-trip
  POLL/ID/CAP under SCS_27/28, keep the shared counter in lockstep
  across 8 commands, and the ACU tears down on a tampered tag and on
  offline timeout — the validated PD exercising the ACU end to end.
- ☑ **Phase 6: Rust + MCP + docs.** FFI mirrors (`sys.rs`) + C source
  list (`build.rs`) grown for SC2. Safe Rust `ScCrypto2` trait +
  `Pd::set_sc2_*` / `Acu::set_sc2_*` / `start_sc2_handshake`;
  `examples/loopback_sc2.rs` validates it against RustCrypto backends
  (aes-gcm + tiny-keccak KMAC256). osdp-mcp `pd_configure` gains
  `sc_mode="scbk2"` (64-hex SCBK) driving an AES-256-GCM virtual PD, with
  the reader badge showing the SC2 posture. Both interop tools
  (`osdp-pd-mock`, `osdp-acu-mock`) speak `--sc=scbk2:HEX64`. Docs:
  PLAN.md + CLAUDE.md.

## Iteration 8 — SC2 asymmetric device pairing (planned)

**Goal:** certificate-based (asymmetric, post-quantum) initialization for
Secure Channel 2 — a cleartext pairing exchange that runs **once, before**
any secure channel and whose only output is the 32-byte SC2 SCBK. After
pairing derives the SCBK, the existing SCS_21..28 handshake + record layer
(Iteration 7) run unchanged with that key. This is a new opt-in front-end
that provisions the key the SC2 code already consumes; the SC2 record layer
is untouched. Agreed 2026-07-05. Full design, wire protocol, crypto, key
schedule, memory budget, and test vectors: **[pairing-design.md](pairing-design.md)**.

Mirrors OSDP.Net `feature/osdp-sc2` (`src/OSDP.Net/Pairing/`,
`docs/pairing-overview.md`) byte-for-byte — an EDHOC-style mutual-auth key
agreement over **ML-KEM-768** (KEM) + **ML-DSA-44** (deterministic
signatures + a compact C509 CBOR cert PKI) + **HKDF/HMAC/SHA-256**. Rides
two cleartext commands, osdp_PAIR (`0xB0`) / osdp_PAIRR (`0x8A`), fragmented
over CRAUTH-style 2-byte multipart framing (4 messages, ~5.3/7.7/2.5 KB +
60 B).

Locked decisions (2026-07-05):
- **Target: full MCU, freestanding.** Same no-malloc / no-OS /
  caller-owned-buffer rules as the rest of `core/`/`pd/`/`acu/`. All PQC is
  HAL callbacks; the core only hands fixed-size caller-owned buffers across
  the boundary. Memory is a first-class constraint (~15–20 KB of
  provisioning-time buffers; see pairing-design.md §7).
- **Crypto fully pluggable via a new `osdp_pair_crypto_t` HAL** (ML-KEM-768
  / ML-DSA-44 / SHA-256 / HMAC-SHA256 / HKDF), exactly like the SC1/SC2
  HALs. The core vendors **zero** PQC code. **Tests/CI use vendored PQClean**
  (ML-KEM-768 + ML-DSA-44 + SHA-256 under `vendor/pqclean/`, CC0), self-
  contained like tiny-*, so KATs run hermetically on the existing Linux CI
  with no external dependency (decided 2026-07-05 after confirming CI is
  hermetic/vendored). **WolfSSL is the documented production backend + a
  live-interop target**; any other backend (mbedTLS+liboqs, OpenSSL 3.5+,
  hardware PQC) drops in behind the same HAL.
- **Multipart scoped to pairing only** — a minimal 2-byte reassembly helper
  dedicated to PAIR/PAIRR; not generalized to CRAUTH/file-transfer (those
  stay out of scope per CLAUDE.md).
- **Wire format mirrored exactly** (experimental / not SIA-assigned);
  provisional codes/strings centralized so a future spec reassignment is a
  one-file change.

- ☑ **Phase 0: Transport.** `core/src/pair/fragment.c` (osdp_PAIR/osdp_PAIRR
  0xB0/0x8A fragment carrier codec) + `core/src/pair/multipart.c` (in-order
  2-byte multipart reassembler + outbound fragment iterator) in the new
  opt-in `osdp::pair` target; `OSDP_CMD_PAIR` / `OSDP_REPLY_PAIRR` +
  buffer-sizing constants (`osdp_pair.h`). 18 Unity tests
  (`tests/test_pair_transport.c`): full fragment→wire→reassemble round trip
  plus short-header / size-mismatch / overrun / gap / bad-total /
  buffer-too-small / idempotent-retransmit / offset-0-restart negatives.
  Whole C suite 31/31 green.
- ☑ **Phase 1: Crypto HAL + CBOR + C509.** `osdp_pair_crypto.h` (pluggable
  ML-KEM-768/ML-DSA-44/SHA-256/HMAC/HKDF contract), `osdp_cbor.h`/`cbor.c`
  (canonical CBOR, 12 tests), `cert.c` (C509 encode/decode/thumbprint/verify,
  9 structural tests). Vendored PQClean test backend (`vendor/pqclean/`,
  `tests/pair_test_crypto.c`) drives 8 crypto KATs: SHA-256 + HKDF RFC-5869
  vectors, KEM round trip, C509 thumbprint + self-signed verify + tamper-
  reject, and **fixed-seed ML-DSA-44 demo-CA + ML-KEM-768 public-key hashes
  that match OSDP.Net's published constants byte-for-byte** (PQClean ↔
  BouncyCastle crypto interop confirmed). Whole C suite green.
- ☐ **Phase 2: Key schedule.** `keyschedule.c`; assert K_m2/3/4 + SCBK vs
  the fixed vectors; HKDF RFC-5869 sanity vector.
- ☐ **Phase 3: Message codecs.** `messages.c` Msg1/2/3/Result CBOR
  encode/parse; TH1..TH4 span extraction; tampered/negative cases.
- ☐ **Phase 4: PD side.** PD-responder state machine + `pd/src/pd_pair.c`
  driver (reassembly, 30 s timeout, `on_scbk_established` persistence);
  opt-in gate / NAK-when-unconfigured.
- ☐ **Phase 5: ACU side.** ACU-initiator state machine + `acu/src/acu_pair.c`
  driver (fragment send, multipart receive, per-message timeout, rejection
  surfacing).
- ☐ **Phase 6: PD↔ACU loopback.** `tests/test_loopback_pair.c`: both real
  state machines derive an identical SCBK, which then feeds the existing SC2
  handshake + a POLL/ACK under SCS_27 — full provisioning-through-operation
  in-process; untrusted-CA / tampered-Msg2/3 / persist-fail negatives.
- ☐ **Phase 7: Live interop (WolfSSL).** WolfSSL `osdp_pair_crypto_t`
  binding for the interop tools; tools gain a pairing mode; live-validate vs
  OSDP.Net `feature/osdp-sc2` over a serial pair. (Hermetic KATs already run
  on PQClean from Phase 1; this phase is the production-backend + on-wire
  cross-check.)
- ☐ **Phase 8: Rust + MCP + docs.** `PairCrypto` trait + pair APIs; `sys.rs`
  / `build.rs` grown; osdp-mcp pairing option; PLAN.md + CLAUDE.md.

## Iteration 6+ — Optional extensions (not yet planned)

- File transfer, biometric, keypad extensions, manufacturer-specific
  commands, multi-part messages, certifiable test harness.
- Full-capture replay: extend `test_capture_replay` from the handshake
  alone (SCS_11..14) to all 592 frames in `sc-monitor-current.osdpcap`,
  including SCS_15..18 operational traffic.
- SC2: SCS_25/26 (authenticated-only, dev/test) interop validation
  against OSDP.Net; SC2 session-expiry counter-rollover handling.
