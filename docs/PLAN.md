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

## Iteration 3 — Secure Channel (in progress)

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
  freestanding. Intended pairing: Z-bit Systems' OSDP.Net `ACUConsole`
  over a null-modem cable or a com0com pair. Secure-channel mode over
  the serial path is pending an AES-vendoring decision (likely
  promoting tiny-AES-c to a top-level vendor dir so both tests and
  tools share one copy).
- ☑ **Phase 5a: ACU handshake.** `osdp::acu` initiates SCS_11..14 via
  `osdp_acu_start_sc_handshake(pd_addr, use_default_key)` — fire-and-
  forget. The ACU sends CHLNG, consumes CCRYPT (validates the Client
  Cryptogram), sends SCRYPT, consumes RMAC_I (validates Initial R-MAC
  + status byte), and fires `osdp_acu_sc_event_cb` with either
  `OSDP_ACU_SC_EVENT_ESTABLISHED` or `OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED`.
  CCRYPT and RMAC_I are consumed by the internal state machine and
  never surface in the application's reply_cb. One shared crypto
  vtable per ACU; per-PD SCBK / SCBK-D state lives in the slot.
- ☐ **Phase 5b: ACU operational SC.** Wrap outbound SCS_15..18,
  unwrap inbound SCS_16/18 replies.
- ☐ **Phase 6: PD↔ACU SC loopback integration test.** Both real state
  machines wired together, full handshake plus operational traffic
  in-process.

## Iteration 4+ — Optional extensions (not yet planned)

- File transfer, biometric, keypad extensions, manufacturer-specific
  commands, multi-part messages, certifiable test harness.
- Rust wrapper crate hardening + publishing.
- Full-capture replay: extend `test_capture_replay` from the handshake
  alone (SCS_11..14) to all 592 frames in `sc-monitor-current.osdpcap`,
  including SCS_15..18 operational traffic.
