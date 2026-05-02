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

- ☑ **Crypto HAL** (`osdp_sc_crypto.h`). Single-block AES-128 ECB
  encrypt + optional decrypt vtable, supplied by the consumer (mbedTLS
  on host, hardware AES on MCU, tiny-AES-c for tests). Per CLAUDE.md
  the core never vendors a crypto implementation.
- ☑ **SC primitives** (`osdp_sc.h` + `core/src/sc/`). Built on top of
  the HAL: session key derivation per spec D.4.1; client/server
  cryptograms per D.4.3-4; initial R-MAC per D.3.2; custom CBC-MAC
  per D.5 (S-MAC1 for blocks 1..n-1, S-MAC2 for block n, 0x80-pad
  only when needed); AES-128 CBC encrypt/decrypt with arbitrary IV.
- ☐ **SC session state machine.** Track current session keys, rolling
  MAC chain, encryption state. Drive the SCS_11..14 handshake from
  either role.
- ☐ **Frame integration.** Extend osdp_frame_decode/build to validate
  and append the 4-byte truncated MAC for SCS_15..18 frames; encrypt
  and decrypt SCS_17/18 payloads; expose the `mac` slice as a separate
  field of `osdp_frame_t`.
- ☐ **PD-side SC integration.** Extend `osdp::pd` to optionally accept
  SCB-bearing frames: handle CHLNG → CCRYPT → SCRYPT → RMAC_I, then
  validate inbound MACs and produce outbound MACs for SCS_15..18.
- ☐ **ACU-side SC integration.** Extend `osdp::acu` to initiate the
  handshake and drive SCS_15..18 traffic.
- ☐ **Capture validation.** With SCBK in hand, decode the encrypted
  SCS_17/18 frames in `tests/captures/sc-monitor-current.osdpcap`.

## Iteration 4+ — Optional extensions (not yet planned)

- File transfer, biometric, keypad extensions, manufacturer-specific
  commands, multi-part messages, certifiable test harness.
- Rust wrapper crate hardening + publishing.
