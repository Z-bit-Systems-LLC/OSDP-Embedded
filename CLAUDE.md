# CLAUDE.md — guidance for working on OSDP-Embedded

This file captures the locked architectural decisions and coding rules for
this project so future Claude sessions can pick up cold without re-deriving
them. Read it before making suggestions or writing code.

## What this project is

A from-scratch implementation of **SIA OSDP v2.2.2** for embedded devices.
Owned by Z-bit Systems. The same author maintains a full C# implementation at
[OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) — useful as a
behavioral oracle, **not** as a porting source.

## Locked architectural decisions

These were agreed on 2026-05-02. Do not silently revise them; if a task
seems to need a change, raise it explicitly with the user first.

1. **Language: C11**, freestanding-friendly. A Rust (`no_std`-compatible)
   wrapper crate is planned on top of the C core.
2. **No OS assumptions in the core.** No malloc, no globals, no threading
   primitives, no I/O calls. All buffers caller-owned. All functions
   reentrant.
3. **Modularity is a primary design goal.** A PD or ACU build must include
   only the code it actually needs.
4. **Module split is by message direction**, not by role. Commands
   (ACU→PD) and replies (PD→ACU) each get their own source directory.
   PD/ACU/Monitor differentiation lives in higher layers (state machine,
   transport) introduced in later iterations.
5. **One translation unit per message**, containing the model struct,
   decoder, and builder for that one command or reply. Linker GC drops
   unused functions thanks to `-ffunction-sections -fdata-sections` +
   `--gc-sections`.
6. **No auto-registration tables** that pull every codec in by symbol
   reference. Dispatch helpers live in their own opt-in TUs under
   `src/dispatch/` and are linked only when the consumer wants bulk
   routing (e.g. a Monitor).
7. **Build system: CMake.** Test framework: **Unity** (vendored).
8. **Scope: OSDP v2.2 baseline command/reply set, plus Secure Channel.**
   Currently implemented: Layer 1 framing, the baseline command/reply
   set, PD-side state machine (with SC), ACU-side state machine (with
   SC), and PD-side file transfer (osdp_FILETRANSFER / osdp_FTSTAT).
   Still deferred: biometric, manufacturer-specific commands, multi-part
   messages, ACU-side file transfer. See [docs/PLAN.md](docs/PLAN.md) for
   what's done and what's next.

## Module layout

```
core/include/osdp/
  osdp_types.h        # shared types, error codes, enums
  osdp_frame.h        # Layer 1 framing (incl. SCB types SCS_11..18)
  osdp_stream.h       # streaming push decoder
  osdp_commands.h     # all command models + per-message prototypes
  osdp_replies.h      # all reply models + per-message prototypes
  osdp_dispatch.h     # optional bulk dispatch helpers
  osdp_sc_crypto.h    # AES-128 ECB + RNG HAL (consumer-supplied)
  osdp_sc.h           # Secure Channel primitives: keys, cryptograms,
                      # MAC, CBC, payload, frame wrap/unwrap

core/src/
  shared/             # crc16.c, checksum.c, frame.c, stream.c — always linked
  commands/           # cmd_<name>.c — model + decode + build per command
  replies/            # reply_<name>.c — model + decode + build per reply
  dispatch/           # opt-in bulk routing; references every codec
  sc/                 # keys.c, mac.c, cbc.c, payload.c, session.c,
                      # wrap.c — Secure Channel primitives

pd/                   # role-specific state machine for the PD side
  include/osdp/osdp_pd.h
  src/pd.c            # baseline state machine (address, SQN, online)
  src/pd_sc.c         # SC handshake (SCS_11..14) + operational SCS_15..18
  src/pd_internal.h
  CMakeLists.txt      # exports osdp::pd

acu/                  # role-specific state machine for the ACU side
  include/osdp/osdp_acu.h
  src/acu.c           # baseline state machine (slots, SQN, timeouts)
  src/acu_sc.c        # SC handshake + operational SC + session-loss
  src/acu_internal.h
  CMakeLists.txt      # exports osdp::acu

tools/
  osdp-parser/        # host CLI: OSDPCAP reader + Monitor pipeline.
                      # Built when OSDP_BUILD_TOOLS=ON.
  osdp-pd-mock/       # host CLI: live PD on a serial port (Win32 +
                      # POSIX adapters). Used for interop validation
                      # against external ACUs (OSDP.Net, hardware).

vendor/               # 3rd-party code shared between tools and tests.
  tiny-aes/           # tiny-AES-c (Unlicense / public domain).
                      # Only built when OSDP_BUILD_TESTS=ON or
                      # OSDP_BUILD_TOOLS=ON.

tests/captures/       # drop OSDPCAP files here. CMake globs *.osdpcap at
                      # configure time and registers a CTest entry per
                      # capture, all backed by the test_captures
                      # executable. Re-run cmake after adding a file.
```

## CMake targets

| Target            | Contents                                                  | Linked by                |
| ----------------- | --------------------------------------------------------- | ------------------------ |
| `osdp::core`      | framing, stream, CRC, checksum                            | everything               |
| `osdp::messages`  | all command + reply codec TUs                             | PD, ACU, Monitor         |
| `osdp::dispatch`  | bulk decode helpers; references every codec               | Monitor only             |
| `osdp::pd`        | PD-side state machine + transport HAL                     | PD applications          |
| `osdp::acu`       | ACU-side state machine + transport HAL                    | ACU applications         |

A PD application links `core + messages + pd`; an ACU application links
`core + messages + acu`. A Monitor adds `dispatch` for one-call bulk
routing. Linker GC keeps each binary's flash usage tight by dropping
codecs the application doesn't reference.

## Per-message API shape

Every command and reply follows the same template:

```c
/* in osdp_commands.h or osdp_replies.h */
typedef struct {
    /* fields per OSDP spec */
} osdp_led_t;

osdp_status_t osdp_led_decode(const uint8_t *payload, size_t len,
                              osdp_led_t *out);

osdp_status_t osdp_led_build(const osdp_led_t *in,
                             uint8_t *buf, size_t buf_cap,
                             size_t *written);
```

Both functions live in `core/src/commands/cmd_led.c`. If an application
references only one of them, the other gets GC'd.

## Library-handled commands (KEYSET, COMSET, FILETRANSFER)

Most commands flow to the application's `osdp_pd_command_cb`, which chooses
the reply. A few are intercepted by the PD state machine itself because they
mutate library-owned state and/or mandate a specific reply the app shouldn't
have to synthesize. Both the plaintext (`pd/src/pd.c`) and Secure Channel
(`pd/src/pd_sc.c`) dispatch paths intercept them identically.

- **`osdp_KEYSET`** — flows to `cmd_cb` (the app ACKs it), then the core
  applies the new SCBK in place. See the Secure Channel conventions below.
- **`osdp_COMSET`** — handled entirely by the core: it never reaches
  `cmd_cb`. The library builds the mandated `osdp_COM` reply and switches
  `pd->address` for it (the state machine owns the address — it filters
  inbound frames and stamps replies with it). Per spec 6.13 the change takes
  effect only *after* the reply is sent, so the reply goes out at the old
  address and the switch is deferred to `process_frame` after `send_bytes`.
  Two optional app hooks bracket the exchange (`osdp_pd_set_comset_handler`):
  `decide` (before the reply — veto/clamp the requested address/baud, the
  spec-6.13 "return what I'll use" path) and `applied` (after the reply is
  sent — enact the baud change on the transport and persist to NVM). The
  address is switched by the core; only the baud is the app's job, because
  the core has no UART. Critical gotcha the app hook must respect: a
  transport `write()` returning does not mean the bytes are physically on the
  wire, so `applied` must **drain the transmitter before changing baud** (a
  premature switch clocks out the tail of `osdp_COM` at the new rate and the
  ACU never follows). `tcdrain` on POSIX; on Windows `FlushFileBuffers` plus
  a timed wait, since USB adapters hold bytes in a chip FIFO past
  `FlushFileBuffers`/`cbOutQue`. `tools/osdp-pd-mock/serial_*.c` implements
  both, and `tools/osdp-mcp/src/serial_transport.rs` does the same: its
  `DefaultComsetHandler` accepts the requested address *and* baud and stages
  the new rate on a lock-free `BaudControl`, which the `SerialTransport`
  applies (drain, then `set_baud_rate`) on its next I/O — after the
  `osdp_COM` reply has drained at the old rate (it previously pinned the baud
  and never retuned). Malformed COMSET (payload ≠ 5 bytes) → NAK 0x02; effective address
  > 0x7E is rejected and the current address kept — 0x7F is **not** an
  assignable working address, it is the *configuration address*
  (`OSDP_CONFIG_ADDR`, the spec's 0x7F "broadcast"). A COMSET that *arrives
  at* 0x7F, however, is the config-discovery flow: the PD processes it and
  assigns the requested (0x00..0x7E) working address. Address / reply rules
  (spec 5.9 Note 2): the PD accepts frames sent to **either** its configured
  address **or** 0x7F, and a reply to a 0x7F-addressed command goes out at
  0x7F | reply-flag = **0xFF** (not the PD's own address). `build_reply` in
  `pd/src/pd.c` implements this by mirroring the inbound `cmd->address`.
- **`osdp_FILETRANSFER`** — handled entirely by the core: it never reaches
  `cmd_cb`. The library decodes each fragment, enforces the offset invariants,
  tracks the running position, and builds every mandated `osdp_FTSTAT` reply.
  The app supplies only a per-fragment evaluation callback (`osdp_pd_file_cb`),
  whose return maps to `FtStatusDetail` — `OSDP_OK` → proceed (0) mid-file /
  processed (1) on the final fragment; `OSDP_ERR_BAD_PAYLOAD` → malformed (−3);
  `OSDP_ERR_NOT_SUPPORTED` → unrecognized (−2); anything else → abort (−1).
  The callback fires on every accepted fragment so the app can validate
  incrementally (check a firmware header at offset 0, hash as it goes) and
  reject mid-transfer. **Two modes**, both driving the same callback, chosen by
  which setter registers it:
  - `osdp_pd_set_file_receiver(buf, cap, …)` — **reassembly**: the core copies
    each fragment into the caller-owned buffer (no malloc; app sizes it to the
    largest expected file) and hands the whole accumulated file to the callback
    (`info->data`). A `total_size` > `cap` aborts with −1. For validate-then-
    commit of small blobs (biomatch template, display data) or whole-file
    signature checks.
  - `osdp_pd_set_file_stream(…)` — **streaming**: no buffer. The core hands
    each fragment to the callback as it arrives (`info->fragment`; `info->data`
    is NULL) without accumulating, with no size ceiling — RAM use is
    independent of file size. For firmware update on RAM-constrained MCUs that
    persist each fragment to flash. `file_buf == NULL` is the internal mode
    flag; the two setters linker-GC independently.

  Invariants enforced in both modes — first fragment at offset 0,
  contiguous/monotonic offsets, stable type/size (plus `total_size` ≤ capacity
  in reassembly mode) — and any violation aborts with −1 and resets so the ACU
  can restart at offset 0. Byte-identical retransmits replay from the SQN cache
  before the callback runs, so a lost FTSTAT never corrupts the offset. With no
  receiver registered, FILETRANSFER → NAK 0x03; an undecodable frame (payload <
  11-byte header) → NAK 0x02. The `osdp_FTSTAT` reply is data-bearing, so under
  SC it wraps as SCS_18. Deferred while the callback is synchronous: the
  "finishing" (status 3) idle-fragment protocol and `FtUpdateMsgMax` throttling
  (the PD always reports `update_msg_max = 0`).

## Coding rules

- C11. Freestanding-only headers (`<stdint.h>`, `<stddef.h>`, `<string.h>`,
  `<stdbool.h>`). No `<stdio.h>`, `<stdlib.h>`, no malloc, no globals,
  no thread-local storage.
- All public symbols prefixed `osdp_`. Internal-linkage helpers prefixed
  `osdp_<module>_` and declared `static`.
- Return `osdp_status_t` from anything that can fail; never use errno-style
  global state.
- No undefined behavior on invalid input. Decoders must defend against
  truncated, oversized, and malformed frames; they report errors, they do
  not crash.
- No copying of code from OSDP.Net. Use it only as a clarifying reference
  when the spec is ambiguous.
- **Every source file (`.c`, `.h`, `.rs`, `CMakeLists.txt`) starts with an
  SPDX header**:

  ```
  // SPDX-License-Identifier: GPL-3.0-or-later
  // Copyright (C) 2026 Z-bit Systems, LLC
  ```

  Use `#` comments for CMake/Python, `//` for C/C++/Rust. The project is
  dual-licensed (GPL-3.0-or-later or commercial); the SPDX line states
  the open-source option, and a signed commercial license supersedes it
  for paying customers. Do not omit the header. Do not write any
  alternative license text in source files — `LICENSE.md` is canonical.

## Reference material

- **Spec**: `docs/spec/SIA-OSDP-2.2-2.txt` (extracted from PDF, gitignored,
  ~4165 lines, layout-preserved). When implementing or verifying any
  framing, command code, payload layout, or CRC/checksum detail, grep this
  rather than guessing.
  - Sections 6.x — Commands (ACU → PD).
  - Sections 7.x — Replies (PD → ACU).
  - Appendix B — payload encoding details.
- **OSDP.Net repo**: <https://github.com/Z-bit-Systems-LLC/OSDP.Net>.
  Behavioral oracle. Mine for command/reply enums, payload layouts, and
  test vectors. Do not copy code.
- **OSDPCAP capture format**: SIA's libosdp-conformance project,
  <https://github.com/Security-Industry-Association/libosdp-conformance/blob/master/doc/doc-src/osdpcap-format.md>.
  JSON-Lines, one record per line, fields: `timeSec`, `timeNano`, `io`
  (input/output/trace), `data` (hex bytes with optional spaces, may
  carry leading 0xFF marking bytes), `osdpTraceVersion`, `osdpSource`.
  The `data` field is "usually but not always a whole OSDP message" —
  the streaming decoder is the right way to consume it.

## Testing

- Unity is vendored under `tests/vendor/unity/`.
- Tests live under `tests/`, organized by module (`test_crc.c`,
  `test_frame.c`, `test_stream.c`, plus per-message tests).
- Test vectors as hex blobs under `tests/vectors/`. When adding a codec,
  add at least one round-trip test (decode → re-build → byte-compare) and
  at least one negative test (truncated, bad CRC, bad command code).

## Secure Channel conventions

Secure Channel (osdp_CHLNG / osdp_SCRYPT / osdp_CCRYPT / osdp_RMAC_I,
SCS_11..18, AES-128 session keys, custom CBC-MAC) is fully implemented
in `core/src/sc/`, `pd/src/pd_sc.c`, and `acu/src/acu_sc.c`. The core
exposes the cryptographic primitives behind `osdp_sc_crypto_t` — the
consumer supplies AES-128 ECB encrypt + decrypt + RNG callbacks; the
library never vendors a crypto implementation. A few project-wide rules
that aren't explicit in the spec:

- **SCS_15/16 for empty messages, SCS_17/18 for data-bearing** (spec
  D.1.4 interpretation: "SCS_17 and SCS_18 also include encrypted
  message DATA"). Empty replies / commands always use the plaintext-
  with-MAC variant. `osdp_sc_wrap_frame` enforces this by coercing
  SCS_17→SCS_15 and SCS_18→SCS_16 when `payload_len == 0`, so callers
  can pick the encrypted variant generically and it Does The Right
  Thing.
- **SQN cache must compare wire bytes, not just SQN.** The OSDP SQN
  cycles 1→2→3→1→…, so a mere SQN match is not sufficient evidence
  of a retransmit. Byte-identical bytes = retransmit (per spec 5.9);
  same SQN with different bytes = a new command and must process
  fresh. Implemented in `pd/src/pd.c::is_retransmit`.
- **KEYSET rotates the SCBK in place; the current SC session keeps
  running.** When a well-formed `osdp_KEYSET` (key_type=SCBK,
  key_length=16) is accepted by the application handler, the PD-side
  dispatch path applies the new key into `pd->sc.scbk` and ACKs.
  Session keys (`s_enc`, `s_mac1`, `s_mac2`, SQN counters) are
  intentionally left alone — the rotated key only matters for the
  *next* handshake, which the ACU initiates whenever it chooses.
  Malformed KEYSET payloads (header length mismatch, unsupported
  key_type) downgrade the wire reply from ACK to NAK 0x09
  (`OSDP_NAK_RECORD_INVALID`) so the ACU sees the failure; the
  stored SCBK is never overwritten on a bad write.
- **Clear-text (USC) commands are refused once secure operation is
  expected.** During an *established* session (either key), ANY clear-text
  (non-SCB) command from the ACU tears the session down and is answered
  `osdp_NAK 0x06` (`OSDP_NAK_ENCRYPTION_REQUIRED`) in the clear —
  interleaving USC inside an SCS is a protocol violation (spec D
  "Interleaving USC packets during communication in a SCS is NOT allowed").
  This replaces the older "clear command at SQN 0 silently resets and is
  processed" reconnect shortcut. *Before* a session exists, a PD keyed for
  full security (an operational SCBK is set, not merely SCBK-D) refuses
  restricted clear commands the same way; only the discovery/config
  allowlist — `osdp_ID`, `osdp_CAP`, `osdp_COMSET` — is accepted so the ACU
  can find the PD and bring SC up. The SCB-bearing handshake
  (`osdp_CHLNG`/`osdp_SCRYPT`) never reaches the clear-text path, so a
  re-handshake still works mid-session. A PD with no operational key
  (clear-only / install-only) stays permissive. Implemented in
  `pd/src/pd.c::handle_command_into_tx`.
- **`osdp_NAK 0x01`/`0x06` and `osdp_BUSY` are the only replies allowed
  plaintext under SC.** A frame that fails its CRC/checksum but is addressed
  to this PD is answered `osdp_NAK 0x01` (`OSDP_NAK_BAD_CHECK`) rather than
  silently dropped, so the ACU retransmits with the same SQN (spec Table 47
  / §5). To make this possible `osdp_frame_decode` surfaces the frame
  identity (address / reply / sequence / integrity) *before* the integrity
  check; on `OSDP_ERR_BAD_CRC` / `_BAD_CHECKSUM` those fields are valid while
  the rest of `*out` is not. Bad-check frames for another address,
  broadcast/config traffic, and non-integrity decode errors stay silent.
  Implemented in `pd/src/pd.c::osdp_pd_tick`.
- **ACU session-loss conditions** (any one terminates the SC session,
  fires `OSDP_ACU_SC_EVENT_SESSION_LOST` or `_HANDSHAKE_FAILED`, and
  resets the slot to IDLE; the application can re-handshake at will):
  - MAC verification fails on an inbound SCS_16/18 (D.1.4).
  - A non-BUSY plaintext reply arrives during ESTABLISHED (D.1.4).
  - The PD replies with SQN=0 during ESTABLISHED (5.9 reset signal).
  - The PD goes silent for `OSDP_ACU_OFFLINE_TIMEOUT_MS` (5.7).
  - During the handshake itself: bad Client Cryptogram in CCRYPT, or
    `sec_blk_data[0] == 0xFF` in RMAC_I, or the offline timeout fires
    while still in `AWAITING_*`.

## Out of scope (do not introduce without explicit user approval)

- Dynamic memory allocation anywhere in `core/`, `pd/`, or `acu/`.
- OS / RTOS calls (threading, mutexes, sleeps, file I/O) in `core/`,
  `pd/`, or `acu/`. Tools (`tools/osdp-pd-mock`, ...) are exempt by
  design — they're host-only.
- A vendored crypto library inside `core/`. The consumer supplies the
  AES + RNG primitives via the `osdp_sc_crypto_t` HAL. Tests and
  `tools/osdp-pd-mock` use tiny-AES-c (vendor/tiny-aes/, Unlicense)
  but production binaries are expected to bind their own (mbedTLS,
  hardware AES, BCryptGenRandom / /dev/urandom, etc.).
- ACU-side file transfer (the PD side is implemented; the ACU currently
  has no file-send driver). Biometric, manufacturer-specific commands,
  multi-part / multi-record messages, PIV data exchange.
- Auto-poll scheduling on the ACU (the application currently drives
  every command).

## When in doubt

Ask the user. The user prefers iterative agreement on architecture over
silently broadening scope.
