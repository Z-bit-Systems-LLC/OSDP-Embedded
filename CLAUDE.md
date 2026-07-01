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
8. **Scope: OSDP v2.2 baseline command/reply set, plus Secure Channel
   (SC1) and Secure Channel 2 (SC2).** Currently implemented: Layer 1
   framing, the baseline command/reply set, PD-side state machine (with
   SC1 + SC2), ACU-side state machine (with SC1 + SC2). SC2 is the
   quantum-resistant channel (AES-256-GCM + KMAC256) built as a parallel
   implementation in the SCS_21..28 range; both sides are live-validated
   against OSDP.Net's `feature/osdp-sc2`. Still deferred: file transfer,
   biometric, manufacturer-specific commands, multi-part messages. See
   [docs/PLAN.md](docs/PLAN.md) for what's done and what's next.

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
  osdp_sc2_crypto.h   # SC2 HAL: KMAC256 + AES-256-GCM + AES-256 + RNG
  osdp_sc2.h          # SC2 primitives: keys, cryptograms, nonce,
                      # frame wrap/unwrap (AES-256-GCM)

core/src/
  shared/             # crc16.c, checksum.c, frame.c, stream.c — always linked
  commands/           # cmd_<name>.c — model + decode + build per command
  replies/            # reply_<name>.c — model + decode + build per reply
  dispatch/           # opt-in bulk routing; references every codec
  sc/                 # keys.c, mac.c, cbc.c, payload.c, session.c,
                      # wrap.c — Secure Channel (SC1) primitives
  sc2/                # keys.c, crypto.c, session.c, wrap.c — SC2
                      # (AES-256-GCM / KMAC256) primitives

pd/                   # role-specific state machine for the PD side
  include/osdp/osdp_pd.h
  src/pd.c            # baseline state machine (address, SQN, online)
  src/pd_sc.c         # SC1 handshake (SCS_11..14) + operational SCS_15..18
  src/pd_sc2.c        # SC2 handshake (SCS_21..24) + operational SCS_25..28
  src/pd_internal.h
  CMakeLists.txt      # exports osdp::pd

acu/                  # role-specific state machine for the ACU side
  include/osdp/osdp_acu.h
  src/acu.c           # baseline state machine (slots, SQN, timeouts)
  src/acu_sc.c        # SC1 handshake + operational SC + session-loss
  src/acu_sc2.c       # SC2 handshake + operational SC2 + session-loss
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

## Secure Channel 2 conventions

SC2 (the quantum-resistant channel: AES-256-GCM message protection +
KMAC256-derived session keys) is a **parallel** implementation to SC1 in
the SCS_21..28 range, in `core/src/sc2/`, `pd/src/pd_sc2.c`, and
`acu/src/acu_sc2.c`. It uses its own HAL (`osdp_sc2_crypto_t`: KMAC256 +
AES-256-GCM encrypt/decrypt + AES-256 block + RNG) and its own session
type (`osdp_sc2_session_t`) — the SC1 vtable/session are untouched. Both
sides are live-validated against OSDP.Net's `feature/osdp-sc2`. Rules
that differ from SC1:

- **Device-specific key only.** No SCBK-D install mode. `SEC_BLK_DATA[0]
  = 0x02` selects SC2 during the SCS_21..24 handshake. There is no
  SC1/SC2 negotiation — the ACU chooses by which CHLNG it sends; a PD
  that doesn't support the requested version NAKs 0x05.
- **The code byte is encrypted.** For SCS_27/28 the GCM plaintext is
  `code || data`, so a decoded frame's `code` is a ciphertext byte until
  `osdp_sc2_unwrap_frame` decrypts it (it returns the real code
  separately). SCS_25/26 (auth-only, dev/test) send code+data in the
  clear and fold them into the GCM AAD.
- **AAD = the 7-byte header incl. the security block**
  (`SOM|ADDR|LEN|CTRL|SEC_BLK_LEN|SEC_BLK_TYPE`). The GCM tag is the full
  16 bytes (no truncation) and is the sole authenticator; there is no
  rolling MAC chain.
- **One shared message counter**, seeded to 0 at establish and
  incremented on **every** wrap AND unwrap, keeps both peers in lockstep
  and feeds the per-message nonce (`cUID || counter(LE) || 0x80 00 00 00`
  encrypted with S-NONCE, first 12 bytes). No SC2 traffic is valid until
  `session.established`.
- **RMAC_I (SCS_24) carries no payload** — success/fail is the SCB status
  byte (0x02 ok / 0xFF fail). CCRYPT (SCS_22) is 56 bytes
  (`cUID[8] || RND.B[16] || ClientCryptogram[32]`); the cryptograms are
  AES-256-CBC (zero IV, genuinely chained across the two blocks — NOT
  ECB), 32 bytes.
- **KEYSET KeyType 0x02** rotates the 32-byte AES-256 SCBK in place
  (`pd->sc2.scbk`), same "next handshake" semantics as SC1; malformed
  records NAK 0x09.
- **Test/tool crypto lives in `vendor/`** (`tiny-gcm` = AES-256-GCM over
  `tiny-aes256`; `tiny-kmac` = Keccak/KMAC256), never in `core/`. The
  AES-256 build renames its symbols (`AES_*`→`AES256_*`) so one binary
  can link both the AES-128 (SC1) and AES-256 (SC2) tiny-AES builds.
- **The Rust FFI mirror is hand-maintained.** Growing a C struct
  (`osdp_pd_t` / `osdp_acu_t`) REQUIRES updating both `rust/osdp/src/sys.rs`
  (the `#[repr(C)]` mirror — a stale one is silent heap corruption at
  runtime) and the C source list in `rust/osdp/build.rs`.

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
- File transfer, biometric, manufacturer-specific commands, multi-
  part / multi-record messages, PIV data exchange.
- Auto-poll scheduling on the ACU (the application currently drives
  every command).

## When in doubt

Ask the user. The user prefers iterative agreement on architecture over
silently broadening scope.
