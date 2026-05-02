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
8. **Scope: OSDP v2.2 baseline command/reply set.** Secure Channel, file
   transfer, biometric, and similar extensions are deferred to later
   iterations.
9. **Iteration 1 is decoder-only.** No transmit path, no state machine, no
   Secure Channel. See [docs/PLAN.md](docs/PLAN.md).

## Module layout

```
core/include/osdp/
  osdp_types.h        # shared types, error codes, enums
  osdp_frame.h        # Layer 1 framing
  osdp_stream.h       # streaming push decoder
  osdp_commands.h     # all command models + per-message prototypes
  osdp_replies.h      # all reply models + per-message prototypes
  osdp_dispatch.h     # optional bulk dispatch helpers

core/src/
  shared/             # crc16.c, checksum.c, frame.c, stream.c — always linked
  commands/           # cmd_<name>.c — model + decode + build per command
  replies/            # reply_<name>.c — model + decode + build per reply
  dispatch/           # opt-in bulk routing; references every codec

tools/
  osdp-parser/        # host-side CLI: OSDPCAP reader + Monitor pipeline
                      # (osdpcap.{c,h} + main.c). Built when
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

A PD or ACU links `core + messages` and uses linker GC to keep flash usage
tight. A Monitor adds `dispatch` for one-call bulk routing.

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

## Out of scope (do not introduce without explicit user approval)

- Dynamic memory allocation anywhere in `core/`.
- OS / RTOS calls (threading, mutexes, sleeps, file I/O) in `core/`.
- Secure Channel (osdp_SCRYPT, osdp_KEYSET, AES-128 session, MAC).
- File transfer, biometric, manufacturer-specific commands.
- State machines or transport layers — those belong in `pd/`, `acu/`,
  `monitor/` peer trees added in later iterations.
- A vendored crypto library — when SC arrives, it goes behind a HAL the
  consumer fulfills (e.g. mbedTLS on host, hardware AES on MCU).

## When in doubt

Ask the user. The user prefers iterative agreement on architecture over
silently broadening scope.
