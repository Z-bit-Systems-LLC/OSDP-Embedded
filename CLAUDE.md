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
   framing, the full v2.2 command/reply set (baseline plus osdp_KEYSET /
   LSTAT / ISTAT / OSTAT / RSTAT / ABORT / ACURXSIZE / KEEPACTIVE / MFG
   and their replies), PD-side state machine (with SC1 + SC2), ACU-side
   state machine (with SC1 + SC2), PD-side file transfer
   (osdp_FILETRANSFER / osdp_FTSTAT), and multi-part transport (spec
   5.10) carrying fragmented osdp_MFG. SC2 is the quantum-resistant
   channel (AES-256-GCM + KMAC256) built as a parallel implementation in
   the SCS_21..28 range; both sides are live-validated against OSDP.Net's
   `feature/osdp-sc2`. Still deferred: biometric, PIV / credential-set
   messages and their multi-part replies, multi-record messages, ACU-side
   file transfer. See [docs/PLAN.md](docs/PLAN.md) for what's done and
   what's next.

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

## Buffer sizing and working buffers

**One constant per role.** `OSDP_PD_BUF_LEN` (512) and `OSDP_ACU_BUF_LEN`
(1440), both `#ifndef`-guarded so a build can override with `-D` or CMake
`target_compile_definitions`, size every working buffer in `osdp_pd_t` /
`osdp_acu_t`. A device is a PD or an ACU, rarely both, so one knob per role is
enough. The roles default differently on purpose: a PD is the constrained end,
an ACU is normally a host and is the side that receives whatever any PD sends.

The same constant is what the role should advertise to its peer: the PD's
**PDCAP function code 10** ("Receive BufferSize", spec B.11) and the ACU's
**`osdp_ACURXSIZE`** (spec Table 28). Deriving the advertised capability from
the constant that sizes the buffers means a device cannot promise its peer
more than it can hold.

`OSDP_STREAM_BUFFER_LEN` (1440 = spec max) is separate and also overridable.
It is *wire-level* reassembly — big enough to resync through any legal frame,
including traffic addressed to other devices — as distinct from the message
size a role actually processes.

`osdp_pd_set_buffers(pd, &bufs)` then rebinds any subset at caller-owned
storage at run time (`osdp_pd_buffers_t`; a NULL member leaves that region
alone, an undersized one returns `OSDP_ERR_BUFFER_TOO_SMALL` and applies
nothing). Use the constant to set what every PD context costs; use the setter
when one particular PD needs something different.

- **`tx`** — the outbound frame under construction and the bytes handed to
  `transport.write()`.
- **`rx_plain`** — the decrypted plaintext of an inbound SCS_17 / SCS_27
  command. Was a stack array in `pd_sc.c` / `pd_sc2.c`. **Must not alias
  `tx`**: the reply an application returns may point into this plaintext, and
  the SC wrap then reads it while writing the outbound frame.
- **`rpl_cache` / `cmd_cache`** — the spec-5.9 retransmit caches. Rebinding
  either clears it, since the recorded lengths describe bytes the PD has just
  stopped reading; the cost is one non-replayed retransmit, processed fresh.

Every internal user goes through the `pd->tx` / `pd->tx_cap` pointers, never
the arrays or `sizeof()` — a path that reaches for `pd->tx_buf` directly keeps
passing field-inspection tests while writing to the wrong memory.

**No fixed internal ceilings on the Secure Channel paths.**
`osdp_sc_wrap_frame` and `osdp_sc2_unwrap_frame` used to route the
ciphertext through 256-byte *stack* scratch arrays, which capped every SC
message there no matter how much capacity the caller supplied. Both now work
directly in the caller's buffer, so SC message size is bounded by the bound
buffers alone:

- **SC1 wrap** encrypts into the ciphertext's final position in `out_buf`,
  located via `osdp_frame_payload_offset`. `osdp_frame_build` detects a
  payload pointer that already equals its destination and skips the copy —
  self-`memcpy` is UB, so this is a check, not a coincidence.
  `osdp_sc_encrypt_payload` already documented that its plaintext may alias
  its ciphertext.
- **SC2 unwrap** decrypts into the caller's buffer and `memmove`s the data
  down over the code byte. Consequence: `plain_cap` must hold `code || data`,
  i.e. **one byte more than the payload**. Pinned by
  `test_sc2_unwrap_needs_one_byte_more_than_the_payload`.

Raising the constants instead was rejected (1440 bytes of stack per wrap call
on an MCU), as was caller-supplied scratch (it would need a *fifth* PD
region, since neither `tx` nor `rx_plain` is free at that moment).

**Sizing helpers — use these instead of deriving overhead by hand:**

| Function | Answers |
| --- | --- |
| `osdp_frame_max_payload(shape, cap, *out)` | largest payload for plain framing |
| `osdp_sc_max_payload(...)` | same, less spec D.4.5 padding (always ≥1 byte, then rounds to an AES block) |
| `osdp_sc2_max_payload(...)` | same as plain framing — GCM does not expand |
| `osdp_pd_max_reply_payload(pd)` | what this PD can send *right now*, resolved against bound TX capacity and the live channel |

Each takes a frame *shape* (header fields only). Every one of their tests
checks the answer against what `build`/`wrap` actually accepts — reported
maximum must succeed, one more byte must fail — rather than restating the
arithmetic, so the helpers cannot drift from the code they describe.

## PD command dispatch — one path for every channel

`pd/src/pd_dispatch.c::osdp_pd_internal_dispatch` decides the reply for one
accepted command, whatever channel carried it. Plaintext, SC1 and SC2 all
funnel through it once the payload is in the clear; each caller then frames
the result its own way, which is the only thing that legitimately differs.
Anything added here works on all three channels at once — that is the point,
and it exists because the SC2 copy had already drifted (it intercepted
neither COMSET nor FILETRANSFER).

It returns an `osdp_pd_dispatch_outcome_t` rather than a status:

| Outcome | Meaning |
| --- | --- |
| `SEND` | frame `*reply` on the inbound channel. **Refusals are `SEND`** — a NAK is an ordinary reply. |
| `DROP` | no reply at all; the ACU waits out its timeout. Only an unrecognised handler error. |
| `BUSY` | `osdp_BUSY`, which cannot be framed on the inbound channel — see below. |

**Application handler status → wire reply (spec Table 47).** Before this
mapping, anything other than `OSDP_OK` / `OSDP_ERR_NOT_SUPPORTED` was dropped
silently and the ACU spent a full reply timeout learning nothing:

| `cmd_cb` returns | PD sends |
| --- | --- |
| `OSDP_OK` | the reply the handler filled in |
| `OSDP_ERR_NOT_SUPPORTED` | `osdp_NAK` 0x03 unknown command |
| `OSDP_ERR_BAD_PAYLOAD` / `_BAD_LENGTH` | `osdp_NAK` 0x02 bad length |
| `OSDP_ERR_INVALID_ARG` | `osdp_NAK` 0x09 unable to process record |
| `OSDP_ERR_BUSY` | `osdp_BUSY` (appended to `osdp_status_t` as 11) |
| anything else | nothing — silent drop survives as an escape hatch |

**`osdp_BUSY` is the one reply that leaves its channel.** Spec 7.19 puts
three rules on it, all exceptions, all centralised in
`pd.c::osdp_pd_internal_build_busy` so no caller has to remember them:

1. sequence number is **always 0**, not the inbound SQN;
2. it goes out **plaintext even during an established Secure Channel** and
   must not advance the MAC chain (SC1) or the message counter (SC2) — which
   is why the SC paths return before their wrap rather than framing it
   themselves. One of only three replies allowed outside the SCS format,
   with `osdp_NAK` 0x01 and 0x06;
3. it is **not cached** as the retransmit answer (`pd->reply_cacheable`),
   because the ACU repeats the command in its original form — a replayed BUSY
   would answer a command the PD is by then ready to handle.

`tests/test_pd_sc.c::test_busy_under_sc_is_plaintext_and_preserves_the_mac_chain`
pins rule 2 by having the ACU send its next SCS_15 against the pre-BUSY chain
state and unwrap the reply cleanly.

## Multi-part messages (spec 5.10)

The transport lives in `core/src/shared/multipart.c` + `osdp_multipart.h`
(`osdp_mp_*`). It was written for SC2 pairing, whose fragment header turned
out to be **byte-identical to spec Table 4** rather than merely similar, so
`core/src/pair/` now uses this one copy rather than keeping its own.

Header, everywhere it appears: `MpSizeTotal(2) || MpOffset(2) ||
MpFragmentSize(2)`, all little-endian, then the fragment bytes.

5.10.2 rules implemented: sequential with no gaps; first fragment at offset 0
(which also makes a retry idempotent — offset 0 restarts rather than
erroring); and **early termination**, which pairing never needed and is the
one genuinely new piece. A sender abandons a transfer by setting MpOffset at
or past MpSizeTotal with MpFragmentSize 0; `osdp_mp_reasm_push` reports
`OSDP_MP_TERMINATED` and discards the partial message. Two subtleties:

- The termination marker must be recognised **before** the "fragment cannot
  extend past MpSizeTotal" bounds check, since sitting at or past the end is
  exactly what identifies it.
- **MpSizeTotal 0 does not count.** Read literally an all-zero header is a
  valid marker, but a transfer declaring no bytes has nothing to terminate,
  and all-zeros is the shape a truncated frame takes — treating it as a
  marker would turn a malformed payload into a silent ACK instead of the
  NAK 0x09 it deserves.

Any sequencing violation is reported to the caller, which answers
`osdp_NAK 0x09` — spec 5.10.2 says that reply aborts the sender's sequence.

**`osdp_MFG` is the one in-scope v2.2 message that uses it.** Every other
multi-part message (osdp_PIVDATAR 7.20, osdp_GENAUTHR 7.21, osdp_CRAUTHR,
transparent-mode osdp_XWR/XRD) is in the deferred credential set. Fragmented
MFG is:

```
vendor_code[3] || MpSizeTotal,MpOffset,MpFragmentSize[6] || fragment
```

The vendor code sits **outside** the fragmentation and repeats on every
fragment, so a PD can tell whether a transfer is addressed to it before
committing buffer, and can refuse the first fragment rather than the last.

**Nothing on the wire distinguishes a multi-part header from six bytes of
ordinary vendor data** — Table 27 defines no multi-part fields for osdp_MFG —
so it cannot be auto-detected. Binding `osdp_pd_set_mfg_receiver` IS the
manufacturer's declaration that its protocol uses the standard format; leave
it unbound and MFG payloads stay opaque and reach `cmd_cb` unchanged. A
mid-transfer vendor-code switch is rejected rather than merged.

`osdp_ABORT` terminates a multi-part transfer as well as a file transfer,
which is what spec 6.22 actually says.

## PDCAP consistency (advisory)

`osdp_pd_check_pdcap` validates an application's capability records against
what the library can honour. Own TU, so an application that never calls it
does not link it; no wire behaviour, nothing calls it automatically.

Only three records are checked — the ones describing the *library's* limits,
since the rest describe the device and only the application knows those:
function code 9 claiming AES128 with no crypto vtable/key bound; function
code 10 exceeding `OSDP_STREAM_BUFFER_LEN`, or (with SC configured) implying
a plaintext larger than the bound `rx_plain`; function code 11 non-zero with
no multi-part reassembly buffer bound, or larger than the one that is.
Returns the offending record's index.

The fn-10-under-SC half is the non-obvious one: a message that fits the wire
can still be too large to *decrypt*, because SC plaintext lands in
`rx_plain`. The frame arrives cleanly and then fails to unwrap, which reads
as a MAC failure and isn't.

**Codes 10 and 11 encode a 16-bit size as LSB-then-MSB** across the two bytes
Annex B names "compliance level" and "number of" everywhere else. Filling them
in as the names suggest is precisely the mistake this checker exists to catch.

## PD status providers and the poll-response event queue

**Status providers** (`osdp_pd_set_status_provider`) answer osdp_LSTAT /
ISTAT / OSTAT / RSTAT. The reply *layout* is the spec's business and the
*values* are the application's, so the library builds the frame and calls a
provider for the bytes. Every member is independent and optional: a NULL
member leaves that one command falling through to `cmd_cb`, so existing
consumers that hand-build their own osdp_LSTATR keep working unchanged. The
array-valued members are capped at `OSDP_PD_REPLY_SCRATCH_LEN` (64) items and
an over-reporting provider is clamped rather than trusted.

**The event queue** (`osdp_pd_set_event_queue` / `osdp_pd_enqueue_event`)
holds the "sent as a poll response" replies — osdp_RAW, osdp_FMT,
osdp_KEYPAD, osdp_MFGREP — until the ACU next polls. Caller-owned storage, no
malloc. Records are `[u16 len][u8 code][payload]` laid out from offset 0, and
it is deliberately **not** a wrapping ring: a wrap would split a payload
across the buffer end, and the dequeue hands the payload to the framer as a
contiguous slice. Dequeue compacts what remains down to the front instead.
An empty queue falls through to `cmd_cb`, so this is additive. Per spec
7.11/7.12 the queue is emptied on the offline transition — delivering a
credential read from before an outage would have the ACU act on a stale
presentation.

## Library-handled commands (KEYSET, COMSET, FILETRANSFER, ABORT, ACURXSIZE, KEEPACTIVE)

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
- **`osdp_ABORT`** — handled entirely by the core. It tears down the
  file-transfer and multi-part state the spec requires terminated (6.22), then
  runs the optional `osdp_pd_set_abort_handler` hook for application-side work
  the core cannot know about. ACK by default; a hook returning non-OK becomes
  NAK 0x03, the spec's "PD unable to abort" case (a firmware update past the
  point of no return being its example).
- **`osdp_ACURXSIZE`** — handled entirely by the core: it stores the ACU's
  declared receive capacity (`osdp_pd_acu_rx_size`, seeded to
  `OSDP_PD_DEFAULT_ACU_RX_SIZE` = 128 per spec 6.26) and ACKs. The optional
  hook is a notification, not a veto — refusing to believe the ACU about its
  own buffer would only produce replies it drops. Malformed payload → NAK 0x02
  with the stored value left alone. **This is the peer's limit**; combine it
  with `osdp_pd_max_reply_payload` (this PD's own) and honour the smaller.
- **`osdp_KEEPACTIVE`** — decoded by the core, decided by the application via
  `osdp_pd_set_keepactive_handler`. Unlike the hooks above, with **no** handler
  the PD NAKs 0x03: holding a reader field energised is physical, so an ACK the
  PD cannot honour would be a lie.
- **`osdp_MFG` is deliberately NOT intercepted** unless a multi-part receiver
  is bound. The content is vendor-defined, so it flows to `cmd_cb`, which
  returns `reply.code = OSDP_REPLY_MFGREP` with a body built by
  `osdp_mfgrep_build`. See `docs/PD_GUIDE.md` for the pattern.

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

## Releasing

**"release the code"** / **"cut a release"** → run the four-step process
in [docs/PUBLISHING.md](docs/PUBLISHING.md), in order:

1. `./scripts/New-Release.ps1 -IncrementType <Patch|Minor|Major>` — bumps
   `rust/Cargo.toml` + `CMakeLists.txt` in lockstep, runs the
   `Check-Code.ps1` gates, commits, tags `v<version>`, pushes `main` and
   the tag.
2. Wait for the Azure build pipeline on the tag to go green. It packages
   the `.crate` and the tool binaries; it publishes nothing.
3. Approve the Classic **Release pipeline** in Azure DevOps. This runs
   `Publish-Crate.ps1` and is the **irreversible** step — the version is
   burned on crates.io forever, `cargo yank` only hides it.
4. `./scripts/Publish-GitHubRelease.ps1 -Tag v<version>` — builds notes
   from the commits since the previous tag and creates the GitHub
   Release. `-Draft` to hand-edit before it goes public.

   **Generated notes are the default**, matching OSDP.Net: no
   `CHANGELOG.md`, nothing written between releases, commit subjects
   *are* the notes. `-NotesFile` is the exception for a release a commit
   list would misrepresent — v1.0.0 is the only one so far.

Rules that are easy to get wrong:

- **Never re-tag or re-publish a version.** If a tagged build fails, fix
  forward and cut the next patch. crates.io will not accept the same
  version twice with different bytes.
- **Step 4 comes after step 3**, not before: a GitHub Release is an
  announcement, and the crate should exist before people try to install
  it.
- **Step 4 is manual and has been missed before.** v1.0.0 reached
  crates.io with no GitHub Release because the tooling only prompted for
  steps 2 and 3. `New-Release.ps1` now prints the step-4 command when it
  finishes; do not treat a cut tag as a finished release.
- **Releases start at v1.0.0.** The pre-1.0 tags (`v0.1.2`..`v0.1.28`)
  have no GitHub Releases and are deliberately not backfilled. crates.io
  holds only 0.1.0 from that era.
- **The repo-root `README.md` is the crates.io front page** —
  `Stage-Crate.ps1` copies it into the crate verbatim, with no link
  rewriting. Every in-repo link in it must therefore be an absolute
  `https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/...` URL, or it
  will 404 for crates.io readers. The README follows the
  [Z-bit README guidelines](https://github.com/Z-bit-Systems-LLC/Guidelines/blob/main/docs/readme-template.md);
  keep its structure when editing.
- **1.0.0 makes the public API a promise.** See "What 1.0.0 commits us
  to" in PUBLISHING.md before changing a public header — adding a member
  to a public struct is a breaking change, because consumers embed those
  structs by value.

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
- **Once in secure mode only the discovery commands are answered in the
  clear; sequence 0 resets a stale session but is not an escape hatch.** The
  clear-text (USC) policy has two independent parts, and both are identical
  for SC1 and SC2:

  1. *Session handling*, split on the sequence number:
     - **SQN 0** is the ACU's connection-restart sentinel (spec 5.9): it is
       only sent when the link is being (re)started, so any session the PD
       still believes in is stale. The PD drops it — both `sc` and `sc2` —
       **without** treating it as a violation, and moves on to (2).
     - **SQN != 0 during an established session** is a genuine interleaving
       violation (spec D "Interleaving USC packets during communication in a
       SCS is NOT allowed"): the session is torn down and the command
       answered `osdp_NAK 0x06` (`OSDP_NAK_ENCRYPTION_REQUIRED`) immediately.

  2. *Secure-mode allowlist*, applied at **every** sequence number including
     0. A PD keyed for full security — an operational SCBK is set for
     *either* channel version (`sc.scbk_set` or `sc2.scbk_set`), not merely
     SCBK-D — answers only `osdp_ID`, `osdp_CAP`, `osdp_COMSET` in the clear,
     the commands the ACU needs to find the PD and bring SC up. Everything
     else gets `osdp_NAK 0x06` until a session exists. A PD with no
     operational key (clear-only / install-only) is not in secure mode and
     stays permissive.

  So SQN 0 buys a session reset and nothing more: a clear-text `osdp_POLL` at
  SQN 0 against a full-security PD still gets NAK 0x06, while an `osdp_ID` at
  SQN 0 both clears the stale session and is answered — the reconnect costs
  one message without opening a hole around Secure Channel.

  The SCB-bearing handshake (`osdp_CHLNG`/`osdp_SCRYPT`) never reaches the
  clear-text path, so a re-handshake still works mid-session, and the SC2
  pairing hook runs ahead of all of this so `osdp_PAIR` is never refused.
  Implemented in `pd/src/pd.c::handle_command_into_tx`.
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
  `rust/osdp/src/pd_layout_tests.rs` now guards the `osdp_pd_t` half of
  that: `osdp_pd_init` writes *self-referential* pointers (each buffer
  binding points at an embedded array in the same struct), so the test
  compares C-computed addresses against Rust-computed ones and fails when
  the layouts disagree. It lives in `src/` rather than `tests/` because
  `sys` is `pub(crate)`. It covers the struct up to the buffer bindings,
  not the tail — a mirror that is *too small* still corrupts the heap
  before any assertion runs (verified: the C `memset` in `osdp_pd_init`
  overruns the Rust `Box`), so keep adding fields to both sides in step.

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
  has no file-send driver). Biometric, PIV data exchange and the rest of
  the credential set (osdp_GENAUTH / osdp_CRAUTH / transparent-mode
  osdp_XWR / osdp_XRD), and multi-record messages. Multi-part transport
  itself is implemented, but only osdp_MFG rides it — extending it to a
  deferred credential message means implementing that message first.
- Auto-poll scheduling on the ACU (the application currently drives
  every command).

## When in doubt

Ask the user. The user prefers iterative agreement on architecture over
silently broadening scope.
