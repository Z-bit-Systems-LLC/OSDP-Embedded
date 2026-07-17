# Using the OSDP-Embedded PD library

This guide explains how to build an OSDP **Peripheral Device** (PD) — a
reader, I/O board, or other access-control endpoint on top of the
`osdp::pd` layer. It is the role-specific state machine that sits on top
of the framing/codec core: it turns an inbound byte stream into decoded
commands, drives the Secure Channel handshake, and frames your replies
back onto the wire.

The public API lives in [`pd/include/osdp/osdp_pd.h`](../pd/include/osdp/osdp_pd.h).
A complete, working reference application is
[`tools/osdp-pd-mock/main.c`](../tools/osdp-pd-mock/main.c) — read it
alongside this guide.

**Contents**

- [Design constraints you inherit](#design-constraints-you-inherit)
- [Getting started](#getting-started) — the fast path to a running PD
- Function-by-function reference:
  - [`osdp_pd_init`](#osdp_pd_init--create-a-pd)
  - [`osdp_pd_set_transport`](#osdp_pd_set_transport--the-io-hal)
  - [`osdp_pd_set_command_handler`](#osdp_pd_set_command_handler--your-device-logic)
  - [Reporting events on POLL](#reporting-events-on-poll--keep-queued-replies-fresh) — freshness of queued replies
  - [`osdp_pd_tick`](#osdp_pd_tick--pump-the-state-machine)
  - [`osdp_pd_is_online`](#osdp_pd_is_online--connection-state)
  - [LED observation](#led-observation--osdp_pd_set_led_handler--osdp_pd_led_color)
  - [Buzzer observation](#buzzer-observation--osdp_pd_set_buzzer_handler--osdp_pd_buzzer_sounding)
  - [Communication configuration](#communication-configuration--osdp_pd_set_comset_handler)
  - [File transfer](#file-transfer--osdp_pd_set_file_receiver)
  - [Secure Channel](#secure-channel--osdp_pd_set_sc_)
  - [Key rotation with `osdp_KEYSET`](#key-rotation-with-osdp_keyset)
- [Reference tables](#reference-tables)
- [Try it without hardware](#try-it-without-hardware)

---

## Design constraints you inherit

The PD layer keeps the core's freestanding contract, and these shape how
you use it:

- **No memory allocation, no globals, no I/O of its own.** You own every
  buffer. The `osdp_pd_t` context is a plain struct you place wherever
  you like (static storage, stack, a larger device struct).
- **Non-blocking and cooperative.** Nothing inside the library sleeps or
  blocks. You call `osdp_pd_tick()` from your main loop; it reads
  whatever bytes are available right now, processes any complete frames,
  and returns.
- **Reentrant.** No hidden shared state. Multiple PD instances in one
  binary are fine, each with its own context and transport.
- **You supply transport and crypto.** The library never touches a UART,
  socket, or AES engine directly — it calls callbacks you provide.

---

## Getting started

This section gets you from nothing to a PD that stays online and answers
the ACU's poll. The later sections then cover each API call in depth.

### 1. Link the right targets

A PD application links three CMake targets:

```cmake
target_link_libraries(my_pd_app PRIVATE
    osdp::core       # framing, stream decoder, CRC, checksum
    osdp::messages   # the command/reply codecs you reference
    osdp::pd)        # PD-side state machine + transport HAL
```

Linker garbage collection (already configured by the project's CMake)
drops every codec your application never calls, so advertising
`osdp::messages` doesn't bloat your binary. You do **not** link
`osdp::dispatch` — that's for Monitors that bulk-decode every message
type; a PD only reacts to commands aimed at its own address.

### 2. Write a minimal command handler

The handler is where your device logic lives. A PD that merely stays
online only needs to acknowledge the poll:

```c
#include "osdp/osdp_pd.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"

static osdp_status_t handler(void *user, uint8_t code,
                             const uint8_t *payload, size_t len,
                             osdp_pd_reply_t *reply)
{
    switch (code) {
    case OSDP_CMD_POLL:                 /* the ACU's heartbeat */
        reply->code = OSDP_REPLY_ACK;
        reply->payload = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;  /* → NAK 0x03 */
    }
}
```

### 3. Wire up and run the tick loop

```c
osdp_pd_t pd;
osdp_pd_init(&pd, /* address */ 0x00);
osdp_pd_set_transport(&pd, &my_transport);     /* see osdp_pd_set_transport */
osdp_pd_set_command_handler(&pd, handler, NULL);

for (;;) {
    osdp_pd_tick(&pd);
    /* cooperative yield: sleep a couple ms, wfi, schedule other work … */
}
```

The one piece you must provide for real I/O is the transport — three
non-blocking callbacks over your UART/socket. That's the next section.

Want to see it end-to-end before writing any of it? `tools/osdp-pd-mock`
*is* this library running as a live PD on a serial port — jump to
[Try it without hardware](#try-it-without-hardware).

---

## `osdp_pd_init` — create a PD

```c
void osdp_pd_init(osdp_pd_t *pd, uint8_t address);
```

Zeroes the entire context, masks `address` to 7 bits (`0x00`–`0x7E`), and
initializes the inbound stream decoder. Call it first, before any other
PD function. Everything optional (Secure Channel, LED/buzzer observation)
stays dormant until you opt in.

The PD answers its own `address` **and** the broadcast address `0x7F`. It
ignores frames addressed elsewhere and frames flowing the wrong direction
(replies). `osdp_pd_t` is a plain value type — place it in static storage,
on the stack, or inside a larger device struct; multiple independent PDs
in one binary are fine.

---

## `osdp_pd_set_transport` — the I/O HAL

```c
void osdp_pd_set_transport(osdp_pd_t *pd, const osdp_pd_transport_t *transport);
```

You implement three callbacks and bind them. The vtable is copied into
the context, so a stack-local `osdp_pd_transport_t` is fine.

```c
typedef struct osdp_pd_transport {
    int  (*read)(void *user, uint8_t *buf, size_t cap);
    int  (*write)(void *user, const uint8_t *buf, size_t len);
    uint32_t (*now_ms)(void *user);   /* optional */
    void *user;
} osdp_pd_transport_t;
```

- **`read`** — non-blocking. Copy up to `cap` bytes of whatever has
  arrived into `buf`, return the count. Return `0` when nothing is
  available (do **not** block waiting for data). Negative returns are
  reserved; return `0` on idle.
- **`write`** — push `len` bytes out. May briefly block to enqueue into a
  UART driver, but must not stall indefinitely. Return the number of
  bytes accepted; a short write is treated as a transmission error and the
  reply is dropped.
- **`now_ms`** — a monotonic millisecond clock. **Optional but
  recommended.** If `NULL`:
  - the online/offline timeout (spec 5.7) is disabled — the PD becomes
    "online" after its first successful reply and stays so forever;
  - time-driven LED flashing and buzzer pattern edges don't advance
    (command-driven colour changes still resolve).
  32-bit wraparound (~49.7 days) is handled internally via unsigned
  subtraction, so a 32-bit clock is sufficient.

`user` is threaded back into every callback unchanged — point it at your
UART handle, socket, or device struct.

> **RS-485 note:** the library writes the whole reply in one `write()`
> call. If your transceiver needs driver-enable (DE/RE) toggling, do it
> inside `write` around the byte push (assert DE, send, wait for the last
> byte to clear the shift register, deassert).

---

## `osdp_pd_set_command_handler` — your device logic

```c
void osdp_pd_set_command_handler(osdp_pd_t *pd, osdp_pd_command_cb cb, void *user);
```

Binds the callback the PD invokes for each accepted command. Pass
`cb = NULL` to detach (every command then NAKs with code `0x03`). The
PD validates each inbound frame (CRC/checksum, address, length, and —
under Secure Channel — the MAC and decryption) *before* calling you, so
the handler only ever sees clean, plaintext commands:

```c
osdp_status_t handler(void *user,
                      uint8_t cmd_code,
                      const uint8_t *payload, size_t payload_len,
                      osdp_pd_reply_t *reply);
```

Fill in `*reply` and return one of three policies:

| Return value             | Wire result                                            |
| ------------------------ | ------------------------------------------------------ |
| `OSDP_OK`                | The PD frames and transmits the reply you filled in.   |
| `OSDP_ERR_NOT_SUPPORTED` | The PD sends `NAK` with code `0x03` (Unknown Command). |
| any other `osdp_status_t`| Treated as an internal error; the command is dropped silently (no reply). |

The reply is a code plus an optional payload buffer:

```c
typedef struct osdp_pd_reply {
    uint8_t        code;          /* an OSDP_REPLY_* value              */
    const uint8_t *payload;       /* body bytes (may be NULL)           */
    size_t         payload_len;   /* 0 for ACK and other empty replies  */
} osdp_pd_reply_t;
```

The payload buffer must stay valid only until the handler returns — the PD
copies it into its own TX scratch before transmitting. The usual pattern
is a scratch buffer inside your own application-state struct (pointed to
by `user`), sized at most `OSDP_PD_TX_BUF_LEN`.

### Replies that carry data

For commands that demand a structured reply (ID, capabilities, status
requests), use the matching `osdp::messages` builder to encode the body
into your scratch buffer, then point the reply at it:

```c
case OSDP_CMD_ID: {                     /* osdp_ID → osdp_PDID */
    size_t built = 0;
    if (osdp_pdid_build(&app->pdid, app->scratch,
                        sizeof(app->scratch), &built) != OSDP_OK)
        return OSDP_ERR_BAD_PAYLOAD;
    reply->code        = OSDP_REPLY_PDID;
    reply->payload     = app->scratch;
    reply->payload_len = built;
    return OSDP_OK;
}
```

> **Status requests need real reports, not an ACK.** `osdp_LSTAT`,
> `osdp_ISTAT`, `osdp_OSTAT`, and `osdp_RSTAT` must be answered with
> `LSTATR`/`ISTATR`/`OSTATR`/`RSTATR` respectively (spec 7.6–7.9). ACKing
> them is a conformance bug. See the mock's handler for the report
> builders and how the report length derives from the capabilities you
> advertise.

### Commands the framework handles around you

A few commands have framework behaviour layered on top of your handler —
you still just ACK them, and the PD does the right thing on the wire:

- **`osdp_LED` / `osdp_BUZ`** — the PD transparently decodes these into
  its internal reader-state banks (see the LED/buzzer sections)
  *regardless* of what your handler replies. ACK them.
- **`osdp_KEYSET`** — ACK it and the PD rotates the stored Secure Channel
  Base Key for you; NAK it (or leave it unhandled) and nothing rotates.
  The rotation happens in RAM only — persisting the new key across a reboot
  is your job. See [Key rotation with `osdp_KEYSET`](#key-rotation-with-osdp_keyset)
  for the full contract, the exact NAK codes, and the persistence pattern.
- **`osdp_COMSET`** — handled entirely by the PD: it builds the mandated
  `osdp_COM` reply and switches its own address for you. It never reaches
  your command handler. Register an
  [`osdp_pd_set_comset_handler`](#communication-configuration--osdp_pd_set_comset_handler)
  hook to veto/clamp the requested values and to enact the baud change on
  your transport.
- **`osdp_FILETRANSFER`** — handled entirely by the PD: it reassembles the
  file into a buffer you provide and builds every `osdp_FTSTAT` reply. It
  never reaches your command handler. Register an
  [`osdp_pd_set_file_receiver`](#file-transfer--osdp_pd_set_file_receiver)
  to supply the buffer and evaluate the bytes.

### Sequencing & retransmits are automatic

You don't manage sequence numbers. The PD echoes the inbound SQN,
address, and integrity mode into every reply (spec 5.9), and it detects
retransmits the spec-correct way: a frame **byte-identical** to the
previously accepted command replays the cached reply *without*
re-invoking your handler. (SQN-only matching is insufficient because OSDP
cycles 1→2→3→1.) So your handler is effectively "called once per
genuinely new command" — side effects won't double-fire on a retransmit.

---

## Reporting events on POLL — keep queued replies fresh

OSDP is strictly master-slave: a PD **never** transmits spontaneously. So
anything the device wants to tell the ACU — a card was presented (`RAW`),
a key was pressed (`KEYPAD`), tamper/power changed (`LSTATR`) — has to
wait for the next `OSDP_CMD_POLL` and be returned *in place of* the usual
`ACK`. The natural implementation is an application-side FIFO that your
POLL handler drains one entry per poll:

```c
case OSDP_CMD_POLL: {
    event_t ev;
    if (event_queue_pop_fresh(&app->events, now_ms, &ev)) {
        reply->code        = ev.code;       /* RAW / KEYPAD / LSTATR … */
        reply->payload     = ev.payload;
        reply->payload_len = ev.payload_len;
    } else {
        reply->code = OSDP_REPLY_ACK;       /* nothing pending */
        reply->payload = NULL; reply->payload_len = 0;
    }
    return OSDP_OK;
}
```

### Stale events must be discarded, not replayed

A point-in-time report is only meaningful right after it happens. A real
reader reports a card on the *very next* poll (sub-second) or the read is
gone — it never buffers a credential for minutes. If your queue lets
entries live forever, an ACU that stopped polling and reconnected later
would receive a **stale** card-read and could grant access for a
credential presented minutes ago — a replay risk.

So stamp each event with the time it was enqueued and **drop it once it
ages past a short freshness window** (the reference MCP PD uses a 2 s TTL,
matching its "actively polling" definition). A queued read is delivered
promptly while the link is actively polled, or discarded — reported on the
next poll or not at all. Prune from the front of the FIFO on each POLL;
with a uniform TTL, once you reach a fresh entry the rest are fresher
still.

### Exception: status reports reflect current state

`osdp_LSTATR`, `osdp_OSTATR`, and `osdp_ISTATR` are **not** transient
events and are exempt from the freshness rule. They answer the ACU's
explicit status *queries* (`osdp_LSTAT` / `osdp_OSTAT` / `osdp_ISTAT`) with
the device's *current* local, output, and input state — there is no such
thing as a "stale" current state, so you always report live values rather
than aging a queued snapshot.

The one moment a status report is naturally "queued" is **power-up**: a
power-cycle condition is surfaced through the local status report at
initialization (the first poll after the PD comes up), then reflects
steady state thereafter. Don't apply the credential-style TTL to it —
losing the power-on indication to an expiry timer would hide a genuine
device-state change.

---

## `osdp_pd_tick` — pump the state machine

```c
void osdp_pd_tick(osdp_pd_t *pd);
```

Call this repeatedly from your main loop. Each call: checks the offline
timeout, drains available bytes via `transport.read`, processes every
complete frame addressed to this PD or the broadcast, dispatches to your
handler, transmits replies via `transport.write`, and re-resolves the
LED/buzzer banks so time-driven changes reach their callbacks. It is
idempotent, non-blocking, and a no-op if no transport `read` is bound.

Because it never blocks, you control the cadence — yield, sleep a couple
of milliseconds, or `wfi` between ticks. At 9600 baud a byte is ~1 ms, so
a 1–2 ms loop interval keeps latency low without busy-spinning.

---

## `osdp_pd_is_online` — connection state

```c
bool osdp_pd_is_online(const osdp_pd_t *pd);
```

Per spec 5.7 a PD considers itself **offline** after
`OSDP_PD_OFFLINE_TIMEOUT_MS` (8 s) with no successfully transmitted reply.

```c
if (osdp_pd_is_online(&pd)) { /* drive a "linked" indicator, etc. */ }
```

A freshly-initialized PD is offline; it flips online on the first
successful reply and back offline if the ACU goes quiet past the timeout
(at which point the sequence cache is cleared so a reconnect starts
clean). This tracking requires the `now_ms` clock; without it the PD is
simply "online once it has replied."

---

## LED observation — `osdp_pd_set_led_handler` / `osdp_pd_led_color`

```c
void    osdp_pd_set_led_handler(osdp_pd_t *pd, osdp_pd_led_cb cb, void *user);
uint8_t osdp_pd_led_color(const osdp_pd_t *pd, uint8_t reader_no, uint8_t led_no);
```

When the ACU drives a reader's LED you usually want to *act* on it (light
a physical LED) rather than parse the `osdp_LED` (0x69) command yourself.
The PD folds every inbound LED command into internal resolver banks and
hands you an already-resolved view. The command still flows to your
handler (ACK it as normal); the wire behaviour is unchanged.

Consume it with a change callback, by polling, or both:

```c
/* Callback: fires on every displayed-colour change — a new command, a
 * temporary-override timer expiring, and each flash on/off edge.
 * color: osdp_led_color_t, 0x00 black/off .. 0x07 white. */
static void on_led(void *user, uint8_t reader, uint8_t led, uint8_t color) {
    set_physical_led(reader, led, color);
}
osdp_pd_set_led_handler(&pd, on_led, &app);

/* …or poll the current resolved colour whenever you like: */
uint8_t c = osdp_pd_led_color(&pd, /*reader*/0, /*led*/0);
```

- Time-driven transitions (override-timer expiry, flash edges) are
  detected inside `osdp_pd_tick()`, so they only fire if your transport
  supplies `now_ms`. Command-driven changes fire immediately regardless.
- `osdp_pd_led_color` returns `OSDP_LED_BLACK` for an LED no command has
  ever addressed.
- The bank holds `OSDP_PD_MAX_LEDS` (8) distinct `(reader, led)` pairs.
  LEDs beyond capacity are still ACKed on the wire, just not tracked. Bump
  the `#define` if you need more.
- Registering a handler reports changes from that point on; it does not
  replay current colours. The callback **must not** re-enter the PD API.

---

## Buzzer observation — `osdp_pd_set_buzzer_handler` / `osdp_pd_buzzer_sounding`

```c
void osdp_pd_set_buzzer_handler(osdp_pd_t *pd, osdp_pd_buzzer_cb cb, void *user);
bool osdp_pd_buzzer_sounding(const osdp_pd_t *pd, uint8_t reader_no);
```

The buzzer mirror works exactly like the LED one, for inbound `osdp_BUZ`
(0x6A) commands. The PD resolves the command's on/off/count pattern over
time so you don't have to.

```c
/* Fires when the buzzer starts, on each beep/silence edge, and once more
 * when the pattern completes (a final sounding=false).
 * tone: 0x01 off / 0x02 default tone. */
static void on_buz(void *user, uint8_t reader, bool sounding, uint8_t tone) {
    set_beeper(reader, sounding);
}
osdp_pd_set_buzzer_handler(&pd, on_buz, &app);

bool beeping = osdp_pd_buzzer_sounding(&pd, /*reader*/0);
```

- Pattern edges are time-driven, so they need `now_ms`; the initial start
  fires immediately regardless.
- The bank holds `OSDP_PD_MAX_BUZZERS` (4) readers (one buzzer each);
  beyond that, commands are ACKed but untracked.
- Callbacks **must not** re-enter the PD API.

---

## Communication configuration — `osdp_pd_set_comset_handler`

```c
void osdp_pd_set_comset_handler(osdp_pd_t *pd,
                                osdp_pd_comset_cb         decide,
                                osdp_pd_comset_applied_cb applied,
                                void *user);
```

`osdp_COMSET` (0x6E) asks the PD to adopt a new address and/or baud rate.
The PD owns its 7-bit address (it filters inbound frames on it and stamps
it into every reply), so — like `osdp_KEYSET` — the library handles COMSET
itself instead of routing it to your command handler: it builds the
mandated `osdp_COM` (0x54) reply and switches `pd->address` for you. Per
spec 6.13 the change takes effect **only after the reply has been sent** at
the old parameters.

Two optional hooks bracket that exchange:

```c
/* decide: runs BEFORE osdp_COM is built. eff_* start as the requested
 * values; overwrite them if you can't comply (spec 6.13 — report what you
 * WILL use). Leave them alone to accept. */
static void on_comset_decide(void *user, uint8_t req_addr, uint32_t req_baud,
                             uint8_t *eff_addr, uint32_t *eff_baud) {
    if (!baud_supported(req_baud)) *eff_baud = current_baud();  /* keep old */
}

/* applied: runs AFTER osdp_COM has been sent and the PD adopted the new
 * address. Reconfigure your UART to `baud` and persist (address, baud) to
 * non-volatile storage here — doing it earlier would corrupt the reply. */
static void on_comset_applied(void *user, uint8_t address, uint32_t baud) {
    uart_set_baud(baud);
    nvm_store_comms(address, baud);
}

osdp_pd_set_comset_handler(&pd, on_comset_decide, on_comset_applied, &app);
```

- Both callbacks are optional (pass `NULL`). With no `decide` handler the
  PD accepts the requested values verbatim; with no `applied` handler the
  address still switches but you get no signal to change the baud — supply
  one whenever the baud can actually change.
- The **address** change is automatic; the `applied` hook only needs to
  *persist* it. The **baud** change is yours to enact — the core has no
  UART.
- **Drain TX before you change the baud.** The library has already called
  your transport's `write()` for the `osdp_COM` reply by the time `applied`
  fires, but `write()` returning does **not** mean the bytes have physically
  left the wire — most drivers return once the data is queued. If you switch
  the line rate while the tail of the reply is still in a FIFO, the ACU sees
  a corrupted `osdp_COM` and never follows you to the new rate. Block until
  the reply has actually drained first: `tcdrain(fd)` on POSIX; on Windows
  `FlushFileBuffers` **plus** a wait, since USB adapters (FTDI etc.) hold
  bytes in a chip FIFO past `FlushFileBuffers`/`cbOutQue` and add USB
  latency — waiting out one worst-case frame time at the *old* baud (plus a
  small margin) is the reliable guard. See `tools/osdp-pd-mock/serial_*.c`
  for a working implementation on both platforms.
- An effective address above 0x7E is rejected (the current address is
  kept). A malformed COMSET (payload ≠ 5 bytes) is NAK'd 0x02 and neither
  hook fires.
- Callbacks **must not** re-enter the PD API.

---

## File transfer — `osdp_pd_set_file_receiver`

`osdp_FILETRANSFER` (0x7C) streams a file — a firmware image, a config blob —
from the ACU to the PD as a sequence of fragments at increasing offsets, each
answered with an `osdp_FTSTAT` (0x7A) status. The PD **owns the whole
exchange**: it decodes each fragment, enforces the offset rules, tracks the
running position, and builds every `osdp_FTSTAT`. Your only job is to evaluate
(and store) the bytes, through one per-fragment callback.

### Two modes — pick by what the target can afford

The exact same callback runs in either mode; the choice is only about **who
holds the file**:

| | **Reassembly** — `osdp_pd_set_file_receiver` | **Streaming** — `osdp_pd_set_file_stream` |
| --- | --- | --- |
| Buffer | You supply one, sized for the whole file | None |
| RAM cost | Whole file | One fragment (~128 B–1.5 KB) |
| Size ceiling | `total_size` must fit the buffer (else abort `-1`) | No ceiling |
| Callback reads | `info->data` (the complete file, on the final fragment) | `info->fragment` (this fragment only; `info->data` is `NULL`) |
| **Use when…** | You must **validate the whole file before acting** (verify a signature/CRC over the complete image) or parse a small structured blob (biomatch template, display data) | You're doing **firmware update on a RAM-constrained MCU** — persist each fragment to a flash staging area as it arrives; RAM use is independent of file size |

Rule of thumb: **small blob you want in one piece → reassembly; large image you
stream to flash → streaming.** If you'd end up copying fragments into your own
buffer in streaming mode anyway, use reassembly and let the core do it.

**Reassembly** — the core hands you the complete file to validate then commit:

```c
/* A caller-owned reassembly buffer, sized for the largest file you expect. */
static uint8_t g_file_buf[64 * 1024];

static osdp_status_t on_file(void *user, const osdp_pd_file_info_t *info)
{
    if (info->offset == 0 && info->fragment_len >= 4 &&
        memcmp(info->fragment, "FWUP", 4) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;   /* wrong file → FtStatusDetail -3 */
    }
    if (info->complete) {
        if (!signature_ok(info->data, info->received)) {  /* whole-file check */
            return OSDP_ERR_BAD_PAYLOAD;
        }
        flash_image(info->data, info->received);          /* commit the file */
    }
    return OSDP_OK;   /* proceed (0) mid-file; processed (1) when complete */
}

osdp_pd_set_file_receiver(&pd, g_file_buf, sizeof(g_file_buf), on_file, NULL);
```

**Streaming** — the core hands you each fragment; you persist it as it comes,
holding no more than one fragment in RAM:

```c
static osdp_status_t on_chunk(void *user, const osdp_pd_file_info_t *info)
{
    /* info->data is NULL here — read info->fragment / fragment_len. */
    flash_write(info->offset, info->fragment, info->fragment_len);
    if (info->complete) {
        flash_finalize();   /* whole image is now on flash */
    }
    return OSDP_OK;
}

osdp_pd_set_file_stream(&pd, on_chunk, NULL);   /* no buffer */
```

### What the core does for you in both modes

- **The callback fires once per accepted fragment**, so you can validate
  *incrementally* — check a header the moment `offset == 0` arrives, hash as
  bytes stream in — and reject mid-transfer. The return value maps to the
  reported status:

  | return | `FtStatusDetail` | meaning |
  | --- | --- | --- |
  | `OSDP_OK` (mid-file) | `0` | ok to proceed |
  | `OSDP_OK` (final fragment) | `1` | file processed |
  | `OSDP_ERR_BAD_PAYLOAD` | `-3` | malformed — transfer aborts |
  | `OSDP_ERR_NOT_SUPPORTED` | `-2` | unrecognized — transfer aborts |
  | anything else | `-1` | abort |

- **Offset invariants are enforced for you** (both modes). The first fragment
  must be at offset 0; offsets must be contiguous and monotonic; the type/size
  must not change mid-stream. Any violation aborts (`-1`) and resets, so the
  ACU can restart at offset 0. A byte-identical retransmit of the previous
  fragment replays the cached FTSTAT (spec 5.9) *before* the callback runs — a
  lost reply never corrupts the running offset or re-delivers a fragment.
- `info->received` is the cumulative contiguous byte count in both modes — use
  it for "N of `total_size`" progress.
- **No receiver registered → NAK 0x03** (the PD advertises no file-transfer
  support). An undecodable frame (payload shorter than the 11-byte header) →
  NAK 0x02.
- Under Secure Channel the `osdp_FTSTAT` reply is data-bearing, so it wraps as
  SCS_18 automatically — nothing extra to do.
- Not yet implemented (the callback is synchronous, so you don't need them):
  the "finishing" (`FtStatusDetail = 3`) idle-fragment protocol and
  `FtUpdateMsgMax` throttling — the PD always reports `update_msg_max = 0`.
- The callback **must not** re-enter the PD API.

---

## Secure Channel — `osdp_pd_set_sc_*`

```c
void osdp_pd_set_sc_crypto(osdp_pd_t *pd, const osdp_sc_crypto_t *crypto);
void osdp_pd_set_sc_scbk  (osdp_pd_t *pd, const uint8_t scbk[OSDP_SC_KEY_LEN]);
void osdp_pd_set_sc_scbk_d(osdp_pd_t *pd, const uint8_t scbk_d[OSDP_SC_KEY_LEN]);
void osdp_pd_set_sc_cuid  (osdp_pd_t *pd, const uint8_t cuid[OSDP_SC_CUID_LEN]);
bool osdp_pd_sc_established(const osdp_pd_t *pd);
```

Secure Channel is entirely opt-in. Leave it unconfigured and the PD NAKs
any SCB-bearing frame with code `0x05` (`OSDP_NAK_UNSUPPORTED_SCB`).
Configure it and the PD drives the full SCS_11..14 handshake and then
transparently unwraps SCS_15..18 operational traffic — your command
handler keeps seeing plaintext command codes and payloads either way, and
your replies get wrapped automatically (encrypted SCS_18 when they carry a
payload, MAC-only SCS_16 when empty).

### Supply the crypto

Because the core never vendors crypto, you fill an AES-128 + RNG vtable
([`osdp_sc_crypto_t`](../core/include/osdp/osdp_sc_crypto.h)):

```c
typedef struct osdp_sc_crypto {
    osdp_status_t (*aes128_ecb_encrypt)(void*, const uint8_t key[16],
                                        const uint8_t in[16], uint8_t out[16]);
    osdp_status_t (*aes128_ecb_decrypt)(void*, const uint8_t key[16],
                                        const uint8_t in[16], uint8_t out[16]);
    osdp_status_t (*rand_bytes)(void*, uint8_t *out, size_t len);
    void *user;
} osdp_sc_crypto_t;
```

Back it with whatever your platform has: a hardware AES peripheral
(STM32 CRYP, nRF CryptoCell, ESP32), or a software library (mbedTLS,
BearSSL) plus a real CSPRNG (`BCryptGenRandom`, `/dev/urandom`, a hardware
RNG). The PD needs all three: `encrypt` and `decrypt` (it receives
encrypted SCS_17 payloads) and `rand_bytes` (it generates the 8-byte
RND.B).

### Configure keys and identity

Bind the crypto, the cUID, and at least one key before the first inbound
`CHLNG`:

```c
osdp_pd_set_sc_crypto(&pd, my_crypto);          /* AES + RNG vtable          */
osdp_pd_set_sc_cuid  (&pd, cuid);               /* first 8 bytes of the PDID */
osdp_pd_set_sc_scbk_d(&pd, OSDP_SCBK_DEFAULT);  /* install/dev key …         */
osdp_pd_set_sc_scbk  (&pd, my_scbk);            /* …and/or operational key   */
```

- The **cUID** is the first 8 bytes of the PDID byte stream (vendor[3] +
  model + version + serial[0..2], spec D.4.3). Build the PDID with
  `osdp_pdid_build` and copy the leading 8 bytes — the mock's
  `cuid_from_pdid` helper does exactly this.
- **SCBK-D** (`OSDP_SCBK_DEFAULT`, the well-known default install key) is
  used when the ACU requests the SCBK-D key selector — first-time keying
  and development. **SCBK** is the per-installation operational key. Set
  either or both; the ACU's `CHLNG` selects which applies.

### Observe the session

The handshake runs invisibly below your handler. Poll
`osdp_pd_sc_established()` to react to the session coming up or being torn
down (the mock prints a banner on the transition):

```c
bool sc_up = osdp_pd_sc_established(&pd);
```

> A clear-text command at sequence 0 signals the ACU is (re)starting the
> connection and drops any stale SC session automatically; the ACU then
> re-discovers the PD and re-handshakes. You don't manage any of this.

---

## Key rotation with `osdp_KEYSET`

The ACU rotates a PD's Secure Channel Base Key (SCBK) by sending
`osdp_KEYSET` (0x75) — almost always **inside** an established Secure
Channel, so the new key never crosses the wire in the clear. The library
performs the rotation for you, but two things are yours to own: **ACKing
the command** and **persisting the key**.

### What the library does

When your command handler returns `OSDP_OK` for an `osdp_KEYSET`, the PD —
*before* it transmits the ACK — decodes the payload and, if it is a
well-formed 16-byte SCBK (`key_type` = `OSDP_KEYSET_KEY_TYPE_SCBK`,
`key_length` = 16), overwrites the stored key in `pd.sc.scbk`. The **live
SC session keeps running untouched**: the session keys, SQN counters, and
`established` flag are all left alone. The rotated key matters only for the
*next* handshake, which the ACU initiates whenever it chooses — typically
right away: it drops the session and re-runs SCS_11..14 requesting the SCBK
key selector.

> **Observed on the wire.** A KEYSET arrives as an encrypted **SCS_17**
> frame; the PD answers **ACK under SCS_16** (MAC-only — an empty reply is
> never encrypted, per spec D.1.4); the ACU then immediately re-handshakes
> with **key selector 1 (SCBK)** and the session re-establishes on the new
> key. The re-handshake only succeeds because the PD actually stored the
> key the KEYSET carried — which is the proof the rotation took effect.

If your handler does **not** ACK the KEYSET (it returns
`OSDP_ERR_NOT_SUPPORTED`, or no handler is bound), the PD NAKs and
**nothing rotates**. A PD that wants to support re-keying must therefore
handle `OSDP_CMD_KEYSET` and return `OSDP_OK`.

### Rejections leave the stored key intact

If the handler ACKs but the payload can't be applied, the PD automatically
demotes the wire reply from ACK to **`NAK 0x09`
(`OSDP_NAK_RECORD_INVALID`)** and the stored SCBK is **never overwritten**.
Every malformed-but-recognized KEYSET maps to 0x09 — the spec's "Unable to
process command record" (Table 47) — because the PD *does* implement
KEYSET; 0x03 "Unknown Command Code" is reserved for command codes the PD
doesn't implement at all. The cases that reject:

| Payload problem                                                                       |
| ------------------------------------------------------------------------------------- |
| Envelope malformed — truncated, or the `key_length` field disagrees with the trailing bytes |
| `key_type` is not SCBK (`0x01`)                                                        |
| The key is not exactly 16 bytes                                                        |

### Persisting the new key is your job

The library keeps its "no I/O of its own" contract: it rotates the key in
RAM and never writes it anywhere. On its own, a rotated key is therefore
lost on the next power cycle, and the PD falls back to whatever key you set
at boot. To make the rotation survive a reboot, **persist it yourself.**

There is no rotation callback or accessor — the supported hook is the
command handler, which sees the KEYSET payload *before* the library applies
it. Decode and store it there, then reload it at boot with
`osdp_pd_set_sc_scbk`:

```c
case OSDP_CMD_KEYSET: {
    osdp_keyset_cmd_t ks;
    if (osdp_keyset_decode(payload, len, &ks) == OSDP_OK &&
        ks.key_type   == OSDP_KEYSET_KEY_TYPE_SCBK &&
        ks.key_length == OSDP_SC_KEY_LEN) {
        secure_store_scbk(ks.key_data);   /* 16 bytes → your key store */
    }
    reply->code = OSDP_REPLY_ACK;         /* library rotates pd.sc.scbk after this returns OK */
    reply->payload = NULL; reply->payload_len = 0;
    return OSDP_OK;
}
```

Gate your store on the same checks the library uses (SCBK type, 16 bytes)
so you never persist a key the library then rejects. At startup, load the
persisted key back *before* the first `CHLNG`:

```c
uint8_t scbk[OSDP_SC_KEY_LEN];
if (secure_load_scbk(scbk))                          /* a key was rotated before */
    osdp_pd_set_sc_scbk(&pd, scbk);
else
    osdp_pd_set_sc_scbk_d(&pd, OSDP_SCBK_DEFAULT);   /* still on the install key */
```

> **Store the key in a secure element, not plaintext flash.** The SCBK is
> the root of the Secure Channel's confidentiality and authenticity — an
> attacker who reads it can impersonate the ACU or decrypt traffic. Best
> practice is to hold it in a secure element / secure key store (ATECC608,
> SE050, an MCU's protected key slots, a TPM) where the key can be written
> and used for AES **without ever being read back** into general-purpose
> memory. If you have no secure element, at minimum use a read-protected /
> OTP region and lock the debug interface — and never log the key or place
> it in a world-readable filesystem.

---

## Reference tables

### Common command codes (ACU → PD)

| Code             | Value | Expected reply            |
| ---------------- | ----- | ------------------------- |
| `OSDP_CMD_POLL`  | 0x60  | `ACK`, or a queued event (see [freshness](#reporting-events-on-poll--keep-queued-replies-fresh)) |
| `OSDP_CMD_ID`    | 0x61  | `PDID`                    |
| `OSDP_CMD_CAP`   | 0x62  | `PDCAP`                   |
| `OSDP_CMD_LSTAT` | 0x64  | `LSTATR`                  |
| `OSDP_CMD_ISTAT` | 0x65  | `ISTATR`                  |
| `OSDP_CMD_OSTAT` | 0x66  | `OSTATR`                  |
| `OSDP_CMD_RSTAT` | 0x67  | `RSTATR`                  |
| `OSDP_CMD_OUT`   | 0x68  | `ACK` / `OSTATR`          |
| `OSDP_CMD_LED`   | 0x69  | `ACK` (observed)          |
| `OSDP_CMD_BUZ`   | 0x6A  | `ACK` (observed)          |
| `OSDP_CMD_TEXT`  | 0x6B  | `ACK`                     |
| `OSDP_CMD_COMSET`| 0x6E  | `COM`                     |
| `OSDP_CMD_KEYSET`| 0x75  | `ACK` (rotates SCBK)      |
| `OSDP_CMD_CHLNG` | 0x76  | `CCRYPT` (SC, internal)   |
| `OSDP_CMD_SCRYPT`| 0x77  | `RMAC_I` (SC, internal)   |

### Common reply codes (PD → ACU)

`OSDP_REPLY_ACK` 0x40, `NAK` 0x41, `PDID` 0x45, `PDCAP` 0x46,
`LSTATR` 0x48, `ISTATR` 0x49, `OSTATR` 0x4A, `RSTATR` 0x4B,
`RAW` 0x50, `KEYPAD` 0x53, `COM` 0x54, `BUSY` 0x79,
`CCRYPT` 0x76, `RMAC_I` 0x78.

### NAK error codes

| Macro                          | Value | Meaning                                |
| ------------------------------ | ----- | -------------------------------------- |
| `OSDP_NAK_NO_ERROR`            | 0x00  | No error                               |
| `OSDP_NAK_BAD_CHECK`           | 0x01  | Bad checksum/CRC                       |
| `OSDP_NAK_CMD_LENGTH`          | 0x02  | Bad command length                     |
| `OSDP_NAK_UNKNOWN_CMD`         | 0x03  | Unknown command code (the default NAK) |
| `OSDP_NAK_UNEXPECTED_SEQUENCE` | 0x04  | Unexpected sequence number             |
| `OSDP_NAK_UNSUPPORTED_SCB`     | 0x05  | SCB unsupported (SC not configured)    |
| `OSDP_NAK_ENCRYPTION_REQUIRED` | 0x06  | Encryption required                    |
| `OSDP_NAK_RECORD_INVALID`      | 0x09  | Bad record (e.g. malformed KEYSET)     |

### Status codes (`osdp_status_t`)

`OSDP_OK` is the only success. Errors: `OSDP_ERR_INVALID_ARG`,
`OSDP_ERR_BUFFER_TOO_SMALL`, `OSDP_ERR_TRUNCATED`, `OSDP_ERR_BAD_SOM`,
`OSDP_ERR_BAD_LENGTH`, `OSDP_ERR_BAD_CTRL`, `OSDP_ERR_BAD_CRC`,
`OSDP_ERR_BAD_CHECKSUM`, `OSDP_ERR_BAD_PAYLOAD`, `OSDP_ERR_NOT_SUPPORTED`.

---

## Try it without hardware

`tools/osdp-pd-mock` runs this exact library as a live PD on a serial
port, so you can wire it to an external ACU (OSDP.Net's ACUConsole, a
hardware controller) and watch the exchange:

```
osdp-pd-mock --port COM5 --address 0x00 --baud 9600 -v
osdp-pd-mock --port /dev/ttyUSB0 --sc=scbkd -vv     # with Secure Channel
```

It's the most complete usage example in the tree — identity/capability
configuration, every baseline reply builder, the LED/buzzer mirrors, and
the Secure Channel setup all in one file.
