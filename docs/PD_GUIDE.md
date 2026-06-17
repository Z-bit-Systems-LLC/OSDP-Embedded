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
  - [`osdp_pd_tick`](#osdp_pd_tick--pump-the-state-machine)
  - [`osdp_pd_is_online`](#osdp_pd_is_online--connection-state)
  - [LED observation](#led-observation--osdp_pd_set_led_handler--osdp_pd_led_color)
  - [Buzzer observation](#buzzer-observation--osdp_pd_set_buzzer_handler--osdp_pd_buzzer_sounding)
  - [Secure Channel](#secure-channel--osdp_pd_set_sc_)
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
- **`osdp_KEYSET`** — if your handler ACKs a well-formed KEYSET
  (`key_type` = SCBK, length 16), the PD rotates the stored SCBK in place
  *before* sending the ACK; the new key takes effect on the next
  handshake while the current SC session keeps running. A malformed
  KEYSET payload is automatically downgraded from ACK to `NAK 0x09`
  (`OSDP_NAK_RECORD_INVALID`) and the stored key is left untouched. Your
  handler doesn't need to know any of this.

### Sequencing & retransmits are automatic

You don't manage sequence numbers. The PD echoes the inbound SQN,
address, and integrity mode into every reply (spec 5.9), and it detects
retransmits the spec-correct way: a frame **byte-identical** to the
previously accepted command replays the cached reply *without*
re-invoking your handler. (SQN-only matching is insufficient because OSDP
cycles 1→2→3→1.) So your handler is effectively "called once per
genuinely new command" — side effects won't double-fire on a retransmit.

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

## Reference tables

### Common command codes (ACU → PD)

| Code             | Value | Expected reply            |
| ---------------- | ----- | ------------------------- |
| `OSDP_CMD_POLL`  | 0x60  | `ACK` (or a queued event) |
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
