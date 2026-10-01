# osdp-embedded

A `no_std` Rust implementation of SIA OSDP v2.2.2 for access control readers and controllers, built on a freestanding C11 core.

[![crates.io](https://img.shields.io/crates/v/osdp-embedded.svg)](https://crates.io/crates/osdp-embedded)
[![Build Status](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_apis/build/status%2FOSDP%20Embedded-CI?branchName=main)](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_build/latest?definitionId=6&branchName=main)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later%20OR%20Commercial-blue.svg)](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE.md)

## Overview

The Open Supervised Device Protocol (OSDP) is the Security Industry Association's
standard for communication between access control units and peripheral devices —
card readers, keypads, and I/O boards on an RS-485 bus.

This crate is the Rust face of [OSDP-Embedded](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded).
The protocol logic lives in a freestanding C11 library — no `malloc`, no globals,
no OS calls — and the crate wraps it in safe types and traits. Nothing is
reimplemented in Rust, so the C test suite remains the single correctness oracle
for both languages.

- **PD state machine** ([`pd::Pd`](https://docs.rs/osdp-embedded/latest/osdp_embedded/pd/struct.Pd.html)) —
  address filtering, sequence-number policing, online/offline tracking, retransmit
  caching, and Secure Channel. You implement one trait to answer commands.
- **ACU state machine** ([`acu::Acu`](https://docs.rs/osdp-embedded/latest/osdp_embedded/acu/struct.Acu.html)) —
  multi-PD slots, per-PD sequence numbers and reply timeouts, and Secure Channel
  with spec-mandated session-loss detection.
- **Secure Channel** (AES-128, SCS_11..18) — you supply AES and an RNG through the
  `ScCrypto` trait; the crate bundles no crypto.
- **Typed message codecs** ([`messages`](https://docs.rs/osdp-embedded/latest/osdp_embedded/messages/index.html)) —
  decode and build for the complete v2.2 command and reply set outside the
  credential domain.
- **Pay only for your role** — the `pd` and `acu` features gate both the Rust
  modules and the C sources compiled, so PD firmware carries no ACU code.

## Supported Platforms

Requires **Rust 1.70 or later**. The crate is `no_std` with `alloc`: handlers are
stored as boxed trait objects, and the C core itself never allocates.

The C sources are compiled by the [`cc`](https://crates.io/crates/cc) crate at build
time, so all you need is a C compiler for your target — no CMake, no `libclang`,
no pre-built library. `cargo build --target thumbv7m-none-eabi` works wherever a
matching C toolchain (e.g. `arm-none-eabi-gcc`) is installed.

## Installation

```toml
[dependencies]
# PD firmware — no ACU code compiled, at either the Rust or the C level:
osdp-embedded = { version = "1.0", default-features = false, features = ["pd"] }

# ACU controller:
osdp-embedded = { version = "1.0", features = ["acu"] }

# Both (the default; typical for tools, monitors, and tests):
osdp-embedded = "1.0"
```

| Feature | Default | Effect |
| --- | --- | --- |
| `std` | yes | `std::error::Error` for `Error`. Everything else is `no_std`. |
| `pd` | yes | The `pd` module and the PD-side C sources. |
| `acu` | yes | The `acu` module and the ACU-side C sources. |
| `buffered-transport` | no | Widens the spec's 20 ms inter-character timeout to 150 ms, for transports that deliver received bytes in batches (USB-serial adapters, TCP). Leave it off on a real UART. |

## Quick Start

A complete peripheral device: it answers the ACU's poll and NAKs anything it
doesn't implement.

```rust
use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::{Error, Result, Transport};

/// Your UART. `read` returns what is available now (0 is fine) and must not block.
struct Uart;

impl Transport for Uart {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        uart_read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        uart_write(buf)
    }
    fn now_ms(&mut self) -> Option<u32> {
        Some(millis())
    }
}

/// Your device logic. The PD has already validated the frame, filtered on
/// address, and decrypted the payload if Secure Channel is running.
struct Reader;

impl CommandHandler for Reader {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(Error::NotSupported), // the PD sends NAK 0x03
        }
    }
}

let mut pd = Pd::new(0x00); // 7-bit PD address
pd.set_transport(Uart);
pd.set_command_handler(Reader);

loop {
    pd.tick(); // never blocks: reads what's there, replies, returns
}
```

`tick()` does all the work: it drains available bytes, processes complete frames
addressed to this PD, calls your handler, and frames the reply back onto the wire.

`now_ms` drives online/offline tracking and the LED/buzzer timers. Returning `None`
disables them, which is fine for a first bring-up.

To see a PD and an ACU talk before you wire up hardware, clone the repository and
run the in-process loopback examples:

```sh
cargo run --manifest-path rust/Cargo.toml --example loopback
cargo run --manifest-path rust/Cargo.toml --example loopback_sc   # with Secure Channel
```

## Common Scenarios

### Reporting a card read

A reader reports credentials as a **poll response**: the read is queued, and the
PD delivers it the next time the ACU polls.

```rust
use osdp_embedded::messages::{Raw, OSDP_REPLY_RAW};

pd.set_event_queue(256); // bytes; budget roughly payload + 3 per event

// ... later, from your card front-end:
let raw = Raw {
    reader_no: 0,
    format_code: 1, // spec Table 33: 1 = Wiegand
    bit_count: 26,
    bit_data: &card_bits, // (bit_count + 7) / 8 bytes
};
let mut buf = [0u8; 64];
let len = raw.build(&mut buf)?;
pd.enqueue_event(OSDP_REPLY_RAW, &buf[..len])?; // Err(BufferTooSmall) when full
```

**Notes:** the queue is emptied automatically when the PD goes offline (spec
7.11/7.12). Delivering a card read from before an outage would have the ACU act on
a stale presentation. `osdp_KEYPAD`, `osdp_FMT`, and `osdp_MFGREP` queue the same
way.

### Enabling Secure Channel

Implement `ScCrypto` over whatever AES you have (a hardware peripheral, or a crate
such as RustCrypto's [`aes`](https://crates.io/crates/aes)), then bind it with a
key. The handshake, MAC chain, and payload encryption are then transparent: your
command handler keeps seeing plaintext.

```rust
use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};
use osdp_embedded::Result;

struct Crypto;

impl ScCrypto for Crypto {
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()> {
        aes128_ecb_encrypt(key, in_, out);
        Ok(())
    }
    fn aes_decrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()> {
        aes128_ecb_decrypt(key, in_, out);
        Ok(())
    }
    fn rand_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        fill_from_trng(out); // must be a CSPRNG in production
        Ok(())
    }
}

pd.set_sc_crypto(Crypto);
pd.set_sc_scbk(&installation_key); // 16 bytes from secure storage
```

**Notes:** keep the SCBK in a secure element or protected flash, never in plain
application flash. `set_sc_scbk_d(osdp_embedded::sc::scbk_default())` enables the
spec's well-known install-time key and is meant for commissioning only. A PD
holding an operational SCBK refuses clear-text commands outside the discovery
allowlist (`osdp_ID`, `osdp_CAP`, `osdp_COMSET`) with NAK 0x06. Check
`pd.sc_established()` to see whether a session is up.

### Observing what the reader is showing

The PD decodes inbound `osdp_LED` and `osdp_BUZ` commands into a resolved display
state (flash phase, temporary override, and permanent colour folded together) and
calls you only when the *displayed* result changes. Drive your hardware from the
callback rather than reimplementing the spec's timing rules.

```rust
use osdp_embedded::pd::{LedColor, LedHandler};

struct Leds;

impl LedHandler for Leds {
    fn on_led_change(&mut self, _reader_no: u8, led_no: u8, color: LedColor) {
        set_rgb(led_no, color); // LedColor::Red, Green, Amber, ...
    }
}

pd.set_led_handler(Leds);
```

**Notes:** flashing and temporary-override expiry are detected inside `tick()`, so
they need the transport's `now_ms` clock. `BuzzerHandler` works the same way via
`set_buzzer_handler`. This is observe-only: the wire reply is unchanged.

### Answering status commands

`osdp_LSTAT`, `ISTAT`, `OSTAT`, and `RSTAT` have spec-defined reply layouts and
application-defined values. Supply the values and the PD builds the replies.

```rust
use osdp_embedded::messages::{OSDP_LSTATR_NORMAL, OSDP_LSTATR_TAMPER};
use osdp_embedded::pd::StatusProviders;

pd.set_status_providers(
    StatusProviders::new()
        .local(|| {
            let tamper = if tamper_open() {
                OSDP_LSTATR_TAMPER
            } else {
                OSDP_LSTATR_NORMAL
            };
            (tamper, OSDP_LSTATR_NORMAL) // (tamper, power)
        })
        .inputs(|out| {
            out[0] = door_contact_active() as u8;
            1 // number of inputs reported
        }),
);
```

**Notes:** every provider is optional. A status command without one falls through
to your `CommandHandler`, so you can adopt this incrementally.

### Driving PDs from an ACU

```rust
use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::OSDP_CMD_POLL;

struct Replies;

impl ReplyHandler for Replies {
    fn on_reply(&mut self, event: &ReplyEvent<'_>) {
        // event.pd_address, event.reply_code, event.payload (copy out to keep it)
    }
}

let mut acu = Acu::new(4); // slots for up to four PDs
acu.set_transport(Uart);
acu.set_reply_handler(Replies);
acu.register_pd(0, 0x00)?; // slot 0 <- PD address 0

loop {
    if !acu.is_pd_busy(0x00) {
        acu.send_command(0x00, OSDP_CMD_POLL, &[])?;
    }
    acu.tick();
}
```

**Notes:** one command may be outstanding per PD. `send_command` returns
`Err(NotSupported)` until the previous reply has arrived or timed out. The ACU does
not auto-poll: your application decides what to send and when. For Secure Channel,
bind `set_sc_crypto` and `set_pd_scbk`, call `start_sc_handshake`, and watch the
outcome through an `ScEventHandler`.

## Core Concepts

| Term | Meaning |
| --- | --- |
| **PD** | Peripheral Device — the reader, keypad, or I/O board. Answers commands; never speaks unprompted. |
| **ACU** | Access Control Unit (also CP, control panel). Polls the bus and issues every command. |
| **Secure Channel** | AES-128 encryption and message authentication between one ACU and one PD, established by a four-message handshake. |
| **SCBK / SCBK-D** | Secure Channel Base Key: the per-installation key, and the spec's well-known default used only for commissioning. |
| **Sequence number** | A 2-bit counter cycling 1→2→3→1 that detects retransmits. Zero signals a connection reset. |

## Advanced Usage

### Error handling

Every fallible call returns `osdp_embedded::Result<T>`. Decoders defend against
truncated, oversized, and malformed input: they return an error, they never panic.

What your `CommandHandler` returns reaches the ACU as a real reply, so a refusal
costs the ACU one round trip rather than a timeout:

| Handler returns | PD sends |
| --- | --- |
| `Ok(reply)` | `reply` |
| `Err(Error::NotSupported)` | `osdp_NAK` 0x03 — unknown command |
| `Err(Error::BadPayload)` / `Err(Error::BadLength)` | `osdp_NAK` 0x02 — bad length |
| `Err(Error::InvalidArg)` | `osdp_NAK` 0x09 — unable to process record |

### Commands the PD handles for you

Some commands change state the library owns, or require a specific reply, so the
PD handles them itself and they never reach your handler: `osdp_COMSET`,
`osdp_FILETRANSFER`, `osdp_ABORT`, and `osdp_ACURXSIZE`. Where the decision really
is yours there is a hook: `set_comset_handler` (veto an address or baud change, and
retune your UART afterwards), `set_file_receiver` / `set_file_stream` (validate each
file-transfer fragment), `set_keepactive_handler`, and `set_mfg_receiver`.

### Threading

`Pd` and `Acu` are deliberately not `Send`. Drive each one from a single thread or
task.

## Documentation

- **[API reference on docs.rs](https://docs.rs/osdp-embedded)** — every type,
  trait, and method.
- **[PD Guide](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/PD_GUIDE.md)** —
  the full guide to building a peripheral device. Written against the C API, whose
  concepts map one-to-one onto the Rust methods of the same name.
- **[Examples](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/tree/main/rust/osdp/examples)** —
  in-process PD↔ACU loopback, plain and with Secure Channel.
- **[Project README](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded#readme)** —
  the C library, PlatformIO and CMake integration, and host-side interop tools.
- **Specification** — SIA OSDP v2.2.2. Not redistributed; source it from the
  [Security Industry Association](https://www.securityindustry.org/).

## License

OSDP-Embedded is dual-licensed. You may use it under either, at your choice:

- **Open source**: [GNU General Public License v3.0 or later](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE-GPL-3.0.txt)
  (GPL-3.0-or-later) — for products that are themselves distributed under a
  GPL-compatible license.
- **Commercial**: a paid license from Z-bit Systems for use in proprietary products
  that cannot comply with GPL terms, such as closed-source embedded firmware. See
  [LICENSING](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSING)
  for inquiries.

See [LICENSE.md](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE.md)
for the full explainer.

## Support

- Open an issue on [GitHub Issues](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/issues)
- Contact [Z-bit Systems, LLC](https://z-bitco.com) for commercial support and
  custom development.
