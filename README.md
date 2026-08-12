# OSDP-Embedded

A freestanding C11 implementation of SIA OSDP v2.2.2 for access control readers and controllers, with a `no_std` Rust wrapper.

[![Build Status](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_apis/build/status%2FOSDP%20Embedded-CI?branchName=main)](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_build/latest?definitionId=6&branchName=main)
[![crates.io](https://img.shields.io/crates/v/osdp-embedded.svg)](https://crates.io/crates/osdp-embedded)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later%20OR%20Commercial-blue.svg)](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE.md)

## Overview

The Open Supervised Device Protocol (OSDP) is the Security Industry Association's
standard for communication between access control units and peripheral devices —
card readers, keypads, and I/O boards on an RS-485 bus. Most available
implementations assume a hosted operating system: dynamic allocation, threads,
sockets, a filesystem. That rules them out on the microcontrollers those readers
actually ship on.

OSDP-Embedded is written for that constrained end. The core is freestanding C11
with no `malloc`, no globals, no OS calls, and no I/O of its own — the application
owns every buffer and supplies the UART and AES primitives through callbacks. Each
message is a separate translation unit, so linker garbage collection drops the
codecs a device never references. A `no_std`-compatible Rust wrapper is published
alongside it as the [`osdp-embedded`](https://crates.io/crates/osdp-embedded) crate.

Key features:

- **Peripheral Device (PD) state machine** — address filtering, sequence-number
  policing, online/offline tracking, and Secure Channel, with the protocol
  mechanics handled for you rather than left to the application.
- **Access Control Unit (ACU) state machine** — multi-PD slot management, per-PD
  sequence numbers and reply timeouts, and Secure Channel with spec-mandated
  session-loss detection.
- **Secure Channel, both generations** — SC1 (AES-128, SCS_11..18) and **SC2**,
  the quantum-resistant channel from the SIA OSDP-SC2 annex (AES-256-GCM with
  KMAC256-derived session keys, SCS_21..28). SC2 is a parallel implementation,
  not a replacement: a build can link either, both, or neither. The consumer
  supplies the crypto through a small HAL in both cases; the library vendors no
  crypto.
- **Complete v2.2 command and reply set** outside the credential domain — 20 of
  25 commands and 19 of 21 replies in Annex A.
- **No allocation, no globals, no OS dependency** in `core/`, `pd/`, or `acu/`.
  Buffers are caller-owned and rebindable at run time; every function is reentrant.
- **Verified against independent implementations** — byte-level capture replay
  against [libosdp-conformance](https://github.com/Security-Industry-Association/libosdp-conformance),
  and live serial interop against Z-bit Systems'
  [OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) under both SC1 and
  SC2, in both directions (our PD against `ACUConsole`, our ACU against
  `PDConsole`).

This release makes the **PD side** the primary supported surface: it answers every
v2.2 command an ACU can legally send outside the deferred credential set. The ACU
side is complete and tested — it drives the loopback integration suite and the
`osdp-acu-mock` interop tool — and is included in the same stability promise.

Development happens on `main`. Please open pull requests against it.

## Supported Platforms

The core library needs a C11 compiler and four freestanding headers
(`<stdint.h>`, `<stddef.h>`, `<string.h>`, `<stdbool.h>`). It has no other
dependency, so it builds anywhere those exist — including bare-metal targets with
no libc.

What continuous integration verifies:

| Target | Toolchain | Coverage |
| --- | --- | --- |
| Linux x86_64 | GCC | Full build and the complete test suite, every commit |
| Linux aarch64 | `gcc-aarch64-linux-gnu` | Cross-compiled every commit (64-bit Raspberry Pi) |
| Windows x86_64 | MSVC | Library and tools built on every tagged release |

Windows builds with clang and MinGW are supported by the CMake presets and used
during development, but are not part of the automated matrix.

The Rust crate requires **Rust 1.70 or later** and is `no_std`-compatible; it needs
`alloc` for its trait-object callbacks. It compiles the C sources through the
[`cc` crate](https://crates.io/crates/cc) at build time, so `cargo build --target …`
cross-compiles to any target the C library compiles on — no CMake step and no
`libclang` required.

## Installation

### CMake (C)

Add the repository as a subdirectory and link the targets your role needs:

```cmake
add_subdirectory(OSDP-Embedded)

target_link_libraries(my_reader_firmware PRIVATE
    osdp::core       # framing, stream decoder, CRC, checksum
    osdp::messages   # the command/reply codecs you reference
    osdp::pd)        # PD-side state machine
```

An ACU application links `osdp::acu` in place of `osdp::pd`. A passive bus monitor
adds `osdp::dispatch` for one-call bulk routing. For a minimal firmware build, turn
the host-side extras off:

```sh
cmake -S . -B build -DOSDP_BUILD_TESTS=OFF -DOSDP_BUILD_TOOLS=OFF
```

### Cargo (Rust)

```toml
# PD-only firmware — no ACU code compiled, at either the Rust or the C level:
osdp-embedded = { version = "1.0", default-features = false, features = ["pd"] }

# ACU controller:
osdp-embedded = { version = "1.0", features = ["acu"] }

# Both (the default; typical for tools, monitors, and integration tests):
osdp-embedded = "1.0"
```

Default features are `["std", "pd", "acu"]`.

## Quick Start

### A PD that stays online (C)

This is a complete peripheral device: it answers the ACU's poll and NAKs anything
it doesn't implement. Everything else is optional and stays dormant until you opt in.

```c
#include "osdp/osdp_pd.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"

/* Your device logic. The PD has already validated the frame, filtered on
 * address, and decrypted the payload if Secure Channel is running. */
static osdp_status_t on_command(void *user, uint8_t code,
                                const uint8_t *payload, size_t len,
                                osdp_pd_reply_t *reply)
{
    switch (code) {
    case OSDP_CMD_POLL:                  /* the ACU's heartbeat */
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        return OSDP_OK;
    default:
        return OSDP_ERR_NOT_SUPPORTED;   /* the library sends NAK 0x03 */
    }
}

int main(void)
{
    /* Three non-blocking callbacks over your UART. read() returns the byte
     * count available now (0 is fine), write() must send all len bytes,
     * now_ms() is a free-running millisecond counter. */
    osdp_pd_transport_t transport = {
        .read = uart_read, .write = uart_write, .now_ms = millis, .user = NULL
    };

    osdp_pd_t pd;
    osdp_pd_init(&pd, 0x00);                 /* 7-bit PD address */
    osdp_pd_set_transport(&pd, &transport);
    osdp_pd_set_command_handler(&pd, on_command, NULL);

    for (;;) {
        osdp_pd_tick(&pd);   /* never blocks: reads what's there, replies, returns */
        /* yield to the rest of your main loop — sleep, WFI, run other tasks */
    }
}
```

`osdp_pd_tick()` does all the work: it drains available bytes, processes complete
frames addressed to this PD, calls your handler, and frames the reply back onto the
wire. Nothing in the library sleeps or blocks.

### The same PD in Rust

```rust
use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::{Error, Result};

struct Reader;

impl CommandHandler for Reader {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(Error::NotSupported), // the library sends NAK 0x03
        }
    }
}

let mut pd = Pd::new(0x00);
pd.set_transport(my_uart);      // any type implementing osdp_embedded::Transport
pd.set_command_handler(Reader);

loop {
    pd.tick();
}
```

The borrowed `Reply<'a>` is how a reply payload can point straight into your own
storage — no copy, no allocation. `examples/loopback.rs` and `examples/loopback_sc.rs`
run a complete PD against a complete ACU in-process if you want to see it working
before wiring real hardware.

## Common Scenarios

### Reporting a card read

A reader reports credentials as a **poll response**: the read is queued, and the PD
delivers it the next time the ACU polls. Storage is caller-owned, so queue depth is
your choice, not the library's.

```c
static uint8_t event_buf[256];

osdp_pd_set_event_queue(&pd, event_buf, sizeof event_buf);

/* ... later, from wherever your Wiegand/OSDP reader front-end runs: */
void on_card_presented(const uint8_t *bits, uint16_t bit_count)
{
    uint8_t  payload[64];
    size_t   written;
    osdp_raw_t raw = {
        .reader_no    = 0,
        .format_code  = OSDP_RAW_FORMAT_WIEGAND,
        .bit_count    = bit_count,
        .bit_data     = bits,
        .bit_data_len = (bit_count + 7u) / 8u,
    };

    if (osdp_raw_build(&raw, payload, sizeof payload, &written) == OSDP_OK)
        osdp_pd_enqueue_event(&pd, OSDP_REPLY_RAW, payload, written);
}
```

**Notes:** the queue is emptied automatically when the PD goes offline (spec
7.11/7.12) — delivering a card read from before an outage would have the ACU act on
a stale presentation. `osdp_KEYPAD`, `osdp_FMT`, and `osdp_MFGREP` queue the same way.

### Enabling Secure Channel

Secure Channel is opt-in. Bind a crypto vtable and a key; the handshake, MAC chain,
and payload encryption are then transparent — your command handler keeps seeing
plaintext.

```c
/* You supply AES-128 ECB and an RNG. The library vendors no crypto:
 * bind mbedTLS, a hardware AES block, BCryptGenRandom, /dev/urandom, … */
static const osdp_sc_crypto_t crypto = {
    .aes128_ecb_encrypt = my_aes_encrypt,
    .aes128_ecb_decrypt = my_aes_decrypt,
    .rand_bytes         = my_rand_bytes,
};

osdp_pd_set_sc_crypto(&pd, &crypto);
osdp_pd_set_sc_scbk(&pd, installation_key);   /* 16 bytes from secure storage */
```

For **SC2** — the quantum-resistant channel — the shape is identical, with a wider
HAL and a 32-byte key:

```c
/* AES-256-GCM + KMAC256 + AES-256 block + RNG. */
osdp_pd_set_sc2_crypto(&pd, &crypto2);
osdp_pd_set_sc2_scbk(&pd, installation_key_256);   /* 32 bytes */
```

**Notes:** store the SCBK in a secure element or protected flash region, never in
plain application flash. Use `osdp_pd_set_sc_scbk_d()` for the spec's well-known
install-time key during commissioning only. A PD holding an operational SCBK refuses
clear-text commands outside the discovery allowlist (`osdp_ID`, `osdp_CAP`,
`osdp_COMSET`) with NAK 0x06, per the spec's prohibition on interleaving unsecured
packets into a secure session. SC1 and SC2 are independent — binding one does not
enable the other, and a build that references neither links no crypto code at all.

### Observing what the reader is showing

The PD decodes inbound `osdp_LED` and `osdp_BUZ` commands into a resolved
display state — flash phase, temporary-override countdown, and permanent colour all
folded together — and calls you only when the *displayed* result actually changes.
Drive your hardware from the callback instead of reimplementing the spec's timing rules.

```c
static void on_led_change(void *user, uint8_t reader_no,
                          uint8_t led_no, uint8_t color)
{
    set_gpio_rgb(led_no, color);   /* OSDP_LED_RED, _GREEN, _AMBER, … */
}

osdp_pd_set_led_handler(&pd, on_led_change, NULL);
```

**Notes:** timer-driven transitions (flashing, temporary-override expiry) are
detected inside `osdp_pd_tick()`, so they require the transport's `now_ms` clock.
The buzzer works identically via `osdp_pd_set_buzzer_handler()`. The wire reply is
unchanged, so this is observe-only with no interop impact.

### Answering status commands

`osdp_LSTAT`, `ISTAT`, `OSTAT`, and `RSTAT` have spec-defined reply layouts and
application-defined values. Register a status provider and the library builds the
replies; you supply only the numbers.

```c
static void read_local(void *user, uint8_t *tamper, uint8_t *power)
{
    *tamper = tamper_switch_open() ? 1u : 0u;
    *power  = mains_lost()         ? 1u : 0u;
}

static size_t read_inputs(void *user, uint8_t *out, size_t cap)
{
    size_t n = input_count() < cap ? input_count() : cap;
    for (size_t i = 0; i < n; i++)
        out[i] = input_is_active(i) ? 1u : 0u;
    return n;
}

static const osdp_pd_status_provider_t status = {
    .local = read_local, .inputs = read_inputs,
};

osdp_pd_set_status_provider(&pd, &status, NULL);
```

**Notes:** every member is independent and optional. A `NULL` member leaves that one
command falling through to your command handler, so you can adopt this incrementally.

### Driving PDs from an ACU

```c
osdp_acu_pd_slot_t slots[4];
osdp_acu_t acu;

osdp_acu_init(&acu, slots, 4);
osdp_acu_set_transport(&acu, &transport);
osdp_acu_set_reply_handler(&acu, on_reply, NULL);
osdp_acu_register_pd(&acu, 0, 0x00);          /* slot 0 <- PD address 0 */

osdp_acu_send_command(&acu, 0x00, OSDP_CMD_POLL, NULL, 0);

for (;;)
    osdp_acu_tick(&acu);
```

**Notes:** one command may be outstanding per PD; `osdp_acu_send_command` returns
`OSDP_ERR_NOT_SUPPORTED` if the previous reply hasn't landed or timed out. The
application drives command scheduling — the ACU does not auto-poll.

## Core Concepts

| Term | Meaning |
| --- | --- |
| **PD** | Peripheral Device — the reader, keypad, or I/O board. Answers commands; never speaks unprompted. |
| **ACU** | Access Control Unit (also CP, control panel). Polls the bus and issues every command. |
| **Secure Channel (SC1)** | AES-128 encryption and message authentication between one ACU and one PD, established by a four-message handshake. |
| **Secure Channel 2 (SC2)** | The quantum-resistant channel from the SIA OSDP-SC2 annex: AES-256-GCM message protection with KMAC256-derived session keys. Parallel to SC1, not a replacement. |
| **SCBK / SCBK-D** | Secure Channel Base Key: the per-installation key, and the spec's well-known default used only for commissioning. 16 bytes for SC1, 32 for SC2. |
| **SCS_11..18** | The SC1 frame types: 11–14 carry the handshake, 15/16 authenticate empty messages, 17/18 authenticate and encrypt data-bearing ones. |
| **SCS_21..28** | The SC2 equivalents, in the same 11→21 arrangement. |
| **Sequence number** | A 2-bit counter cycling 1→2→3→1 that detects retransmits. Zero signals a connection reset. |
| **Multi-part message** | The spec-5.10 transport that splits a message too large for one frame across several. |

## Advanced Usage

### Sizing the library

One build-time constant per role sizes every working buffer: `OSDP_PD_BUF_LEN`
(512) and `OSDP_ACU_BUF_LEN` (1440). Both are `#ifndef`-guarded, so a build can
override them without touching headers. `osdp_pd_t` is roughly 4.4 KB at the
defaults.

Buffers can also be rebound at run time to caller-owned storage with
`osdp_pd_set_buffers()`, which takes any subset. Use the sizing helpers —
`osdp_frame_max_payload()`, `osdp_sc_max_payload()`, and
`osdp_pd_max_reply_payload()` — instead of deriving framing overhead by hand.

### Extension points

The library reaches the outside world through small callback vtables you
implement:

| HAL | Callbacks | Typical binding |
| --- | --- | --- |
| `osdp_pd_transport_t` / `osdp_acu_transport_t` | `read`, `write`, `now_ms` | UART, USB CDC, TCP socket, or a test double |
| `osdp_sc_crypto_t` (SC1) | `aes128_ecb_encrypt`, `aes128_ecb_decrypt`, `rand_bytes` | mbedTLS, wolfCrypt, a hardware AES block, `BCryptGenRandom`, `/dev/urandom` |
| `osdp_sc2_crypto_t` (SC2) | KMAC256, AES-256-GCM seal/open, AES-256 block, `rand_bytes` | mbedTLS, a hardware crypto accelerator; RustCrypto's `aes-gcm` + `tiny-keccak` on the Rust side |

An application that never binds a crypto vtable gets a plaintext-only build, with
no AES or RNG code linked in. Binding SC1 does not pull in SC2 or vice versa.

### Error handling

Every fallible function returns `osdp_status_t`; there is no errno-style global
state. Decoders defend against truncated, oversized, and malformed input — they
report errors, they never invoke undefined behavior.

Your command handler's return value maps onto the spec's Table 47 NAK codes, so a
rejection reaches the ACU as a real reply rather than a timeout:

| Handler returns | PD sends |
| --- | --- |
| `OSDP_OK` | the reply you filled in |
| `OSDP_ERR_NOT_SUPPORTED` | `osdp_NAK` 0x03 — unknown command |
| `OSDP_ERR_BAD_PAYLOAD` / `OSDP_ERR_BAD_LENGTH` | `osdp_NAK` 0x02 — bad length |
| `OSDP_ERR_INVALID_ARG` | `osdp_NAK` 0x09 — unable to process record |
| `OSDP_ERR_BUSY` | `osdp_BUSY` |

### Commands the library handles for you

Some commands mutate library-owned state or mandate a specific reply, so the state
machine intercepts them and they never reach your handler: `osdp_COMSET`,
`osdp_FILETRANSFER`, `osdp_ABORT`, and `osdp_ACURXSIZE`. Optional hooks let you
participate where a decision is genuinely yours — vetoing a COMSET address change,
evaluating each file-transfer fragment, or honoring `osdp_KEEPACTIVE`. See the
[PD guide](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/PD_GUIDE.md)
for each hook's contract.

## Testing and Development

### Building and testing

`CMakePresets.json` ships `debug`, `release`, `asan`, and `lib-only` configurations.
The whole configure → build → test loop is one command:

```sh
cmake --workflow --preset debug
```

On Windows with MSVC, run from a *Developer PowerShell for VS* so `cl` and `rc` are
on `PATH` — the presets use the single-config Ninja generator. The Rust workspace
builds separately:

```sh
cargo test --manifest-path rust/Cargo.toml
cargo run  --manifest-path rust/Cargo.toml --example loopback      # plaintext
cargo run  --manifest-path rust/Cargo.toml --example loopback_sc   # SC1
cargo run  --manifest-path rust/Cargo.toml --example loopback_sc2  # SC2
```

Before pushing, `./scripts/Check-Code.ps1` runs every gate CI enforces — CMake
configure/build/`ctest`, then `cargo fmt`, `clippy -D warnings`, workspace
build/test, and the loopback examples — in one invocation.

Tests use the vendored [Unity](https://github.com/ThrowTheSwitch/Unity) framework
under `tests/`. Dropping an OSDPCAP capture into `tests/captures/` registers it as a
CTest case automatically (re-run `cmake` after adding one).

To chase a suspected memory bug, the `asan` preset builds with AddressSanitizer
(and UBSan on GCC/clang) into its own `build/asan/` directory, kept apart so
instrumented and plain objects never mix:

```sh
cmake --workflow --preset asan
```

On Windows, ASan needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH`; it ships with
Visual Studio under `VC\Tools\MSVC\<version>\bin\Hostx64\x64\`.

### Interop tools

Four host-side tools ship with the repository for validating against real hardware
and third-party stacks:

| Tool | Purpose |
| --- | --- |
| `osdp-pd-mock` | Runs a real PD on a serial port. Pair with any ACU to validate this stack against it. |
| `osdp-acu-mock` | Runs a real ACU on a serial port, driving an external PD. Closes the symmetric interop loop. |
| `osdp-parser` | Reads [OSDPCAP](https://github.com/Security-Industry-Association/libosdp-conformance/blob/master/doc/doc-src/osdpcap-format.md) captures and prints a decoded line per frame. |
| `osdp-mcp` | A [Model Context Protocol](https://modelcontextprotocol.io/) server exposing a virtual PD, so an AI agent can drive it against an ACU under test — scripting replies, injecting NAKs and card reads, and reading decoded wire history. Includes an optional browser view of the reader's LEDs, buzzer, and keypad. See the [MCP guide](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/MCP_GUIDE.md). |

```sh
# Run a PD at address 0 with the default install key:
build/tools/osdp-pd-mock/osdp-pd-mock --address 0 --sc=scbkd -v

# SC2 (AES-256-GCM) with a 32-byte SCBK:
build/tools/osdp-pd-mock/osdp-pd-mock --address 0 \
    --sc=scbk2:404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F -v
```

Both mocks take `--sc=scbkd` or `--sc=scbk:HEX32` for SC1, and `--sc=scbk2:HEX64`
for SC2. Both have been validated live against OSDP.Net under each. Run any tool
with `--help` for its full flag set.

## Documentation

- **[PD Guide](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/PD_GUIDE.md)** —
  the complete guide to building a peripheral device: every API call, the transport
  and crypto HALs, buffer sizing, file transfer, and Secure Channel.
- **[MCP Guide](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/MCP_GUIDE.md)** —
  driving a virtual PD from an AI agent to test an ACU: every tool, the transports,
  client configuration, and the browser reader view.
- **[Public headers](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/tree/main/core/include/osdp)** —
  each declaration carries the spec section it implements.
- **[Architecture and coding rules](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/CLAUDE.md)** —
  the locked design decisions and the reasoning behind them.
- **[Roadmap](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/docs/PLAN.md)** —
  phased plan, what shipped when.
- **Specification** — SIA OSDP v2.2.2 (2024). Not redistributed here; source the PDF
  directly from the [Security Industry Association](https://www.securityindustry.org/).

## Roadmap

Current development goals:

- [ ] Credential-domain messages: biometric, PIV data exchange, `osdp_GENAUTH` /
      `osdp_CRAUTH`, and transparent smartcard mode (`osdp_XWR` / `osdp_XRD`). These
      ride the multi-part transport that already exists, so the remaining work is
      the messages themselves.
- [ ] Multi-record messages and reply convenience helpers.
- [ ] ACU-side file transfer and auto-poll scheduling.
- [ ] SC2 asymmetric device pairing — C509 certificates, a post-quantum key
      schedule, and transcript hashing, so a PD and ACU can establish an SCBK
      without one being pre-shared. In progress on `feature/osdp-sc2`.
- [ ] The deferred halves of PD file transfer: the "finishing" idle-fragment
      protocol and `FtUpdateMsgMax` throttling.
- [ ] A certifiable test harness.

The goal is to support every command and reply in the SIA OSDP v2.2.2
specification.

## Contributing

We welcome contributions! Please:

1. Submit pull requests against the `main` branch
2. Follow existing code style and conventions — see
   [CLAUDE.md](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/CLAUDE.md)
   for the architectural rules that constrain the core
3. Include tests for new features: at minimum a round-trip test and a negative
   (truncated or malformed input) test for any new codec
4. Update documentation as needed

For collaboration inquiries or questions, contact us through
[Z-bit Systems, LLC](https://z-bitco.com).

**Hardware Vendor Collaboration**

We encourage OSDP hardware vendors to utilize this project to accelerate
development of OSDP-related devices. Core functionality is under an open source
license to help increase adoption rates of the OSDP standard. Contact Z-bit
Systems, LLC for inquiries regarding commercial integration or custom development.

## License

OSDP-Embedded is dual-licensed. You may use it under either, at your choice:

- **Open source**: [GNU General Public License v3.0 or later](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE-GPL-3.0.txt)
  (GPL-3.0-or-later) — for products that are themselves distributed under a
  GPL-compatible license.
- **Commercial**: a paid license from Z-bit Systems for use in proprietary products
  that cannot comply with GPL terms, such as closed-source embedded firmware. See
  [LICENSING](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSING)
  for inquiries.

Every source file carries the SPDX identifier `GPL-3.0-or-later`; a signed
commercial agreement supersedes those terms for its licensee. See
[LICENSE.md](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/blob/main/LICENSE.md)
for the full explainer.

## Acknowledgments

- **[Security Industry Association](https://www.securityindustry.org/)** — for the
  OSDP standard and for publishing
  [libosdp-conformance](https://github.com/Security-Industry-Association/libosdp-conformance),
  whose captures validate our framing byte-for-byte.
- **[tiny-AES-c](https://github.com/kokke/tiny-AES-c)** (Unlicense) — the AES-128
  primitive used by tests and host tools. Production builds bind their own.
- **[Unity](https://github.com/ThrowTheSwitch/Unity)** — the vendored test framework.

## Support

For questions, issues, or feature requests:

- Open an issue on [GitHub Issues](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/issues)
- Contact [Z-bit Systems, LLC](https://z-bitco.com)

---

**About Z-bit Systems, LLC**

Z-bit Systems specializes in access control systems, physical security integration,
and enterprise security software solutions. We provide commercial support, custom
development, and consulting services. Learn more at [z-bitco.com](https://z-bitco.com).
