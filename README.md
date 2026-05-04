# OSDP-Embedded

A portable, embedded-friendly implementation of the SIA OSDP (Open Supervised
Device Protocol) v2.2.2, written in freestanding C11 with a planned Rust
(`no_std`-compatible) wrapper.

The library is structured so that a Peripheral Device (PD), an Access Control
Unit (ACU/CP), or a passive bus Monitor can each pull in **only the code they
actually need** — no malloc, no globals, no OS dependencies in the core.

## Project status

**Iterations 1–3 done.** The library now covers:

- **Layer 1 framing** — encode and decode every OSDP frame variant
  (plain, with-SCB, MAC-bearing, encrypted-payload). Round-trips a
  592-frame `libosdp-conformance` Secure Channel capture byte-for-byte.
- **Per-message codecs** for the v2.2 baseline command/reply set
  (POLL, ID, CAP, LED, BUZ, OUT, TEXT, COMSET on the ACU side; ACK,
  NAK, PDID, PDCAP, RAW, KEYPAD, COM on the PD side), plus the SC
  handshake messages (CHLNG, SCRYPT, CCRYPT, RMAC_I).
- **PD-side state machine** (`osdp::pd`): address filtering,
  sequence-number policing with byte-identical retransmit detection,
  online/offline tracking, optional Secure Channel handshake +
  operational SCS_15..18.
- **ACU-side state machine** (`osdp::acu`): multi-PD slot management,
  per-PD SQN, reply/timeout callbacks, optional Secure Channel
  handshake (fire-and-forget) and operational SCS_15..18 with
  automatic session-loss detection per spec D.1.4 / 5.7 / 5.9.
- **Live interop verified** against both
  [libosdp-conformance](https://github.com/Security-Industry-Association/libosdp-conformance)
  (via byte-level capture replay in tests) and Z-bit Systems'
  [OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) `ACUConsole`
  (over a com0com null-modem pair, exercising POLL/ID/CAP plus SC).

See [docs/PLAN.md](docs/PLAN.md) for the phased roadmap and what's still
in progress.

The included `osdp-parser` CLI consumes
[OSDPCAP-format](https://github.com/Security-Industry-Association/libosdp-conformance/blob/master/doc/doc-src/osdpcap-format.md)
captures (JSON-Lines) — both the libosdp-conformance space-separated
dialect and OSDP.Net's dash-separated dialect — and prints a one-line
summary per frame. Drop captures into `tests/captures/` to register
them as integration tests automatically.

The included `osdp-pd-mock` CLI runs an `osdp::pd` instance on a real
or virtual serial port (Win32 or POSIX), with optional Secure Channel
(`--sc=scbkd` or `--sc=scbk:HEX32`). Useful for live interop validation
against a hardware ACU, OSDP.Net's `ACUConsole`, etc.

The companion `osdp-acu-mock` CLI runs an `osdp::acu` instance on a
serial port, driving an external PD (OSDP.Net's `PDConsole`, a
hardware PD, or another `osdp-pd-mock` over a com0com pair). Closes
the symmetric interop loop: pd-mock validates our PD against
third-party ACUs, acu-mock validates our ACU against third-party PDs.

## Architecture at a glance

The core library is split by **message direction**, not by role:

| Target           | Contents                                                           | Linked by         |
| ---------------- | ------------------------------------------------------------------ | ----------------- |
| `osdp::core`     | CRC-16, checksum, frame decode/build, streaming push API, Secure Channel primitives (key derivation, cryptograms, custom CBC-MAC, AES-CBC payload encrypt/decrypt, frame wrap/unwrap) | everything |
| `osdp::messages` | One TU per command and per reply, each containing model + decoder + builder | PD, ACU, Monitor |
| `osdp::dispatch` | Optional switch-router from frame → typed message; pulls all codecs | Monitor only      |
| `osdp::pd`       | PD-side state machine: address filtering, command handler dispatch, sequence-number policing (byte-identical retransmit detection), online/offline tracking, optional Secure Channel handshake + operational SCS_15..18 | PD applications |
| `osdp::acu`      | ACU-side state machine: multi-PD registration, command issuance, reply/timeout callbacks, sequence-number progression, optional Secure Channel handshake (fire-and-forget) + operational SCS_15..18 with session-loss detection | ACU applications |

A PD or ACU application calls per-message codec functions directly
(`osdp_led_decode`, `osdp_pdid_build`, etc.) and lets the linker garbage-collect
everything it doesn't reference. A Monitor links `osdp::dispatch` to decode
arbitrary traffic without writing its own switch.

Secure Channel is opt-in: a PD or ACU application that doesn't bind a
crypto vtable + key material via the `osdp_*_set_sc_*` API behaves
exactly like the iteration-2 (insecure) build, and the AES + RNG code
isn't pulled into the link. When SC is enabled, the consumer supplies
the AES-128 ECB primitive and the RNG via callbacks (`osdp_sc_crypto_t`)
— the core never vendors a crypto implementation. Tests use a vendored
copy of [tiny-AES-c](https://github.com/kokke/tiny-AES-c) (Unlicense /
public domain) at `vendor/tiny-aes/`; production builds typically bind
mbedTLS, hardware AES, or `BCryptGenRandom` / `/dev/urandom`.

See [CLAUDE.md](CLAUDE.md) for the full set of architectural constraints and
coding rules.

## Repository layout

```
core/                         # C11 portable library, framing + codecs
├── include/osdp/             # public headers (consumers #include <osdp/...>)
├── src/
│   ├── shared/               # framing, integrity, stream — always linked
│   ├── commands/             # ACU→PD message codecs (one TU per command)
│   ├── replies/              # PD→ACU message codecs (one TU per reply)
│   └── dispatch/             # optional bulk dispatch helpers
└── CMakeLists.txt
pd/                           # PD-side state machine + transport HAL
└── ...                       # exports osdp::pd
acu/                          # ACU-side state machine + transport HAL
└── ...                       # exports osdp::acu
tools/
├── osdp-parser/              # OSDPCAP-aware CLI Monitor (osdpcap reader + main)
├── osdp-pd-mock/             # live PD on a serial port; pair with any ACU
│                             # for interop validation
└── osdp-acu-mock/            # live ACU on a serial port; pair with any PD
                              # for interop validation
tests/
├── vendor/unity/             # vendored Unity test framework
├── captures/                 # drop *.osdpcap files here for integration tests
└── test_*.c                  # Unity-based unit tests, run on host
vendor/                       # 3rd-party code shared between tools and tests
└── tiny-aes/                 # tiny-AES-c (Unlicense / public domain) —
                              # AES-128 ECB primitive for tests + osdp-pd-mock
rust/                         # planned: osdp-sys + osdp Rust crates
docs/                         # design docs and plan; spec/ is gitignored
```

## Building

CMake-based; targets Windows host first (MSVC, clang, MinGW) and any
embedded toolchain with a C11 compiler.

```sh
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Useful CMake options:

| Option              | Default | Effect                                           |
| ------------------- | ------- | ------------------------------------------------ |
| `OSDP_BUILD_TESTS`  | `ON`    | Build the Unity test suites under `tests/`.      |
| `OSDP_BUILD_TOOLS`  | `ON`    | Build host-side tools (`osdp-parser`).           |
| `OSDP_SANITIZE`     | `OFF`   | Build with AddressSanitizer (and UBSan on GCC/Clang) for memory-error debugging. Use a separate build directory; sanitizer-instrumented objects don't mix with the regular cache. |

### Debugging with sanitizers

To investigate a crash or suspected memory bug, configure a separate
build directory with `OSDP_SANITIZE=ON`:

```sh
cmake -S . -B build-asan -DOSDP_SANITIZE=ON
cmake --build build-asan --config Debug
ctest --test-dir build-asan -C Debug
```

On Windows, ASan needs `clang_rt.asan_dynamic-x86_64.dll` on PATH.
The DLL ships with Visual Studio under
`VC\Tools\MSVC\<version>\bin\Hostx64\x64\` — add it to PATH or run from
a Developer PowerShell.

For a tight embedded build (core only), set both options to `OFF` and
link the `osdp::core` and `osdp::messages` (and optionally
`osdp::dispatch`) targets only — no compiler-options or test framework
get pulled in.

### Inspecting a capture

```sh
build/tools/osdp-parser/osdp-parser my-capture.osdpcap
# or via stdin:
cat my-capture.osdpcap | build/tools/osdp-parser/osdp-parser
```

### Live interop on a serial port

`osdp-pd-mock` runs a real PD on a serial port so you can validate
this stack against an independent ACU implementation (Z-bit Systems'
[OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) `ACUConsole`,
a hardware controller, etc.). The PD library itself stays freestanding;
the tool supplies a Win32 (`CreateFile` / `ReadFile`) or POSIX
(`termios` / `O_NONBLOCK`) serial transport adapter selected at build
time by CMake.

```sh
# Windows (com0com pair, ACUConsole on COM4):
$env:OSDP_INTEROP_PD_PORT = "COM3"
build\tools\osdp-pd-mock\Debug\osdp-pd-mock.exe --address 0 -v

# Linux (USB-RS485 dongle):
export OSDP_INTEROP_PD_PORT=/dev/ttyUSB0
build/tools/osdp-pd-mock/osdp-pd-mock --address 0 -v
```

The mock answers POLL with ACK, ID with a placeholder PDID, CAP with a
small default capability set, and ACKs LED / BUZ / OUT / TEXT /
COMSET / KEYSET. Run with `--help` for the full flag set. Secure
Channel mode (`--sc=scbkd`) is pending an AES-vendoring decision in
this build of the tool.

`osdp-acu-mock` is the companion tool that runs an `osdp::acu` on a
serial port and drives an external PD. It auto-sends ID once, CAP
once, then POLL on a configurable interval (default 500 ms) and
prints decoded replies / SC events / timeouts to stderr. SC mode is
identical to the PD tool (`--sc=scbkd` or `--sc=scbk:HEX32`); on
session loss it auto-restarts the handshake so a PD reboot doesn't
require restarting the ACU process.

```sh
# Drive a PD at address 0 on COM3 with the default install key:
$env:OSDP_INTEROP_ACU_PORT = "COM3"
build\tools\osdp-acu-mock\Debug\osdp-acu-mock.exe --address 0 --sc=scbkd -v

# Plaintext mode (no SC), faster polling:
build\tools\osdp-acu-mock\Debug\osdp-acu-mock.exe --address 0 \
    --poll-interval 200 -v
```

## Reference material

- **Spec**: SIA OSDP v2.2.2 (2024). Not redistributed in this repo;
  `docs/spec/` is gitignored. Implementers should source the PDF directly
  from SIA.
- **Behavioral oracle**: [Z-bit Systems' OSDP.Net](https://github.com/Z-bit-Systems-LLC/OSDP.Net) — full C# OSDP implementation by the same author. Used as a
  reference for command/reply layouts and as a known-good comparison target;
  no code is copied across.

## License

OSDP-Embedded is **dual-licensed**:

- **Open source**: [GNU General Public License v3.0 or later](LICENSE-GPL-3.0.txt) (GPL-3.0-or-later).
  Use this if your product is also distributed under a GPL-compatible license.
- **Commercial**: a paid license from Z-bit Systems for use in proprietary
  products that cannot comply with GPL terms (e.g. closed-source embedded
  firmware). See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for inquiries.

You may choose either license. Every source file carries the SPDX identifier
`GPL-3.0-or-later`; commercial licensees receive a separate written
agreement that supersedes the GPL terms for their use.

See [LICENSE.md](LICENSE.md) for the full explainer.
