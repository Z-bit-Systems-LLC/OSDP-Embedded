# OSDP-Embedded

A portable, embedded-friendly implementation of the SIA OSDP (Open Supervised
Device Protocol) v2.2.2, written in freestanding C11 with a planned Rust
(`no_std`-compatible) wrapper.

The library is structured so that a Peripheral Device (PD), an Access Control
Unit (ACU/CP), or a passive bus Monitor can each pull in **only the code they
actually need** — no malloc, no globals, no OS dependencies in the core.

## Project status

**Iteration 1 — Decoder.** Take raw OSDP bytes (e.g. captured from a bus
sniffer or logic analyzer) and decode them into typed message structs. No
transmit path, no state machine, no Secure Channel yet. See [docs/PLAN.md](docs/PLAN.md)
for the phased roadmap.

The included `osdp-parser` CLI consumes
[OSDPCAP-format](https://github.com/Security-Industry-Association/libosdp-conformance/blob/master/doc/doc-src/osdpcap-format.md)
captures (JSON-Lines, as produced by `libosdp-conformance` and similar
tools) and prints a one-line summary per frame. Drop captures into
`tests/captures/` to register them as integration tests automatically.

## Architecture at a glance

The core library is split by **message direction**, not by role:

| Target           | Contents                                                           | Linked by         |
| ---------------- | ------------------------------------------------------------------ | ----------------- |
| `osdp::core`     | CRC-16, checksum, frame decode/build, streaming push API           | everything        |
| `osdp::messages` | One TU per command and per reply, each containing model + decoder + builder | PD, ACU, Monitor |
| `osdp::dispatch` | Optional switch-router from frame → typed message; pulls all codecs | Monitor only      |
| `osdp::pd`       | PD-side state machine: address filtering, command handler dispatch, sequence-number policing, online/offline tracking | PD applications |
| `osdp::acu`      | ACU-side state machine: multi-PD registration, command issuance, reply/timeout callbacks, sequence-number progression | ACU applications |

A PD or ACU application calls per-message codec functions directly
(`osdp_led_decode`, `osdp_pdid_build`, etc.) and lets the linker garbage-collect
everything it doesn't reference. A Monitor links `osdp::dispatch` to decode
arbitrary traffic without writing its own switch.

Role-specific concerns — RS-485 transport, polling schedules, sequence numbers,
PD-side responder state — live **above** the core in iteration 2+
(`pd/`, `acu/`, `monitor/` peers of `core/`), not in this initial decoder
release.

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
└── osdp-parser/              # OSDPCAP-aware CLI Monitor (osdpcap reader + main)
tests/
├── vendor/unity/             # vendored Unity test framework
├── captures/                 # drop *.osdpcap files here for integration tests
└── test_*.c                  # Unity-based unit tests, run on host
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
