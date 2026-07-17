# OSDP-Embedded

[![Build Status](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_apis/build/status/6?branchName=main)](https://dev.azure.com/Z-bitSystems/OSDP%20Embedded/_build/latest?definitionId=6&branchName=main)

A portable, embedded-friendly implementation of the SIA OSDP (Open Supervised
Device Protocol) v2.2.2, written in freestanding C11 with a `no_std`-compatible
Rust wrapper on top.

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

The `osdp-mcp` server (Rust,
[Model Context Protocol](https://modelcontextprotocol.io/) over
stdio or streamable HTTP) exposes the same PD-on-a-serial-port
behavior as `osdp-pd-mock` but driven through an AI agent. The
agent can bring a PD up, script its replies for any command code,
inject NAKs, wait for specific inbound commands, and read the
decoded wire history — useful for interactive ACU interop
investigation and for letting an agent author its own regression
tests against a controller.

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
├── osdp-acu-mock/            # live ACU on a serial port; pair with any PD
│                             # for interop validation
└── osdp-mcp/                 # MCP server exposing an `osdp::pd` for
                              # agent-driven ACU testing (Rust;
                              # member of the rust/ workspace)
tests/
├── vendor/unity/             # vendored Unity test framework
├── captures/                 # drop *.osdpcap files here for integration tests
└── test_*.c                  # Unity-based unit tests, run on host
vendor/                       # 3rd-party code shared between tools and tests
└── tiny-aes/                 # tiny-AES-c (Unlicense / public domain) —
                              # AES-128 ECB primitive for tests + osdp-pd-mock
rust/                         # Rust workspace
└── osdp/                     #   `osdp-embedded` crate: typed Pd / Acu /
                              #   frame / messages / sc + private FFI seam
                              #   (mod sys, no_std, built via cc crate)
docs/                         # design docs and plan; spec/ is gitignored
```

## Building

CMake-based; targets Windows host first (MSVC, clang, MinGW) and any
embedded toolchain with a C11 compiler.

### With CMake presets (recommended)

`CMakePresets.json` ships ready-made `debug`, `release`, `asan`, and
`lib-only` configurations (Ninja generator, each in its own
`build/<preset>/` directory). The whole configure → build → test loop
is one command:

```sh
cmake --workflow --preset debug
```

Or run the steps individually:

```sh
cmake --preset debug          # configure  -> build/debug/
cmake --build --preset debug  # build
ctest --preset debug          # test (output-on-failure baked in)
```

`cmake --list-presets` shows them all. On **Windows + MSVC**, run these
from a *Developer PowerShell for VS* (or after
`Launch-VsDevShell.ps1 -Arch amd64`) so `cl` and `rc` are on `PATH` —
the presets use the single-config Ninja generator, which doesn't locate
the toolchain on its own the way the Visual Studio generator does.

### Manual configure

Without presets (e.g. to pick a different generator), the classic form
still works:

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

To investigate a crash or suspected memory bug, use the `asan` preset
(its own `build/asan/` directory, kept apart from the regular cache so
instrumented and plain objects never mix):

```sh
cmake --workflow --preset asan
```

Or manually, with a separate build directory:

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

### Rust crate

The `osdp-embedded` crate under `rust/osdp/` wraps the C library
behind an idiomatic Rust API. `no_std`-compatible (requires `alloc`
for the trait-object based callbacks); compiles the C sources via
the [`cc` crate](https://crates.io/crates/cc) at build time, so no
separate CMake step or `libclang` is needed and `cargo build --target …`
cross-compiles cleanly to any target the C library compiles on.

The crate offers Cargo features for selecting which roles get
compiled in. A PD-only firmware build doesn't carry any ACU code —
not at the Rust level, not at the C level:

```toml
# Pure PD firmware:
osdp-embedded = { version = "0.1", default-features = false, features = ["pd"] }

# ACU controller:
osdp-embedded = { version = "0.1", features = ["acu"] }

# Both (typical for tools, monitors, integration tests — also the default):
osdp-embedded = "0.1"
```

Default features: `["std", "pd", "acu"]`.

Public API: `osdp_embedded::{Error, Result, Transport, frame, messages, sc}`,
`osdp_embedded::pd::{Pd, CommandHandler, Reply}` (under `pd`),
`osdp_embedded::acu::{Acu, ReplyHandler, TimeoutHandler, …}` (under
`acu`), and the `osdp_embedded::sc::ScCrypto` trait for application-
supplied AES + RNG.

Build / test / run the loopback examples:

```sh
cargo build  --manifest-path rust/Cargo.toml
cargo test   --manifest-path rust/Cargo.toml
cargo run    --manifest-path rust/Cargo.toml --example loopback
cargo run    --manifest-path rust/Cargo.toml --example loopback_sc
```

To cut a release, run `./scripts/New-Release.ps1` (patch bump by default;
`-IncrementType Minor`/`Major` or `-Version x.y.z` to override, `-DryRun`
to preview). It bumps the version, verifies, commits, tags `v<version>`,
and pushes — the tag drives the pipeline, and the Azure DevOps Release
pipeline publishes to crates.io and uploads the tool binaries after
approval. See [docs/PUBLISHING.md](docs/PUBLISHING.md) for the full
recipe and the manual fallback.

### Pre-push checks

Before pushing, run every gate the CI `build` job enforces in one shot:

```sh
./scripts/Check-Code.ps1
```

It mirrors [ci/build.yml](ci/build.yml) — CMake configure/build/`ctest`
(Release preset) for the C library, then `cargo fmt --check`, `cargo
clippy -D warnings`, `cargo build`/`test --workspace --release`, and the
two loopback examples for the Rust workspace. A clean run means the
pipeline should pass. Every gate runs even if an earlier one fails, so a
single invocation surfaces all problems; the script exits non-zero if any
gate failed, so it drops straight into a git `pre-push` hook.

The C gates use the Ninja-based `release` preset, so on Windows run from a
*Developer PowerShell for VS* (it skips the CMake stack with a hint if
`cmake` isn't on PATH). Handy flags: `-Fix` auto-applies `cargo fmt`
instead of failing on it; `-SkipC` / `-SkipRust` run just one stack.

To run the suite automatically on every `git push`, enable the
version-controlled hook once per clone:

```sh
git config core.hooksPath scripts/hooks
```

[`scripts/hooks/pre-push`](scripts/hooks/pre-push) then runs the checks
and aborts the push if any gate fails. It needs PowerShell (`pwsh` or
Windows `powershell`) on PATH; bypass in a pinch with
`git push --no-verify`.

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

### Agent-driven testing (MCP server)

`tools/osdp-mcp/` is a stdio
[Model Context Protocol](https://modelcontextprotocol.io/) server
that wraps the Rust `osdp_embedded::pd::Pd` so an AI agent
(Claude Code, an IDE assistant, an autonomous test runner) can
drive a virtual PD against an ACU under test. The agent gets a
small set of tools for lifecycle, observation, and reply
scripting; the PD itself lives on a dedicated thread inside the
server so the `!Send` C state machine stays single-threaded
while the MCP layer remains async.

Built as part of the Rust workspace — no CMake step:

```sh
# Default build (RustCrypto AES backend for Secure Channel):
cargo build  --manifest-path rust/Cargo.toml -p osdp-mcp
cargo test   --manifest-path rust/Cargo.toml -p osdp-mcp

# Add the tiny-AES-c backend on top:
cargo build  --manifest-path rust/Cargo.toml -p osdp-mcp --features crypto-tiny-aes
```

Cargo features select which AES backends get compiled into the
binary. At runtime, `--crypto <name>` picks among them.

| Feature             | Default | AES source                       |
| ------------------- | ------- | -------------------------------- |
| `crypto-rustcrypto` | yes     | pure-Rust [`aes`](https://crates.io/crates/aes) crate (constant-time) |
| `crypto-tiny-aes`   | no      | vendored tiny-AES-c, compiled via `build.rs` from `vendor/tiny-aes/` |

Both backends source random bytes from `getrandom` (the OS CSPRNG —
`BCryptGenRandom` / `/dev/urandom` / `getentropy`). Adding a third
backend (wolfCrypt, mbedTLS, hardware AES) is a single file behind
a new `crypto-*` feature.

The binary lands at `rust/target/debug/osdp-mcp` (or `…/release/`
with `--release`). Two transports are supported, selected at
runtime by `--transport`:

| Transport          | Flag                  | Use                                                                  |
| ------------------ | --------------------- | -------------------------------------------------------------------- |
| stdio (default)    | `--transport stdio`   | One MCP client per process over stdin/stdout. What desktop clients (Claude Desktop, Claude Code) launch directly. |
| Streamable HTTP    | `--transport http`    | Long-running HTTP server mounted at `/mcp`. Multiple concurrent clients share one PD. Useful for remote agents, CI runners, or sharing a PD across IDE sessions. |

For HTTP mode the bind address is `--bind <addr>`, defaulting to
`127.0.0.1:8080`. Loopback is the default by design — the
PD-control surface (script replies, inject events, force session
loss) is unauthenticated, so binding to a non-loopback address is
something the operator opts into deliberately. Put a reverse
proxy with auth in front if you need that.

Example for Claude Code (`~/.claude.json`), launching osdp-mcp on
stdio (the typical local-agent setup):

```json
{
  "mcpServers": {
    "osdp-mcp": {
      "command": "C:\\path\\to\\OSDP-Embedded\\rust\\target\\release\\osdp-mcp.exe",
      "args": ["--crypto", "rustcrypto"]
    }
  }
}
```

Example for running as a remote/shared HTTP server and pointing a
client at it by URL:

```sh
# Start the server (loopback by default):
osdp-mcp --transport http --bind 127.0.0.1:8080

# In the client config, reference the endpoint instead of a command:
#   "osdp-mcp": { "url": "http://127.0.0.1:8080/mcp" }
```

`--crypto` may be omitted; the binary defaults to the first
compiled-in backend (RustCrypto when built with default features).
Run `osdp-mcp --help` for the full list of recognised backend
names in the current build.

Tools exposed today:

| Category    | Tool                   | Purpose                                                          |
| ----------- | ---------------------- | ---------------------------------------------------------------- |
| Lifecycle   | `pd_configure`         | Open a serial port and start the PD on it (with optional SC).    |
|             | `pd_stop`              | Tear the PD down (idempotent).                                   |
|             | `pd_status`            | Structured snapshot: running / online / SC / last cmd+reply / event queue depth. |
| Observation | `get_log`              | Cursor-paged decoded wire history (commands, replies, NAKs). **Hides POLL/ACK heartbeat by default** — pass `exclude_codes: []` to see every entry. Response's `suppressed` block reports per-code hidden counts. |
|             | `get_log_summary`      | Per-(direction, code) counts across the whole ring. No payloads — cheap "what's interesting in the log?" probe. |
|             | `clear_log`            | Drop log entries; cursor stays monotonic.                        |
|             | `wait_for_command`     | Block until an inbound command with a given code arrives.        |
| Scripting   | `set_reply_for`        | Pin a static reply for a command code.                           |
|             | `set_reply_script`     | Queue a sequence of replies (one-shot or cycling).               |
|             | `nak_next`             | One-shot: make the next command of a given code reply NAK.       |
|             | `clear_overrides`      | Drop every installed override.                                   |
| Events      | `inject_raw`           | Queue a card-read; the PD reports RAW on its next POLL.          |
|             | `inject_keypad`        | Queue a keypad press; reports KEYPAD on the next POLL.           |
|             | `inject_local_status`  | Queue a tamper/power change; reports LSTATR on the next POLL.    |
|             | `clear_events`         | Drop every queued event.                                         |
| Faults      | `drop_next_n_replies`  | Silently swallow the next N replies — exercises ACU offline detection. |
|             | `force_session_loss`   | Rebuild the PD with the same params; ACU should re-handshake.    |
| Liveness    | `ping`                 | Banner string — confirms the server is reachable.                |

Defaults (PDID vendor "ZBC", a small PDCAP set, baseline
POLL/ID/CAP/LED/BUZ/OUT/TEXT/KEYSET/COMSET behavior) match
`osdp-pd-mock` so a freshly-configured MCP-driven PD behaves
identically to the CLI tool. The agent overrides specific cmd
codes from there.

Secure Channel is enabled per-PD by passing `sc_mode` to
`pd_configure`. Two modes:

  - `"scbkd"` — bind the well-known install-time SCBK-D from the
    spec. Convenient for development against an ACU that supports
    handshake with the default key.
  - `"scbk"` + `scbk_hex` — bind a per-installation SCBK (32 hex
    chars = 16 bytes). The ACU side must hold the matching key.

Either mode also derives the cUID from the configured PDID per
spec D.4.3 and binds the chosen AES backend (`--crypto`) as the
PD's `ScCrypto` provider.

Event injection (RAW / KEYPAD / LSTATR) and fault injection
(`drop_next_n_replies`, `force_session_loss`) are wired up.
`pd_status` surfaces both `event_queue_depth` and `drop_remaining`
so an agent can confirm its setup before driving the ACU. A queued
event is only deliverable for a short freshness window (~2 s): like a
real reader it is reported on the next POLL or dropped, so a card-read
injected while the ACU isn't polling can't be replayed minutes later
when polling resumes.

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
