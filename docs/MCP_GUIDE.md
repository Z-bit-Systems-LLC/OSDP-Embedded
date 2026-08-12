# Agent-driven ACU testing with `osdp-mcp`

`tools/osdp-mcp/` is a [Model Context Protocol](https://modelcontextprotocol.io/)
server that wraps the Rust `osdp_embedded::pd::Pd` so an AI agent (Claude Code, an
IDE assistant, an autonomous test runner) can drive a virtual PD against an ACU
under test.

The agent gets tools for lifecycle, observation, identity, reply scripting, and
fault injection. The PD itself lives on a dedicated thread inside the server, so
the `!Send` C state machine stays single-threaded while the MCP layer remains
async.

Defaults (PDID vendor `ZBC`, the library's "Secure Reader" capability template,
baseline POLL/ID/CAP/LED/BUZ/OUT/TEXT/KEYSET/COMSET behavior) match `osdp-pd-mock`,
so a freshly-configured MCP-driven PD behaves identically to the CLI tool. The
agent overrides specific command codes from there.

## Building

Built as part of the Rust workspace — no CMake step:

```sh
# Default build (RustCrypto AES backend for Secure Channel):
cargo build  --manifest-path rust/Cargo.toml -p osdp-mcp
cargo test   --manifest-path rust/Cargo.toml -p osdp-mcp

# Add the tiny-AES-c backend on top:
cargo build  --manifest-path rust/Cargo.toml -p osdp-mcp --features crypto-tiny-aes
```

Cargo features select which AES backends get compiled in. At runtime, `--crypto
<name>` picks among them.

| Feature | Default | AES source |
| --- | --- | --- |
| `crypto-rustcrypto` | yes | pure-Rust [`aes`](https://crates.io/crates/aes) crate (constant-time) |
| `crypto-tiny-aes` | no | vendored tiny-AES-c, compiled via `build.rs` from `vendor/tiny-aes/` |

Both backends source random bytes from `getrandom` (the OS CSPRNG —
`BCryptGenRandom` / `/dev/urandom` / `getentropy`). Adding a third backend
(wolfCrypt, mbedTLS, hardware AES) is a single file behind a new `crypto-*` feature.

`--crypto` may be omitted; the binary defaults to the first compiled-in backend.
Run `osdp-mcp --help` for the backend names recognised in your build.

## Transports

The binary lands at `rust/target/debug/osdp-mcp` (or `…/release/`). Two transports
are selected at runtime with `--transport`:

| Transport | Flag | Use |
| --- | --- | --- |
| stdio (default) | `--transport stdio` | One MCP client per process over stdin/stdout. What desktop clients launch directly. |
| Streamable HTTP | `--transport http` | Long-running server mounted at `/mcp`. Multiple concurrent clients share one PD. Useful for remote agents, CI runners, or sharing a PD across IDE sessions. |

For HTTP mode the bind address is `--bind <addr>`, defaulting to `127.0.0.1:8080`.
Loopback is the default by design — the PD-control surface (script replies, inject
events, force session loss) is unauthenticated, so binding to a non-loopback
address is something the operator opts into deliberately. Put a reverse proxy with
auth in front if you need that.

## Client configuration

Claude Code (`~/.claude.json`), launching on stdio — the typical local setup:

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

Running as a shared HTTP server and pointing a client at it by URL:

```sh
# Start the server (loopback by default):
osdp-mcp --transport http --bind 127.0.0.1:8080

# In the client config, reference the endpoint instead of a command:
#   "osdp-mcp": { "url": "http://127.0.0.1:8080/mcp" }
```

## Tools

Call `pd_status` first. The operator may have pre-configured a PD via `OSDP_MCP_*`
environment variables, in which case it is already running; otherwise call
`pd_configure` before anything else, since the observation and injection tools
error until a PD exists.

### Lifecycle

| Tool | Purpose |
| --- | --- |
| `pd_configure` | Bring up a PD on a serial port (port, baud, address, SC mode). Tears down any previous PD first. |
| `pd_stop` | Stop the current PD. Idempotent. |
| `pd_start` | Restart a stopped PD from the remembered configuration — no need to re-supply the SCBK. |
| `pd_status` | Snapshot: running / online / SC / most recent command and reply. Cheap, safe to poll. |

### Identity and capabilities

| Tool | Purpose |
| --- | --- |
| `pd_get_pdid` / `pd_set_pdid` | Read and edit the identity reported in `osdp_ID`. `set` is partial — only the fields you pass change. |
| `pd_get_pdcap` | Read the capability set reported in `osdp_CAP`, each record annotated with its Annex B meaning. |
| `pd_set_capability` | Add, update, or remove one capability record by function code, validated against OSDP v2.2.2 Annex B. |
| `pd_reset_pdcap` | Restore the library's "Secure Reader" template. |

Identity and capabilities are process state: they persist across `pd_stop` /
`pd_start` and are independent of whether a PD is running.

### Observation

| Tool | Purpose |
| --- | --- |
| `get_log` | Cursor-paged decoded wire history. **Hides POLL/ACK heartbeat by default** — pass `exclude_codes: []` to see everything; the `suppressed` block reports per-code hidden counts. |
| `get_log_summary` | Per-(direction, code) counts across the whole ring. No payloads — a cheap "what's interesting?" probe. |
| `clear_log` | Drop log entries; the cursor stays monotonic. |
| `get_wire_trace` | Raw byte-level TX/RX chunks with microsecond timestamps and full hex. For diagnosing framing, integrity, and SC-vs-plaintext faults. |
| `clear_wire_trace` | Drop captured chunks. Pair with `get_wire_trace`: clear, reproduce, snapshot. |
| `wait_for_command` | Block until a command with the given code arrives, or time out. |
| `pd_reader_state` | Snapshot the virtual reader's outputs — the resolved colour of each LED the ACU has driven, plus buzzer state. |
| `ping` / `version` | Liveness banner; build identity. Use `version` to confirm a deployed binary includes a fix before chasing a bug that's already patched. |

### Reply scripting

| Tool | Purpose |
| --- | --- |
| `set_reply_for` | Pin a fixed reply for a command code until cleared. |
| `set_reply_script` | Install a sequenced override — first match gets `steps[0]`, and so on, optionally cycling. |
| `nak_next` | One-shot: make the next command of a given code reply NAK, then resume. |
| `clear_overrides` | Drop every installed override. Idempotent. |

### Event and fault injection

| Tool | Purpose |
| --- | --- |
| `inject_raw` | Queue a card read; surfaces as `osdp_RAW` on the next POLL. |
| `inject_keypad` | Queue a keypad press; surfaces as `osdp_KEYPAD`. |
| `inject_local_status` | Queue a tamper/power change; surfaces as `osdp_LSTATR`. |
| `clear_events` | Drop every queued event. Idempotent. |
| `drop_next_n_replies` | Silently swallow the next N replies — exercises the ACU's offline detection. The inbound command is still logged. |
| `force_session_loss` | Tear down and rebuild the PD with the same parameters; the ACU should re-handshake. |

Queued events are delivered in FIFO order. A queued event is only deliverable for a
short freshness window (~2 s): like a real reader it is reported on the next POLL or
dropped, so a card read injected while the ACU isn't polling can't be replayed
minutes later when polling resumes. `pd_status` surfaces both `event_queue_depth`
and `drop_remaining` so an agent can confirm its setup before driving the ACU.

## Secure Channel

Enabled per-PD by passing `sc_mode` to `pd_configure`:

- `"none"` — Secure Channel disabled.
- `"install"` — accept handshakes with the spec's well-known SCBK-D. Convenient for
  development against an ACU that supports the default key. Commissioning only.
- `"scbk"` + `scbk_hex` — bind a per-installation SCBK (32 hex chars = 16 bytes).
  The ACU must hold the matching key.

Either keyed mode derives the cUID from the configured PDID per spec D.4.3 and binds
the chosen AES backend (`--crypto`) as the PD's `ScCrypto` provider. `pd_status`
never exposes the key.

## Virtual reader UI

An optional browser view of the reader runs alongside either MCP transport, enabled
with `--ui-bind <addr>` or `OSDP_MCP_UI_BIND` (off by default, loopback-only):

- `GET /` serves a self-contained page rendering each reader LED as a glowing circle,
  with a speaker icon that pulses while the buzzer sounds (audio plays through the
  Web Audio API behind a one-click enable, per browser autoplay policy).
- `GET /api/state` returns the JSON snapshot; `GET /api/events` streams one
  server-sent event per change, with a slow polling backstop so it degrades
  gracefully behind a buffering proxy.
- The page's keypad digits and a card-number field POST `/api/keypad` and
  `/api/card`, enqueuing real `osdp_KEYPAD` / `osdp_RAW` events — the reader's
  keypad and card slot driven from the browser. These are the only writes the UI
  surface performs.
