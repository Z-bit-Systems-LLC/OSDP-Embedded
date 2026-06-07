// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! osdp-mcp — MCP server that drives an osdp-embedded PD against an
//! ACU under test.
//!
//! Two transports, chosen at startup via `--transport`:
//!   - `stdio` (default) — one MCP client per process over
//!     stdin/stdout. What local desktop clients launch directly.
//!   - `http` — streamable-HTTP server mounted at `/mcp` on
//!     `--bind <addr>` (default `127.0.0.1:8080`). Multiple clients
//!     share one PD (one `PdHandle` per process).
//!
//! PDID / PDCAP defaults match `osdp-pd-mock` so a freshly-configured
//! PD behaves identically to the existing CLI tool.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use osdp_embedded::messages::{Keypad, Raw, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_RAW};
use osdp_mcp::crypto::Selector;
use osdp_mcp::log::{LogEntry, LogFilter, LogPage, LogSummary, DEFAULT_CAPACITY};
use osdp_mcp::overrides::OverrideReply;
use osdp_mcp::pd_actor::{PdHandle, PdStatus, ScConfig};
use osdp_mcp::wire::{WirePage, DEFAULT_WIRE_CAPACITY};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{schemars, tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt};
use tracing_subscriber::EnvFilter;

// ---- Tool parameter schemas ------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PingArgs {
    /// Echoed back verbatim. Optional.
    #[serde(default)]
    message: Option<String>,
}

/// Build identity reported by the `version` tool. Lets an operator
/// confirm a deployed binary includes a given fix instead of guessing
/// from file timestamps.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
struct VersionInfo {
    /// Crate package name — always "osdp-mcp".
    name: &'static str,
    /// Semantic version from Cargo.toml (e.g. "0.1.7"). Bumped per
    /// release commit, so this is the quickest "is the running binary
    /// current" check.
    version: &'static str,
    /// Short git commit the binary was built from, or "unknown" when
    /// built outside a git checkout. Pin-points the exact source even
    /// between version bumps.
    git_commit: &'static str,
    /// True when the working tree had uncommitted changes at build
    /// time — a red flag for a binary that's meant to match a tag.
    git_dirty: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PdConfigureArgs {
    /// Serial port name. Windows: "COM5". POSIX: "/dev/ttyUSB0".
    /// A virtual port (com0com pair, socat pty) works the same.
    port: String,
    /// Line rate. Defaults to 9600 (the OSDP spec's baseline).
    #[serde(default = "default_baud")]
    baud: u32,
    /// 7-bit PD address (0x00..0x7E). Defaults to 0. Broadcast
    /// (0x7F) is always accepted in addition to this one.
    #[serde(default)]
    address: u8,
    /// Secure Channel mode. Accepted values:
    ///   - "none" (default): SC disabled; the PD NAKs any SCB frame.
    ///   - "install" (alias: "scbkd", "default"): PD is in install
    ///     mode and accepts handshakes with the well-known SCBK-D
    ///     key from the spec (D.4). Use this for first-time keying
    ///     and for development against ACUs that handshake with the
    ///     default key.
    ///   - "scbk" (alias: "operational"): PD uses a per-installation
    ///     16-byte SCBK — pair with `scbk_hex`. This is the steady-
    ///     state mode after a KEYSET has rotated the install key.
    #[serde(default)]
    sc_mode: Option<String>,
    /// 32-hex-char SCBK (16 bytes) — required when `sc_mode` is
    /// "scbk" / "operational", ignored otherwise.
    #[serde(default)]
    scbk_hex: Option<String>,
}

fn default_baud() -> u32 {
    9600
}

/// Resolve a Secure Channel mode + optional key into a `ScConfig`.
/// Shared by the `pd_configure` tool and the `OSDP_MCP_SC_MODE` /
/// `OSDP_MCP_SCBK_HEX` startup defaults, so both accept the same
/// spellings and produce identical errors.
fn parse_sc_config(
    sc_mode: Option<&str>,
    scbk_hex: Option<&str>,
) -> Result<Option<ScConfig>, String> {
    // Normalise to lowercase so "Install" / "SCBKD" etc. all work.
    let mode = sc_mode.map(|s| s.trim().to_ascii_lowercase());
    match mode.as_deref() {
        None | Some("") | Some("none") | Some("off") => Ok(None),
        // Install mode = SCBK-D (spec D.4 well-known default key).
        // Accept the colloquial term plus the spec-internal name and
        // a few common synonyms an agent might reach for.
        Some("install") | Some("scbkd") | Some("scbk-d") | Some("default") => {
            Ok(Some(ScConfig::Scbkd))
        }
        Some("scbk") | Some("operational") | Some("custom") => {
            let hex = scbk_hex.unwrap_or("");
            let bytes = hex_decode(hex)?;
            if bytes.len() != 16 {
                return Err(format!(
                    "sc_mode='scbk' requires a 32-hex-char key (16 bytes); got {} byte(s)",
                    bytes.len()
                ));
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&bytes);
            Ok(Some(ScConfig::Scbk(key)))
        }
        Some(other) => Err(format!(
            "unknown sc_mode {other:?}; expected one of: \
             none, install (= scbkd / default), scbk (= operational, with scbk_hex)"
        )),
    }
}

/// Human-readable one-word summary of an SC config, for log lines and
/// the `pd_configure` success message.
fn sc_label(sc: &Option<ScConfig>) -> &'static str {
    match sc {
        None => "off",
        Some(ScConfig::Scbkd) => "install (SCBK-D)",
        Some(ScConfig::Scbk(_)) => "operational (SCBK)",
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetLogArgs {
    /// Skip entries with `seq < since_seq`. Use the `next_seq` from
    /// a previous response to continue paging. Defaults to 0 (all).
    #[serde(default)]
    since_seq: u64,
    /// Cap the number of entries returned. Defaults to the ring
    /// capacity so a single call drains everything.
    #[serde(default = "default_log_limit")]
    limit: u32,
    /// Codes to omit. **Default is `[0x60, 0x40]`** (POLL/ACK
    /// heartbeat) — without this filter a polling ACU will fill the
    /// log with thousands of repetitive entries. The response's
    /// `suppressed` block reports per-code counts of what was hidden,
    /// so you can see the heartbeat is alive without paging through
    /// it. Pass `exclude_codes: []` (empty array) to see every entry
    /// including heartbeat. Ignored if `include_codes` is set.
    #[serde(default)]
    exclude_codes: Option<Vec<u8>>,
    /// Only include entries whose code is in this list. Everything
    /// else is treated as suppressed. Pair with a focused list when
    /// hunting for a specific exchange (e.g. `[0x61, 0x45]` for ID
    /// + PDID).
    #[serde(default)]
    include_codes: Option<Vec<u8>>,
}

impl GetLogArgs {
    fn filter(&self) -> LogFilter {
        LogFilter {
            exclude_codes: self.exclude_codes.clone(),
            include_codes: self.include_codes.clone(),
        }
    }
}

fn default_log_limit() -> u32 {
    DEFAULT_CAPACITY as u32
}

fn default_wire_limit() -> u32 {
    DEFAULT_WIRE_CAPACITY as u32
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WireTraceArgs {
    /// Skip chunks with `seq < since_seq`. Pass the previous response's
    /// `next_seq` to page only newer chunks. Defaults to 0 (all).
    #[serde(default)]
    since_seq: u64,
    /// Cap the number of chunks returned. Defaults to the full ring.
    #[serde(default = "default_wire_limit")]
    limit: u32,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WaitForCommandArgs {
    /// OSDP command code (e.g. 0x60 for POLL, 0x61 for ID).
    cmd_code: u8,
    /// Hard timeout. Defaults to 5s — long enough to catch slow ACUs,
    /// short enough that an MCP client doesn't hang forever.
    #[serde(default = "default_wait_timeout_ms")]
    timeout_ms: u32,
    /// Only consider entries with `seq > since_seq`. Defaults to 0
    /// — the agent typically snapshots the log first, drives the
    /// ACU, then waits using the snapshot's `next_seq` as cursor.
    #[serde(default)]
    since_seq: u64,
}

fn default_wait_timeout_ms() -> u32 {
    5_000
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReplyStep {
    /// OSDP reply code (e.g. 0x40 for ACK, 0x41 for NAK, 0x45 PDID).
    code: u8,
    /// Optional payload, hex-encoded ("00FF1A"). Empty / omitted for
    /// ACK and other payload-less replies.
    #[serde(default)]
    payload_hex: String,
}

impl ReplyStep {
    fn into_override(self) -> Result<OverrideReply, String> {
        Ok(OverrideReply {
            code: self.code,
            payload: hex_decode(&self.payload_hex)?,
        })
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetReplyForArgs {
    /// Command code (e.g. 0x60 for POLL) to override.
    cmd_code: u8,
    /// Reply to send for every matching command until cleared.
    #[serde(flatten)]
    reply: ReplyStep,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetReplyScriptArgs {
    cmd_code: u8,
    /// Sequence of replies. The first matching command gets `steps[0]`,
    /// the next `steps[1]`, and so on.
    steps: Vec<ReplyStep>,
    /// When false (default), the override is removed once `steps` is
    /// exhausted and subsequent commands fall back to the default
    /// handler. When true, popped steps go to the back so the queue
    /// loops forever.
    #[serde(default)]
    cycle: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct NakNextArgs {
    cmd_code: u8,
    /// NAK error code per spec table 32. 0x03 (Unknown Command) is
    /// the common default; use 0x04 for "Unexpected Sequence", 0x05
    /// "Unsupported Security Block", 0x06 "Encryption Required", etc.
    #[serde(default = "default_nak_code")]
    nak_code: u8,
}

fn default_nak_code() -> u8 {
    0x03
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct InjectRawArgs {
    /// Reader number on the PD (most PDs only have one — reader 0).
    #[serde(default)]
    reader_no: u8,
    /// Spec Table 33: 0 = raw, 1 = Wiegand (default), 2 = UID,
    /// 3 = OSS-SID.
    #[serde(default = "default_format_code")]
    format_code: u8,
    /// Bit count of the card data — Wiegand 26 / Wiegand 34 are
    /// typical. `data_hex` must hold `(bit_count + 7) / 8` bytes.
    bit_count: u16,
    /// Hex-encoded card bit data (e.g. "DEADBEEF" for 32 bits).
    /// MSB-aligned per spec Table 33.
    data_hex: String,
}

fn default_format_code() -> u8 {
    1 // Wiegand — the realistic default for most access-control PDs.
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct InjectKeypadArgs {
    /// Reader number on the PD (most PDs only have one — reader 0).
    #[serde(default)]
    reader_no: u8,
    /// ASCII digits typed at the keypad (e.g. "1234#" for code 1234
    /// followed by enter). Each char becomes one byte per spec
    /// Table 35.
    digits: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct InjectLocalStatusArgs {
    /// 0 = not tampered (default), 1 = tampered.
    #[serde(default)]
    tamper: u8,
    /// 0 = power OK (default), 1 = power lost.
    #[serde(default)]
    power: u8,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DropNextNRepliesArgs {
    /// How many upcoming replies the PD should silently swallow.
    /// Passing 0 effectively cancels any pending drop.
    n: u32,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err(format!("hex string must have even length, got {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char {:?}", b as char)),
    }
}

// ---- Service ---------------------------------------------------------

/// Connect-time guidance handed to the MCP client/agent in the
/// `initialize` response (`ServerInfo.instructions`). Its job is to
/// make the required first step impossible to miss: nothing works
/// until a PD is running, and `pd_configure` is how you start one.
const SERVER_INSTRUCTIONS: &str = "\
This server drives a single virtual OSDP Peripheral Device (PD) on a serial \
port so you can test an Access Control Unit (ACU).

FIRST STEP: call `pd_status`. The operator may have pre-configured a PD that \
is already running (via OSDP_MCP_* environment variables), in which case you \
can go straight to observing/scripting it. If no PD is running, call \
`pd_configure` (\"Start PD on Serial Port\") before anything else — every other \
tool (get_log, the inject_*/set_reply_* fault-injection tools, \
force_session_loss) errors until a PD is running. `pd_configure` also \
reconfigures an already-running PD.

`pd_configure` parameters:
  - port (required): serial device, e.g. \"/dev/ttyUSB0\", \"/dev/serial0\", or \"COM5\".
  - baud (default 9600): line rate; must match the ACU.
  - address (default 0): 7-bit PD address 0x00..0x7E; must match what the ACU polls.
  - sc_mode (default \"none\"): Secure Channel mode —
      \"none\"    : SC disabled.
      \"install\" : accept handshakes with the spec's well-known SCBK-D key (first-time keying / dev).
      \"scbk\"    : operational per-installation key — also pass scbk_hex (32 hex chars / 16 bytes).

If you are unsure of port/baud/address, ask the user before calling pd_configure \
rather than guessing. After configuring, use `pd_status` to confirm the PD is \
running and online, then `get_log` to watch ACU traffic.";

#[derive(Clone)]
struct OsdpMcp {
    pd: Arc<PdHandle>,
}

impl OsdpMcp {
    fn new(crypto: Selector) -> anyhow::Result<Self> {
        let factory = crypto.factory().map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            pd: Arc::new(PdHandle::spawn(factory)),
        })
    }
}

#[tool_router]
impl OsdpMcp {
    /// Liveness check. Returns a banner string; useful to confirm
    /// the server is up before issuing real tools.
    #[tool(
        title = "Ping / Liveness Check",
        description = "Liveness check. Returns a banner string."
    )]
    fn ping(&self, Parameters(args): Parameters<PingArgs>) -> String {
        match args.message {
            Some(m) => format!("osdp-mcp pong: {}", m),
            None => "osdp-mcp pong".to_string(),
        }
    }

    /// Report the running server's build identity. Use this to confirm
    /// a deployed binary actually includes a given fix before chasing a
    /// bug that's already patched in source.
    #[tool(
        title = "Get Server Version",
        description = "Return the running osdp-mcp build identity: package \
                       name, semantic version (Cargo.toml), the git commit \
                       it was built from, and whether the build tree was \
                       dirty. Use it to confirm a deployed binary includes \
                       a given fix rather than guessing from file timestamps."
    )]
    fn version(&self) -> Json<VersionInfo> {
        Json(VersionInfo {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            git_commit: option_env!("OSDP_MCP_GIT_HASH").unwrap_or("unknown"),
            git_dirty: matches!(option_env!("OSDP_MCP_GIT_DIRTY"), Some("true")),
        })
    }

    /// Bring up a PD on a serial port. Any previously-configured PD
    /// is torn down first. PDID and PDCAP currently default to the
    /// values osdp-pd-mock ships with (vendor ZBC, one of every
    /// basic capability) — per-message overrides land in a later
    /// milestone.
    #[tool(
        title = "Start PD on Serial Port",
        description = "Configure and start a PD on a serial port. Replaces any existing PD configuration."
    )]
    async fn pd_configure(
        &self,
        Parameters(args): Parameters<PdConfigureArgs>,
    ) -> Result<String, String> {
        let sc = parse_sc_config(args.sc_mode.as_deref(), args.scbk_hex.as_deref())?;
        let sc_label = sc_label(&sc);
        self.pd
            .configure(args.port.clone(), args.baud, args.address, sc)
            .await
            .map(|()| {
                format!(
                    "PD configured on {} @ {}bps addr=0x{:02X} sc={}",
                    args.port, args.baud, args.address, sc_label
                )
            })
            .map_err(|e| format!("pd_configure failed: {}", e))
    }

    /// Stop the current PD. Idempotent — fine to call when nothing
    /// is configured.
    #[tool(
        title = "Stop PD",
        description = "Stop the current PD, if any. Idempotent."
    )]
    async fn pd_stop(&self) -> Result<String, String> {
        self.pd
            .stop()
            .await
            .map(|()| "PD stopped".to_string())
            .map_err(|e| format!("pd_stop failed: {}", e))
    }

    /// Snapshot of the PD's current state (running / online / SC /
    /// most recent cmd+reply). Cheap; safe to poll.
    #[tool(
        title = "Get PD Status",
        description = "Return a JSON snapshot of the PD's state: running, \
                       online, actively_polling, sc_mode (none/install/scbk = \
                       clear text / SCBK-D / operational), sc_established, and \
                       the last cmd/reply."
    )]
    async fn pd_status(&self) -> Result<Json<PdStatus>, String> {
        self.pd
            .status()
            .await
            .map(Json)
            .map_err(|e| format!("pd_status failed: {}", e))
    }

    /// Read recent on-wire events (commands accepted, replies sent,
    /// library-synthesised NAKs). Cursor-paged via `since_seq`.
    ///
    /// **POLL (0x60) and ACK (0x40) heartbeat never enter the ring** —
    /// they're aggregated into the `suppressed` block at write time so
    /// the 1024-entry ring stays reserved for interesting traffic in
    /// long-running sessions. `exclude_codes: []` does NOT bring them
    /// back as individual entries (their payloads are not stored); use
    /// `get_log_summary` for the count + last-seen timestamp.
    ///
    /// `exclude_codes` / `include_codes` apply on top of that to filter
    /// other codes at read time.
    #[tool(
        title = "Get Wire Log",
        description = "Return up to `limit` log entries with seq >= since_seq. \
                       By default POLL/ACK heartbeat is filtered out and reported in `suppressed`; \
                       pass `exclude_codes: []` to see every entry. \
                       Pair with `get_log_summary` to scan for noise without reading payloads."
    )]
    fn get_log(&self, Parameters(args): Parameters<GetLogArgs>) -> Json<LogPage> {
        let filter = args.filter().resolve();
        Json(self.pd.get_log(args.since_seq, args.limit as usize, filter))
    }

    /// Per-(direction, code) summary of the whole current ring.
    /// Returns counts only — no payloads — so the response stays
    /// small even when the log is full of heartbeat. Sorted by
    /// count desc so noisy codes surface first. Use this as a
    /// cheap "what's interesting in the log?" probe before
    /// committing to a full `get_log` page.
    #[tool(
        title = "Summarize Wire Log",
        description = "Return per-(direction, code) counts across the entire log ring. \
                       Cheap; payload-free. Useful for spotting noise (POLL/ACK at the top) \
                       and deciding which codes to focus on with get_log."
    )]
    fn get_log_summary(&self) -> Json<LogSummary> {
        Json(self.pd.get_log_summary())
    }

    /// Drop every entry currently in the log. `next_seq` keeps
    /// climbing so cursors from before the clear stay meaningful.
    #[tool(
        title = "Clear Wire Log",
        description = "Drop every entry currently in the log. Idempotent."
    )]
    fn clear_log(&self) -> String {
        self.pd.clear_log();
        "log cleared".to_string()
    }

    /// Raw byte-level wire trace — every TX/RX chunk the serial
    /// transport moved, with a microsecond timestamp and the full hex
    /// (SOM, control byte, SCB, integrity), cursor-paged via
    /// `since_seq`. This is the low-level companion to `get_log`:
    /// `get_log` shows decoded frames but drops POLL/ACK timing and the
    /// control byte; this shows neither-decoded-nor-filtered bytes so
    /// you can measure reply latency (last `rx` → next `tx` vs the
    /// ACU's firstByte window) and inspect on-wire framing (SQN,
    /// CRC-vs-checksum, SC vs plaintext). Typical use: `clear_wire_trace`
    /// → reproduce the fault → `get_wire_trace`.
    #[tool(
        title = "Get Raw Wire Trace",
        description = "Return up to `limit` raw serial chunks (seq >= since_seq), each with a \
                       microsecond timestamp `t_us`, direction (rx/tx), and full hex bytes \
                       incl. control + integrity. Use it to measure reply latency and inspect \
                       on-wire framing the decoded get_log can't show. `dropped` > 0 means older \
                       chunks scrolled off the ring."
    )]
    fn get_wire_trace(&self, Parameters(args): Parameters<WireTraceArgs>) -> Json<WirePage> {
        Json(self.pd.get_wire_trace(args.since_seq, args.limit as usize))
    }

    /// Drop every captured wire chunk. Pair with `get_wire_trace`:
    /// clear, reproduce the fault, then snapshot a clean window.
    #[tool(
        title = "Clear Raw Wire Trace",
        description = "Drop every captured raw wire chunk. Idempotent. Clear before reproducing \
                       a fault so the next get_wire_trace is a clean capture window."
    )]
    fn clear_wire_trace(&self) -> String {
        self.pd.clear_wire_trace();
        "wire trace cleared".to_string()
    }

    /// Block until a command with the given code arrives, or the
    /// timeout fires. Returns the matching log entry on success.
    #[tool(
        title = "Wait for Command",
        description = "Wait up to `timeout_ms` for an inbound command with `cmd_code`. Returns the matching log entry, or errors on timeout."
    )]
    async fn wait_for_command(
        &self,
        Parameters(args): Parameters<WaitForCommandArgs>,
    ) -> Result<Json<LogEntry>, String> {
        self.pd
            .wait_for_command(args.cmd_code, args.timeout_ms, args.since_seq)
            .await
            .map(Json)
    }

    /// Pin a fixed reply for `cmd_code`. The handler will return this
    /// for every matching command until you call `clear_overrides`
    /// or replace it with another set_reply_*.
    #[tool(
        title = "Set Static Reply Override",
        description = "Install a static reply override for a command code. Replies are repeated for every matching command until cleared."
    )]
    fn set_reply_for(
        &self,
        Parameters(args): Parameters<SetReplyForArgs>,
    ) -> Result<String, String> {
        let reply = args.reply.into_override()?;
        let code = args.cmd_code;
        let reply_code = reply.code;
        self.pd.set_reply_for(code, reply);
        Ok(format!(
            "static override installed: cmd 0x{:02X} -> reply 0x{:02X}",
            code, reply_code
        ))
    }

    /// Install a sequenced override. The first matching command gets
    /// `steps[0]`, the second `steps[1]`, etc. When the queue
    /// empties, behavior depends on `cycle`: false (default) falls
    /// back to the default handler; true wraps around forever.
    #[tool(
        title = "Set Scripted Reply Sequence",
        description = "Install a scripted reply sequence for a command code. cycle=false (default) consumes; cycle=true loops forever."
    )]
    fn set_reply_script(
        &self,
        Parameters(args): Parameters<SetReplyScriptArgs>,
    ) -> Result<String, String> {
        let n = args.steps.len();
        let steps: Result<Vec<_>, _> = args
            .steps
            .into_iter()
            .map(ReplyStep::into_override)
            .collect();
        let steps = steps?;
        self.pd.set_reply_script(args.cmd_code, steps, args.cycle);
        Ok(format!(
            "script override installed: cmd 0x{:02X}, {} step(s), cycle={}",
            args.cmd_code, n, args.cycle
        ))
    }

    /// One-shot: make the next command with `cmd_code` reply with
    /// NAK `nak_code`, then resume default behavior. Convenient for
    /// "make the ACU see a single NAK and verify it recovers".
    #[tool(
        title = "NAK Next Command",
        description = "Make the next inbound command with `cmd_code` reply with NAK `nak_code`, then resume default behavior."
    )]
    fn nak_next(&self, Parameters(args): Parameters<NakNextArgs>) -> String {
        self.pd.nak_next(args.cmd_code, args.nak_code);
        format!(
            "next cmd 0x{:02X} will reply NAK 0x{:02X}",
            args.cmd_code, args.nak_code
        )
    }

    /// Drop every installed override. Subsequent commands fall
    /// through to the default handler. Idempotent.
    #[tool(
        title = "Clear Reply Overrides",
        description = "Drop every installed reply override. Idempotent."
    )]
    fn clear_overrides(&self) -> String {
        self.pd.clear_overrides();
        "overrides cleared".to_string()
    }

    /// Queue a card-read event. Surfaces as RAW on the next POLL
    /// (in FIFO order with other queued events).
    #[tool(
        title = "Inject Card Read (RAW)",
        description = "Inject a card-read event. The PD will reply RAW on its next POLL with the supplied card data."
    )]
    fn inject_raw(&self, Parameters(args): Parameters<InjectRawArgs>) -> Result<String, String> {
        let bit_data = hex_decode(&args.data_hex)?;
        let expected = (args.bit_count as usize + 7) / 8;
        if bit_data.len() != expected {
            return Err(format!(
                "bit_count={} needs {} bytes of data_hex, got {}",
                args.bit_count,
                expected,
                bit_data.len()
            ));
        }
        let raw = Raw {
            reader_no: args.reader_no,
            format_code: args.format_code,
            bit_count: args.bit_count,
            bit_data: &bit_data,
        };
        let mut buf = vec![0u8; 4 + bit_data.len()];
        let n = raw
            .build(&mut buf)
            .map_err(|e| format!("RAW build failed: {e:?}"))?;
        buf.truncate(n);
        self.pd.enqueue_event(OverrideReply {
            code: OSDP_REPLY_RAW,
            payload: buf,
        });
        Ok(format!(
            "RAW queued: reader={}, format={}, bit_count={}, data_len={}",
            args.reader_no, args.format_code, args.bit_count, expected
        ))
    }

    /// Queue a keypad event. Surfaces as KEYPAD on the next POLL.
    #[tool(
        title = "Inject Keypad Entry",
        description = "Inject a keypad event. The PD will reply KEYPAD on its next POLL with the supplied ASCII digits."
    )]
    fn inject_keypad(
        &self,
        Parameters(args): Parameters<InjectKeypadArgs>,
    ) -> Result<String, String> {
        let digits = args.digits.as_bytes();
        if digits.len() > u8::MAX as usize {
            return Err(format!(
                "keypad digits limited to 255 bytes, got {}",
                digits.len()
            ));
        }
        let kp = Keypad {
            reader_no: args.reader_no,
            digits,
        };
        let mut buf = vec![0u8; 2 + digits.len()];
        let n = kp
            .build(&mut buf)
            .map_err(|e| format!("KEYPAD build failed: {e:?}"))?;
        buf.truncate(n);
        self.pd.enqueue_event(OverrideReply {
            code: OSDP_REPLY_KEYPAD,
            payload: buf,
        });
        Ok(format!(
            "KEYPAD queued: reader={}, digits={:?}",
            args.reader_no, args.digits
        ))
    }

    /// Queue a local-status event (tamper / power). Surfaces as
    /// LSTATR on the next POLL. Spec D.2.1 — the payload is two
    /// bytes: tamper_status (0/1), power_status (0/1).
    #[tool(
        title = "Inject Tamper / Power Status",
        description = "Inject a tamper/power state change. The PD will reply LSTATR on its next POLL with the supplied flags."
    )]
    fn inject_local_status(
        &self,
        Parameters(args): Parameters<InjectLocalStatusArgs>,
    ) -> Result<String, String> {
        // No typed builder in osdp-embedded for LSTATR; the payload
        // is simply [tamper, power], each 0 or 1 per spec D.2.1.
        if args.tamper > 1 || args.power > 1 {
            return Err(format!(
                "tamper and power must be 0 or 1, got tamper={}, power={}",
                args.tamper, args.power
            ));
        }
        self.pd.enqueue_event(OverrideReply {
            code: OSDP_REPLY_LSTATR,
            payload: vec![args.tamper, args.power],
        });
        Ok(format!(
            "LSTATR queued: tamper={}, power={}",
            args.tamper, args.power
        ))
    }

    /// Drop every queued event. The next POLL goes straight to
    /// override-or-ACK. Idempotent.
    #[tool(
        title = "Clear Queued Events",
        description = "Drop every queued PD-initiated event. Idempotent."
    )]
    fn clear_events(&self) -> String {
        self.pd.clear_events();
        "events cleared".to_string()
    }

    /// Make the PD silently swallow the next `n` replies. Each
    /// dropped reply still logs the inbound command so the agent
    /// can verify which got eaten. Exercises the ACU's offline-
    /// detection path; replaces any previous pending drop count.
    #[tool(
        title = "Drop Next N Replies",
        description = "Make the PD silently swallow the next `n` replies (tests the ACU's offline-detection path)."
    )]
    fn drop_next_n_replies(&self, Parameters(args): Parameters<DropNextNRepliesArgs>) -> String {
        self.pd.drop_next_n_replies(args.n);
        format!("PD will drop the next {} reply(ies)", args.n)
    }

    /// Tear down and rebuild the current PD with the same
    /// parameters (port, baud, address, SC config). The serial
    /// port briefly closes and reopens; the ACU sees the PD reset
    /// its SQN (and SC state, if enabled), which trips spec
    /// D.1.4 / 5.9 session-loss detection. Errors if no PD is
    /// currently configured.
    #[tool(
        title = "Force Session Loss",
        description = "Force a session-loss event by rebuilding the current PD. The ACU should re-handshake."
    )]
    async fn force_session_loss(&self) -> Result<String, String> {
        self.pd
            .force_session_loss()
            .await
            .map(|()| "PD reset; session loss forced on the ACU side".to_string())
            .map_err(|e| format!("force_session_loss failed: {}", e))
    }
}

// `tool_handler` fills in call_tool / list_tools / get_tool from the
// router; we supply `get_info` ourselves so the `initialize` response
// carries SERVER_INSTRUCTIONS, steering the client to call
// `pd_configure` before anything else.
#[tool_handler(router = Self::tool_router())]
impl ServerHandler for OsdpMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(SERVER_INSTRUCTIONS)
    }
}

// ---- Main ------------------------------------------------------------

/// Which transport the server should listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    /// MCP over stdio — the default. One client per process, exits
    /// when the client closes stdin. What every local MCP client
    /// (Claude Desktop, Claude Code, etc.) expects.
    Stdio,
    /// MCP over streamable HTTP — the modern remote transport. The
    /// server mounts at `/mcp` on the address given by `--bind` and
    /// stays up until Ctrl-C; any number of concurrent clients all
    /// share the one PD instance.
    Http,
}

/// Parsed CLI args. Tiny enough that hand-rolling beats pulling in clap.
struct Cli {
    crypto: Selector,
    transport: TransportKind,
    bind: SocketAddr,
}

/// Default bind address for `--transport http`. Loopback by design —
/// the user has to opt into a non-localhost address explicitly,
/// since this exposes the PD-control surface (script replies, inject
/// events, force session loss) to whoever can reach the port.
const DEFAULT_HTTP_BIND: &str = "127.0.0.1:8080";

fn parse_cli() -> Result<Cli, String> {
    let mut args = std::env::args().skip(1);
    let mut crypto: Option<Selector> = None;
    let mut transport: Option<TransportKind> = None;
    let mut bind: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--crypto" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--crypto requires a value".to_string())?;
                crypto = Some(v.parse()?);
            }
            "--transport" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--transport requires a value".to_string())?;
                transport = Some(match v.trim().to_ascii_lowercase().as_str() {
                    "stdio" => TransportKind::Stdio,
                    "http" | "streamable-http" => TransportKind::Http,
                    other => {
                        return Err(format!(
                            "unknown --transport {other:?}; expected stdio or http"
                        ))
                    }
                });
            }
            "--bind" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--bind requires a value".to_string())?;
                bind = Some(v);
            }
            "--help" | "-h" => {
                eprintln!(
                    "osdp-mcp — MCP server exposing an osdp-embedded PD\n\n\
                     Usage: osdp-mcp [--transport <stdio|http>] [--bind <addr>] [--crypto <backend>]\n\n\
                     Options:\n  \
                       --transport <kind>  MCP transport.\n                       \
                                         stdio (default): one client over stdin/stdout.\n                       \
                                         http: streamable-HTTP server mounted at /mcp.\n  \
                       --bind <addr>     Bind address for --transport http.\n                       \
                                         Default: {bind} (loopback).\n  \
                       --crypto <name>   AES backend to use for Secure Channel.\n                       \
                                         Available in this build: {available}\n                       \
                                         Default: {default}\n  \
                       --help, -h        Show this message and exit.\n\n\
                     Pre-configured PD (auto-start at launch, set via environment):\n  \
                       OSDP_MCP_PORT      Serial device, e.g. /dev/ttyUSB0. Set this to\n                       \
                                         auto-start the PD before any client connects.\n  \
                       OSDP_MCP_BAUD      Line rate (default 9600).\n  \
                       OSDP_MCP_ADDRESS   7-bit address, decimal or 0x-hex (default 0).\n  \
                       OSDP_MCP_SC_MODE   Secure Channel: none | install | scbk (default none).\n  \
                       OSDP_MCP_SCBK_HEX  32-hex-char SCBK, required when SC_MODE=scbk.\n",
                    bind = DEFAULT_HTTP_BIND,
                    available = Selector::available()
                        .into_iter()
                        .map(|s| s.name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    default = Selector::default_for_build()
                        .map(|s| s.name())
                        .unwrap_or("<none>"),
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let crypto = crypto.or_else(Selector::default_for_build).ok_or_else(|| {
        "no crypto backend compiled in; rebuild with `--features crypto-rustcrypto` \
         and/or `--features crypto-tiny-aes`"
            .to_string()
    })?;
    let transport = transport.unwrap_or(TransportKind::Stdio);
    let bind_str = bind.as_deref().unwrap_or(DEFAULT_HTTP_BIND);
    let bind: SocketAddr = bind_str
        .parse()
        .map_err(|e| format!("invalid --bind {bind_str:?}: {e}"))?;
    Ok(Cli {
        crypto,
        transport,
        bind,
    })
}

/// Pre-configured PD settings read from the environment at launch.
///
/// When `OSDP_MCP_PORT` is set, the server brings the PD up
/// automatically before accepting any client, so a connecting agent
/// finds it already running. The other vars fill in the remaining
/// `pd_configure` parameters; `pd_configure` can still reconfigure the
/// PD at runtime. With no `OSDP_MCP_PORT`, nothing auto-starts and the
/// behavior is unchanged (the agent must call `pd_configure`).
///
/// Env vars (all optional):
///   OSDP_MCP_PORT      serial device; presence triggers auto-start.
///   OSDP_MCP_BAUD      line rate (default 9600).
///   OSDP_MCP_ADDRESS   7-bit PD address, decimal or 0x-hex (default 0).
///   OSDP_MCP_SC_MODE   none | install | scbk (default none).
///   OSDP_MCP_SCBK_HEX  32-hex-char key, required when SC_MODE=scbk.
struct PdDefaults {
    port: Option<String>,
    baud: u32,
    address: u8,
    sc: Option<ScConfig>,
}

/// Read an env var, trim it, and treat empty/whitespace as unset — so
/// `OSDP_MCP_PORT=` (common in templated unit files) means "no default"
/// rather than an empty port name.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Parse a 7-bit PD address from a string, accepting decimal or a
/// `0x`-prefixed hex literal. Rejects the broadcast address 0x7F and
/// anything above it.
fn parse_pd_address(s: &str) -> Result<u8, String> {
    let t = s.trim();
    let val = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16)
    } else {
        t.parse::<u8>()
    }
    .map_err(|e| format!("OSDP_MCP_ADDRESS={s:?} is not a valid address: {e}"))?;
    if val > 0x7E {
        return Err(format!(
            "OSDP_MCP_ADDRESS={s:?} out of range; must be 0x00..0x7E (0x7F is broadcast)"
        ));
    }
    Ok(val)
}

/// Resolve the `OSDP_MCP_*` startup defaults. Malformed values
/// (bad baud, out-of-range address, unknown SC mode, missing/short
/// SCBK) fail here so the operator gets a clear error at boot rather
/// than a silently misconfigured PD.
fn parse_pd_defaults() -> Result<PdDefaults, String> {
    let port = env_nonempty("OSDP_MCP_PORT");
    let baud = match env_nonempty("OSDP_MCP_BAUD") {
        Some(v) => v
            .parse::<u32>()
            .map_err(|e| format!("OSDP_MCP_BAUD={v:?} is not a valid baud rate: {e}"))?,
        None => default_baud(),
    };
    let address = match env_nonempty("OSDP_MCP_ADDRESS") {
        Some(v) => parse_pd_address(&v)?,
        None => 0,
    };
    let sc = parse_sc_config(
        env_nonempty("OSDP_MCP_SC_MODE").as_deref(),
        env_nonempty("OSDP_MCP_SCBK_HEX").as_deref(),
    )
    .map_err(|e| format!("OSDP_MCP_SC_MODE/SCBK_HEX: {e}"))?;
    Ok(PdDefaults {
        port,
        baud,
        address,
        sc,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // On stdio the JSON-RPC framing owns stdout; we must keep stderr
    // for logs. On HTTP it's fine either way, but keeping the same
    // writer means the log output looks identical whichever transport
    // is in use.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = parse_cli().map_err(|e| {
        eprintln!("osdp-mcp: {e}\n(run with --help for usage)");
        anyhow::anyhow!(e)
    })?;

    // Malformed OSDP_MCP_* values are a config error — fail fast with a
    // clear message rather than booting a misconfigured PD.
    let defaults = parse_pd_defaults().map_err(|e| {
        eprintln!("osdp-mcp: {e}");
        anyhow::anyhow!(e)
    })?;

    let handler = OsdpMcp::new(cli.crypto)?;

    // Auto-start the PD from OSDP_MCP_* when a port was supplied, before
    // any client connects. A runtime failure here (e.g. the serial port
    // isn't present yet) is logged but non-fatal: the server stays up so
    // an agent can fix it and call pd_configure. A bad config would have
    // already failed in parse_pd_defaults above.
    if let Some(port) = defaults.port {
        let label = sc_label(&defaults.sc);
        match handler
            .pd
            .configure(port.clone(), defaults.baud, defaults.address, defaults.sc)
            .await
        {
            Ok(()) => tracing::info!(
                port = %port,
                baud = defaults.baud,
                address = format_args!("0x{:02X}", defaults.address),
                sc = label,
                "auto-started PD from OSDP_MCP_* environment"
            ),
            Err(e) => tracing::warn!(
                port = %port,
                error = %e,
                "auto-start from OSDP_MCP_* failed; PD not running — use pd_configure"
            ),
        }
    }

    match cli.transport {
        TransportKind::Stdio => run_stdio(handler, cli.crypto).await,
        TransportKind::Http => run_http(handler, cli.crypto, cli.bind).await,
    }
}

async fn run_stdio(handler: OsdpMcp, crypto: Selector) -> Result<()> {
    tracing::info!(
        crypto = crypto.name(),
        "osdp-mcp starting (stdio transport)"
    );

    // .inspect_err is Rust 1.76+; workspace MSRV is 1.70 so use map_err.
    let service = handler.serve(stdio()).await.map_err(|e| {
        tracing::error!(?e, "failed to start MCP service");
        e
    })?;

    service.waiting().await?;
    Ok(())
}

async fn run_http(handler: OsdpMcp, crypto: Selector, bind: SocketAddr) -> Result<()> {
    tracing::info!(
        crypto = crypto.name(),
        %bind,
        "osdp-mcp starting (streamable-HTTP transport at /mcp)"
    );

    // Cancellation token lets us cut in-flight SSE streams when the
    // process is asked to shut down (Ctrl-C). Without it, axum's
    // graceful shutdown would still wait for long-lived response
    // bodies (the MCP SSE side-channel) to drain on their own.
    let ct = tokio_util::sync::CancellationToken::new();
    let svc_ct = ct.child_token();

    // StreamableHttpService is a tower::Service. Per-session
    // semantics: the factory closure is called once per new MCP
    // client; we hand out a clone of the shared handler so every
    // session sees the same `Arc<PdHandle>` (one PD per process —
    // matches stdio).
    //
    // `StreamableHttpServerConfig` is `#[non_exhaustive]` so the
    // struct-expression form is blocked; assign the one field we
    // care about after default-construction instead.
    let mut svc_cfg = StreamableHttpServerConfig::default();
    svc_cfg.cancellation_token = svc_ct;
    let svc = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        svc_cfg,
    );

    let router = axum::Router::new().nest_service("/mcp", svc);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind {bind} failed: {e}"))?;
    tracing::info!(%bind, "osdp-mcp listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Ctrl-C received, shutting down");
            ct.cancel();
        })
        .await?;
    Ok(())
}
