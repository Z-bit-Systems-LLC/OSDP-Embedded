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
use osdp_embedded::messages::{
    Keypad, Pdcap, PdcapRecord, Pdid, Raw, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_RAW,
};
use osdp_mcp::crypto::Selector;
use osdp_mcp::log::{LogEntry, LogFilter, LogPage, LogSummary, DEFAULT_CAPACITY};
use osdp_mcp::overrides::OverrideReply;
use osdp_mcp::pd_actor::{PdHandle, PdStatus, ScConfig, StartupConfig};
use osdp_mcp::pdcap_spec;
use osdp_mcp::reader_state::ReaderStateView;
use osdp_mcp::ui;
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

/// The PD identity reported in the `osdp_PDID` (0x45) reply, returned
/// by `pd_get_pdid` / `pd_set_pdid`.
#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct PdidView {
    /// IEEE OUI (3 bytes) as 6 uppercase hex chars, transmission order
    /// (e.g. "5A4243" for the ASCII vendor tag "ZBC").
    vendor_code_hex: String,
    /// Manufacturer-defined model number.
    model: u8,
    /// Manufacturer-defined version.
    version: u8,
    /// 32-bit device serial number.
    serial: u32,
    /// Firmware version as "major.minor.build" (convenience view of the
    /// three fields below).
    firmware: String,
    firmware_major: u8,
    firmware_minor: u8,
    firmware_build: u8,
}

impl From<Pdid> for PdidView {
    fn from(p: Pdid) -> Self {
        Self {
            vendor_code_hex: format!(
                "{:02X}{:02X}{:02X}",
                p.vendor_code[0], p.vendor_code[1], p.vendor_code[2]
            ),
            model: p.model,
            version: p.version,
            serial: p.serial,
            firmware: format!(
                "{}.{}.{}",
                p.firmware_major, p.firmware_minor, p.firmware_build
            ),
            firmware_major: p.firmware_major,
            firmware_minor: p.firmware_minor,
            firmware_build: p.firmware_build,
        }
    }
}

/// Partial-update args for `pd_set_pdid`. Every field is optional; only
/// the ones supplied are changed, the rest keep their current value.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PdSetPdidArgs {
    /// IEEE OUI (3 bytes) as 6 hex chars, transmission order (e.g.
    /// "5A4243"). Omit to leave the vendor code unchanged.
    #[serde(default)]
    vendor_code_hex: Option<String>,
    /// Manufacturer-defined model number.
    #[serde(default)]
    model: Option<u8>,
    /// Manufacturer-defined version.
    #[serde(default)]
    version: Option<u8>,
    /// 32-bit device serial number.
    #[serde(default)]
    serial: Option<u32>,
    #[serde(default)]
    firmware_major: Option<u8>,
    #[serde(default)]
    firmware_minor: Option<u8>,
    #[serde(default)]
    firmware_build: Option<u8>,
}

/// One capability record as seen through `pd_get_pdcap` /
/// `pd_set_capability` — the three wire bytes plus the spec
/// interpretation of each, so an agent reading the view understands what
/// every value means without consulting Annex B.
#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct PdcapRecordView {
    /// OSDP function code (spec Annex B), e.g. 4 = Reader LED Control.
    function_code: u8,
    /// Human name of the function code, or "unknown function code".
    function_name: String,
    /// Compliance-level byte as sent on the wire.
    compliance_level: u8,
    /// What `compliance_level` means for this function code.
    compliance_meaning: String,
    /// "Number of objects" byte as sent on the wire.
    num_objects: u8,
    /// What `num_objects` means for this function code (a count, a
    /// bitmap, the MSB of a size, or "must be 0x00").
    num_objects_meaning: String,
}

impl From<&PdcapRecord> for PdcapRecordView {
    fn from(r: &PdcapRecord) -> Self {
        let (function_name, compliance_meaning, num_objects_meaning) =
            pdcap_spec::interpret(r.function_code, r.compliance_level, r.num_objects);
        Self {
            function_code: r.function_code,
            function_name,
            compliance_level: r.compliance_level,
            compliance_meaning,
            num_objects: r.num_objects,
            num_objects_meaning,
        }
    }
}

/// The capability set reported in `osdp_PDCAP` (0x46), returned by the
/// `pd_get_pdcap` / `pd_set_capability` / `pd_reset_pdcap` tools.
#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct PdcapView {
    /// Capability records, in the order they are sent on the wire.
    records: Vec<PdcapRecordView>,
}

impl From<&Pdcap> for PdcapView {
    fn from(p: &Pdcap) -> Self {
        Self {
            records: p.records.iter().map(PdcapRecordView::from).collect(),
        }
    }
}

/// Args for `pd_set_capability` — upsert or remove a single capability
/// record, keyed by function code.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PdSetCapabilityArgs {
    /// OSDP function code to edit (spec Annex B, 1..=17). Examples:
    /// 1 = Contact Status Monitoring, 2 = Output Control,
    /// 4 = Reader LED Control, 5 = Reader Audible Output,
    /// 6 = Reader Text Output, 8 = Check Character Support,
    /// 9 = Communication Security, 16 = OSDP Version.
    function_code: u8,
    /// Compliance level for this function code. Required unless
    /// `remove` is true. Meaning is function-code-specific — see the
    /// error message or `pd_get_pdcap` for valid values.
    #[serde(default)]
    compliance_level: Option<u8>,
    /// "Number of objects" byte. Optional; defaults to 0 when adding a
    /// new record. Meaning is function-code-specific (a count, a
    /// bitmap, the MSB of a size, or required-zero).
    #[serde(default)]
    num_objects: Option<u8>,
    /// When true, remove the record for `function_code` instead of
    /// adding/updating it. `compliance_level` / `num_objects` are then
    /// ignored.
    #[serde(default)]
    remove: bool,
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

Lifecycle: `pd_stop` tears the PD down but the actor remembers its \
configuration; `pd_start` (no arguments) brings it back up with the same \
port/baud/address/SC key. The OSDP_MCP_* startup values seed that \
remembered config, so `pd_start` works for an env-auto-started PD too. \
Use `pd_start` after a `pd_stop` instead of re-issuing `pd_configure` — \
you don't have to re-supply the SCBK (which `pd_status` never exposes). \
`pd_configure` is for the first start or to change settings.

`pd_configure` parameters:
  - port (required): serial device, e.g. \"/dev/ttyUSB0\", \"/dev/serial0\", or \"COM5\".
  - baud (default 9600): line rate; must match the ACU.
  - address (default 0): 7-bit PD address 0x00..0x7E; must match what the ACU polls.
  - sc_mode (default \"none\"): Secure Channel mode —
      \"none\"    : SC disabled.
      \"install\" : accept handshakes with the spec's well-known SCBK-D key (first-time keying / dev).
      \"scbk\"    : operational per-installation key — also pass scbk_hex (32 hex chars / 16 bytes).

Identity & capabilities: `pd_get_pdid` / `pd_set_pdid` read and edit the device \
identity reported in the osdp_ID reply; `pd_get_pdcap` / `pd_set_capability` / \
`pd_reset_pdcap` read and edit the capability set reported in the osdp_CAP reply. \
Capability edits are validated against OSDP v2.2.2 Annex B and the get-view \
annotates every byte with its spec meaning. Both the identity and the capability \
set persist across `pd_stop` / `pd_configure`.

If you are unsure of port/baud/address, ask the user before calling pd_configure \
rather than guessing. After configuring, use `pd_status` to confirm the PD is \
running and online, then `get_log` to watch ACU traffic.";

#[derive(Clone)]
struct OsdpMcp {
    pd: Arc<PdHandle>,
}

impl OsdpMcp {
    fn new(crypto: Selector, startup: Option<StartupConfig>) -> anyhow::Result<Self> {
        let factory = crypto.factory().map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            pd: Arc::new(PdHandle::spawn(factory, startup)),
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

    /// Restart a stopped PD using the configuration remembered from
    /// the last `pd_configure`. The remembered config (port, baud,
    /// address, and SC key) survives a `pd_stop`, so this brings the
    /// PD back without re-supplying it — in particular the SCBK, which
    /// `pd_status` never exposes.
    #[tool(
        title = "Start PD",
        description = "Restart a stopped PD using the configuration from the last \
                       pd_configure. No arguments. Errors if the PD was never configured \
                       this session, or if it is already running (stop it first, or use \
                       pd_configure to change settings)."
    )]
    async fn pd_start(&self) -> Result<String, String> {
        self.pd
            .start()
            .await
            .map_err(|e| format!("pd_start failed: {}", e))?;
        // Report what came back up. status() is cheap and gives the
        // caller the same confirmation pd_configure does.
        let s = self
            .pd
            .status()
            .await
            .map_err(|e| format!("pd_start: started, but status read failed: {}", e))?;
        Ok(format!(
            "PD started on {} @ {}bps addr=0x{:02X} sc={:?}",
            s.port.as_deref().unwrap_or("?"),
            s.baud.unwrap_or(0),
            s.address.unwrap_or(0),
            s.sc_mode
        ))
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

    /// Snapshot the virtual reader's current output state — today, the
    /// colour of each LED the ACU has driven via `osdp_LED`. The PD
    /// decodes LED commands transparently (temporary vs permanent, the
    /// temporary countdown timer, and flash phase) and this is the
    /// resolved "what is the reader showing right now" view, suitable for
    /// a visual display polled alongside the MCP server.
    #[tool(
        title = "Get Reader State",
        description = "Return the virtual reader's current output state: the resolved colour \
                       of each LED the ACU has driven via osdp_LED (reader_no, led_no, color \
                       code 0..7, and a colour name). Empty until the ACU sends an LED command. \
                       Reflects temporary/permanent overrides, timers, and flashing."
    )]
    fn pd_reader_state(&self) -> Json<ReaderStateView> {
        Json(self.pd.reader_state())
    }

    /// Read the PD identity reported in the `osdp_ID` reply (`osdp_PDID`,
    /// 0x45). Independent of whether a PD is running — the identity is
    /// process state that persists across `pd_stop` / `pd_configure`.
    #[tool(
        title = "Get PDID",
        description = "Return the PD identity reported in the osdp_PDID (0x45) reply: \
                       vendor code (hex), model, version, serial, and firmware version. \
                       Edit it with pd_set_pdid."
    )]
    fn pd_get_pdid(&self) -> Json<PdidView> {
        Json(self.pd.get_pdid().into())
    }

    /// Update the PD identity reported in the `osdp_ID` reply. Partial:
    /// only the fields you pass change; the rest keep their current
    /// value. Takes effect on the next `osdp_ID` command. The new
    /// identity also feeds the SC cUID derived at the *next* handshake —
    /// an already-established SC session keeps its current cUID until it
    /// re-handshakes (reconfigure to force that). Persists across
    /// `pd_stop` / `pd_configure`.
    #[tool(
        title = "Set PDID",
        description = "Update the PD identity reported in osdp_PDID (0x45). Partial update: \
                       pass only the fields to change (vendor_code_hex = 6 hex chars / 3 bytes, \
                       model, version, serial, firmware_major/minor/build). Returns the resulting \
                       identity. Affects the next osdp_ID reply and the next SC handshake's cUID."
    )]
    fn pd_set_pdid(
        &self,
        Parameters(args): Parameters<PdSetPdidArgs>,
    ) -> Result<Json<PdidView>, String> {
        let mut pdid = self.pd.get_pdid();
        if let Some(hex) = args.vendor_code_hex.as_deref() {
            let bytes = hex_decode(hex)?;
            if bytes.len() != 3 {
                return Err(format!(
                    "vendor_code_hex must be 6 hex chars (3 bytes); got {} byte(s)",
                    bytes.len()
                ));
            }
            pdid.vendor_code = [bytes[0], bytes[1], bytes[2]];
        }
        if let Some(v) = args.model {
            pdid.model = v;
        }
        if let Some(v) = args.version {
            pdid.version = v;
        }
        if let Some(v) = args.serial {
            pdid.serial = v;
        }
        if let Some(v) = args.firmware_major {
            pdid.firmware_major = v;
        }
        if let Some(v) = args.firmware_minor {
            pdid.firmware_minor = v;
        }
        if let Some(v) = args.firmware_build {
            pdid.firmware_build = v;
        }
        self.pd.set_pdid(pdid);
        Ok(Json(pdid.into()))
    }

    /// Read the capability set reported in the `osdp_CAP` reply
    /// (`osdp_PDCAP`, 0x46). Each record is annotated with the spec
    /// (Annex B) meaning of its function code and both data bytes, so
    /// you can see what the PD advertises without consulting the spec.
    /// Independent of whether a PD is running — the capability set is
    /// process state that persists across `pd_stop` / `pd_configure`.
    #[tool(
        title = "Get PDCAP",
        description = "Return the capability set reported in the osdp_PDCAP (0x46) reply: \
                       one record per function code (Annex B), each annotated with its name and \
                       the meaning of its compliance-level and number-of-objects bytes. \
                       Edit it with pd_set_capability or restore defaults with pd_reset_pdcap."
    )]
    fn pd_get_pdcap(&self) -> Json<PdcapView> {
        Json((&self.pd.get_pdcap()).into())
    }

    /// Add, update, or remove a single capability record, keyed by
    /// function code. Adds/updates are validated against OSDP v2.2.2
    /// Annex B — an out-of-range compliance level, a non-zero
    /// "number of objects" where the spec requires zero, reserved
    /// bitmap bits, or an unknown function code are all rejected with a
    /// message listing the valid values. Takes effect on the next
    /// `osdp_CAP` command and persists across `pd_stop` /
    /// `pd_configure`.
    #[tool(
        title = "Set Capability",
        description = "Add/update or remove one osdp_PDCAP capability record by function code \
                       (spec Annex B, 1..=17). Pass compliance_level (required to add/update) and \
                       optionally num_objects; or remove=true to delete the record. The record is \
                       validated against the spec (valid compliance levels, required-zero fields, \
                       bitmap masks) and rejected with the allowed values on a violation. Returns \
                       the full resulting capability set."
    )]
    fn pd_set_capability(
        &self,
        Parameters(args): Parameters<PdSetCapabilityArgs>,
    ) -> Result<Json<PdcapView>, String> {
        let mut pdcap = self.pd.get_pdcap();

        if args.remove {
            let before = pdcap.records.len();
            pdcap
                .records
                .retain(|r| r.function_code != args.function_code);
            if pdcap.records.len() == before {
                return Err(format!(
                    "no capability record with function code {} to remove",
                    args.function_code
                ));
            }
            self.pd.set_pdcap(pdcap.clone());
            return Ok(Json((&pdcap).into()));
        }

        // Add/update path. compliance_level is required; num_objects
        // defaults to 0 (the most common required value, and a safe
        // default for count/bitmap fields).
        let compliance_level = args.compliance_level.ok_or_else(|| {
            "compliance_level is required when adding or updating a capability \
             (pass remove=true to delete instead)"
                .to_string()
        })?;
        // Reuse the existing num_objects when updating and the caller
        // didn't supply one; otherwise default to 0.
        let existing_num = pdcap
            .records
            .iter()
            .find(|r| r.function_code == args.function_code)
            .map(|r| r.num_objects);
        let num_objects = args.num_objects.or(existing_num).unwrap_or(0);

        // Validate against the spec before mutating anything.
        pdcap_spec::validate_record(args.function_code, compliance_level, num_objects)?;

        let record = PdcapRecord {
            function_code: args.function_code,
            compliance_level,
            num_objects,
        };
        match pdcap
            .records
            .iter_mut()
            .find(|r| r.function_code == args.function_code)
        {
            Some(existing) => *existing = record,
            None => pdcap.records.push(record),
        }
        self.pd.set_pdcap(pdcap.clone());
        Ok(Json((&pdcap).into()))
    }

    /// Restore the capability set to the built-in default (the same
    /// spec-conformant set a freshly-configured PD reports). Useful to
    /// undo experimentation. Returns the restored set.
    #[tool(
        title = "Reset PDCAP",
        description = "Restore the osdp_PDCAP capability set to the built-in default \
                       (vendor reference set, spec-conformant). Returns the restored set."
    )]
    fn pd_reset_pdcap(&self) -> Json<PdcapView> {
        let pdcap = osdp_mcp::handler::default_pdcap();
        self.pd.set_pdcap(pdcap.clone());
        Json((&pdcap).into())
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
    /// Address for the browser reader-visual server, if enabled. `None`
    /// (the default) leaves the UI off entirely. Set via `--ui-bind` or
    /// `OSDP_MCP_UI_BIND`; spawned regardless of which MCP transport runs.
    ui_bind: Option<SocketAddr>,
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
    let mut ui_bind: Option<String> = None;
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
            "--ui-bind" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--ui-bind requires a value".to_string())?;
                ui_bind = Some(v);
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
                       --ui-bind <addr>  Enable the browser reader-visual server on <addr>\n                       \
                                         (e.g. 127.0.0.1:8088). Off by default; serves a\n                       \
                                         live LED view at GET / and JSON at GET /api/state,\n                       \
                                         alongside either MCP transport.\n  \
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
                       OSDP_MCP_SCBK_HEX  32-hex-char SCBK, required when SC_MODE=scbk.\n  \
                       OSDP_MCP_UI_BIND   Enable the reader-visual server on this address\n                       \
                                         (same as --ui-bind; the flag wins if both are set).\n",
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

    // The reader UI is off unless an address is supplied. A `--ui-bind`
    // flag wins; otherwise fall back to OSDP_MCP_UI_BIND so an operator
    // can enable it from a unit file. Either way the value must parse as a
    // socket address.
    let ui_bind = ui_bind.or_else(|| env_nonempty("OSDP_MCP_UI_BIND"));
    let ui_bind: Option<SocketAddr> = match ui_bind {
        Some(s) => Some(
            s.parse()
                .map_err(|e| format!("invalid reader UI bind {s:?}: {e}"))?,
        ),
        None => None,
    };

    Ok(Cli {
        crypto,
        transport,
        bind,
        ui_bind,
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

    // Seed the actor with the startup posture so `pd_start` can bring
    // the PD up from the OSDP_MCP_* values regardless of whether the
    // boot-time auto-start below succeeds. Only meaningful when a port
    // was supplied — without one there's nothing to start.
    let startup = defaults.port.as_ref().map(|port| StartupConfig {
        port: port.clone(),
        baud: defaults.baud,
        address: defaults.address,
        sc: defaults.sc.clone(),
    });
    let handler = OsdpMcp::new(cli.crypto, startup)?;

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

    // Spin up the browser reader-visual server if enabled. It's
    // independent of the MCP transport — shares the one PdHandle, reads
    // the live reader state — so it runs the same way under stdio or HTTP.
    // A bind failure is logged but non-fatal: the MCP server still serves.
    if let Some(ui_addr) = cli.ui_bind {
        let ui_pd = Arc::clone(&handler.pd);
        tracing::info!(%ui_addr, "reader UI enabled at http://{ui_addr}/");
        tokio::spawn(async move {
            if let Err(e) = ui::serve(ui_pd, ui_addr).await {
                tracing::error!(%ui_addr, error = %e, "reader UI server stopped");
            }
        });
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
