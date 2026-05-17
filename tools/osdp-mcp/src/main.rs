// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! osdp-mcp — MCP server that drives an osdp-embedded PD against an
//! ACU under test.
//!
//! Milestone 2: PD actor + serial transport + lifecycle tools
//! (`pd_configure`, `pd_stop`, `pd_status`) plus the milestone-1
//! `ping` keep-alive. PDID / PDCAP defaults match `osdp-pd-mock` so
//! a freshly-configured PD behaves identically to the existing tool.

use std::sync::Arc;

use anyhow::Result;
use osdp_embedded::messages::{Keypad, Raw, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_RAW};
use osdp_mcp::crypto::Selector;
use osdp_mcp::log::{LogEntry, LogPage, DEFAULT_CAPACITY};
use osdp_mcp::overrides::OverrideReply;
use osdp_mcp::pd_actor::{PdHandle, PdStatus, ScConfig};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_router, Json, ServiceExt};
use tracing_subscriber::EnvFilter;

// ---- Tool parameter schemas ------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PingArgs {
    /// Echoed back verbatim. Optional.
    #[serde(default)]
    message: Option<String>,
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

fn parse_sc_config(args: &PdConfigureArgs) -> Result<Option<ScConfig>, String> {
    // Normalise to lowercase so "Install" / "SCBKD" etc. all work.
    let mode = args
        .sc_mode
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase());
    match mode.as_deref() {
        None | Some("") | Some("none") | Some("off") => Ok(None),
        // Install mode = SCBK-D (spec D.4 well-known default key).
        // Accept the colloquial term plus the spec-internal name and
        // a few common synonyms an agent might reach for.
        Some("install") | Some("scbkd") | Some("scbk-d") | Some("default") => {
            Ok(Some(ScConfig::Scbkd))
        }
        Some("scbk") | Some("operational") | Some("custom") => {
            let hex = args.scbk_hex.as_deref().unwrap_or("");
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetLogArgs {
    /// Skip entries with `seq <= since_seq`. Use the `next_seq` from
    /// a previous response to continue paging. Defaults to 0 (all).
    #[serde(default)]
    since_seq: u64,
    /// Cap the number of entries returned. Defaults to the ring
    /// capacity so a single call drains everything.
    #[serde(default = "default_log_limit")]
    limit: u32,
}

fn default_log_limit() -> u32 {
    DEFAULT_CAPACITY as u32
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

#[tool_router(server_handler)]
impl OsdpMcp {
    /// Liveness check. Returns a banner string; useful to confirm
    /// the server is up before issuing real tools.
    #[tool(description = "Liveness check. Returns a banner string.")]
    fn ping(&self, Parameters(args): Parameters<PingArgs>) -> String {
        match args.message {
            Some(m) => format!("osdp-mcp pong: {}", m),
            None => "osdp-mcp pong".to_string(),
        }
    }

    /// Bring up a PD on a serial port. Any previously-configured PD
    /// is torn down first. PDID and PDCAP currently default to the
    /// values osdp-pd-mock ships with (vendor ZBC, one of every
    /// basic capability) — per-message overrides land in a later
    /// milestone.
    #[tool(
        description = "Configure and start a PD on a serial port. Replaces any existing PD configuration."
    )]
    async fn pd_configure(
        &self,
        Parameters(args): Parameters<PdConfigureArgs>,
    ) -> Result<String, String> {
        let sc = parse_sc_config(&args)?;
        let sc_label = match &sc {
            None => "off".to_string(),
            Some(ScConfig::Scbkd) => "install (SCBK-D)".to_string(),
            Some(ScConfig::Scbk(_)) => "operational (SCBK)".to_string(),
        };
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
    #[tool(description = "Stop the current PD, if any. Idempotent.")]
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
        description = "Return a JSON snapshot of the PD's state (running, online, SC, last cmd/reply)."
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
    #[tool(
        description = "Return up to `limit` log entries with seq > since_seq. Includes the cursor for the next call."
    )]
    fn get_log(&self, Parameters(args): Parameters<GetLogArgs>) -> Json<LogPage> {
        Json(self.pd.get_log(args.since_seq, args.limit as usize))
    }

    /// Drop every entry currently in the log. `next_seq` keeps
    /// climbing so cursors from before the clear stay meaningful.
    #[tool(description = "Drop every entry currently in the log. Idempotent.")]
    fn clear_log(&self) -> String {
        self.pd.clear_log();
        "log cleared".to_string()
    }

    /// Block until a command with the given code arrives, or the
    /// timeout fires. Returns the matching log entry on success.
    #[tool(
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
    #[tool(description = "Drop every installed reply override. Idempotent.")]
    fn clear_overrides(&self) -> String {
        self.pd.clear_overrides();
        "overrides cleared".to_string()
    }

    /// Queue a card-read event. Surfaces as RAW on the next POLL
    /// (in FIFO order with other queued events).
    #[tool(
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
    #[tool(description = "Drop every queued PD-initiated event. Idempotent.")]
    fn clear_events(&self) -> String {
        self.pd.clear_events();
        "events cleared".to_string()
    }

    /// Make the PD silently swallow the next `n` replies. Each
    /// dropped reply still logs the inbound command so the agent
    /// can verify which got eaten. Exercises the ACU's offline-
    /// detection path; replaces any previous pending drop count.
    #[tool(
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

// ---- Main ------------------------------------------------------------

/// Parsed CLI args. Tiny enough that hand-rolling beats pulling in clap.
struct Cli {
    crypto: Selector,
}

fn parse_cli() -> Result<Cli, String> {
    let mut args = std::env::args().skip(1);
    let mut crypto: Option<Selector> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--crypto" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--crypto requires a value".to_string())?;
                crypto = Some(v.parse()?);
            }
            "--help" | "-h" => {
                eprintln!(
                    "osdp-mcp — MCP server exposing an osdp-embedded PD\n\n\
                     Usage: osdp-mcp [--crypto <backend>]\n\n\
                     Options:\n  \
                       --crypto <name>   AES backend to use for Secure Channel.\n                       \
                                       Available in this build: {available}\n                       \
                                       Default: {default}\n  \
                       --help, -h        Show this message and exit.\n",
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
    Ok(Cli { crypto })
}

#[tokio::main]
async fn main() -> Result<()> {
    // CRITICAL: MCP uses stdout for JSON-RPC framing; logs MUST go to
    // stderr or the client will choke on interleaved bytes.
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

    tracing::info!(
        crypto = cli.crypto.name(),
        "osdp-mcp starting (stdio transport)"
    );

    // .inspect_err is Rust 1.76+; workspace MSRV is 1.70 so use map_err.
    let service = OsdpMcp::new(cli.crypto)?
        .serve(stdio())
        .await
        .map_err(|e| {
            tracing::error!(?e, "failed to start MCP service");
            e
        })?;

    service.waiting().await?;
    Ok(())
}
