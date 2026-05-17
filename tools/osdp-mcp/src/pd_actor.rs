// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Single-threaded actor that owns the [`osdp_embedded::pd::Pd`] and
//! its serial port.
//!
//! `Pd` is `!Send` by design (see `rust/osdp/src/lib.rs`). The MCP
//! tool handlers run on a Tokio reactor and are `Send + Sync` —
//! incompatible. We bridge that gap by pinning the PD to a dedicated
//! `std::thread`, exchanging commands with the async side via an
//! unbounded mpsc channel and one-shot reply channels.
//!
//! The actor thread runs forever (until the process exits). Inside
//! it, a PD is *optionally* configured — `pd_configure` starts one,
//! `pd_stop` tears it down. The thread loop ticks the current PD (if
//! any) and drains pending commands once per cycle.

use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use osdp_embedded::pd::Pd;
use tokio::sync::{mpsc, oneshot};

use crate::crypto::{BoxedSc, CryptoFactory};
use crate::events::{self, EventQueue};
use crate::handler::{DefaultHandler, PdStats};
use crate::log::{LogInner, LogPage, DEFAULT_CAPACITY};
use crate::overrides::{self, OverrideMap, OverrideReply};
use crate::serial_transport::SerialTransport;

/// Snapshot of the PD's current state, returned by `pd_status`.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct PdStatus {
    /// True when a PD is configured and ticking.
    pub running: bool,
    /// Serial port name the PD is bound to, e.g. "COM5".
    pub port: Option<String>,
    pub baud: Option<u32>,
    /// 7-bit PD address (0x00..0x7E). 0x7F (broadcast) is always
    /// accepted in addition to this one.
    pub address: Option<u8>,
    /// True iff the PD has sent at least one reply within the last
    /// 8 seconds (`osdp_pd_is_online`).
    pub is_online: bool,
    /// True iff the SCS_11..14 handshake completed (always false in
    /// milestone 2 — SC is wired up in milestone 5).
    pub sc_established: bool,
    /// Most recent command code accepted from the ACU, ms since the
    /// PD epoch (32-bit wrap is fine).
    pub last_command_at_ms: Option<u32>,
    pub last_reply_at_ms: Option<u32>,
    /// Most recent command and reply codes (for quick debugging
    /// without pulling the full log).
    pub last_cmd_code: Option<u8>,
    pub last_reply_code: Option<u8>,
    /// How many PD-initiated events are queued for the next POLLs
    /// (RAW / KEYPAD / LSTATR from inject_* tools).
    pub event_queue_depth: u32,
}

impl PdStatus {
    fn idle() -> Self {
        Self {
            running: false,
            port: None,
            baud: None,
            address: None,
            is_online: false,
            sc_established: false,
            last_command_at_ms: None,
            last_reply_at_ms: None,
            last_cmd_code: None,
            last_reply_code: None,
            event_queue_depth: 0,
        }
    }
}

/// Secure Channel configuration for a freshly-configured PD.
///
/// `None` means "no SC" — the PD will NAK any SCB-bearing frame
/// with code 0x05 (matches the C library's behavior when the
/// crypto vtable + keys are absent).
#[derive(Debug, Clone)]
pub enum ScConfig {
    /// Use the well-known install-time SCBK-D from the spec. The
    /// PD will accept handshakes initiated with the SCBK-D selector.
    Scbkd,
    /// Use a per-installation SCBK (custom 16-byte key). PD will
    /// accept handshakes with the SCBK selector.
    Scbk([u8; 16]),
}

/// Messages the MCP side sends to the actor. Every variant carries a
/// `oneshot::Sender` so the caller can await the result.
enum Cmd {
    Configure {
        port: String,
        baud: u32,
        address: u8,
        sc: Option<ScConfig>,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Stop {
        reply: oneshot::Sender<()>,
    },
    Status {
        reply: oneshot::Sender<PdStatus>,
    },
}

/// Handle the MCP service holds. Clone-able, Send + Sync — multiple
/// concurrent tool calls all funnel into one actor.
#[derive(Clone)]
pub struct PdHandle {
    tx: mpsc::UnboundedSender<Cmd>,
    /// Shared with the handler so reads (`get_log`, `wait_for_command`,
    /// `clear_log`) can bypass the actor channel for minimal latency.
    log: Arc<LogInner>,
    /// Shared with the handler. Writers (the override-related tools)
    /// modify it directly; the handler reads + consumes script steps
    /// inside `take_for`.
    overrides: OverrideMap,
    /// PD-initiated events queued for the next POLL (RAW / KEYPAD /
    /// LSTATR). The handler drains one per POLL when the override
    /// table misses; the inject_* tools enqueue.
    events: EventQueue,
    /// Kept alive so we can `join` on shutdown (currently unused;
    /// reserved for graceful stop in later milestones).
    _join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PdHandle {
    /// Spawn the actor thread with the given crypto factory. The
    /// factory is invoked once per `pd_configure` that enables SC,
    /// so each PD has its own fresh `ScCrypto` instance (and RNG
    /// state, if the backend keeps any).
    pub fn spawn(crypto_factory: CryptoFactory) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let log = Arc::new(LogInner::new(DEFAULT_CAPACITY));
        let overrides = overrides::new_map();
        let events = events::new_queue();
        let log_for_thread = Arc::clone(&log);
        let overrides_for_thread = Arc::clone(&overrides);
        let events_for_thread = Arc::clone(&events);
        let join = thread::Builder::new()
            .name("osdp-mcp-pd".into())
            .spawn(move || {
                actor_loop(
                    rx,
                    log_for_thread,
                    overrides_for_thread,
                    events_for_thread,
                    crypto_factory,
                )
            })
            .expect("spawn PD actor thread");
        Self {
            tx,
            log,
            overrides,
            events,
            _join: Arc::new(Mutex::new(Some(join))),
        }
    }

    pub async fn configure(
        &self,
        port: String,
        baud: u32,
        address: u8,
        sc: Option<ScConfig>,
    ) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Configure {
                port,
                baud,
                address,
                sc,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))?
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Stop { reply })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))?;
        Ok(())
    }

    pub async fn status(&self) -> anyhow::Result<PdStatus> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Status { reply })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))
    }

    /// Read up to `limit` log entries with `seq > since_seq`. Goes
    /// straight to the shared log — no actor round-trip.
    pub fn get_log(&self, since_seq: u64, limit: usize) -> LogPage {
        self.log.snapshot(since_seq, limit)
    }

    /// Drop every entry currently in the log. `next_seq` is
    /// preserved so any outstanding cursor stays meaningful.
    pub fn clear_log(&self) {
        self.log.clear();
    }

    /// Install a static reply override for `cmd_code` — every
    /// matching command gets the same canned reply until cleared or
    /// replaced.
    pub fn set_reply_for(&self, cmd_code: u8, reply: OverrideReply) {
        overrides::set_static(&self.overrides, cmd_code, reply);
    }

    /// Install a scripted sequence of replies for `cmd_code`.
    /// `cycle=true` loops forever; `cycle=false` falls back to the
    /// default handler once exhausted.
    pub fn set_reply_script(&self, cmd_code: u8, steps: Vec<OverrideReply>, cycle: bool) {
        overrides::set_script(&self.overrides, cmd_code, steps, cycle);
    }

    /// One-shot: make the next command with `cmd_code` reply with
    /// NAK `nak_code`, then resume default behavior.
    pub fn nak_next(&self, cmd_code: u8, nak_code: u8) {
        overrides::nak_next(&self.overrides, cmd_code, nak_code);
    }

    /// Drop every installed override.
    pub fn clear_overrides(&self) {
        overrides::clear(&self.overrides);
    }

    /// Queue a pre-baked reply to be emitted on the next POLL
    /// (after the override table misses). FIFO ordering — multiple
    /// inject_* calls drain across consecutive POLLs.
    pub fn enqueue_event(&self, ev: OverrideReply) {
        events::enqueue(&self.events, ev);
    }

    /// Current event-queue depth (how many POLLs it would take to
    /// drain). Exposed in `pd_status`.
    pub fn event_queue_depth(&self) -> usize {
        events::len(&self.events)
    }

    /// Drop every queued event. Subsequent POLLs go straight to
    /// override-or-ACK.
    pub fn clear_events(&self) {
        events::clear(&self.events);
    }

    /// Wait up to `timeout_ms` for a command with `cmd_code` to
    /// arrive (entries with `seq > since_seq`). Returns the matching
    /// entry on success, an error string on timeout.
    pub async fn wait_for_command(
        &self,
        cmd_code: u8,
        timeout_ms: u32,
        since_seq: u64,
    ) -> Result<crate::log::LogEntry, String> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);

        loop {
            // Register interest BEFORE checking — closes the window
            // where a notify could fire between the check and the
            // await and get missed.
            let notified = self.log.notify.notified();
            if let Some(entry) = self.log.find_command_at_or_after(since_seq, cmd_code) {
                return Ok(entry);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timeout: no cmd 0x{:02X} arrived within {} ms",
                    cmd_code, timeout_ms
                ));
            }
            // notify_waiters may have already fired — that's OK,
            // `notified` was registered before the check above, so
            // the next iteration will see the new entry.
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(format!(
                    "timeout: no cmd 0x{:02X} arrived within {} ms",
                    cmd_code, timeout_ms
                ));
            }
        }
    }
}

/// Runtime state held by the actor thread itself.
struct Slot {
    pd: Pd,
    port: String,
    baud: u32,
    address: u8,
    stats: Arc<Mutex<PdStats>>,
}

fn actor_loop(
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    log: Arc<LogInner>,
    overrides: OverrideMap,
    events: EventQueue,
    crypto_factory: CryptoFactory,
) {
    let mut slot: Option<Slot> = None;
    // Tick the PD ~1000 times/sec. OSDP timing tolerances are loose
    // (ms-scale) so this is plenty; sleeping yields the CPU.
    let tick_period = Duration::from_millis(1);

    loop {
        // Drain everything queued before ticking. try_recv on a tokio
        // channel works from a non-async context.
        loop {
            match rx.try_recv() {
                Ok(cmd) => handle_cmd(cmd, &mut slot, &log, &overrides, &events, &crypto_factory),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Service shut down — exit cleanly.
                    return;
                }
            }
        }

        if let Some(s) = slot.as_mut() {
            s.pd.tick();
        }

        thread::sleep(tick_period);
    }
}

fn handle_cmd(
    cmd: Cmd,
    slot: &mut Option<Slot>,
    log: &Arc<LogInner>,
    overrides: &OverrideMap,
    events: &EventQueue,
    crypto_factory: &CryptoFactory,
) {
    match cmd {
        Cmd::Configure {
            port,
            baud,
            address,
            sc,
            reply,
        } => {
            // Tear down any existing PD first; one slot per actor.
            *slot = None;
            let result = open_pd(
                &port,
                baud,
                address,
                Arc::clone(log),
                Arc::clone(overrides),
                Arc::clone(events),
                sc,
                crypto_factory,
            )
            .map(|s| {
                *slot = Some(s);
            });
            let _ = reply.send(result);
        }
        Cmd::Stop { reply } => {
            *slot = None;
            let _ = reply.send(());
        }
        Cmd::Status { reply } => {
            // Event queue depth is independent of whether a PD is
            // running — inject_* calls enqueue regardless, and the
            // queue persists across pd_stop / pd_configure cycles.
            let queue_depth = events::len(events) as u32;
            let status = match slot.as_ref() {
                None => PdStatus {
                    event_queue_depth: queue_depth,
                    ..PdStatus::idle()
                },
                Some(s) => {
                    let stats = s.stats.lock().map(|g| g.clone()).unwrap_or_default();
                    PdStatus {
                        running: true,
                        port: Some(s.port.clone()),
                        baud: Some(s.baud),
                        address: Some(s.address),
                        is_online: s.pd.is_online(),
                        sc_established: s.pd.sc_established(),
                        last_command_at_ms: stats.last_command_at_ms,
                        last_reply_at_ms: stats.last_reply_at_ms,
                        last_cmd_code: stats.last_cmd_code,
                        last_reply_code: stats.last_reply_code,
                        event_queue_depth: queue_depth,
                    }
                }
            };
            let _ = reply.send(status);
        }
    }
}

// Internal fan-in helper; takes one arg per shared resource it
// needs to wire into the freshly-minted Pd. Could be folded into a
// builder struct but every arg is distinct, so a plain function is
// clearer despite the count.
#[allow(clippy::too_many_arguments)]
fn open_pd(
    port: &str,
    baud: u32,
    address: u8,
    log: Arc<LogInner>,
    overrides: OverrideMap,
    events: EventQueue,
    sc: Option<ScConfig>,
    crypto_factory: &CryptoFactory,
) -> anyhow::Result<Slot> {
    let transport = SerialTransport::open(port, baud)?;
    let stats = Arc::new(Mutex::new(PdStats::default()));

    let mut pd = Pd::new(address);
    pd.set_transport(transport);
    pd.set_command_handler(DefaultHandler::new(
        Arc::clone(&stats),
        log,
        overrides,
        events,
        address,
    ));

    // Bind Secure Channel material if requested. The crypto factory
    // mints a fresh provider per PD so the AES + RNG state is
    // independent across configures. The cUID is derived from the
    // default PDID we report (spec D.4.3 — first 8 bytes of the PDID
    // byte stream: vendor[3] + model + version + serial[0..2]).
    let mut sc_mode_label = "none";
    if let Some(cfg) = sc {
        let crypto = crypto_factory();
        pd.set_sc_crypto(BoxedSc(crypto));
        let cuid = derive_cuid_from_default_pdid();
        pd.set_sc_cuid(&cuid);
        match cfg {
            ScConfig::Scbkd => {
                pd.set_sc_scbk_d(osdp_embedded::sc::scbk_default());
                sc_mode_label = "scbkd";
            }
            ScConfig::Scbk(key) => {
                pd.set_sc_scbk(&key);
                sc_mode_label = "scbk";
            }
        }
    }

    tracing::info!(
        port,
        baud,
        address = format!("0x{:02X}", address),
        sc = sc_mode_label,
        "PD configured"
    );
    Ok(Slot {
        pd,
        port: port.to_string(),
        baud,
        address,
        stats,
    })
}

/// Build the 8-byte cUID from the default PDID. Spec D.4.3:
/// `vendor[0..3] + model + version + serial[0..2]` (the first two
/// bytes of serial in transmission order — little-endian on the wire).
fn derive_cuid_from_default_pdid() -> [u8; 8] {
    let p = crate::handler::default_pdid();
    let serial_le = p.serial.to_le_bytes();
    [
        p.vendor_code[0],
        p.vendor_code[1],
        p.vendor_code[2],
        p.model,
        p.version,
        serial_le[0],
        serial_le[1],
        // Spec D.4.3 takes the first 8 bytes of the PDID byte stream.
        // After vendor[3] + model + version we have 2 bytes of serial
        // left to fill 8. Pad the 8th byte with serial[2] for
        // continuity with the wire layout.
        serial_le[2],
    ]
}
