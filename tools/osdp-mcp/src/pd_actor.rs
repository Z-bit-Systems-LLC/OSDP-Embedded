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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use osdp_embedded::messages::{Pdcap, Pdid};
use osdp_embedded::pd::Pd;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::crypto::{BoxedSc, CryptoFactory};
use crate::events::{self, EventQueue};
use crate::handler::{DefaultHandler, DropCounter, PdStats, SharedPdcap, SharedPdid};
use crate::log::{EffectiveFilter, LogInner, LogPage, LogSummary, DEFAULT_CAPACITY};
use crate::overrides::{self, OverrideMap, OverrideReply};
use crate::reader_state::{self, ReaderLedHandler, ReaderStateView, SharedReaderState};
use crate::serial_transport::SerialTransport;
use crate::wire::{WirePage, WireTrace, DEFAULT_WIRE_CAPACITY};

/// How long after the most recent inbound command the link still
/// counts as "actively polled". OSDP ACUs poll on a sub-second
/// cadence, so a 2 s window catches a stalled poll loop promptly
/// while tolerating a slow ACU. Independent of the C library's
/// (reply-based) ~8 s online window — see [`PdStatus::actively_polling`].
const POLLING_WINDOW_MS: u32 = 2_000;

/// Configured Secure Channel posture of a running PD — the answer to
/// "is this link clear text, install-keyed, or operationally keyed?".
/// Reflects how the PD was configured (which key it will handshake
/// with), independent of whether a handshake has actually completed
/// yet (that's [`PdStatus::sc_established`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScMode {
    /// No Secure Channel — the link is clear text. The PD NAKs any
    /// SCB-bearing frame.
    None,
    /// Install mode: the PD accepts handshakes with the spec's
    /// well-known default key (SCBK-D, D.4). First-time keying / dev.
    Install,
    /// Operational mode: the PD uses a per-installation 16-byte SCBK.
    Scbk,
}

impl ScMode {
    fn from_cfg(sc: &Option<ScConfig>) -> Self {
        match sc {
            None => ScMode::None,
            Some(ScConfig::Scbkd) => ScMode::Install,
            Some(ScConfig::Scbk(_)) => ScMode::Scbk,
        }
    }
}

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
    /// 8 seconds (`osdp_pd_is_online`). Reply-based: if replies are
    /// being dropped (`drop_next_n_replies`) this trends false even
    /// while the ACU keeps polling — compare `actively_polling`.
    pub is_online: bool,
    /// True iff the ACU is actively polling: a command (POLL or any
    /// other) arrived within the last [`POLLING_WINDOW_MS`]. Unlike
    /// `is_online` this is command-based, so it stays true through a
    /// reply-drop fault while `is_online` decays.
    pub actively_polling: bool,
    /// Configured Secure Channel posture — clear text (`none`),
    /// install-keyed (`install`, SCBK-D), or operationally keyed
    /// (`scbk`). Answers "which key is this PD using" regardless of
    /// handshake state.
    pub sc_mode: ScMode,
    /// True iff the SCS_11..14 handshake has completed and the PD is
    /// handling SCS_15..18 operational traffic. With `sc_mode` this
    /// separates "keyed for SC" from "SC actually up right now".
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
    /// How many upcoming replies the handler will swallow silently
    /// (set via `drop_next_n_replies`).
    pub drop_remaining: u32,
}

impl PdStatus {
    fn idle() -> Self {
        Self {
            running: false,
            port: None,
            baud: None,
            address: None,
            is_online: false,
            actively_polling: false,
            sc_mode: ScMode::None,
            sc_established: false,
            last_command_at_ms: None,
            last_reply_at_ms: None,
            last_cmd_code: None,
            last_reply_code: None,
            event_queue_depth: 0,
            drop_remaining: 0,
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
    /// Bring the PD back up using the configuration remembered from the
    /// last `Configure` (which survives a `Stop`). Errors if the PD has
    /// never been configured this process, or if it is already running.
    Start {
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Status {
        reply: oneshot::Sender<PdStatus>,
    },
    /// Tear down and rebuild the current PD with the same parameters
    /// (port, baud, address, SC config). The serial port briefly
    /// closes and reopens; the ACU sees the PD reset its SC state
    /// and SQN, which trips the spec D.1.4 / 5.9 session-loss path.
    /// Errors if no PD is currently configured.
    ForceSessionLoss {
        reply: oneshot::Sender<anyhow::Result<()>>,
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
    /// Shared with the serial transport. Captures raw TX/RX bytes +
    /// microsecond timestamps for `get_wire_trace`; bypasses the actor
    /// channel just like `log`.
    wire: Arc<WireTrace>,
    /// Shared with the handler. Writers (the override-related tools)
    /// modify it directly; the handler reads + consumes script steps
    /// inside `take_for`.
    overrides: OverrideMap,
    /// PD-initiated events queued for the next POLL (RAW / KEYPAD /
    /// LSTATR). The handler drains one per POLL when the override
    /// table misses; the inject_* tools enqueue.
    events: EventQueue,
    /// Atomic count of upcoming replies the handler should silently
    /// swallow. `drop_next_n_replies` writes this; the handler
    /// decrements once per dropped reply.
    drop_remaining: DropCounter,
    /// The PD identity reported in `osdp_PDID`. Shared with the handler
    /// so `get_pdid` / `set_pdid` can read and mutate it live. Created
    /// once at spawn, so edits persist across `configure` / `stop`.
    pdid: SharedPdid,
    /// The capability set reported in `osdp_PDCAP`. Shared with the
    /// handler so `get_pdcap` / `set_pdcap` can read and mutate it live.
    /// Created once at spawn, so edits persist across `configure` /
    /// `stop`.
    pdcap: SharedPdcap,
    /// Observed reader output state (LED colours), updated on the actor
    /// thread by the PD's LED change callback and read by the
    /// `pd_reader_state` tool. Created once at spawn; cleared whenever a
    /// PD is (re)opened so a fresh reader starts blank.
    reader_state: SharedReaderState,
    /// Kept alive so we can `join` on shutdown (currently unused;
    /// reserved for graceful stop in later milestones).
    _join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PdHandle {
    /// Spawn the actor thread with the given crypto factory. The
    /// factory is invoked once per `pd_configure` that enables SC,
    /// so each PD has its own fresh `ScCrypto` instance (and RNG
    /// state, if the backend keeps any).
    ///
    /// `startup` carries the operator's `OSDP_MCP_*` values (if any).
    /// It seeds the actor's remembered config so `pd_start` can bring
    /// the PD up from the startup posture even before — and regardless
    /// of whether — the boot-time auto-start ran.
    pub fn spawn(crypto_factory: CryptoFactory, startup: Option<StartupConfig>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let log = Arc::new(LogInner::new(DEFAULT_CAPACITY));
        let wire = Arc::new(WireTrace::new(DEFAULT_WIRE_CAPACITY));
        let overrides = overrides::new_map();
        let events = events::new_queue();
        let drop_remaining: DropCounter = Arc::new(AtomicU32::new(0));
        let pdid: SharedPdid = Arc::new(Mutex::new(crate::handler::default_pdid()));
        let pdcap: SharedPdcap = Arc::new(Mutex::new(crate::handler::default_pdcap()));
        let reader_state = reader_state::new_shared();
        let log_for_thread = Arc::clone(&log);
        let wire_for_thread = Arc::clone(&wire);
        let overrides_for_thread = Arc::clone(&overrides);
        let events_for_thread = Arc::clone(&events);
        let drop_for_thread = Arc::clone(&drop_remaining);
        let pdid_for_thread = Arc::clone(&pdid);
        let pdcap_for_thread = Arc::clone(&pdcap);
        let reader_state_for_thread = Arc::clone(&reader_state);
        let join = thread::Builder::new()
            .name("osdp-mcp-pd".into())
            .spawn(move || {
                actor_loop(
                    rx,
                    log_for_thread,
                    wire_for_thread,
                    overrides_for_thread,
                    events_for_thread,
                    drop_for_thread,
                    pdid_for_thread,
                    pdcap_for_thread,
                    reader_state_for_thread,
                    crypto_factory,
                    startup,
                )
            })
            .expect("spawn PD actor thread");
        Self {
            tx,
            log,
            wire,
            overrides,
            events,
            drop_remaining,
            pdid,
            pdcap,
            reader_state,
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

    /// Restart the PD from the configuration remembered at the last
    /// `configure`. The remembered config survives a `stop`, so this is
    /// how you bring a stopped PD back without re-supplying port/baud/
    /// address/SCBK. Errors if nothing was ever configured, or if the
    /// PD is already running.
    pub async fn start(&self) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Start { reply })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))?
    }

    pub async fn status(&self) -> anyhow::Result<PdStatus> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Status { reply })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))
    }

    /// Read up to `limit` log entries with `seq >= since_seq`,
    /// filtered through `filter`. Goes straight to the shared log
    /// — no actor round-trip.
    pub fn get_log(&self, since_seq: u64, limit: usize, filter: EffectiveFilter) -> LogPage {
        self.log.snapshot(since_seq, limit, filter)
    }

    /// Per-(direction, code) summary of the whole current ring.
    /// Cheap probe: returns counts only, never payloads. Useful for
    /// "what's in the log?" without paging through it.
    pub fn get_log_summary(&self) -> LogSummary {
        self.log.summary()
    }

    /// Drop every entry currently in the log. `next_seq` is
    /// preserved so any outstanding cursor stays meaningful.
    pub fn clear_log(&self) {
        self.log.clear();
    }

    /// Read up to `limit` raw wire chunks (TX/RX bytes + µs
    /// timestamps) with `seq >= since_seq`. Straight to the shared
    /// trace — no actor round-trip.
    pub fn get_wire_trace(&self, since_seq: u64, limit: usize) -> WirePage {
        self.wire.snapshot(since_seq, limit)
    }

    /// Drop every captured wire chunk. `next_seq` is preserved.
    /// Clear → reproduce → snapshot gives a clean capture window.
    pub fn clear_wire_trace(&self) {
        self.wire.clear();
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

    /// Snapshot the PD identity currently reported in `osdp_PDID`.
    /// Reads the shared value directly — no actor round-trip — so it
    /// works whether or not a PD is running. A poisoned lock falls back
    /// to the default identity.
    pub fn get_pdid(&self) -> Pdid {
        self.pdid
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|_| crate::handler::default_pdid())
    }

    /// Replace the PD identity reported in `osdp_PDID`. Takes effect on
    /// the next `osdp_ID` command. The new identity also feeds the SC
    /// cUID the *next* handshake derives — an established session keeps
    /// its current cUID until it re-handshakes. Persists across
    /// `configure` / `stop`.
    pub fn set_pdid(&self, pdid: Pdid) {
        if let Ok(mut g) = self.pdid.lock() {
            *g = pdid;
        }
    }

    /// Snapshot the capability set currently reported in `osdp_PDCAP`.
    /// Reads the shared value directly — no actor round-trip — so it
    /// works whether or not a PD is running. A poisoned lock falls back
    /// to the default capability set.
    pub fn get_pdcap(&self) -> Pdcap {
        self.pdcap
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| crate::handler::default_pdcap())
    }

    /// Replace the capability set reported in `osdp_PDCAP`. Takes effect
    /// on the next `osdp_CAP` command. Persists across `configure` /
    /// `stop`. Validation against the OSDP spec is the caller's
    /// responsibility (see `crate::pdcap_spec`).
    pub fn set_pdcap(&self, pdcap: Pdcap) {
        if let Ok(mut g) = self.pdcap.lock() {
            *g = pdcap;
        }
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

    /// Snapshot the reader's observed output state (LED colours). Reads
    /// the shared state directly — no actor round-trip. A poisoned lock
    /// yields an empty snapshot rather than failing.
    pub fn reader_state(&self) -> ReaderStateView {
        self.reader_state
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_else(|_| ReaderStateView { leds: Vec::new() })
    }

    /// Subscribe to reader-state changes — one snapshot per LED change —
    /// for the `/api/events` SSE stream. The broadcast channel lives inside
    /// the shared `ReaderState` and survives PD reconfigure, so a client
    /// stays subscribed across `pd_stop` / `pd_configure`.
    pub fn subscribe_reader(&self) -> broadcast::Receiver<ReaderStateView> {
        match self.reader_state.lock() {
            Ok(s) => s.subscribe(),
            Err(poisoned) => poisoned.into_inner().subscribe(),
        }
    }

    /// Drop every queued event. Subsequent POLLs go straight to
    /// override-or-ACK.
    pub fn clear_events(&self) {
        events::clear(&self.events);
    }

    /// Make the handler silently drop the next `n` replies. Each
    /// dropped reply still logs the inbound command (so the agent
    /// can see what was eaten); the PD just doesn't transmit
    /// anything in response. Tests the ACU's offline-detection
    /// path. Cumulative — calling twice with n=2 each sets the
    /// counter to 4 only if the first hasn't been consumed yet;
    /// otherwise the new value replaces the residual.
    pub fn drop_next_n_replies(&self, n: u32) {
        self.drop_remaining.store(n, Ordering::Relaxed);
    }

    /// Tear down and rebuild the current PD with the same parameters.
    /// Forces the ACU into session-loss detection — the rebuilt PD
    /// starts with a fresh SQN and (if SC was configured) loses its
    /// SC session state.
    pub async fn force_session_loss(&self) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::ForceSessionLoss { reply })
            .map_err(|_| anyhow::anyhow!("PD actor is gone"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("PD actor dropped the reply"))?
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

/// The parameters of the most recent [`Cmd::Configure`], retained by
/// the actor across a [`Cmd::Stop`] so [`Cmd::Start`] can bring the PD
/// back up without the caller re-supplying them — notably the SCBK,
/// which `pd_status` deliberately never exposes. Captured when a
/// configure is requested (before the serial port is opened), so a
/// `start` retries the exact same request even if the first attempt
/// failed to open the port.
#[derive(Clone)]
struct RememberedConfig {
    port: String,
    baud: u32,
    address: u8,
    sc: Option<ScConfig>,
}

/// The operator's `OSDP_MCP_*` startup values, handed to [`PdHandle::spawn`]
/// and used to seed the actor's remembered config before any interactive
/// `pd_configure` runs. This makes `pd_start` able to bring the PD up from
/// the startup posture out of the box — independent of whether the boot-time
/// auto-start succeeded — and gives it a baseline to fall back to even after
/// an interactive reconfigure.
#[derive(Clone)]
pub struct StartupConfig {
    pub port: String,
    pub baud: u32,
    pub address: u8,
    pub sc: Option<ScConfig>,
}

/// Runtime state held by the actor thread itself.
struct Slot {
    pd: Pd,
    port: String,
    baud: u32,
    address: u8,
    /// Last SC config we were asked for. Replayed by
    /// `ForceSessionLoss` so the rebuilt PD comes up with the same
    /// SC posture as the original.
    sc: Option<ScConfig>,
    stats: Arc<Mutex<PdStats>>,
    /// PD-local clock zero. Shares the same wall-clock basis as the
    /// handler's `last_command_at_ms` stamps (both anchored at
    /// `open_pd`), so `status` can age the last command to decide
    /// `actively_polling`.
    epoch: Instant,
}

#[allow(clippy::too_many_arguments)]
fn actor_loop(
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    log: Arc<LogInner>,
    wire: Arc<WireTrace>,
    overrides: OverrideMap,
    events: EventQueue,
    drop_remaining: DropCounter,
    pdid: SharedPdid,
    pdcap: SharedPdcap,
    reader_state: SharedReaderState,
    crypto_factory: CryptoFactory,
    startup: Option<StartupConfig>,
) {
    let mut slot: Option<Slot> = None;
    // Survives `Stop` so `Start` can rebuild the PD from it. Seeded
    // from the operator's `OSDP_MCP_*` startup values so `pd_start`
    // has the startup posture as a baseline from the very first tick.
    let mut last_config: Option<RememberedConfig> = startup.map(|s| RememberedConfig {
        port: s.port,
        baud: s.baud,
        address: s.address,
        sc: s.sc,
    });
    // Tick the PD ~1000 times/sec. OSDP timing tolerances are loose
    // (ms-scale) so this is plenty; sleeping yields the CPU.
    let tick_period = Duration::from_millis(1);

    loop {
        // Drain everything queued before ticking. try_recv on a tokio
        // channel works from a non-async context.
        loop {
            match rx.try_recv() {
                Ok(cmd) => handle_cmd(
                    cmd,
                    &mut slot,
                    &mut last_config,
                    &log,
                    &wire,
                    &overrides,
                    &events,
                    &drop_remaining,
                    &pdid,
                    &pdcap,
                    &reader_state,
                    &crypto_factory,
                ),
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

#[allow(clippy::too_many_arguments)]
fn handle_cmd(
    cmd: Cmd,
    slot: &mut Option<Slot>,
    last_config: &mut Option<RememberedConfig>,
    log: &Arc<LogInner>,
    wire: &Arc<WireTrace>,
    overrides: &OverrideMap,
    events: &EventQueue,
    drop_remaining: &DropCounter,
    pdid: &SharedPdid,
    pdcap: &SharedPdcap,
    reader_state: &SharedReaderState,
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
            // Remember the request before doing anything, so a later
            // `Start` (or a retry) replays these exact parameters even
            // if the open below fails.
            *last_config = Some(RememberedConfig {
                port: port.clone(),
                baud,
                address,
                sc: sc.clone(),
            });
            // Tear down any existing PD first; one slot per actor.
            *slot = None;
            let result = open_pd(
                &port,
                baud,
                address,
                Arc::clone(log),
                Arc::clone(wire),
                Arc::clone(overrides),
                Arc::clone(events),
                Arc::clone(drop_remaining),
                Arc::clone(pdid),
                Arc::clone(pdcap),
                Arc::clone(reader_state),
                sc,
                crypto_factory,
            )
            .map(|s| {
                *slot = Some(s);
            });
            let _ = reply.send(result);
        }
        Cmd::Stop { reply } => {
            // Drop the running PD but keep `last_config` so `Start` can
            // bring it back.
            *slot = None;
            let _ = reply.send(());
        }
        Cmd::Start { reply } => {
            let result = if slot.is_some() {
                Err(anyhow::anyhow!(
                    "PD is already running; stop it first or use pd_configure to reconfigure"
                ))
            } else {
                match last_config.as_ref() {
                    None => Err(anyhow::anyhow!(
                        "no remembered configuration; call pd_configure first"
                    )),
                    Some(cfg) => open_pd(
                        &cfg.port,
                        cfg.baud,
                        cfg.address,
                        Arc::clone(log),
                        Arc::clone(wire),
                        Arc::clone(overrides),
                        Arc::clone(events),
                        Arc::clone(drop_remaining),
                        Arc::clone(pdid),
                        Arc::clone(pdcap),
                        Arc::clone(reader_state),
                        cfg.sc.clone(),
                        crypto_factory,
                    )
                    .map(|s| {
                        *slot = Some(s);
                    }),
                }
            };
            let _ = reply.send(result);
        }
        Cmd::ForceSessionLoss { reply } => {
            let result = match slot.take() {
                None => Err(anyhow::anyhow!("no PD configured; nothing to force-reset")),
                Some(old) => {
                    // Replay the original configure with the same
                    // port/baud/address/sc. The serial port briefly
                    // closes and reopens; the ACU's next exchange
                    // sees a fresh-boot PD.
                    tracing::info!(
                        port = %old.port,
                        address = format!("0x{:02X}", old.address),
                        "force_session_loss: rebuilding PD"
                    );
                    let r = open_pd(
                        &old.port,
                        old.baud,
                        old.address,
                        Arc::clone(log),
                        Arc::clone(wire),
                        Arc::clone(overrides),
                        Arc::clone(events),
                        Arc::clone(drop_remaining),
                        Arc::clone(pdid),
                        Arc::clone(pdcap),
                        Arc::clone(reader_state),
                        old.sc.clone(),
                        crypto_factory,
                    );
                    match r {
                        Ok(s) => {
                            *slot = Some(s);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
            };
            let _ = reply.send(result);
        }
        Cmd::Status { reply } => {
            // Event queue depth + drop counter are independent of
            // whether a PD is running — agent-side state that the
            // handler reads when a PD is later configured.
            let queue_depth = events::len(events) as u32;
            let drops = drop_remaining.load(Ordering::Relaxed);
            let status = match slot.as_ref() {
                None => PdStatus {
                    event_queue_depth: queue_depth,
                    drop_remaining: drops,
                    ..PdStatus::idle()
                },
                Some(s) => {
                    let stats = s.stats.lock().map(|g| g.clone()).unwrap_or_default();
                    // Age the most recent command against the shared
                    // PD clock. wrapping_sub keeps us safe across the
                    // u32-ms wrap and any sub-ms epoch skew.
                    let now_ms = s.epoch.elapsed().as_millis() as u32;
                    let actively_polling = stats
                        .last_command_at_ms
                        .is_some_and(|t| now_ms.wrapping_sub(t) <= POLLING_WINDOW_MS);
                    PdStatus {
                        running: true,
                        port: Some(s.port.clone()),
                        baud: Some(s.baud),
                        address: Some(s.address),
                        is_online: s.pd.is_online(),
                        actively_polling,
                        sc_mode: ScMode::from_cfg(&s.sc),
                        sc_established: s.pd.sc_established(),
                        last_command_at_ms: stats.last_command_at_ms,
                        last_reply_at_ms: stats.last_reply_at_ms,
                        last_cmd_code: stats.last_cmd_code,
                        last_reply_code: stats.last_reply_code,
                        event_queue_depth: queue_depth,
                        drop_remaining: drops,
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
    wire: Arc<WireTrace>,
    overrides: OverrideMap,
    events: EventQueue,
    drop_remaining: DropCounter,
    pdid: SharedPdid,
    pdcap: SharedPdcap,
    reader_state: SharedReaderState,
    sc: Option<ScConfig>,
    crypto_factory: &CryptoFactory,
) -> anyhow::Result<Slot> {
    let transport = SerialTransport::open(port, baud, wire)?;
    let stats = Arc::new(Mutex::new(PdStats::default()));
    // Anchor the PD-local clock before the handler is built so the
    // Slot and the handler's `last_command_at_ms` stamps share a zero
    // (the handler mints its own Instant a few µs later, which only
    // makes its stamps marginally smaller than `epoch.elapsed()` —
    // never larger, so no underflow in the `actively_polling` math).
    let epoch = Instant::now();

    // Snapshot the shared PDID for the cUID derivation below. The
    // handler keeps the shared handle so later `set_pdid` edits show up
    // in the `osdp_ID` reply; the cUID, by contrast, is fixed for the
    // life of this PD instance (a real device's cUID doesn't change
    // without a reboot — re-handshake by reconfiguring to pick up an
    // edited identity).
    let pdid_snapshot = pdid
        .lock()
        .map(|g| *g)
        .unwrap_or_else(|_| crate::handler::default_pdid());

    let mut pd = Pd::new(address);
    pd.set_transport(transport);
    pd.set_command_handler(DefaultHandler::with_pdid(
        pdid,
        pdcap,
        Arc::clone(&stats),
        log,
        overrides,
        events,
        drop_remaining,
        address,
    ));

    // A freshly-opened PD starts with no LED state; clear any colours the
    // previous PD left in the snapshot, then bind the change callback so
    // the PD's transparent osdp_LED decoding flows into the reader state.
    if let Ok(mut rs) = reader_state.lock() {
        rs.clear();
    }
    pd.set_led_handler(ReaderLedHandler::new(reader_state));

    // Bind Secure Channel material if requested. The crypto factory
    // mints a fresh provider per PD so the AES + RNG state is
    // independent across configures. The cUID is derived from the
    // PDID we report (spec D.4.3 — first 8 bytes of the PDID byte
    // stream: vendor[3] + model + version + serial[0..2]).
    let mut sc_mode_label = "none";
    if let Some(cfg) = sc.as_ref() {
        let crypto = crypto_factory();
        pd.set_sc_crypto(BoxedSc(crypto));
        let cuid = derive_cuid_from_pdid(&pdid_snapshot);
        pd.set_sc_cuid(&cuid);
        match cfg {
            ScConfig::Scbkd => {
                pd.set_sc_scbk_d(osdp_embedded::sc::scbk_default());
                sc_mode_label = "scbkd";
            }
            ScConfig::Scbk(key) => {
                pd.set_sc_scbk(key);
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
        sc,
        stats,
        epoch,
    })
}

/// Build the 8-byte cUID from a PDID. Spec D.4.3:
/// `vendor[0..3] + model + version + serial[0..2]` (the first two
/// bytes of serial in transmission order — little-endian on the wire).
fn derive_cuid_from_pdid(p: &Pdid) -> [u8; 8] {
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
