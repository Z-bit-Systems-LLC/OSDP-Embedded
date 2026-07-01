// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Observed output state of the virtual reader.
//!
//! Today this tracks the reader's **LED colours**. The PD library decodes
//! inbound `osdp_LED` commands transparently and resolves "what colour is
//! each LED showing right now" (temporary-vs-permanent, the temporary
//! countdown timer, and flash phase) behind its change callback; we just
//! register that callback and fold the reported colour into a shared
//! snapshot the UI / an MCP tool can read. Buzzer / text / relay state can
//! join the same struct later following the same pattern.
//!
//! The handler runs on the PD actor thread (the `Pd` is `!Send`); the
//! snapshot is read from the async tool side. The `Arc<Mutex<…>>` bridges
//! the two — only short, non-blocking critical sections.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use osdp_embedded::pd::{BuzzerHandler, LedColor, LedHandler};
use tokio::sync::broadcast;

use crate::pd_actor::ScMode;

/// Capacity of the change-broadcast ring. Snapshots are tiny; a slow SSE
/// subscriber that lags just resyncs to the next snapshot, never serving
/// stale data, so a small buffer is plenty.
const EVENT_CHANNEL_CAP: usize = 64;

/// Latest displayed colour of each `(reader_no, led_no)` the PD has driven,
/// plus a broadcast channel that fans each change out to live SSE clients.
pub struct ReaderState {
    leds: BTreeMap<(u8, u8), LedColor>,
    /// Sounding state of each reader's buzzer, keyed by reader_no, with the
    /// driving tone code.
    buzzers: BTreeMap<u8, (bool, u8)>,
    /// Current Secure Channel link posture (clear text / install / secure)
    /// and whether the handshake has completed. Surfaced to the UI's
    /// connection badge; updated by the PD actor, not the LED/buzzer path.
    connection: ConnectionView,
    tx: broadcast::Sender<ReaderStateView>,
}

impl Default for ReaderState {
    fn default() -> Self {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAP);
        Self {
            leds: BTreeMap::new(),
            buzzers: BTreeMap::new(),
            connection: ConnectionView::default(),
            tx,
        }
    }
}

impl ReaderState {
    /// Record the current colour of one LED and notify subscribers.
    pub fn set_led(&mut self, reader_no: u8, led_no: u8, color: LedColor) {
        self.leds.insert((reader_no, led_no), color);
        self.notify();
    }

    /// Record a reader buzzer's sounding state (and tone) and notify.
    pub fn set_buzzer(&mut self, reader_no: u8, sounding: bool, tone: u8) {
        self.buzzers.insert(reader_no, (sounding, tone));
        self.notify();
    }

    /// Record the reader's connection view (configured + operational
    /// posture, polling) and notify subscribers **only if it changed** (the
    /// actor rebuilds this every tick, so guarding on change keeps the SSE
    /// stream quiet). Called by the PD actor when a PD is (re)opened or
    /// stopped, and whenever the session establishes/drops/re-keys or the
    /// ACU starts/stops polling.
    pub fn set_connection(&mut self, next: ConnectionView) {
        if self.connection != next {
            self.connection = next;
            self.notify();
        }
    }

    /// Forget all tracked LEDs and buzzers. Called when a PD is (re)opened so
    /// a fresh reader starts blank rather than showing the previous PD's
    /// state.
    pub fn clear(&mut self) {
        self.leds.clear();
        self.buzzers.clear();
        self.notify();
    }

    /// Subscribe to per-change snapshots — drives the `/api/events` SSE
    /// stream. Each subscriber also receives an explicit snapshot-on-connect
    /// from the endpoint, so a missed early event can't leave it blank.
    pub fn subscribe(&self) -> broadcast::Receiver<ReaderStateView> {
        self.tx.subscribe()
    }

    /// Push the current snapshot to any live subscribers. `send` errs only
    /// when there are none, which we ignore.
    fn notify(&self) {
        let _ = self.tx.send(self.snapshot());
    }

    /// A serialisable snapshot for `pd_reader_state` / the UI.
    pub fn snapshot(&self) -> ReaderStateView {
        ReaderStateView {
            leds: self
                .leds
                .iter()
                .map(|(&(reader_no, led_no), &color)| LedView {
                    reader_no,
                    led_no,
                    color: color.as_u8(),
                    color_name: color_name(color),
                })
                .collect(),
            buzzers: self
                .buzzers
                .iter()
                .map(|(&reader_no, &(sounding, tone))| BuzzerView {
                    reader_no,
                    sounding,
                    tone,
                })
                .collect(),
            connection: self.connection,
        }
    }
}

/// Shared, mutable reader state. The PD actor thread writes (via the LED
/// callback), tool handlers read.
pub type SharedReaderState = Arc<Mutex<ReaderState>>;

/// Create a fresh shared reader state.
pub fn new_shared() -> SharedReaderState {
    Arc::new(Mutex::new(ReaderState::default()))
}

/// PD LED change handler that folds every reported colour change into a
/// [`SharedReaderState`]. Bind it with `Pd::set_led_handler`.
pub struct ReaderLedHandler {
    state: SharedReaderState,
}

impl ReaderLedHandler {
    pub fn new(state: SharedReaderState) -> Self {
        Self { state }
    }
}

impl LedHandler for ReaderLedHandler {
    fn on_led_change(&mut self, reader_no: u8, led_no: u8, color: LedColor) {
        // A poisoned lock just means a reader-side panic; drop the update
        // rather than propagating — the next change will refresh it.
        if let Ok(mut s) = self.state.lock() {
            s.set_led(reader_no, led_no, color);
        }
    }
}

/// PD buzzer change handler that folds each sounding-state change into a
/// [`SharedReaderState`]. Bind it with `Pd::set_buzzer_handler`.
pub struct ReaderBuzzerHandler {
    state: SharedReaderState,
}

impl ReaderBuzzerHandler {
    pub fn new(state: SharedReaderState) -> Self {
        Self { state }
    }
}

impl BuzzerHandler for ReaderBuzzerHandler {
    fn on_buzzer_change(&mut self, reader_no: u8, sounding: bool, tone: u8) {
        if let Ok(mut s) = self.state.lock() {
            s.set_buzzer(reader_no, sounding, tone);
        }
    }
}

/// One LED's current colour in the snapshot returned to the agent / UI.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LedView {
    /// Reader number on the PD (0 for single-reader devices).
    pub reader_no: u8,
    /// LED number on that reader.
    pub led_no: u8,
    /// Raw `osdp_led_color_t` code (0 black/off .. 7 white).
    pub color: u8,
    /// Human-readable colour name ("red", "green", …; "0xNN" for any
    /// reserved/vendor code).
    pub color_name: String,
}

/// One reader buzzer's current sounding state in the snapshot.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct BuzzerView {
    /// Reader number on the PD.
    pub reader_no: u8,
    /// True while the buzzer is making sound right now (it toggles through
    /// the command's on/off pattern).
    pub sounding: bool,
    /// Driving tone code (0x01 off, 0x02 default tone).
    pub tone: u8,
}

/// The reader's current output state, returned by `pd_reader_state`.
#[derive(Debug, Clone, Default, serde::Serialize, schemars::JsonSchema)]
pub struct ReaderStateView {
    /// Every LED the reader has been told to display, with its current
    /// colour. Empty until the ACU sends an `osdp_LED` command.
    pub leds: Vec<LedView>,
    /// Each reader buzzer's current sounding state. Empty until the ACU
    /// sends an `osdp_BUZ` command.
    pub buzzers: Vec<BuzzerView>,
    /// The reader's connection view — configured vs. operational Secure
    /// Channel posture, and whether the ACU is polling. Drives the status
    /// badge, the "configured" sub-label, and the polling indicator.
    pub connection: ConnectionView,
}

/// The reader's link status for the UI: whether a PD is running, the
/// Secure Channel posture it is **configured** for vs. the one **actually
/// in force on the wire** right now, and whether the ACU is polling.
/// Distinct from the LED/buzzer output (it describes the link, not the
/// display).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct ConnectionView {
    /// True while a PD is configured and ticking. When false the badge is
    /// hidden — there's no link to describe.
    pub running: bool,
    /// The Secure Channel posture the PD is **configured** for: `none`
    /// (clear text), `install` (SCBK-D), or `scbk` (operational). Static
    /// for the life of the PD. Serialised snake_case.
    pub configured: ScMode,
    /// The Secure Channel posture actually **in force on the wire** right
    /// now: `none` until a session establishes, then `install`/`scbk` by
    /// the session's key. A PD configured for install reads `none` here
    /// until it handshakes, and flips to `scbk` once a KEYSET-rotated key
    /// takes over. This is the main badge.
    pub operational: ScMode,
    /// True iff the ACU is actively polling — a command arrived within the
    /// polling window. Drives the "polling / idle" indicator.
    pub polling: bool,
}

fn color_name(c: LedColor) -> String {
    match c {
        LedColor::Black => "black".to_string(),
        LedColor::Red => "red".to_string(),
        LedColor::Green => "green".to_string(),
        LedColor::Amber => "amber".to_string(),
        LedColor::Blue => "blue".to_string(),
        LedColor::Magenta => "magenta".to_string(),
        LedColor::Cyan => "cyan".to_string(),
        LedColor::White => "white".to_string(),
        LedColor::Other(v) => format!("0x{v:02X}"),
    }
}
