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

use osdp_embedded::pd::{LedColor, LedHandler};

/// Latest displayed colour of each `(reader_no, led_no)` the PD has driven.
#[derive(Default)]
pub struct ReaderState {
    leds: BTreeMap<(u8, u8), LedColor>,
}

impl ReaderState {
    /// Record the current colour of one LED.
    pub fn set_led(&mut self, reader_no: u8, led_no: u8, color: LedColor) {
        self.leds.insert((reader_no, led_no), color);
    }

    /// Forget all tracked LEDs. Called when a PD is (re)opened so a fresh
    /// reader starts blank rather than showing the previous PD's colours.
    pub fn clear(&mut self) {
        self.leds.clear();
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

/// The reader's current output state, returned by `pd_reader_state`.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct ReaderStateView {
    /// Every LED the reader has been told to display, with its current
    /// colour. Empty until the ACU sends an `osdp_LED` command.
    pub leds: Vec<LedView>,
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
