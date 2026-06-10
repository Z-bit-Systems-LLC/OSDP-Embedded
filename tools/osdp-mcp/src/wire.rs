// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Raw wire-level byte trace for the PD serial link.
//!
//! Unlike the frame-level [`crate::log`] ring — which records *decoded*
//! frames, aggregates the POLL/ACK heartbeat away, and keeps only the
//! payload — this captures every byte the
//! [`crate::serial_transport::SerialTransport`] reads or writes, with a
//! microsecond timestamp. That's the data a hardware sniffer would
//! give us, and exactly what the decoded log can't:
//!
//!   - **per-frame timing** — last inbound byte → first outbound byte
//!     is the PD's reply latency against the ACU's ~210 ms firstByte
//!     window. The decoded log doesn't timestamp POLL/ACK at all.
//!   - **the whole frame** — SOM, control byte (SQN, CRC-vs-checksum,
//!     SCB present), security block, and integrity bytes. The decoded
//!     log drops all of that and keeps only the payload.
//!
//! Used to chase timing / framing desync bugs against a live ACU when a
//! physical capture isn't available. Writes happen on the PD actor
//! thread (inside the transport); reads happen on the Tokio reactor
//! (the `get_wire_trace` tool). Both share an `Arc<WireTrace>`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

/// Direction of a captured chunk, from the PD's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WireDir {
    /// Bytes the PD read from the wire (ACU → PD).
    Rx,
    /// Bytes the PD wrote to the wire (PD → ACU).
    Tx,
}

/// One captured I/O chunk — the bytes moved in a single transport
/// `read()` / `write()` call. **Not** necessarily a whole OSDP frame:
/// inbound bytes trickle in across 1 ms ticks, so one frame can span
/// several `rx` entries, and their `t_us` deltas reveal byte-arrival
/// pacing. Outbound `tx` is the full frame the PD built, stamped the
/// moment it began transmitting.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct WireEntry {
    /// Monotonic sequence number, starts at 0, survives `clear`.
    pub seq: u64,
    /// Microseconds since the trace epoch (monotonic). Absolute value
    /// is meaningless; **deltas between entries** are the point — e.g.
    /// the gap from the last `rx` byte of a POLL to the next `tx` is
    /// the reply latency to compare against the ACU's firstByte window.
    pub t_us: u64,
    pub dir: WireDir,
    /// Number of bytes in this chunk (= `hex.len() / 2`).
    pub len: u32,
    /// Raw bytes as uppercase hex — the whole thing incl. SOM, control
    /// byte, SCB, and integrity. Everything the decoded log omits.
    pub hex: String,
}

/// Default capacity. Wire traffic is chatty (every tick that reads any
/// bytes adds an entry), but each entry is tiny. 8192 spans a couple of
/// minutes of active polling — enough to cover a grant → offline →
/// re-discovery cycle when dumped promptly after reproducing.
pub const DEFAULT_WIRE_CAPACITY: usize = 8192;

struct State {
    entries: VecDeque<WireEntry>,
    next_seq: u64,
    cap: usize,
    /// Lifetime count of chunks evicted from the front of the ring, so
    /// a reader can tell the window scrolled past older traffic rather
    /// than assuming it has the full history.
    dropped: u64,
}

/// Shared between the writer (the transport on the PD thread) and the
/// reader (`get_wire_trace` on tokio). Captures its own monotonic
/// epoch so every `tx`/`rx` timestamp shares one zero.
pub struct WireTrace {
    state: Mutex<State>,
    epoch: Instant,
}

impl WireTrace {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: VecDeque::with_capacity(capacity.min(1024)),
                next_seq: 0,
                cap: capacity,
                dropped: 0,
            }),
            epoch: Instant::now(),
        }
    }

    /// Record one I/O chunk. Called on the PD actor thread for every
    /// non-empty read and every write. Cheap: one lock, one hex
    /// encode, one push — microseconds, far below the 1 ms tick and the
    /// 210 ms reply window, so it doesn't meaningfully perturb the
    /// timing it measures. No-op on an empty slice.
    pub fn record(&self, dir: WireDir, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let t_us = self.epoch.elapsed().as_micros() as u64;
        let mut s = self.state.lock().expect("wire mutex");
        if s.entries.len() == s.cap {
            s.entries.pop_front();
            s.dropped += 1;
        }
        let seq = s.next_seq;
        s.next_seq += 1;
        s.entries.push_back(WireEntry {
            seq,
            t_us,
            dir,
            len: bytes.len() as u32,
            hex: hex_encode(bytes),
        });
    }

    /// Return entries with `seq >= since_seq`, capped at `limit`.
    pub fn snapshot(&self, since_seq: u64, limit: usize) -> WirePage {
        let s = self.state.lock().expect("wire mutex");
        let mut out = Vec::new();
        let mut highest_seen: Option<u64> = None;
        for e in &s.entries {
            if e.seq < since_seq {
                continue;
            }
            if out.len() >= limit {
                break;
            }
            highest_seen = Some(e.seq);
            out.push(e.clone());
        }
        WirePage {
            entries: out,
            next_seq: highest_seen.map(|h| h + 1).unwrap_or(since_seq),
            total: s.entries.len() as u32,
            dropped: s.dropped,
        }
    }

    /// Drop every captured chunk. `next_seq` keeps climbing so a cursor
    /// held across the clear stays unambiguous. Typical workflow:
    /// `clear` → reproduce (e.g. inject the offending card) → `snapshot`
    /// for a clean window of the failing exchange.
    pub fn clear(&self) {
        let mut s = self.state.lock().expect("wire mutex");
        s.entries.clear();
        s.dropped = 0;
    }
}

/// Result of [`WireTrace::snapshot`].
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct WirePage {
    pub entries: Vec<WireEntry>,
    /// Pass back as `since_seq` to read the next page.
    pub next_seq: u64,
    /// Chunks currently held in the ring (after the snapshot).
    pub total: u32,
    /// Lifetime count of chunks evicted because the ring filled. Non-
    /// zero means older traffic scrolled off — capture sooner or raise
    /// the capacity if you need a longer window.
    pub dropped: u64,
}

fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_tx_and_rx_in_order() {
        let w = WireTrace::new(8);
        w.record(WireDir::Rx, &[0x53, 0x00]);
        w.record(WireDir::Tx, &[0x53, 0x80, 0x08]);
        let page = w.snapshot(0, 100);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].dir, WireDir::Rx);
        assert_eq!(page.entries[0].hex, "5300");
        assert_eq!(page.entries[0].len, 2);
        assert_eq!(page.entries[1].dir, WireDir::Tx);
        assert_eq!(page.entries[1].hex, "538008");
        assert_eq!(page.next_seq, 2);
        assert_eq!(page.dropped, 0);
        // Timestamps are monotonic non-decreasing.
        assert!(page.entries[1].t_us >= page.entries[0].t_us);
    }

    #[test]
    fn empty_chunk_is_ignored() {
        let w = WireTrace::new(8);
        w.record(WireDir::Tx, &[]);
        assert_eq!(w.snapshot(0, 100).entries.len(), 0);
    }

    #[test]
    fn cursor_returns_only_new_entries() {
        let w = WireTrace::new(8);
        w.record(WireDir::Rx, &[1]);
        w.record(WireDir::Rx, &[2]);
        let first = w.snapshot(0, 100);
        assert_eq!(first.next_seq, 2);
        let second = w.snapshot(first.next_seq, 100);
        assert!(second.entries.is_empty());
        assert_eq!(second.next_seq, 2);
    }

    #[test]
    fn ring_evicts_oldest_and_counts_drops() {
        let w = WireTrace::new(2);
        for i in 0..5u8 {
            w.record(WireDir::Tx, &[i]);
        }
        let page = w.snapshot(0, 100);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].seq, 3);
        assert_eq!(page.entries[1].seq, 4);
        assert_eq!(page.dropped, 3);
    }

    #[test]
    fn clear_drops_entries_but_keeps_seq() {
        let w = WireTrace::new(8);
        w.record(WireDir::Rx, &[1]);
        w.record(WireDir::Rx, &[2]);
        w.clear();
        let page = w.snapshot(0, 100);
        assert!(page.entries.is_empty());
        assert_eq!(page.dropped, 0);
        w.record(WireDir::Tx, &[3]);
        // next_seq kept climbing across clear() — new entry is seq 2.
        let page = w.snapshot(0, 100);
        assert_eq!(page.entries[0].seq, 2);
    }
}
