// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Ring buffer of decoded OSDP events.
//!
//! Writes happen on the PD actor thread (from inside the handler);
//! reads happen on the Tokio reactor (from the MCP tool methods).
//! The two sides share an `Arc<LogInner>` directly — no need to bounce
//! through the actor's command channel for log reads, which keeps
//! `get_log` / `wait_for_command` latency tight.
//!
//! Cursor model: every entry carries a monotonically-increasing
//! `seq` starting at 0. `get_log(since_seq)` returns entries with
//! `seq >= since_seq` plus `next_seq = highest + 1` for the agent's
//! next call (so passing the previous response's `next_seq` returns
//! only entries added since). `clear_log` drops entries but does NOT
//! rewind `next_seq` — clients holding a cursor stay consistent.

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::Notify;

/// Where a logged frame came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// ACU → PD command accepted by the handler.
    Cmd,
    /// PD → ACU reply emitted by the handler.
    Reply,
    /// Library-synthesised NAK (handler returned `NotSupported`).
    /// Carries the NAK code in `payload_hex[0]`.
    Nak,
}

/// One captured event. `payload_hex` is the raw payload as an
/// uppercase hex string ("ABCD") for friction-free consumption from
/// JSON-RPC clients. The decoded payload typing belongs to a future
/// milestone — for now agents can re-parse the hex if they care.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LogEntry {
    /// Monotonic sequence number, starts at 0, survives `clear_log`.
    /// To page through new entries, pass the previous response's
    /// `next_seq` (= highest returned seq + 1) as the next `since_seq`.
    pub seq: u64,
    /// ms since the actor epoch (32-bit wrap is fine — agents care
    /// about deltas, not absolute time).
    pub timestamp_ms: u32,
    pub direction: Direction,
    /// PD address that produced / received this frame.
    pub pd_address: u8,
    /// Command code (for `Cmd`), reply code (for `Reply`), or
    /// the NAK error code (for `Nak`).
    pub code: u8,
    pub payload_hex: String,
}

/// Default ring capacity — large enough for a few minutes of polling
/// traffic, small enough that JSON serialisation of the whole thing
/// stays under a few hundred KB. Older entries get dropped silently.
pub const DEFAULT_CAPACITY: usize = 1024;

struct State {
    entries: VecDeque<LogEntry>,
    next_seq: u64,
    cap: usize,
}

/// Shared between the writer (handler on the PD thread) and the
/// readers (MCP tool methods on tokio). The `Notify` wakes blocked
/// `wait_for_command` futures whenever a new entry lands.
pub struct LogInner {
    state: Mutex<State>,
    pub notify: Notify,
}

impl LogInner {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: VecDeque::with_capacity(capacity),
                next_seq: 0,
                cap: capacity,
            }),
            notify: Notify::new(),
        }
    }

    /// Append an entry. Drops the oldest if the buffer is full.
    /// Called from the writer side (the PD thread) — no async.
    pub fn push(
        &self,
        direction: Direction,
        pd_address: u8,
        code: u8,
        payload: &[u8],
        timestamp_ms: u32,
    ) {
        let entry_seq;
        {
            let mut s = self.state.lock().expect("log mutex");
            if s.entries.len() == s.cap {
                s.entries.pop_front();
            }
            entry_seq = s.next_seq;
            s.next_seq += 1;
            s.entries.push_back(LogEntry {
                seq: entry_seq,
                timestamp_ms,
                direction,
                pd_address,
                code,
                payload_hex: hex_encode(payload),
            });
        }
        // notify_waiters wakes every current waiter; they each
        // re-check the log and either return or sleep again. Cheap
        // because there are usually zero or one waiters.
        self.notify.notify_waiters();
        let _ = entry_seq;
    }

    /// Return entries with `seq >= since_seq`, capped at `limit`.
    /// `next_seq` in the returned page is `highest returned seq + 1`
    /// (or `since_seq` if nothing matched) — pass it back as the
    /// next call's `since_seq` to read only new entries.
    pub fn snapshot(&self, since_seq: u64, limit: usize) -> LogPage {
        let s = self.state.lock().expect("log mutex");
        let mut out = Vec::new();
        let mut highest: Option<u64> = None;
        for e in &s.entries {
            if e.seq >= since_seq {
                if out.len() >= limit {
                    break;
                }
                highest = Some(e.seq);
                out.push(e.clone());
            }
        }
        LogPage {
            entries: out,
            next_seq: highest.map(|h| h + 1).unwrap_or(since_seq),
            // Total length of the ring at snapshot time — handy for
            // agents that just want to know "is there anything?".
            total: s.entries.len() as u32,
        }
    }

    /// Drop every entry but leave `next_seq` alone so external
    /// cursors remain unambiguous.
    pub fn clear(&self) {
        let mut s = self.state.lock().expect("log mutex");
        s.entries.clear();
    }

    /// Scan for the first entry with `seq >= since_seq` whose
    /// direction is [`Direction::Cmd`] and whose code matches.
    pub fn find_command_at_or_after(&self, since_seq: u64, cmd_code: u8) -> Option<LogEntry> {
        let s = self.state.lock().expect("log mutex");
        for e in &s.entries {
            if e.seq >= since_seq && matches!(e.direction, Direction::Cmd) && e.code == cmd_code {
                return Some(e.clone());
            }
        }
        None
    }
}

/// Result of `LogInner::snapshot`. Carries entries + the cursor the
/// agent should pass on its next call.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    /// Pass back as `since_seq` to read the next page. Equals
    /// `since_seq` from the request if nothing new arrived.
    pub next_seq: u64,
    /// Number of entries currently in the ring (after the snapshot).
    pub total: u32,
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
    fn push_and_snapshot() {
        let log = LogInner::new(4);
        log.push(Direction::Cmd, 0x10, 0x60, &[], 0);
        log.push(Direction::Reply, 0x10, 0x40, &[], 1);
        let page = log.snapshot(0, 100);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].seq, 0);
        assert_eq!(page.entries[1].seq, 1);
        assert_eq!(page.entries[0].code, 0x60);
        assert!(matches!(page.entries[0].direction, Direction::Cmd));
        // next_seq = highest returned + 1 → re-paging with this
        // cursor returns nothing new yet.
        assert_eq!(page.next_seq, 2);
    }

    #[test]
    fn snapshot_with_cursor_returns_only_new() {
        let log = LogInner::new(8);
        log.push(Direction::Cmd, 0, 0x60, &[], 0);
        log.push(Direction::Cmd, 0, 0x61, &[], 1);
        let first = log.snapshot(0, 100);
        assert_eq!(first.next_seq, 2);
        // Nothing added since → empty page, cursor unchanged.
        let second = log.snapshot(first.next_seq, 100);
        assert!(second.entries.is_empty());
        assert_eq!(second.next_seq, 2);
        // Add an entry, page returns just it.
        log.push(Direction::Cmd, 0, 0x62, &[], 2);
        let third = log.snapshot(first.next_seq, 100);
        assert_eq!(third.entries.len(), 1);
        assert_eq!(third.entries[0].seq, 2);
        assert_eq!(third.next_seq, 3);
    }

    #[test]
    fn ring_drops_oldest() {
        let log = LogInner::new(2);
        for i in 0..5u32 {
            log.push(Direction::Cmd, 0, i as u8, &[], i);
        }
        let page = log.snapshot(0, 100);
        assert_eq!(page.entries.len(), 2);
        // Oldest 3 should be gone; remaining are seq 3 and 4.
        assert_eq!(page.entries[0].seq, 3);
        assert_eq!(page.entries[1].seq, 4);
    }

    #[test]
    fn clear_preserves_seq() {
        let log = LogInner::new(4);
        log.push(Direction::Cmd, 0, 0x60, &[], 0);
        log.push(Direction::Cmd, 0, 0x61, &[], 1);
        log.clear();
        assert!(log.snapshot(0, 100).entries.is_empty());
        log.push(Direction::Cmd, 0, 0x62, &[], 2);
        let page = log.snapshot(0, 100);
        // next_seq kept climbing across clear() — new entry is seq 2.
        assert_eq!(page.entries[0].seq, 2);
    }

    #[test]
    fn find_command_at_or_after_finds_first_match() {
        let log = LogInner::new(8);
        log.push(Direction::Cmd, 0, 0x60, &[], 0); // POLL  @ seq 0
        log.push(Direction::Reply, 0, 0x40, &[], 1);
        log.push(Direction::Cmd, 0, 0x61, &[], 2); // ID    @ seq 2
        log.push(Direction::Cmd, 0, 0x60, &[], 3); // POLL  @ seq 3

        // From cursor 0, first POLL is the one at seq 0.
        let e = log.find_command_at_or_after(0, 0x60).unwrap();
        assert_eq!(e.seq, 0);
        // From cursor 1, the seq-0 POLL is skipped; next POLL = seq 3.
        let e = log.find_command_at_or_after(1, 0x60).unwrap();
        assert_eq!(e.seq, 3);

        // ID is at seq 2.
        let e = log.find_command_at_or_after(0, 0x61).unwrap();
        assert_eq!(e.seq, 2);

        // Nothing matches 0x99.
        assert!(log.find_command_at_or_after(0, 0x99).is_none());
    }
}
