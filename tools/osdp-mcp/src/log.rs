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

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use tokio::sync::Notify;

/// Default codes hidden from `get_log` when neither `include_codes`
/// nor `exclude_codes` is supplied — the heartbeat POLL → ACK pair.
/// Agents that want to see every byte pass `exclude_codes: []`.
pub const DEFAULT_NOISE_CODES: &[u8] = &[0x60, 0x40];

/// Where a logged frame came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, schemars::JsonSchema)]
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

/// Spec-defined symbolic name for a given `(direction, code)` pair.
/// Returned in [`LogEntry::name`] / [`LogCodeStat::name`] so an agent
/// reading the log doesn't have to memorise the OSDP code table.
///
/// Command and reply names are taken verbatim from SIA OSDP v2.2.2
/// Annex A (Tables A.1 and A.2) — the `osdp_NAME` form. NAK reason
/// names come from §7.3 Table 47 (the spec describes them in prose,
/// not symbols, so we use human-readable lowercase labels). Unknown
/// codes return `"?"` — the numeric `code` field is authoritative.
pub fn code_name(direction: Direction, code: u8) -> &'static str {
    match direction {
        // Annex A.1 — Table A.1 Commands.
        Direction::Cmd => match code {
            0x60 => "osdp_POLL",
            0x61 => "osdp_ID",
            0x62 => "osdp_CAP",
            0x64 => "osdp_LSTAT",
            0x65 => "osdp_ISTAT",
            0x66 => "osdp_OSTAT",
            0x67 => "osdp_RSTAT",
            0x68 => "osdp_OUT",
            0x69 => "osdp_LED",
            0x6A => "osdp_BUZ",
            0x6B => "osdp_TEXT",
            0x6E => "osdp_COMSET",
            0x73 => "osdp_BIOREAD",
            0x74 => "osdp_BIOMATCH",
            0x75 => "osdp_KEYSET",
            0x76 => "osdp_CHLNG",
            0x77 => "osdp_SCRYPT",
            0x7B => "osdp_ACURXSIZE",
            0x7C => "osdp_FILETRANSFER",
            0x80 => "osdp_MFG",
            0xA1 => "osdp_XWR",
            0xA2 => "osdp_ABORT",
            0xA3 => "osdp_PIVDATA",
            0xA4 => "osdp_GENAUTH",
            0xA5 => "osdp_CRAUTH",
            0xA7 => "osdp_KEEPACTIVE",
            _ => "?",
        },
        // Annex A.2 — Table A.2 Replies.
        Direction::Reply => match code {
            0x40 => "osdp_ACK",
            0x41 => "osdp_NAK",
            0x45 => "osdp_PDID",
            0x46 => "osdp_PDCAP",
            0x48 => "osdp_LSTATR",
            0x49 => "osdp_ISTATR",
            0x4A => "osdp_OSTATR",
            0x4B => "osdp_RSTATR",
            0x50 => "osdp_RAW",
            0x51 => "osdp_FMT",
            0x53 => "osdp_KEYPAD",
            0x54 => "osdp_COM",
            0x57 => "osdp_BIOREADR",
            0x58 => "osdp_BIOMATCHR",
            0x76 => "osdp_CCRYPT",
            0x78 => "osdp_RMAC_I",
            0x79 => "osdp_BUSY",
            0x7A => "osdp_FTSTAT",
            0x80 => "osdp_PIVDATAR",
            0x81 => "osdp_GENAUTHR",
            0x82 => "osdp_CRAUTHR",
            0x83 => "osdp_MFGSTATR",
            0x84 => "osdp_MFGERRR",
            0x90 => "osdp_MFGREP",
            0xB1 => "osdp_XRD",
            _ => "?",
        },
        // §7.3 Table 47 — NAK reason codes. The spec describes them
        // in prose only, so we use lowercase human-readable labels
        // rather than invent symbolic names.
        Direction::Nak => match code {
            0x00 => "no_error",
            0x01 => "bad_check",
            0x02 => "cmd_length",
            0x03 => "unknown_cmd",
            0x04 => "unexpected_sequence",
            0x05 => "unsupported_scb",
            0x06 => "encryption_required",
            0x07 => "bio_type_unsupported",
            0x08 => "bio_format_unsupported",
            0x09 => "record_invalid",
            _ => "?",
        },
    }
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
    /// Spec-defined symbolic name for `(direction, code)` — e.g.
    /// "POLL", "PDID", "unknown_cmd". `"?"` if the code is not in
    /// the v2.2.2 baseline. See [`code_name`].
    pub name: &'static str,
    pub payload_hex: String,
}

/// Default ring capacity — large enough for a few minutes of polling
/// traffic, small enough that JSON serialisation of the whole thing
/// stays under a few hundred KB. Older entries get dropped silently.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Lifetime aggregate for a `(direction, code)` pair that was
/// filtered at push time and never got a ring slot. Survives ring
/// rollover; reset by `clear`.
#[derive(Debug, Clone)]
struct PushCount {
    count: u32,
    last_timestamp_ms: u32,
}

struct State {
    entries: VecDeque<LogEntry>,
    next_seq: u64,
    cap: usize,
    /// Codes that bypass the ring at push time — they only update
    /// aggregate counters. Initialised to the heartbeat
    /// (`DEFAULT_NOISE_CODES`) so a long-running session doesn't
    /// have its ring evicted by POLL/ACK noise. Code-byte match,
    /// not direction-aware (mirrors `EffectiveFilter`).
    push_filter: Vec<u8>,
    /// Lifetime aggregates for push-filtered events.
    push_counts: BTreeMap<(Direction, u8), PushCount>,
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
                push_filter: DEFAULT_NOISE_CODES.to_vec(),
                push_counts: BTreeMap::new(),
            }),
            notify: Notify::new(),
        }
    }

    /// Record an event. POLL/ACK heartbeat goes to a counter (no
    /// ring slot, no notify) so the 1024-entry ring stays reserved
    /// for interesting traffic in long-running sessions. Everything
    /// else gets a `LogEntry` in the ring and drops the oldest if
    /// the buffer is full.
    ///
    /// Called from the writer side (the PD thread) — no async.
    pub fn push(
        &self,
        direction: Direction,
        pd_address: u8,
        code: u8,
        payload: &[u8],
        timestamp_ms: u32,
    ) {
        {
            let mut s = self.state.lock().expect("log mutex");

            if s.push_filter.contains(&code) {
                // Heartbeat: aggregate-only path. No ring slot, no
                // seq advance, no notify — `wait_for_command` on a
                // push-filtered code is intentionally unsupported
                // (those codes are noise by definition).
                let entry = s
                    .push_counts
                    .entry((direction, code))
                    .or_insert(PushCount {
                        count: 0,
                        last_timestamp_ms: timestamp_ms,
                    });
                entry.count = entry.count.saturating_add(1);
                entry.last_timestamp_ms = timestamp_ms;
                return;
            }

            if s.entries.len() == s.cap {
                s.entries.pop_front();
            }
            let entry_seq = s.next_seq;
            s.next_seq += 1;
            s.entries.push_back(LogEntry {
                seq: entry_seq,
                timestamp_ms,
                direction,
                pd_address,
                code,
                name: code_name(direction, code),
                payload_hex: hex_encode(payload),
            });
        }
        // notify_waiters wakes every current waiter; they each
        // re-check the log and either return or sleep again. Cheap
        // because there are usually zero or one waiters.
        self.notify.notify_waiters();
    }

    /// Return entries with `seq >= since_seq`, capped at `limit`,
    /// filtered through `filter`. Suppressed entries (those that
    /// matched in range but were filtered out) are reported back in
    /// `LogPage::suppressed` so the agent can see they exist without
    /// scrolling them. `next_seq` in the returned page is
    /// `highest seq seen + 1` (across BOTH kept and suppressed
    /// entries) — pass it back as the next call's `since_seq` to
    /// read only newer entries.
    pub fn snapshot(&self, since_seq: u64, limit: usize, filter: EffectiveFilter) -> LogPage {
        let s = self.state.lock().expect("log mutex");
        let mut out = Vec::new();
        let mut highest_seen: Option<u64> = None;
        let mut suppressed_counts: BTreeMap<u8, u32> = BTreeMap::new();
        let mut suppressed_total: u32 = 0;

        // Push-filtered codes never enter the ring; seed the
        // suppression report with their lifetime counters so the
        // agent sees the heartbeat is alive regardless of `since_seq`.
        for ((_, code), pc) in &s.push_counts {
            let entry = suppressed_counts.entry(*code).or_insert(0);
            *entry = entry.saturating_add(pc.count);
            suppressed_total = suppressed_total.saturating_add(pc.count);
        }

        for e in &s.entries {
            if e.seq < since_seq {
                continue;
            }
            if out.len() >= limit {
                break;
            }
            // Advance the cursor across kept + read-suppressed
            // entries alike — otherwise a page full of nothing-but-
            // suppressed would re-page the same entries forever.
            highest_seen = Some(e.seq);
            if filter.passes(e.code) {
                out.push(e.clone());
            } else {
                *suppressed_counts.entry(e.code).or_insert(0) += 1;
                suppressed_total = suppressed_total.saturating_add(1);
            }
        }
        let by_code = suppressed_counts
            .into_iter()
            .map(|(code, count)| SuppressedCount { code, count })
            .collect();
        LogPage {
            entries: out,
            next_seq: highest_seen.map(|h| h + 1).unwrap_or(since_seq),
            total: s.entries.len() as u32,
            suppressed: Suppressed {
                total: suppressed_total,
                by_code,
            },
        }
    }

    /// Per-(direction, code) count across the entire current ring.
    /// Bypasses `get_log`'s filter — the point of the summary is to
    /// reveal what's noisy. Sorted by count desc so the loudest codes
    /// surface first.
    pub fn summary(&self) -> LogSummary {
        let s = self.state.lock().expect("log mutex");
        let mut stats: BTreeMap<(Direction, u8), LogCodeStat> = BTreeMap::new();

        // Seed with the push-filtered aggregates. They have no seq
        // (they never entered the ring), so first_seq/last_seq are
        // 0 placeholders — agents should rely on count +
        // last_timestamp_ms for these rows.
        for ((dir, code), pc) in &s.push_counts {
            stats.insert(
                (*dir, *code),
                LogCodeStat {
                    direction: *dir,
                    code: *code,
                    name: code_name(*dir, *code),
                    count: pc.count,
                    first_seq: 0,
                    last_seq: 0,
                    last_timestamp_ms: pc.last_timestamp_ms,
                },
            );
        }

        for e in &s.entries {
            let key = (e.direction, e.code);
            stats
                .entry(key)
                .and_modify(|st| {
                    st.count += 1;
                    st.last_seq = e.seq;
                    st.last_timestamp_ms = e.timestamp_ms;
                })
                .or_insert(LogCodeStat {
                    direction: e.direction,
                    code: e.code,
                    name: code_name(e.direction, e.code),
                    count: 1,
                    first_seq: e.seq,
                    last_seq: e.seq,
                    last_timestamp_ms: e.timestamp_ms,
                });
        }
        let total: u32 = stats.values().map(|r| r.count).sum();
        let mut by_code: Vec<LogCodeStat> = stats.into_values().collect();
        by_code.sort_by_key(|row| std::cmp::Reverse(row.count));
        LogSummary {
            total,
            by_code,
            next_seq: s.next_seq,
        }
    }

    /// Drop every entry but leave `next_seq` alone so external
    /// cursors remain unambiguous. Push-filtered counters reset to
    /// zero too — the agent's intent on `clear_log` is "fresh
    /// session", and a heartbeat counter from before is misleading.
    pub fn clear(&self) {
        let mut s = self.state.lock().expect("log mutex");
        s.entries.clear();
        s.push_counts.clear();
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

/// Result of `LogInner::snapshot`. Carries kept entries, the cursor
/// the agent should pass on its next call, and a per-code report of
/// how many entries got filtered out so the agent can confirm the
/// heartbeat is alive without scrolling through it.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    /// Pass back as `since_seq` to read the next page. Advances past
    /// suppressed entries too, so a heartbeat-only window doesn't
    /// re-page forever.
    pub next_seq: u64,
    /// Number of entries currently in the ring (after the snapshot).
    pub total: u32,
    /// Entries that matched the cursor range but were filtered out.
    /// Useful for "is anything happening, just hidden by my filter?".
    pub suppressed: Suppressed,
}

/// Filter as accepted from the MCP layer. Both fields are
/// `Option<Vec<u8>>` so the layer above can distinguish "not set"
/// (apply the default heartbeat filter) from "explicitly empty"
/// (no filter at all). Resolve into an [`EffectiveFilter`] before
/// passing into [`LogInner::snapshot`].
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct LogFilter {
    /// Codes to omit from the returned entries. Suppressed counts
    /// still appear in `suppressed`. Ignored if `include_codes` is
    /// also set.
    #[serde(default)]
    pub exclude_codes: Option<Vec<u8>>,
    /// If set, only include entries whose code is in this list;
    /// everything else is treated as suppressed.
    #[serde(default)]
    pub include_codes: Option<Vec<u8>>,
}

impl LogFilter {
    /// Apply the "default = exclude POLL+ACK" policy when neither
    /// list is supplied. An explicitly-empty `exclude_codes: []`
    /// stays empty (= no exclusions).
    pub fn resolve(self) -> EffectiveFilter {
        match (self.include_codes, self.exclude_codes) {
            (Some(inc), _) => EffectiveFilter::Include(inc),
            (None, Some(exc)) => EffectiveFilter::Exclude(exc),
            (None, None) => EffectiveFilter::Exclude(DEFAULT_NOISE_CODES.to_vec()),
        }
    }
}

/// Filter after policy resolution. Either an allow-list or a
/// deny-list. An empty `Exclude([])` matches every entry.
#[derive(Debug, Clone)]
pub enum EffectiveFilter {
    Include(Vec<u8>),
    Exclude(Vec<u8>),
}

impl EffectiveFilter {
    pub fn passes(&self, code: u8) -> bool {
        match self {
            EffectiveFilter::Include(allow) => allow.contains(&code),
            EffectiveFilter::Exclude(deny) => !deny.contains(&code),
        }
    }
}

/// Per-code count of suppressed entries during a snapshot.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct SuppressedCount {
    pub code: u8,
    pub count: u32,
}

/// Report of entries the filter dropped during a snapshot.
#[derive(Debug, Clone, Default, serde::Serialize, schemars::JsonSchema)]
pub struct Suppressed {
    /// Sum of all `by_code[].count`.
    pub total: u32,
    /// Per-code breakdown, sorted ascending by code.
    pub by_code: Vec<SuppressedCount>,
}

/// One row in [`LogSummary`] — count + cursor metadata for a single
/// (direction, code) pair across the entire current ring.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LogCodeStat {
    pub direction: Direction,
    pub code: u8,
    /// Spec-defined symbolic name for `(direction, code)`. See
    /// [`code_name`].
    pub name: &'static str,
    pub count: u32,
    pub first_seq: u64,
    pub last_seq: u64,
    pub last_timestamp_ms: u32,
}

/// Result of `LogInner::summary`. Tells the agent what's in the log
/// without serialising every entry — cheap "is there anything
/// interesting?" probe.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct LogSummary {
    /// Number of entries currently in the ring.
    pub total: u32,
    /// One row per (direction, code) pair, sorted by count descending.
    /// The first entries are typically the noisiest (POLL/ACK).
    pub by_code: Vec<LogCodeStat>,
    /// Next seq the ring will assign. Pass to `get_log(since_seq=...)`
    /// to read only entries arriving after this summary.
    pub next_seq: u64,
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
        // Use non-heartbeat codes (ID + PDID) so the ring fills; POLL
        // and ACK go to the heartbeat counter and never get a slot.
        let log = LogInner::new(4);
        log.push(Direction::Cmd, 0x10, 0x61, &[], 0);
        log.push(Direction::Reply, 0x10, 0x45, &[], 1);
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].seq, 0);
        assert_eq!(page.entries[1].seq, 1);
        assert_eq!(page.entries[0].code, 0x61);
        assert!(matches!(page.entries[0].direction, Direction::Cmd));
        // next_seq = highest returned + 1 → re-paging with this
        // cursor returns nothing new yet.
        assert_eq!(page.next_seq, 2);
    }

    #[test]
    fn snapshot_with_cursor_returns_only_new() {
        // Non-heartbeat codes (ID / CAP / KEYSET) so they enter the
        // ring; POLL/ACK would be aggregated by the push filter.
        let log = LogInner::new(8);
        log.push(Direction::Cmd, 0, 0x61, &[], 0);
        log.push(Direction::Cmd, 0, 0x62, &[], 1);
        let first = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(first.next_seq, 2);
        // Nothing added since → empty page, cursor unchanged.
        let second = log.snapshot(first.next_seq, 100, EffectiveFilter::Exclude(vec![]));
        assert!(second.entries.is_empty());
        assert_eq!(second.next_seq, 2);
        // Add an entry, page returns just it.
        log.push(Direction::Cmd, 0, 0x75, &[], 2);
        let third = log.snapshot(first.next_seq, 100, EffectiveFilter::Exclude(vec![]));
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
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(page.entries.len(), 2);
        // Oldest 3 should be gone; remaining are seq 3 and 4.
        assert_eq!(page.entries[0].seq, 3);
        assert_eq!(page.entries[1].seq, 4);
    }

    #[test]
    fn clear_preserves_seq() {
        let log = LogInner::new(4);
        log.push(Direction::Cmd, 0, 0x61, &[], 0);
        log.push(Direction::Cmd, 0, 0x62, &[], 1);
        log.clear();
        assert!(log.snapshot(0, 100, EffectiveFilter::Exclude(vec![])).entries.is_empty());
        log.push(Direction::Cmd, 0, 0x75, &[], 2);
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        // next_seq kept climbing across clear() — new entry is seq 2.
        assert_eq!(page.entries[0].seq, 2);
    }

    #[test]
    fn code_name_disambiguates_overlapping_codes_by_direction() {
        // Spec codes that agents commonly mix up — 0x69 is osdp_LED
        // (cmd), 0x6E is osdp_COMSET (cmd), 0x7B is osdp_ACURXSIZE
        // (cmd, NOT MFG — MFG is 0x80), 0x76 means osdp_CHLNG as a
        // cmd but osdp_CCRYPT as a reply.
        assert_eq!(code_name(Direction::Cmd, 0x69), "osdp_LED");
        assert_eq!(code_name(Direction::Cmd, 0x6E), "osdp_COMSET");
        assert_eq!(code_name(Direction::Cmd, 0x7B), "osdp_ACURXSIZE");
        assert_eq!(code_name(Direction::Cmd, 0x80), "osdp_MFG");
        assert_eq!(code_name(Direction::Cmd, 0x76), "osdp_CHLNG");
        assert_eq!(code_name(Direction::Reply, 0x76), "osdp_CCRYPT");
        // Routine codes.
        assert_eq!(code_name(Direction::Cmd, 0x60), "osdp_POLL");
        assert_eq!(code_name(Direction::Reply, 0x40), "osdp_ACK");
        assert_eq!(code_name(Direction::Reply, 0x45), "osdp_PDID");
        // NAK reason byte labels (Table 47 — prose only in the spec,
        // so we use human-readable lowercase labels).
        assert_eq!(code_name(Direction::Nak, 0x03), "unknown_cmd");
        assert_eq!(code_name(Direction::Nak, 0x09), "record_invalid");
        // Unknown codes get "?" — agent should fall back to the
        // numeric code field.
        assert_eq!(code_name(Direction::Cmd, 0xFF), "?");
    }

    #[test]
    fn log_entries_carry_symbolic_names() {
        let log = LogInner::new(8);
        log.push(Direction::Cmd, 0, 0x75, &[], 0); // KEYSET
        log.push(Direction::Nak, 0, 0x09, &[], 1); // record_invalid
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(page.entries[0].name, "osdp_KEYSET");
        assert_eq!(page.entries[1].name, "record_invalid");
    }

    #[test]
    fn filter_default_resolves_to_exclude_heartbeat() {
        let f: LogFilter = Default::default();
        match f.resolve() {
            EffectiveFilter::Exclude(deny) => {
                assert_eq!(deny, DEFAULT_NOISE_CODES.to_vec());
            }
            _ => panic!("expected Exclude default"),
        }
    }

    #[test]
    fn filter_explicit_empty_exclude_keeps_everything() {
        let f = LogFilter {
            exclude_codes: Some(vec![]),
            include_codes: None,
        };
        match f.resolve() {
            EffectiveFilter::Exclude(deny) => assert!(deny.is_empty()),
            _ => panic!("expected Exclude with empty list"),
        }
    }

    #[test]
    fn snapshot_default_filter_hides_heartbeat_and_reports_suppressed() {
        let log = LogInner::new(16);
        // 3× POLL/ACK heartbeat + one ID/PDID pair. POLL/ACK go
        // straight to the push counter (no ring slot), so the ring
        // only holds the two non-heartbeat entries (ID @ seq 0,
        // PDID @ seq 1).
        for i in 0..3 {
            log.push(Direction::Cmd, 0, 0x60, &[], i);
            log.push(Direction::Reply, 0, 0x40, &[], i);
        }
        log.push(Direction::Cmd, 0, 0x61, &[], 100);
        log.push(Direction::Reply, 0, 0x45, &[0xAA], 100);

        let filter = LogFilter::default().resolve();
        let page = log.snapshot(0, 100, filter);

        // Only ID + PDID survive — POLL/ACK never entered the ring.
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].code, 0x61);
        assert_eq!(page.entries[1].code, 0x45);

        // Cursor advances past the ring entries (next_seq = last
        // ring seq + 1 = 2). The heartbeat counter is decoupled
        // from the cursor model.
        assert_eq!(page.next_seq, 2);

        // Suppression report carries 3 POLL + 3 ACK from the push
        // counter so the agent sees the heartbeat is alive.
        assert_eq!(page.suppressed.total, 6);
        let counts: Vec<(u8, u32)> = page
            .suppressed
            .by_code
            .iter()
            .map(|c| (c.code, c.count))
            .collect();
        assert!(counts.contains(&(0x60, 3)));
        assert!(counts.contains(&(0x40, 3)));
    }

    #[test]
    fn heartbeat_pushes_never_grow_the_ring() {
        // A tiny 4-entry ring with 1000 POLL/ACK pushes: the ring
        // must stay empty (everything aggregated in the counter)
        // and `total` in the LogPage is 0.
        let log = LogInner::new(4);
        for i in 0..500 {
            log.push(Direction::Cmd, 0, 0x60, &[], i);
            log.push(Direction::Reply, 0, 0x40, &[], i);
        }
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(page.entries.len(), 0);
        assert_eq!(page.total, 0);
        // But the counter saw all 1000.
        assert_eq!(page.suppressed.total, 1000);

        // Summary surfaces the counter too — the ring has nothing
        // but POLL+ACK rows must still show up with count 500 each.
        let s = log.summary();
        assert_eq!(s.total, 1000);
        let poll = s
            .by_code
            .iter()
            .find(|r| r.code == 0x60 && r.direction == Direction::Cmd)
            .expect("POLL row");
        assert_eq!(poll.count, 500);
        let ack = s
            .by_code
            .iter()
            .find(|r| r.code == 0x40 && r.direction == Direction::Reply)
            .expect("ACK row");
        assert_eq!(ack.count, 500);
    }

    #[test]
    fn clear_resets_push_counters_too() {
        let log = LogInner::new(4);
        log.push(Direction::Cmd, 0, 0x60, &[], 0);
        log.push(Direction::Reply, 0, 0x40, &[], 0);
        log.clear();
        let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
        assert_eq!(page.suppressed.total, 0);
        let s = log.summary();
        assert_eq!(s.total, 0);
        assert!(s.by_code.is_empty());
    }

    #[test]
    fn snapshot_include_filter_returns_only_listed_codes() {
        let log = LogInner::new(8);
        // POLL push goes to the heartbeat counter (= 1 in suppressed
        // total). ID and PDID go to the ring; the Include([0x61])
        // filter keeps just ID and read-suppresses PDID.
        log.push(Direction::Cmd, 0, 0x60, &[], 0);
        log.push(Direction::Cmd, 0, 0x61, &[], 1);
        log.push(Direction::Reply, 0, 0x45, &[], 2);

        let page = log.snapshot(0, 100, EffectiveFilter::Include(vec![0x61]));
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].code, 0x61);
        // POLL (push-filtered, 1) + PDID (read-filtered, 1) = 2.
        assert_eq!(page.suppressed.total, 2);
    }

    #[test]
    fn summary_groups_by_direction_and_code_sorted_by_count_desc() {
        let log = LogInner::new(32);
        for i in 0..10 {
            log.push(Direction::Cmd, 0, 0x60, &[], i);
            log.push(Direction::Reply, 0, 0x40, &[], i);
        }
        log.push(Direction::Cmd, 0, 0x61, &[], 100);
        log.push(Direction::Reply, 0, 0x45, &[], 100);

        let s = log.summary();
        assert_eq!(s.total, 22);
        // POLL (10) and ACK (10) must be the loudest, in some order.
        let top_two: Vec<u8> = s.by_code.iter().take(2).map(|r| r.code).collect();
        assert!(top_two.contains(&0x60));
        assert!(top_two.contains(&0x40));
        // ID + PDID rows must each have count 1.
        assert!(s
            .by_code
            .iter()
            .any(|r| r.code == 0x61 && r.direction == Direction::Cmd && r.count == 1));
        assert!(s
            .by_code
            .iter()
            .any(|r| r.code == 0x45 && r.direction == Direction::Reply && r.count == 1));
    }

    #[test]
    fn find_command_at_or_after_finds_first_match() {
        // POLL is push-filtered and never enters the ring, so the
        // ring entries here are ID @ seq 0 and KEYSET @ seq 1.
        // `wait_for_command` on POLL is intentionally unsupported.
        let log = LogInner::new(8);
        log.push(Direction::Cmd, 0, 0x60, &[], 0); // POLL → counter
        log.push(Direction::Reply, 0, 0x40, &[], 1); // ACK → counter
        log.push(Direction::Cmd, 0, 0x61, &[], 2); // ID    @ ring seq 0
        log.push(Direction::Cmd, 0, 0x75, &[], 3); // KEYSET @ ring seq 1

        // ID is at ring seq 0.
        let e = log.find_command_at_or_after(0, 0x61).unwrap();
        assert_eq!(e.seq, 0);
        // From cursor 1, the seq-0 ID is skipped; KEYSET is at 1.
        let e = log.find_command_at_or_after(1, 0x75).unwrap();
        assert_eq!(e.seq, 1);

        // POLL is push-filtered → not findable in the ring.
        assert!(log.find_command_at_or_after(0, 0x60).is_none());

        // Nothing matches 0x99.
        assert!(log.find_command_at_or_after(0, 0x99).is_none());
    }
}
