// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Application command handler that turns inbound ACU commands into
//! PD replies.
//!
//! Milestone 2 ships the "default" behavior — the same baseline the
//! [`osdp-pd-mock`](../../../tools/osdp-pd-mock/main.c) tool provides:
//! POLL → ACK, ID → PDID, CAP → PDCAP, LED / BUZ / OUT / TEXT /
//! KEYSET / COMSET → ACK, everything else → NAK (unknown command).
//!
//! Later milestones add an override table the agent can populate via
//! `set_reply_for` etc.; the override check will be wired into the
//! match below.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use osdp_embedded::messages::{
    Pdcap, PdcapRecord, Pdid, OSDP_CMD_BUZ, OSDP_CMD_CAP, OSDP_CMD_COMSET, OSDP_CMD_ID,
    OSDP_CMD_KEYSET, OSDP_CMD_LED, OSDP_CMD_OUT, OSDP_CMD_POLL, OSDP_CMD_TEXT,
    OSDP_NAK_UNKNOWN_CMD, OSDP_REPLY_ACK, OSDP_REPLY_PDCAP, OSDP_REPLY_PDID,
};
use osdp_embedded::pd::{CommandHandler, Reply};

use crate::events::{self, EventQueue};
use crate::log::{Direction, LogInner};
use crate::overrides::{self, OverrideMap, OverrideReply};

/// PD TX buffer cap as defined by the C side
/// (`OSDP_PD_TX_BUF_LEN` in pd/include/osdp/osdp_pd.h). We size the
/// scratch buffer the handler builds replies into to match — any
/// reply that doesn't fit is a programming error, not user input.
const SCRATCH_LEN: usize = 256;

/// Counters the PD actor exposes through `pd_status`. Shared with
/// the handler so it can stamp the latest cmd/reply on every call.
#[derive(Default, Debug, Clone)]
pub struct PdStats {
    pub last_command_at_ms: Option<u32>,
    pub last_reply_at_ms: Option<u32>,
    pub last_cmd_code: Option<u8>,
    pub last_reply_code: Option<u8>,
}

/// Default PDID — matches the osdp-pd-mock CLI tool so behavior is
/// consistent across the two interop harnesses. Vendor "ZBC" is a
/// placeholder; consumers should override via a future pd_set_pdid
/// tool once they want a realistic device identity.
pub fn default_pdid() -> Pdid {
    Pdid {
        vendor_code: [b'Z', b'B', b'C'],
        model: 0x01,
        version: 0x00,
        serial: 0x0000_0001,
        firmware_major: 0,
        firmware_minor: 1,
        firmware_build: 0,
    }
}

/// Default PDCAP — same minimal set as osdp-pd-mock: one contact
/// monitor / output / card-data-format / reader-LED / buzzer / text
/// output, plus four "CRC support" objects on function code 9.
pub fn default_pdcap() -> Pdcap {
    Pdcap {
        records: vec![
            PdcapRecord {
                function_code: 1,
                compliance_level: 1,
                num_objects: 1,
            }, // contact monitor
            PdcapRecord {
                function_code: 2,
                compliance_level: 1,
                num_objects: 1,
            }, // output control
            PdcapRecord {
                function_code: 3,
                compliance_level: 1,
                num_objects: 1,
            }, // card data fmt
            PdcapRecord {
                function_code: 4,
                compliance_level: 1,
                num_objects: 1,
            }, // reader LED ctrl
            PdcapRecord {
                function_code: 5,
                compliance_level: 1,
                num_objects: 1,
            }, // audible
            PdcapRecord {
                function_code: 6,
                compliance_level: 1,
                num_objects: 1,
            }, // text output
            PdcapRecord {
                function_code: 9,
                compliance_level: 1,
                num_objects: 4,
            }, // CRC support
        ],
    }
}

/// Atomic counter tracking how many upcoming replies the handler
/// should swallow silently. Shared with the actor / PdHandle so
/// `drop_next_n_replies` can write it while the handler decrements.
pub type DropCounter = Arc<AtomicU32>;

/// Application handler. Owns the PDID/PDCAP it reports and a scratch
/// buffer the build helpers serialize into; the `Reply.payload` slice
/// the PD copies out borrows from this buffer.
pub struct DefaultHandler {
    pub pdid: Pdid,
    pub pdcap: Pdcap,
    scratch: [u8; SCRATCH_LEN],
    stats: Arc<Mutex<PdStats>>,
    log: Arc<LogInner>,
    overrides: OverrideMap,
    events: EventQueue,
    drop_remaining: DropCounter,
    pd_address: u8,
    epoch: Instant,
}

impl DefaultHandler {
    pub fn new(
        stats: Arc<Mutex<PdStats>>,
        log: Arc<LogInner>,
        overrides: OverrideMap,
        events: EventQueue,
        drop_remaining: DropCounter,
        pd_address: u8,
    ) -> Self {
        Self {
            pdid: default_pdid(),
            pdcap: default_pdcap(),
            scratch: [0; SCRATCH_LEN],
            stats,
            log,
            overrides,
            events,
            drop_remaining,
            pd_address,
            epoch: Instant::now(),
        }
    }

    /// Emit a pre-baked reply borrowed from `self.scratch`. Shared
    /// between the override-table path and the events path so the
    /// scratch-copy + stats-stamp + log-push logic stays in one place.
    fn emit_canned(
        &mut self,
        ov: OverrideReply,
        cmd_code: u8,
        now: u32,
    ) -> osdp_embedded::Result<Reply<'_>> {
        if ov.payload.len() > self.scratch.len() {
            // Programmer error — replies shouldn't exceed
            // OSDP_PD_TX_BUF_LEN. Drop silently rather than panic;
            // the agent will see the absence of a reply.
            return Err(osdp_embedded::Error::BadPayload);
        }
        self.scratch[..ov.payload.len()].copy_from_slice(&ov.payload);
        if let Ok(mut s) = self.stats.lock() {
            s.last_command_at_ms = Some(now);
            s.last_cmd_code = Some(cmd_code);
            s.last_reply_at_ms = Some(now);
            s.last_reply_code = Some(ov.code);
        }
        let reply_payload = &self.scratch[..ov.payload.len()];
        self.log.push(
            Direction::Reply,
            self.pd_address,
            ov.code,
            reply_payload,
            now,
        );
        Ok(Reply {
            code: ov.code,
            payload: reply_payload,
        })
    }
}

impl CommandHandler for DefaultHandler {
    fn handle<'a>(&'a mut self, cmd_code: u8, payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        let now = self.epoch.elapsed().as_millis() as u32;

        // Log the inbound command first, so the agent sees it even
        // if we end up returning an error below.
        self.log
            .push(Direction::Cmd, self.pd_address, cmd_code, payload, now);

        // Fault injection: drop the next N replies silently.
        // Returning a non-NotSupported error makes the C library
        // skip emitting a reply (see osdp_embedded::pd docs), which
        // is exactly the "PD went deaf" scenario for testing the
        // ACU's offline-detection path.
        if self
            .drop_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                if n > 0 {
                    Some(n - 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            if let Ok(mut s) = self.stats.lock() {
                s.last_command_at_ms = Some(now);
                s.last_cmd_code = Some(cmd_code);
            }
            return Err(osdp_embedded::Error::BadPayload);
        }

        // Override table wins over events and over the default
        // behavior. take_for both pops scripted steps and clones the
        // resulting reply, so we don't hold the override mutex while
        // copying into scratch.
        if let Some(ov) = overrides::take_for(&self.overrides, cmd_code) {
            return self.emit_canned(ov, cmd_code, now);
        }

        // Events are PD-initiated reports waiting for a POLL to
        // surface them — RAW for card reads, KEYPAD for key
        // presses, LSTATR for tamper/power changes. One per POLL,
        // in FIFO order. When the queue's empty the POLL gets a
        // plain ACK below.
        if cmd_code == OSDP_CMD_POLL {
            if let Some(ev) = events::pop(&self.events) {
                return self.emit_canned(ev, cmd_code, now);
            }
        }

        // Decide the reply (and serialise payload into scratch)
        // before touching stats — keeps the &mut self.scratch borrow
        // clean of any cross-field borrows.
        let (reply_code, payload_len) = match cmd_code {
            OSDP_CMD_POLL => (OSDP_REPLY_ACK, 0),
            OSDP_CMD_ID => {
                let n = self.pdid.build(&mut self.scratch)?;
                (OSDP_REPLY_PDID, n)
            }
            OSDP_CMD_CAP => {
                let n = self.pdcap.build(&mut self.scratch)?;
                (OSDP_REPLY_PDCAP, n)
            }
            OSDP_CMD_LED | OSDP_CMD_BUZ | OSDP_CMD_OUT | OSDP_CMD_TEXT | OSDP_CMD_KEYSET
            | OSDP_CMD_COMSET => (OSDP_REPLY_ACK, 0),
            _ => {
                // Library will synthesise NAK 0x03; record it now
                // since we won't get a hook on the outbound path.
                self.log.push(
                    Direction::Nak,
                    self.pd_address,
                    OSDP_NAK_UNKNOWN_CMD,
                    &[],
                    now,
                );
                if let Ok(mut s) = self.stats.lock() {
                    s.last_command_at_ms = Some(now);
                    s.last_cmd_code = Some(cmd_code);
                }
                return Err(osdp_embedded::Error::NotSupported);
            }
        };

        // Stats stamp covers both the command arrival and our reply,
        // close enough — the two events happen inside the same tick.
        if let Ok(mut s) = self.stats.lock() {
            s.last_command_at_ms = Some(now);
            s.last_cmd_code = Some(cmd_code);
            s.last_reply_at_ms = Some(now);
            s.last_reply_code = Some(reply_code);
        }

        let reply_payload = &self.scratch[..payload_len];
        self.log.push(
            Direction::Reply,
            self.pd_address,
            reply_code,
            reply_payload,
            now,
        );

        Ok(Reply {
            code: reply_code,
            payload: reply_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events;
    use crate::log::LogInner;
    use crate::overrides;
    use osdp_embedded::pd::CommandHandler;

    fn make_handler(drops: u32) -> (DefaultHandler, DropCounter) {
        let stats = Arc::new(Mutex::new(PdStats::default()));
        let log = Arc::new(LogInner::new(16));
        let ovmap = overrides::new_map();
        let evq = events::new_queue();
        let drop_counter: DropCounter = Arc::new(AtomicU32::new(drops));
        let h = DefaultHandler::new(stats, log, ovmap, evq, Arc::clone(&drop_counter), 0x10);
        (h, drop_counter)
    }

    #[test]
    fn drop_counter_silences_n_replies_then_resumes() {
        let (mut h, drops) = make_handler(2);

        // First two POLLs return Err(BadPayload), which causes the C
        // library to drop the reply silently.
        let r1 = h.handle(OSDP_CMD_POLL, &[]);
        assert!(matches!(r1, Err(osdp_embedded::Error::BadPayload)));
        assert_eq!(drops.load(Ordering::Relaxed), 1);

        let r2 = h.handle(OSDP_CMD_POLL, &[]);
        assert!(matches!(r2, Err(osdp_embedded::Error::BadPayload)));
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // Third POLL goes through to the default ACK behavior.
        let r3 = h.handle(OSDP_CMD_POLL, &[]).expect("third POLL ok");
        assert_eq!(r3.code, OSDP_REPLY_ACK);
        assert!(r3.payload.is_empty());
        // Counter stays at 0 — no underflow.
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn drop_counter_zero_passes_through() {
        let (mut h, drops) = make_handler(0);
        let r = h.handle(OSDP_CMD_POLL, &[]).unwrap();
        assert_eq!(r.code, OSDP_REPLY_ACK);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
}
