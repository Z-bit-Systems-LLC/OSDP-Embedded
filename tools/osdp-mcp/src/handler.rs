// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Application command handler that turns inbound ACU commands into
//! PD replies.
//!
//! Milestone 2 ships the "default" behavior — the same baseline the
//! [`osdp-pd-mock`](../../../tools/osdp-pd-mock/main.c) tool provides:
//! POLL → ACK, ID → PDID, CAP → PDCAP, LED / BUZ / OUT / TEXT /
//! KEYSET → ACK, everything else → NAK (unknown command).
//!
//! `osdp_COMSET` never reaches this handler: the C library intercepts it,
//! builds the `osdp_COM` reply, and switches the PD address itself. The
//! virtual PD's COMSET policy lives in [`DefaultComsetHandler`] instead
//! (registered in the actor). One consequence: the override / fault-
//! injection tools can't target COMSET, the same as the SC handshake.
//!
//! Later milestones add an override table the agent can populate via
//! `set_reply_for` etc.; the override check will be wired into the
//! match below.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use osdp_embedded::messages::{
    Keyset, Pdcap, PdcapRecord, Pdid, OSDP_CMD_BUZ, OSDP_CMD_CAP, OSDP_CMD_ID, OSDP_CMD_KEYSET,
    OSDP_CMD_LED, OSDP_CMD_LSTAT, OSDP_CMD_OUT, OSDP_CMD_POLL, OSDP_CMD_TEXT,
    OSDP_KEYSET_KEY_TYPE_SCBK, OSDP_NAK_UNKNOWN_CMD, OSDP_REPLY_ACK, OSDP_REPLY_LSTATR,
    OSDP_REPLY_PDCAP, OSDP_REPLY_PDID,
};
use osdp_embedded::pd::{
    CommandHandler, ComsetHandler, FileFragment, FileReceiver, FileReject, Reply,
};

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

/// COMSET policy for the virtual PD. The C library builds the `osdp_COM`
/// reply and switches the PD's address on its own; this handler decides the
/// values that reply reports and reacts once the change is live.
///
/// Baud is deliberately pinned to the port's configured rate: the MCP's live
/// serial link isn't reconfigured mid-session (change it with `pd_configure`
/// instead), so reporting a new baud in `osdp_COM` while staying at the old
/// rate would desync the link. Pinning the current baud is the spec 6.13
/// "unable to comply — report what I'll use" behavior, and keeps the wire
/// working while the ACU's requested address still takes effect.
pub struct DefaultComsetHandler {
    baud: u32,
}

impl DefaultComsetHandler {
    pub fn new(baud: u32) -> Self {
        Self { baud }
    }
}

impl ComsetHandler for DefaultComsetHandler {
    fn decide(&mut self, req_address: u8, _req_baud: u32) -> (u8, u32) {
        // Accept the address; keep our baud (see struct docs).
        (req_address, self.baud)
    }

    fn applied(&mut self, address: u8, baud: u32) {
        tracing::info!(
            address = format!("0x{:02X}", address),
            baud,
            "osdp_COMSET applied — PD now answering on the new address"
        );
    }
}

/// Default `osdp_FILETRANSFER` receiver for the virtual PD. Registered in
/// **streaming** mode (no reassembly buffer), so it accepts a file of any size
/// without a ceiling — the MCP PD is a protocol simulator, not a firmware
/// target, so it just logs progress and accepts every fragment (the PD then
/// reports "proceed" mid-file and "processed" on completion). A consumer that
/// needs to reject a file (bad header, unsupported type) can extend this to
/// return [`FileReject`].
pub struct DefaultFileReceiver;

impl FileReceiver for DefaultFileReceiver {
    fn on_fragment(&mut self, f: &FileFragment) -> Result<(), FileReject> {
        // Streaming mode: read `received` (cumulative), not `data` (empty).
        tracing::info!(
            ft_type = format!("0x{:02X}", f.ft_type),
            received = f.received,
            total = f.total_size,
            offset = f.offset,
            complete = f.complete,
            "osdp_FILETRANSFER fragment accepted"
        );
        Ok(())
    }
}

/// Default PDID — matches the osdp-pd-mock CLI tool so behavior is
/// consistent across the two interop harnesses. Vendor "ZBC" is a
/// placeholder; consumers override it at runtime via the `pd_set_pdid`
/// tool when they want a realistic device identity.
pub fn default_pdid() -> Pdid {
    Pdid {
        vendor_code: *b"ZBC",
        model: 0x01,
        version: 0x00,
        serial: 0x0000_0001,
        firmware_major: 0,
        firmware_minor: 1,
        firmware_build: 0,
    }
}

/// Default PDCAP, mirroring OSDP.Net's PDConsole reference PD
/// (src/PDConsole/appsettings.json) so an ACU that interoperates with
/// PDConsole treats this PD identically. Kept in lockstep with
/// osdp-pd-mock's `kDefaultPdcap`. Function codes follow spec Annex B.
///
/// Function code 9 (Communication Security) is what gates Secure
/// Channel: per spec B.10 BOTH bytes are "Bit 0 = AES128 support", so
/// the key-exchange (num_objects) byte must be 0x01. The previous value
/// 0x04 left bit 0 CLEAR — advertising "no AES128 key exchange" — so a
/// spec-conformant ACU never initiated a handshake and the link stayed
/// clear-text.
pub fn default_pdcap() -> Pdcap {
    Pdcap {
        records: vec![
            PdcapRecord {
                function_code: 1,
                compliance_level: 4,
                num_objects: 1,
            }, // ContactStatusMonitoring
            PdcapRecord {
                function_code: 2,
                compliance_level: 4,
                num_objects: 1,
            }, // OutputControl
            PdcapRecord {
                function_code: 3,
                compliance_level: 1,
                num_objects: 0,
            }, // CardDataFormat (num must be 0x00 per spec B.4)
            PdcapRecord {
                function_code: 4,
                compliance_level: 4,
                num_objects: 1,
            }, // ReaderLEDControl
            PdcapRecord {
                function_code: 5,
                compliance_level: 2,
                num_objects: 1,
            }, // ReaderAudibleOutput
            PdcapRecord {
                function_code: 6,
                compliance_level: 1,
                num_objects: 1,
            }, // ReaderTextOutput
            PdcapRecord {
                function_code: 8,
                compliance_level: 1,
                num_objects: 0,
            }, // CheckCharacterSupport (num must be 0x00 per spec B.9)
            PdcapRecord {
                function_code: 9,
                compliance_level: 1,
                num_objects: 1,
            }, // CommunicationSecurity (AES128)
            PdcapRecord {
                function_code: 12,
                compliance_level: 0,
                num_objects: 0,
            }, // SmartCardSupport
            PdcapRecord {
                function_code: 13,
                compliance_level: 0,
                num_objects: 1,
            }, // Readers
            PdcapRecord {
                function_code: 16,
                compliance_level: 2,
                num_objects: 0,
            }, // OSDPVersion
            PdcapRecord {
                function_code: 17,
                compliance_level: 1,
                num_objects: 0,
            }, // SecurePDBiometricsMatchSupport (spec B.18)
        ],
    }
}

/// Atomic counter tracking how many upcoming replies the handler
/// should swallow silently. Shared with the actor / PdHandle so
/// `drop_next_n_replies` can write it while the handler decrements.
pub type DropCounter = Arc<AtomicU32>;

/// A KEYSET-rotated SCBK captured by the handler, waiting for the actor
/// loop to fold it into the remembered SC config. `None` means no pending
/// rotation.
///
/// The C library rotates the PD's live SCBK in place for a well-formed
/// `osdp_KEYSET`, but the actor tracks the SC posture separately (in
/// `Slot.sc` / the remembered config) so it can rebuild the PD on a Power
/// Cycle / stop-start. Without this hand-off a rebuild re-applies the
/// original install-time SCBK-D and silently drops the rotated key,
/// breaking Secure Channel exactly after an ACU keys the PD — which is the
/// whole point of a KEYSET. Written by the handler on an accepted KEYSET;
/// drained once per tick by the actor loop.
pub type SharedKeyRotation = Arc<Mutex<Option<[u8; 16]>>>;

/// The PD identity reported in the `osdp_PDID` (0x45) reply. Shared
/// (`Arc<Mutex<_>>`) so the `pd_get_pdid` / `pd_set_pdid` tools on the
/// async side can read and mutate it while the handler — pinned to the
/// PD actor thread — serves the reply from the current value. Created
/// once per process in `PdHandle::spawn`, so edits persist across
/// `pd_stop` / `pd_configure` like the override and event state do.
pub type SharedPdid = Arc<Mutex<Pdid>>;

/// The capability set reported in the `osdp_PDCAP` (0x46) reply. Shared
/// (`Arc<Mutex<_>>`) so the `pd_get_pdcap` / `pd_set_capability` /
/// `pd_reset_pdcap` tools on the async side can read and mutate it while
/// the handler — pinned to the PD actor thread — serves the reply from
/// the current value. Created once per process in `PdHandle::spawn`, so
/// edits persist across `pd_stop` / `pd_configure` like the PDID and
/// override state do.
pub type SharedPdcap = Arc<Mutex<Pdcap>>;

/// Application handler. Reports its PDID and PDCAP from shared handles
/// (so the `pd_set_*` tools can edit them live) and serialises replies
/// into a scratch buffer; the `Reply.payload` slice the PD copies out
/// borrows from that buffer.
pub struct DefaultHandler {
    pub pdid: SharedPdid,
    pub pdcap: SharedPdcap,
    scratch: [u8; SCRATCH_LEN],
    stats: Arc<Mutex<PdStats>>,
    log: Arc<LogInner>,
    overrides: OverrideMap,
    events: EventQueue,
    drop_remaining: DropCounter,
    pd_address: u8,
    epoch: Instant,
    /// Where an accepted KEYSET stashes its rotated SCBK for the actor
    /// loop to pick up. Defaults to a private, unwatched cell (the test
    /// constructors); the actor binds the shared one via
    /// [`DefaultHandler::with_key_rotation`].
    key_rotation: SharedKeyRotation,
}

impl DefaultHandler {
    /// Build a handler with a private, default PDID. Convenient for
    /// tests that don't need to share identity with the async side.
    pub fn new(
        stats: Arc<Mutex<PdStats>>,
        log: Arc<LogInner>,
        overrides: OverrideMap,
        events: EventQueue,
        drop_remaining: DropCounter,
        pd_address: u8,
    ) -> Self {
        Self::with_pdid(
            Arc::new(Mutex::new(default_pdid())),
            Arc::new(Mutex::new(default_pdcap())),
            stats,
            log,
            overrides,
            events,
            drop_remaining,
            pd_address,
        )
    }

    /// Build a handler that serves its `osdp_PDID` and `osdp_PDCAP`
    /// replies from the given shared handles, so the `pd_set_pdid` /
    /// `pd_set_capability` tools can mutate the reported identity and
    /// capabilities live.
    #[allow(clippy::too_many_arguments)]
    pub fn with_pdid(
        pdid: SharedPdid,
        pdcap: SharedPdcap,
        stats: Arc<Mutex<PdStats>>,
        log: Arc<LogInner>,
        overrides: OverrideMap,
        events: EventQueue,
        drop_remaining: DropCounter,
        pd_address: u8,
    ) -> Self {
        Self {
            pdid,
            pdcap,
            scratch: [0; SCRATCH_LEN],
            stats,
            log,
            overrides,
            events,
            drop_remaining,
            pd_address,
            epoch: Instant::now(),
            key_rotation: Arc::new(Mutex::new(None)),
        }
    }

    /// Bind the shared KEYSET-rotation cell so an accepted `osdp_KEYSET`
    /// hands its new SCBK back to the actor loop (which folds it into the
    /// remembered SC config so a rebuild survives the rotation). The actor
    /// calls this in `open_pd`; tests that don't care leave the private
    /// default in place.
    pub fn with_key_rotation(mut self, cell: SharedKeyRotation) -> Self {
        self.key_rotation = cell;
        self
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
                // Snapshot the shared PDID (a poisoned lock falls back
                // to the default identity rather than failing the reply).
                let pdid = self
                    .pdid
                    .lock()
                    .map(|g| *g)
                    .unwrap_or_else(|_| default_pdid());
                let n = pdid.build(&mut self.scratch)?;
                (OSDP_REPLY_PDID, n)
            }
            OSDP_CMD_CAP => {
                // Snapshot the shared PDCAP (a poisoned lock falls back
                // to the default capability set rather than failing the
                // reply).
                let pdcap = self
                    .pdcap
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_else(|_| default_pdcap());
                let n = pdcap.build(&mut self.scratch)?;
                (OSDP_REPLY_PDCAP, n)
            }
            OSDP_CMD_LED | OSDP_CMD_BUZ | OSDP_CMD_OUT | OSDP_CMD_TEXT => (OSDP_REPLY_ACK, 0),
            OSDP_CMD_KEYSET => {
                // The C library rotates the PD's live SCBK in place for a
                // well-formed SCBK KEYSET (and NAKs a malformed one,
                // keeping the old key). Mirror that acceptance test and
                // stash the rotated key so the actor loop can update its
                // remembered SC config; otherwise a later rebuild (Power
                // Cycle / stop-start) would re-apply the install-time
                // SCBK-D and drop the new key, breaking Secure Channel
                // right after the ACU keyed the PD. We still just ACK —
                // the core applies the rotation on the way out.
                if let Ok(ks) = Keyset::decode(payload) {
                    if ks.key_type == OSDP_KEYSET_KEY_TYPE_SCBK
                        && ks.key_length == 16
                        && ks.key_data.len() == 16
                    {
                        let mut key = [0u8; 16];
                        key.copy_from_slice(ks.key_data);
                        if let Ok(mut cell) = self.key_rotation.lock() {
                            *cell = Some(key);
                        }
                    }
                }
                (OSDP_REPLY_ACK, 0)
            }
            OSDP_CMD_LSTAT => {
                // Local status query. Hard-coded "all clear" for now:
                // tamper=0, power=0 (spec D.2.1 LSTATR payload is two
                // bytes). TODO: the library has no way for a consumer
                // to supply real tamper/power state in response to an
                // LSTAT *command* — only via the inject_local_status
                // POLL event. A future API should let the application
                // own this reply rather than us synthesising a constant.
                self.scratch[0] = 0; // tamper: not tampered
                self.scratch[1] = 0; // power: OK
                (OSDP_REPLY_LSTATR, 2)
            }
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
