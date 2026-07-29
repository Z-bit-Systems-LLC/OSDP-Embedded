// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Application command handler that turns inbound ACU commands into
//! PD replies.
//!
//! Milestone 2 ships the "default" behavior — the same baseline the
//! [`osdp-pd-mock`](../../../tools/osdp-pd-mock/main.c) tool provides:
//! POLL → ACK, ID → PDID, LED / BUZ / OUT / TEXT / KEYSET → ACK,
//! everything else → NAK (unknown command).
//!
//! `osdp_COMSET` and `osdp_CAP` never reach this handler: the C library
//! intercepts both. COMSET builds the `osdp_COM` reply and switches the PD
//! address itself (the virtual PD's COMSET policy lives in
//! [`DefaultComsetHandler`] instead, registered in the actor). CAP is
//! answered directly from the capability set bound via `Pd::set_pdcap`
//! (`pd_actor::open_pd` binds it unconditionally). One consequence: the
//! override / fault-injection tools can't target either, the same as the
//! SC handshake.
//!
//! Later milestones add an override table the agent can populate via
//! `set_reply_for` etc.; the override check will be wired into the
//! match below.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use osdp_embedded::messages::{
    Keyset, Out, Pdid, OSDP_CMD_BUZ, OSDP_CMD_ID, OSDP_CMD_KEYSET, OSDP_CMD_LED, OSDP_CMD_OUT,
    OSDP_CMD_POLL, OSDP_CMD_TEXT, OSDP_KEYSET_KEY_TYPE_SCBK, OSDP_NAK_UNKNOWN_CMD, OSDP_REPLY_ACK,
    OSDP_REPLY_PDID,
};
use osdp_embedded::pd::{
    CommandHandler, ComsetHandler, FileFragment, FileReceiver, FileReject, Reply,
};

use crate::events::{self, EventQueue};
use crate::log::{Direction, LogInner};
use crate::overrides::{self, OverrideMap, OverrideReply};
use crate::serial_transport::BaudControl;
use crate::status::SharedStatus;

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
/// values that reply reports and enacts the baud change once it's live.
///
/// Both the address and the baud in the request are accepted. The C core owns
/// the address switch (it filters and stamps frames); the baud is the MCP's
/// job because the C core has no UART — so `applied` stages a retune on the
/// [`BaudControl`], which the [`SerialTransport`](crate::serial_transport)
/// picks up on its next I/O. Ordering matters (spec 6.13): the `osdp_COM`
/// reply reporting the new rate goes out at the *old* rate, then the port
/// retunes — the transport drains the reply before switching so its tail
/// isn't clocked out at the wrong baud and the ACU follows cleanly.
pub struct DefaultComsetHandler {
    baud_ctl: BaudControl,
}

impl DefaultComsetHandler {
    pub fn new(baud_ctl: BaudControl) -> Self {
        Self { baud_ctl }
    }
}

impl ComsetHandler for DefaultComsetHandler {
    fn decide(&mut self, req_address: u8, req_baud: u32) -> (u8, u32) {
        // Accept both the requested address and baud; the transport retunes
        // to the new rate when `applied` fires below.
        (req_address, req_baud)
    }

    fn applied(&mut self, address: u8, baud: u32) {
        // Stage the retune; the transport applies it on its next read/write,
        // after this COMSET reply has drained at the old rate.
        self.baud_ctl.request(baud);
        tracing::info!(
            address = format!("0x{:02X}", address),
            baud,
            "osdp_COMSET applied — PD now answering on the new address, retuning to new baud"
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

/// Default multi-part `osdp_MFG` (spec 5.10) receiver for the virtual PD.
/// Registered so the reassembly buffer backing the default PDCAP's fn 11
/// ("Largest Combined Message") claim actually exists — without a bound
/// receiver, that claim would fail `Pd::set_pdcap`'s validation the moment
/// it's non-zero. Just logs the reassembled message and ACKs; a consumer
/// that wants to decode vendor-specific multi-part payloads can extend
/// this to return an `osdp_MFGREP`.
pub struct DefaultMfgReceiver;

impl osdp_embedded::pd::MfgReceiver for DefaultMfgReceiver {
    fn on_message<'a>(
        &'a mut self,
        vendor_code: &[u8; 3],
        data: &[u8],
    ) -> osdp_embedded::Result<Option<Reply<'a>>> {
        tracing::info!(
            vendor_code = format!(
                "{:02X}{:02X}{:02X}",
                vendor_code[0], vendor_code[1], vendor_code[2]
            ),
            len = data.len(),
            "osdp_MFG multi-part message reassembled"
        );
        Ok(None)
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

/// Application handler. Reports its PDID from a shared handle (so
/// `pd_set_pdid` can edit it live) and serialises replies into a scratch
/// buffer; the `Reply.payload` slice the PD copies out borrows from that
/// buffer.
///
/// `osdp_CAP` never reaches this handler once a capability set is bound —
/// see `PdHandle::set_pdcap` / `pd_actor::open_pd` — so there is no PDCAP
/// field here the way there is a PDID one; the C library answers it
/// directly from `osdp::pd::Pd::set_pdcap`.
pub struct DefaultHandler {
    pub pdid: SharedPdid,
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
    /// Monitored conditions behind the four status queries. The PD answers
    /// osdp_LSTAT / ISTAT / OSTAT / RSTAT from the providers bound in
    /// `pd_actor::open_pd`, so this handler only ever *writes* it — the
    /// osdp_OUT arm records commanded relay state so a later osdp_OSTAT is
    /// truthful. `None` in the test constructors, which have no PD actor
    /// binding providers; the actor supplies it via
    /// [`DefaultHandler::with_status`].
    status: Option<SharedStatus>,
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
            stats,
            log,
            overrides,
            events,
            drop_remaining,
            pd_address,
        )
    }

    /// Build a handler that serves its `osdp_PDID` reply from the given
    /// shared handle, so the `pd_set_pdid` tool can mutate the reported
    /// identity live.
    #[allow(clippy::too_many_arguments)]
    pub fn with_pdid(
        pdid: SharedPdid,
        stats: Arc<Mutex<PdStats>>,
        log: Arc<LogInner>,
        overrides: OverrideMap,
        events: EventQueue,
        drop_remaining: DropCounter,
        pd_address: u8,
    ) -> Self {
        Self {
            pdid,
            scratch: [0; SCRATCH_LEN],
            stats,
            log,
            overrides,
            events,
            drop_remaining,
            pd_address,
            epoch: Instant::now(),
            key_rotation: Arc::new(Mutex::new(None)),
            status: None,
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

    /// Bind the shared status block so `osdp_OUT` commands are recorded into
    /// the output state the `osdp_OSTAT` provider reports. Same arrangement
    /// as [`DefaultHandler::with_key_rotation`]: the actor calls this in
    /// `open_pd`, tests that don't care leave it unbound.
    pub fn with_status(mut self, status: SharedStatus) -> Self {
        self.status = Some(status);
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
            // osdp_CAP never reaches here once a capability set is bound via
            // `Pd::set_pdcap` (done unconditionally in `pd_actor::open_pd`)
            // — the C library answers it directly. Falling through to the
            // `_` arm below (NAK 0x03) only happens if that binding somehow
            // failed, which `open_pd` logs loudly if it ever does.
            OSDP_CMD_OUT => {
                // Record what the ACU commanded so a later osdp_OSTAT
                // reports the real relay state instead of a constant. The
                // reply is a plain ACK either way — a payload we can't
                // decode is still ACKed, matching the previous behaviour;
                // we simply have nothing to record.
                if let Some(status) = self.status.as_ref() {
                    if let Ok(records) = Out::decode(payload) {
                        if let Ok(mut s) = status.lock() {
                            for r in &records.records {
                                s.apply_output(r.output_no, r.control_code);
                            }
                        }
                    }
                }
                (OSDP_REPLY_ACK, 0)
            }
            OSDP_CMD_LED | OSDP_CMD_BUZ | OSDP_CMD_TEXT => (OSDP_REPLY_ACK, 0),
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
            // osdp_LSTAT / ISTAT / OSTAT / RSTAT never reach here: the PD
            // answers all four from the status providers bound in
            // `pd_actor::open_pd`, which build the *STATR replies from the
            // shared status block. This handler used to synthesise a
            // constant "all clear" LSTATR and NAK the other three.
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
