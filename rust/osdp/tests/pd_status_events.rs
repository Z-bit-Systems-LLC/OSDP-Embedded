// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! End-to-end Rust integration tests for the PD APIs added by the
//! PD-completion work: status providers, the poll-response event queue,
//! multi-part `osdp_MFG` reception, the miscellaneous command hooks
//! (`ABORT` / `ACURXSIZE` / `KEEPACTIVE`) and the advisory PDCAP check.
//!
//! Everything runs plaintext over an in-memory wire between a real [`Pd`]
//! and a real [`Acu`], so each test exercises the whole path: the Rust
//! setter, the C state machine's interception, and the reply the ACU
//! actually receives.
//!
//! The property worth guarding hardest is the **per-member optionality of
//! [`StatusProviders`]** — the C vtable allows binding `local` alone and
//! leaving `ISTAT` to the application, and a Rust wrapper that always bound
//! all four would silently take three commands away from existing
//! consumers' command handlers.

#![cfg(feature = "pd")]
#![cfg(feature = "acu")]

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    PdcapRecord, Raw, OSDP_CMD_ABORT, OSDP_CMD_ACURXSIZE, OSDP_CMD_ISTAT, OSDP_CMD_KEEPACTIVE,
    OSDP_CMD_LSTAT, OSDP_CMD_MFG, OSDP_CMD_POLL, OSDP_ISTATR_ACTIVE, OSDP_LSTATR_NORMAL,
    OSDP_LSTATR_TAMPER, OSDP_NAK_UNKNOWN_CMD, OSDP_REPLY_ACK, OSDP_REPLY_ISTATR, OSDP_REPLY_LSTATR,
    OSDP_REPLY_MFGREP, OSDP_REPLY_NAK, OSDP_REPLY_RAW,
};
use osdp_embedded::pd::{
    CommandHandler, MfgReceiver, Pd, Reply, StatusProviders, DEFAULT_ACU_RX_SIZE,
};
use osdp_embedded::{Error, Result, Transport};

// ---- In-process wire ------------------------------------------------

#[derive(Default)]
struct Wire {
    a2p: Vec<u8>,
    p2a: Vec<u8>,
}
type SharedWire = Rc<RefCell<Wire>>;

struct WireAdapter<const PD: bool> {
    wire: SharedWire,
}

impl<const PD: bool> Transport for WireAdapter<PD> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let src = if PD { &mut w.a2p } else { &mut w.p2a };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        src.drain(..n);
        n
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let dst = if PD { &mut w.p2a } else { &mut w.a2p };
        dst.extend_from_slice(buf);
        buf.len()
    }
    fn now_ms(&mut self) -> Option<u32> {
        None
    }
}

// ---- ACU reply capture ----------------------------------------------

#[derive(Default)]
struct Captured {
    replies: Vec<(u8, u8, Vec<u8>)>, // (cmd_code, reply_code, payload)
}
struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner
            .borrow_mut()
            .replies
            .push((e.cmd_code, e.reply_code, e.payload.to_vec()));
    }
}

impl Captured {
    /// The reply the PD sent for the most recent `cmd` (panics if none).
    fn last_for(&self, cmd: u8) -> (u8, Vec<u8>) {
        let r = self
            .replies
            .iter()
            .rev()
            .find(|r| r.0 == cmd)
            .unwrap_or_else(|| panic!("no reply captured for command {cmd:#04X}"));
        (r.1, r.2.clone())
    }
}

// ---- A command handler that records what still reaches it -----------

#[derive(Default)]
struct HandlerLog {
    seen: Vec<u8>,
}
struct RecordingHandler {
    log: Rc<RefCell<HandlerLog>>,
}
impl CommandHandler for RecordingHandler {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> Result<Reply<'a>> {
        self.log.borrow_mut().seen.push(cmd_code);
        // Anything reaching the application here is simply ACKed; the tests
        // assert on *which* codes arrive, not on the reply.
        Ok(Reply {
            code: OSDP_REPLY_ACK,
            payload: &[],
        })
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

const PD_ADDRESS: u8 = 0x10;

/// Wire up a PD + ACU pair with a recording command handler and reply capture.
fn rig() -> (Pd, Acu, Rc<RefCell<Captured>>, Rc<RefCell<HandlerLog>>) {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let log = Rc::new(RefCell::new(HandlerLog::default()));
    let captured = Rc::new(RefCell::new(Captured::default()));

    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(RecordingHandler {
        log: Rc::clone(&log),
    });

    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");

    (pd, acu, captured, log)
}

// ---- Status providers -----------------------------------------------

#[test]
fn status_provider_answers_lstat_with_application_values() {
    let (mut pd, mut acu, captured, log) = rig();

    pd.set_status_providers(
        StatusProviders::new().local(|| (OSDP_LSTATR_TAMPER, OSDP_LSTATR_NORMAL)),
    );

    acu.send_command(PD_ADDRESS, OSDP_CMD_LSTAT, &[])
        .expect("send LSTAT");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_LSTAT);
    assert_eq!(
        code, OSDP_REPLY_LSTATR,
        "the library should build osdp_LSTATR itself"
    );
    assert_eq!(
        payload,
        [OSDP_LSTATR_TAMPER, OSDP_LSTATR_NORMAL],
        "the provider's values must reach the wire in spec order (tamper, power)"
    );
    assert!(
        !log.borrow().seen.contains(&OSDP_CMD_LSTAT),
        "a provided command must not also reach the command handler"
    );
}

/// The property the builder exists to preserve: binding `local` alone must
/// leave `osdp_ISTAT` falling through to the application, exactly as the C
/// vtable's per-member NULLs allow.
#[test]
fn unprovided_status_commands_still_reach_the_command_handler() {
    let (mut pd, mut acu, captured, log) = rig();

    // Only `local` is supplied — inputs/outputs/readers stay unbound.
    pd.set_status_providers(StatusProviders::new().local(|| (0, 0)));

    acu.send_command(PD_ADDRESS, OSDP_CMD_ISTAT, &[])
        .expect("send ISTAT");
    cycle(&mut pd, &mut acu, 6);

    assert!(
        log.borrow().seen.contains(&OSDP_CMD_ISTAT),
        "osdp_ISTAT must reach cmd_cb when no inputs provider is bound"
    );
    let (code, _) = captured.borrow().last_for(OSDP_CMD_ISTAT);
    assert_eq!(
        code, OSDP_REPLY_ACK,
        "the handler's own reply should go out untouched"
    );
}

#[test]
fn inputs_provider_reports_one_byte_per_input() {
    let (mut pd, mut acu, captured, _log) = rig();

    pd.set_status_providers(StatusProviders::new().inputs(|out| {
        out[0] = OSDP_ISTATR_ACTIVE;
        out[1] = OSDP_ISTATR_ACTIVE;
        out[2] = 0;
        3
    }));

    acu.send_command(PD_ADDRESS, OSDP_CMD_ISTAT, &[])
        .expect("send ISTAT");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_ISTAT);
    assert_eq!(code, OSDP_REPLY_ISTATR);
    assert_eq!(payload, [OSDP_ISTATR_ACTIVE, OSDP_ISTATR_ACTIVE, 0]);
}

/// A provider claiming more bytes than the scratch holds is clamped rather
/// than trusted — over-reporting must not run off the end of the buffer.
#[test]
fn over_reporting_inputs_provider_is_clamped() {
    let (mut pd, mut acu, captured, _log) = rig();

    pd.set_status_providers(StatusProviders::new().inputs(|out| {
        for b in out.iter_mut() {
            *b = OSDP_ISTATR_ACTIVE;
        }
        usize::MAX // absurd claim
    }));

    acu.send_command(PD_ADDRESS, OSDP_CMD_ISTAT, &[])
        .expect("send ISTAT");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_ISTAT);
    assert_eq!(code, OSDP_REPLY_ISTATR);
    assert!(
        !payload.is_empty() && payload.len() <= osdp_embedded::pd::REPLY_SCRATCH_LEN,
        "report must be clamped to the scratch capacity, got {}",
        payload.len()
    );
    assert!(payload.iter().all(|&b| b == OSDP_ISTATR_ACTIVE));
}

// ---- Poll-response event queue ---------------------------------------

#[test]
fn queued_event_is_delivered_as_the_next_poll_response() {
    let (mut pd, mut acu, captured, log) = rig();
    pd.set_event_queue(256);

    // Encode a card read exactly as an application would.
    let mut body = [0u8; 32];
    let n = Raw {
        reader_no: 0,
        format_code: 1,
        bit_count: 26,
        bit_data: &[0x12, 0x34, 0x56, 0x80],
    }
    .build(&mut body)
    .expect("build RAW");

    pd.enqueue_event(OSDP_REPLY_RAW, &body[..n])
        .expect("enqueue");
    assert!(
        pd.event_pending(),
        "the queue should report the pending read"
    );

    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_POLL);
    assert_eq!(
        code, OSDP_REPLY_RAW,
        "the poll must be answered from the queue"
    );
    assert_eq!(payload, &body[..n]);
    assert!(!pd.event_pending(), "delivery should drain the queue");
    assert!(
        !log.borrow().seen.contains(&OSDP_CMD_POLL),
        "a queued event must pre-empt the command handler for that poll"
    );
}

#[test]
fn empty_queue_falls_through_to_the_command_handler() {
    let (mut pd, mut acu, captured, log) = rig();
    pd.set_event_queue(256);

    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");
    cycle(&mut pd, &mut acu, 6);

    assert!(
        log.borrow().seen.contains(&OSDP_CMD_POLL),
        "an empty queue must remain invisible to the application"
    );
    let (code, _) = captured.borrow().last_for(OSDP_CMD_POLL);
    assert_eq!(code, OSDP_REPLY_ACK);
}

/// Whether a dropped card read matters is the application's call, so a full
/// queue reports rather than silently discarding.
#[test]
fn full_event_queue_reports_buffer_too_small() {
    let (mut pd, _acu, _captured, _log) = rig();
    pd.set_event_queue(16); // room for one small record, not many

    let payload = [0xAAu8; 8];
    let mut accepted = 0;
    let mut rejected = None;
    for _ in 0..8 {
        match pd.enqueue_event(OSDP_REPLY_RAW, &payload) {
            Ok(()) => accepted += 1,
            Err(e) => {
                rejected = Some(e);
                break;
            }
        }
    }

    assert!(accepted >= 1, "at least one event should fit in 16 bytes");
    assert_eq!(
        rejected,
        Some(Error::BufferTooSmall),
        "a full queue must report, not silently drop"
    );
}

#[test]
fn clear_events_discards_everything_queued() {
    let (mut pd, _acu, _captured, _log) = rig();
    pd.set_event_queue(256);

    pd.enqueue_event(OSDP_REPLY_RAW, &[1, 2, 3])
        .expect("enqueue");
    assert!(pd.event_pending());
    pd.clear_events();
    assert!(!pd.event_pending(), "clear_events must empty the queue");
}

// ---- Multi-part osdp_MFG ---------------------------------------------

#[derive(Default)]
struct MfgLog {
    calls: usize,
    vendor: [u8; 3],
    data: Vec<u8>,
}
struct CaptureMfg {
    log: Rc<RefCell<MfgLog>>,
}
impl MfgReceiver for CaptureMfg {
    fn on_message<'a>(
        &'a mut self,
        vendor_code: &[u8; 3],
        data: &[u8],
    ) -> Result<Option<Reply<'a>>> {
        let mut l = self.log.borrow_mut();
        l.calls += 1;
        l.vendor = *vendor_code;
        l.data = data.to_vec();
        Ok(None) // ACK
    }
}

/// Build a fragmented `osdp_MFG` payload by hand:
/// `vendor[3] || MpSizeTotal || MpOffset || MpFragmentSize (LE u16 each) || fragment`.
fn mfg_fragment(vendor: [u8; 3], total: u16, offset: u16, fragment: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&vendor);
    v.extend_from_slice(&total.to_le_bytes());
    v.extend_from_slice(&offset.to_le_bytes());
    v.extend_from_slice(&(fragment.len() as u16).to_le_bytes());
    v.extend_from_slice(fragment);
    v
}

#[test]
fn multipart_mfg_is_reassembled_and_delivered_once() {
    let (mut pd, mut acu, captured, _log) = rig();
    let mlog = Rc::new(RefCell::new(MfgLog::default()));
    pd.set_mfg_receiver(
        256,
        CaptureMfg {
            log: Rc::clone(&mlog),
        },
    );

    const VENDOR: [u8; 3] = [0x5A, 0x42, 0x43];
    let message: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    for (offset, chunk) in [(0u16, &message[..4]), (4u16, &message[4..])] {
        let payload = mfg_fragment(VENDOR, message.len() as u16, offset, chunk);
        acu.send_command(PD_ADDRESS, OSDP_CMD_MFG, &payload)
            .expect("send MFG fragment");
        cycle(&mut pd, &mut acu, 6);
    }

    let l = mlog.borrow();
    assert_eq!(
        l.calls, 1,
        "the receiver fires once per completed message, not per fragment"
    );
    assert_eq!(l.vendor, VENDOR, "vendor code repeats on every fragment");
    assert_eq!(l.data, message, "fragments must reassemble in order");

    let (code, _) = captured.borrow().last_for(OSDP_CMD_MFG);
    assert_eq!(code, OSDP_REPLY_ACK, "Ok(None) from the receiver means ACK");
}

/// A receiver may answer with `osdp_MFGREP` instead of an ACK.
#[test]
fn mfg_receiver_can_answer_with_mfgrep() {
    struct Responder {
        body: Vec<u8>,
    }
    impl MfgReceiver for Responder {
        fn on_message<'a>(
            &'a mut self,
            _vendor_code: &[u8; 3],
            _data: &[u8],
        ) -> Result<Option<Reply<'a>>> {
            Ok(Some(Reply {
                code: OSDP_REPLY_MFGREP,
                payload: &self.body,
            }))
        }
    }

    let (mut pd, mut acu, captured, _log) = rig();

    const VENDOR: [u8; 3] = [0x5A, 0x42, 0x43];
    // osdp_MFGREP body is vendor_code[3] || vendor data. Hand-encoded here
    // because the typed codec wrapper for it is not in `messages` yet.
    let body: Vec<u8> = VENDOR.iter().copied().chain([0xAB, 0xCD]).collect();

    pd.set_mfg_receiver(256, Responder { body: body.clone() });

    let payload = mfg_fragment(VENDOR, 2, 0, &[0x01, 0x02]);
    acu.send_command(PD_ADDRESS, OSDP_CMD_MFG, &payload)
        .expect("send MFG");
    cycle(&mut pd, &mut acu, 6);

    let (code, got) = captured.borrow().last_for(OSDP_CMD_MFG);
    assert_eq!(code, OSDP_REPLY_MFGREP);
    assert_eq!(got, body);
}

// ---- Miscellaneous command hooks -------------------------------------

#[test]
fn abort_hook_runs_and_acks() {
    let (mut pd, mut acu, captured, _log) = rig();
    let fired = Rc::new(RefCell::new(false));
    let f = Rc::clone(&fired);
    pd.set_abort_handler(move || {
        *f.borrow_mut() = true;
        Ok(())
    });

    acu.send_command(PD_ADDRESS, OSDP_CMD_ABORT, &[])
        .expect("send ABORT");
    cycle(&mut pd, &mut acu, 6);

    assert!(*fired.borrow(), "the abort hook should have run");
    let (code, _) = captured.borrow().last_for(OSDP_CMD_ABORT);
    assert_eq!(code, OSDP_REPLY_ACK);
}

/// Spec 6.22's "PD unable to abort" case — a hook that fails becomes NAK 0x03.
#[test]
fn failing_abort_hook_naks() {
    let (mut pd, mut acu, captured, _log) = rig();
    pd.set_abort_handler(|| Err(Error::NotSupported));

    acu.send_command(PD_ADDRESS, OSDP_CMD_ABORT, &[])
        .expect("send ABORT");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_ABORT);
    assert_eq!(code, OSDP_REPLY_NAK);
    assert_eq!(payload.first().copied(), Some(OSDP_NAK_UNKNOWN_CMD));
}

#[test]
fn acurxsize_is_stored_and_notified() {
    let (mut pd, mut acu, captured, _log) = rig();

    assert_eq!(
        pd.acu_rx_size(),
        DEFAULT_ACU_RX_SIZE,
        "before any ACURXSIZE the PD assumes the spec 6.26 default"
    );

    let notified = Rc::new(RefCell::new(None));
    let n = Rc::clone(&notified);
    pd.set_acurxsize_handler(move |size| *n.borrow_mut() = Some(size));

    // osdp_ACURXSIZE payload is a little-endian u16.
    acu.send_command(PD_ADDRESS, OSDP_CMD_ACURXSIZE, &600u16.to_le_bytes())
        .expect("send ACURXSIZE");
    cycle(&mut pd, &mut acu, 6);

    assert_eq!(pd.acu_rx_size(), 600, "the declared size must be stored");
    assert_eq!(*notified.borrow(), Some(600), "and surfaced to the hook");
    let (code, _) = captured.borrow().last_for(OSDP_CMD_ACURXSIZE);
    assert_eq!(
        code, OSDP_REPLY_ACK,
        "the hook is a notification, never a veto"
    );
}

#[test]
fn keepactive_is_answered_by_the_handler() {
    let (mut pd, mut acu, captured, _log) = rig();
    let held = Rc::new(RefCell::new(None));
    let h = Rc::clone(&held);
    pd.set_keepactive_handler(move |ms| {
        *h.borrow_mut() = Some(ms);
        Ok(())
    });

    acu.send_command(PD_ADDRESS, OSDP_CMD_KEEPACTIVE, &5000u16.to_le_bytes())
        .expect("send KEEPACTIVE");
    cycle(&mut pd, &mut acu, 6);

    assert_eq!(*held.borrow(), Some(5000));
    let (code, _) = captured.borrow().last_for(OSDP_CMD_KEEPACTIVE);
    assert_eq!(code, OSDP_REPLY_ACK);
}

/// Holding a reader field energised is physical, so an unbound KEEPACTIVE
/// must NAK rather than ACK a promise the PD cannot keep.
#[test]
fn keepactive_without_a_handler_naks() {
    let (mut pd, mut acu, captured, _log) = rig();

    acu.send_command(PD_ADDRESS, OSDP_CMD_KEEPACTIVE, &5000u16.to_le_bytes())
        .expect("send KEEPACTIVE");
    cycle(&mut pd, &mut acu, 6);

    let (code, payload) = captured.borrow().last_for(OSDP_CMD_KEEPACTIVE);
    assert_eq!(code, OSDP_REPLY_NAK);
    assert_eq!(payload.first().copied(), Some(OSDP_NAK_UNKNOWN_CMD));
}

// ---- Advisory PDCAP check --------------------------------------------

#[test]
fn check_pdcap_accepts_records_the_library_can_honour() {
    let pd = Pd::new(PD_ADDRESS);
    let records = [
        PdcapRecord {
            function_code: 1, // contact status monitoring
            compliance_level: 1,
            num_objects: 4,
        },
        PdcapRecord {
            function_code: 2, // output control
            compliance_level: 1,
            num_objects: 4,
        },
    ];
    assert!(
        pd.check_pdcap(&records).is_ok(),
        "records describing the device, not the library, are never rejected"
    );
}

/// Function code 10 encodes a 16-bit receive-buffer size LSB-then-MSB across
/// the two bytes Annex B names "compliance level" and "number of" — filling
/// them in as the names suggest is exactly the mistake this checker exists
/// to catch. Here the PD is asked to promise 0xFFFF bytes, far past what it
/// can hold.
#[test]
fn check_pdcap_rejects_an_oversized_receive_buffer_and_reports_the_index() {
    let pd = Pd::new(PD_ADDRESS);
    let records = [
        PdcapRecord {
            function_code: 1,
            compliance_level: 1,
            num_objects: 4,
        },
        PdcapRecord {
            function_code: 10,      // receive buffer size
            compliance_level: 0xFF, // LSB
            num_objects: 0xFF,      // MSB -> 65535 bytes
        },
    ];

    let problem = pd
        .check_pdcap(&records)
        .expect_err("over-advertising the receive buffer must be caught");
    assert_eq!(problem.index, 1, "should point at the offending record");
    assert_eq!(problem.error, Error::BufferTooSmall);
}

/// Function code 9 claiming AES-128 with no crypto bound is a promise the
/// PD cannot keep — the ACU would open a handshake the PD must refuse.
#[test]
fn check_pdcap_rejects_aes_claim_without_crypto() {
    let pd = Pd::new(PD_ADDRESS);
    let records = [PdcapRecord {
        function_code: 9,    // communication security
        compliance_level: 1, // AES128
        num_objects: 1,
    }];

    let problem = pd
        .check_pdcap(&records)
        .expect_err("claiming AES128 with no crypto vtable must be caught");
    assert_eq!(problem.index, 0);
    assert_eq!(problem.error, Error::NotSupported);
}
