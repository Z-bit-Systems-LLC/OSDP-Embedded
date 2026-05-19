// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Drives the osdp-mcp default handler against an in-process Acu over
//! a Secure Channel session, using the rustcrypto backend. Verifies:
//!
//!   - SCBK-D handshake completes (both sides report ESTABLISHED),
//!   - POLL → ACK round-trips under SCS_15/16,
//!   - ID → PDID round-trips under SCS_17/18 (encrypted payload),
//!   - the log captures both round trips as plaintext (the handler
//!     never sees ciphertext — encrypt/decrypt happens below).
//!
//! Same wire/adapter shape as actor_loopback.rs but with both sides
//! configured for SC. Runs in CI; no hardware required.

// Skip entirely if no crypto backend is compiled in (Secure Channel
// is impossible without one).
#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-tiny-aes"))]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc as StdArc, Arc, Mutex};

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    Keypad, OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_KEYPAD, OSDP_REPLY_PDID,
};
use osdp_embedded::pd::Pd;
use osdp_embedded::sc::{
    scbk_default, ScCrypto, ScEvent, ScEventHandler, ScEventKind, AES_BLOCK_LEN, AES_KEY_LEN,
};
use osdp_embedded::Transport;

use osdp_mcp::crypto::{BoxedSc, Selector};
use osdp_mcp::events;
use osdp_mcp::handler;
use osdp_mcp::log::{Direction, EffectiveFilter, LogInner};
use osdp_mcp::overrides;

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

#[derive(Default)]
struct Captured {
    replies: Vec<(u8, u8, u8, Vec<u8>)>,
    sc_events: Vec<(u8, ScEventKind)>,
}

struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner.borrow_mut().replies.push((
            e.pd_address,
            e.cmd_code,
            e.reply_code,
            e.payload.to_vec(),
        ));
    }
}

struct ScEventCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ScEventHandler for ScEventCapture {
    fn on_sc_event(&mut self, e: &ScEvent) {
        self.inner
            .borrow_mut()
            .sc_events
            .push((e.pd_address, e.kind));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

/// cUID we hand the PD must match the first 8 bytes of the PDID
/// byte stream (vendor[3] + model + version + serial[0..2]) — same
/// derivation pd_actor.rs::derive_cuid_from_default_pdid uses.
fn cuid_from_default_pdid() -> [u8; 8] {
    let p = handler::default_pdid();
    let s = p.serial.to_le_bytes();
    [
        p.vendor_code[0],
        p.vendor_code[1],
        p.vendor_code[2],
        p.model,
        p.version,
        s[0],
        s[1],
        s[2],
    ]
}

const PD_ADDRESS: u8 = 0x10;

/// Mint a fresh ScCrypto from the named backend. Goes through the
/// public Selector::factory so the test exercises the same code
/// path the binary uses at runtime.
fn fresh_crypto(sel: Selector) -> Box<dyn ScCrypto> {
    sel.factory().expect("backend should be compiled in")()
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn sc_handshake_then_operational_round_trips_rustcrypto() {
    run_sc_round_trip(Selector::RustCrypto);
}

#[cfg(feature = "crypto-tiny-aes")]
#[test]
fn sc_handshake_then_operational_round_trips_tiny_aes() {
    run_sc_round_trip(Selector::TinyAes);
}

fn run_sc_round_trip(sel: Selector) {
    let wire = Rc::new(RefCell::new(Wire::default()));

    // ---- PD side: wire osdp-mcp's default handler + SC config ----
    let stats = Arc::new(Mutex::new(handler::PdStats::default()));
    let log = StdArc::new(LogInner::new(128));
    let ovmap = overrides::new_map();
    let evq = events::new_queue();
    let drops: handler::DropCounter = StdArc::new(std::sync::atomic::AtomicU32::new(0));
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(handler::DefaultHandler::new(
        Arc::clone(&stats),
        StdArc::clone(&log),
        StdArc::clone(&ovmap),
        StdArc::clone(&evq),
        StdArc::clone(&drops),
        PD_ADDRESS,
    ));
    pd.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    pd.set_sc_scbk_d(scbk_default());
    pd.set_sc_cuid(&cuid_from_default_pdid());

    // ---- ACU side ----
    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.set_sc_event_handler(ScEventCapture {
        inner: Rc::clone(&captured),
    });
    acu.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");
    acu.set_pd_scbk_d(PD_ADDRESS, scbk_default())
        .expect("set_pd_scbk_d");

    // ---- Handshake (use_default_key=true → SCBK-D selector) ----
    acu.start_sc_handshake(PD_ADDRESS, true)
        .expect("start_sc_handshake");
    cycle(&mut pd, &mut acu, 8);

    assert!(pd.sc_established(), "PD never reached ESTABLISHED");
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "ACU never reached ESTABLISHED"
    );
    {
        let cap = captured.borrow();
        assert_eq!(cap.sc_events.len(), 1);
        assert_eq!(cap.sc_events[0].1, ScEventKind::Established);
    }

    // ---- Operational POLL → ACK under SCS_15/16 ----
    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");
    cycle(&mut pd, &mut acu, 4);

    // ---- Operational ID → PDID under SCS_17/18 (encrypted payload) ----
    let id_request: [u8; 1] = [0x00];
    acu.send_command(PD_ADDRESS, OSDP_CMD_ID, &id_request)
        .expect("send ID");
    cycle(&mut pd, &mut acu, 4);

    // ---- Reply capture ----
    let cap = captured.borrow();
    assert_eq!(cap.replies.len(), 2, "expected POLL+ID replies");
    let (_, cmd, reply, payload) = &cap.replies[0];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_ACK));
    assert!(payload.is_empty());
    let (_, cmd, reply, payload) = &cap.replies[1];
    assert_eq!((*cmd, *reply), (OSDP_CMD_ID, OSDP_REPLY_PDID));
    // PDID payload is 12 bytes per spec — the default_pdid() values.
    let decoded = osdp_embedded::messages::Pdid::decode(payload).expect("decode PDID");
    assert_eq!(decoded, handler::default_pdid());
    drop(cap);

    // ---- Log captured plaintext on both sides ----
    // POLL/ACK are push-filtered to a counter; only ID/PDID show up
    // as ring entries.
    let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
    let codes: Vec<(Direction, u8)> = page.entries.iter().map(|e| (e.direction, e.code)).collect();
    assert_eq!(
        codes,
        vec![
            (Direction::Cmd, OSDP_CMD_ID),
            (Direction::Reply, osdp_embedded::messages::OSDP_REPLY_PDID),
        ]
    );
}

/// Regression: a data-bearing event reply (RAW / KEYPAD / LSTATR
/// queued via the events module) in response to an empty POLL must
/// be wrapped as SCS_18 (encrypted), not SCS_16 (plaintext+MAC). The
/// previous coercion rule was one-way (SCS_17/18 → SCS_15/16 when
/// payload empty) and the PD's reply-SCB choice mirrored the inbound
/// — which silently emitted SCS_16 frames with payload bytes, a
/// spec violation that made OSDP.Net's ACU drop the reply and tear
/// the session down.
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn pd_replies_to_empty_poll_with_data_bearing_event_under_sc() {
    let sel = Selector::RustCrypto;
    let wire = Rc::new(RefCell::new(Wire::default()));

    let stats = Arc::new(Mutex::new(handler::PdStats::default()));
    let log = StdArc::new(LogInner::new(128));
    let ovmap = overrides::new_map();
    let evq = events::new_queue();
    let drops: handler::DropCounter = StdArc::new(std::sync::atomic::AtomicU32::new(0));
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(handler::DefaultHandler::new(
        Arc::clone(&stats),
        StdArc::clone(&log),
        StdArc::clone(&ovmap),
        StdArc::clone(&evq),
        StdArc::clone(&drops),
        PD_ADDRESS,
    ));
    pd.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    pd.set_sc_scbk_d(scbk_default());
    pd.set_sc_cuid(&cuid_from_default_pdid());

    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.set_sc_event_handler(ScEventCapture {
        inner: Rc::clone(&captured),
    });
    acu.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");
    acu.set_pd_scbk_d(PD_ADDRESS, scbk_default())
        .expect("set_pd_scbk_d");

    acu.start_sc_handshake(PD_ADDRESS, true)
        .expect("start_sc_handshake");
    cycle(&mut pd, &mut acu, 8);
    assert!(pd.sc_established());
    assert!(acu.is_pd_sc_established(PD_ADDRESS));

    // Queue a KEYPAD event the PD will surface on the next POLL.
    let digits = b"1234#";
    let kp = Keypad {
        reader_no: 0,
        digits,
    };
    let mut payload = vec![0u8; 2 + digits.len()];
    let n = kp.build(&mut payload).expect("build KEYPAD payload");
    payload.truncate(n);
    events::enqueue(
        &evq,
        osdp_mcp::overrides::OverrideReply {
            code: OSDP_REPLY_KEYPAD,
            payload,
        },
    );

    // ACU sends POLL. Payload is empty, so the command goes out as
    // SCS_15 (no data + MAC). The PD's reply has KEYPAD data — must
    // be wrapped as SCS_18 (encrypted + MAC), not SCS_16.
    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");

    // Tick only the PD so its reply lands on the wire but the ACU
    // hasn't consumed it yet. Sniff the bytes directly and assert
    // the SCB type is SCS_18 (the spec-correct choice for a
    // data-bearing reply) and NOT SCS_16. Before the wrap-step
    // upgrade landed, this assertion was the gap — both peers
    // agreed on (the wrong) SCS_16 and silently round-tripped, only
    // breaking against a strict third-party ACU.
    for _ in 0..4 {
        pd.tick();
    }
    {
        let p2a_bytes: Vec<u8> = {
            let w = wire.borrow();
            w.p2a.clone()
        };
        assert!(
            !p2a_bytes.is_empty(),
            "PD didn't emit a reply on the wire"
        );
        let f = osdp_embedded::frame::decode(&p2a_bytes).expect("decode PD reply");
        let scb = f.scb.as_ref().expect("reply lacks SCB block");
        // SCS_18 = 0x18. Anything else (SCS_16, SCS_15, ...) is wrong
        // for a data-bearing event reply.
        assert_eq!(
            scb.ty, 0x18,
            "expected SCS_18 (encrypted+MAC) for data-bearing KEYPAD reply, got 0x{:02X}",
            scb.ty
        );
    }
    for _ in 0..4 {
        acu.tick();
    }

    let cap = captured.borrow();

    // No session-loss event — the rewrap must have stayed in sync.
    assert!(
        !cap.sc_events
            .iter()
            .any(|(_, k)| matches!(k, ScEventKind::SessionLost | ScEventKind::HandshakeFailed)),
        "unexpected SC failure during data-bearing event reply: {:?}",
        cap.sc_events
    );
    assert!(
        pd.sc_established(),
        "PD lost its SC session during the event reply"
    );
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "ACU lost its SC session during the event reply"
    );

    // ACU received exactly one reply, a KEYPAD with the queued digits.
    assert_eq!(cap.replies.len(), 1, "expected single POLL reply");
    let (_, cmd, reply, payload) = &cap.replies[0];
    assert_eq!(*cmd, OSDP_CMD_POLL);
    assert_eq!(*reply, OSDP_REPLY_KEYPAD);
    let decoded = Keypad::decode(payload).expect("decode KEYPAD");
    assert_eq!(decoded.reader_no, 0);
    assert_eq!(decoded.digits, digits);
}

// Silence the unused_imports warning for AES_KEY_LEN / AES_BLOCK_LEN
// when this module is compiled stand-alone — they appear in trait
// signatures referenced from BoxedSc.
const _: usize = AES_KEY_LEN + AES_BLOCK_LEN;
