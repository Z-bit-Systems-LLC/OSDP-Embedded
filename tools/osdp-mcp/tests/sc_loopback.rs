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
    Keypad, Keyset, OSDP_CMD_ID, OSDP_CMD_KEYSET, OSDP_CMD_POLL, OSDP_KEYSET_KEY_TYPE_SCBK,
    OSDP_REPLY_ACK, OSDP_REPLY_KEYPAD, OSDP_REPLY_PDID,
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
        assert!(!p2a_bytes.is_empty(), "PD didn't emit a reply on the wire");
        // The PD prepends the spec-5.7 marking byte(s) (0xFF) ahead of
        // the SOM; frame::decode expects SOM-aligned input, so skip to
        // the SOM before decoding the sniffed wire bytes.
        let som = p2a_bytes
            .iter()
            .position(|&b| b == 0x53)
            .expect("no SOM in PD reply");
        let f = osdp_embedded::frame::decode(&p2a_bytes[som..]).expect("decode PD reply");
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

/// Regression: an `osdp_KEYSET` that rotates the SCBK during an SC
/// session must survive a PD **Power Cycle** (the actor's
/// `force_session_loss` / stop-start rebuild).
///
/// The bug: the C core rotates the live PD's SCBK in place, but osdp-mcp
/// tracks the SC posture separately in the actor so it can rebuild the PD.
/// The handler used to treat KEYSET as a bare ACK and never captured the
/// new key, so a rebuild re-applied the install-time SCBK-D and silently
/// dropped the rotated key — Secure Channel then broke on the ACU's next
/// handshake (a Mercury panel keys the PD, then a Power Cycle knocks it
/// offline). The fix stashes the accepted key in a shared cell that the
/// actor folds into its remembered config.
///
/// This harness builds `Pd`/`Acu` directly (no actor/serial), so it
/// exercises the two halves the fix hinges on:
///   1. the handler captures the rotated key into the shared cell, and
///   2. rebuilding the PD with *that captured key* (what the actor's
///      Power-Cycle path does) lets the ACU re-handshake with the new key.
///
/// Before the fix, step 1's cell stays `None` and the `.expect` below
/// fails — so this test bites the moment the capture regresses.
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn keyset_rotation_survives_power_cycle() {
    let sel = Selector::RustCrypto;
    // A per-installation SCBK distinct from the well-known SCBK-D, so a
    // rebuild that wrongly fell back to SCBK-D would fail the re-handshake.
    const NEW_SCBK: [u8; 16] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF,
    ];

    let wire = Rc::new(RefCell::new(Wire::default()));

    // ---- PD #1: install mode (SCBK-D), with the shared rotation cell ----
    let stats = Arc::new(Mutex::new(handler::PdStats::default()));
    let log = StdArc::new(LogInner::new(128));
    let ovmap = overrides::new_map();
    let evq = events::new_queue();
    let drops: handler::DropCounter = StdArc::new(std::sync::atomic::AtomicU32::new(0));
    // The cell the actor would own; we hold a clone to observe the capture.
    let key_rotation: handler::SharedKeyRotation = StdArc::new(Mutex::new(None));

    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(
        handler::DefaultHandler::new(
            Arc::clone(&stats),
            StdArc::clone(&log),
            StdArc::clone(&ovmap),
            StdArc::clone(&evq),
            StdArc::clone(&drops),
            PD_ADDRESS,
        )
        .with_key_rotation(StdArc::clone(&key_rotation)),
    );
    pd.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    pd.set_sc_scbk_d(scbk_default());
    pd.set_sc_cuid(&cuid_from_default_pdid());

    // ---- ACU: handshake with the default key (install) ----
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
        .expect("start_sc_handshake (install)");
    cycle(&mut pd, &mut acu, 8);
    assert!(pd.sc_established(), "install handshake never established");
    assert!(acu.is_pd_sc_established(PD_ADDRESS));

    // ---- ACU sends KEYSET (new SCBK) under the live SC session ----
    let ks = Keyset {
        key_type: OSDP_KEYSET_KEY_TYPE_SCBK,
        key_length: 16,
        key_data: &NEW_SCBK,
    };
    let mut ks_buf = [0u8; 2 + 16];
    let n = ks.build(&mut ks_buf).expect("build KEYSET payload");
    acu.send_command(PD_ADDRESS, OSDP_CMD_KEYSET, &ks_buf[..n])
        .expect("send KEYSET");
    cycle(&mut pd, &mut acu, 4);

    // PD ACK'd it and the session is still up (rotation is in-place).
    {
        let cap = captured.borrow();
        let kr = cap
            .replies
            .iter()
            .find(|r| r.1 == OSDP_CMD_KEYSET)
            .expect("ACU never captured a KEYSET reply");
        assert_eq!(kr.2, OSDP_REPLY_ACK, "PD did not ACK the KEYSET");
    }
    assert!(pd.sc_established(), "KEYSET tore the SC session down");

    // (1) The osdp-mcp handler captured the rotated key for the actor.
    let captured_key = key_rotation
        .lock()
        .unwrap()
        .as_ref()
        .copied()
        .expect("handler did not capture the rotated SCBK from KEYSET");
    assert_eq!(
        captured_key, NEW_SCBK,
        "captured SCBK does not match the KEYSET key"
    );

    // ---- Power Cycle: rebuild the PD with the *captured* key ----
    // Mirrors the actor folding the cell into `ScConfig::Scbk(key)` and
    // `open_pd` calling `set_sc_scbk`. A fresh serial buffer on a real
    // reopen → clear the in-process wire.
    drop(pd);
    {
        let mut w = wire.borrow_mut();
        w.a2p.clear();
        w.p2a.clear();
    }
    let mut pd2 = Pd::new(PD_ADDRESS);
    pd2.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd2.set_command_handler(handler::DefaultHandler::new(
        Arc::clone(&stats),
        StdArc::clone(&log),
        StdArc::clone(&ovmap),
        StdArc::clone(&evq),
        StdArc::clone(&drops),
        PD_ADDRESS,
    ));
    pd2.set_sc_crypto(BoxedSc(fresh_crypto(sel)));
    pd2.set_sc_scbk(&captured_key); // operational key, NOT scbk_d
    pd2.set_sc_cuid(&cuid_from_default_pdid());

    // ---- ACU re-handshakes with the operational key ----
    acu.set_pd_scbk(PD_ADDRESS, &NEW_SCBK).expect("set_pd_scbk");
    acu.start_sc_handshake(PD_ADDRESS, /*use_default_key=*/ false)
        .expect("start_sc_handshake (operational)");
    cycle(&mut pd2, &mut acu, 12);

    // (2) The rebuilt PD re-handshakes with the rotated key — the panel
    // stays online after the Power Cycle.
    assert!(
        pd2.sc_established(),
        "rebuilt PD failed to re-handshake with the rotated SCBK — \
         Power Cycle reverted to SCBK-D"
    );
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "ACU failed to re-handshake with the rotated SCBK after Power Cycle"
    );
}

// Silence the unused_imports warning for AES_KEY_LEN / AES_BLOCK_LEN
// when this module is compiled stand-alone — they appear in trait
// signatures referenced from BoxedSc.
const _: usize = AES_KEY_LEN + AES_BLOCK_LEN;
