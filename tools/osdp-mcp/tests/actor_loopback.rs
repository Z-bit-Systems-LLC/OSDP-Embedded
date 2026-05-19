// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Library-level test that exercises the default handler against a
//! real ACU through an in-process loopback transport. Bypasses MCP
//! and serial so it can run in CI without any hardware.
//!
//! Validates: POLL → ACK, ID → PDID (with the default PDID), and
//! CAP → PDCAP. These are the three flows that turn a freshly-
//! configured osdp-mcp PD into a functional peer for an ACU's
//! capability exchange.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    Keypad, Pdcap, Pdid, Raw, OSDP_CMD_CAP, OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK,
    OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_PDCAP, OSDP_REPLY_PDID, OSDP_REPLY_RAW,
};
use osdp_embedded::pd::Pd;
use osdp_embedded::Transport;
use osdp_mcp::overrides::OverrideReply;

// Pull the handler + log + overrides + events from osdp-mcp's lib.
use osdp_mcp::events;
use osdp_mcp::handler;
use osdp_mcp::log::{Direction, EffectiveFilter, LogInner};
use osdp_mcp::overrides;
use std::sync::Arc as StdArc;

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
    log: Vec<(u8, u8, u8, Vec<u8>)>,
}
struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner.borrow_mut().log.push((
            e.pd_address,
            e.cmd_code,
            e.reply_code,
            e.payload.to_vec(),
        ));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

#[test]
fn default_handler_handles_baseline() {
    let wire = Rc::new(RefCell::new(Wire::default()));

    let stats = Arc::new(Mutex::new(handler::PdStats::default()));
    let log = StdArc::new(LogInner::new(64));
    let ovmap = overrides::new_map();
    let evq = events::new_queue();
    let drops: handler::DropCounter = StdArc::new(std::sync::atomic::AtomicU32::new(0));
    let mut pd = Pd::new(0x10);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(handler::DefaultHandler::new(
        Arc::clone(&stats),
        StdArc::clone(&log),
        StdArc::clone(&ovmap),
        StdArc::clone(&evq),
        StdArc::clone(&drops),
        0x10,
    ));

    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, 0x10).expect("register_pd");

    // POLL → ACK
    acu.send_command(0x10, OSDP_CMD_POLL, &[]).unwrap();
    cycle(&mut pd, &mut acu, 4);

    // ID → PDID (with default PDID payload — 12 bytes)
    acu.send_command(0x10, OSDP_CMD_ID, &[0x00]).unwrap();
    cycle(&mut pd, &mut acu, 4);

    // CAP → PDCAP
    acu.send_command(0x10, OSDP_CMD_CAP, &[0x00]).unwrap();
    cycle(&mut pd, &mut acu, 4);

    let cap = captured.borrow();
    assert_eq!(cap.log.len(), 3, "expected 3 replies, got {:?}", cap.log);

    // POLL → ACK
    let (addr, cmd, reply, payload) = &cap.log[0];
    assert_eq!((*addr, *cmd, *reply), (0x10, OSDP_CMD_POLL, OSDP_REPLY_ACK));
    assert!(payload.is_empty());

    // ID → PDID — decode and confirm it matches default_pdid().
    let (_, cmd, reply, payload) = &cap.log[1];
    assert_eq!((*cmd, *reply), (OSDP_CMD_ID, OSDP_REPLY_PDID));
    let pdid = Pdid::decode(payload).expect("decode default PDID");
    assert_eq!(pdid, handler::default_pdid());

    // CAP → PDCAP — decode and confirm it matches default_pdcap().
    let (_, cmd, reply, payload) = &cap.log[2];
    assert_eq!((*cmd, *reply), (OSDP_CMD_CAP, OSDP_REPLY_PDCAP));
    let pdcap = Pdcap::decode(payload).expect("decode default PDCAP");
    assert_eq!(pdcap, handler::default_pdcap());
    drop(cap);

    // Stats picked up the last cmd/reply.
    let s = stats.lock().unwrap();
    assert_eq!(s.last_cmd_code, Some(OSDP_CMD_CAP));
    assert_eq!(s.last_reply_code, Some(OSDP_REPLY_PDCAP));
    drop(s);

    // ---- Log captured all three round trips ----
    // POLL/ACK go to the heartbeat counter (push-filtered, no ring
    // slot) so the 1024-entry ring stays reserved for interesting
    // traffic; only ID/PDID and CAP/PDCAP show up as entries.
    let page = log.snapshot(0, 100, EffectiveFilter::Exclude(vec![]));
    let codes: Vec<(Direction, u8)> = page.entries.iter().map(|e| (e.direction, e.code)).collect();
    assert_eq!(
        codes,
        vec![
            (Direction::Cmd, OSDP_CMD_ID),
            (Direction::Reply, OSDP_REPLY_PDID),
            (Direction::Cmd, OSDP_CMD_CAP),
            (Direction::Reply, OSDP_REPLY_PDCAP),
        ]
    );
    // The heartbeat IS visible — just aggregated. The suppression
    // report carries POLL/ACK counts from the push counter.
    assert!(page.suppressed.total >= 2, "expected POLL/ACK in suppressed counter, got {:?}", page.suppressed);
    drop(page);

    // ---- nak_next override: next POLL → NAK 0x03, then default ----
    // Reset reply capture so the assertions below are about new
    // events only.
    captured.borrow_mut().log.clear();
    overrides::nak_next(&ovmap, OSDP_CMD_POLL, 0x03);

    acu.send_command(0x10, OSDP_CMD_POLL, &[]).unwrap();
    cycle(&mut pd, &mut acu, 4);
    acu.send_command(0x10, OSDP_CMD_POLL, &[]).unwrap();
    cycle(&mut pd, &mut acu, 4);

    let cap = captured.borrow();
    assert_eq!(cap.log.len(), 2);
    use osdp_embedded::messages::OSDP_REPLY_NAK;
    let (_, cmd, reply, payload) = &cap.log[0];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_NAK));
    assert_eq!(payload, &vec![0x03], "NAK code in payload");
    // Second POLL falls back to the default ACK behavior.
    let (_, cmd, reply, payload) = &cap.log[1];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_ACK));
    assert!(payload.is_empty());
    drop(cap);

    // ---- Event injection: RAW / KEYPAD / LSTATR drain in FIFO ----
    captured.borrow_mut().log.clear();

    // 26-bit Wiegand card (the textbook example): 4 bytes carrying
    // the bit-packed data, format_code = 1.
    let raw_payload = {
        let raw = Raw {
            reader_no: 0,
            format_code: 1,
            bit_count: 26,
            bit_data: &[0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = vec![0u8; 16];
        let n = raw.build(&mut buf).unwrap();
        buf.truncate(n);
        buf
    };
    let kp_payload = {
        let kp = Keypad {
            reader_no: 0,
            digits: b"1234#",
        };
        let mut buf = vec![0u8; 16];
        let n = kp.build(&mut buf).unwrap();
        buf.truncate(n);
        buf
    };
    events::enqueue(
        &evq,
        OverrideReply {
            code: OSDP_REPLY_RAW,
            payload: raw_payload.clone(),
        },
    );
    events::enqueue(
        &evq,
        OverrideReply {
            code: OSDP_REPLY_KEYPAD,
            payload: kp_payload.clone(),
        },
    );
    events::enqueue(
        &evq,
        OverrideReply {
            code: OSDP_REPLY_LSTATR,
            payload: vec![1, 0], // tamper=1, power=0
        },
    );

    // Three POLLs should drain the three events; a fourth gets ACK.
    for _ in 0..4 {
        acu.send_command(0x10, OSDP_CMD_POLL, &[]).unwrap();
        cycle(&mut pd, &mut acu, 4);
    }

    let cap = captured.borrow();
    assert_eq!(
        cap.log.len(),
        4,
        "expected 4 POLL replies, got {:?}",
        cap.log
    );
    // POLL #1 → RAW
    let (_, cmd, reply, payload) = &cap.log[0];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_RAW));
    let raw_decoded = Raw::decode(payload).expect("decode RAW");
    assert_eq!(raw_decoded.bit_count, 26);
    assert_eq!(raw_decoded.format_code, 1);
    assert_eq!(raw_decoded.bit_data, &[0xDE, 0xAD, 0xBE, 0xEF][..]);

    // POLL #2 → KEYPAD
    let (_, cmd, reply, payload) = &cap.log[1];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_KEYPAD));
    let kp_decoded = Keypad::decode(payload).expect("decode KEYPAD");
    assert_eq!(kp_decoded.digits, b"1234#");

    // POLL #3 → LSTATR (tamper=1, power=0)
    let (_, cmd, reply, payload) = &cap.log[2];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_LSTATR));
    assert_eq!(payload, &vec![1, 0]);

    // POLL #4 → ACK (queue empty)
    let (_, cmd, reply, payload) = &cap.log[3];
    assert_eq!((*cmd, *reply), (OSDP_CMD_POLL, OSDP_REPLY_ACK));
    assert!(payload.is_empty());
    // Drop counter wasn't touched in this test path; covered by the
    // separate handler-level unit test (handler::tests::drop_counter…).
    drop(cap);
    let _ = drops;
}
