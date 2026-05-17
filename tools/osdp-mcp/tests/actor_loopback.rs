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
    Pdcap, Pdid, OSDP_CMD_CAP, OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_PDCAP,
    OSDP_REPLY_PDID,
};
use osdp_embedded::pd::Pd;
use osdp_embedded::Transport;

// Pull the handler + log from osdp-mcp's library half (src/lib.rs).
use osdp_mcp::handler;
use osdp_mcp::log::{Direction, LogInner};
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
    let mut pd = Pd::new(0x10);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(handler::DefaultHandler::new(
        Arc::clone(&stats),
        StdArc::clone(&log),
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

    // ---- Log captured all three round trips (cmd + reply each) ----
    let page = log.snapshot(0, 100);
    assert_eq!(page.entries.len(), 6, "expected 3 cmd + 3 reply entries");
    let codes: Vec<(Direction, u8)> = page.entries.iter().map(|e| (e.direction, e.code)).collect();
    assert_eq!(
        codes,
        vec![
            (Direction::Cmd, OSDP_CMD_POLL),
            (Direction::Reply, OSDP_REPLY_ACK),
            (Direction::Cmd, OSDP_CMD_ID),
            (Direction::Reply, OSDP_REPLY_PDID),
            (Direction::Cmd, OSDP_CMD_CAP),
            (Direction::Reply, OSDP_REPLY_PDCAP),
        ]
    );
}
