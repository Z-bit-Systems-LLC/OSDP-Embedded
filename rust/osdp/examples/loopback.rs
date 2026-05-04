// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Pd ↔ Acu in-process round trip — Rust port of `tests/test_loopback.c`.
//!
//! Wires a [`Pd`] and an [`Acu`] through a shared in-memory wire and
//! exercises POLL → ACK and ID → PDID over it. Plain text only; SC is
//! deferred until the safe wrapper grows an `Aes128` trait.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example loopback
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use osdp::acu::{
    Acu,
    ReplyEvent,
    ReplyHandler,
    Transport as AcuTransport,
};
use osdp::pd::{
    CommandHandler,
    Pd,
    Reply,
    Transport as PdTransport,
};
use osdp_sys::{
    OSDP_CMD_ID,
    OSDP_CMD_POLL,
    OSDP_REPLY_ACK,
    OSDP_REPLY_PDID,
};

/// Two append-only byte buffers, one per direction.
#[derive(Default)]
struct Wire {
    /// ACU → PD bytes the PD hasn't yet read.
    a2p: Vec<u8>,
    /// PD → ACU bytes the ACU hasn't yet read.
    p2a: Vec<u8>,
}

type SharedWire = Rc<RefCell<Wire>>;

/// Adapter exposing one direction of [`Wire`] as a [`PdTransport`] /
/// [`AcuTransport`]. Generic over which buffers are "incoming" and
/// "outgoing"; the concrete `PdAdapter` and `AcuAdapter` aliases below
/// pin those down.
struct WireAdapter<const PD: bool> {
    wire: SharedWire,
}

impl<const PD: bool> WireAdapter<PD> {
    /// Drain `cap` bytes from the incoming buffer.
    fn drain_incoming(&self, buf: &mut [u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let src = if PD { &mut w.a2p } else { &mut w.p2a };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        src.drain(..n);
        n
    }

    fn append_outgoing(&self, buf: &[u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let dst = if PD { &mut w.p2a } else { &mut w.a2p };
        dst.extend_from_slice(buf);
        buf.len()
    }
}

impl PdTransport for WireAdapter<true> {
    fn read(&mut self, buf: &mut [u8]) -> usize { self.drain_incoming(buf) }
    fn write(&mut self, buf: &[u8])     -> usize { self.append_outgoing(buf) }
    fn now_ms(&mut self) -> Option<u32> { None }  // Online tracking off.
}

impl AcuTransport for WireAdapter<false> {
    fn read(&mut self, buf: &mut [u8]) -> usize { self.drain_incoming(buf) }
    fn write(&mut self, buf: &[u8])     -> usize { self.append_outgoing(buf) }
    fn now_ms(&mut self) -> Option<u32> { None }
}

// ---- PD application logic --------------------------------------------

/// PDID payload kept in static storage so the slice we hand back from
/// `handle()` lives at least as long as the trait method's borrow of
/// `&mut self`. Vendor + model + version + serial (LE) +
/// firmware major/minor/build, exactly as the spec describes.
const SAMPLE_PDID: [u8; 12] = [
    0xCA, 0xFE, 0x00,         // vendor
    0x10,                     // model
    0x01,                     // version
    0xEF, 0xBE, 0xAD, 0xDE,   // serial = 0xDEAD_BEEF (little-endian on the wire)
    0x01, 0x02, 0x03,         // fw major / minor / build
];

struct DemoHandler;

impl CommandHandler for DemoHandler {
    fn handle<'a>(
        &'a mut self,
        cmd_code: u8,
        _payload: &[u8],
    ) -> osdp::Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply { code: OSDP_REPLY_ACK,  payload: &[] }),
            OSDP_CMD_ID   => Ok(Reply { code: OSDP_REPLY_PDID, payload: &SAMPLE_PDID }),
            _             => Err(osdp::Error::NotSupported),
        }
    }
}

// ---- ACU reply capture -----------------------------------------------

#[derive(Default)]
struct CapturedReplies {
    log: Vec<(u8, u8, u8, Vec<u8>)>,  // (pd_addr, cmd, reply, payload)
}

struct ReplyCapture {
    inner: Rc<RefCell<CapturedReplies>>,
}

impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner.borrow_mut().log.push((
            e.pd_address, e.cmd_code, e.reply_code, e.payload.to_vec(),
        ));
    }
}

// ---- Driver ----------------------------------------------------------

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

fn main() {
    let wire = Rc::new(RefCell::new(Wire::default()));

    // ---- PD side ----
    let mut pd = Pd::new(0x10);
    pd.set_transport(WireAdapter::<true> { wire: Rc::clone(&wire) });
    pd.set_command_handler(DemoHandler);

    // ---- ACU side ----
    let captured = Rc::new(RefCell::new(CapturedReplies::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> { wire: Rc::clone(&wire) });
    acu.set_reply_handler(ReplyCapture { inner: Rc::clone(&captured) });
    acu.register_pd(0, 0x10).expect("register_pd");

    // ---- Round trip 1: POLL → ACK ----
    acu.send_command(0x10, OSDP_CMD_POLL, &[]).expect("send POLL");
    cycle(&mut pd, &mut acu, 4);

    // ---- Round trip 2: ID → PDID ----
    let id_request: [u8; 1] = [0x00];  // standard PDID selector
    acu.send_command(0x10, OSDP_CMD_ID, &id_request).expect("send ID");
    cycle(&mut pd, &mut acu, 4);

    // ---- Verify ----
    let log = captured.borrow();
    assert_eq!(log.log.len(), 2, "expected exactly 2 replies");
    let (addr, cmd, reply, payload) = &log.log[0];
    assert_eq!(*addr, 0x10);
    assert_eq!(*cmd, OSDP_CMD_POLL);
    assert_eq!(*reply, OSDP_REPLY_ACK);
    assert!(payload.is_empty());

    let (addr, cmd, reply, payload) = &log.log[1];
    assert_eq!(*addr, 0x10);
    assert_eq!(*cmd, OSDP_CMD_ID);
    assert_eq!(*reply, OSDP_REPLY_PDID);
    assert_eq!(&payload[..], &SAMPLE_PDID[..]);

    println!("loopback: POLL→ACK and ID→PDID round-trip OK");
    println!("  captured replies:");
    for (addr, cmd, reply, payload) in &log.log {
        println!(
            "    PD 0x{:02X}  cmd 0x{:02X}  reply 0x{:02X}  payload={:?}",
            addr, cmd, reply, payload
        );
    }
}
