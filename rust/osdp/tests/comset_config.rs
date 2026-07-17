// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! End-to-end Rust integration test for `osdp_COMSET` handling via the
//! safe [`ComsetHandler`] binding.
//!
//! Scenario (plaintext, no Secure Channel needed):
//!   1. Pair a [`Pd`] with an [`Acu`] over an in-memory wire.
//!   2. Register a [`ComsetHandler`] on the PD that accepts the requested
//!      address but pins the baud (the "unable to comply" path, spec 6.13).
//!   3. ACU sends `osdp_COMSET` requesting a new address + baud.
//!   4. Assert the ACU captured an `osdp_COM` reply echoing the effective
//!      values (new address, pinned baud) and that the PD's `applied`
//!      callback fired with the same effective values.
//!
//! This exercises the whole binding: the decide thunk (return values flow
//! back into the C library) and the applied thunk (fires after the reply is
//! sent), plus the enlarged `osdp_pd_t` ABI.

#![cfg(feature = "pd")]
#![cfg(feature = "acu")]

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{Com, ComsetCmd, OSDP_CMD_COMSET, OSDP_REPLY_COM};
use osdp_embedded::pd::{ComsetHandler, Pd};
use osdp_embedded::Transport;

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

// ---- COMSET handler that pins the baud ------------------------------

#[derive(Default)]
struct ComsetLog {
    decided: Option<(u8, u32)>,
    applied: Option<(u8, u32)>,
}

struct PinBaudComset {
    baud: u32,
    log: Rc<RefCell<ComsetLog>>,
}
impl ComsetHandler for PinBaudComset {
    fn decide(&mut self, req_address: u8, req_baud: u32) -> (u8, u32) {
        self.log.borrow_mut().decided = Some((req_address, req_baud));
        // Accept the address; keep our baud ("unable to comply", spec 6.13).
        (req_address, self.baud)
    }
    fn applied(&mut self, address: u8, baud: u32) {
        self.log.borrow_mut().applied = Some((address, baud));
    }
}

// ---- ACU reply capture ----------------------------------------------

#[derive(Default)]
struct Captured {
    replies: Vec<(u8, u8, u8, Vec<u8>)>, // (pd_addr, cmd, reply, payload)
}
struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner
            .borrow_mut()
            .replies
            .push((e.pd_address, e.cmd_code, e.reply_code, e.payload.to_vec()));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

const PD_ADDRESS: u8 = 0x10;
const CONFIGURED_BAUD: u32 = 9600;
const REQUESTED_NEW_ADDRESS: u8 = 0x22;
const REQUESTED_NEW_BAUD: u32 = 115_200;

#[test]
fn comset_reports_effective_values_and_fires_applied() {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let log = Rc::new(RefCell::new(ComsetLog::default()));

    // ---- PD side ----
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_comset_handler(PinBaudComset {
        baud: CONFIGURED_BAUD,
        log: Rc::clone(&log),
    });

    // ---- ACU side ----
    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");

    // ---- ACU sends COMSET requesting a new address + baud ----
    let mut payload = [0u8; 5];
    let n = ComsetCmd {
        address: REQUESTED_NEW_ADDRESS,
        baud_rate: REQUESTED_NEW_BAUD,
    }
    .build(&mut payload)
    .expect("build COMSET payload");
    assert_eq!(n, 5);

    acu.send_command(PD_ADDRESS, OSDP_CMD_COMSET, &payload)
        .expect("send COMSET");
    cycle(&mut pd, &mut acu, 4);

    // ---- The PD replied osdp_COM with the EFFECTIVE values ----
    let cap = captured.borrow();
    let com_reply = cap
        .replies
        .iter()
        .find(|r| r.1 == OSDP_CMD_COMSET)
        .expect("ACU didn't capture a COMSET reply");
    assert_eq!(
        com_reply.2, OSDP_REPLY_COM,
        "COMSET must be answered with osdp_COM (got 0x{:02X})",
        com_reply.2
    );
    let com = Com::decode(&com_reply.3).expect("decode osdp_COM payload");
    assert_eq!(com.address, REQUESTED_NEW_ADDRESS, "COM must report new address");
    assert_eq!(
        com.baud_rate, CONFIGURED_BAUD,
        "COM must report the pinned baud, not the requested one"
    );

    // ---- The decide + applied callbacks fired with the right values ----
    let l = log.borrow();
    assert_eq!(
        l.decided,
        Some((REQUESTED_NEW_ADDRESS, REQUESTED_NEW_BAUD)),
        "decide() should see the ACU's requested values"
    );
    assert_eq!(
        l.applied,
        Some((REQUESTED_NEW_ADDRESS, CONFIGURED_BAUD)),
        "applied() should fire with the effective (address, baud)"
    );
}
