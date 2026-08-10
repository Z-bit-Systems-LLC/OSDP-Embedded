// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Library-level tests for the virtual PD's status providers, driven by a
//! real ACU over an in-process loopback — no MCP, no serial, no hardware.
//!
//! Two behaviours these lock down, both regressions the old hard-coded path
//! would have reintroduced silently:
//!
//! 1. **`osdp_LSTAT` answers from real state.** It used to return a constant
//!    "all clear", so a tamper injected through `inject_local_status` was
//!    reported once as an unsolicited `osdp_LSTATR` and then denied by every
//!    subsequent query.
//! 2. **`ISTAT` / `OSTAT` / `RSTAT` are answered at all.** They used to fall
//!    through to NAK 0x03 while the PD's own PDCAP advertised one input, one
//!    output and one reader.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    Istatr, Lstatr, Ostatr, Out, OutRecord, Rstatr, OSDP_CMD_ISTAT, OSDP_CMD_LSTAT, OSDP_CMD_OSTAT,
    OSDP_CMD_OUT, OSDP_CMD_RSTAT, OSDP_LSTATR_NORMAL, OSDP_LSTATR_TAMPER, OSDP_OSTATR_ACTIVE,
    OSDP_OSTATR_INACTIVE, OSDP_REPLY_ACK, OSDP_REPLY_ISTATR, OSDP_REPLY_LSTATR, OSDP_REPLY_OSTATR,
    OSDP_REPLY_RSTATR, OSDP_RSTATR_NORMAL,
};
use osdp_embedded::pd::{Pd, StatusProviders};
use osdp_embedded::Transport;
use osdp_mcp::status::{self, SharedStatus};
use osdp_mcp::{events, handler, log::LogInner, overrides};

// ---- Loopback wire ---------------------------------------------------

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
    log: Vec<(u8, u8, Vec<u8>)>, // (cmd, reply, payload)
}
struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner
            .borrow_mut()
            .log
            .push((e.cmd_code, e.reply_code, e.payload.to_vec()));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

const ADDR: u8 = 0x10;

/// Build a PD wired exactly as `pd_actor::open_pd` wires one — the same
/// default handler and the same four status providers over a shared status
/// block — plus an ACU to drive it.
fn rig() -> (Pd, Acu, Rc<RefCell<Captured>>, SharedStatus) {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let status = status::shared();

    let mut pd = Pd::new(ADDR);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(
        handler::DefaultHandler::new(
            Arc::new(Mutex::new(handler::PdStats::default())),
            Arc::new(LogInner::new(32)),
            overrides::new_map(),
            events::new_queue(),
            Arc::new(std::sync::atomic::AtomicU32::new(0)),
            ADDR,
        )
        .with_status(Arc::clone(&status)),
    );

    // Mirrors open_pd's binding.
    {
        let local = Arc::clone(&status);
        let inputs = Arc::clone(&status);
        let outputs = Arc::clone(&status);
        let readers = Arc::clone(&status);
        pd.set_status_providers(
            StatusProviders::new()
                .local(move || {
                    local
                        .lock()
                        .map(|s| (s.tamper, s.power))
                        .unwrap_or((OSDP_LSTATR_NORMAL, OSDP_LSTATR_NORMAL))
                })
                .inputs(move |out| copy(&inputs, out, |s| s.inputs.clone()))
                .outputs(move |out| copy(&outputs, out, |s| s.outputs.clone()))
                .readers(move |out| copy(&readers, out, |s| s.readers.clone())),
        );
    }

    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, ADDR).expect("register_pd");

    (pd, acu, captured, status)
}

fn copy(
    status: &SharedStatus,
    out: &mut [u8],
    pick: impl Fn(&osdp_mcp::status::DeviceStatus) -> Vec<u8>,
) -> usize {
    let Ok(s) = status.lock() else { return 0 };
    let src = pick(&s);
    let n = src.len().min(out.len());
    out[..n].copy_from_slice(&src[..n]);
    n
}

/// Send one command and return the (reply_code, payload) the ACU received.
fn ask(
    pd: &mut Pd,
    acu: &mut Acu,
    cap: &Rc<RefCell<Captured>>,
    cmd: u8,
    payload: &[u8],
) -> (u8, Vec<u8>) {
    acu.send_command(ADDR, cmd, payload).expect("send");
    cycle(pd, acu, 6);
    let c = cap.borrow();
    let (_, reply, body) = c
        .log
        .iter()
        .rev()
        .find(|r| r.0 == cmd)
        .unwrap_or_else(|| panic!("no reply for {cmd:#04X}"));
    (*reply, body.clone())
}

// ---- osdp_LSTAT ------------------------------------------------------

#[test]
fn lstat_reports_nominal_on_a_fresh_pd() {
    let (mut pd, mut acu, cap, _status) = rig();
    let (code, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_LSTAT, &[]);
    assert_eq!(code, OSDP_REPLY_LSTATR);
    let r = Lstatr::decode(&payload).expect("decode LSTATR");
    assert_eq!(r.tamper, OSDP_LSTATR_NORMAL);
    assert_eq!(r.power, OSDP_LSTATR_NORMAL);
}

/// The regression that motivated the whole change: an injected tamper has to
/// survive into the answer for a *query*, not just the one unsolicited
/// report. The old hard-coded arm returned (0, 0) here forever.
#[test]
fn lstat_reports_an_injected_tamper_rather_than_a_constant() {
    let (mut pd, mut acu, cap, status) = rig();

    status::set_local(&status, OSDP_LSTATR_TAMPER, OSDP_LSTATR_NORMAL);

    let (code, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_LSTAT, &[]);
    assert_eq!(code, OSDP_REPLY_LSTATR);
    let r = Lstatr::decode(&payload).expect("decode LSTATR");
    assert_eq!(
        r.tamper, OSDP_LSTATR_TAMPER,
        "an LSTAT query must see the standing tamper condition"
    );
    assert_eq!(r.power, OSDP_LSTATR_NORMAL);

    // …and clearing it is visible on the next query too.
    status::set_local(&status, OSDP_LSTATR_NORMAL, OSDP_LSTATR_NORMAL);
    let (_, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_LSTAT, &[]);
    assert_eq!(Lstatr::decode(&payload).unwrap().tamper, OSDP_LSTATR_NORMAL);
}

// ---- The three array-valued reports ----------------------------------

/// All three used to NAK 0x03 while PDCAP advertised the objects. Each now
/// reports exactly as many bytes as the capability record claims.
#[test]
fn istat_ostat_rstat_are_answered_and_match_the_advertised_counts() {
    let (mut pd, mut acu, cap, status) = rig();
    let expected = status.lock().unwrap().clone();

    let (code, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_ISTAT, &[]);
    assert_eq!(code, OSDP_REPLY_ISTATR, "ISTAT must not NAK");
    assert_eq!(Istatr::decode(&payload).unwrap().statuses, expected.inputs);

    let (code, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_OSTAT, &[]);
    assert_eq!(code, OSDP_REPLY_OSTATR, "OSTAT must not NAK");
    assert_eq!(Ostatr::decode(&payload).unwrap().statuses, expected.outputs);

    let (code, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_RSTAT, &[]);
    assert_eq!(code, OSDP_REPLY_RSTATR, "RSTAT must not NAK");
    let readers = Rstatr::decode(&payload).unwrap().statuses;
    assert_eq!(readers, expected.readers);
    assert!(readers.iter().all(|&b| b == OSDP_RSTATR_NORMAL));
}

/// `osdp_OSTAT` should report what the ACU actually commanded, so the
/// handler records each `osdp_OUT` into the same status block the provider
/// reads. Without that the report is a constant and an ACU can never confirm
/// the relay it just drove.
#[test]
fn ostat_reflects_a_commanded_output() {
    let (mut pd, mut acu, cap, _status) = rig();

    // Baseline: the output is inactive.
    let (_, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_OSTAT, &[]);
    assert_eq!(
        Ostatr::decode(&payload).unwrap().statuses[0],
        OSDP_OSTATR_INACTIVE
    );

    // Drive output 0 to permanent ON (control code 0x02, spec Table 14).
    let mut buf = [0u8; 16];
    let n = Out {
        records: vec![OutRecord {
            output_no: 0,
            control_code: 0x02,
            timer_100ms: 0,
        }],
    }
    .build(&mut buf)
    .expect("build OUT");
    let (code, _) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_OUT, &buf[..n]);
    assert_eq!(code, OSDP_REPLY_ACK, "osdp_OUT is still just ACKed");

    // The report now shows it active.
    let (_, payload) = ask(&mut pd, &mut acu, &cap, OSDP_CMD_OSTAT, &[]);
    assert_eq!(
        Ostatr::decode(&payload).unwrap().statuses[0],
        OSDP_OSTATR_ACTIVE,
        "OSTAT must reflect the commanded relay state"
    );
}
