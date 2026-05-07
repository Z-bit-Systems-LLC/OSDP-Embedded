// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Pd ↔ Acu Secure Channel round trip in process — Rust port of
//! `tests/test_loopback_sc.c`.
//!
//! Wires a [`Pd`] and an [`Acu`] through a shared in-memory wire,
//! configures both sides with an SCBK + AES, drives the four-frame
//! handshake (CHLNG / CCRYPT / SCRYPT / RMAC_I) to completion, then
//! exchanges POLL → ACK and ID → PDID under SCS_15..18. The PD's
//! `command_handler` only ever sees plaintext; encryption and MAC
//! verification are transparent.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example loopback_sc
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_PDID};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::sc::{
    ScCrypto, ScEvent, ScEventHandler, ScEventKind, AES_BLOCK_LEN, AES_KEY_LEN,
};
use osdp_embedded::Transport;

// ---- Wire (same shape as plaintext loopback) -------------------------

#[derive(Default)]
struct Wire {
    a2p: Vec<u8>,
    p2a: Vec<u8>,
}

type SharedWire = Rc<RefCell<Wire>>;

struct WireAdapter<const PD: bool> {
    wire: SharedWire,
}

impl<const PD: bool> WireAdapter<PD> {
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

// One Transport impl, generic over which side of the wire we are.
impl<const PD: bool> Transport for WireAdapter<PD> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        self.drain_incoming(buf)
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        self.append_outgoing(buf)
    }
    fn now_ms(&mut self) -> Option<u32> {
        None
    }
}

// ---- Crypto provider --------------------------------------------------
//
// The aes crate is constant-time, well-tested, MIT/Apache. For the RNG
// we use a deterministic LCG so failed runs are reproducible — a real
// PD or ACU should bind a CSPRNG (BCryptGenRandom, /dev/urandom,
// hardware TRNG).

struct DemoCrypto {
    rng_state: u64,
}

impl DemoCrypto {
    fn new(seed: u64) -> Self {
        Self { rng_state: seed }
    }
}

impl ScCrypto for DemoCrypto {
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(in_);
        cipher.encrypt_block(&mut block);
        out.copy_from_slice(&block);
        Ok(())
    }

    fn aes_decrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(in_);
        cipher.decrypt_block(&mut block);
        out.copy_from_slice(&block);
        Ok(())
    }

    fn rand_bytes(&mut self, out: &mut [u8]) -> osdp_embedded::Result<()> {
        // LCG (Numerical Recipes constants). Reproducible across runs.
        for byte in out.iter_mut() {
            self.rng_state = self
                .rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (self.rng_state >> 33) as u8;
        }
        Ok(())
    }
}

// ---- PD application ---------------------------------------------------

const SAMPLE_PDID: [u8; 12] = [
    0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03,
];

const SC_CUID: [u8; 8] = [0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD];

const SCBK: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

struct DemoHandler;

impl CommandHandler for DemoHandler {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            OSDP_CMD_ID => Ok(Reply {
                code: OSDP_REPLY_PDID,
                payload: &SAMPLE_PDID,
            }),
            _ => Err(osdp_embedded::Error::NotSupported),
        }
    }
}

// ---- ACU captures ----------------------------------------------------

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

// ---- Driver ----------------------------------------------------------

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

const PD_ADDRESS: u8 = 0x10;

fn main() {
    let wire = Rc::new(RefCell::new(Wire::default()));

    // ---- PD side ----
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(DemoHandler);
    // Different RNG seed on each side (the PRNG's state is per-instance,
    // not shared, so RND.A and RND.B end up distinct anyway — but the
    // explicit seed makes that obvious).
    pd.set_sc_crypto(DemoCrypto::new(0xCAFE_BABE));
    pd.set_sc_scbk(&SCBK);
    pd.set_sc_cuid(&SC_CUID);

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
    acu.set_sc_crypto(DemoCrypto::new(0xDEAD_BEEF));
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");
    acu.set_pd_scbk(PD_ADDRESS, &SCBK).expect("set_pd_scbk");

    // ---- Handshake ----
    acu.start_sc_handshake(PD_ADDRESS, /*use_default_key*/ false)
        .expect("start_sc_handshake");
    cycle(&mut pd, &mut acu, 8);

    assert!(pd.sc_established(), "PD never reached established");
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "ACU never reached established"
    );

    {
        let cap = captured.borrow();
        assert_eq!(
            cap.sc_events.len(),
            1,
            "expected exactly one ESTABLISHED event"
        );
        assert_eq!(cap.sc_events[0].0, PD_ADDRESS);
        assert_eq!(cap.sc_events[0].1, ScEventKind::Established);
        // Handshake replies (CCRYPT / RMAC_I) are consumed by the
        // handshake state machine — never delivered as ordinary replies.
        assert!(
            cap.replies.is_empty(),
            "handshake leaked into reply_handler"
        );
    }

    println!("handshake: PD and ACU both report ESTABLISHED");

    // ---- Operational POLL → ACK (SCS_15/16) ----
    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");
    cycle(&mut pd, &mut acu, 4);

    // ---- Operational ID → PDID (SCS_17/18, encrypted payloads) ----
    let id_request: [u8; 1] = [0x00];
    acu.send_command(PD_ADDRESS, OSDP_CMD_ID, &id_request)
        .expect("send ID");
    cycle(&mut pd, &mut acu, 4);

    // ---- Verify operational round-trips ----
    let cap = captured.borrow();
    assert_eq!(cap.replies.len(), 2, "expected 2 operational replies");

    let (addr, cmd, reply, payload) = &cap.replies[0];
    assert_eq!(*addr, PD_ADDRESS);
    assert_eq!(*cmd, OSDP_CMD_POLL);
    assert_eq!(*reply, OSDP_REPLY_ACK);
    assert!(payload.is_empty());

    let (addr, cmd, reply, payload) = &cap.replies[1];
    assert_eq!(*addr, PD_ADDRESS);
    assert_eq!(*cmd, OSDP_CMD_ID);
    assert_eq!(*reply, OSDP_REPLY_PDID);
    assert_eq!(&payload[..], &SAMPLE_PDID[..]);

    println!("loopback_sc: handshake + POLL→ACK + ID→PDID under SC OK");
    println!("  decrypted PDID payload: {:02X?}", payload);
}
