// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Pd ↔ Acu Secure Channel 2 round trip in process — the SC2 analogue
//! of `loopback_sc.rs`, and the runtime validation of the safe
//! [`ScCrypto2`] API and its FFI thunks.
//!
//! Wires a [`Pd`] and an [`Acu`] through a shared in-memory wire, both
//! SC2-configured, drives the SCS_21..24 handshake, then exchanges
//! POLL → ACK and ID → PDID under SCS_25..28 (AES-256-GCM). The
//! `ScCrypto2` provider is backed by the RustCrypto `aes` / `aes-gcm`
//! crates and `tiny-keccak`'s KMAC256 — a real, independent crypto
//! stack from the C test backend.
//!
//! ```sh
//! cargo run --example loopback_sc2
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes256Gcm;
use tiny_keccak::{Hasher, Kmac};

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_PDID};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::sc::{
    ScCrypto2, ScEvent, ScEventHandler, ScEventKind, SC2_KEY_LEN, SC2_NONCE_LEN, SC2_TAG_LEN,
};
use osdp_embedded::Transport;

// ---- Wire ------------------------------------------------------------

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

// ---- SC2 crypto provider ---------------------------------------------

struct DemoCrypto2 {
    rng_state: u64,
}

impl DemoCrypto2 {
    fn new(seed: u64) -> Self {
        Self { rng_state: seed }
    }
}

impl ScCrypto2 for DemoCrypto2 {
    fn kmac256(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) -> osdp_embedded::Result<()> {
        // KMAC256 with an empty customization string.
        let mut mac = Kmac::v256(key, &[]);
        mac.update(data);
        mac.finalize(out);
        Ok(())
    }

    fn aes256_gcm_encrypt(
        &mut self,
        key: &[u8; SC2_KEY_LEN],
        nonce: &[u8; SC2_NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; SC2_TAG_LEN],
    ) -> osdp_embedded::Result<()> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let mut buf = pt.to_vec();
        let t = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
            .map_err(|_| osdp_embedded::Error::BadCrc)?;
        ct.copy_from_slice(&buf);
        tag.copy_from_slice(&t);
        Ok(())
    }

    fn aes256_gcm_decrypt(
        &mut self,
        key: &[u8; SC2_KEY_LEN],
        nonce: &[u8; SC2_NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; SC2_TAG_LEN],
        pt: &mut [u8],
    ) -> osdp_embedded::Result<()> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let mut buf = ct.to_vec();
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                aad,
                &mut buf,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| osdp_embedded::Error::BadCrc)?;
        pt.copy_from_slice(&buf);
        Ok(())
    }

    fn aes256_ecb_encrypt(
        &mut self,
        key: &[u8; SC2_KEY_LEN],
        in_: &[u8; 16],
        out: &mut [u8; 16],
    ) -> osdp_embedded::Result<()> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(in_);
        cipher.encrypt_block(&mut block);
        out.copy_from_slice(&block);
        Ok(())
    }

    fn rand_bytes(&mut self, out: &mut [u8]) -> osdp_embedded::Result<()> {
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
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0x01, 0x02, 0x03, 0x04,
];
const SC2_CUID: [u8; 8] = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7];
const SCBK: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
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

    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(DemoHandler);
    pd.set_sc2_crypto(DemoCrypto2::new(0xCAFE_BABE));
    pd.set_sc2_scbk(&SCBK);
    pd.set_sc2_cuid(&SC2_CUID);

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
    acu.set_sc2_crypto(DemoCrypto2::new(0xDEAD_BEEF));
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");
    acu.set_pd_sc2_scbk(PD_ADDRESS, &SCBK)
        .expect("set_pd_sc2_scbk");

    // ---- Handshake ----
    acu.start_sc2_handshake(PD_ADDRESS)
        .expect("start_sc2_handshake");
    cycle(&mut pd, &mut acu, 8);

    assert!(pd.sc2_established(), "PD never reached SC2 established");
    assert!(
        acu.is_pd_sc2_established(PD_ADDRESS),
        "ACU never reached SC2 established"
    );
    {
        let cap = captured.borrow();
        assert_eq!(cap.sc_events.len(), 1, "expected one ESTABLISHED event");
        assert_eq!(cap.sc_events[0].1, ScEventKind::Established);
        assert!(
            cap.replies.is_empty(),
            "handshake leaked into reply_handler"
        );
    }
    println!("handshake: PD and ACU both report SC2 ESTABLISHED");

    // ---- POLL → ACK (SCS_27/28) ----
    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("send POLL");
    cycle(&mut pd, &mut acu, 4);

    // ---- ID → PDID (SCS_27/28, encrypted payload) ----
    let id_request: [u8; 1] = [0x00];
    acu.send_command(PD_ADDRESS, OSDP_CMD_ID, &id_request)
        .expect("send ID");
    cycle(&mut pd, &mut acu, 4);

    let cap = captured.borrow();
    assert_eq!(cap.replies.len(), 2, "expected 2 operational replies");

    let (_, cmd, reply, payload) = &cap.replies[0];
    assert_eq!(*cmd, OSDP_CMD_POLL);
    assert_eq!(*reply, OSDP_REPLY_ACK);
    assert!(payload.is_empty());

    let (_, cmd, reply, payload) = &cap.replies[1];
    assert_eq!(*cmd, OSDP_CMD_ID);
    assert_eq!(*reply, OSDP_REPLY_PDID);
    assert_eq!(&payload[..], &SAMPLE_PDID[..]);

    println!("loopback_sc2: handshake + POLL→ACK + ID→PDID under SC2 OK");
    println!("  decrypted PDID payload: {:02X?}", payload);
}
