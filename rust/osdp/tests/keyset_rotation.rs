// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! End-to-end Rust integration test for runtime SCBK rotation via the
//! `osdp_KEYSET` command.
//!
//! Scenario:
//!   1. Pair a [`Pd`] with an [`Acu`] over an in-memory wire and
//!      handshake under SCBK-D (install mode).
//!   2. ACU sends `osdp_KEYSET` carrying a new 16-byte SCBK under
//!      SCS_17.
//!   3. PD ACKs without tearing the SC session down — verified by a
//!      follow-up POLL succeeding under the same session keys.
//!   4. Drive a fresh handshake using the rotated key from the ACU
//!      side; it succeeds, proving the PD actually stored the new
//!      SCBK rather than just ACK'ing the wire frame.
//!
//! This is the strongest available signal that `KEYSET` updates the
//! PD's stored key without forcing a session restart.

#![cfg(all(feature = "pd", feature = "acu"))]

use std::cell::RefCell;
use std::rc::Rc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    Keyset, OSDP_CMD_KEYSET, OSDP_CMD_POLL, OSDP_KEYSET_KEY_TYPE_SCBK, OSDP_REPLY_ACK,
};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::sc::{
    scbk_default, ScCrypto, ScEvent, ScEventHandler, ScEventKind, AES_BLOCK_LEN, AES_KEY_LEN,
};
use osdp_embedded::Transport;

// ---- In-process wire (same shape as loopback_sc) --------------------

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

// ---- Test crypto provider (RustCrypto AES + deterministic LCG RNG) ---

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

// ---- PD app handler: ACK every supported baseline command -----------

const SC_CUID: [u8; 8] = [0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD];

struct DemoHandler;
impl CommandHandler for DemoHandler {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL | OSDP_CMD_KEYSET => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(osdp_embedded::Error::NotSupported),
        }
    }
}

// ---- ACU reply / SC-event capture ------------------------------------

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

const PD_ADDRESS: u8 = 0x10;

/// New SCBK the ACU rotates the PD to. Deliberately different from
/// the well-known SCBK-D so the post-rotation handshake provably
/// uses the *new* key.
const NEW_SCBK: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

#[test]
fn keyset_rotates_pd_scbk_and_next_handshake_uses_it() {
    let wire = Rc::new(RefCell::new(Wire::default()));

    // ---- PD side: bound under SCBK-D ("install mode") ----
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(DemoHandler);
    pd.set_sc_crypto(DemoCrypto::new(0xCAFE_BABE));
    pd.set_sc_scbk_d(scbk_default());
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
    acu.set_pd_scbk_d(PD_ADDRESS, scbk_default())
        .expect("set_pd_scbk_d");

    // ---- Step 1: install-mode handshake with SCBK-D ----
    acu.start_sc_handshake(PD_ADDRESS, /*use_default_key*/ true)
        .expect("start_sc_handshake (install)");
    cycle(&mut pd, &mut acu, 8);

    assert!(pd.sc_established(), "install handshake failed on PD");
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "install handshake failed on ACU"
    );
    {
        let cap = captured.borrow();
        assert_eq!(cap.sc_events.len(), 1);
        assert_eq!(cap.sc_events[0].1, ScEventKind::Established);
    }

    // ---- Step 2: ACU sends KEYSET carrying the new SCBK ----
    let mut keyset_payload = [0u8; 2 + 16];
    let keyset = Keyset {
        key_type: OSDP_KEYSET_KEY_TYPE_SCBK,
        key_length: 16,
        key_data: &NEW_SCBK,
    };
    let n = keyset
        .build(&mut keyset_payload)
        .expect("build KEYSET payload");
    assert_eq!(n, 2 + 16);

    acu.send_command(PD_ADDRESS, OSDP_CMD_KEYSET, &keyset_payload)
        .expect("send KEYSET");
    cycle(&mut pd, &mut acu, 4);

    // PD ACK'd it.
    {
        let cap = captured.borrow();
        let kr = cap
            .replies
            .iter()
            .find(|r| r.1 == OSDP_CMD_KEYSET)
            .expect("ACU didn't capture a KEYSET reply");
        assert_eq!(
            kr.2, OSDP_REPLY_ACK,
            "PD did not ACK the KEYSET (got 0x{:02X})",
            kr.2
        );
        // No new SC events — session is intact, not torn down.
        assert_eq!(
            cap.sc_events.len(),
            1,
            "KEYSET should not trigger a new SC event; got {:?}",
            cap.sc_events
        );
    }

    // The PD should still report SC established. This is the
    // "without force restarting" requirement.
    assert!(
        pd.sc_established(),
        "KEYSET unexpectedly tore the PD's SC session down"
    );
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "KEYSET unexpectedly invalidated the ACU's view of the session"
    );

    // ---- Step 3: a follow-up POLL still rides the same session ----
    let log_len_before_poll = captured.borrow().replies.len();
    acu.send_command(PD_ADDRESS, OSDP_CMD_POLL, &[])
        .expect("post-KEYSET POLL");
    cycle(&mut pd, &mut acu, 4);
    {
        let cap = captured.borrow();
        assert_eq!(cap.replies.len(), log_len_before_poll + 1);
        let last = cap.replies.last().unwrap();
        assert_eq!(
            (last.1, last.2),
            (OSDP_CMD_POLL, OSDP_REPLY_ACK),
            "POLL under same SC after KEYSET failed: {last:?}"
        );
    }

    // ---- Step 4: prove the PD's stored SCBK actually changed ----
    // Tell the ACU to use the new SCBK from now on and re-handshake.
    // If the PD stored NEW_SCBK during step 2, this handshake
    // succeeds; otherwise the cryptograms won't match and the ACU
    // reports HandshakeFailed.
    acu.set_pd_scbk(PD_ADDRESS, &NEW_SCBK).expect("set_pd_scbk");
    acu.start_sc_handshake(PD_ADDRESS, /*use_default_key*/ false)
        .expect("start_sc_handshake (with new SCBK)");
    cycle(&mut pd, &mut acu, 12);

    assert!(
        pd.sc_established(),
        "re-handshake with rotated SCBK failed on PD — key wasn't stored"
    );
    assert!(
        acu.is_pd_sc_established(PD_ADDRESS),
        "re-handshake with rotated SCBK failed on ACU — key wasn't stored"
    );
    let cap = captured.borrow();
    // Expect 2 Established events total now (install + post-KEYSET).
    let established_events = cap
        .sc_events
        .iter()
        .filter(|(_, k)| *k == ScEventKind::Established)
        .count();
    assert_eq!(
        established_events, 2,
        "expected install + rotated-key handshake to both ESTABLISH; got events {:?}",
        cap.sc_events
    );
}
