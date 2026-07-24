// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Secure Channel clear-text policy on the PD side:
//!
//!   1. During an ESTABLISHED session, any clear-text (unsecured) command
//!      tears the session down and is answered osdp_NAK 0x06 ("Encrypted
//!      communication required") in the clear.
//!
//!   2. On a PD keyed for full security (operational SCBK set) with NO
//!      session yet, a clear-text command that isn't one of the discovery/
//!      config commands (osdp_ID / osdp_CAP / osdp_COMSET) is refused
//!      NAK 0x06; the allow-listed ones still pass through.

#![cfg(feature = "pd")]

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::frame::{build, decode, FrameBuild, Integrity, FRAME_MARK_LEN};
use osdp_embedded::messages::{OSDP_CMD_ID, OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_NAK};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::Transport;

const PD_ADDRESS: u8 = 0x10;
const NAK_ENCRYPTION_REQUIRED: u8 = 0x06;
const SCBK: [u8; 16] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
];

// ---- Handlers & transport shared by both cases ----------------------

struct AckHandler;
impl CommandHandler for AckHandler {
    fn handle<'a>(&'a mut self, code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        match code {
            OSDP_CMD_POLL | OSDP_CMD_ID => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(osdp_embedded::Error::NotSupported),
        }
    }
}

/// Feeds a fixed byte string to the PD and captures what it writes back.
struct FeedTransport {
    input: Vec<u8>,
    pos: usize,
    output: Rc<RefCell<Vec<u8>>>,
}
impl Transport for FeedTransport {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.input.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
        self.pos += n;
        n
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        self.output.borrow_mut().extend_from_slice(buf);
        buf.len()
    }
    fn now_ms(&mut self) -> Option<u32> {
        None
    }
}

fn clear_command(code: u8, sequence: u8) -> Vec<u8> {
    let frame = FrameBuild {
        address: PD_ADDRESS,
        sequence,
        integrity: Some(Integrity::Crc),
        code,
        ..Default::default()
    };
    let mut buf = [0u8; 16];
    let n = build(&frame, &mut buf).expect("build clear command");
    buf[..n].to_vec()
}

/// Drive a fresh full-security PD (operational SCBK, no session) with one
/// clear-text command and return its reply bytes (SOM-aligned).
fn drive_pre_sc(code: u8) -> Vec<u8> {
    let output = Rc::new(RefCell::new(Vec::new()));
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(FeedTransport {
        input: clear_command(code, 1),
        pos: 0,
        output: Rc::clone(&output),
    });
    pd.set_command_handler(AckHandler);
    pd.set_sc_scbk(&SCBK); // keyed for full security → scbk_set == true
    pd.tick();
    let out = output.borrow().clone();
    out
}

fn reply_of(bytes: &[u8]) -> (u8, Vec<u8>) {
    let f = decode(&bytes[FRAME_MARK_LEN..]).expect("decode PD reply");
    (f.code, f.payload.to_vec())
}

#[test]
fn pre_sc_restricted_clear_command_naks_0x06() {
    let out = drive_pre_sc(OSDP_CMD_POLL);
    assert!(!out.is_empty(), "PD gave no reply to a clear POLL");
    let (code, payload) = reply_of(&out);
    assert_eq!(code, OSDP_REPLY_NAK);
    assert_eq!(payload, [NAK_ENCRYPTION_REQUIRED]);
}

#[test]
fn pre_sc_discovery_clear_command_is_allowed() {
    // osdp_ID is on the pre-SC allow-list, so it reaches the handler (ACK)
    // instead of being refused NAK 0x06.
    let out = drive_pre_sc(OSDP_CMD_ID);
    assert!(!out.is_empty(), "PD gave no reply to a clear ID");
    let (code, _payload) = reply_of(&out);
    assert_eq!(
        code, OSDP_REPLY_ACK,
        "discovery command must pass the pre-SC gate (got 0x{code:02X})"
    );
}

// ---- Case 1: clear command during an ESTABLISHED session ------------
//
// Reuses the ACU+PD in-memory-wire handshake harness to reach an
// established session, then injects a raw clear-text POLL straight onto
// the wire (bypassing the ACU, which would otherwise secure it).

mod established {
    use super::*;

    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes128;

    use osdp_embedded::acu::Acu;
    use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};

    const SC_CUID: [u8; 8] = [0xCA, 0xFE, 0x00, 0x10, 0x01, 0xEF, 0xBE, 0xAD];

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

    struct DemoCrypto {
        rng: u64,
    }
    impl ScCrypto for DemoCrypto {
        fn aes_encrypt(
            &mut self,
            key: &[u8; AES_KEY_LEN],
            in_: &[u8; AES_BLOCK_LEN],
            out: &mut [u8; AES_BLOCK_LEN],
        ) -> osdp_embedded::Result<()> {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            let mut b = GenericArray::clone_from_slice(in_);
            cipher.encrypt_block(&mut b);
            out.copy_from_slice(&b);
            Ok(())
        }
        fn aes_decrypt(
            &mut self,
            key: &[u8; AES_KEY_LEN],
            in_: &[u8; AES_BLOCK_LEN],
            out: &mut [u8; AES_BLOCK_LEN],
        ) -> osdp_embedded::Result<()> {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            let mut b = GenericArray::clone_from_slice(in_);
            cipher.decrypt_block(&mut b);
            out.copy_from_slice(&b);
            Ok(())
        }
        fn rand_bytes(&mut self, out: &mut [u8]) -> osdp_embedded::Result<()> {
            for byte in out.iter_mut() {
                self.rng = self
                    .rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (self.rng >> 33) as u8;
            }
            Ok(())
        }
    }

    fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
        for _ in 0..n {
            pd.tick();
            acu.tick();
        }
    }

    #[test]
    fn clear_command_tears_down_session_and_naks_0x06() {
        let wire: SharedWire = Rc::new(RefCell::new(Wire::default()));

        let mut pd = Pd::new(PD_ADDRESS);
        pd.set_transport(WireAdapter::<true> {
            wire: Rc::clone(&wire),
        });
        pd.set_command_handler(AckHandler);
        pd.set_sc_crypto(DemoCrypto { rng: 0xCAFE_BABE });
        pd.set_sc_scbk(&SCBK);
        pd.set_sc_cuid(&SC_CUID);

        let mut acu = Acu::new(1);
        acu.set_transport(WireAdapter::<false> {
            wire: Rc::clone(&wire),
        });
        acu.set_sc_crypto(DemoCrypto { rng: 0xDEAD_BEEF });
        acu.register_pd(0, PD_ADDRESS).expect("register_pd");
        acu.set_pd_scbk(PD_ADDRESS, &SCBK).expect("set_pd_scbk");

        // Establish the session under the operational SCBK.
        acu.start_sc_handshake(PD_ADDRESS, /*use_default_key*/ false)
            .expect("start_sc_handshake");
        cycle(&mut pd, &mut acu, 8);
        assert!(pd.sc_established(), "handshake failed on the PD");

        // Inject a raw clear-text POLL straight onto the wire, then tick
        // only the PD so the ACU doesn't secure or consume anything.
        {
            let mut w = wire.borrow_mut();
            w.a2p.clear();
            w.p2a.clear();
            w.a2p.extend_from_slice(&clear_command(OSDP_CMD_POLL, 2));
        }
        pd.tick();

        let reply_bytes = wire.borrow().p2a.clone();
        assert!(
            !reply_bytes.is_empty(),
            "PD gave no reply to a clear command during an established session"
        );
        let (code, payload) = reply_of(&reply_bytes);
        assert_eq!(code, OSDP_REPLY_NAK);
        assert_eq!(payload, [NAK_ENCRYPTION_REQUIRED]);
        assert!(
            !pd.sc_established(),
            "a clear command during an established session must tear the session down"
        );
    }
}
