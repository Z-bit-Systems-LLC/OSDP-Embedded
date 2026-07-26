// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! A command whose check characters (CRC-16 or 8-bit checksum) don't match
//! is not silently dropped: if it is addressed to this PD, the PD answers
//! osdp_NAK with error code 0x01 ("Message check character(s) error", spec
//! Table 47 / §5) so the ACU retransmits with the same SQN. A bad-check
//! frame addressed to *another* PD is left alone — a corrupt frame is too
//! weak a basis to answer on someone else's behalf.

#![cfg(feature = "pd")]

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::frame::{build, decode, FrameBuild, Integrity, FRAME_MARK_LEN};
use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK, OSDP_REPLY_NAK};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::Transport;

const PD_ADDRESS: u8 = 0x10;
const OTHER_ADDRESS: u8 = 0x11;
const NAK_BAD_CHECK: u8 = 0x01;

/// Feeds a fixed byte string to the PD and captures whatever it writes back.
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

struct AckPoll;
impl CommandHandler for AckPoll {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(osdp_embedded::Error::NotSupported),
        }
    }
}

/// Build a valid POLL frame to `address` in `integrity` mode, then flip the
/// trailing check character so it fails verification on receipt.
fn corrupt_poll(address: u8, integrity: Integrity) -> Vec<u8> {
    let frame = FrameBuild {
        address,
        sequence: 1,
        integrity: Some(integrity),
        code: OSDP_CMD_POLL,
        ..Default::default()
    };
    let mut buf = [0u8; 32];
    let n = build(&frame, &mut buf).expect("build POLL");
    let mut bytes = buf[..n].to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF; // corrupt the check character
    bytes
}

/// Drive a fresh PD@PD_ADDRESS with `input` for one tick; return its output.
fn drive(input: Vec<u8>) -> Vec<u8> {
    let output = Rc::new(RefCell::new(Vec::new()));
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(FeedTransport {
        input,
        pos: 0,
        output: Rc::clone(&output),
    });
    pd.set_command_handler(AckPoll);
    pd.tick();
    let out = output.borrow().clone();
    out
}

#[test]
fn bad_crc_addressed_to_us_naks_0x01() {
    let out = drive(corrupt_poll(PD_ADDRESS, Integrity::Crc));
    assert!(
        !out.is_empty(),
        "PD stayed silent on a bad-CRC command addressed to it"
    );
    let reply = decode(&out[FRAME_MARK_LEN..]).expect("decode reply");
    assert!(reply.reply, "reply flag not set");
    assert_eq!(reply.address, PD_ADDRESS);
    assert_eq!(reply.code, OSDP_REPLY_NAK);
    assert_eq!(reply.payload, [NAK_BAD_CHECK]);
    // The NAK mirrors the offending frame's integrity mode.
    assert_eq!(reply.integrity, Integrity::Crc);
}

#[test]
fn bad_checksum_addressed_to_us_naks_0x01() {
    let out = drive(corrupt_poll(PD_ADDRESS, Integrity::Checksum));
    assert!(
        !out.is_empty(),
        "PD stayed silent on a bad-checksum command addressed to it"
    );
    let reply = decode(&out[FRAME_MARK_LEN..]).expect("decode reply");
    assert_eq!(reply.code, OSDP_REPLY_NAK);
    assert_eq!(reply.payload, [NAK_BAD_CHECK]);
    assert_eq!(reply.integrity, Integrity::Checksum);
}

#[test]
fn bad_crc_addressed_to_another_pd_is_silent() {
    let out = drive(corrupt_poll(OTHER_ADDRESS, Integrity::Crc));
    assert!(
        out.is_empty(),
        "PD answered a bad-CRC frame addressed to another PD"
    );
}
