// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Smoke test for `osdp-embedded`. Exercises the same surface the old
//! osdp-sys-level tests covered, but through the public safe API:
//!
//!   1. CRC and checksum match known fixtures (proves the C library
//!      compiled and the FFI seam delivered correct byte values).
//!
//!   2. A POLL frame round-trips through `frame::build` /
//!      `frame::decode` preserving header fields (proves the
//!      `osdp_frame_t` struct layout in both directions).
//!
//!   3. With `pd` feature on: `Pd::new(0x10)` allocates and initialises
//!      cleanly. With `acu` feature on: `Acu::new(1) +
//!      register_pd(...)` does the same. Bad struct-layout assumptions
//!      (size or alignment) would crash inside the C-side memset-zero.

use osdp_embedded::frame::{build, checksum, crc16, decode, FrameBuild, Integrity, FRAME_MARK_LEN};
use osdp_embedded::messages::OSDP_CMD_POLL;

#[test]
fn crc16_matches_known_vector() {
    // "123456789" - standard CRC test vector. OSDP CRC-16 with init
    // 0x1D0F, no reflection, no final xor produces 0xE5CC.
    assert_eq!(crc16(b"123456789"), 0xE5CC);
}

#[test]
fn checksum_matches_definition() {
    // Spec: cksum = (uint8_t)(- sum_of_bytes). For [0x01, 0x02, 0x03]
    // the sum is 0x06, so the checksum is 0xFA.
    assert_eq!(checksum(&[0x01, 0x02, 0x03]), 0xFA);
}

#[test]
fn poll_frame_round_trips() {
    let frame_in = FrameBuild {
        address: 0x10,
        sequence: 1,
        integrity: Some(Integrity::Crc),
        code: OSDP_CMD_POLL,
        ..Default::default()
    };
    let mut buf = [0u8; 16];
    let n = build(&frame_in, &mut buf).expect("frame::build");

    // build() prepends the spec-5.7 marking byte(s) ahead of the SOM;
    // decode() expects SOM-aligned input, so skip them.
    let frame_out = decode(&buf[FRAME_MARK_LEN..n]).expect("frame::decode");
    assert_eq!(frame_out.address, 0x10);
    assert!(!frame_out.reply);
    assert_eq!(frame_out.sequence, 1);
    assert_eq!(frame_out.integrity, Integrity::Crc);
    assert!(frame_out.scb.is_none());
    assert_eq!(frame_out.code, OSDP_CMD_POLL);
    assert!(frame_out.payload.is_empty());
}

#[cfg(feature = "pd")]
#[test]
fn pd_constructible() {
    let pd = osdp_embedded::pd::Pd::new(0x10);
    // Fresh PD hasn't sent anything yet, so it's not online.
    assert!(!pd.is_online());
}

#[cfg(feature = "acu")]
#[test]
fn acu_constructible_with_one_slot() {
    let mut acu = osdp_embedded::acu::Acu::new(1);
    acu.register_pd(0, 0x10).expect("register_pd");
    assert_eq!(acu.pd_count(), 1);
    // A registered but never-replied PD is offline from the ACU's view.
    assert!(!acu.is_pd_online(0x10));
}
