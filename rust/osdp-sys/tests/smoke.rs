// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Smoke test for `osdp-sys`: prove that the C library was compiled,
//! the symbols are reachable from Rust, and the FFI types we declared
//! agree with the C side at the ABI level.
//!
//! Three layers of confidence:
//!
//!   1. `osdp_crc16` returns a known-good value for a known-good input
//!      (CRC-16/X-25 / CCITT variant per OSDP Annex C).
//!
//!   2. We build a minimal POLL frame with `osdp_frame_build`, decode
//!      it back with `osdp_frame_decode`, and verify the round-trip
//!      preserves the header fields and integrity. This exercises
//!      `osdp_frame_t` field layout in both directions.
//!
//!   3. We allocate an `osdp_pd_t` and an `osdp_acu_t` on the stack and
//!      call their respective `_init`. If our struct sizes / alignment
//!      were wrong, this would write past the end of the stack frame
//!      or crash inside memset.
//!
//! That gives us enough certainty that the safe wrapper can build on
//! top without surprises.

use core::mem::MaybeUninit;
use core::ptr;

use osdp_sys::*;

/// Known CRC-16 vectors. The value below was produced by the C unit
/// tests (`tests/test_crc.c`) and is the canonical fixture.
#[test]
fn crc16_matches_known_vector() {
    // "123456789" — standard CRC test vector. OSDP CRC-16 with init
    // 0x1D0F, no reflection, no final xor produces 0xE5CC.
    let data = b"123456789";
    let crc = unsafe { osdp_crc16(data.as_ptr(), data.len()) };
    assert_eq!(crc, 0xE5CC, "osdp_crc16 vector mismatch");
}

#[test]
fn crc16_init_constant_round_trip() {
    // osdp_crc16(buf, len) and osdp_crc16_update(OSDP_CRC16_INIT, buf, len)
    // must agree.
    let data = b"hello osdp";
    let one_shot = unsafe { osdp_crc16(data.as_ptr(), data.len()) };
    let streamed = unsafe {
        osdp_crc16_update(OSDP_CRC16_INIT, data.as_ptr(), data.len())
    };
    assert_eq!(one_shot, streamed);
}

#[test]
fn checksum_matches_definition() {
    // Spec: cksum = (uint8_t)(- sum_of_bytes). For [0x01, 0x02, 0x03]
    // the sum is 0x06, so the checksum is 0xFA.
    let data = [0x01u8, 0x02, 0x03];
    let cksum = unsafe { osdp_checksum(data.as_ptr(), data.len()) };
    assert_eq!(cksum, 0xFA);
}

#[test]
fn poll_frame_round_trips() {
    // Build a POLL command (code 0x60, no payload, no SCB, CRC mode,
    // address 0x10, sequence 1). Decode it back. Header fields must
    // round-trip.
    let mut frame_in = osdp_frame_t {
        address:      0x10,
        reply:        false,
        sequence:     1,
        integrity:    osdp_integrity_t::OSDP_INTEGRITY_CRC,
        has_scb:      false,
        scb_length:   0,
        scb_type:     0,
        scb_data:     ptr::null(),
        scb_data_len: 0,
        code:         OSDP_CMD_POLL,
        payload:      ptr::null(),
        payload_len:  0,
        mac:          ptr::null(),
        mac_len:      0,
        raw:          ptr::null(),
        raw_len:      0,
    };

    let mut buf = [0u8; OSDP_FRAME_MAX_LEN];
    let mut written: usize = 0;
    let r = unsafe {
        osdp_frame_build(
            &frame_in as *const _,
            buf.as_mut_ptr(),
            buf.len(),
            &mut written,
        )
    };
    assert_eq!(r, osdp_status_t::OSDP_OK);
    assert!(written >= OSDP_FRAME_MIN_LEN_CRC);
    // First byte must be SOM.
    assert_eq!(buf[0], OSDP_SOM);

    // Decode back.
    let mut frame_out = MaybeUninit::<osdp_frame_t>::zeroed();
    let r = unsafe {
        osdp_frame_decode(buf.as_ptr(), written, frame_out.as_mut_ptr())
    };
    assert_eq!(r, osdp_status_t::OSDP_OK);
    let frame_out = unsafe { frame_out.assume_init() };
    assert_eq!(frame_out.address,    0x10);
    assert_eq!(frame_out.reply,      false);
    assert_eq!(frame_out.sequence,   1);
    assert_eq!(frame_out.integrity,  osdp_integrity_t::OSDP_INTEGRITY_CRC);
    assert_eq!(frame_out.has_scb,    false);
    assert_eq!(frame_out.code,       OSDP_CMD_POLL);
    assert_eq!(frame_out.payload_len, 0);

    // Suppress unused-mut warnings on the input frame.
    frame_in.address = 0x10;
    let _ = frame_in;
}

#[test]
fn pd_init_produces_addressable_struct() {
    // If our `osdp_pd_t` mirror has the wrong size or alignment,
    // `osdp_pd_init`'s memset-zero would clobber surrounding memory or
    // crash. Boxing it pulls the storage onto the heap which the
    // sanitizers will catch errors on.
    let mut pd = Box::<osdp_pd_t>::new(unsafe { core::mem::zeroed() });
    unsafe { osdp_pd_init(&mut *pd, 0x10) };
    assert_eq!(pd.address, 0x10);
    assert_eq!(pd.have_last, false);
    // is_online is false right after init (no reply sent yet).
    assert!(unsafe { !osdp_pd_is_online(&*pd) });
}

#[test]
fn acu_init_with_one_slot() {
    // ACU + one PD slot, both heap-allocated. Same purpose as the PD
    // test: catches struct-layout mistakes via memset-zero in init.
    let mut slot = Box::<osdp_acu_pd_slot_t>::new(unsafe { core::mem::zeroed() });
    let mut acu  = Box::<osdp_acu_t>::new(unsafe { core::mem::zeroed() });
    unsafe { osdp_acu_init(&mut *acu, &mut *slot, 1) };

    let r = unsafe { osdp_acu_register_pd(&mut *acu, 0, 0x10) };
    assert_eq!(r, osdp_status_t::OSDP_OK);
    assert!(slot.in_use);
    assert_eq!(slot.address, 0x10);
}
