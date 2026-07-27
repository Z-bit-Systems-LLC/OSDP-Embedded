// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Guards the hand-maintained `#[repr(C)]` mirror of `osdp_pd_t` in
//! `sys.rs` against drifting from the real C struct.
//!
//! CLAUDE.md flags this mirror as the project's sharpest footgun: growing a
//! field in `pd/include/osdp/osdp_pd.h` without matching it here is silent
//! heap corruption, not a compile error. Rust cannot see the C layout, so
//! `assert_eq!(size_of::<..>(), ..)` against a hard-coded number would only
//! restate the mirror's own opinion — useless.
//!
//! What makes a genuine check possible is that `osdp_pd_init` writes
//! *self-referential* values: each of the four working-buffer pointers is set
//! to the address of an embedded array in the same struct, and each capacity
//! to that array's `sizeof`. Reading those back through the Rust mirror and
//! confirming the pointers land exactly on the mirror's own arrays proves the
//! two layouts agree — because the C side computed the addresses and the Rust
//! side computed the expectations, independently. Any field inserted, resized,
//! or reordered before `cmd_cache` shifts one side relative to the other and
//! the pointer comparison fails.
//!
//! This does not prove the *tail* of the struct matches (fields after the last
//! self-referential one are unverified); it pins down everything up to and
//! including the buffer bindings, which is where every field so far has landed.

use crate::sys;
use alloc::boxed::Box;
use alloc::vec;
use core::mem::MaybeUninit;

/// Run `osdp_pd_init` on a zeroed context and hand the result to `check`.
/// Boxed so the struct's address is stable while we take interior pointers.
fn with_initialised_pd(check: impl FnOnce(&sys::osdp_pd_t)) {
    let mut pd = Box::<sys::osdp_pd_t>::new(unsafe { MaybeUninit::zeroed().assume_init() });
    unsafe { sys::osdp_pd_init(&mut *pd, 0x10) };
    check(&pd);
}

#[test]
fn init_binds_every_buffer_to_its_own_embedded_array() {
    with_initialised_pd(|pd| {
        // The C `osdp_pd_init` resolved these addresses; the Rust mirror
        // resolves the right-hand side. Equality means the two structs place
        // the arrays at the same offsets.
        assert_eq!(
            pd.tx.cast_const(),
            pd.tx_buf.as_ptr(),
            "tx must point at tx_buf — mirror is out of sync with osdp_pd_t"
        );
        assert_eq!(
            pd.rx_plain.cast_const(),
            pd.rx_plain_buf.as_ptr(),
            "rx_plain must point at rx_plain_buf"
        );
        assert_eq!(
            pd.rpl_cache.cast_const(),
            pd.last_reply.as_ptr(),
            "rpl_cache must point at last_reply"
        );
        assert_eq!(
            pd.cmd_cache.cast_const(),
            pd.last_cmd.as_ptr(),
            "cmd_cache must point at last_cmd"
        );
    });
}

#[test]
fn init_binds_every_capacity_to_its_array_length() {
    with_initialised_pd(|pd| {
        // Capacities come from `sizeof()` on the C side. If the mirror's
        // OSDP_PD_TX_BUF_LEN disagreed with the header's, these would differ.
        assert_eq!(pd.tx_cap, sys::OSDP_PD_TX_BUF_LEN);
        assert_eq!(pd.rx_plain_cap, sys::OSDP_PD_TX_BUF_LEN);
        assert_eq!(pd.rpl_cache_cap, sys::OSDP_PD_TX_BUF_LEN);
        assert_eq!(pd.cmd_cache_cap, sys::OSDP_PD_TX_BUF_LEN);
    });
}

#[test]
fn init_leaves_the_address_the_caller_asked_for() {
    // Cheap anchor on the FRONT of the struct: `address` is field 0, so a
    // mismatch here means the mirror's head is wrong rather than its middle.
    with_initialised_pd(|pd| {
        assert_eq!(pd.address, 0x10);
        assert!(!pd.have_last, "a fresh PD has no cached command");
        assert_eq!(pd.last_reply_len, 0);
        assert_eq!(pd.last_cmd_len, 0);
    });
}

#[test]
fn set_buffers_rebinds_only_what_it_is_given() {
    let mut pd = Box::<sys::osdp_pd_t>::new(unsafe { MaybeUninit::zeroed().assume_init() });
    unsafe { sys::osdp_pd_init(&mut *pd, 0x10) };

    let mut big_tx = vec![0u8; 1440];
    let default_rx_plain = pd.rx_plain;

    let bufs = sys::osdp_pd_buffers_t {
        tx: big_tx.as_mut_ptr(),
        tx_cap: big_tx.len(),
        // Everything else NULL: "leave this region alone".
        rx_plain: core::ptr::null_mut(),
        rx_plain_cap: 0,
        rpl_cache: core::ptr::null_mut(),
        rpl_cache_cap: 0,
        cmd_cache: core::ptr::null_mut(),
        cmd_cache_cap: 0,
    };
    let rc = unsafe { sys::osdp_pd_set_buffers(&mut *pd, &bufs) };
    assert_eq!(rc, sys::osdp_status_t::OSDP_OK);

    assert_eq!(pd.tx.cast_const(), big_tx.as_ptr(), "tx should be rebound");
    assert_eq!(pd.tx_cap, 1440);
    assert_eq!(
        pd.rx_plain, default_rx_plain,
        "a NULL member must leave its region on the previous binding"
    );
    assert_eq!(pd.rx_plain_cap, sys::OSDP_PD_TX_BUF_LEN);
}

#[test]
fn set_buffers_rejects_an_undersized_region_without_applying_anything() {
    let mut pd = Box::<sys::osdp_pd_t>::new(unsafe { MaybeUninit::zeroed().assume_init() });
    unsafe { sys::osdp_pd_init(&mut *pd, 0x10) };

    let default_tx = pd.tx;
    let mut ok_tx = vec![0u8; 512];
    let mut tiny = [0u8; 4]; // under OSDP_PD_BUF_MIN_LEN (8)

    let bufs = sys::osdp_pd_buffers_t {
        tx: ok_tx.as_mut_ptr(),
        tx_cap: ok_tx.len(),
        rx_plain: tiny.as_mut_ptr(),
        rx_plain_cap: tiny.len(),
        rpl_cache: core::ptr::null_mut(),
        rpl_cache_cap: 0,
        cmd_cache: core::ptr::null_mut(),
        cmd_cache_cap: 0,
    };
    let rc = unsafe { sys::osdp_pd_set_buffers(&mut *pd, &bufs) };
    assert_eq!(rc, sys::osdp_status_t::OSDP_ERR_BUFFER_TOO_SMALL);

    // All-or-nothing: the valid `tx` in the same call must NOT have landed.
    assert_eq!(
        pd.tx, default_tx,
        "a rejected set_buffers must leave every region on its previous binding"
    );
    assert_eq!(pd.tx_cap, sys::OSDP_PD_TX_BUF_LEN);
}
