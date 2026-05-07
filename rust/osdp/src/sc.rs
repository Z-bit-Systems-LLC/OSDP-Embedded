// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Secure Channel — application-supplied crypto + key configuration.
//!
//! `osdp::core` does not vendor a crypto implementation: AES-128 ECB
//! and the RNG are supplied by the application via the [`ScCrypto`]
//! trait. The wrapper here adapts that trait into the C-side
//! [`osdp_sys::osdp_sc_crypto_t`] vtable, which the C state machines
//! call into for every key derivation, cryptogram, MAC, and CBC-mode
//! payload encrypt/decrypt operation during a Secure Channel session.
//!
//! Bind one [`ScCrypto`] implementation per peer:
//!
//!   - On a [`Pd`](crate::pd::Pd): `pd.set_sc_crypto(...)`,
//!     `set_sc_scbk` and/or `set_sc_scbk_d`, and `set_sc_cuid`.
//!   - On an [`Acu`](crate::acu::Acu): `acu.set_sc_crypto(...)`, then
//!     per-PD `set_pd_scbk` / `set_pd_scbk_d`, plus optionally
//!     `set_sc_event_handler`. Trigger the handshake with
//!     `acu.start_sc_handshake(pd_address, use_default_key)`.

// `Box`, `c_void`, and `ptr` are used by the C-side vtable thunks
// below, which only compile when at least one role feature is active
// (the thunks have no callers without `pd` or `acu`). Gating the
// imports too keeps the core-only build (`--no-default-features`)
// warning-free.
#[cfg(any(feature = "pd", feature = "acu"))]
use alloc::boxed::Box;
#[cfg(any(feature = "pd", feature = "acu"))]
use core::ffi::c_void;
#[cfg(any(feature = "pd", feature = "acu"))]
use core::ptr;

use crate::sys;

use crate::error::{Error, Result};

/// Length of an SC base key (SCBK / SCBK-D) in bytes.
pub const SC_KEY_LEN: usize = sys::OSDP_SC_KEY_LEN;
/// Length of the cUID — first 8 bytes of the PDID byte stream per
/// spec D.4.3.
pub const SC_CUID_LEN: usize = sys::OSDP_SC_CUID_LEN;
/// AES-128 block size, also the key size for the symmetric primitives
/// the C side calls into.
pub const AES_BLOCK_LEN: usize = sys::OSDP_AES_BLOCK_LEN;
pub const AES_KEY_LEN: usize = sys::OSDP_AES_KEY_LEN;

/// Default install-time SCBK ("SCBK-D") from spec D.4 — re-export of
/// `osdp_sys::OSDP_SCBK_DEFAULT`. Known to anyone with the public spec;
/// only PDs in installation mode are supposed to use it.
#[inline]
pub fn scbk_default() -> &'static [u8; SC_KEY_LEN] {
    // Safety: `OSDP_SCBK_DEFAULT` is a `static` array in C, exposed as
    // `extern static`. Reading it is always safe; the `&` produces a
    // shared reference for an arbitrary lifetime, which we narrow to
    // `'static` since the underlying storage is.
    unsafe { &sys::OSDP_SCBK_DEFAULT }
}

/// Application-supplied crypto provider. One instance per OSDP peer.
///
/// The C side calls these from inside [`Pd::tick`](crate::pd::Pd::tick)
/// and [`Acu::tick`](crate::acu::Acu::tick) whenever a Secure Channel
/// operation is in flight.
///
/// Implementations on bare-metal targets typically wrap a hardware AES
/// peripheral; on hosted targets they wrap mbedTLS, OpenSSL, BearSSL,
/// or a Rust crate like [`aes`](https://crates.io/crates/aes). The RNG
/// callback should ideally be a CSPRNG; for tests a deterministic LCG
/// is fine.
pub trait ScCrypto: 'static {
    /// Encrypt one 16-byte block under `key`.
    ///
    /// In the C contract `out` may alias `in_`. The wrapper copies
    /// `in_` to an internal scratch buffer before calling this method,
    /// so implementers see distinct slices and can ignore the
    /// aliasing case.
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()>;

    /// Decrypt one 16-byte block. Required for receiving SCS_17/18
    /// encrypted payloads. Default impl returns `Err(NotSupported)`
    /// for one-direction agents (e.g. a Monitor verifying MACs only).
    fn aes_decrypt(
        &mut self,
        _key: &[u8; AES_KEY_LEN],
        _in_: &[u8; AES_BLOCK_LEN],
        _out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()> {
        Err(Error::NotSupported)
    }

    /// Fill `out` with cryptographically-random bytes. Required by the
    /// side that generates randomness during the SC handshake (ACU
    /// generates 8-byte RND.A; PD generates 8-byte RND.B). Default
    /// impl returns `Err(NotSupported)` for consume-only agents.
    fn rand_bytes(&mut self, _out: &mut [u8]) -> Result<()> {
        Err(Error::NotSupported)
    }
}

// ---- C-side vtable plumbing --------------------------------------------
//
// The thunks below adapt a `Box<dyn ScCrypto>` into the C
// `osdp_sc_crypto_t` vtable. They're called from inside the C-side
// state machines, so they're only meaningful when at least one role
// (PD or ACU) is feature-enabled. With neither, this section compiles
// cleanly but is dead code; gating avoids the dead-code warnings
// without forfeiting the ScCrypto trait itself (consumers building
// their own monitor-style wrapper might still want it).

#[cfg(any(feature = "pd", feature = "acu"))]
pub(crate) type ScCryptoBox = Box<dyn ScCrypto>;

#[cfg(any(feature = "pd", feature = "acu"))]
/// Build a C `osdp_sc_crypto_t` whose function pointers route into the
/// supplied trait object. Returns the raw user pointer the caller must
/// reclaim (via `Box::from_raw`) and stash inside the owning struct.
pub(crate) fn build_vtable(crypto: ScCryptoBox) -> (sys::osdp_sc_crypto_t, *mut c_void) {
    let boxed: Box<ScCryptoBox> = Box::new(crypto);
    let user = Box::into_raw(boxed) as *mut c_void;
    let v = sys::osdp_sc_crypto_t {
        aes128_ecb_encrypt: Some(aes_encrypt_thunk),
        aes128_ecb_decrypt: Some(aes_decrypt_thunk),
        rand_bytes: Some(rand_thunk),
        user,
    };
    (v, user)
}

#[cfg(any(feature = "pd", feature = "acu"))]
/// Shared implementation for both the encrypt and decrypt thunks: copy
/// the 16-byte input to a stack buffer (handles potential aliasing
/// with `out`), then dispatch into the trait method.
unsafe fn run_block_op(
    user: *mut c_void,
    key: *const u8,
    in_: *const u8,
    out: *mut u8,
    op: impl FnOnce(
        &mut dyn ScCrypto,
        &[u8; AES_KEY_LEN],
        &[u8; AES_BLOCK_LEN],
        &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()>,
) -> sys::osdp_status_t {
    let storage = &mut *(user as *mut ScCryptoBox);

    // Copy key + input out into owned arrays so we can hand &T / &mut T
    // to the trait method without aliasing concerns.
    let mut key_arr = [0u8; AES_KEY_LEN];
    let mut in_arr = [0u8; AES_BLOCK_LEN];
    ptr::copy_nonoverlapping(key, key_arr.as_mut_ptr(), AES_KEY_LEN);
    ptr::copy_nonoverlapping(in_, in_arr.as_mut_ptr(), AES_BLOCK_LEN);

    // Stage output through a stack buffer too — mirrors the input
    // copy so an aliasing call doesn't cause us to write into `out`
    // while the trait method is still reading from it.
    let mut out_arr = [0u8; AES_BLOCK_LEN];
    let r = op(storage.as_mut(), &key_arr, &in_arr, &mut out_arr);

    if r.is_ok() {
        ptr::copy_nonoverlapping(out_arr.as_ptr(), out, AES_BLOCK_LEN);
    }
    match r {
        Ok(()) => sys::osdp_status_t::OSDP_OK,
        Err(e) => e.to_status(),
    }
}

#[cfg(any(feature = "pd", feature = "acu"))]
unsafe extern "C" fn aes_encrypt_thunk(
    user: *mut c_void,
    key: *const u8,
    in_: *const u8,
    out: *mut u8,
) -> sys::osdp_status_t {
    run_block_op(user, key, in_, out, |c, k, i, o| c.aes_encrypt(k, i, o))
}

#[cfg(any(feature = "pd", feature = "acu"))]
unsafe extern "C" fn aes_decrypt_thunk(
    user: *mut c_void,
    key: *const u8,
    in_: *const u8,
    out: *mut u8,
) -> sys::osdp_status_t {
    run_block_op(user, key, in_, out, |c, k, i, o| c.aes_decrypt(k, i, o))
}

#[cfg(any(feature = "pd", feature = "acu"))]
unsafe extern "C" fn rand_thunk(user: *mut c_void, out: *mut u8, len: usize) -> sys::osdp_status_t {
    let storage = &mut *(user as *mut ScCryptoBox);
    let slice = core::slice::from_raw_parts_mut(out, len);
    match storage.rand_bytes(slice) {
        Ok(()) => sys::osdp_status_t::OSDP_OK,
        Err(e) => e.to_status(),
    }
}

// ---- ACU-side SC events ------------------------------------------------
//
// SC handshake outcomes are reported by the ACU only - the PD's
// handshake state is queryable directly via `Pd::sc_established`. These
// types and the dispatch thunk are gated on the `acu` feature so a
// PD-only build doesn't carry them.

#[cfg(feature = "acu")]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ScEventKind {
    /// Handshake completed; SCS_15..18 traffic is now permitted on
    /// this slot.
    Established,
    /// Handshake failed cryptographically — bad CCRYPT or RMAC_I
    /// status 0xFF. The slot is back in IDLE; the application may
    /// retry.
    HandshakeFailed,
    /// An established session terminated — MAC failure on an inbound
    /// SCS_16/18, a non-BUSY plaintext reply during ESTABLISHED, the
    /// PD replied with SQN=0, or the line went silent past the
    /// 8-second offline threshold (see `osdp::acu` docs and PLAN.md).
    SessionLost,
}

#[cfg(feature = "acu")]
impl ScEventKind {
    fn from_sys(k: sys::osdp_acu_sc_event_kind_t) -> Self {
        match k {
            sys::osdp_acu_sc_event_kind_t::ESTABLISHED => Self::Established,
            sys::osdp_acu_sc_event_kind_t::HANDSHAKE_FAILED => Self::HandshakeFailed,
            sys::osdp_acu_sc_event_kind_t::SESSION_LOST => Self::SessionLost,
            // Forward-compatible: any unknown event maps to SessionLost
            // since the slot has already returned to IDLE on the C side.
            _ => Self::SessionLost,
        }
    }
}

#[cfg(feature = "acu")]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ScEvent {
    pub pd_address: u8,
    pub kind: ScEventKind,
}

#[cfg(feature = "acu")]
pub trait ScEventHandler: 'static {
    fn on_sc_event(&mut self, event: &ScEvent);
}

#[cfg(feature = "acu")]
pub(crate) type ScEventBox = Box<dyn ScEventHandler>;

#[cfg(feature = "acu")]
pub(crate) unsafe extern "C" fn sc_event_thunk(
    user: *mut c_void,
    event: *const sys::osdp_acu_sc_event_t,
) {
    let storage = &mut *(user as *mut ScEventBox);
    let e = &*event;
    storage.on_sc_event(&ScEvent {
        pd_address: e.pd_address,
        kind: ScEventKind::from_sys(e.kind),
    });
}
