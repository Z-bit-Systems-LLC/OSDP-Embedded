// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! AES-128 backend built on vendored tiny-AES-c.
//!
//! The C source lives in `vendor/tiny-aes/` (Unlicense / public
//! domain). [`build.rs`](../../../build.rs) compiles it with
//! `AES128=1 ECB=1 CBC=0 CTR=0` so only the ECB code path lands in
//! the binary.
//!
//! `AES_ECB_encrypt` / `AES_ECB_decrypt` operate in place. We stage
//! through a 16-byte stack buffer so the trait's `in_` / `out`
//! slices stay logically distinct (the wrapper in `osdp-embedded`
//! already copies through scratch, but keeping the convention here
//! makes the code easier to follow).
//!
//! RNG bytes come from `getrandom` — same source as the rustcrypto
//! backend.

use std::os::raw::c_void;

use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};

// tiny-AES-c's AES_ctx: 176 bytes of round-key for AES-128 ECB-only.
// Conservatively sized; the C struct may be slightly larger on
// platforms with non-trivial alignment, but a 256-byte buffer
// covers any plausible padding without leaking ABI knowledge.
const AES_CTX_SIZE: usize = 256;

#[repr(C, align(8))]
struct AesCtx {
    bytes: [u8; AES_CTX_SIZE],
}

extern "C" {
    fn AES_init_ctx(ctx: *mut c_void, key: *const u8);
    fn AES_ECB_encrypt(ctx: *const c_void, buf: *mut u8);
    fn AES_ECB_decrypt(ctx: *const c_void, buf: *mut u8);
}

pub struct TinyAesBackend;

impl TinyAesBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TinyAesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScCrypto for TinyAesBackend {
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        let mut ctx = AesCtx {
            bytes: [0u8; AES_CTX_SIZE],
        };
        let mut block = *in_;
        unsafe {
            AES_init_ctx(ctx.bytes.as_mut_ptr() as *mut c_void, key.as_ptr());
            AES_ECB_encrypt(ctx.bytes.as_ptr() as *const c_void, block.as_mut_ptr());
        }
        out.copy_from_slice(&block);
        Ok(())
    }

    fn aes_decrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        let mut ctx = AesCtx {
            bytes: [0u8; AES_CTX_SIZE],
        };
        let mut block = *in_;
        unsafe {
            AES_init_ctx(ctx.bytes.as_mut_ptr() as *mut c_void, key.as_ptr());
            AES_ECB_decrypt(ctx.bytes.as_ptr() as *const c_void, block.as_mut_ptr());
        }
        out.copy_from_slice(&block);
        Ok(())
    }

    fn rand_bytes(&mut self, out: &mut [u8]) -> osdp_embedded::Result<()> {
        getrandom::getrandom(out).map_err(|e| {
            tracing::error!(?e, "getrandom failed in tiny-aes RNG");
            osdp_embedded::Error::NotSupported
        })
    }
}
