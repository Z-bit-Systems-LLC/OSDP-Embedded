// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! AES-128 backend built on the [`aes`] RustCrypto crate. Pure Rust,
//! constant-time, no external setup. RNG bytes come from `getrandom`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};

pub struct RustCryptoBackend;

impl RustCryptoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustCryptoBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScCrypto for RustCryptoBackend {
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
        getrandom::getrandom(out).map_err(|e| {
            tracing::error!(?e, "getrandom failed in rustcrypto RNG");
            osdp_embedded::Error::NotSupported
        })
    }
}
