// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! AES-128 backend built on the [`aes`] RustCrypto crate. Pure Rust,
//! constant-time, no external setup. RNG bytes come from `getrandom`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes256Gcm;
use tiny_keccak::{Hasher, Kmac};

use osdp_embedded::sc::{
    ScCrypto, ScCrypto2, AES_BLOCK_LEN, AES_KEY_LEN, SC2_KEY_LEN, SC2_NONCE_LEN, SC2_TAG_LEN,
};

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

/// OSDP-SC2 backend: AES-256-GCM ([`aes_gcm`]) + KMAC256
/// ([`tiny_keccak`]) + a raw AES-256 block ([`aes`]). Pure Rust,
/// `getrandom` for the RNG. Backs the MCP virtual PD's `scbk2` mode.
pub struct RustCrypto2Backend;

impl RustCrypto2Backend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustCrypto2Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScCrypto2 for RustCrypto2Backend {
    fn kmac256(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) -> osdp_embedded::Result<()> {
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
        getrandom::getrandom(out).map_err(|e| {
            tracing::error!(?e, "getrandom failed in rustcrypto SC2 RNG");
            osdp_embedded::Error::NotSupported
        })
    }
}
