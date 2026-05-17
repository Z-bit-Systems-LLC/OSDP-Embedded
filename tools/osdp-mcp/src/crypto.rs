// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Pluggable AES + RNG providers for Secure Channel.
//!
//! The library (`osdp_embedded`) never vendors crypto — every PD or
//! ACU consumer hands it an `ScCrypto` impl with `aes_encrypt`,
//! `aes_decrypt`, and `rand_bytes` callbacks. osdp-mcp inherits that
//! design and lets the user choose which AES backend to compile in
//! (Cargo feature) and which one to use at runtime (`--crypto` CLI
//! flag).
//!
//! Backends shipped today:
//!
//!   - `rustcrypto` — pure-Rust constant-time AES-128 from the
//!     [`aes`](https://crates.io/crates/aes) crate. Default. No
//!     external dependencies; works on every host the rest of the
//!     binary builds for.
//!   - `tiny-aes` — vendored tiny-AES-c (`vendor/tiny-aes/`). Tiny
//!     code size, no constant-time guarantees. Useful for parity
//!     with the C-side osdp-pd-mock tool and for hosts where the
//!     RustCrypto build is too heavy.
//!
//! Both backends source random bytes from `getrandom` (the OS CSPRNG
//! — `BCryptGenRandom` / `/dev/urandom` / `getentropy`).
//!
//! Adding a third backend (wolfCrypt, hardware AES, mbedTLS, …) is a
//! single file in this module behind a new `crypto-*` feature, plus
//! one arm in [`Selector::factory`].

use std::str::FromStr;
use std::sync::Arc;

use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};

/// Forwarding wrapper that adapts a `Box<dyn ScCrypto>` (the erased
/// type the factory returns) into a concrete `ScCrypto` impl. Needed
/// because `Pd::set_sc_crypto<C: ScCrypto>(c: C)` takes the impl by
/// value, but our runtime selection model erases the backend type.
pub struct BoxedSc(pub Box<dyn ScCrypto>);

impl ScCrypto for BoxedSc {
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        self.0.aes_encrypt(key, in_, out)
    }

    fn aes_decrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> osdp_embedded::Result<()> {
        self.0.aes_decrypt(key, in_, out)
    }

    fn rand_bytes(&mut self, out: &mut [u8]) -> osdp_embedded::Result<()> {
        self.0.rand_bytes(out)
    }
}

#[cfg(feature = "crypto-rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "crypto-tiny-aes")]
pub mod tiny_aes;

/// A factory that mints a fresh `ScCrypto` impl per PD instance.
/// Used by the PD actor: every `pd_configure` that enables SC pulls
/// a new boxed provider out of the factory so each PD has its own
/// crypto state (notably, the RNG seed).
pub type CryptoFactory = Arc<dyn Fn() -> Box<dyn ScCrypto> + Send + Sync + 'static>;

/// User-visible names for the compiled-in crypto backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    RustCrypto,
    TinyAes,
}

impl Selector {
    /// All backends compiled into this binary.
    //
    // unused_mut: mut isn't needed when no crypto features are on.
    // vec_init_then_push: cfg-conditional pushes can't be expressed
    // as a single vec![] literal.
    #[allow(unused_mut, clippy::vec_init_then_push)]
    pub fn available() -> Vec<Self> {
        let mut v = Vec::new();
        #[cfg(feature = "crypto-rustcrypto")]
        v.push(Self::RustCrypto);
        #[cfg(feature = "crypto-tiny-aes")]
        v.push(Self::TinyAes);
        v
    }

    /// Best default: the first compiled-in backend in preference
    /// order (RustCrypto, then TinyAes). Caller verifies at startup
    /// that at least one backend exists.
    pub fn default_for_build() -> Option<Self> {
        Self::available().into_iter().next()
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::RustCrypto => "rustcrypto",
            Self::TinyAes => "tiny-aes",
        }
    }

    /// Build a [`CryptoFactory`] for the chosen backend. Returns an
    /// error string if the backend wasn't compiled in (so the binary
    /// can surface a clear "rebuild with --features crypto-X" hint).
    pub fn factory(self) -> Result<CryptoFactory, String> {
        match self {
            Self::RustCrypto => {
                #[cfg(feature = "crypto-rustcrypto")]
                {
                    Ok(Arc::new(|| {
                        Box::new(rustcrypto::RustCryptoBackend::new()) as Box<dyn ScCrypto>
                    }))
                }
                #[cfg(not(feature = "crypto-rustcrypto"))]
                {
                    Err("rustcrypto backend not compiled in; rebuild with \
                         `--features crypto-rustcrypto`"
                        .into())
                }
            }
            Self::TinyAes => {
                #[cfg(feature = "crypto-tiny-aes")]
                {
                    Ok(Arc::new(|| {
                        Box::new(tiny_aes::TinyAesBackend::new()) as Box<dyn ScCrypto>
                    }))
                }
                #[cfg(not(feature = "crypto-tiny-aes"))]
                {
                    Err("tiny-aes backend not compiled in; rebuild with \
                         `--features crypto-tiny-aes`"
                        .into())
                }
            }
        }
    }
}

impl FromStr for Selector {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "rustcrypto" | "rust-crypto" => Ok(Self::RustCrypto),
            "tiny-aes" | "tiny_aes" | "tinyaes" => Ok(Self::TinyAes),
            other => Err(format!(
                "unknown crypto backend {other:?}; available: {}",
                Self::available()
                    .into_iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}
