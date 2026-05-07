// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Safe Rust wrapper around the OSDP-Embedded C library.
//!
//! Provides idiomatic Rust types around the C state machines and codecs
//! without reimplementing protocol logic in Rust - every operation
//! delegates to the C side, so the C unit tests continue to be the
//! authoritative correctness oracle.
//!
//! # Cargo features
//!
//! By default the crate brings everything along (PD + ACU + std). For
//! a tighter footprint (e.g. embedded firmware), opt out:
//!
//! ```toml
//! # Pure PD device firmware:
//! osdp-embedded = { version = "0.1", default-features = false, features = ["pd"] }
//!
//! # ACU controller in a Linux app:
//! osdp-embedded = { version = "0.1", features = ["acu"] }
//! ```
//!
//! Disabling a role-feature also drops the matching .c files from the
//! C compilation, so a PD-only firmware doesn't carry any ACU code.
//!
//! Default features: `["std", "pd", "acu"]`.
//!
//! # What's covered
//!
//! - [`Error`] / [`Result`] over the C `osdp_status_t` enum.
//! - [`frame::Frame`] for decoding and building Layer-1 frames.
//! - [`messages`] - typed decoders and builders for every command and
//!   reply in the OSDP v2.2.2 baseline set.
//! - [`Transport`] - shared read/write/now_ms callback trait used by
//!   both PD and ACU when bound via `set_transport`.
//! - [`sc::ScCrypto`] for application-supplied AES + RNG.
//! - [`pd::Pd`] (feature `pd`) - PD-side state machine, with
//!   [`pd::CommandHandler`].
//! - [`acu::Acu`] (feature `acu`) - ACU-side state machine, with
//!   [`acu::ReplyHandler`], [`acu::TimeoutHandler`], and the
//!   [`sc::ScEventHandler`] for SC handshake outcomes.
//!
//! # Threading
//!
//! [`pd::Pd`] and [`acu::Acu`] are deliberately **not** `Send`. The
//! callbacks they hold are `dyn Trait` objects with a `'static` bound
//! and the underlying C state is not synchronised. Drive each peer
//! from one thread.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// In-crate FFI seam. Private to the crate; consumers go through the
// safe modules (frame, messages, pd, acu, sc).
pub(crate) mod sys;

pub mod error;
pub mod frame;
pub mod messages;
pub mod sc;
pub mod transport;

#[cfg(feature = "pd")]
pub mod pd;

#[cfg(feature = "acu")]
pub mod acu;

pub use error::{Error, Result};
pub use transport::Transport;
