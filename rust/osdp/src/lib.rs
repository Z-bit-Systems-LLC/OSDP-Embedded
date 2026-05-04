// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Safe Rust wrapper around the OSDP-Embedded C library.
//!
//! Built on top of [`osdp_sys`]. Provides idiomatic Rust types around
//! the C state machines and codecs without reimplementing protocol
//! logic in Rust — every operation delegates to the C side, so the C
//! unit tests continue to be the authoritative correctness oracle.
//!
//! # What's covered
//!
//! - [`Error`] / [`Result`] over the C `osdp_status_t` enum.
//! - [`frame::Frame`] for decoding and building Layer-1 frames.
//! - [`pd::Pd`] — PD-side state machine, with [`pd::Transport`] and
//!   [`pd::CommandHandler`] traits.
//! - [`acu::Acu`] — ACU-side state machine, with [`acu::Transport`],
//!   [`acu::ReplyHandler`], and [`acu::TimeoutHandler`] traits.
//! - [`sc::ScCrypto`] for application-supplied AES + RNG, plus the
//!   PD-side SCBK / SCBK-D / cUID setters and the ACU-side
//!   `start_sc_handshake` + [`sc::ScEventHandler`].
//!
//! # Not covered (yet)
//!
//! - Per-message codec wrappers. The C codecs are exposed via
//!   `osdp_sys` (e.g. `osdp_sys::osdp_pdid_build`) but no typesafe
//!   sugar yet.
//!
//! # Threading
//!
//! [`pd::Pd`] and [`acu::Acu`] are deliberately **not** `Send`. The
//! callbacks they hold are `dyn Trait` objects with a `'static` bound
//! and the underlying C state is not synchronised. Drive each peer
//! from one thread.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod acu;
pub mod error;
pub mod frame;
pub mod pd;
pub mod sc;

pub use error::{Error, Result};
