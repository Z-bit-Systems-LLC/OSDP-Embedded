// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Wire-side I/O abstraction shared by [`Pd`](crate::pd::Pd) and
//! [`Acu`](crate::acu::Acu).
//!
//! The C side has two byte-identical transport vtables
//! (`osdp_pd_transport_t` and `osdp_acu_transport_t`); from the
//! application's perspective they're the same shape - read, write,
//! optional millisecond clock - so we expose one trait and let both
//! state machines use it.

/// Wire-side I/O. Implementations supply the bytes the OSDP state
/// machine reads and writes; both [`Pd::set_transport`](crate::pd::Pd::set_transport)
/// and [`Acu::set_transport`](crate::acu::Acu::set_transport) accept
/// any `T: Transport`.
///
/// `read` returns 0 on idle (no bytes available). Negative returns are
/// reserved for future error reporting; for now, return 0 on any
/// transient error. Bytes returned should belong to the slice the
/// caller provided.
///
/// `write` returns the byte count successfully written; a short write
/// is treated as a transmission error by the state machine.
///
/// `now_ms` is optional. If `None`, online/offline tracking is
/// disabled and the peer is "online" forever once it has sent a frame.
pub trait Transport: 'static {
    fn read(&mut self, buf: &mut [u8]) -> usize;
    fn write(&mut self, buf: &[u8]) -> usize;
    fn now_ms(&mut self) -> Option<u32>;
}
