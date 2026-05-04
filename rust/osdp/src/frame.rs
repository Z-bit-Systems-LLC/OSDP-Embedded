// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Layer-1 frame decode and build.
//!
//! Wraps `osdp_frame_decode` / `osdp_frame_build`. The decode side
//! returns a [`Frame<'a>`] that borrows the input slice — the C side
//! never copies frame payloads, and neither do we. The build side
//! takes a [`FrameBuild`] (a value-typed view of a frame to be
//! assembled) plus a caller-provided output buffer.

use core::mem::MaybeUninit;
use core::ptr;
use core::slice;

use osdp_sys as sys;

use crate::error::{Error, Result};

/// Re-export of the frame size limits so callers don't have to reach
/// into `osdp-sys` directly.
pub const FRAME_MAX_LEN: usize = sys::OSDP_FRAME_MAX_LEN;
/// Smallest valid CRC-mode frame.
pub const FRAME_MIN_LEN_CRC: usize = sys::OSDP_FRAME_MIN_LEN_CRC;
/// Smallest valid checksum-mode frame.
pub const FRAME_MIN_LEN_CKSUM: usize = sys::OSDP_FRAME_MIN_LEN_CKSUM;

/// Whether a frame uses the 16-bit CRC or the legacy 8-bit checksum.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Integrity {
    Checksum,
    Crc,
}

impl Integrity {
    fn into_sys(self) -> sys::osdp_integrity_t {
        match self {
            Integrity::Checksum => sys::osdp_integrity_t::OSDP_INTEGRITY_CHECKSUM,
            Integrity::Crc      => sys::osdp_integrity_t::OSDP_INTEGRITY_CRC,
        }
    }

    fn from_sys(s: sys::osdp_integrity_t) -> Self {
        if s == sys::osdp_integrity_t::OSDP_INTEGRITY_CRC {
            Integrity::Crc
        } else {
            Integrity::Checksum
        }
    }
}

/// A decoded OSDP frame, with all slice fields borrowing the input
/// buffer that produced it.
#[derive(Debug)]
pub struct Frame<'a> {
    pub address:    u8,
    pub reply:      bool,
    pub sequence:   u8,
    pub integrity:  Integrity,
    /// `Some` when the frame carried a security control block.
    pub scb:        Option<Scb<'a>>,
    pub code:       u8,
    pub payload:    &'a [u8],
    /// Truncated MAC trailing bytes for SCS_15..18 frames; empty for
    /// every other frame.
    pub mac:        &'a [u8],
    /// The raw bytes the frame occupies, including SOM and trailing
    /// integrity. Useful for SC verification.
    pub raw:        &'a [u8],
}

#[derive(Debug)]
pub struct Scb<'a> {
    /// Total SCB length, including the length byte itself (matches the
    /// on-the-wire SEC_BLK_LEN).
    pub length: u8,
    pub ty:     u8,
    pub data:   &'a [u8],
}

/// Decode one OSDP frame from `buf`. The returned [`Frame`] borrows
/// `buf`; the input must outlive every use of the frame.
pub fn decode(buf: &[u8]) -> Result<Frame<'_>> {
    let mut raw = MaybeUninit::<sys::osdp_frame_t>::zeroed();
    let s = unsafe {
        sys::osdp_frame_decode(buf.as_ptr(), buf.len(), raw.as_mut_ptr())
    };
    Error::from_status(s)?;
    let raw = unsafe { raw.assume_init() };

    Ok(unsafe { frame_from_sys(&raw, buf) })
}

/// Convert a freshly-decoded `osdp_frame_t` into a borrowed [`Frame`].
///
/// SAFETY: every slice pointer in `raw` must point into `_parent` (or
/// be NULL with the matching `_len == 0`). The `_parent` argument is
/// taken solely to anchor the output lifetime to the input slice — its
/// contents aren't read; we trust the C decoder to have produced
/// pointers into the same buffer.
unsafe fn frame_from_sys<'a>(
    raw:     &sys::osdp_frame_t,
    _parent: &'a [u8],
) -> Frame<'a> {
    let scb = if raw.has_scb {
        Some(Scb {
            length: raw.scb_length,
            ty:     raw.scb_type,
            data:   slice_from_raw(raw.scb_data, raw.scb_data_len),
        })
    } else {
        None
    };

    Frame {
        address:   raw.address,
        reply:     raw.reply,
        sequence:  raw.sequence,
        integrity: Integrity::from_sys(raw.integrity),
        scb,
        code:      raw.code,
        payload:   slice_from_raw(raw.payload, raw.payload_len),
        mac:       slice_from_raw(raw.mac, raw.mac_len),
        raw:       slice_from_raw(raw.raw, raw.raw_len),
    }
}

/// `slice::from_raw_parts` but tolerating `(NULL, 0)` from C.
unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

/// All the fields a caller fills in to build a frame. Mirrors
/// [`Frame`] but is owned (and the slices reference caller-owned
/// memory).
#[derive(Default)]
pub struct FrameBuild<'a> {
    pub address:   u8,
    pub reply:     bool,
    pub sequence:  u8,
    pub integrity: Option<Integrity>, // None defaults to Crc
    pub scb:       Option<ScbBuild<'a>>,
    pub code:      u8,
    pub payload:   &'a [u8],
    /// For SCS_15..18 the caller may pre-compute the truncated MAC and
    /// pass it here. Most callers wrap via the SC helpers instead and
    /// don't touch this directly.
    pub mac:       &'a [u8],
}

pub struct ScbBuild<'a> {
    pub length: u8,
    pub ty:     u8,
    pub data:   &'a [u8],
}

/// Build a frame into `out`, returning the number of bytes written.
pub fn build(in_: &FrameBuild<'_>, out: &mut [u8]) -> Result<usize> {
    // Translate the safe view into the C struct layout.
    let mut raw = sys::osdp_frame_t {
        address:      in_.address,
        reply:        in_.reply,
        sequence:     in_.sequence,
        integrity:    in_.integrity.unwrap_or(Integrity::Crc).into_sys(),
        has_scb:      in_.scb.is_some(),
        scb_length:   0,
        scb_type:     0,
        scb_data:     ptr::null(),
        scb_data_len: 0,
        code:         in_.code,
        payload:      if in_.payload.is_empty() { ptr::null() } else { in_.payload.as_ptr() },
        payload_len:  in_.payload.len(),
        mac:          if in_.mac.is_empty() { ptr::null() } else { in_.mac.as_ptr() },
        mac_len:      in_.mac.len(),
        raw:          ptr::null(),
        raw_len:      0,
    };
    if let Some(scb) = &in_.scb {
        raw.scb_length   = scb.length;
        raw.scb_type     = scb.ty;
        raw.scb_data     = if scb.data.is_empty() { ptr::null() } else { scb.data.as_ptr() };
        raw.scb_data_len = scb.data.len();
    }

    let mut written: usize = 0;
    let s = unsafe {
        sys::osdp_frame_build(
            &raw as *const _,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    };
    Error::from_status(s)?;
    Ok(written)
}

// ---- CRC-16 / checksum convenience -------------------------------------

/// OSDP CRC-16 of `data`. Convenience wrapper around `osdp_crc16`.
#[inline]
pub fn crc16(data: &[u8]) -> u16 {
    unsafe { sys::osdp_crc16(data.as_ptr(), data.len()) }
}

/// OSDP 8-bit checksum of `data`. Convenience wrapper around
/// `osdp_checksum`.
#[inline]
pub fn checksum(data: &[u8]) -> u8 {
    unsafe { sys::osdp_checksum(data.as_ptr(), data.len()) }
}

// ---- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_round_trip() {
        let build_in = FrameBuild {
            address:  0x10,
            sequence: 1,
            code:     sys::OSDP_CMD_POLL,
            ..Default::default()
        };
        let mut buf = [0u8; FRAME_MAX_LEN];
        let n = build(&build_in, &mut buf).unwrap();
        assert!(n >= FRAME_MIN_LEN_CRC);

        let frame = decode(&buf[..n]).unwrap();
        assert_eq!(frame.address,   0x10);
        assert_eq!(frame.sequence,  1);
        assert_eq!(frame.code,      sys::OSDP_CMD_POLL);
        assert_eq!(frame.reply,     false);
        assert_eq!(frame.integrity, Integrity::Crc);
        assert!(frame.scb.is_none());
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn truncated_returns_truncated() {
        // 4 bytes is below the minimum frame length.
        let bytes = [0x53u8, 0x00, 0x00, 0x00];
        assert!(matches!(decode(&bytes), Err(Error::Truncated)));
    }

    #[test]
    fn crc_helper_matches_known_vector() {
        assert_eq!(crc16(b"123456789"), 0xE5CC);
    }
}
