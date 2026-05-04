// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Error type — a typed Rust enum mirroring `osdp_status_t`.

use core::fmt;

use osdp_sys::osdp_status_t;

/// Every error the C library can report. The `Other` variant is a
/// catch-all for forward compatibility — a future C release that adds
/// a status code we don't enumerate here will deliver it through that
/// arm without an ABI break.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Caller violated the API contract (NULL pointer, zero-length
    /// output, sequence number out of range, ...).
    InvalidArg,
    /// Output buffer cannot hold the result.
    BufferTooSmall,
    /// Not enough bytes to decode the frame yet.
    Truncated,
    /// First byte was not OSDP_SOM (0x53).
    BadSom,
    /// Length field is impossible or inconsistent.
    BadLength,
    /// Control byte has reserved bits set.
    BadCtrl,
    /// CRC-16 mismatch.
    BadCrc,
    /// 8-bit checksum mismatch.
    BadChecksum,
    /// Payload length wrong for the command/reply code.
    BadPayload,
    /// Feature recognised but not implemented (ACU-side `send_command`
    /// while the slot is busy, decrypt without a decrypt callback,
    /// etc.).
    NotSupported,
    /// Forward-compatible catch-all. The wrapped value is the raw
    /// `osdp_status_t.0` int the C side returned.
    Other(i32),
}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Convert a raw status code into either `Ok(())` or `Err(...)`.
    pub(crate) fn from_status(s: osdp_status_t) -> Result<()> {
        match s {
            osdp_status_t::OSDP_OK                   => Ok(()),
            osdp_status_t::OSDP_ERR_INVALID_ARG      => Err(Error::InvalidArg),
            osdp_status_t::OSDP_ERR_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
            osdp_status_t::OSDP_ERR_TRUNCATED        => Err(Error::Truncated),
            osdp_status_t::OSDP_ERR_BAD_SOM          => Err(Error::BadSom),
            osdp_status_t::OSDP_ERR_BAD_LENGTH       => Err(Error::BadLength),
            osdp_status_t::OSDP_ERR_BAD_CTRL         => Err(Error::BadCtrl),
            osdp_status_t::OSDP_ERR_BAD_CRC          => Err(Error::BadCrc),
            osdp_status_t::OSDP_ERR_BAD_CHECKSUM     => Err(Error::BadChecksum),
            osdp_status_t::OSDP_ERR_BAD_PAYLOAD      => Err(Error::BadPayload),
            osdp_status_t::OSDP_ERR_NOT_SUPPORTED    => Err(Error::NotSupported),
            osdp_status_t(other)                     => Err(Error::Other(other)),
        }
    }

    /// Inverse: the canonical `osdp_status_t` we'd return back to C.
    /// Used by the trait-object thunks when an application handler
    /// returns `Err(...)`.
    pub(crate) fn to_status(self) -> osdp_status_t {
        match self {
            Error::InvalidArg     => osdp_status_t::OSDP_ERR_INVALID_ARG,
            Error::BufferTooSmall => osdp_status_t::OSDP_ERR_BUFFER_TOO_SMALL,
            Error::Truncated      => osdp_status_t::OSDP_ERR_TRUNCATED,
            Error::BadSom         => osdp_status_t::OSDP_ERR_BAD_SOM,
            Error::BadLength      => osdp_status_t::OSDP_ERR_BAD_LENGTH,
            Error::BadCtrl        => osdp_status_t::OSDP_ERR_BAD_CTRL,
            Error::BadCrc         => osdp_status_t::OSDP_ERR_BAD_CRC,
            Error::BadChecksum    => osdp_status_t::OSDP_ERR_BAD_CHECKSUM,
            Error::BadPayload     => osdp_status_t::OSDP_ERR_BAD_PAYLOAD,
            Error::NotSupported   => osdp_status_t::OSDP_ERR_NOT_SUPPORTED,
            Error::Other(n)       => osdp_status_t(n),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArg     => f.write_str("invalid argument"),
            Error::BufferTooSmall => f.write_str("output buffer too small"),
            Error::Truncated      => f.write_str("not enough bytes to decode"),
            Error::BadSom         => f.write_str("bad SOM marker"),
            Error::BadLength      => f.write_str("bad LEN field"),
            Error::BadCtrl        => f.write_str("bad CTRL byte"),
            Error::BadCrc         => f.write_str("bad CRC"),
            Error::BadChecksum    => f.write_str("bad checksum"),
            Error::BadPayload     => f.write_str("bad payload"),
            Error::NotSupported   => f.write_str("not supported"),
            Error::Other(n)       => write!(f, "osdp_status_t({})", n),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
