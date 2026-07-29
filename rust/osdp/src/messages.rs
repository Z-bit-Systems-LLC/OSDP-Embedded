// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Per-message codecs — typed decoders and builders for every command
//! and reply in the OSDP v2.2.2 baseline set.
//!
//! Each message gets a struct (or unit type for payload-less ones)
//! plus matching `decode` / `build` functions:
//!
//!   - `decode(payload: &[u8]) -> Result<Self>` — turn the bytes that
//!     follow the command/reply code byte into a typed value. Slice
//!     fields borrow the input.
//!   - `build(&self, out: &mut [u8]) -> Result<usize>` — write the
//!     payload bytes into `out` and return the written length. The
//!     caller is responsible for prepending the code byte and framing
//!     the result; that's [`crate::frame::build`]'s job.
//!
//! This layer is convenience only — every function delegates to its
//! `osdp_*_decode` / `osdp_*_build` C counterpart, so the C unit
//! tests remain the authoritative correctness oracle.
//!
//! Constants for every command code, reply code, NAK error code, and
//! enum value live next to the struct that uses them, re-exported
//! from `osdp_sys` so applications don't have to import that crate
//! directly.

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ptr;

use crate::sys;

use crate::error::{Error, Result};

// ---- Re-exports: command + reply + NAK code constants ------------------

pub use sys::{
    OSDP_CMD_ABORT, OSDP_CMD_ACURXSIZE, OSDP_CMD_BUZ, OSDP_CMD_CAP, OSDP_CMD_CHLNG,
    OSDP_CMD_COMSET, OSDP_CMD_FILETRANSFER, OSDP_CMD_ID, OSDP_CMD_ISTAT, OSDP_CMD_KEEPACTIVE,
    OSDP_CMD_KEYSET, OSDP_CMD_LED, OSDP_CMD_LSTAT, OSDP_CMD_MFG, OSDP_CMD_OSTAT, OSDP_CMD_OUT,
    OSDP_CMD_POLL, OSDP_CMD_RSTAT, OSDP_CMD_SCRYPT, OSDP_CMD_TEXT,
};
// Direction bytes for osdp_FMT.
pub use sys::{OSDP_FMT_DIR_FORWARD, OSDP_FMT_DIR_REVERSE};
// Status bytes for the four *STATR reports — the values a
// [`crate::pd::StatusProviders`] hands back.
pub use sys::{
    OSDP_ISTATR_ACTIVE, OSDP_ISTATR_FAULT, OSDP_ISTATR_INACTIVE, OSDP_ISTATR_OPEN,
    OSDP_ISTATR_SHORT, OSDP_ISTATR_UNKNOWN, OSDP_LSTATR_NORMAL, OSDP_LSTATR_POWER_FAILURE,
    OSDP_LSTATR_TAMPER, OSDP_OSTATR_ACTIVE, OSDP_OSTATR_INACTIVE, OSDP_RSTATR_NORMAL,
    OSDP_RSTATR_NOT_CONNECTED, OSDP_RSTATR_TAMPER,
};
// File-transfer type + status constants.
pub use sys::{
    OSDP_FTSTAT_ABORT, OSDP_FTSTAT_ACTION_INTERLEAVE_OK, OSDP_FTSTAT_ACTION_LEAVE_SC,
    OSDP_FTSTAT_ACTION_POLL_AVAIL, OSDP_FTSTAT_FINISHING, OSDP_FTSTAT_MALFORMED, OSDP_FTSTAT_OK,
    OSDP_FTSTAT_PROCESSED, OSDP_FTSTAT_REBOOTING, OSDP_FTSTAT_UNRECOGNIZED, OSDP_FT_TYPE_BIOMATCH,
    OSDP_FT_TYPE_DISPLAY, OSDP_FT_TYPE_OPAQUE,
};
pub use sys::{
    OSDP_NAK_BAD_CHECK, OSDP_NAK_CMD_LENGTH, OSDP_NAK_ENCRYPTION_REQUIRED, OSDP_NAK_NO_ERROR,
    OSDP_NAK_RECORD_INVALID, OSDP_NAK_UNEXPECTED_SEQUENCE, OSDP_NAK_UNKNOWN_CMD,
    OSDP_NAK_UNSUPPORTED_SCB,
};
pub use sys::{
    OSDP_REPLY_ACK, OSDP_REPLY_BUSY, OSDP_REPLY_CCRYPT, OSDP_REPLY_COM, OSDP_REPLY_FMT,
    OSDP_REPLY_FTSTAT, OSDP_REPLY_ISTATR, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_MFGERRR,
    OSDP_REPLY_MFGREP, OSDP_REPLY_MFGSTATR, OSDP_REPLY_NAK, OSDP_REPLY_OSTATR, OSDP_REPLY_PDCAP,
    OSDP_REPLY_PDID, OSDP_REPLY_RAW, OSDP_REPLY_RMAC_I, OSDP_REPLY_RSTATR,
};

// ========================================================================
// COMMANDS (ACU → PD)
// ========================================================================

/// `osdp_POLL` (0x60) — empty payload.
pub struct Poll;

impl Poll {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let s = unsafe { sys::osdp_poll_decode(payload.as_ptr(), payload.len()) };
        Error::from_status(s).map(|_| Self)
    }

    pub fn build(out: &mut [u8]) -> Result<usize> {
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_poll_build(out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_ID` (0x61) — 1-byte ID-type request.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct IdRequest {
    /// 0x00 = standard PD ID block; rest reserved.
    pub id_type: u8,
}

impl IdRequest {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_id_cmd_t>::zeroed();
        let s = unsafe { sys::osdp_id_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let raw = unsafe { raw.assume_init() };
        Ok(Self {
            id_type: raw.id_type,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_id_cmd_t {
            id_type: self.id_type,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_id_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_CAP` (0x62) — 1-byte reply-type request.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CapRequest {
    /// 0x00 = standard, 0x01 = extended.
    pub reply_type: u8,
}

impl CapRequest {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_cap_cmd_t>::zeroed();
        let s = unsafe { sys::osdp_cap_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let raw = unsafe { raw.assume_init() };
        Ok(Self {
            reply_type: raw.reply_type,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_cap_cmd_t {
            reply_type: self.reply_type,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_cap_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// One 4-byte record inside an `osdp_OUT` command.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct OutRecord {
    pub output_no: u8,
    pub control_code: u8,
    pub timer_100ms: u16,
}

/// `osdp_OUT` (0x68) — output control, N×4-byte records.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Out {
    pub records: Vec<OutRecord>,
}

impl Out {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        // The C decoder requires `records_cap >= count`; pre-compute
        // count from the payload length to size the buffer exactly.
        if payload.len() % sys::OSDP_OUT_RECORD_BYTES != 0 {
            return Err(Error::BadPayload);
        }
        let count = payload.len() / sys::OSDP_OUT_RECORD_BYTES;
        let mut raw: Vec<sys::osdp_out_record_t> = (0..count)
            .map(|_| sys::osdp_out_record_t {
                output_no: 0,
                control_code: 0,
                timer_100ms: 0,
            })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_out_decode(
                payload.as_ptr(),
                payload.len(),
                raw.as_mut_ptr(),
                raw.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        raw.truncate(written);
        Ok(Self {
            records: raw
                .into_iter()
                .map(|r| OutRecord {
                    output_no: r.output_no,
                    control_code: r.control_code,
                    timer_100ms: r.timer_100ms,
                })
                .collect(),
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw: Vec<sys::osdp_out_record_t> = self
            .records
            .iter()
            .map(|r| sys::osdp_out_record_t {
                output_no: r.output_no,
                control_code: r.control_code,
                timer_100ms: r.timer_100ms,
            })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_out_build(
                raw.as_ptr(),
                raw.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// One 14-byte LED record. Fields mirror spec Tables 16/17 directly.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct LedRecord {
    pub reader_no: u8,
    pub led_no: u8,
    /// Temporary settings (spec Table 16). 0x00 NOP, 0x01 cancel, 0x02 set.
    pub temp_control_code: u8,
    pub temp_on_time: u8,
    pub temp_off_time: u8,
    pub temp_on_color: u8,
    pub temp_off_color: u8,
    pub temp_timer_100ms: u16,
    /// Permanent settings (spec Table 17). 0x00 NOP, 0x01 set.
    pub perm_control_code: u8,
    pub perm_on_time: u8,
    pub perm_off_time: u8,
    pub perm_on_color: u8,
    pub perm_off_color: u8,
}

/// `osdp_LED` (0x69) — LED control, N×14-byte records.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Led {
    pub records: Vec<LedRecord>,
}

impl Led {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() % sys::OSDP_LED_RECORD_BYTES != 0 {
            return Err(Error::BadPayload);
        }
        let count = payload.len() / sys::OSDP_LED_RECORD_BYTES;
        let mut raw: Vec<sys::osdp_led_record_t> = (0..count)
            .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_led_decode(
                payload.as_ptr(),
                payload.len(),
                raw.as_mut_ptr(),
                raw.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        raw.truncate(written);
        Ok(Self {
            records: raw
                .into_iter()
                .map(|r| LedRecord {
                    reader_no: r.reader_no,
                    led_no: r.led_no,
                    temp_control_code: r.temp_control_code,
                    temp_on_time: r.temp_on_time,
                    temp_off_time: r.temp_off_time,
                    temp_on_color: r.temp_on_color,
                    temp_off_color: r.temp_off_color,
                    temp_timer_100ms: r.temp_timer_100ms,
                    perm_control_code: r.perm_control_code,
                    perm_on_time: r.perm_on_time,
                    perm_off_time: r.perm_off_time,
                    perm_on_color: r.perm_on_color,
                    perm_off_color: r.perm_off_color,
                })
                .collect(),
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw: Vec<sys::osdp_led_record_t> = self
            .records
            .iter()
            .map(|r| sys::osdp_led_record_t {
                reader_no: r.reader_no,
                led_no: r.led_no,
                temp_control_code: r.temp_control_code,
                temp_on_time: r.temp_on_time,
                temp_off_time: r.temp_off_time,
                temp_on_color: r.temp_on_color,
                temp_off_color: r.temp_off_color,
                temp_timer_100ms: r.temp_timer_100ms,
                perm_control_code: r.perm_control_code,
                perm_on_time: r.perm_on_time,
                perm_off_time: r.perm_off_time,
                perm_on_color: r.perm_on_color,
                perm_off_color: r.perm_off_color,
            })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_led_build(
                raw.as_ptr(),
                raw.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_BUZ` (0x6A) — buzzer control, single 5-byte record.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct BuzCmd {
    pub reader_no: u8,
    /// 0x01 = off, 0x02 = default tone.
    pub tone_code: u8,
    pub on_time_100ms: u8,
    pub off_time_100ms: u8,
    /// 0x00 = continuous.
    pub count: u8,
}

impl BuzCmd {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_buz_cmd_t>::zeroed();
        let s = unsafe { sys::osdp_buz_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            reader_no: r.reader_no,
            tone_code: r.tone_code,
            on_time_100ms: r.on_time_100ms,
            off_time_100ms: r.off_time_100ms,
            count: r.count,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_buz_cmd_t {
            reader_no: self.reader_no,
            tone_code: self.tone_code,
            on_time_100ms: self.on_time_100ms,
            off_time_100ms: self.off_time_100ms,
            count: self.count,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_buz_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_TEXT` (0x6B) — text output, 6-byte header + variable-length text.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Text<'a> {
    pub reader_no: u8,
    /// Spec Table 21: 0x01 perm-no-wrap, 0x02 perm-wrap, 0x03 temp-no-wrap, 0x04 temp-wrap.
    pub text_command: u8,
    /// Duration in seconds for temporary text.
    pub temp_text_time_s: u8,
    /// 1-based row.
    pub row: u8,
    /// 1-based column.
    pub column: u8,
    pub text: &'a [u8],
}

impl<'a> Text<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_text_cmd_t>::zeroed();
        let s = unsafe { sys::osdp_text_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        let text = unsafe { slice_from_raw_or_empty(r.text, r.text_len) };
        Ok(Self {
            reader_no: r.reader_no,
            text_command: r.text_command,
            temp_text_time_s: r.temp_text_time_s,
            row: r.row,
            column: r.column,
            text,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        // text_length on the wire must equal the byte count of the
        // text slice; both fields are filled in here.
        if self.text.len() > u8::MAX as usize {
            return Err(Error::InvalidArg);
        }
        let raw = sys::osdp_text_cmd_t {
            reader_no: self.reader_no,
            text_command: self.text_command,
            temp_text_time_s: self.temp_text_time_s,
            row: self.row,
            column: self.column,
            text_length: self.text.len() as u8,
            text: if self.text.is_empty() {
                ptr::null()
            } else {
                self.text.as_ptr()
            },
            text_len: self.text.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_text_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_COMSET` (0x6E) — communications-config change.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct ComsetCmd {
    pub address: u8,
    pub baud_rate: u32,
}

impl ComsetCmd {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_comset_cmd_t>::zeroed();
        let s =
            unsafe { sys::osdp_comset_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            address: r.address,
            baud_rate: r.baud_rate,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_comset_cmd_t {
            address: self.address,
            baud_rate: self.baud_rate,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_comset_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// Key-type values for [`Keyset`]. Spec v2.2 baseline only defines
/// SCBK; other values are reserved.
pub const OSDP_KEYSET_KEY_TYPE_SCBK: u8 = 0x01;

/// `osdp_KEYSET` (0x75) — rotate the PD's Secure Channel Base Key.
///
/// Wire layout per spec Annex B: 2-byte header (`key_type`,
/// `key_length`) followed by `key_length` bytes of new key material.
/// For SCBK rotation, `key_type = 0x01` and `key_length = 16`.
///
/// The PD-side state machine in [`crate::pd::Pd`] applies a
/// well-formed SCBK KEYSET inline (writes the new key into the PD's
/// SCBK slot, keeps the existing SC session running). The next
/// handshake will use the rotated key — the current one is left
/// untouched so the ACU can either keep using the live session or
/// initiate a new handshake at its discretion.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Keyset<'a> {
    pub key_type: u8,
    pub key_length: u8,
    pub key_data: &'a [u8],
}

impl<'a> Keyset<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_keyset_cmd_t>::zeroed();
        let s =
            unsafe { sys::osdp_keyset_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            key_type: r.key_type,
            key_length: r.key_length,
            key_data: unsafe { slice_from_raw_or_empty(r.key_data, r.key_data_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_keyset_cmd_t {
            key_type: self.key_type,
            key_length: self.key_length,
            key_data: if self.key_data.is_empty() {
                ptr::null()
            } else {
                self.key_data.as_ptr()
            },
            key_data_len: self.key_data.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_keyset_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_FILETRANSFER` (0x7C) — one fragment of a file streamed ACU → PD:
/// an 11-byte header plus optional fragment bytes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct FileTransfer<'a> {
    /// FtType — 0x01 opaque, 0x02 biomatch template, 0x03 display, ...
    pub ft_type: u8,
    /// Total file size.
    pub total_size: u32,
    /// Byte offset of this fragment (monotonically increasing).
    pub offset: u32,
    /// This fragment's bytes (may be empty for an idle fragment).
    pub data: &'a [u8],
}

impl<'a> FileTransfer<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_filetransfer_cmd_t>::zeroed();
        let s = unsafe {
            sys::osdp_filetransfer_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr())
        };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            ft_type: r.ft_type,
            total_size: r.total_size,
            offset: r.offset,
            data: unsafe { slice_from_raw_or_empty(r.data, r.data_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        if self.data.len() > u16::MAX as usize {
            return Err(Error::InvalidArg);
        }
        let raw = sys::osdp_filetransfer_cmd_t {
            ft_type: self.ft_type,
            total_size: self.total_size,
            offset: self.offset,
            fragment_size: self.data.len() as u16,
            data: if self.data.is_empty() {
                ptr::null()
            } else {
                self.data.as_ptr()
            },
            data_len: self.data.len(),
        };
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_filetransfer_build(&raw, out.as_mut_ptr(), out.len(), &mut written)
        };
        Error::from_status(s)?;
        Ok(written)
    }
}

// ========================================================================
// REPLIES (PD → ACU)
// ========================================================================

/// `osdp_ACK` (0x40) — empty payload.
pub struct Ack;

impl Ack {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let s = unsafe { sys::osdp_ack_decode(payload.as_ptr(), payload.len()) };
        Error::from_status(s).map(|_| Self)
    }

    pub fn build(out: &mut [u8]) -> Result<usize> {
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_ack_build(out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_NAK` (0x41) — 1-byte error code, optional details.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Nak<'a> {
    /// One of the `OSDP_NAK_*` constants re-exported from this module.
    pub error_code: u8,
    pub details: &'a [u8],
}

impl<'a> Nak<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_nak_t>::zeroed();
        let s = unsafe { sys::osdp_nak_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            error_code: r.error_code,
            details: unsafe { slice_from_raw_or_empty(r.details, r.details_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_nak_t {
            error_code: self.error_code,
            details: if self.details.is_empty() {
                ptr::null()
            } else {
                self.details.as_ptr()
            },
            details_len: self.details.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_nak_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_PDID` (0x45) — 12-byte PD identification report.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Pdid {
    /// IEEE OUI, octets in transmission order.
    pub vendor_code: [u8; 3],
    pub model: u8,
    pub version: u8,
    /// Serial number (32-bit LE on the wire).
    pub serial: u32,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub firmware_build: u8,
}

impl Pdid {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_pdid_t>::zeroed();
        let s = unsafe { sys::osdp_pdid_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            vendor_code: r.vendor_code,
            model: r.model,
            version: r.version,
            serial: r.serial,
            firmware_major: r.firmware_major,
            firmware_minor: r.firmware_minor,
            firmware_build: r.firmware_build,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_pdid_t {
            vendor_code: self.vendor_code,
            model: self.model,
            version: self.version,
            serial: self.serial,
            firmware_major: self.firmware_major,
            firmware_minor: self.firmware_minor,
            firmware_build: self.firmware_build,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_pdid_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// One 3-byte capability record.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PdcapRecord {
    pub function_code: u8,
    pub compliance_level: u8,
    pub num_objects: u8,
}

/// `osdp_PDCAP` (0x46) — list of 3-byte capability records.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Pdcap {
    pub records: Vec<PdcapRecord>,
}

impl Pdcap {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() % sys::OSDP_PDCAP_RECORD_BYTES != 0 {
            return Err(Error::BadPayload);
        }
        let count = payload.len() / sys::OSDP_PDCAP_RECORD_BYTES;
        let mut raw: Vec<sys::osdp_pdcap_record_t> = (0..count)
            .map(|_| sys::osdp_pdcap_record_t {
                function_code: 0,
                compliance_level: 0,
                num_objects: 0,
            })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_pdcap_decode(
                payload.as_ptr(),
                payload.len(),
                raw.as_mut_ptr(),
                raw.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        raw.truncate(written);
        Ok(Self {
            records: raw
                .into_iter()
                .map(|r| PdcapRecord {
                    function_code: r.function_code,
                    compliance_level: r.compliance_level,
                    num_objects: r.num_objects,
                })
                .collect(),
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw: Vec<sys::osdp_pdcap_record_t> = self
            .records
            .iter()
            .map(|r| sys::osdp_pdcap_record_t {
                function_code: r.function_code,
                compliance_level: r.compliance_level,
                num_objects: r.num_objects,
            })
            .collect();
        let mut written: usize = 0;
        let s = unsafe {
            sys::osdp_pdcap_build(
                raw.as_ptr(),
                raw.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_RAW` (0x50) — card data, 4-byte header + bit-packed bytes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Raw<'a> {
    pub reader_no: u8,
    /// Spec Table 33: 0 raw, 1 wiegand, 2 UID, 3 OSS-SID.
    pub format_code: u8,
    pub bit_count: u16,
    /// Card data, `(bit_count + 7) / 8` bytes.
    pub bit_data: &'a [u8],
}

impl<'a> Raw<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_raw_t>::zeroed();
        let s = unsafe { sys::osdp_raw_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            reader_no: r.reader_no,
            format_code: r.format_code,
            bit_count: r.bit_count,
            bit_data: unsafe { slice_from_raw_or_empty(r.bit_data, r.bit_data_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_raw_t {
            reader_no: self.reader_no,
            format_code: self.format_code,
            bit_count: self.bit_count,
            bit_data: if self.bit_data.is_empty() {
                ptr::null()
            } else {
                self.bit_data.as_ptr()
            },
            bit_data_len: self.bit_data.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_raw_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_KEYPAD` (0x53) — 2-byte header + ASCII digit bytes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Keypad<'a> {
    pub reader_no: u8,
    pub digits: &'a [u8],
}

impl<'a> Keypad<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_keypad_t>::zeroed();
        let s =
            unsafe { sys::osdp_keypad_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            reader_no: r.reader_no,
            digits: unsafe { slice_from_raw_or_empty(r.digits, r.digits_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        if self.digits.len() > u8::MAX as usize {
            return Err(Error::InvalidArg);
        }
        let raw = sys::osdp_keypad_t {
            reader_no: self.reader_no,
            digit_count: self.digits.len() as u8,
            digits: if self.digits.is_empty() {
                ptr::null()
            } else {
                self.digits.as_ptr()
            },
            digits_len: self.digits.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_keypad_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_COM` (0x54) — comm-config report. Fixed 5-byte payload.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Com {
    pub address: u8,
    pub baud_rate: u32,
}

impl Com {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_com_t>::zeroed();
        let s = unsafe { sys::osdp_com_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            address: r.address,
            baud_rate: r.baud_rate,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_com_t {
            address: self.address,
            baud_rate: self.baud_rate,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_com_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_FTSTAT` (0x7A) — file-transfer status. Fixed 7-byte payload.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Ftstat {
    /// FtAction control flags (see `OSDP_FTSTAT_ACTION_*`).
    pub action: u8,
    /// FtDelay — ms the ACU should wait before the next FILETRANSFER.
    pub delay_ms: u16,
    /// FtStatusDetail — signed status (see `OSDP_FTSTAT_*`): negative =
    /// failure, 0 = proceed, 1 = processed, 2 = rebooting, 3 = finishing.
    pub status_detail: i16,
    /// FtUpdateMsgMax — alternate max fragment size (0 = no change).
    pub update_msg_max: u16,
}

impl Ftstat {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_ftstat_t>::zeroed();
        let s =
            unsafe { sys::osdp_ftstat_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            action: r.action,
            delay_ms: r.delay_ms,
            status_detail: r.status_detail,
            update_msg_max: r.update_msg_max,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_ftstat_t {
            action: self.action,
            delay_ms: self.delay_ms,
            status_detail: self.status_detail,
            update_msg_max: self.update_msg_max,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_ftstat_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

// ========================================================================
// Status-report requests (empty payload)
// ========================================================================

/// Generate the `decode`/`build` pair for a command or reply whose payload is
/// empty — the codec only validates that nothing extra arrived, and builds
/// zero bytes. Six messages share that shape exactly.
macro_rules! empty_payload_message {
    ($(#[$meta:meta])* $name:ident, $decode:ident, $build:ident) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Eq, PartialEq, Debug)]
        pub struct $name;

        impl $name {
            pub fn decode(payload: &[u8]) -> Result<Self> {
                let s = unsafe { sys::$decode(payload.as_ptr(), payload.len()) };
                Error::from_status(s).map(|_| Self)
            }

            pub fn build(out: &mut [u8]) -> Result<usize> {
                let mut written: usize = 0;
                let s = unsafe { sys::$build(out.as_mut_ptr(), out.len(), &mut written) };
                Error::from_status(s)?;
                Ok(written)
            }
        }
    };
}

empty_payload_message!(
    /// `osdp_LSTAT` (0x64) — request local status; answered by `osdp_LSTATR`.
    Lstat,
    osdp_lstat_decode,
    osdp_lstat_build
);
empty_payload_message!(
    /// `osdp_ISTAT` (0x65) — request input status; answered by `osdp_ISTATR`.
    Istat,
    osdp_istat_decode,
    osdp_istat_build
);
empty_payload_message!(
    /// `osdp_OSTAT` (0x66) — request output status; answered by `osdp_OSTATR`.
    Ostat,
    osdp_ostat_decode,
    osdp_ostat_build
);
empty_payload_message!(
    /// `osdp_RSTAT` (0x67) — request reader status; answered by `osdp_RSTATR`.
    Rstat,
    osdp_rstat_decode,
    osdp_rstat_build
);
empty_payload_message!(
    /// `osdp_ABORT` (0xA2) — terminate any multi-part message or file
    /// transfer in progress (spec 6.22).
    Abort,
    osdp_abort_decode,
    osdp_abort_build
);
empty_payload_message!(
    /// `osdp_BUSY` (0x79) — "not ready, repeat the command" (spec 7.19).
    ///
    /// The one reply that leaves its channel: it always goes out at sequence
    /// number 0, stays plaintext even during an established Secure Channel,
    /// and is never cached as the retransmit answer.
    Busy,
    osdp_busy_decode,
    osdp_busy_build
);

// ========================================================================
// Remaining v2.2 commands
// ========================================================================

/// `osdp_ACURXSIZE` (0x7B) — the ACU declares its receive capacity
/// (spec 6.20).
///
/// This bounds what the PD may *send*; it is the mirror of the PD
/// advertising PDCAP function code 10.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AcuRxSize {
    /// ACURX_BUFSIZE, 16-bit little-endian on the wire.
    pub max_size: u16,
}

impl AcuRxSize {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_acurxsize_cmd_t>::zeroed();
        let s = unsafe {
            sys::osdp_acurxsize_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr())
        };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            max_size: r.max_size,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_acurxsize_cmd_t {
            max_size: self.max_size,
        };
        let mut written: usize = 0;
        let s =
            unsafe { sys::osdp_acurxsize_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_KEEPACTIVE` (0xA7) — hold reader operations open for `time_ms`
/// milliseconds so a credential still in the field is not dropped
/// (spec 6.21). A time of 0 cancels a previous extension and is legal.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct KeepActive {
    /// Milliseconds, 16-bit little-endian on the wire.
    pub time_ms: u16,
}

impl KeepActive {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_keepactive_cmd_t>::zeroed();
        let s = unsafe {
            sys::osdp_keepactive_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr())
        };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self { time_ms: r.time_ms })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_keepactive_cmd_t {
            time_ms: self.time_ms,
        };
        let mut written: usize = 0;
        let s =
            unsafe { sys::osdp_keepactive_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_MFG` (0x80) — manufacturer-specific command: a 3-byte IEEE MA-L
/// vendor code followed by vendor-defined data.
///
/// This codec covers the *unfragmented* form. A vendor protocol that uses
/// spec 5.10 multi-part transport puts the header after the vendor code —
/// see [`crate::pd::MfgReceiver`], which reassembles that case.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Mfg<'a> {
    pub vendor_code: [u8; 3],
    pub data: &'a [u8],
}

impl<'a> Mfg<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_mfg_cmd_t>::zeroed();
        let s = unsafe { sys::osdp_mfg_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            vendor_code: r.vendor_code,
            data: unsafe { slice_from_raw_or_empty(r.data, r.data_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_mfg_cmd_t {
            vendor_code: self.vendor_code,
            data: if self.data.is_empty() {
                ptr::null()
            } else {
                self.data.as_ptr()
            },
            data_len: self.data.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_mfg_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

// ========================================================================
// Status reports
// ========================================================================

/// `osdp_LSTATR` (0x48) — local status: tamper and power (spec Table 50).
/// `0x00` is the healthy state for both bytes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Lstatr {
    pub tamper: u8,
    pub power: u8,
}

impl Lstatr {
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_lstatr_t>::zeroed();
        let s =
            unsafe { sys::osdp_lstatr_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            tamper: r.tamper,
            power: r.power,
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_lstatr_t {
            tamper: self.tamper,
            power: self.power,
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_lstatr_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// Generate the wrapper for a status report that is just one status byte per
/// object — `osdp_ISTATR`, `OSTATR` and `RSTATR` differ only in what the byte
/// values mean.
macro_rules! status_array_message {
    ($(#[$meta:meta])* $name:ident, $decode:ident, $build:ident) => {
        $(#[$meta])*
        #[derive(Clone, Eq, PartialEq, Debug, Default)]
        pub struct $name {
            pub statuses: Vec<u8>,
        }

        impl $name {
            /// Decode into an owned `Vec`. A report with no objects is legal
            /// and decodes to an empty vector.
            pub fn decode(payload: &[u8]) -> Result<Self> {
                // One status byte per object, so the payload length is an
                // exact upper bound on the count.
                let mut statuses = alloc::vec![0u8; payload.len()];
                let mut written: usize = 0;
                let s = unsafe {
                    sys::$decode(
                        payload.as_ptr(),
                        payload.len(),
                        statuses.as_mut_ptr(),
                        statuses.len(),
                        &mut written,
                    )
                };
                Error::from_status(s)?;
                statuses.truncate(written);
                Ok(Self { statuses })
            }

            pub fn build(&self, out: &mut [u8]) -> Result<usize> {
                let mut written: usize = 0;
                let s = unsafe {
                    sys::$build(
                        if self.statuses.is_empty() {
                            ptr::null()
                        } else {
                            self.statuses.as_ptr()
                        },
                        self.statuses.len(),
                        out.as_mut_ptr(),
                        out.len(),
                        &mut written,
                    )
                };
                Error::from_status(s)?;
                Ok(written)
            }
        }
    };
}

status_array_message!(
    /// `osdp_ISTATR` (0x49) — one `OSDP_ISTATR_*` byte per input.
    Istatr,
    osdp_istatr_decode,
    osdp_istatr_build
);
status_array_message!(
    /// `osdp_OSTATR` (0x4A) — one `OSDP_OSTATR_*` byte per output.
    Ostatr,
    osdp_ostatr_decode,
    osdp_ostatr_build
);
status_array_message!(
    /// `osdp_RSTATR` (0x4B) — one `OSDP_RSTATR_*` byte per reader.
    Rstatr,
    osdp_rstatr_decode,
    osdp_rstatr_build
);

// ========================================================================
// Remaining v2.2 replies
// ========================================================================

/// `osdp_FMT` (0x51) — card data in character-array format (spec 7.11).
///
/// **Deprecated by the spec**; wrapped so a Monitor can decode existing
/// traffic. New PD code should report card data as [`Raw`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Fmt<'a> {
    pub reader_no: u8,
    /// [`OSDP_FMT_DIR_FORWARD`] / [`OSDP_FMT_DIR_REVERSE`].
    pub direction: u8,
    /// ASCII characters; must match `char_count` on the wire.
    pub chars: &'a [u8],
}

impl<'a> Fmt<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_fmt_t>::zeroed();
        let s = unsafe { sys::osdp_fmt_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            reader_no: r.reader_no,
            direction: r.direction,
            chars: unsafe { slice_from_raw_or_empty(r.chars, r.chars_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_fmt_t {
            reader_no: self.reader_no,
            direction: self.direction,
            // The C codec validates that char_count matches chars_len, so
            // deriving it here keeps the two from ever disagreeing.
            char_count: self.chars.len() as u8,
            chars: if self.chars.is_empty() {
                ptr::null()
            } else {
                self.chars.as_ptr()
            },
            chars_len: self.chars.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_fmt_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// `osdp_MFGREP` (0x90) — manufacturer-specific reply (spec 7.18). Same shape
/// as [`Mfg`]: a 3-byte vendor code then vendor-defined data. Sent either in
/// answer to an `osdp_MFG` or unprompted as a poll response.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Mfgrep<'a> {
    pub vendor_code: [u8; 3],
    pub data: &'a [u8],
}

impl<'a> Mfgrep<'a> {
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut raw = MaybeUninit::<sys::osdp_mfgrep_t>::zeroed();
        let s =
            unsafe { sys::osdp_mfgrep_decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr()) };
        Error::from_status(s)?;
        let r = unsafe { raw.assume_init() };
        Ok(Self {
            vendor_code: r.vendor_code,
            data: unsafe { slice_from_raw_or_empty(r.data, r.data_len) },
        })
    }

    pub fn build(&self, out: &mut [u8]) -> Result<usize> {
        let raw = sys::osdp_mfgrep_t {
            vendor_code: self.vendor_code,
            data: if self.data.is_empty() {
                ptr::null()
            } else {
                self.data.as_ptr()
            },
            data_len: self.data.len(),
        };
        let mut written: usize = 0;
        let s = unsafe { sys::osdp_mfgrep_build(&raw, out.as_mut_ptr(), out.len(), &mut written) };
        Error::from_status(s)?;
        Ok(written)
    }
}

/// Generate the wrapper for a one-vendor-byte reply — `osdp_MFGSTATR` and
/// `osdp_MFGERRR` are identical in shape.
macro_rules! single_byte_message {
    ($(#[$meta:meta])* $name:ident, $ctype:ident, $decode:ident, $build:ident) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Eq, PartialEq, Debug)]
        pub struct $name {
            /// Vendor defined.
            pub data: u8,
        }

        impl $name {
            pub fn decode(payload: &[u8]) -> Result<Self> {
                let mut raw = MaybeUninit::<sys::$ctype>::zeroed();
                let s = unsafe {
                    sys::$decode(payload.as_ptr(), payload.len(), raw.as_mut_ptr())
                };
                Error::from_status(s)?;
                Ok(Self { data: unsafe { raw.assume_init() }.data })
            }

            pub fn build(&self, out: &mut [u8]) -> Result<usize> {
                let raw = sys::$ctype { data: self.data };
                let mut written: usize = 0;
                let s = unsafe {
                    sys::$build(&raw, out.as_mut_ptr(), out.len(), &mut written)
                };
                Error::from_status(s)?;
                Ok(written)
            }
        }
    };
}

single_byte_message!(
    /// `osdp_MFGSTATR` (0x83) — one vendor-defined status byte (spec 7.23).
    ///
    /// **Deprecated**: the spec calls it "incomplete or incorrect" and will
    /// redefine it in v2.3.0. Wrapped so the code is not a silent hole and a
    /// Monitor can decode it; new PD code should not emit it.
    Mfgstatr,
    osdp_mfgstatr_t,
    osdp_mfgstatr_decode,
    osdp_mfgstatr_build
);
single_byte_message!(
    /// `osdp_MFGERRR` (0x84) — one vendor-defined error byte (spec 7.24).
    /// Deprecated on the same terms as [`Mfgstatr`].
    Mfgerrr,
    osdp_mfgerrr_t,
    osdp_mfgerrr_decode,
    osdp_mfgerrr_build
);

// ========================================================================
// Internals
// ========================================================================

/// Build a slice from `(ptr, len)`. Treats `(NULL, 0)` and `(_, 0)` as
/// the empty slice (the C side may pass either when there's no data).
unsafe fn slice_from_raw_or_empty<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        core::slice::from_raw_parts(ptr, len)
    }
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn round_trip<F: FnOnce(&mut [u8]) -> Result<usize>>(build: F) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let n = build(&mut buf).expect("build");
        buf[..n].to_vec()
    }

    #[test]
    fn poll_round_trip() {
        let bytes = round_trip(Poll::build);
        assert!(bytes.is_empty(), "POLL has empty payload");
        Poll::decode(&bytes).expect("POLL decode");
    }

    #[test]
    fn id_request_round_trip() {
        let cmd = IdRequest { id_type: 0x00 };
        let bytes = round_trip(|b| cmd.build(b));
        let decoded = IdRequest::decode(&bytes).unwrap();
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn pdid_round_trip() {
        let pdid = Pdid {
            vendor_code: [0xCA, 0xFE, 0x00],
            model: 0x10,
            version: 0x01,
            serial: 0xDEAD_BEEF,
            firmware_major: 0x01,
            firmware_minor: 0x02,
            firmware_build: 0x03,
        };
        let bytes = round_trip(|b| pdid.build(b));
        assert_eq!(bytes.len(), sys::OSDP_PDID_PAYLOAD_BYTES);
        let decoded = Pdid::decode(&bytes).unwrap();
        assert_eq!(pdid, decoded);
    }

    #[test]
    fn pdcap_round_trip_and_empty() {
        let cap = Pdcap {
            records: vec![
                PdcapRecord {
                    function_code: 1,
                    compliance_level: 1,
                    num_objects: 1,
                },
                PdcapRecord {
                    function_code: 2,
                    compliance_level: 2,
                    num_objects: 1,
                },
                PdcapRecord {
                    function_code: 9,
                    compliance_level: 1,
                    num_objects: 4,
                },
            ],
        };
        let bytes = round_trip(|b| cap.build(b));
        assert_eq!(bytes.len(), 3 * sys::OSDP_PDCAP_RECORD_BYTES);
        let decoded = Pdcap::decode(&bytes).unwrap();
        assert_eq!(cap, decoded);

        // Empty payload also round-trips.
        let empty = Pdcap::default();
        let bytes = round_trip(|b| empty.build(b));
        assert!(bytes.is_empty());
        let decoded = Pdcap::decode(&bytes).unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn nak_round_trip() {
        // Borrowed-payload type — careful with lifetimes. Decode
        // borrows from a buffer; the buffer must outlive the use.
        let nak = Nak {
            error_code: OSDP_NAK_UNKNOWN_CMD,
            details: &[],
        };
        let bytes = round_trip(|b| nak.build(b));
        let decoded = Nak::decode(&bytes).unwrap();
        assert_eq!(decoded.error_code, OSDP_NAK_UNKNOWN_CMD);
        assert!(decoded.details.is_empty());
    }

    #[test]
    fn led_round_trip_minimal() {
        let led = Led {
            records: vec![LedRecord {
                reader_no: 0,
                led_no: 0,
                temp_control_code: 0x02, // set
                temp_on_time: 5,
                temp_off_time: 5,
                temp_on_color: 0x02,  // green
                temp_off_color: 0x00, // black
                temp_timer_100ms: 10,
                perm_control_code: 0x01, // set
                perm_on_time: 0,
                perm_off_time: 0,
                perm_on_color: 0x01, // red
                perm_off_color: 0x00,
            }],
        };
        let bytes = round_trip(|b| led.build(b));
        assert_eq!(bytes.len(), sys::OSDP_LED_RECORD_BYTES);
        let decoded = Led::decode(&bytes).unwrap();
        assert_eq!(led, decoded);
    }

    #[test]
    fn text_round_trip_with_borrowed_text() {
        let text = b"HELLO";
        let cmd = Text {
            reader_no: 0,
            text_command: OSDP_TEXT_PERM_NO_WRAP_CONST,
            temp_text_time_s: 0,
            row: 1,
            column: 1,
            text,
        };
        let bytes = round_trip(|b| cmd.build(b));
        let decoded = Text::decode(&bytes).unwrap();
        assert_eq!(decoded.row, 1);
        assert_eq!(decoded.column, 1);
        assert_eq!(decoded.text, text);
    }

    // The text_command enum constant lives in osdp_sys; re-exported here
    // for the test only since the test consumes constants by value.
    const OSDP_TEXT_PERM_NO_WRAP_CONST: u8 = sys::OSDP_TEXT_PERM_NO_WRAP;

    #[test]
    fn truncated_decode_rejects() {
        // PDID is exactly 12 bytes; 11 must fail.
        let too_short = [0u8; 11];
        assert!(Pdid::decode(&too_short).is_err());
    }

    #[test]
    fn file_transfer_round_trip_with_fragment() {
        let frag = [0xDE, 0xAD, 0xBE, 0xEF];
        let cmd = FileTransfer {
            ft_type: OSDP_FT_TYPE_OPAQUE,
            total_size: 0x1234,
            offset: 0x100,
            data: &frag,
        };
        let bytes = round_trip(|b| cmd.build(b));
        let decoded = FileTransfer::decode(&bytes).unwrap();
        assert_eq!(decoded.ft_type, OSDP_FT_TYPE_OPAQUE);
        assert_eq!(decoded.total_size, 0x1234);
        assert_eq!(decoded.offset, 0x100);
        assert_eq!(decoded.data, &frag);
    }

    #[test]
    fn ftstat_round_trip_negative_status() {
        let st = Ftstat {
            action: OSDP_FTSTAT_ACTION_INTERLEAVE_OK,
            delay_ms: 250,
            status_detail: OSDP_FTSTAT_MALFORMED,
            update_msg_max: 128,
        };
        let bytes = round_trip(|b| st.build(b));
        let decoded = Ftstat::decode(&bytes).unwrap();
        assert_eq!(decoded.status_detail, -3);
        assert_eq!(decoded.delay_ms, 250);
        assert_eq!(decoded.update_msg_max, 128);
        assert_eq!(decoded.action, OSDP_FTSTAT_ACTION_INTERLEAVE_OK);
    }

    // ---- The v2.2 codecs added by the PD-completion work --------------

    #[test]
    fn empty_payload_messages_round_trip_and_reject_trailing_bytes() {
        // All six build nothing and accept nothing — assert that as a group
        // so a codec that silently grew a payload is caught.
        assert_eq!(round_trip(Lstat::build).len(), 0);
        assert_eq!(round_trip(Istat::build).len(), 0);
        assert_eq!(round_trip(Ostat::build).len(), 0);
        assert_eq!(round_trip(Rstat::build).len(), 0);
        assert_eq!(round_trip(Abort::build).len(), 0);
        assert_eq!(round_trip(Busy::build).len(), 0);

        assert!(Lstat::decode(&[]).is_ok());
        assert!(Abort::decode(&[]).is_ok());
        assert!(Busy::decode(&[]).is_ok());

        // A stray byte is a malformed frame, not something to ignore.
        assert!(Lstat::decode(&[0x00]).is_err());
        assert!(Istat::decode(&[0x00]).is_err());
        assert!(Ostat::decode(&[0x00]).is_err());
        assert!(Rstat::decode(&[0x00]).is_err());
        assert!(Abort::decode(&[0x00]).is_err());
        assert!(Busy::decode(&[0x00]).is_err());
    }

    #[test]
    fn acurxsize_round_trip_is_little_endian() {
        let bytes = round_trip(|b| AcuRxSize { max_size: 0x0640 }.build(b));
        assert_eq!(bytes, [0x40, 0x06], "ACURX_BUFSIZE is 16-bit LE");
        assert_eq!(AcuRxSize::decode(&bytes).unwrap().max_size, 0x0640);
        assert!(AcuRxSize::decode(&[0x40]).is_err(), "truncated");
    }

    #[test]
    fn keepactive_round_trip_including_the_zero_cancel() {
        let bytes = round_trip(|b| KeepActive { time_ms: 5000 }.build(b));
        assert_eq!(KeepActive::decode(&bytes).unwrap().time_ms, 5000);

        // 0 is a legal value — it cancels a previous extension.
        let zero = round_trip(|b| KeepActive { time_ms: 0 }.build(b));
        assert_eq!(KeepActive::decode(&zero).unwrap().time_ms, 0);

        assert!(KeepActive::decode(&[]).is_err());
    }

    #[test]
    fn mfg_round_trip_keeps_vendor_code_and_data_separate() {
        let m = Mfg {
            vendor_code: [0x5A, 0x42, 0x43],
            data: &[0x11, 0x22, 0x33],
        };
        let bytes = round_trip(|b| m.build(b));
        assert_eq!(bytes, [0x5A, 0x42, 0x43, 0x11, 0x22, 0x33]);

        let decoded = Mfg::decode(&bytes).unwrap();
        assert_eq!(decoded.vendor_code, [0x5A, 0x42, 0x43]);
        assert_eq!(decoded.data, &[0x11, 0x22, 0x33]);

        // Vendor code alone (no data) is legal; two bytes is not.
        assert!(Mfg::decode(&[0x5A, 0x42, 0x43]).is_ok());
        assert!(Mfg::decode(&[0x5A, 0x42]).is_err());
    }

    #[test]
    fn lstatr_round_trip() {
        let bytes = round_trip(|b| {
            Lstatr {
                tamper: OSDP_LSTATR_TAMPER,
                power: OSDP_LSTATR_NORMAL,
            }
            .build(b)
        });
        assert_eq!(bytes, [OSDP_LSTATR_TAMPER, OSDP_LSTATR_NORMAL]);
        let decoded = Lstatr::decode(&bytes).unwrap();
        assert_eq!(decoded.tamper, OSDP_LSTATR_TAMPER);
        assert_eq!(decoded.power, OSDP_LSTATR_NORMAL);
        assert!(Lstatr::decode(&[0x00]).is_err(), "needs both bytes");
    }

    #[test]
    fn status_array_reports_round_trip_including_the_empty_case() {
        let statuses = vec![OSDP_ISTATR_ACTIVE, OSDP_ISTATR_INACTIVE, OSDP_ISTATR_FAULT];
        let bytes = round_trip(|b| {
            Istatr {
                statuses: statuses.clone(),
            }
            .build(b)
        });
        assert_eq!(Istatr::decode(&bytes).unwrap().statuses, statuses);

        let o = vec![OSDP_OSTATR_ACTIVE, OSDP_OSTATR_INACTIVE];
        let bytes = round_trip(|b| {
            Ostatr {
                statuses: o.clone(),
            }
            .build(b)
        });
        assert_eq!(Ostatr::decode(&bytes).unwrap().statuses, o);

        let r = vec![OSDP_RSTATR_NORMAL, OSDP_RSTATR_TAMPER];
        let bytes = round_trip(|b| {
            Rstatr {
                statuses: r.clone(),
            }
            .build(b)
        });
        assert_eq!(Rstatr::decode(&bytes).unwrap().statuses, r);

        // A PD with no inputs genuinely has nothing to report, and an empty
        // report must survive the round trip rather than being an error.
        let bytes = round_trip(|b| Istatr::default().build(b));
        assert!(bytes.is_empty());
        assert!(Istatr::decode(&bytes).unwrap().statuses.is_empty());
    }

    #[test]
    fn fmt_round_trip_derives_char_count_from_the_slice() {
        let f = Fmt {
            reader_no: 0,
            direction: OSDP_FMT_DIR_FORWARD,
            chars: b"12345",
        };
        let bytes = round_trip(|b| f.build(b));
        assert_eq!(bytes[2], 5, "char_count must match the slice length");

        let decoded = Fmt::decode(&bytes).unwrap();
        assert_eq!(decoded.chars, b"12345");
        assert_eq!(decoded.direction, OSDP_FMT_DIR_FORWARD);

        assert!(Fmt::decode(&bytes[..2]).is_err(), "truncated header");
    }

    #[test]
    fn mfgrep_round_trip() {
        let m = Mfgrep {
            vendor_code: [0x5A, 0x42, 0x43],
            data: &[0xAB, 0xCD],
        };
        let bytes = round_trip(|b| m.build(b));
        let decoded = Mfgrep::decode(&bytes).unwrap();
        assert_eq!(decoded.vendor_code, [0x5A, 0x42, 0x43]);
        assert_eq!(decoded.data, &[0xAB, 0xCD]);
        assert!(Mfgrep::decode(&[0x5A, 0x42]).is_err());
    }

    #[test]
    fn single_byte_replies_round_trip() {
        let bytes = round_trip(|b| Mfgstatr { data: 0x7F }.build(b));
        assert_eq!(bytes, [0x7F]);
        assert_eq!(Mfgstatr::decode(&bytes).unwrap().data, 0x7F);

        let bytes = round_trip(|b| Mfgerrr { data: 0x02 }.build(b));
        assert_eq!(Mfgerrr::decode(&bytes).unwrap().data, 0x02);

        assert!(Mfgstatr::decode(&[]).is_err());
        assert!(Mfgerrr::decode(&[0x01, 0x02]).is_err());
    }
}
