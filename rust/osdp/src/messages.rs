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
    OSDP_CMD_BUZ, OSDP_CMD_CAP, OSDP_CMD_CHLNG, OSDP_CMD_COMSET, OSDP_CMD_ID, OSDP_CMD_ISTAT,
    OSDP_CMD_KEYSET, OSDP_CMD_LED, OSDP_CMD_LSTAT, OSDP_CMD_OSTAT, OSDP_CMD_OUT, OSDP_CMD_POLL,
    OSDP_CMD_RSTAT, OSDP_CMD_SCRYPT, OSDP_CMD_TEXT,
};
pub use sys::{
    OSDP_NAK_BAD_CHECK, OSDP_NAK_CMD_LENGTH, OSDP_NAK_ENCRYPTION_REQUIRED, OSDP_NAK_NO_ERROR,
    OSDP_NAK_UNEXPECTED_SEQUENCE, OSDP_NAK_UNKNOWN_CMD, OSDP_NAK_UNSUPPORTED_SCB,
};
pub use sys::{
    OSDP_REPLY_ACK, OSDP_REPLY_BUSY, OSDP_REPLY_CCRYPT, OSDP_REPLY_COM, OSDP_REPLY_FMT,
    OSDP_REPLY_ISTATR, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_NAK, OSDP_REPLY_OSTATR,
    OSDP_REPLY_PDCAP, OSDP_REPLY_PDID, OSDP_REPLY_RAW, OSDP_REPLY_RMAC_I, OSDP_REPLY_RSTATR,
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
}
