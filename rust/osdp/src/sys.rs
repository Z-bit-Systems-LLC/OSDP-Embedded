// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Raw FFI bindings to the OSDP-Embedded C library (private module).
//!
//! Every name here mirrors a name in one of the C public headers under
//! `core/include/osdp/`, `pd/include/osdp/`, or `acu/include/osdp/`. No
//! ergonomics, no policy: pointer-and-length APIs, `*mut c_void` user
//! pointers, raw `extern "C" fn` callbacks, structs as the C side
//! defines them.
//!
//! Consumers don't access this module directly - they go through the
//! safe wrappers in `osdp_embedded::pd`, `::acu`, `::frame`, etc. This
//! module exists as the in-crate FFI seam.
//!
//! ## Feature gating
//!
//! - The shared FFI (framing, codecs, dispatch, SC primitives, crc16,
//!   checksum) is always compiled.
//! - PD bindings (`osdp_pd_t` and friends) live in [`pd_ffi`] and are
//!   re-exported under the `pd` feature; the matching .c files in
//!   `pd/src/` only compile when the feature is on.
//! - ACU bindings live in [`acu_ffi`] under the `acu` feature.
//!
//! ## ABI assumptions
//!
//! - The C library is compiled with the same toolchain `cargo` selects
//!   for the active target (the build script uses the `cc` crate).
//! - C `_Bool` and Rust `bool` agree on a 1-byte representation. This is
//!   true for all targets we care about (gcc/clang/MSVC on x86_64,
//!   ARMv7-M, ARMv7-A, ARMv8-M).
//! - `size_t` matches `usize` and `int` matches `core::ffi::c_int`.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// FFI bindings exist for the entire C public surface; not every item
// is referenced by the safe wrappers above. Silencing dead-code is
// preferable to dropping bindings that consumers might reach via
// `crate::sys::*` in custom unsafe code or that we'll wrap in a
// future module.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_void};

// ====================================================================
// osdp_types.h
// ====================================================================

/// Mirror of the C `osdp_status_t` enum. Values defined as associated
/// constants on a transparent `i32` newtype — using `#[repr(C)] enum`
/// directly would invoke UB if the C side ever returned a value Rust
/// hadn't enumerated.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct osdp_status_t(pub c_int);

impl osdp_status_t {
    pub const OSDP_OK: Self = Self(0);
    pub const OSDP_ERR_INVALID_ARG: Self = Self(1);
    pub const OSDP_ERR_BUFFER_TOO_SMALL: Self = Self(2);
    pub const OSDP_ERR_TRUNCATED: Self = Self(3);
    pub const OSDP_ERR_BAD_SOM: Self = Self(4);
    pub const OSDP_ERR_BAD_LENGTH: Self = Self(5);
    pub const OSDP_ERR_BAD_CTRL: Self = Self(6);
    pub const OSDP_ERR_BAD_CRC: Self = Self(7);
    pub const OSDP_ERR_BAD_CHECKSUM: Self = Self(8);
    pub const OSDP_ERR_BAD_PAYLOAD: Self = Self(9);
    pub const OSDP_ERR_NOT_SUPPORTED: Self = Self(10);
}

// ====================================================================
// osdp_crc.h / osdp_checksum.h
// ====================================================================

pub const OSDP_CRC16_INIT: u16 = 0x1D0F;

extern "C" {
    pub fn osdp_crc16(data: *const u8, len: usize) -> u16;
    pub fn osdp_crc16_update(crc: u16, data: *const u8, len: usize) -> u16;
    pub fn osdp_checksum(data: *const u8, len: usize) -> u8;
}

// ====================================================================
// osdp_frame.h
// ====================================================================

pub const OSDP_SOM: u8 = 0x53;
pub const OSDP_BROADCAST_ADDR: u8 = 0x7F;
pub const OSDP_REPLY_FLAG: u8 = 0x80;
pub const OSDP_ADDR_MASK: u8 = 0x7F;

pub const OSDP_CTRL_SQN_MASK: u8 = 0x03;
pub const OSDP_CTRL_USE_CRC: u8 = 0x04;
pub const OSDP_CTRL_SCB: u8 = 0x08;
pub const OSDP_CTRL_RESERVED: u8 = 0xF0;

pub const OSDP_FRAME_HEADER_LEN: usize = 5;
pub const OSDP_FRAME_MIN_LEN_CKSUM: usize = 7;
pub const OSDP_FRAME_MIN_LEN_CRC: usize = 8;
pub const OSDP_FRAME_MAX_LEN: usize = 1440;
/// Spec 5.7 marking byte (0xFF) and how many `osdp_frame_build`
/// prepends ahead of the SOM. Excluded from the LEN field and
/// integrity; stripped on receive by the stream decoder.
pub const OSDP_FRAME_MARK: u8 = 0xFF;
pub const OSDP_FRAME_MARK_LEN: usize = 1;

pub const OSDP_SCB_MIN_LEN: u8 = 2;

// SCB types
pub const OSDP_SCS_11: u8 = 0x11;
pub const OSDP_SCS_12: u8 = 0x12;
pub const OSDP_SCS_13: u8 = 0x13;
pub const OSDP_SCS_14: u8 = 0x14;
pub const OSDP_SCS_15: u8 = 0x15;
pub const OSDP_SCS_16: u8 = 0x16;
pub const OSDP_SCS_17: u8 = 0x17;
pub const OSDP_SCS_18: u8 = 0x18;

pub const OSDP_FRAME_MAC_LEN: usize = 4;

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct osdp_integrity_t(pub c_int);

impl osdp_integrity_t {
    pub const OSDP_INTEGRITY_CHECKSUM: Self = Self(0);
    pub const OSDP_INTEGRITY_CRC: Self = Self(1);
}

#[repr(C)]
pub struct osdp_frame_t {
    pub address: u8,
    pub reply: bool,
    pub sequence: u8,
    pub integrity: osdp_integrity_t,
    pub has_scb: bool,

    pub scb_length: u8,
    pub scb_type: u8,
    pub scb_data: *const u8,
    pub scb_data_len: usize,

    pub code: u8,
    pub payload: *const u8,
    pub payload_len: usize,

    pub mac: *const u8,
    pub mac_len: usize,

    pub raw: *const u8,
    pub raw_len: usize,
}

extern "C" {
    pub fn osdp_frame_decode(buf: *const u8, len: usize, out: *mut osdp_frame_t) -> osdp_status_t;

    pub fn osdp_frame_build(
        in_: *const osdp_frame_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;
}

// ====================================================================
// osdp_stream.h
// ====================================================================

pub const OSDP_STREAM_BUFFER_LEN: usize = OSDP_FRAME_MAX_LEN;

#[repr(C)]
pub struct osdp_stream_t {
    pub buffer: [u8; OSDP_STREAM_BUFFER_LEN],
    pub fill: usize,
    pub pending_consume: usize,
}

extern "C" {
    pub fn osdp_stream_init(s: *mut osdp_stream_t);
    pub fn osdp_stream_reset(s: *mut osdp_stream_t);
    pub fn osdp_stream_feed(s: *mut osdp_stream_t, data: *const u8, len: usize) -> osdp_status_t;
    pub fn osdp_stream_next(s: *mut osdp_stream_t, out: *mut osdp_frame_t) -> osdp_status_t;
}

// ====================================================================
// osdp_commands.h
// ====================================================================

pub const OSDP_CMD_POLL: u8 = 0x60;
pub const OSDP_CMD_ID: u8 = 0x61;
pub const OSDP_CMD_CAP: u8 = 0x62;
pub const OSDP_CMD_LSTAT: u8 = 0x64;
pub const OSDP_CMD_ISTAT: u8 = 0x65;
pub const OSDP_CMD_OSTAT: u8 = 0x66;
pub const OSDP_CMD_RSTAT: u8 = 0x67;
pub const OSDP_CMD_OUT: u8 = 0x68;
pub const OSDP_CMD_LED: u8 = 0x69;
pub const OSDP_CMD_BUZ: u8 = 0x6A;
pub const OSDP_CMD_TEXT: u8 = 0x6B;
pub const OSDP_CMD_COMSET: u8 = 0x6E;
pub const OSDP_CMD_BIOREAD: u8 = 0x73;
pub const OSDP_CMD_BIOMATCH: u8 = 0x74;
pub const OSDP_CMD_KEYSET: u8 = 0x75;
pub const OSDP_CMD_CHLNG: u8 = 0x76;
pub const OSDP_CMD_SCRYPT: u8 = 0x77;
pub const OSDP_CMD_ACURXSIZE: u8 = 0x7B;
pub const OSDP_CMD_FILETRANSFER: u8 = 0x7C;
pub const OSDP_CMD_MFG: u8 = 0x80;
pub const OSDP_CMD_XWR: u8 = 0xA1;
pub const OSDP_CMD_ABORT: u8 = 0xA2;
pub const OSDP_CMD_PIVDATA: u8 = 0xA3;
pub const OSDP_CMD_GENAUTH: u8 = 0xA4;
pub const OSDP_CMD_CRAUTH: u8 = 0xA5;
pub const OSDP_CMD_KEEPACTIVE: u8 = 0xA7;

#[repr(C)]
pub struct osdp_id_cmd_t {
    pub id_type: u8,
}

#[repr(C)]
pub struct osdp_cap_cmd_t {
    pub reply_type: u8,
}

pub const OSDP_OUT_RECORD_BYTES: usize = 4;

#[repr(C)]
pub struct osdp_out_record_t {
    pub output_no: u8,
    pub control_code: u8,
    pub timer_100ms: u16,
}

pub const OSDP_LED_RECORD_BYTES: usize = 14;

#[repr(C)]
pub struct osdp_led_record_t {
    pub reader_no: u8,
    pub led_no: u8,
    pub temp_control_code: u8,
    pub temp_on_time: u8,
    pub temp_off_time: u8,
    pub temp_on_color: u8,
    pub temp_off_color: u8,
    pub temp_timer_100ms: u16,
    pub perm_control_code: u8,
    pub perm_on_time: u8,
    pub perm_off_time: u8,
    pub perm_on_color: u8,
    pub perm_off_color: u8,
}

pub const OSDP_BUZ_PAYLOAD_BYTES: usize = 5;

#[repr(C)]
pub struct osdp_buz_cmd_t {
    pub reader_no: u8,
    pub tone_code: u8,
    pub on_time_100ms: u8,
    pub off_time_100ms: u8,
    pub count: u8,
}

pub const OSDP_TEXT_HEADER_BYTES: usize = 6;

pub const OSDP_TEXT_PERM_NO_WRAP: u8 = 0x01;
pub const OSDP_TEXT_PERM_WRAP: u8 = 0x02;
pub const OSDP_TEXT_TEMP_NO_WRAP: u8 = 0x03;
pub const OSDP_TEXT_TEMP_WRAP: u8 = 0x04;

#[repr(C)]
pub struct osdp_text_cmd_t {
    pub reader_no: u8,
    pub text_command: u8,
    pub temp_text_time_s: u8,
    pub row: u8,
    pub column: u8,
    pub text_length: u8,
    pub text: *const u8,
    pub text_len: usize,
}

pub const OSDP_COMSET_PAYLOAD_BYTES: usize = 5;

#[repr(C)]
pub struct osdp_comset_cmd_t {
    pub address: u8,
    pub baud_rate: u32,
}

extern "C" {
    pub fn osdp_poll_decode(payload: *const u8, len: usize) -> osdp_status_t;
    pub fn osdp_poll_build(buf: *mut u8, buf_cap: usize, written: *mut usize) -> osdp_status_t;

    pub fn osdp_id_decode(payload: *const u8, len: usize, out: *mut osdp_id_cmd_t)
        -> osdp_status_t;
    pub fn osdp_id_build(
        in_: *const osdp_id_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_cap_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_cap_cmd_t,
    ) -> osdp_status_t;
    pub fn osdp_cap_build(
        in_: *const osdp_cap_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_out_decode(
        payload: *const u8,
        len: usize,
        records: *mut osdp_out_record_t,
        records_cap: usize,
        records_written: *mut usize,
    ) -> osdp_status_t;
    pub fn osdp_out_build(
        records: *const osdp_out_record_t,
        record_count: usize,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_led_decode(
        payload: *const u8,
        len: usize,
        records: *mut osdp_led_record_t,
        records_cap: usize,
        records_written: *mut usize,
    ) -> osdp_status_t;
    pub fn osdp_led_build(
        records: *const osdp_led_record_t,
        record_count: usize,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_buz_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_buz_cmd_t,
    ) -> osdp_status_t;
    pub fn osdp_buz_build(
        in_: *const osdp_buz_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_text_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_text_cmd_t,
    ) -> osdp_status_t;
    pub fn osdp_text_build(
        in_: *const osdp_text_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_comset_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_comset_cmd_t,
    ) -> osdp_status_t;
    pub fn osdp_comset_build(
        in_: *const osdp_comset_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_keyset_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_keyset_cmd_t,
    ) -> osdp_status_t;
    pub fn osdp_keyset_build(
        in_: *const osdp_keyset_cmd_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;
}

pub const OSDP_KEYSET_HEADER_BYTES: usize = 2;

#[repr(C)]
pub struct osdp_keyset_cmd_t {
    pub key_type: u8,
    pub key_length: u8,
    pub key_data: *const u8,
    pub key_data_len: usize,
}

// ====================================================================
// osdp_replies.h
// ====================================================================

pub const OSDP_REPLY_ACK: u8 = 0x40;
pub const OSDP_REPLY_NAK: u8 = 0x41;
pub const OSDP_REPLY_PDID: u8 = 0x45;
pub const OSDP_REPLY_PDCAP: u8 = 0x46;
pub const OSDP_REPLY_LSTATR: u8 = 0x48;
pub const OSDP_REPLY_ISTATR: u8 = 0x49;
pub const OSDP_REPLY_OSTATR: u8 = 0x4A;
pub const OSDP_REPLY_RSTATR: u8 = 0x4B;
pub const OSDP_REPLY_RAW: u8 = 0x50;
pub const OSDP_REPLY_FMT: u8 = 0x51;
pub const OSDP_REPLY_KEYPAD: u8 = 0x53;
pub const OSDP_REPLY_COM: u8 = 0x54;
pub const OSDP_REPLY_BIOREADR: u8 = 0x57;
pub const OSDP_REPLY_BIOMATCHR: u8 = 0x58;
pub const OSDP_REPLY_CCRYPT: u8 = 0x76;
pub const OSDP_REPLY_RMAC_I: u8 = 0x78;
pub const OSDP_REPLY_BUSY: u8 = 0x79;
pub const OSDP_REPLY_FTSTAT: u8 = 0x7A;
pub const OSDP_REPLY_PIVDATAR: u8 = 0x80;
pub const OSDP_REPLY_GENAUTHR: u8 = 0x81;
pub const OSDP_REPLY_CRAUTHR: u8 = 0x82;
pub const OSDP_REPLY_MFGSTATR: u8 = 0x83;
pub const OSDP_REPLY_MFGERRR: u8 = 0x84;
pub const OSDP_REPLY_MFGREP: u8 = 0x90;
pub const OSDP_REPLY_XRD: u8 = 0xB1;

pub const OSDP_NAK_NO_ERROR: u8 = 0x00;
pub const OSDP_NAK_BAD_CHECK: u8 = 0x01;
pub const OSDP_NAK_CMD_LENGTH: u8 = 0x02;
pub const OSDP_NAK_UNKNOWN_CMD: u8 = 0x03;
pub const OSDP_NAK_UNEXPECTED_SEQUENCE: u8 = 0x04;
pub const OSDP_NAK_UNSUPPORTED_SCB: u8 = 0x05;
pub const OSDP_NAK_ENCRYPTION_REQUIRED: u8 = 0x06;
pub const OSDP_NAK_BIO_TYPE_UNSUPPORTED: u8 = 0x07;
pub const OSDP_NAK_BIO_FORMAT_UNSUPPORTED: u8 = 0x08;
pub const OSDP_NAK_RECORD_INVALID: u8 = 0x09;

#[repr(C)]
pub struct osdp_nak_t {
    pub error_code: u8,
    pub details: *const u8,
    pub details_len: usize,
}

pub const OSDP_PDID_PAYLOAD_BYTES: usize = 12;

#[repr(C)]
pub struct osdp_pdid_t {
    pub vendor_code: [u8; 3],
    pub model: u8,
    pub version: u8,
    pub serial: u32,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub firmware_build: u8,
}

pub const OSDP_PDCAP_RECORD_BYTES: usize = 3;

#[repr(C)]
pub struct osdp_pdcap_record_t {
    pub function_code: u8,
    pub compliance_level: u8,
    pub num_objects: u8,
}

pub const OSDP_RAW_HEADER_BYTES: usize = 4;

#[repr(C)]
pub struct osdp_raw_t {
    pub reader_no: u8,
    pub format_code: u8,
    pub bit_count: u16,
    pub bit_data: *const u8,
    pub bit_data_len: usize,
}

pub const OSDP_KEYPAD_HEADER_BYTES: usize = 2;

#[repr(C)]
pub struct osdp_keypad_t {
    pub reader_no: u8,
    pub digit_count: u8,
    pub digits: *const u8,
    pub digits_len: usize,
}

pub const OSDP_COM_PAYLOAD_BYTES: usize = 5;

#[repr(C)]
pub struct osdp_com_t {
    pub address: u8,
    pub baud_rate: u32,
}

extern "C" {
    pub fn osdp_ack_decode(payload: *const u8, len: usize) -> osdp_status_t;
    pub fn osdp_ack_build(buf: *mut u8, buf_cap: usize, written: *mut usize) -> osdp_status_t;

    pub fn osdp_nak_decode(payload: *const u8, len: usize, out: *mut osdp_nak_t) -> osdp_status_t;
    pub fn osdp_nak_build(
        in_: *const osdp_nak_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_pdid_decode(payload: *const u8, len: usize, out: *mut osdp_pdid_t)
        -> osdp_status_t;
    pub fn osdp_pdid_build(
        in_: *const osdp_pdid_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_pdcap_decode(
        payload: *const u8,
        len: usize,
        records: *mut osdp_pdcap_record_t,
        records_cap: usize,
        records_written: *mut usize,
    ) -> osdp_status_t;
    pub fn osdp_pdcap_build(
        records: *const osdp_pdcap_record_t,
        record_count: usize,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_raw_decode(payload: *const u8, len: usize, out: *mut osdp_raw_t) -> osdp_status_t;
    pub fn osdp_raw_build(
        in_: *const osdp_raw_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_keypad_decode(
        payload: *const u8,
        len: usize,
        out: *mut osdp_keypad_t,
    ) -> osdp_status_t;
    pub fn osdp_keypad_build(
        in_: *const osdp_keypad_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_com_decode(payload: *const u8, len: usize, out: *mut osdp_com_t) -> osdp_status_t;
    pub fn osdp_com_build(
        in_: *const osdp_com_t,
        buf: *mut u8,
        buf_cap: usize,
        written: *mut usize,
    ) -> osdp_status_t;
}

// ====================================================================
// osdp_dispatch.h
// ====================================================================

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct osdp_message_kind_t(pub c_int);

impl osdp_message_kind_t {
    pub const UNKNOWN_COMMAND: Self = Self(0);
    pub const UNKNOWN_REPLY: Self = Self(1);
    pub const CMD_POLL: Self = Self(2);
    pub const CMD_ID: Self = Self(3);
    pub const CMD_CAP: Self = Self(4);
    // Other values exist (LSTAT..KEEPACTIVE for commands, ACK..XRD for
    // replies). Consumers that need to inspect specific message kinds
    // should compare against the integer value returned by the C side.
}

extern "C" {
    pub fn osdp_dispatch_classify(frame: *const osdp_frame_t) -> osdp_message_kind_t;
    pub fn osdp_dispatch_name(kind: osdp_message_kind_t) -> *const c_char;
}

// ====================================================================
// osdp_sc_crypto.h
// ====================================================================

pub const OSDP_AES_BLOCK_LEN: usize = 16;
pub const OSDP_AES_KEY_LEN: usize = 16;

pub type osdp_sc_aes_cb = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        key: *const u8, // [u8; OSDP_AES_KEY_LEN]
        in_: *const u8, // [u8; OSDP_AES_BLOCK_LEN]
        out: *mut u8,   // [u8; OSDP_AES_BLOCK_LEN]
    ) -> osdp_status_t,
>;

pub type osdp_sc_rand_cb =
    Option<unsafe extern "C" fn(user: *mut c_void, out: *mut u8, len: usize) -> osdp_status_t>;

#[repr(C)]
pub struct osdp_sc_crypto_t {
    pub aes128_ecb_encrypt: osdp_sc_aes_cb,
    pub aes128_ecb_decrypt: osdp_sc_aes_cb,
    pub rand_bytes: osdp_sc_rand_cb,
    pub user: *mut c_void,
}

// ====================================================================
// osdp_sc.h
// ====================================================================

pub const OSDP_SC_KEY_LEN: usize = 16;
pub const OSDP_SC_RND_LEN: usize = 8;
pub const OSDP_SC_CUID_LEN: usize = 8;
pub const OSDP_SC_CRYPTOGRAM_LEN: usize = 16;
pub const OSDP_SC_MAC_LEN: usize = 16;
pub const OSDP_SC_MAC_TRUNCATED: usize = 4;

extern "C" {
    pub static OSDP_SCBK_DEFAULT: [u8; OSDP_SC_KEY_LEN];
}

#[repr(C)]
pub struct osdp_sc_session_keys_t {
    pub s_enc: [u8; OSDP_SC_KEY_LEN],
    pub s_mac1: [u8; OSDP_SC_KEY_LEN],
    pub s_mac2: [u8; OSDP_SC_KEY_LEN],
}

#[repr(C)]
pub struct osdp_sc_session_t {
    pub keys: osdp_sc_session_keys_t,
    pub last_outbound_mac: [u8; OSDP_SC_MAC_LEN],
    pub last_inbound_mac: [u8; OSDP_SC_MAC_LEN],
    pub established: bool,
}

extern "C" {
    pub fn osdp_sc_session_init(session: *mut osdp_sc_session_t);

    pub fn osdp_sc_derive_session_keys(
        crypto: *const osdp_sc_crypto_t,
        scbk: *const u8,  // [u8; OSDP_SC_KEY_LEN]
        rnd_a: *const u8, // [u8; OSDP_SC_RND_LEN]
        out: *mut osdp_sc_session_keys_t,
    ) -> osdp_status_t;

    pub fn osdp_sc_client_cryptogram(
        crypto: *const osdp_sc_crypto_t,
        s_enc: *const u8,
        rnd_a: *const u8,
        rnd_b: *const u8,
        out: *mut u8, // [u8; OSDP_SC_CRYPTOGRAM_LEN]
    ) -> osdp_status_t;

    pub fn osdp_sc_server_cryptogram(
        crypto: *const osdp_sc_crypto_t,
        s_enc: *const u8,
        rnd_a: *const u8,
        rnd_b: *const u8,
        out: *mut u8,
    ) -> osdp_status_t;

    pub fn osdp_sc_initial_rmac(
        crypto: *const osdp_sc_crypto_t,
        s_mac1: *const u8,
        s_mac2: *const u8,
        server_cryptogram: *const u8,
        out: *mut u8, // [u8; OSDP_SC_MAC_LEN]
    ) -> osdp_status_t;

    pub fn osdp_sc_compute_mac(
        crypto: *const osdp_sc_crypto_t,
        s_mac1: *const u8,
        s_mac2: *const u8,
        icv: *const u8,
        msg: *const u8,
        len: usize,
        out: *mut u8,
    ) -> osdp_status_t;

    pub fn osdp_sc_cbc_encrypt(
        crypto: *const osdp_sc_crypto_t,
        key: *const u8,
        iv: *const u8,
        plaintext: *const u8,
        len: usize,
        ciphertext: *mut u8,
    ) -> osdp_status_t;

    pub fn osdp_sc_cbc_decrypt(
        crypto: *const osdp_sc_crypto_t,
        key: *const u8,
        iv: *const u8,
        ciphertext: *const u8,
        len: usize,
        plaintext: *mut u8,
    ) -> osdp_status_t;

    pub fn osdp_sc_encrypt_payload(
        crypto: *const osdp_sc_crypto_t,
        s_enc: *const u8,
        last_inbound_mac: *const u8,
        plaintext: *const u8,
        plaintext_len: usize,
        ciphertext: *mut u8,
        ciphertext_cap: usize,
        ciphertext_len: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_sc_decrypt_payload(
        crypto: *const osdp_sc_crypto_t,
        s_enc: *const u8,
        last_outbound_mac: *const u8,
        ciphertext: *const u8,
        ciphertext_len: usize,
        plaintext: *mut u8,
        plaintext_cap: usize,
        plaintext_len: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_sc_wrap_frame(
        crypto: *const osdp_sc_crypto_t,
        session: *mut osdp_sc_session_t,
        plain_template: *const osdp_frame_t,
        out_buf: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> osdp_status_t;

    pub fn osdp_sc_unwrap_frame(
        crypto: *const osdp_sc_crypto_t,
        session: *mut osdp_sc_session_t,
        frame: *const osdp_frame_t,
        plaintext_out: *mut u8,
        plain_cap: usize,
        plain_len: *mut usize,
    ) -> osdp_status_t;
}

// ====================================================================
// osdp_pd.h - feature-gated to `pd`
// ====================================================================

#[cfg(feature = "pd")]
pub use pd_ffi::*;

#[cfg(feature = "pd")]
mod pd_ffi {
    use super::*;

    pub const OSDP_PD_TX_BUF_LEN: usize = 256;
    pub const OSDP_PD_OFFLINE_TIMEOUT_MS: u32 = 8000;

    pub type osdp_pd_read_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, buf: *mut u8, cap: usize) -> c_int>;
    pub type osdp_pd_write_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, buf: *const u8, len: usize) -> c_int>;
    pub type osdp_pd_now_ms_cb = Option<unsafe extern "C" fn(user: *mut c_void) -> u32>;

    #[repr(C)]
    pub struct osdp_pd_transport_t {
        pub read: osdp_pd_read_cb,
        pub write: osdp_pd_write_cb,
        pub now_ms: osdp_pd_now_ms_cb,
        pub user: *mut c_void,
    }

    #[repr(C)]
    pub struct osdp_pd_reply_t {
        pub code: u8,
        pub payload: *const u8,
        pub payload_len: usize,
    }

    pub type osdp_pd_command_cb = Option<
        unsafe extern "C" fn(
            user: *mut c_void,
            cmd_code: u8,
            payload: *const u8,
            payload_len: usize,
            reply: *mut osdp_pd_reply_t,
        ) -> osdp_status_t,
    >;

    #[repr(C)]
    pub struct osdp_pd_sc_t {
        pub crypto: osdp_sc_crypto_t,
        pub crypto_set: bool,
        pub scbk: [u8; OSDP_SC_KEY_LEN],
        pub scbk_set: bool,
        pub scbk_d: [u8; OSDP_SC_KEY_LEN],
        pub scbk_d_set: bool,
        pub cuid: [u8; OSDP_SC_CUID_LEN],
        pub cuid_set: bool,
        pub session: osdp_sc_session_t,
        pub got_chlng: bool,
        pub rnd_a: [u8; OSDP_SC_RND_LEN],
        pub rnd_b: [u8; OSDP_SC_RND_LEN],
        pub key_selector: u8,
    }

    #[repr(C)]
    pub struct osdp_pd_t {
        pub address: u8,
        pub rx: osdp_stream_t,
        pub transport: osdp_pd_transport_t,
        pub cmd_cb: osdp_pd_command_cb,
        pub cmd_user: *mut c_void,
        pub tx_buf: [u8; OSDP_PD_TX_BUF_LEN],

        pub last_reply: [u8; OSDP_PD_TX_BUF_LEN],
        pub last_reply_len: usize,
        pub last_cmd: [u8; OSDP_PD_TX_BUF_LEN],
        pub last_cmd_len: usize,
        pub last_seq: u8,
        pub have_last: bool,

        pub online: bool,
        pub last_comm_ms: u32,

        pub sc: osdp_pd_sc_t,
    }

    extern "C" {
        pub fn osdp_pd_init(pd: *mut osdp_pd_t, address: u8);
        pub fn osdp_pd_set_transport(pd: *mut osdp_pd_t, transport: *const osdp_pd_transport_t);
        pub fn osdp_pd_set_command_handler(
            pd: *mut osdp_pd_t,
            cb: osdp_pd_command_cb,
            user: *mut c_void,
        );
        pub fn osdp_pd_tick(pd: *mut osdp_pd_t);
        pub fn osdp_pd_is_online(pd: *const osdp_pd_t) -> bool;

        pub fn osdp_pd_set_sc_crypto(pd: *mut osdp_pd_t, crypto: *const osdp_sc_crypto_t);
        pub fn osdp_pd_set_sc_scbk(pd: *mut osdp_pd_t, scbk: *const u8);
        pub fn osdp_pd_set_sc_scbk_d(pd: *mut osdp_pd_t, scbk_d: *const u8);
        pub fn osdp_pd_set_sc_cuid(pd: *mut osdp_pd_t, cuid: *const u8);
        pub fn osdp_pd_sc_established(pd: *const osdp_pd_t) -> bool;
    }
} // mod pd_ffi

// ====================================================================
// osdp_acu.h - feature-gated to `acu`
// ====================================================================

#[cfg(feature = "acu")]
pub use acu_ffi::*;

#[cfg(feature = "acu")]
mod acu_ffi {
    use super::*;

    pub const OSDP_ACU_REPLY_TIMEOUT_MS: u32 = 200;
    pub const OSDP_ACU_OFFLINE_TIMEOUT_MS: u32 = 8000;
    pub const OSDP_ACU_TX_BUF_LEN: usize = 256;

    // The transport callback shape is identical between PD and ACU; rather
    // than aliasing `osdp_pd_read_cb` (which would create a hard cross-
    // feature dependency), we redeclare them here. They're ABI-identical
    // to the PD versions.
    pub type osdp_acu_read_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, buf: *mut u8, cap: usize) -> c_int>;
    pub type osdp_acu_write_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, buf: *const u8, len: usize) -> c_int>;
    pub type osdp_acu_now_ms_cb = Option<unsafe extern "C" fn(user: *mut c_void) -> u32>;

    #[repr(C)]
    pub struct osdp_acu_transport_t {
        pub read: osdp_acu_read_cb,
        pub write: osdp_acu_write_cb,
        pub now_ms: osdp_acu_now_ms_cb,
        pub user: *mut c_void,
    }

    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub struct osdp_acu_sc_phase_t(pub c_int);

    impl osdp_acu_sc_phase_t {
        pub const IDLE: Self = Self(0);
        pub const AWAITING_CCRYPT: Self = Self(1);
        pub const AWAITING_RMAC_I: Self = Self(2);
        pub const ESTABLISHED: Self = Self(3);
    }

    #[repr(C)]
    pub struct osdp_acu_pd_slot_t {
        pub in_use: bool,
        pub address: u8,
        pub next_seq: u8,
        pub waiting: bool,
        pub pending_seq: u8,
        pub pending_code: u8,
        pub pending_sent_ms: u32,
        pub online: bool,
        pub last_reply_ms: u32,

        pub scbk_set: bool,
        pub scbk: [u8; OSDP_SC_KEY_LEN],
        pub scbk_d_set: bool,
        pub scbk_d: [u8; OSDP_SC_KEY_LEN],

        pub sc_phase: osdp_acu_sc_phase_t,
        pub sc_key_selector: u8,
        pub sc_rnd_a: [u8; OSDP_SC_RND_LEN],
        pub sc_rnd_b: [u8; OSDP_SC_RND_LEN],
        pub sc_cuid: [u8; OSDP_SC_CUID_LEN],

        pub sc_session: osdp_sc_session_t,
    }

    #[repr(C)]
    pub struct osdp_acu_reply_event_t {
        pub pd_address: u8,
        pub cmd_code: u8,
        pub reply_code: u8,
        pub payload: *const u8,
        pub payload_len: usize,
    }

    #[repr(C)]
    pub struct osdp_acu_timeout_event_t {
        pub pd_address: u8,
        pub cmd_code: u8,
        pub cmd_seq: u8,
    }

    pub type osdp_acu_reply_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, event: *const osdp_acu_reply_event_t)>;
    pub type osdp_acu_timeout_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, event: *const osdp_acu_timeout_event_t)>;

    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub struct osdp_acu_sc_event_kind_t(pub c_int);

    impl osdp_acu_sc_event_kind_t {
        pub const ESTABLISHED: Self = Self(0);
        pub const HANDSHAKE_FAILED: Self = Self(1);
        pub const SESSION_LOST: Self = Self(2);
    }

    #[repr(C)]
    pub struct osdp_acu_sc_event_t {
        pub pd_address: u8,
        pub kind: osdp_acu_sc_event_kind_t,
    }

    pub type osdp_acu_sc_event_cb =
        Option<unsafe extern "C" fn(user: *mut c_void, event: *const osdp_acu_sc_event_t)>;

    #[repr(C)]
    pub struct osdp_acu_t {
        pub transport: osdp_acu_transport_t,
        pub pds: *mut osdp_acu_pd_slot_t,
        pub pd_count: usize,
        pub reply_cb: osdp_acu_reply_cb,
        pub reply_user: *mut c_void,
        pub timeout_cb: osdp_acu_timeout_cb,
        pub timeout_user: *mut c_void,
        pub rx: osdp_stream_t,
        pub tx_buf: [u8; OSDP_ACU_TX_BUF_LEN],
        pub integrity: osdp_integrity_t,
        pub sc_crypto: osdp_sc_crypto_t,
        pub sc_crypto_set: bool,
        pub sc_event_cb: osdp_acu_sc_event_cb,
        pub sc_event_user: *mut c_void,
    }

    extern "C" {
        pub fn osdp_acu_init(
            acu: *mut osdp_acu_t,
            pd_slots: *mut osdp_acu_pd_slot_t,
            pd_count: usize,
        );
        pub fn osdp_acu_set_transport(acu: *mut osdp_acu_t, transport: *const osdp_acu_transport_t);
        pub fn osdp_acu_set_reply_handler(
            acu: *mut osdp_acu_t,
            cb: osdp_acu_reply_cb,
            user: *mut c_void,
        );
        pub fn osdp_acu_set_timeout_handler(
            acu: *mut osdp_acu_t,
            cb: osdp_acu_timeout_cb,
            user: *mut c_void,
        );
        pub fn osdp_acu_set_integrity(acu: *mut osdp_acu_t, integrity: osdp_integrity_t);
        pub fn osdp_acu_register_pd(
            acu: *mut osdp_acu_t,
            slot_index: usize,
            pd_address: u8,
        ) -> osdp_status_t;
        pub fn osdp_acu_send_command(
            acu: *mut osdp_acu_t,
            pd_address: u8,
            cmd_code: u8,
            payload: *const u8,
            payload_len: usize,
        ) -> osdp_status_t;
        pub fn osdp_acu_tick(acu: *mut osdp_acu_t);
        pub fn osdp_acu_is_pd_online(acu: *const osdp_acu_t, pd_address: u8) -> bool;
        pub fn osdp_acu_is_pd_busy(acu: *const osdp_acu_t, pd_address: u8) -> bool;

        pub fn osdp_acu_set_sc_crypto(acu: *mut osdp_acu_t, crypto: *const osdp_sc_crypto_t);
        pub fn osdp_acu_set_pd_scbk(
            acu: *mut osdp_acu_t,
            pd_address: u8,
            scbk: *const u8,
        ) -> osdp_status_t;
        pub fn osdp_acu_set_pd_scbk_d(
            acu: *mut osdp_acu_t,
            pd_address: u8,
            scbk_d: *const u8,
        ) -> osdp_status_t;
        pub fn osdp_acu_set_sc_event_handler(
            acu: *mut osdp_acu_t,
            cb: osdp_acu_sc_event_cb,
            user: *mut c_void,
        );
        pub fn osdp_acu_start_sc_handshake(
            acu: *mut osdp_acu_t,
            pd_address: u8,
            use_default_key: bool,
        ) -> osdp_status_t;
        pub fn osdp_acu_is_pd_sc_established(acu: *const osdp_acu_t, pd_address: u8) -> bool;
    }
} // mod acu_ffi
