// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! PD-side state machine.
//!
//! Wraps `osdp::pd` (the C library's `osdp_pd_*` API) behind two
//! traits:
//!
//!   - [`Transport`] — read / write / now_ms callbacks for the wire.
//!   - [`CommandHandler`] — application logic that turns inbound
//!     commands into outbound replies.
//!
//! The wrapper boxes both trait objects on the heap and threads thin
//! `*mut c_void` pointers into the C side; the boxes are kept alive
//! for the lifetime of the [`Pd`] and dropped automatically when it
//! is.
//!
//! # Example
//!
//! ```no_run
//! use osdp_embedded::pd::{Pd, Transport, CommandHandler, Reply};
//! use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK};
//!
//! struct MyTransport;
//! impl Transport for MyTransport {
//!     fn read(&mut self, buf: &mut [u8]) -> usize { 0 }
//!     fn write(&mut self, _buf: &[u8]) -> usize { 0 }
//!     fn now_ms(&mut self) -> Option<u32> { None }
//! }
//!
//! struct MyHandler;
//! impl CommandHandler for MyHandler {
//!     fn handle(&mut self, code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'_>> {
//!         match code {
//!             OSDP_CMD_POLL => Ok(Reply { code: OSDP_REPLY_ACK, payload: &[] }),
//!             _             => Err(osdp_embedded::Error::NotSupported),
//!         }
//!     }
//! }
//!
//! let mut pd = Pd::new(0x10);
//! pd.set_transport(MyTransport);
//! pd.set_command_handler(MyHandler);
//! pd.tick();
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use core::slice;

use crate::sys;

use crate::error::{Error, Result};
use crate::sc::{self, ScCrypto, ScCrypto2, SC2_CUID_LEN, SC2_KEY_LEN, SC_CUID_LEN, SC_KEY_LEN};
// Hoisted at the crate root - same trait shape worked for both Pd and
// Acu, no reason to keep duplicates. Re-exported here so consumers can
// still write `osdp_embedded::pd::Transport` if they prefer the
// role-qualified path.
pub use crate::transport::Transport;

/// What the application wants to send back for an inbound command.
/// Borrowed payload — the bytes are copied into the PD's TX scratch
/// before [`CommandHandler::handle`] returns, so the buffer can be
/// short-lived.
pub struct Reply<'a> {
    pub code: u8,
    pub payload: &'a [u8],
}

/// Application-level command handler. Called by [`Pd::tick`] for each
/// accepted inbound command.
///
/// Return:
///   - `Ok(reply)` — the PD will frame and transmit `reply`.
///   - `Err(Error::NotSupported)` — the PD will send NAK 0x03 (Unknown
///     Command Code).
///   - any other `Err(...)` — the PD treats it as an internal error
///     and drops the command silently.
pub trait CommandHandler: 'static {
    fn handle<'a>(&'a mut self, cmd_code: u8, payload: &[u8]) -> Result<Reply<'a>>;
}

/// Resolved colour of a reader LED (`osdp_led_color_t`, spec Table 18).
/// `Other` carries any non-standard value rather than silently mapping it
/// to a named colour.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum LedColor {
    /// 0x00 — off.
    Black,
    /// 0x01.
    Red,
    /// 0x02.
    Green,
    /// 0x03.
    Amber,
    /// 0x04.
    Blue,
    /// 0x05.
    Magenta,
    /// 0x06.
    Cyan,
    /// 0x07.
    White,
    /// Any other (reserved / vendor) colour code.
    Other(u8),
}

impl LedColor {
    /// Map a raw `osdp_led_color_t` byte to a [`LedColor`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            sys::OSDP_LED_BLACK => LedColor::Black,
            sys::OSDP_LED_RED => LedColor::Red,
            sys::OSDP_LED_GREEN => LedColor::Green,
            sys::OSDP_LED_AMBER => LedColor::Amber,
            sys::OSDP_LED_BLUE => LedColor::Blue,
            sys::OSDP_LED_MAGENTA => LedColor::Magenta,
            sys::OSDP_LED_CYAN => LedColor::Cyan,
            sys::OSDP_LED_WHITE => LedColor::White,
            other => LedColor::Other(other),
        }
    }

    /// The raw `osdp_led_color_t` byte for this colour.
    pub fn as_u8(self) -> u8 {
        match self {
            LedColor::Black => sys::OSDP_LED_BLACK,
            LedColor::Red => sys::OSDP_LED_RED,
            LedColor::Green => sys::OSDP_LED_GREEN,
            LedColor::Amber => sys::OSDP_LED_AMBER,
            LedColor::Blue => sys::OSDP_LED_BLUE,
            LedColor::Magenta => sys::OSDP_LED_MAGENTA,
            LedColor::Cyan => sys::OSDP_LED_CYAN,
            LedColor::White => sys::OSDP_LED_WHITE,
            LedColor::Other(v) => v,
        }
    }
}

/// Reader-LED change handler. Called by [`Pd::tick`] (and immediately when
/// an `osdp_LED` command arrives) whenever a tracked LED's *resolved*
/// displayed colour changes — on a new command, on temporary-timer
/// expiry, and on each flash on/off transition. Time-driven transitions
/// only surface if the [`Transport`] supplies a `now_ms` clock. The PD
/// decodes the LED command internally; the handler never parses it.
pub trait LedHandler: 'static {
    fn on_led_change(&mut self, reader_no: u8, led_no: u8, color: LedColor);
}

/// Reader-buzzer change handler. Called by [`Pd::tick`] (and immediately on
/// an inbound `osdp_BUZ`) whenever a tracked buzzer's *sounding* state
/// changes — when a command starts it, on each beep/silence edge of the
/// on/off pattern, and once more when the pattern finishes. `sounding` is
/// true while the buzzer is making sound; `tone` is the driving tone code
/// (0x01 off, 0x02 default tone). Time-driven edges only surface if the
/// [`Transport`] supplies a `now_ms` clock. The PD decodes the command
/// internally; the handler never parses it.
pub trait BuzzerHandler: 'static {
    fn on_buzzer_change(&mut self, reader_no: u8, sounding: bool, tone: u8);
}

/// Communication-configuration (`osdp_COMSET`) handler. The PD intercepts
/// inbound COMSET itself — building the `osdp_COM` reply and switching its
/// own 7-bit address — and drives this handler around that exchange:
///
/// - [`decide`](ComsetHandler::decide) runs *before* the reply is built. It
///   receives the ACU's requested `(address, baud)` and returns the values
///   the PD will actually use. Return the input unchanged to accept; lower or
///   replace either field to signal "unable to comply" (spec 6.13 — the PD
///   reports what it *will* use). An effective address above 0x7E is rejected
///   by the library, which keeps the current address instead.
/// - [`applied`](ComsetHandler::applied) runs *after* the `osdp_COM` reply
///   has been transmitted at the old parameters and the PD has adopted the
///   new address. Reconfigure the transport to `baud` and persist
///   `(address, baud)` to non-volatile storage here — doing so any earlier
///   would corrupt the in-flight reply.
///
/// Both methods have accept-the-request / do-nothing defaults, so a handler
/// only overrides the phase it cares about.
pub trait ComsetHandler: 'static {
    /// Decide the effective `(address, baud)`. Default: accept the request.
    fn decide(&mut self, req_address: u8, req_baud: u32) -> (u8, u32) {
        (req_address, req_baud)
    }

    /// The change is now live: the PD answers on `address` and the caller
    /// should switch its transport to `baud`. Default: no-op.
    ///
    /// Drain the transmitter before changing the baud. By the time this runs
    /// the library has handed the `osdp_COM` reply to the transport, but a
    /// `write()` returning does not mean the bytes are physically on the wire
    /// — switching the rate too early clocks out the tail of the reply at the
    /// new baud and the ACU never follows. Block until the reply has drained
    /// (`tcdrain` on POSIX; `FlushFileBuffers` plus a wait on Windows, since
    /// USB adapters hold bytes in a chip FIFO past `FlushFileBuffers`).
    fn applied(&mut self, address: u8, baud: u32) {
        let _ = (address, baud);
    }
}

/// A snapshot of one accepted `osdp_FILETRANSFER` fragment, passed to a
/// [`FileReceiver`]. `fragment` is this message's bytes and is available in
/// both modes. `data` is the accumulated reassembly buffer so far — populated
/// in reassembly mode ([`Pd::set_file_receiver`]), **empty** in streaming mode
/// ([`Pd::set_file_stream`]), where you read `fragment` instead. `complete` is
/// true on the final fragment.
pub struct FileFragment<'a> {
    /// FtType (0x01 opaque, 0x02 biomatch template, 0x03 display, ...).
    pub ft_type: u8,
    /// The full declared file size.
    pub total_size: u32,
    /// Byte offset of this fragment within the file.
    pub offset: u32,
    /// This fragment's bytes (empty for an idle fragment). Available in both
    /// reassembly and streaming modes.
    pub fragment: &'a [u8],
    /// The reassembly buffer filled so far (`0 ..= received`) in reassembly
    /// mode; **empty in streaming mode** — use [`fragment`](Self::fragment).
    pub data: &'a [u8],
    /// Contiguous bytes received so far, including this fragment. Useful for
    /// "N of total" progress in both modes.
    pub received: u32,
    /// True once the whole file has been received.
    pub complete: bool,
}

/// Why a [`FileReceiver`] rejects a fragment. The PD reports the mapped
/// negative `osdp_FTSTAT` status and aborts the transfer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileReject {
    /// File data is malformed (FtStatusDetail = -3).
    Malformed,
    /// File contents are unrecognized (FtStatusDetail = -2).
    Unrecognized,
    /// Abort the transfer for any other reason (FtStatusDetail = -1).
    Abort,
}

/// File-transfer receiver. The PD intercepts inbound `osdp_FILETRANSFER`
/// itself — building every `osdp_FTSTAT` reply — and calls this handler once
/// per accepted fragment to *evaluate* the bytes. The verdict drives the
/// reported status:
///
/// - `Ok(())` → the PD reports "proceed" mid-file and "processed" on the
///   final fragment.
/// - `Err(reject)` → the PD reports the mapped negative status
///   ([`FileReject`]) and aborts the transfer; the ACU may restart at
///   offset 0.
///
/// Register the same handler in one of two modes, depending on what the
/// target can afford:
///
/// - [`Pd::set_file_receiver`] (**reassembly**): the PD collects the whole
///   file into a buffer it owns and hands you the complete image on the final
///   fragment ([`FileFragment::data`]). Use this to validate a signature/CRC
///   over the entire file before acting, or to parse a small structured blob
///   (biomatch template, display data). Bounded by the buffer capacity.
/// - [`Pd::set_file_stream`] (**streaming**): no buffer — the PD hands you
///   each fragment ([`FileFragment::fragment`]) as it arrives and you persist
///   it yourself (e.g. write to flash). RAM use is independent of file size,
///   with no ceiling. Use this for firmware update on RAM-constrained targets.
///
/// Structural / bookkeeping failures (a file bigger than a reassembly buffer,
/// a gapped offset, a malformed frame) are handled by the library before this
/// runs — the handler only sees fragments that passed the invariants.
pub trait FileReceiver: 'static {
    /// Evaluate an accepted fragment. Default: accept everything.
    fn on_fragment(&mut self, fragment: &FileFragment) -> core::result::Result<(), FileReject> {
        let _ = fragment;
        Ok(())
    }
}

// ---- Internal storage ---------------------------------------------------
//
// Each trait object is wrapped in a `Box<dyn Trait>`. We need the
// stored value to be a thin pointer so it survives the round-trip
// through `*mut c_void`, hence the outer `Box<…>`.

type TransportBox = Box<dyn Transport>;
type CommandHandlerBox = Box<dyn CommandHandler>;
type LedHandlerBox = Box<dyn LedHandler>;
type BuzzerHandlerBox = Box<dyn BuzzerHandler>;
type ComsetHandlerBox = Box<dyn ComsetHandler>;
type FileReceiverBox = Box<dyn FileReceiver>;

/// PD context. Owns the C state plus any user-supplied trait objects.
///
/// Drop-safe: when [`Pd`] is dropped, the contained boxes are freed.
pub struct Pd {
    /// The C-side context. Heap-allocated because it's ~2.5 KB and we
    /// want a stable address (the C side stores `*mut osdp_pd_t`
    /// internally during set_transport / set_command_handler).
    inner: Box<sys::osdp_pd_t>,
    /// Held alive for the lifetime of `self`. The C side keeps a raw
    /// `*mut c_void` derived from this box's heap address.
    transport: Option<Box<TransportBox>>,
    cmd_handler: Option<Box<CommandHandlerBox>>,
    /// Held alive for the lifetime of `self`; the C side keeps a raw
    /// `*mut c_void` derived from this box's heap address as `led_user`.
    led_handler: Option<Box<LedHandlerBox>>,
    /// Same arrangement for the buzzer change handler (`buzzer_user`).
    buzzer_handler: Option<Box<BuzzerHandlerBox>>,
    /// Same arrangement for the COMSET handler (`comset_user`).
    comset_handler: Option<Box<ComsetHandlerBox>>,
    /// Same arrangement for the file-transfer receiver (`file_user`).
    file_receiver: Option<Box<FileReceiverBox>>,
    /// The reassembly buffer the C side writes inbound file fragments into.
    /// Its heap allocation must outlive registration (the C side holds a raw
    /// `file_buf` pointer into it); held here for exactly `self`'s lifetime.
    file_buffer: Option<Vec<u8>>,
    /// Secure-channel crypto vtable. The C side embedded a copy of
    /// the function-pointer struct inside `osdp_pd_t.sc.crypto`; we
    /// keep the trait-object box alive so the user pointer in that
    /// copy stays valid.
    sc_crypto: Option<Box<sc::ScCryptoBox>>,
    /// Same arrangement for the SC2 crypto vtable
    /// (`osdp_pd_t.sc2.crypto`).
    sc2_crypto: Option<Box<sc::ScCrypto2Box>>,
}

impl Pd {
    /// Create a fresh PD with working `address` (7-bit, 0x00..0x7E). The PD
    /// also always accepts and responds to frames sent to 0x7F, the
    /// configuration/broadcast address, answering those at 0x7F | reply flag
    /// (0xFF) per spec 5.9 Note 2.
    pub fn new(address: u8) -> Self {
        let mut inner = Box::<sys::osdp_pd_t>::new(unsafe { MaybeUninit::zeroed().assume_init() });
        unsafe { sys::osdp_pd_init(&mut *inner, address) };
        Self {
            inner,
            transport: None,
            cmd_handler: None,
            led_handler: None,
            buzzer_handler: None,
            comset_handler: None,
            file_receiver: None,
            file_buffer: None,
            sc_crypto: None,
            sc2_crypto: None,
        }
    }

    /// Bind a transport. Replaces any previously-set transport (the
    /// old one is dropped).
    pub fn set_transport<T: Transport>(&mut self, transport: T) {
        // Move into a Box<dyn Transport> first, then box THAT to get a
        // thin pointer suitable for round-tripping through *mut c_void.
        let boxed: Box<TransportBox> = Box::new(Box::new(transport));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        let c_transport = sys::osdp_pd_transport_t {
            read: Some(transport_read_thunk),
            write: Some(transport_write_thunk),
            now_ms: Some(transport_now_ms_thunk),
            user: user_ptr,
        };
        unsafe { sys::osdp_pd_set_transport(&mut *self.inner, &c_transport) };

        // Reclaim ownership of the box. Its heap location doesn't
        // change; user_ptr remains valid for as long as we hold the
        // box, which is exactly the lifetime of `self`.
        self.transport = Some(unsafe { Box::from_raw(user_ptr as *mut TransportBox) });
    }

    /// Bind the application command handler. Replaces any previously-
    /// set handler (the old one is dropped).
    pub fn set_command_handler<H: CommandHandler>(&mut self, handler: H) {
        let boxed: Box<CommandHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_pd_set_command_handler(
                &mut *self.inner,
                Some(command_handler_thunk),
                user_ptr,
            );
        }

        self.cmd_handler = Some(unsafe { Box::from_raw(user_ptr as *mut CommandHandlerBox) });
    }

    /// Pump the state machine: drain inbound bytes, dispatch any
    /// complete commands to the handler, send replies. Idempotent and
    /// non-blocking; call from the main loop.
    pub fn tick(&mut self) {
        unsafe { sys::osdp_pd_tick(&mut *self.inner) };
    }

    /// True iff the PD has sent at least one reply within the last
    /// 8 seconds. Always false for a fresh `Pd` until a reply lands.
    pub fn is_online(&self) -> bool {
        unsafe { sys::osdp_pd_is_online(&*self.inner) }
    }

    // ---- Reader LED observation ---------------------------------------

    /// Bind the reader-LED change handler. The PD transparently decodes
    /// inbound `osdp_LED` commands and calls `handler` whenever a tracked
    /// LED's resolved colour changes (see [`LedHandler`]). Replaces any
    /// previously-set handler (the old one is dropped).
    pub fn set_led_handler<H: LedHandler>(&mut self, handler: H) {
        let boxed: Box<LedHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_pd_set_led_handler(&mut *self.inner, Some(led_handler_thunk), user_ptr);
        }

        self.led_handler = Some(unsafe { Box::from_raw(user_ptr as *mut LedHandlerBox) });
    }

    /// Current displayed colour of the given reader LED. Returns
    /// [`LedColor::Black`] for an LED no `osdp_LED` command has addressed.
    /// Resolved against the transport's `now_ms` clock (or time 0 if
    /// none), so a flashing LED returns whichever phase is current.
    pub fn led_color(&self, reader_no: u8, led_no: u8) -> LedColor {
        LedColor::from_u8(unsafe { sys::osdp_pd_led_color(&*self.inner, reader_no, led_no) })
    }

    /// Bind the reader-buzzer change handler. The PD transparently decodes
    /// inbound `osdp_BUZ` commands and calls `handler` whenever a tracked
    /// buzzer's sounding state changes (see [`BuzzerHandler`]). Replaces any
    /// previously-set handler (the old one is dropped).
    pub fn set_buzzer_handler<H: BuzzerHandler>(&mut self, handler: H) {
        let boxed: Box<BuzzerHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_pd_set_buzzer_handler(&mut *self.inner, Some(buzzer_handler_thunk), user_ptr);
        }

        self.buzzer_handler = Some(unsafe { Box::from_raw(user_ptr as *mut BuzzerHandlerBox) });
    }

    /// Whether the given reader's buzzer is sounding right now. False for a
    /// reader no `osdp_BUZ` command has addressed. Resolved against the
    /// transport's `now_ms` clock (or time 0 if none).
    pub fn buzzer_sounding(&self, reader_no: u8) -> bool {
        unsafe { sys::osdp_pd_buzzer_sounding(&*self.inner, reader_no) }
    }

    // ---- Communication configuration ----------------------------------

    /// Bind the `osdp_COMSET` handler (see [`ComsetHandler`]). The PD builds
    /// the `osdp_COM` reply and switches its own address internally; this
    /// handler lets the application veto/clamp the requested values and enact
    /// the baud change once the reply has gone out. Replaces any previously-
    /// set handler (the old one is dropped).
    pub fn set_comset_handler<H: ComsetHandler>(&mut self, handler: H) {
        let boxed: Box<ComsetHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_pd_set_comset_handler(
                &mut *self.inner,
                Some(comset_decide_thunk),
                Some(comset_applied_thunk),
                user_ptr,
            );
        }

        self.comset_handler = Some(unsafe { Box::from_raw(user_ptr as *mut ComsetHandlerBox) });
    }

    // ---- File transfer ------------------------------------------------

    /// Bind a file-transfer receiver (see [`FileReceiver`]). The PD
    /// reassembles inbound `osdp_FILETRANSFER` data into a `capacity`-byte
    /// buffer owned by this `Pd` and calls `receiver` to evaluate each
    /// accepted fragment. `capacity` must be at least as large as the biggest
    /// file the ACU will send — a transfer whose declared size exceeds it is
    /// aborted. Without a receiver the PD NAKs file transfers with 0x03.
    /// Replaces any previously-set receiver and its buffer (both dropped).
    pub fn set_file_receiver<R: FileReceiver>(&mut self, capacity: usize, receiver: R) {
        let boxed: Box<FileReceiverBox> = Box::new(Box::new(receiver));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        // Heap-allocate the reassembly buffer. The Vec's backing allocation
        // has a stable address; moving the Vec handle into `self` below does
        // not move it, so the raw pointer we hand to C stays valid.
        let mut buffer: Vec<u8> = alloc::vec![0u8; capacity];
        let buf_ptr = buffer.as_mut_ptr();

        unsafe {
            sys::osdp_pd_set_file_receiver(
                &mut *self.inner,
                buf_ptr,
                capacity,
                Some(file_receiver_thunk),
                user_ptr,
            );
        }

        self.file_buffer = Some(buffer);
        self.file_receiver = Some(unsafe { Box::from_raw(user_ptr as *mut FileReceiverBox) });
    }

    /// Bind a **streaming** file-transfer receiver (see [`FileReceiver`]). No
    /// reassembly buffer: the PD hands each `osdp_FILETRANSFER` fragment to
    /// `receiver` as it arrives ([`FileFragment::fragment`];
    /// [`FileFragment::data`] is empty) and you persist it yourself. RAM use
    /// is independent of file size and there is no size ceiling — use this for
    /// firmware update on RAM-constrained targets. Replaces any previously-set
    /// receiver (and frees its reassembly buffer, if any).
    pub fn set_file_stream<R: FileReceiver>(&mut self, receiver: R) {
        let boxed: Box<FileReceiverBox> = Box::new(Box::new(receiver));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_pd_set_file_stream(&mut *self.inner, Some(file_receiver_thunk), user_ptr);
        }

        // Streaming needs no reassembly buffer; drop any previously-held one.
        self.file_buffer = None;
        self.file_receiver = Some(unsafe { Box::from_raw(user_ptr as *mut FileReceiverBox) });
    }

    // ---- Secure Channel configuration ---------------------------------
    //
    // Secure Channel is fully optional. The PD only accepts SCB-bearing
    // frames once the application has bound a crypto vtable AND at
    // least one of (SCBK, SCBK-D) AND the cUID. Without all three the
    // PD continues to NAK SCB frames with code 0x05.

    /// Bind the crypto provider (AES + RNG) the PD will use for
    /// Secure Channel. Replaces any previously-bound provider.
    pub fn set_sc_crypto<C: ScCrypto>(&mut self, crypto: C) {
        let boxed: sc::ScCryptoBox = Box::new(crypto);
        let (vtable, user) = sc::build_vtable(boxed);
        unsafe {
            sys::osdp_pd_set_sc_crypto(&mut *self.inner, &vtable);
        }
        // Reclaim ownership of the heap-allocated trait object box so
        // it lives as long as `self` does. The C-side `sc.crypto.user`
        // points at the same allocation.
        self.sc_crypto = Some(unsafe { Box::from_raw(user as *mut sc::ScCryptoBox) });
    }

    /// Set the Secure Channel Base Key (SCBK), the per-installation
    /// 16-byte key used when the ACU starts a handshake with the
    /// SCBK selector.
    pub fn set_sc_scbk(&mut self, scbk: &[u8; SC_KEY_LEN]) {
        unsafe { sys::osdp_pd_set_sc_scbk(&mut *self.inner, scbk.as_ptr()) };
    }

    /// Set the default install-time key (SCBK-D), used when the ACU
    /// starts a handshake with the SCBK-D selector. The well-known
    /// constant from the spec is available as
    /// [`sc::scbk_default()`](crate::sc::scbk_default).
    pub fn set_sc_scbk_d(&mut self, scbk_d: &[u8; SC_KEY_LEN]) {
        unsafe { sys::osdp_pd_set_sc_scbk_d(&mut *self.inner, scbk_d.as_ptr()) };
    }

    /// Set the cUID — first 8 bytes of the PDID byte stream
    /// (vendor[3] + model + version + serial[0..2]) per spec D.4.3.
    pub fn set_sc_cuid(&mut self, cuid: &[u8; SC_CUID_LEN]) {
        unsafe { sys::osdp_pd_set_sc_cuid(&mut *self.inner, cuid.as_ptr()) };
    }

    /// True iff the SCS_11..14 handshake completed successfully and
    /// the PD is ready to handle SCS_15..18 operational traffic.
    pub fn sc_established(&self) -> bool {
        unsafe { sys::osdp_pd_sc_established(&*self.inner) }
    }

    // ---- Secure Channel 2 configuration -------------------------------
    //
    // Parallel to the SC1 setters. SC2 is device-key only (no SCBK-D);
    // the PD accepts SCS_21..28 frames once the SC2 crypto vtable, the
    // 32-byte SCBK, and the cUID are all set.

    /// Bind the SC2 crypto provider (KMAC256 + AES-256-GCM + AES-256
    /// block + RNG). Replaces any previously-bound SC2 provider.
    pub fn set_sc2_crypto<C: ScCrypto2>(&mut self, crypto: C) {
        let boxed: sc::ScCrypto2Box = Box::new(crypto);
        let (vtable, user) = sc::build_vtable2(boxed);
        unsafe {
            sys::osdp_pd_set_sc2_crypto(&mut *self.inner, &vtable);
        }
        self.sc2_crypto = Some(unsafe { Box::from_raw(user as *mut sc::ScCrypto2Box) });
    }

    /// Set the per-PD 32-byte AES-256 SC2 base key (SCBK).
    pub fn set_sc2_scbk(&mut self, scbk: &[u8; SC2_KEY_LEN]) {
        unsafe { sys::osdp_pd_set_sc2_scbk(&mut *self.inner, scbk.as_ptr()) };
    }

    /// Set the SC2 cUID — the PD's 8-byte client UID (part of every
    /// SC2 message nonce).
    pub fn set_sc2_cuid(&mut self, cuid: &[u8; SC2_CUID_LEN]) {
        unsafe { sys::osdp_pd_set_sc2_cuid(&mut *self.inner, cuid.as_ptr()) };
    }

    /// True iff the SCS_21..24 handshake completed and the PD is ready
    /// to handle SCS_25..28 operational traffic.
    pub fn sc2_established(&self) -> bool {
        unsafe { sys::osdp_pd_sc2_established(&*self.inner) }
    }

    /// Which Secure Channel key the **current session** is running under,
    /// or `None` when no session is established — in which case traffic on
    /// the wire is clear text right now, whatever keys happen to be
    /// configured. `Some(false)` = the default install key (SCBK-D);
    /// `Some(true)` = an operational per-installation SCBK. A KEYSET shows
    /// up here: once the ACU re-handshakes with the rotated operational key
    /// this flips from `Some(false)` to `Some(true)`.
    pub fn sc_operational(&self) -> Option<bool> {
        if !self.sc_established() {
            return None;
        }
        // `key_selector` is a plain u8 the C library sets during the
        // handshake (0 = SCBK-D, 1 = SCBK); reading it is a pure field load.
        Some(self.inner.sc.key_selector == 1)
    }
}

// `osdp::pd` is single-threaded by design (no internal locks). Don't
// expose Send/Sync; the user can wrap a Pd in a Mutex if they need to
// share ownership across threads.

// ---- Thunks ------------------------------------------------------------
//
// Translate a C-ABI callback into a Rust trait method invocation.

unsafe extern "C" fn transport_read_thunk(user: *mut c_void, buf: *mut u8, cap: usize) -> c_int {
    let storage = &mut *(user as *mut TransportBox);
    let slice = slice::from_raw_parts_mut(buf, cap);
    storage.read(slice) as c_int
}

unsafe extern "C" fn transport_write_thunk(user: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let storage = &mut *(user as *mut TransportBox);
    let slice = slice::from_raw_parts(buf, len);
    storage.write(slice) as c_int
}

unsafe extern "C" fn transport_now_ms_thunk(user: *mut c_void) -> u32 {
    let storage = &mut *(user as *mut TransportBox);
    storage.now_ms().unwrap_or(0)
}

unsafe extern "C" fn command_handler_thunk(
    user: *mut c_void,
    cmd_code: u8,
    payload: *const u8,
    payload_len: usize,
    reply: *mut sys::osdp_pd_reply_t,
) -> sys::osdp_status_t {
    let storage = &mut *(user as *mut CommandHandlerBox);
    let payload_slice = if payload_len == 0 || payload.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(payload, payload_len)
    };

    match storage.handle(cmd_code, payload_slice) {
        Ok(reply_value) => {
            let r = &mut *reply;
            r.code = reply_value.code;
            r.payload_len = reply_value.payload.len();
            r.payload = if reply_value.payload.is_empty() {
                ptr::null()
            } else {
                reply_value.payload.as_ptr()
            };
            sys::osdp_status_t::OSDP_OK
        }
        Err(e) => e.to_status(),
    }
}

unsafe extern "C" fn led_handler_thunk(user: *mut c_void, reader_no: u8, led_no: u8, color: u8) {
    let storage = &mut *(user as *mut LedHandlerBox);
    storage.on_led_change(reader_no, led_no, LedColor::from_u8(color));
}

unsafe extern "C" fn buzzer_handler_thunk(
    user: *mut c_void,
    reader_no: u8,
    sounding: bool,
    tone: u8,
) {
    let storage = &mut *(user as *mut BuzzerHandlerBox);
    storage.on_buzzer_change(reader_no, sounding, tone);
}

unsafe extern "C" fn comset_decide_thunk(
    user: *mut c_void,
    req_address: u8,
    req_baud: u32,
    eff_address: *mut u8,
    eff_baud: *mut u32,
) {
    if user.is_null() {
        return;
    }
    let storage = &mut *(user as *mut ComsetHandlerBox);
    let (address, baud) = storage.decide(req_address, req_baud);
    if !eff_address.is_null() {
        *eff_address = address;
    }
    if !eff_baud.is_null() {
        *eff_baud = baud;
    }
}

unsafe extern "C" fn comset_applied_thunk(user: *mut c_void, address: u8, baud: u32) {
    if user.is_null() {
        return;
    }
    let storage = &mut *(user as *mut ComsetHandlerBox);
    storage.applied(address, baud);
}

unsafe extern "C" fn file_receiver_thunk(
    user: *mut c_void,
    info: *const sys::osdp_pd_file_info_t,
) -> sys::osdp_status_t {
    if user.is_null() || info.is_null() {
        return sys::osdp_status_t::OSDP_ERR_INVALID_ARG;
    }
    let storage = &mut *(user as *mut FileReceiverBox);
    let info = &*info;

    let fragment = if info.fragment_len == 0 || info.fragment.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(info.fragment, info.fragment_len)
    };
    let data = if info.received == 0 || info.data.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(info.data, info.received as usize)
    };

    let fragment = FileFragment {
        ft_type: info.ft_type,
        total_size: info.total_size,
        offset: info.offset,
        fragment,
        data,
        received: info.received,
        complete: info.complete,
    };

    match storage.on_fragment(&fragment) {
        Ok(()) => sys::osdp_status_t::OSDP_OK,
        Err(FileReject::Malformed) => sys::osdp_status_t::OSDP_ERR_BAD_PAYLOAD,
        Err(FileReject::Unrecognized) => sys::osdp_status_t::OSDP_ERR_NOT_SUPPORTED,
        Err(FileReject::Abort) => sys::osdp_status_t::OSDP_ERR_INVALID_ARG,
    }
}

// ---- Drop impl ---------------------------------------------------------

impl Drop for Pd {
    fn drop(&mut self) {
        // The C side stores raw *mut c_void user pointers into our
        // boxes. Clear the C-side callbacks first so a stray tick
        // can't fire after we drop the boxes — defensive, since
        // `Pd` shouldn't be tick'd from another thread.
        unsafe {
            // Detach the command handler with NULL.
            sys::osdp_pd_set_command_handler(&mut *self.inner, None, ptr::null_mut());
            // Detach the LED change handler too, for the same reason.
            sys::osdp_pd_set_led_handler(&mut *self.inner, None, ptr::null_mut());
            // And the buzzer change handler.
            sys::osdp_pd_set_buzzer_handler(&mut *self.inner, None, ptr::null_mut());
            // And the COMSET decide/applied handlers.
            sys::osdp_pd_set_comset_handler(&mut *self.inner, None, None, ptr::null_mut());
            // And the file-transfer receiver (also clears the C-side buffer
            // pointer before we drop the backing Vec).
            sys::osdp_pd_set_file_receiver(
                &mut *self.inner,
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            );
            // Replace the transport with one whose callbacks are NULL
            // so future tick()s can't dereference our (about to be
            // dropped) trait objects. We still own the C struct; the
            // memcpy inside set_transport just overwrites the C-side
            // copy.
            let dead = sys::osdp_pd_transport_t {
                read: None,
                write: None,
                now_ms: None,
                user: ptr::null_mut(),
            };
            sys::osdp_pd_set_transport(&mut *self.inner, &dead);
        }
        // self.transport / self.cmd_handler drop here, freeing the
        // boxes. self.inner drops too.
    }
}

// Suppress "unused" warning on Error in some configs.
const _: fn() = || {
    let _: fn(Error) -> sys::osdp_status_t = Error::to_status;
};
