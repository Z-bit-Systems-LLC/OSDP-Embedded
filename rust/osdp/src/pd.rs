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
use crate::sc::{self, ScCrypto, SC_CUID_LEN, SC_KEY_LEN};
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

/// Application-supplied values for the four status commands — `osdp_LSTAT`,
/// `ISTAT`, `OSTAT`, `RSTAT`. The reply *layout* is the spec's business and
/// the library builds it; only the values are yours.
///
/// **Every provider is independent and opt-in**, mirroring the C vtable: a
/// command you don't supply keeps falling through to your
/// [`CommandHandler`], so an application already hand-building its own
/// `osdp_LSTATR` keeps working while it adopts the rest.
///
/// ```no_run
/// # use osdp_embedded::pd::{Pd, StatusProviders};
/// # let mut pd = Pd::new(0x10);
/// pd.set_status_providers(
///     StatusProviders::new()
///         .local(|| (0, 0))                       // tamper, power: normal
///         .inputs(|out| { out[0] = 0; 1 })        // one input, inactive
/// );
/// // osdp_OSTAT / osdp_RSTAT still reach the command handler.
/// ```
///
/// The three array-valued providers write into a scratch slice of
/// [`REPLY_SCRATCH_LEN`] bytes and return how many they wrote; returning more
/// than the slice holds is clamped, and returning 0 is legal — a PD with no
/// inputs genuinely has nothing to report.
#[derive(Default)]
pub struct StatusProviders {
    local: Option<StatusLocalFn>,
    inputs: Option<StatusArrayFn>,
    outputs: Option<StatusArrayFn>,
    readers: Option<StatusArrayFn>,
}

/// Answers `osdp_LSTAT` with the `(tamper, power)` pair.
type StatusLocalFn = Box<dyn FnMut() -> (u8, u8)>;
/// Answers `osdp_ISTAT` / `OSTAT` / `RSTAT`: fill the scratch slice, return
/// how many bytes were written.
type StatusArrayFn = Box<dyn FnMut(&mut [u8]) -> usize>;

impl StatusProviders {
    /// An empty set — every status command still reaches the command handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer `osdp_LSTAT` with `(tamper, power)` bytes. Use the
    /// `LSTATR_*` constants ([`crate::messages`] re-exports the raw values).
    pub fn local<F: FnMut() -> (u8, u8) + 'static>(mut self, f: F) -> Self {
        self.local = Some(Box::new(f));
        self
    }

    /// Answer `osdp_ISTAT` with one status byte per input.
    pub fn inputs<F: FnMut(&mut [u8]) -> usize + 'static>(mut self, f: F) -> Self {
        self.inputs = Some(Box::new(f));
        self
    }

    /// Answer `osdp_OSTAT` with one status byte per output.
    pub fn outputs<F: FnMut(&mut [u8]) -> usize + 'static>(mut self, f: F) -> Self {
        self.outputs = Some(Box::new(f));
        self
    }

    /// Answer `osdp_RSTAT` with one status byte per reader.
    pub fn readers<F: FnMut(&mut [u8]) -> usize + 'static>(mut self, f: F) -> Self {
        self.readers = Some(Box::new(f));
        self
    }
}

/// Receiver for a reassembled multi-part `osdp_MFG` (spec 5.10).
///
/// **Binding one is a declaration about your vendor protocol.** Nothing on
/// the wire distinguishes a 6-byte multi-part header from six bytes of
/// ordinary vendor data — Table 27 defines no multi-part fields for
/// `osdp_MFG` — so the library cannot detect the format and must not guess.
/// Registering a receiver says "this PD's vendor messages use the standard
/// multi-part format"; leave it unbound and `osdp_MFG` payloads stay opaque
/// and reach your [`CommandHandler`] unchanged.
///
/// `vendor_code` is the 3 bytes that prefixed *every* fragment (the vendor
/// code sits outside the fragmentation, so a PD can refuse a transfer that
/// isn't addressed to it before committing buffer). `data` is the whole
/// reassembled message with the multi-part headers removed.
pub trait MfgReceiver: 'static {
    /// Handle one complete vendor message.
    ///
    /// Return `Ok(None)` to ACK, `Ok(Some(reply))` to answer with an
    /// `osdp_MFGREP` (or any other reply), or `Err(...)` to NAK using the
    /// same mapping as [`CommandHandler`].
    fn on_message<'a>(
        &'a mut self,
        vendor_code: &[u8; 3],
        data: &[u8],
    ) -> Result<Option<Reply<'a>>>;
}

/// Scratch capacity handed to the array-valued [`StatusProviders`], matching
/// the C `OSDP_PD_REPLY_SCRATCH_LEN`.
pub const REPLY_SCRATCH_LEN: usize = sys::OSDP_PD_REPLY_SCRATCH_LEN;

/// What [`Pd::acu_rx_size`] reports before any `osdp_ACURXSIZE` has arrived
/// (spec 6.26).
pub const DEFAULT_ACU_RX_SIZE: u16 = sys::OSDP_PD_DEFAULT_ACU_RX_SIZE;

/// A capability record that this PD cannot honour, as found by
/// [`Pd::check_pdcap`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PdcapProblem {
    /// Index of the first offending record in the slice that was checked.
    pub index: usize,
    /// Why it was rejected — `NotSupported` for a capability the library
    /// does not implement, `BufferTooSmall` for one that outruns a bound
    /// buffer.
    pub error: Error,
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
type MfgReceiverBox = Box<dyn MfgReceiver>;
type AbortHandlerBox = Box<dyn FnMut() -> Result<()>>;
type AcuRxSizeHandlerBox = Box<dyn FnMut(u16)>;
type KeepActiveHandlerBox = Box<dyn FnMut(u16) -> Result<()>>;

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
    /// Status providers (`status.user`). The C side copied the vtable of
    /// thunk pointers into `osdp_pd_t`, but the user pointer in that copy
    /// aims at this box, so it has to outlive the binding.
    status_providers: Option<Box<StatusProviders>>,
    /// Same arrangement for the multi-part MFG receiver (`mfg_user`)…
    mfg_receiver: Option<Box<MfgReceiverBox>>,
    /// …and its caller-owned reassembly buffer (`mfg_reasm.buf`).
    mfg_buffer: Option<Vec<u8>>,
    /// Caller-owned storage for the poll-response event queue. The C side
    /// holds a raw pointer into this allocation.
    event_buffer: Option<Vec<u8>>,
    /// The three miscellaneous command hooks (`abort_user` etc.).
    abort_handler: Option<Box<AbortHandlerBox>>,
    acurxsize_handler: Option<Box<AcuRxSizeHandlerBox>>,
    keepactive_handler: Option<Box<KeepActiveHandlerBox>>,
    /// Secure-channel crypto vtable. The C side embedded a copy of
    /// the function-pointer struct inside `osdp_pd_t.sc.crypto`; we
    /// keep the trait-object box alive so the user pointer in that
    /// copy stays valid.
    sc_crypto: Option<Box<sc::ScCryptoBox>>,
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
            status_providers: None,
            mfg_receiver: None,
            mfg_buffer: None,
            event_buffer: None,
            abort_handler: None,
            acurxsize_handler: None,
            keepactive_handler: None,
            sc_crypto: None,
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

    // ---- Status reporting ---------------------------------------------

    /// Bind the status providers for `osdp_LSTAT` / `ISTAT` / `OSTAT` /
    /// `RSTAT` (see [`StatusProviders`]). Only the commands you supplied a
    /// provider for are answered by the library; the rest keep reaching the
    /// [`CommandHandler`]. Replaces any previously-set providers.
    pub fn set_status_providers(&mut self, providers: StatusProviders) {
        // One box holds all four closures; the C vtable's single `user`
        // pointer aims at it and each thunk picks the member it needs.
        let boxed = Box::new(providers);
        let user_ptr = Box::into_raw(boxed);

        // Bind a thunk only where the caller actually supplied a closure —
        // this is what preserves the C API's per-member optionality.
        let providers_ref = unsafe { &*user_ptr };
        let vtable = sys::osdp_pd_status_provider_t {
            local: providers_ref
                .local
                .as_ref()
                .map(|_| status_local_thunk as unsafe extern "C" fn(*mut c_void, *mut u8, *mut u8)),
            inputs: providers_ref.inputs.as_ref().map(|_| {
                status_inputs_thunk as unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> usize
            }),
            outputs: providers_ref.outputs.as_ref().map(|_| {
                status_outputs_thunk as unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> usize
            }),
            readers: providers_ref.readers.as_ref().map(|_| {
                status_readers_thunk as unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> usize
            }),
        };

        unsafe {
            sys::osdp_pd_set_status_provider(&mut *self.inner, &vtable, user_ptr as *mut c_void);
        }

        self.status_providers = Some(unsafe { Box::from_raw(user_ptr) });
    }

    // ---- Multi-part osdp_MFG ------------------------------------------

    /// Bind a reassembly buffer and receiver for multi-part `osdp_MFG` (see
    /// [`MfgReceiver`]). `capacity` must hold the biggest vendor message
    /// expected — a transfer declaring more is refused with `osdp_NAK 0x09`,
    /// which spec 5.10.2 says aborts the sender's sequence. Replaces any
    /// previously-set receiver and its buffer (both dropped).
    pub fn set_mfg_receiver<R: MfgReceiver>(&mut self, capacity: usize, receiver: R) {
        let boxed: Box<MfgReceiverBox> = Box::new(Box::new(receiver));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        let mut buffer: Vec<u8> = alloc::vec![0u8; capacity];
        let buf_ptr = buffer.as_mut_ptr();

        unsafe {
            sys::osdp_pd_set_mfg_receiver(
                &mut *self.inner,
                buf_ptr,
                capacity,
                Some(mfg_receiver_thunk),
                user_ptr,
            );
        }

        self.mfg_buffer = Some(buffer);
        self.mfg_receiver = Some(unsafe { Box::from_raw(user_ptr as *mut MfgReceiverBox) });
    }

    // ---- PDCAP consistency (advisory) ---------------------------------

    /// Check capability records against what this PD can actually honour.
    /// Call once at start-up with the same records the command handler will
    /// return for `osdp_CAP`.
    ///
    /// PDCAP is a set of promises the ACU acts on, and over-advertising does
    /// not fail loudly — the PD drops frames the ACU believes were delivered
    /// and it surfaces much later as unexplained retries. Only the three
    /// records describing the *library's* limits are checked (function codes
    /// 9, 10 and 11); how many inputs the device has is your business.
    ///
    /// Purely advisory: nothing calls it automatically and no wire behaviour
    /// depends on it.
    pub fn check_pdcap(
        &self,
        records: &[crate::messages::PdcapRecord],
    ) -> core::result::Result<(), PdcapProblem> {
        let c_records: Vec<sys::osdp_pdcap_record_t> = records
            .iter()
            .map(|r| sys::osdp_pdcap_record_t {
                function_code: r.function_code,
                compliance_level: r.compliance_level,
                num_objects: r.num_objects,
            })
            .collect();

        let mut bad_index: usize = 0;
        let rc = unsafe {
            sys::osdp_pd_check_pdcap(
                &*self.inner,
                if c_records.is_empty() {
                    ptr::null()
                } else {
                    c_records.as_ptr()
                },
                c_records.len(),
                &mut bad_index,
            )
        };

        match Error::from_status(rc) {
            Ok(()) => Ok(()),
            Err(error) => Err(PdcapProblem {
                index: bad_index,
                error,
            }),
        }
    }

    // ---- Poll-response events -----------------------------------------

    /// Bind `capacity` bytes of storage for the poll-response event queue —
    /// the replies the spec generates from physical events rather than from a
    /// command (`osdp_RAW` 7.10, `FMT` 7.11, `KEYPAD` 7.12, `MFGREP` 7.18).
    /// Budget roughly `payload + 3` bytes per queued event.
    ///
    /// With a queue bound, the PD answers the next `osdp_POLL` from the head
    /// of the queue instead of calling the [`CommandHandler`]; an empty queue
    /// falls through to the handler exactly as before, so this is additive.
    /// Replaces any previously-bound queue (discarding anything in it).
    pub fn set_event_queue(&mut self, capacity: usize) {
        let mut buffer: Vec<u8> = alloc::vec![0u8; capacity];
        let buf_ptr = buffer.as_mut_ptr();
        unsafe { sys::osdp_pd_set_event_queue(&mut *self.inner, buf_ptr, capacity) };
        self.event_buffer = Some(buffer);
    }

    /// Queue one reply to be sent in answer to the next `osdp_POLL`.
    /// `payload` is the already-encoded reply body — build it with the
    /// matching [`crate::messages`] builder.
    ///
    /// Returns [`Error::BufferTooSmall`] when the queue is full. Whether a
    /// dropped card read matters is the application's call, not the library's,
    /// so this reports rather than silently discarding.
    ///
    /// Note the queue is emptied when the PD goes offline (spec 7.11/7.12):
    /// a credential read from before an outage is never delivered late to an
    /// ACU that has since reconnected.
    pub fn enqueue_event(&mut self, reply_code: u8, payload: &[u8]) -> Result<()> {
        let rc = unsafe {
            sys::osdp_pd_enqueue_event(
                &mut *self.inner,
                reply_code,
                if payload.is_empty() {
                    ptr::null()
                } else {
                    payload.as_ptr()
                },
                payload.len(),
            )
        };
        Error::from_status(rc)
    }

    /// True while at least one event is waiting for the next poll.
    pub fn event_pending(&self) -> bool {
        unsafe { sys::osdp_pd_event_pending(&*self.inner) }
    }

    /// Discard every queued event. Happens automatically on the offline
    /// transition; call it yourself to drop stale events on a deliberate
    /// reconnect.
    pub fn clear_events(&mut self) {
        unsafe { sys::osdp_pd_clear_events(&mut *self.inner) };
    }

    // ---- Miscellaneous command hooks ----------------------------------

    /// Bind the `osdp_ABORT` hook. The library has already torn down any
    /// in-flight file transfer and multi-part reassembly before this runs;
    /// the hook is for application-side work the core cannot know about.
    ///
    /// Return `Ok(())` to ACK. Any error produces `osdp_NAK 0x03`, the spec's
    /// "PD unable to abort" case. **With no hook the PD ACKs**, so bind one
    /// only if aborting can actually fail.
    pub fn set_abort_handler<F: FnMut() -> Result<()> + 'static>(&mut self, handler: F) {
        let boxed: Box<AbortHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;
        unsafe {
            sys::osdp_pd_set_abort_handler(&mut *self.inner, Some(abort_thunk), user_ptr);
        }
        self.abort_handler = Some(unsafe { Box::from_raw(user_ptr as *mut AbortHandlerBox) });
    }

    /// Bind the `osdp_ACURXSIZE` notification. This is a notification, **not
    /// a veto** — the library stores the value and ACKs either way. Refusing
    /// to believe the ACU about the size of its own buffer would only produce
    /// replies it drops.
    pub fn set_acurxsize_handler<F: FnMut(u16) + 'static>(&mut self, handler: F) {
        let boxed: Box<AcuRxSizeHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;
        unsafe {
            sys::osdp_pd_set_acurxsize_handler(&mut *self.inner, Some(acurxsize_thunk), user_ptr);
        }
        self.acurxsize_handler =
            Some(unsafe { Box::from_raw(user_ptr as *mut AcuRxSizeHandlerBox) });
    }

    /// The largest reply the ACU has said it can receive, or
    /// [`DEFAULT_ACU_RX_SIZE`] if it has not said.
    ///
    /// **This is the peer's limit.** Combine it with
    /// [`max_reply_payload`](Pd::max_reply_payload), which is this PD's own,
    /// and honour whichever is smaller.
    pub fn acu_rx_size(&self) -> u16 {
        unsafe { sys::osdp_pd_acu_rx_size(&*self.inner) }
    }

    /// Bind the `osdp_KEEPACTIVE` handler — hold reader operations open for
    /// the given number of milliseconds (0 cancels a previous extension).
    ///
    /// Return `Ok(())` to ACK; any error produces `osdp_NAK 0x03`. Unlike the
    /// other hooks, **with no handler bound the PD NAKs 0x03**: holding a
    /// reader field energised is physical, so an ACK the PD cannot honour
    /// would be a lie.
    pub fn set_keepactive_handler<F: FnMut(u16) -> Result<()> + 'static>(&mut self, handler: F) {
        let boxed: Box<KeepActiveHandlerBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;
        unsafe {
            sys::osdp_pd_set_keepactive_handler(&mut *self.inner, Some(keepactive_thunk), user_ptr);
        }
        self.keepactive_handler =
            Some(unsafe { Box::from_raw(user_ptr as *mut KeepActiveHandlerBox) });
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

// The four status thunks share one `user` pointer — the boxed
// `StatusProviders` — and each reaches for its own member. A thunk is only
// ever installed alongside a `Some` member (see `set_status_providers`), so
// the `else` arms are unreachable in practice; they answer defensively
// rather than unwrapping.

unsafe extern "C" fn status_local_thunk(user: *mut c_void, tamper: *mut u8, power: *mut u8) {
    if user.is_null() {
        return;
    }
    let providers = &mut *(user as *mut StatusProviders);
    let (t, p) = match providers.local.as_mut() {
        Some(f) => f(),
        None => (0, 0),
    };
    if !tamper.is_null() {
        *tamper = t;
    }
    if !power.is_null() {
        *power = p;
    }
}

/// Shared body for the three array-valued providers. `cap` is the C side's
/// scratch capacity; the closure's return is clamped to it, so a provider
/// that over-reports is truncated rather than trusted to write in bounds.
unsafe fn status_array_thunk(
    provider: Option<&mut StatusArrayFn>,
    out: *mut u8,
    cap: usize,
) -> usize {
    let (Some(f), false) = (provider, out.is_null()) else {
        return 0;
    };
    let slice = slice::from_raw_parts_mut(out, cap);
    f(slice).min(cap)
}

unsafe extern "C" fn status_inputs_thunk(user: *mut c_void, out: *mut u8, cap: usize) -> usize {
    if user.is_null() {
        return 0;
    }
    let providers = &mut *(user as *mut StatusProviders);
    status_array_thunk(providers.inputs.as_mut(), out, cap)
}

unsafe extern "C" fn status_outputs_thunk(user: *mut c_void, out: *mut u8, cap: usize) -> usize {
    if user.is_null() {
        return 0;
    }
    let providers = &mut *(user as *mut StatusProviders);
    status_array_thunk(providers.outputs.as_mut(), out, cap)
}

unsafe extern "C" fn status_readers_thunk(user: *mut c_void, out: *mut u8, cap: usize) -> usize {
    if user.is_null() {
        return 0;
    }
    let providers = &mut *(user as *mut StatusProviders);
    status_array_thunk(providers.readers.as_mut(), out, cap)
}

unsafe extern "C" fn mfg_receiver_thunk(
    user: *mut c_void,
    vendor_code: *const u8,
    data: *const u8,
    data_len: usize,
    reply: *mut sys::osdp_pd_reply_t,
) -> sys::osdp_status_t {
    if user.is_null() || vendor_code.is_null() {
        return sys::osdp_status_t::OSDP_ERR_INVALID_ARG;
    }
    let storage = &mut *(user as *mut MfgReceiverBox);

    let vendor: [u8; 3] = [*vendor_code, *vendor_code.add(1), *vendor_code.add(2)];
    let data_slice = if data_len == 0 || data.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(data, data_len)
    };

    match storage.on_message(&vendor, data_slice) {
        // The C side pre-fills *reply as an ACK before calling us, so
        // `Ok(None)` means "leave it alone" rather than "send nothing".
        Ok(None) => sys::osdp_status_t::OSDP_OK,
        Ok(Some(reply_value)) => {
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

unsafe extern "C" fn abort_thunk(user: *mut c_void) -> sys::osdp_status_t {
    if user.is_null() {
        return sys::osdp_status_t::OSDP_OK;
    }
    let storage = &mut *(user as *mut AbortHandlerBox);
    match storage() {
        Ok(()) => sys::osdp_status_t::OSDP_OK,
        Err(e) => e.to_status(),
    }
}

unsafe extern "C" fn acurxsize_thunk(user: *mut c_void, max_size: u16) {
    if user.is_null() {
        return;
    }
    let storage = &mut *(user as *mut AcuRxSizeHandlerBox);
    storage(max_size);
}

unsafe extern "C" fn keepactive_thunk(user: *mut c_void, time_ms: u16) -> sys::osdp_status_t {
    if user.is_null() {
        return sys::osdp_status_t::OSDP_ERR_NOT_SUPPORTED;
    }
    let storage = &mut *(user as *mut KeepActiveHandlerBox);
    match storage(time_ms) {
        Ok(()) => sys::osdp_status_t::OSDP_OK,
        Err(e) => e.to_status(),
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
            // And the status providers (NULL vtable detaches all four).
            sys::osdp_pd_set_status_provider(&mut *self.inner, ptr::null(), ptr::null_mut());
            // And the multi-part MFG receiver — like the file receiver, this
            // also clears the C-side reassembly pointer before the backing
            // Vec is dropped.
            sys::osdp_pd_set_mfg_receiver(
                &mut *self.inner,
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            );
            // And the event queue, whose buffer is likewise ours to free.
            sys::osdp_pd_set_event_queue(&mut *self.inner, ptr::null_mut(), 0);
            // And the three miscellaneous command hooks.
            sys::osdp_pd_set_abort_handler(&mut *self.inner, None, ptr::null_mut());
            sys::osdp_pd_set_acurxsize_handler(&mut *self.inner, None, ptr::null_mut());
            sys::osdp_pd_set_keepactive_handler(&mut *self.inner, None, ptr::null_mut());
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
