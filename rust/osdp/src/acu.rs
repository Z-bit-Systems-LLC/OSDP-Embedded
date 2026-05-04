// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! ACU-side state machine.
//!
//! Wraps `osdp::acu`. The application supplies:
//!
//!   - a [`Transport`] (read/write/now_ms),
//!   - a [`ReplyHandler`] called when a registered PD answers,
//!   - an optional [`TimeoutHandler`] called when a PD doesn't answer
//!     within the spec-mandated 200 ms window.
//!
//! Commands are sent explicitly via [`Acu::send_command`]; the wrapper
//! does not auto-poll.
//!
//! ```no_run
//! use osdp::acu::{Acu, Transport, ReplyHandler, ReplyEvent};
//! use osdp_sys::OSDP_CMD_POLL;
//!
//! struct MyTransport;
//! impl Transport for MyTransport {
//!     fn read (&mut self, _: &mut [u8]) -> usize { 0 }
//!     fn write(&mut self, _: &[u8])     -> usize { 0 }
//!     fn now_ms(&mut self) -> Option<u32> { None }
//! }
//!
//! struct MyReplies;
//! impl ReplyHandler for MyReplies {
//!     fn on_reply(&mut self, _: &ReplyEvent<'_>) {}
//! }
//!
//! let mut acu = Acu::new(/*pd_count*/ 1);
//! acu.set_transport(MyTransport);
//! acu.set_reply_handler(MyReplies);
//! acu.register_pd(0, 0x10).unwrap();
//! acu.send_command(0x10, OSDP_CMD_POLL, &[]).unwrap();
//! acu.tick();
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use core::slice;

use osdp_sys as sys;

use crate::error::{Error, Result};
use crate::sc::{self, ScCrypto, ScEventHandler, SC_KEY_LEN};

// ---- Public traits ------------------------------------------------------

/// Wire-side I/O. Same shape as `pd::Transport`.
pub trait Transport: 'static {
    fn read (&mut self, buf: &mut [u8]) -> usize;
    fn write(&mut self, buf: &[u8])     -> usize;
    fn now_ms(&mut self) -> Option<u32>;
}

/// What the ACU passes to the application's `ReplyHandler::on_reply`.
/// Slices borrow from the ACU's RX buffer — copy out before returning
/// if you need to keep them past the callback.
pub struct ReplyEvent<'a> {
    pub pd_address: u8,
    pub cmd_code:   u8,
    pub reply_code: u8,
    pub payload:    &'a [u8],
}

pub trait ReplyHandler: 'static {
    fn on_reply(&mut self, event: &ReplyEvent<'_>);
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TimeoutEvent {
    pub pd_address: u8,
    pub cmd_code:   u8,
    pub cmd_seq:    u8,
}

pub trait TimeoutHandler: 'static {
    fn on_timeout(&mut self, event: TimeoutEvent);
}

// ---- Storage types -----------------------------------------------------

type TransportBox = Box<dyn Transport>;
type ReplyBox     = Box<dyn ReplyHandler>;
type TimeoutBox   = Box<dyn TimeoutHandler>;

/// ACU context. Owns the C state plus user-supplied trait objects.
pub struct Acu {
    inner: Box<sys::osdp_acu_t>,
    /// Heap-allocated array of slots. The C side stores a raw pointer
    /// into this slice; we keep ownership so it lives as long as
    /// `self`.
    slots: Vec<sys::osdp_acu_pd_slot_t>,

    transport:    Option<Box<TransportBox>>,
    reply_h:      Option<Box<ReplyBox>>,
    timeout_h:    Option<Box<TimeoutBox>>,
    sc_crypto:    Option<Box<sc::ScCryptoBox>>,
    sc_event_h:   Option<Box<sc::ScEventBox>>,
}

impl Acu {
    /// Create an ACU with `pd_count` slots. Each PD that the
    /// application wants to drive must be registered into a slot via
    /// [`Self::register_pd`] before its address can be used in
    /// [`Self::send_command`].
    pub fn new(pd_count: usize) -> Self {
        let mut inner = Box::<sys::osdp_acu_t>::new(unsafe { MaybeUninit::zeroed().assume_init() });
        // Allocate slot storage. Each slot is ~150 bytes. We pre-zero
        // since osdp_acu_init memsets them but we can't pass an
        // uninitialised slice through Vec without UB.
        let mut slots: Vec<sys::osdp_acu_pd_slot_t> = (0..pd_count)
            .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
            .collect();
        unsafe { sys::osdp_acu_init(&mut *inner, slots.as_mut_ptr(), pd_count) };
        Self {
            inner,
            slots,
            transport: None,
            reply_h: None,
            timeout_h: None,
            sc_crypto: None,
            sc_event_h: None,
        }
    }

    pub fn set_transport<T: Transport>(&mut self, transport: T) {
        let boxed: Box<TransportBox> = Box::new(Box::new(transport));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        let c = sys::osdp_acu_transport_t {
            read:   Some(transport_read_thunk),
            write:  Some(transport_write_thunk),
            now_ms: Some(transport_now_ms_thunk),
            user:   user_ptr,
        };
        unsafe { sys::osdp_acu_set_transport(&mut *self.inner, &c) };

        self.transport = Some(unsafe { Box::from_raw(user_ptr as *mut TransportBox) });
    }

    pub fn set_reply_handler<H: ReplyHandler>(&mut self, handler: H) {
        let boxed: Box<ReplyBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_acu_set_reply_handler(
                &mut *self.inner,
                Some(reply_thunk),
                user_ptr,
            );
        }
        self.reply_h = Some(unsafe { Box::from_raw(user_ptr as *mut ReplyBox) });
    }

    pub fn set_timeout_handler<H: TimeoutHandler>(&mut self, handler: H) {
        let boxed: Box<TimeoutBox> = Box::new(Box::new(handler));
        let user_ptr = Box::into_raw(boxed) as *mut c_void;

        unsafe {
            sys::osdp_acu_set_timeout_handler(
                &mut *self.inner,
                Some(timeout_thunk),
                user_ptr,
            );
        }
        self.timeout_h = Some(unsafe { Box::from_raw(user_ptr as *mut TimeoutBox) });
    }

    /// Bind a PD address to the slot at `slot_index`. The slot's SQN
    /// is reset to 0 (per spec the first command on a new connection
    /// uses SQN zero).
    pub fn register_pd(&mut self, slot_index: usize, pd_address: u8) -> Result<()> {
        let s = unsafe {
            sys::osdp_acu_register_pd(&mut *self.inner, slot_index, pd_address)
        };
        Error::from_status(s)
    }

    /// Send a command to a registered PD. Blocks at most as long as
    /// the transport's `write` callback does. Errors:
    ///
    ///   - `Err(InvalidArg)` — `pd_address` is not registered.
    ///   - `Err(NotSupported)` — the slot has an outstanding command
    ///     awaiting reply (one outstanding command per PD at a time).
    pub fn send_command(
        &mut self,
        pd_address: u8,
        cmd_code:   u8,
        payload:    &[u8],
    ) -> Result<()> {
        let payload_ptr = if payload.is_empty() { ptr::null() } else { payload.as_ptr() };
        let s = unsafe {
            sys::osdp_acu_send_command(
                &mut *self.inner,
                pd_address,
                cmd_code,
                payload_ptr,
                payload.len(),
            )
        };
        Error::from_status(s)
    }

    /// Pump the state machine. Idempotent and non-blocking.
    pub fn tick(&mut self) {
        unsafe { sys::osdp_acu_tick(&mut *self.inner) };
    }

    pub fn is_pd_online(&self, pd_address: u8) -> bool {
        unsafe { sys::osdp_acu_is_pd_online(&*self.inner, pd_address) }
    }

    pub fn is_pd_busy(&self, pd_address: u8) -> bool {
        unsafe { sys::osdp_acu_is_pd_busy(&*self.inner, pd_address) }
    }

    /// Number of slots this ACU was created with. Useful for callers
    /// that want to iterate over `0..pd_count` without recomputing.
    pub fn pd_count(&self) -> usize {
        self.slots.len()
    }

    // ---- Secure Channel ------------------------------------------------
    //
    // One shared crypto provider drives every PD this ACU manages — the
    // controller process has one AES implementation, even if it talks
    // to dozens of PDs. Per-PD state (SCBK, SCBK-D, session keys, MAC
    // chain) lives inside the slot the PD was registered into.

    /// Bind the crypto provider (AES + RNG) the ACU will use across
    /// every Secure Channel session it negotiates.
    pub fn set_sc_crypto<C: ScCrypto>(&mut self, crypto: C) {
        let boxed: sc::ScCryptoBox = Box::new(crypto);
        let (vtable, user) = sc::build_vtable(boxed);
        unsafe { sys::osdp_acu_set_sc_crypto(&mut *self.inner, &vtable) };
        self.sc_crypto = Some(unsafe { Box::from_raw(user as *mut sc::ScCryptoBox) });
    }

    /// Set the SCBK for the registered PD at `pd_address`. Used when
    /// `start_sc_handshake` is invoked with `use_default_key = false`.
    pub fn set_pd_scbk(&mut self, pd_address: u8, scbk: &[u8; SC_KEY_LEN]) -> Result<()> {
        let s = unsafe { sys::osdp_acu_set_pd_scbk(&mut *self.inner, pd_address, scbk.as_ptr()) };
        Error::from_status(s)
    }

    /// Set the SCBK-D for the registered PD at `pd_address`. Used
    /// when `start_sc_handshake` is invoked with `use_default_key =
    /// true`.
    pub fn set_pd_scbk_d(&mut self, pd_address: u8, scbk_d: &[u8; SC_KEY_LEN]) -> Result<()> {
        let s = unsafe { sys::osdp_acu_set_pd_scbk_d(&mut *self.inner, pd_address, scbk_d.as_ptr()) };
        Error::from_status(s)
    }

    /// Bind the SC event handler. Fires on handshake completion,
    /// cryptographic failure, or session loss. Replaces any
    /// previously-set handler.
    pub fn set_sc_event_handler<H: ScEventHandler>(&mut self, handler: H) {
        let boxed: sc::ScEventBox = Box::new(handler);
        let outer: Box<sc::ScEventBox> = Box::new(boxed);
        let user = Box::into_raw(outer) as *mut c_void;
        unsafe {
            sys::osdp_acu_set_sc_event_handler(
                &mut *self.inner,
                Some(sc::sc_event_thunk),
                user,
            );
        }
        self.sc_event_h = Some(unsafe { Box::from_raw(user as *mut sc::ScEventBox) });
    }

    /// Initiate a Secure Channel handshake with `pd_address`. Sends
    /// CHLNG immediately; subsequent ticks drive the rest of the
    /// handshake. The outcome is delivered via the SC event handler.
    ///
    /// `use_default_key = true` selects SCBK-D; `false` selects SCBK.
    /// Errors:
    ///   - `Err(InvalidArg)` — PD not registered, no crypto bound,
    ///     or no key configured for the requested mode.
    ///   - `Err(NotSupported)` — the slot has an outstanding command
    ///     (a prior reply, or another handshake already in progress).
    pub fn start_sc_handshake(&mut self, pd_address: u8, use_default_key: bool) -> Result<()> {
        let s = unsafe {
            sys::osdp_acu_start_sc_handshake(&mut *self.inner, pd_address, use_default_key)
        };
        Error::from_status(s)
    }

    /// True iff `pd_address`'s slot has a fully-established Secure
    /// Channel session (SCS_15..18 traffic permitted).
    pub fn is_pd_sc_established(&self, pd_address: u8) -> bool {
        unsafe { sys::osdp_acu_is_pd_sc_established(&*self.inner, pd_address) }
    }
}

// ---- Thunks ------------------------------------------------------------

unsafe extern "C" fn transport_read_thunk(
    user: *mut c_void, buf: *mut u8, cap: usize,
) -> c_int {
    let storage = &mut *(user as *mut TransportBox);
    let slice = slice::from_raw_parts_mut(buf, cap);
    storage.read(slice) as c_int
}

unsafe extern "C" fn transport_write_thunk(
    user: *mut c_void, buf: *const u8, len: usize,
) -> c_int {
    let storage = &mut *(user as *mut TransportBox);
    let slice = slice::from_raw_parts(buf, len);
    storage.write(slice) as c_int
}

unsafe extern "C" fn transport_now_ms_thunk(user: *mut c_void) -> u32 {
    let storage = &mut *(user as *mut TransportBox);
    storage.now_ms().unwrap_or(0)
}

unsafe extern "C" fn reply_thunk(
    user:  *mut c_void,
    event: *const sys::osdp_acu_reply_event_t,
) {
    let storage = &mut *(user as *mut ReplyBox);
    let e = &*event;
    let payload = if e.payload_len == 0 || e.payload.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(e.payload, e.payload_len)
    };
    storage.on_reply(&ReplyEvent {
        pd_address: e.pd_address,
        cmd_code:   e.cmd_code,
        reply_code: e.reply_code,
        payload,
    });
}

unsafe extern "C" fn timeout_thunk(
    user:  *mut c_void,
    event: *const sys::osdp_acu_timeout_event_t,
) {
    let storage = &mut *(user as *mut TimeoutBox);
    let e = &*event;
    storage.on_timeout(TimeoutEvent {
        pd_address: e.pd_address,
        cmd_code:   e.cmd_code,
        cmd_seq:    e.cmd_seq,
    });
}

// ---- Drop --------------------------------------------------------------

impl Drop for Acu {
    fn drop(&mut self) {
        unsafe {
            sys::osdp_acu_set_reply_handler   (&mut *self.inner, None, ptr::null_mut());
            sys::osdp_acu_set_timeout_handler (&mut *self.inner, None, ptr::null_mut());
            sys::osdp_acu_set_sc_event_handler(&mut *self.inner, None, ptr::null_mut());
            let dead = sys::osdp_acu_transport_t {
                read: None, write: None, now_ms: None, user: ptr::null_mut(),
            };
            sys::osdp_acu_set_transport(&mut *self.inner, &dead);
        }
        // Boxes dropped here. self.slots dropped here. self.inner dropped here.
    }
}

// Quiet a couple of "unused import" warnings in some configurations.
const _: fn() = || { let _: Vec<u8> = vec![]; };
