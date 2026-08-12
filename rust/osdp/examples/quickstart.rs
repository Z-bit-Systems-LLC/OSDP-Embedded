// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! The Quick Start from the project README, as compiled code.
//!
//! The README is the crates.io front page, so its first code sample is the
//! first thing most people read. This example exists so that sample cannot
//! silently rot: `pd_quickstart` below is the README snippet verbatim, and
//! CI compiles every example, so a breaking API change fails the build
//! instead of shipping a broken README.
//!
//! Running it does nothing useful — a real PD needs a real serial port. See
//! `loopback.rs` for a working PD↔ACU exchange, and `tools/osdp-pd-mock` for
//! a PD on an actual port.

use osdp_embedded::Transport;

/// Stand-in for the reader's UART so the snippet has something to bind.
struct NullUart;

impl Transport for NullUart {
    fn read(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        buf.len()
    }
    fn now_ms(&mut self) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------
// Everything below matches the README's "The same PD in Rust" snippet.
// Keep the two in sync — that is the whole point of this file.
// ---------------------------------------------------------------------

use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, Pd, Reply};
use osdp_embedded::{Error, Result};

struct Reader;

impl CommandHandler for Reader {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(Error::NotSupported), // the library sends NAK 0x03
        }
    }
}

/// Not called: a PD main loop never returns, which would make this example
/// hang if it ran. Compiling it is what we are after.
#[allow(dead_code)]
fn pd_quickstart(my_uart: NullUart) -> ! {
    let mut pd = Pd::new(0x00);
    pd.set_transport(my_uart); // any type implementing osdp_embedded::Transport
    pd.set_command_handler(Reader);

    loop {
        pd.tick();
    }
}

fn main() {
    // Prove the pieces actually wire together, without entering the loop.
    let mut pd = Pd::new(0x00);
    pd.set_transport(NullUart);
    pd.set_command_handler(Reader);
    pd.tick();

    println!("Quick Start compiled and a PD ticked once. See loopback.rs for a real exchange.");
}
