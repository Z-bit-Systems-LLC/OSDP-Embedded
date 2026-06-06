// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Serial-port adapter implementing the [`osdp_embedded::Transport`]
//! trait the PD state machine drives.
//!
//! Lives on the PD actor thread (the PD itself is `!Send`); the
//! actor's tick loop calls `read()` / `write()` once per cycle and
//! `now_ms()` whenever the state machine needs a timestamp.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use osdp_embedded::Transport;
use serialport::SerialPort;

/// Single PD-side serial wire. Reads are non-blocking (zero timeout);
/// writes attempt to send the whole buffer, returning the actual
/// bytes accepted by the OS. Both swallow I/O errors and return 0 —
/// the OSDP state machine treats a "no bytes available" the same as
/// "no bytes available, no error," so smoothing over transient
/// `WouldBlock` etc. is the safe behavior.
pub struct SerialTransport {
    port: Box<dyn SerialPort>,
    epoch: Instant,
}

impl SerialTransport {
    /// Open `port_name` at `baud` with 8N1 framing. Returns an
    /// `anyhow::Error` wrapping `serialport::Error` on failure so the
    /// MCP tool can surface a useful message to the agent.
    pub fn open(port_name: &str, baud: u32) -> anyhow::Result<Self> {
        let port = serialport::new(port_name, baud)
            .timeout(Duration::from_millis(0))
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .open()?;
        Ok(Self {
            port,
            epoch: Instant::now(),
        })
    }
}

impl Transport for SerialTransport {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        // A zero-timeout read returns immediately. Any I/O error
        // (`WouldBlock`, `TimedOut`, real errors) → 0 bytes; the PD
        // tick loop will retry next iteration. Real serial errors
        // would also surface in `write` and any subsequent open
        // failure on reconnect, so dropping them here is fine.
        self.port.read(buf).unwrap_or_default()
    }

    fn write(&mut self, buf: &[u8]) -> usize {
        // Push the whole frame out. A single `port.write` may accept fewer
        // bytes than offered (non-blocking port, full kernel TX buffer),
        // and the OSDP state machine ignores the returned count — so a
        // short write would silently truncate a reply (e.g. dropping the
        // trailing integrity byte). Loop until the buffer drains, retrying
        // transient `WouldBlock`/`Interrupted`. The retry budget is bounded
        // so a wedged port can't spin the actor thread forever; it is far
        // larger than any OSDP-sized frame needs at real baud rates.
        let mut sent = 0;
        let mut budget = 10_000u32;
        while sent < buf.len() && budget > 0 {
            budget -= 1;
            match self.port.write(&buf[sent..]) {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::Interrupted
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue
                }
                Err(_) => break,
            }
        }
        // Block until the bytes are actually transmitted, so a half-duplex
        // RS-485 line isn't turned around before the last byte clears.
        let _ = self.port.flush();
        sent
    }

    fn now_ms(&mut self) -> Option<u32> {
        // 32-bit wrap is fine; OSDP only ever computes deltas.
        Some(self.epoch.elapsed().as_millis() as u32)
    }
}
