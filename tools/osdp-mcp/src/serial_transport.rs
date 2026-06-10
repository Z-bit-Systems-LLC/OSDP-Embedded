// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Serial-port adapter implementing the [`osdp_embedded::Transport`]
//! trait the PD state machine drives.
//!
//! Lives on the PD actor thread (the PD itself is `!Send`); the
//! actor's tick loop calls `read()` / `write()` once per cycle and
//! `now_ms()` whenever the state machine needs a timestamp.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use osdp_embedded::Transport;
use serialport::SerialPort;

use crate::wire::{WireDir, WireTrace};

/// Single PD-side serial wire. Reads are non-blocking (zero timeout);
/// writes attempt to send the whole buffer, returning the actual
/// bytes accepted by the OS. Both swallow I/O errors and return 0 —
/// the OSDP state machine treats a "no bytes available" the same as
/// "no bytes available, no error," so smoothing over transient
/// `WouldBlock` etc. is the safe behavior.
///
/// Every non-empty read and every write is mirrored into a shared
/// [`WireTrace`] (raw bytes + microsecond timestamp) so the
/// `get_wire_trace` tool can reconstruct exact on-wire timing and
/// framing — see [`crate::wire`].
pub struct SerialTransport {
    port: Box<dyn SerialPort>,
    epoch: Instant,
    wire: Arc<WireTrace>,
    /// Line rate, kept so `write` can derive the spec-5.7 ¶1 idle
    /// guard (2 character-times) from it.
    baud: u32,
}

impl SerialTransport {
    /// Open `port_name` at `baud` with 8N1 framing, mirroring all I/O
    /// into `wire`. Returns an `anyhow::Error` wrapping
    /// `serialport::Error` on failure so the MCP tool can surface a
    /// useful message to the agent.
    pub fn open(port_name: &str, baud: u32, wire: Arc<WireTrace>) -> anyhow::Result<Self> {
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
            wire,
            baud,
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
        let n = self.port.read(buf).unwrap_or_default();
        // Mirror inbound bytes (timestamped) so the wire trace shows
        // byte-arrival pacing — a frame trickles in across ticks, each
        // a separate rx chunk.
        self.wire.record(WireDir::Rx, &buf[..n]);
        n
    }

    fn write(&mut self, buf: &[u8]) -> usize {
        // Spec 5.7 ¶1: guarantee >= 2 character-times of idle before
        // accessing the channel so the ACU's RS-485 signal converter /
        // multiplexer senses the line idle and is ready to receive
        // before our first byte (the frame builder supplies the ¶2
        // marking byte). Without this the PD answers within
        // microseconds of the command's last byte and the converter
        // misses the reply — the "firstByte timeout, bytes tossed" the
        // z9 ACU logs. 2 chars = 20 bit-times: ~2.1 ms at 9600 baud,
        // far under the 200 ms REPLY_DELAY ceiling.
        let idle = Duration::from_micros(20_000_000 / u64::from(self.baud.max(1)));
        std::thread::sleep(idle);

        // Stamp the outbound frame the instant we begin transmitting
        // (after the idle guard), before the send loop + flush — the
        // timestamp to compare against the preceding rx for reply
        // latency. Carries the whole frame the PD built (including the
        // leading 0xFF marking byte), regardless of how many write()
        // calls the OS needs.
        self.wire.record(WireDir::Tx, buf);

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
