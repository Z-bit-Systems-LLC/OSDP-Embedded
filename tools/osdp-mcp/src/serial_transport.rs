// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Serial-port adapter implementing the [`osdp_embedded::Transport`]
//! trait the PD state machine drives.
//!
//! Lives on the PD actor thread (the PD itself is `!Send`); the
//! actor's tick loop calls `read()` / `write()` once per cycle and
//! `now_ms()` whenever the state machine needs a timestamp.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use osdp_embedded::Transport;
use serialport::SerialPort;

use crate::wire::{WireDir, WireTrace};

/// Latched health of a serial wire. A read/write that hits a *fatal*
/// I/O error (device unplugged, tty re-enumerated on a re-plug or a
/// USB-adapter / RP1-UART glitch) sets `failed`; the actor tick loop
/// polls it and, once tripped, tears the PD down and reopens the port
/// so the link recovers on its own. Without this the transport would
/// keep swallowing the error as "no bytes" forever and the PD would sit
/// silently offline until the process was manually restarted.
///
/// One-way latch: a rebuilt PD opens a fresh port with a fresh
/// `SerialHealth`, so there is no need to clear it in place.
#[derive(Debug, Default)]
pub struct SerialHealth {
    failed: AtomicBool,
}

impl SerialHealth {
    /// True until a fatal I/O error has been observed on the port.
    pub fn is_healthy(&self) -> bool {
        !self.failed.load(Ordering::Relaxed)
    }

    /// True once the port has hit a fatal I/O error.
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// Latch the port as failed. Idempotent.
    pub fn mark_failed(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }
}

/// True when a serial I/O error means the port itself is gone or broken
/// (device unplugged, tty node destroyed/re-enumerated) rather than the
/// benign "no data available right now" a healthy zero-timeout port
/// produces on every idle poll. Benign kinds must never latch the port
/// as failed — otherwise an idle bus (ACU not polling) would trip a
/// needless reconnect.
fn is_fatal_serial_error(err: &std::io::Error) -> bool {
    !matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// Turn a `read()` result into a byte count, latching `health` on a
/// fatal error. Extracted from [`SerialTransport::read`] so the
/// error-classification logic is unit-testable without a real port.
fn account_read(res: std::io::Result<usize>, health: &SerialHealth) -> usize {
    match res {
        Ok(n) => n,
        Err(e) => {
            if is_fatal_serial_error(&e) {
                health.mark_failed();
            }
            0
        }
    }
}

/// One step of the `write()` drain loop. `Sent(n)` advances by `n`
/// bytes; `Retry` re-attempts (transient `WouldBlock`/`TimedOut`/
/// `Interrupted`, e.g. a full kernel TX buffer); `Stop` ends the loop
/// (a zero-length accept, or a fatal error which also latches
/// `health`). Extracted so the classification is testable without a
/// real port.
#[derive(Debug, PartialEq, Eq)]
enum WriteStep {
    Sent(usize),
    Retry,
    Stop,
}

fn classify_write(res: std::io::Result<usize>, health: &SerialHealth) -> WriteStep {
    match res {
        Ok(0) => WriteStep::Stop,
        Ok(n) => WriteStep::Sent(n),
        Err(ref e) if !is_fatal_serial_error(e) => WriteStep::Retry,
        Err(_) => {
            health.mark_failed();
            WriteStep::Stop
        }
    }
}

/// Single PD-side serial wire. Reads are non-blocking (zero timeout);
/// writes attempt to send the whole buffer, returning the actual
/// bytes accepted by the OS. Benign I/O errors (`WouldBlock` etc.) are
/// swallowed and return 0 — the OSDP state machine treats a "no bytes
/// available" the same as "no bytes available, no error." A *fatal*
/// I/O error (the device went away) instead latches [`SerialHealth`],
/// which the actor uses to trigger a reconnect.
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
    /// Latched on a fatal I/O error. Shared with the actor via
    /// [`SerialTransport::health`] so the tick loop can detect a dead
    /// port and reopen it.
    health: Arc<SerialHealth>,
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
            health: Arc::new(SerialHealth::default()),
        })
    }

    /// A handle to this port's health latch. The actor keeps a clone so
    /// it can detect a fatal I/O error after the transport has been
    /// moved into the (`!Send`) PD.
    pub fn health(&self) -> Arc<SerialHealth> {
        Arc::clone(&self.health)
    }
}

impl Transport for SerialTransport {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        // A zero-timeout read returns immediately. A benign error
        // (`WouldBlock`, `TimedOut`) → 0 bytes and the PD tick loop
        // retries next iteration. A *fatal* error (the device is gone)
        // latches `health` so the actor can reopen the port — see
        // `account_read`.
        let n = account_read(self.port.read(buf), &self.health);
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
            match classify_write(self.port.write(&buf[sent..]), &self.health) {
                WriteStep::Sent(n) => sent += n,
                WriteStep::Retry => continue,
                WriteStep::Stop => break,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn health_latch_starts_healthy_and_is_one_way() {
        let h = SerialHealth::default();
        assert!(h.is_healthy());
        assert!(!h.is_failed());
        h.mark_failed();
        assert!(!h.is_healthy());
        assert!(h.is_failed());
        // Idempotent — a second mark keeps it failed.
        h.mark_failed();
        assert!(h.is_failed());
    }

    #[test]
    fn benign_read_errors_do_not_latch_failure() {
        // The kinds a healthy zero-timeout serial port produces on an
        // idle bus must never be treated as fatal.
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
        ] {
            let h = SerialHealth::default();
            let n = account_read(Err(Error::from(kind)), &h);
            assert_eq!(n, 0, "{kind:?} should read 0 bytes");
            assert!(h.is_healthy(), "{kind:?} must not latch failure");
        }
    }

    #[test]
    fn fatal_read_error_latches_failure() {
        // A device that went away surfaces as one of these (ENODEV /
        // ENXIO / EIO / broken pipe, depending on platform + stage).
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::BrokenPipe,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            let h = SerialHealth::default();
            let n = account_read(Err(Error::from(kind)), &h);
            assert_eq!(n, 0);
            assert!(h.is_failed(), "{kind:?} should latch the port as failed");
        }
    }

    #[test]
    fn successful_read_reports_bytes_and_stays_healthy() {
        let h = SerialHealth::default();
        assert_eq!(account_read(Ok(7), &h), 7);
        assert!(h.is_healthy());
    }

    #[test]
    fn write_classification_covers_all_paths() {
        let h = SerialHealth::default();
        assert_eq!(classify_write(Ok(5), &h), WriteStep::Sent(5));
        assert_eq!(classify_write(Ok(0), &h), WriteStep::Stop);
        assert!(h.is_healthy(), "an Ok(0)/Ok(n) must not latch failure");

        // Full TX buffer / interrupted syscall → retry, still healthy.
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
        ] {
            assert_eq!(classify_write(Err(Error::from(kind)), &h), WriteStep::Retry);
        }
        assert!(h.is_healthy());

        // A fatal write error stops the loop and latches failure.
        assert_eq!(
            classify_write(Err(Error::from(ErrorKind::BrokenPipe)), &h),
            WriteStep::Stop
        );
        assert!(h.is_failed());
    }
}
