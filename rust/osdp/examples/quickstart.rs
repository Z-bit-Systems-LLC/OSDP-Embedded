// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! The code samples from the crate README, as compiled code.
//!
//! `rust/osdp/README.md` is the crates.io front page, so its samples are the
//! first code most Rust users read. This example exists so they cannot
//! silently rot: each function below holds one README snippet verbatim
//! (between the `README:` markers), and CI compiles every example, so a
//! breaking API change fails the build instead of shipping a broken README.
//!
//! The stubs at the bottom stand in for the hardware the snippets refer to
//! (`uart_read`, `aes128_ecb_encrypt`, ...). Running this does nothing
//! useful beyond proving the pieces wire together — see `loopback.rs` for a
//! working PD↔ACU exchange.

#![allow(dead_code)]

use osdp_embedded::acu::Acu;
use osdp_embedded::pd::Pd;

// ---- README: Quick Start ---------------------------------------------

use osdp_embedded::messages::{OSDP_CMD_POLL, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, Reply};
use osdp_embedded::{Error, Result, Transport};

/// Your UART. `read` returns what is available now (0 is fine) and must not block.
struct Uart;

impl Transport for Uart {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        uart_read(buf)
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        uart_write(buf)
    }
    fn now_ms(&mut self) -> Option<u32> {
        Some(millis())
    }
}

/// Your device logic. The PD has already validated the frame, filtered on
/// address, and decrypted the payload if Secure Channel is running.
struct Reader;

impl CommandHandler for Reader {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> Result<Reply<'a>> {
        match cmd_code {
            OSDP_CMD_POLL => Ok(Reply {
                code: OSDP_REPLY_ACK,
                payload: &[],
            }),
            _ => Err(Error::NotSupported), // the PD sends NAK 0x03
        }
    }
}

fn quick_start() -> ! {
    let mut pd = Pd::new(0x00); // 7-bit PD address
    pd.set_transport(Uart);
    pd.set_command_handler(Reader);

    loop {
        pd.tick(); // never blocks: reads what's there, replies, returns
    }
}

// ---- README: Reporting a card read -----------------------------------

use osdp_embedded::messages::{Raw, OSDP_REPLY_RAW};

fn card_read(pd: &mut Pd, card_bits: [u8; 4]) -> Result<()> {
    pd.set_event_queue(256); // bytes; budget roughly payload + 3 per event

    // ... later, from your card front-end:
    let raw = Raw {
        reader_no: 0,
        format_code: 1, // spec Table 33: 1 = Wiegand
        bit_count: 26,
        bit_data: &card_bits, // (bit_count + 7) / 8 bytes
    };
    let mut buf = [0u8; 64];
    let len = raw.build(&mut buf)?;
    pd.enqueue_event(OSDP_REPLY_RAW, &buf[..len])?; // Err(BufferTooSmall) when full
    Ok(())
}

// ---- README: Enabling Secure Channel ---------------------------------

use osdp_embedded::sc::{ScCrypto, AES_BLOCK_LEN, AES_KEY_LEN};

struct Crypto;

impl ScCrypto for Crypto {
    fn aes_encrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()> {
        aes128_ecb_encrypt(key, in_, out);
        Ok(())
    }
    fn aes_decrypt(
        &mut self,
        key: &[u8; AES_KEY_LEN],
        in_: &[u8; AES_BLOCK_LEN],
        out: &mut [u8; AES_BLOCK_LEN],
    ) -> Result<()> {
        aes128_ecb_decrypt(key, in_, out);
        Ok(())
    }
    fn rand_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        fill_from_trng(out); // must be a CSPRNG in production
        Ok(())
    }
}

fn secure_channel(pd: &mut Pd, installation_key: [u8; 16]) {
    pd.set_sc_crypto(Crypto);
    pd.set_sc_scbk(&installation_key); // 16 bytes from secure storage

    // Mentioned in the notes under the snippet:
    pd.set_sc_scbk_d(osdp_embedded::sc::scbk_default());
    let _ = pd.sc_established();
}

// ---- README: Observing what the reader is showing --------------------

use osdp_embedded::pd::{LedColor, LedHandler};

struct Leds;

impl LedHandler for Leds {
    fn on_led_change(&mut self, _reader_no: u8, led_no: u8, color: LedColor) {
        set_rgb(led_no, color); // LedColor::Red, Green, Amber, ...
    }
}

fn led_observer(pd: &mut Pd) {
    pd.set_led_handler(Leds);
}

// ---- README: Answering status commands -------------------------------

use osdp_embedded::messages::{OSDP_LSTATR_NORMAL, OSDP_LSTATR_TAMPER};
use osdp_embedded::pd::StatusProviders;

fn status(pd: &mut Pd) {
    pd.set_status_providers(
        StatusProviders::new()
            .local(|| {
                let tamper = if tamper_open() {
                    OSDP_LSTATR_TAMPER
                } else {
                    OSDP_LSTATR_NORMAL
                };
                (tamper, OSDP_LSTATR_NORMAL) // (tamper, power)
            })
            .inputs(|out| {
                out[0] = door_contact_active() as u8;
                1 // number of inputs reported
            }),
    );
}

// ---- README: Driving PDs from an ACU ---------------------------------

use osdp_embedded::acu::{ReplyEvent, ReplyHandler};

struct Replies;

impl ReplyHandler for Replies {
    fn on_reply(&mut self, event: &ReplyEvent<'_>) {
        // event.pd_address, event.reply_code, event.payload (copy out to keep it)
        let _ = event;
    }
}

fn acu() -> Result<()> {
    let mut acu = Acu::new(4); // slots for up to four PDs
    acu.set_transport(Uart);
    acu.set_reply_handler(Replies);
    acu.register_pd(0, 0x00)?; // slot 0 <- PD address 0

    loop {
        if !acu.is_pd_busy(0x00) {
            acu.send_command(0x00, OSDP_CMD_POLL, &[])?;
        }
        acu.tick();
    }
}

// ---- Stubs for the hardware the snippets refer to --------------------

fn uart_read(_buf: &mut [u8]) -> usize {
    0
}
fn uart_write(buf: &[u8]) -> usize {
    buf.len()
}
fn millis() -> u32 {
    0
}
fn aes128_ecb_encrypt(
    _k: &[u8; AES_KEY_LEN],
    i: &[u8; AES_BLOCK_LEN],
    o: &mut [u8; AES_BLOCK_LEN],
) {
    *o = *i;
}
fn aes128_ecb_decrypt(
    _k: &[u8; AES_KEY_LEN],
    i: &[u8; AES_BLOCK_LEN],
    o: &mut [u8; AES_BLOCK_LEN],
) {
    *o = *i;
}
fn fill_from_trng(out: &mut [u8]) {
    out.fill(0);
}
fn set_rgb(_led_no: u8, _color: LedColor) {}
fn tamper_open() -> bool {
    false
}
fn door_contact_active() -> bool {
    false
}

fn main() {
    // Exercise the non-looping snippets once; the looping ones only need to compile.
    let mut pd = Pd::new(0x00);
    pd.set_transport(Uart);
    pd.set_command_handler(Reader);
    card_read(&mut pd, [0; 4]).expect("card read snippet");
    secure_channel(&mut pd, [0x42; 16]);
    led_observer(&mut pd);
    status(&mut pd);
    pd.tick();

    println!("README snippets compiled and a PD ticked once. See loopback.rs for a real exchange.");
}
