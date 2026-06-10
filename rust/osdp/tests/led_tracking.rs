// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Reader-LED tracking through the safe wrapper.
//!
//! Drives a real [`Pd`] and [`Acu`] over an in-process wire with a
//! controllable clock, sends an `osdp_LED` command from the ACU, and
//! checks that the PD's `set_led_handler` callback fires and
//! `led_color()` resolves the right colour — including a temporary
//! override expiring back to the permanent colour purely from the clock.
//! This is the Rust-side counterpart of the C `tests/test_loopback.c`
//! LED cases.

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::acu::Acu;
use osdp_embedded::messages::{BuzCmd, Led, LedRecord, OSDP_CMD_BUZ, OSDP_CMD_LED, OSDP_REPLY_ACK};
use osdp_embedded::pd::{BuzzerHandler, CommandHandler, LedColor, LedHandler, Pd, Reply};
use osdp_embedded::Transport;

#[derive(Default)]
struct Wire {
    a2p: Vec<u8>,
    p2a: Vec<u8>,
    now_ms: u32,
}
type SharedWire = Rc<RefCell<Wire>>;

struct WireAdapter<const PD: bool> {
    wire: SharedWire,
}

impl<const PD: bool> Transport for WireAdapter<PD> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let src = if PD { &mut w.a2p } else { &mut w.p2a };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        src.drain(..n);
        n
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let dst = if PD { &mut w.p2a } else { &mut w.a2p };
        dst.extend_from_slice(buf);
        buf.len()
    }
    fn now_ms(&mut self) -> Option<u32> {
        Some(self.wire.borrow().now_ms)
    }
}

/// PD that ACKs POLL and LED (a real reader ACKs LED control); the PD
/// tracks the resulting colour transparently regardless of the reply.
struct AckHandler;
impl CommandHandler for AckHandler {
    fn handle<'a>(
        &'a mut self,
        _cmd_code: u8,
        _payload: &[u8],
    ) -> osdp_embedded::Result<Reply<'a>> {
        Ok(Reply {
            code: OSDP_REPLY_ACK,
            payload: &[],
        })
    }
}

/// Records every LED change the PD reports.
#[derive(Default)]
struct LedLog {
    events: Vec<(u8, u8, LedColor)>,
}
struct LedCapture {
    inner: Rc<RefCell<LedLog>>,
}
impl LedHandler for LedCapture {
    fn on_led_change(&mut self, reader_no: u8, led_no: u8, color: LedColor) {
        self.inner
            .borrow_mut()
            .events
            .push((reader_no, led_no, color));
    }
}

/// Records every buzzer sounding-change the PD reports.
#[derive(Default)]
struct BuzLog {
    events: Vec<(u8, bool, u8)>, // (reader_no, sounding, tone)
}
struct BuzCapture {
    inner: Rc<RefCell<BuzLog>>,
}
impl BuzzerHandler for BuzCapture {
    fn on_buzzer_change(&mut self, reader_no: u8, sounding: bool, tone: u8) {
        self.inner
            .borrow_mut()
            .events
            .push((reader_no, sounding, tone));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

/// Build the payload of an `osdp_LED` command carrying one record.
fn led_payload(rec: LedRecord) -> Vec<u8> {
    let led = Led { records: vec![rec] };
    let mut buf = [0u8; 32];
    let n = led.build(&mut buf).expect("LED build");
    buf[..n].to_vec()
}

struct Rig {
    wire: SharedWire,
    pd: Pd,
    acu: Acu,
    led_log: Rc<RefCell<LedLog>>,
    buz_log: Rc<RefCell<BuzLog>>,
}

fn rig() -> Rig {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let led_log = Rc::new(RefCell::new(LedLog::default()));
    let buz_log = Rc::new(RefCell::new(BuzLog::default()));

    let mut pd = Pd::new(0x10);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_command_handler(AckHandler);
    pd.set_led_handler(LedCapture {
        inner: Rc::clone(&led_log),
    });
    pd.set_buzzer_handler(BuzCapture {
        inner: Rc::clone(&buz_log),
    });

    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.register_pd(0, 0x10).expect("register_pd");

    Rig {
        wire,
        pd,
        acu,
        led_log,
        buz_log,
    }
}

#[test]
fn steady_led_command_tracked_via_callback_and_query() {
    let mut r = rig();

    // Steady-green permanent LED on reader 0, LED 0.
    let rec = LedRecord {
        reader_no: 0,
        led_no: 0,
        temp_control_code: 0, // NOP
        perm_control_code: 1, // SET
        perm_on_color: LedColor::Green.as_u8(),
        perm_off_color: LedColor::Green.as_u8(),
        ..Default::default()
    };
    let payload = led_payload(rec);
    r.acu
        .send_command(0x10, OSDP_CMD_LED, &payload)
        .expect("send LED");
    cycle(&mut r.pd, &mut r.acu, 4);

    // Query resolves green.
    assert_eq!(r.pd.led_color(0, 0), LedColor::Green);
    // An untouched LED is black.
    assert_eq!(r.pd.led_color(0, 1), LedColor::Black);
    // The callback fired exactly once, reporting green on (0, 0).
    let log = r.led_log.borrow();
    assert_eq!(log.events, vec![(0u8, 0u8, LedColor::Green)]);
}

#[test]
fn temporary_led_timer_expires_to_permanent() {
    let mut r = rig();
    r.wire.borrow_mut().now_ms = 1000;

    // Steady-red permanent + a 1 s steady-green temporary.
    let rec = LedRecord {
        reader_no: 0,
        led_no: 0,
        perm_control_code: 1, // SET
        perm_on_color: LedColor::Red.as_u8(),
        perm_off_color: LedColor::Red.as_u8(),
        temp_control_code: 2, // SET
        temp_on_color: LedColor::Green.as_u8(),
        temp_off_color: LedColor::Green.as_u8(),
        temp_timer_100ms: 10, // 10 × 100 ms = 1 s
        ..Default::default()
    };
    let payload = led_payload(rec);
    r.acu
        .send_command(0x10, OSDP_CMD_LED, &payload)
        .expect("send LED");
    cycle(&mut r.pd, &mut r.acu, 4);

    // Timer running → green.
    assert_eq!(r.pd.led_color(0, 0), LedColor::Green);
    assert_eq!(
        r.led_log.borrow().events.last().copied(),
        Some((0u8, 0u8, LedColor::Green))
    );

    // Advance the clock past the 1 s timer; ticking re-resolves the bank
    // to the permanent red, with no new command sent.
    r.wire.borrow_mut().now_ms = 2500;
    cycle(&mut r.pd, &mut r.acu, 2);

    assert_eq!(r.pd.led_color(0, 0), LedColor::Red);
    assert_eq!(
        r.led_log.borrow().events.last().copied(),
        Some((0u8, 0u8, LedColor::Red))
    );
}

#[test]
fn buzzer_command_drives_sounding_then_silence() {
    let mut r = rig();
    r.wire.borrow_mut().now_ms = 1000;

    // One beep: 100 ms on, 100 ms off, count 1 (total 200 ms).
    let buz = BuzCmd {
        reader_no: 0,
        tone_code: 0x02, // default tone
        on_time_100ms: 1,
        off_time_100ms: 1,
        count: 1,
    };
    let mut buf = [0u8; 8];
    let n = buz.build(&mut buf).expect("BUZ build");
    r.acu
        .send_command(0x10, OSDP_CMD_BUZ, &buf[..n])
        .expect("send BUZ");
    cycle(&mut r.pd, &mut r.acu, 4);

    // Beep is sounding; callback reported sounding=true with the tone.
    assert!(r.pd.buzzer_sounding(0));
    assert_eq!(
        r.buz_log.borrow().events.last().copied(),
        Some((0u8, true, 0x02u8))
    );

    // Advance into the off gap — falls silent purely from the clock.
    r.wire.borrow_mut().now_ms = 1150;
    cycle(&mut r.pd, &mut r.acu, 2);

    assert!(!r.pd.buzzer_sounding(0));
    assert_eq!(
        r.buz_log.borrow().events.last().copied(),
        Some((0u8, false, 0x02u8))
    );
}
