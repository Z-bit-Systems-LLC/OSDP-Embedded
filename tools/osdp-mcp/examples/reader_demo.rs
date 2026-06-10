// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Zero-setup visual demo of the reader UI — no serial port, no hardware.
//!
//! Runs a real `osdp_embedded` PD and ACU wired together through an
//! in-process loopback, has the ACU drive `osdp_LED` commands on a loop,
//! and serves the *same* browser page the live `osdp-mcp --ui-bind` would.
//! Open the printed URL and watch the reader's single status LED:
//!
//! - Idle: steady red (locked).
//! - Every ~4 s an "access granted" pulse — solid green for ~1.8 s, or a
//!   flashing-green "processing" for ~2 s on alternate cycles — then
//!   auto-reverts to red via the temporary-timer path.
//!
//! The flashing edges are resolved by the PD from a single command, so they
//! exercise the time-driven LED change callback.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p osdp-mcp --example reader_demo            # 127.0.0.1:8088
//! cargo run -p osdp-mcp --example reader_demo 127.0.0.1:9090
//! ```

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};

use osdp_embedded::acu::Acu;
use osdp_embedded::messages::{Led, LedRecord, OSDP_CMD_LED, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, LedColor, Pd, Reply};
use osdp_embedded::Transport;
use osdp_mcp::reader_state::{self, ReaderLedHandler, ReaderStateView, SharedReaderState};

const PD_ADDR: u8 = 0x10;

// ---- In-process loopback wire (shared real clock) --------------------

#[derive(Default)]
struct Wire {
    a2p: Vec<u8>,
    p2a: Vec<u8>,
}

struct WireAdapter<const PD: bool> {
    wire: Rc<RefCell<Wire>>,
    start: Instant,
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
        // Real elapsed time so the PD's flash phase / temporary timer
        // actually advance and fire the LED change callback.
        Some(self.start.elapsed().as_millis() as u32)
    }
}

/// A PD that just ACKs everything — enough for LED control. The reader
/// LED bank is maintained transparently by the PD regardless of the reply.
struct AckAll;
impl CommandHandler for AckAll {
    fn handle<'a>(&'a mut self, _code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        Ok(Reply {
            code: OSDP_REPLY_ACK,
            payload: &[],
        })
    }
}

/// Encode an `osdp_LED` command payload from a set of records.
fn led_payload(records: Vec<LedRecord>) -> Vec<u8> {
    let led = Led { records };
    let mut buf = [0u8; 128];
    let n = led.build(&mut buf).expect("LED build");
    buf[..n].to_vec()
}

/// A steady-colour permanent record for one LED.
fn steady(led_no: u8, color: LedColor) -> LedRecord {
    LedRecord {
        reader_no: 0,
        led_no,
        perm_control_code: 1, // SET
        perm_on_color: color.as_u8(),
        perm_off_color: color.as_u8(),
        ..Default::default()
    }
}

/// A temporary colour over a steady permanent, with a countdown timer.
/// `on_100ms`/`off_100ms` flash the temporary while it runs (0/0 = solid);
/// when it elapses the LED reverts to the permanent colour.
fn temporary(
    led_no: u8,
    perm: LedColor,
    temp: LedColor,
    timer_100ms: u16,
    on_100ms: u8,
    off_100ms: u8,
) -> LedRecord {
    let solid = on_100ms == 0 && off_100ms == 0;
    LedRecord {
        reader_no: 0,
        led_no,
        perm_control_code: 1, // SET (baseline)
        perm_on_color: perm.as_u8(),
        perm_off_color: perm.as_u8(),
        temp_control_code: 2, // SET (override)
        temp_on_color: temp.as_u8(),
        temp_off_color: if solid {
            temp.as_u8()
        } else {
            LedColor::Black.as_u8()
        },
        temp_on_time: on_100ms,
        temp_off_time: off_100ms,
        temp_timer_100ms: timer_100ms,
        ..Default::default()
    }
}

/// Drive the PD↔ACU loopback forever, feeding the shared reader state.
/// Runs on its own std::thread because `Pd`/`Acu` are `!Send`.
fn run_driver(reader_state: SharedReaderState) {
    let start = Instant::now();
    let wire = Rc::new(RefCell::new(Wire::default()));

    let mut pd = Pd::new(PD_ADDR);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
        start,
    });
    pd.set_command_handler(AckAll);
    pd.set_led_handler(ReaderLedHandler::new(reader_state));

    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
        start,
    });
    acu.register_pd(0, PD_ADDR).expect("register_pd");

    // Idle state: the reader's status LED sits steady red (locked).
    let _ = acu.send_command(
        PD_ADDR,
        OSDP_CMD_LED,
        &led_payload(vec![steady(0, LedColor::Red)]),
    );

    let mut last_event = Instant::now();
    let mut n: u32 = 0;

    loop {
        pd.tick();
        acu.tick();

        // The ACU allows one outstanding command at a time; only issue a
        // new one once the previous reply has landed.
        if !acu.is_pd_busy(PD_ADDR) && last_event.elapsed() >= Duration::from_secs(4) {
            // Alternate between a clean "granted" (solid green, 1.8 s) and
            // a "processing" (flashing green, ~2 s). Both ride on top of
            // the steady-red idle and auto-revert when the timer expires.
            let rec = if n % 2 == 0 {
                temporary(0, LedColor::Red, LedColor::Green, 18, 0, 0)
            } else {
                temporary(0, LedColor::Red, LedColor::Green, 20, 3, 3)
            };
            let _ = acu.send_command(PD_ADDR, OSDP_CMD_LED, &led_payload(vec![rec]));
            n += 1;
            last_event = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(8));
    }
}

// ---- UI server (reuses the osdp-mcp embedded page) -------------------

async fn index() -> Html<&'static str> {
    Html(osdp_mcp::ui::index_html())
}

async fn api_state(State(rs): State<SharedReaderState>) -> Json<ReaderStateView> {
    let view = rs
        .lock()
        .map(|s| s.snapshot())
        .unwrap_or_else(|_| ReaderStateView { leds: Vec::new() });
    Json(view)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8088".to_string())
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;

    let reader_state = reader_state::new_shared();

    // PD/ACU loopback driver on its own thread (the state machines are
    // !Send); it feeds `reader_state` through the LED change callback.
    let driver_state = Arc::clone(&reader_state);
    std::thread::spawn(move || run_driver(driver_state));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .with_state(reader_state);

    println!("reader demo: open http://{bind}/ in a browser (Ctrl-C to quit)");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
