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
use std::convert::Infallible;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::mpsc;
use tokio_stream::Stream;

use std::collections::VecDeque;

use osdp_embedded::acu::Acu;
use osdp_embedded::messages::{BuzCmd, Led, LedRecord, OSDP_CMD_BUZ, OSDP_CMD_LED, OSDP_REPLY_ACK};
use osdp_embedded::pd::{CommandHandler, LedColor, Pd, Reply};
use osdp_embedded::Transport;
use osdp_mcp::reader_state::{
    self, ReaderBuzzerHandler, ReaderLedHandler, ReaderStateView, SharedReaderState,
};

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

/// Encode an `osdp_BUZ` command payload (default tone).
fn buz_payload(on_100ms: u8, off_100ms: u8, count: u8) -> Vec<u8> {
    let buz = BuzCmd {
        reader_no: 0,
        tone_code: 0x02, // default tone
        on_time_100ms: on_100ms,
        off_time_100ms: off_100ms,
        count,
    };
    let mut buf = [0u8; 8];
    let n = buz.build(&mut buf).expect("BUZ build");
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
/// Runs on its own std::thread because `Pd`/`Acu` are `!Send`. Keypresses
/// arrive over `key_rx` (from the page) and trigger a short confirmation
/// beep.
fn run_driver(reader_state: SharedReaderState, mut key_rx: mpsc::UnboundedReceiver<()>) {
    let start = Instant::now();
    let wire = Rc::new(RefCell::new(Wire::default()));

    let mut pd = Pd::new(PD_ADDR);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
        start,
    });
    pd.set_command_handler(AckAll);
    pd.set_led_handler(ReaderLedHandler::new(Arc::clone(&reader_state)));
    pd.set_buzzer_handler(ReaderBuzzerHandler::new(reader_state));

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
    // The ACU allows one outstanding command at a time, so queue the
    // grant's commands and drain one per free cycle.
    let mut queue: VecDeque<(u8, Vec<u8>)> = VecDeque::new();

    loop {
        pd.tick();
        acu.tick();

        // Each keypress from the page → a short confirmation beep, queued
        // ahead of the idle grant loop.
        while key_rx.try_recv().is_ok() {
            queue.push_back((OSDP_CMD_BUZ, buz_payload(1, 0, 1)));
        }

        if !acu.is_pd_busy(PD_ADDR) {
            if let Some((code, payload)) = queue.pop_front() {
                let _ = acu.send_command(PD_ADDR, code, &payload);
            } else if last_event.elapsed() >= Duration::from_secs(4) {
                // "Access granted": flash the LED green and beep. Alternate
                // a clean grant (solid green + two short beeps) with a
                // "processing" look (flashing green + one longer beep).
                let (led, buz) = if n % 2 == 0 {
                    (
                        temporary(0, LedColor::Red, LedColor::Green, 18, 0, 0),
                        buz_payload(1, 1, 2),
                    )
                } else {
                    (
                        temporary(0, LedColor::Red, LedColor::Green, 20, 3, 3),
                        buz_payload(3, 2, 2),
                    )
                };
                queue.push_back((OSDP_CMD_LED, led_payload(vec![led])));
                queue.push_back((OSDP_CMD_BUZ, buz));
                n += 1;
                last_event = Instant::now();
            }
        }

        std::thread::sleep(Duration::from_millis(8));
    }
}

// ---- UI server (reuses the osdp-mcp embedded page) -------------------

/// Shared axum state: the reader snapshot plus a channel that forwards
/// keypresses to the driver thread.
#[derive(Clone)]
struct DemoState {
    reader: SharedReaderState,
    keypress: mpsc::UnboundedSender<()>,
}

async fn index() -> Html<&'static str> {
    Html(osdp_mcp::ui::index_html())
}

async fn api_state(State(st): State<DemoState>) -> Json<ReaderStateView> {
    let view = st
        .reader
        .lock()
        .map(|s| s.snapshot())
        .unwrap_or_else(|_| ReaderStateView::default());
    Json(view)
}

/// SSE stream, reusing the osdp-mcp builder so the demo page gets the same
/// instant push as the real server.
async fn api_events(
    State(st): State<DemoState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (initial, rx) = {
        let s = st.reader.lock().expect("reader state lock");
        (s.snapshot(), s.subscribe())
    };
    osdp_mcp::ui::reader_sse(initial, rx)
}

/// Keypad press from the page → a confirmation beep on the driver thread.
/// (The real osdp-mcp instead injects an osdp_KEYPAD event for the ACU.)
async fn api_keypad(State(st): State<DemoState>, Json(body): Json<KeypadPress>) -> StatusCode {
    // Validate the key the same way the real server does.
    if osdp_mcp::ui::keypad_event(&body.key).is_err() {
        return StatusCode::BAD_REQUEST;
    }
    let _ = st.keypress.send(());
    StatusCode::NO_CONTENT
}

#[derive(serde::Deserialize)]
struct KeypadPress {
    key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8088".to_string())
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;

    let reader_state = reader_state::new_shared();
    let (keypress_tx, keypress_rx) = mpsc::unbounded_channel::<()>();

    // PD/ACU loopback driver on its own thread (the state machines are
    // !Send); it feeds `reader_state` and turns keypresses into beeps.
    let driver_state = Arc::clone(&reader_state);
    std::thread::spawn(move || run_driver(driver_state, keypress_rx));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/events", get(api_events))
        .route("/api/keypad", post(api_keypad))
        .with_state(DemoState {
            reader: reader_state,
            keypress: keypress_tx,
        });

    println!("reader demo: open http://{bind}/ in a browser (Ctrl-C to quit)");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
