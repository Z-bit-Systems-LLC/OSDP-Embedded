// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Browser-facing reader visual.
//!
//! A tiny axum server, independent of whichever MCP transport is running,
//! that lets a human watch the virtual reader's LEDs update in real time
//! while an agent drives the PD over MCP. Off by default; enabled with
//! `--ui-bind <addr>` / `OSDP_MCP_UI_BIND` (loopback by convention — the
//! page exposes read-only reader state, but the bind address is the
//! operator's choice, mirroring the `--bind` MCP-HTTP flag).
//!
//! Routes (read-only except the keypad):
//! - `GET /` → the self-contained HTML page (`ui_index.html`).
//! - `GET /api/state` → a JSON [`ReaderStateView`] snapshot (one-shot;
//!   the page's polling backstop and `pd_reader_state` use it).
//! - `GET /api/events` → a Server-Sent Events stream: a snapshot on
//!   connect, then one `state` event per reader-LED/buzzer change. The
//!   page prefers this over polling.
//! - `POST /api/keypad` → inject one keypad press; the PD surfaces it as
//!   an `osdp_KEYPAD` reply on its next POLL (the reader's keypad, driven
//!   from the browser).
//! - `POST /api/card` → inject a card read; the PD surfaces it as an
//!   `osdp_RAW` reply on its next POLL (a card tapped, from the browser).
//! - `POST /api/tamper` → inject a tamper condition; the PD surfaces it
//!   as an `osdp_LSTATR` (tamper bit set) on its next POLL. A status
//!   report, so it never goes stale — delivered whenever the ACU next
//!   polls.
//! - `POST /api/power-cycle` → power-cycle the reader: rebuild the PD
//!   (SQN reset, Secure Channel session dropped — the ACU must
//!   re-handshake), which on re-init queues a non-stale power-up
//!   `osdp_LSTATR` for the next POLL.
//!
//! The keypad / card / tamper / power-cycle POSTs are the only writes
//! the UI performs; everything else is read-only.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use osdp_embedded::messages::{Keypad, Raw, OSDP_REPLY_KEYPAD, OSDP_REPLY_LSTATR, OSDP_REPLY_RAW};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::overrides::OverrideReply;
use crate::pd_actor::PdHandle;
use crate::reader_state::ReaderStateView;

/// Build a single-key `osdp_KEYPAD` reply payload, or an error if `key`
/// isn't one keypad character. Shared by the UI server and the
/// `reader_demo` example so both validate presses identically.
pub fn keypad_event(key: &str) -> Result<OverrideReply, &'static str> {
    let mut chars = key.chars();
    let c = chars.next().ok_or("empty key")?;
    if chars.next().is_some() || !matches!(c, '0'..='9' | '*' | '#') {
        return Err("key must be a single digit, * or #");
    }
    // Mirror the inject_keypad tool: the key's ASCII byte is the keypad
    // datum (per spec Table 35, one byte per key).
    let digits = [c as u8];
    let kp = Keypad {
        reader_no: 0,
        digits: &digits,
    };
    let mut buf = vec![0u8; 2 + digits.len()];
    let n = kp.build(&mut buf).map_err(|_| "KEYPAD build failed")?;
    buf.truncate(n);
    Ok(OverrideReply {
        code: OSDP_REPLY_KEYPAD,
        payload: buf,
    })
}

/// Build a card-read `osdp_RAW` event as a standard **26-bit Wiegand**
/// (H10301) credential: an 8-bit `facility` code, a 16-bit `card` number,
/// and the two computed parity bits, sent as format 1 on reader 0:
///
/// ```text
///   bit:  0      1 .. 8      9 .. 24     25
///        [Pe]   [facility]  [card num]  [Po]
/// ```
///
/// `Pe` is even parity over the leading 12 data bits (facility + top 4 of
/// the card number); `Po` is odd parity over the trailing 12 (bottom 12 of
/// the card number). Shared by the UI server and the `reader_demo` example.
pub fn card_event(facility: u8, card: u16) -> Result<OverrideReply, &'static str> {
    // 24 data bits, MSB-first: facility(8) then card(16).
    let data24: u32 = ((facility as u32) << 16) | (card as u32);
    let lead12 = (data24 >> 12) & 0xFFF; // facility(8) + top 4 of card
    let trail12 = data24 & 0xFFF; // bottom 12 of card
                                  // Even-parity bit = parity of its data; odd-parity bit = its inverse.
    let pe = lead12.count_ones() & 1;
    let po = (trail12.count_ones() & 1) ^ 1;
    // [Pe | 24 data bits | Po] = 26 bits.
    let frame26: u32 = (pe << 25) | (data24 << 1) | po;
    // Left-align the 26 bits into 4 bytes (MSB-first, per spec Table 33).
    let bit_data = (frame26 << 6).to_be_bytes();

    let raw = Raw {
        reader_no: 0,
        format_code: 1, // Wiegand
        bit_count: 26,
        bit_data: &bit_data,
    };
    let mut buf = vec![0u8; 4 + bit_data.len()];
    let n = raw.build(&mut buf).map_err(|_| "RAW build failed")?;
    buf.truncate(n);
    Ok(OverrideReply {
        code: OSDP_REPLY_RAW,
        payload: buf,
    })
}

/// Build a Local Status Report (`osdp_LSTATR`) event with the given
/// tamper / power flags. Spec §7.6 / Table 50: a 2-byte payload, byte 0
/// = tamper status (0 normal, 1 tamper), byte 1 = power status (0
/// normal, 1 power failure). A status report, so `events::enqueue` keeps
/// it non-staleable — it is reported on the next POLL however delayed.
pub fn local_status_event(tamper: u8, power: u8) -> OverrideReply {
    OverrideReply {
        code: OSDP_REPLY_LSTATR,
        payload: vec![tamper, power],
    }
}

/// The reader visual page. Self-contained (inline CSS + JS, no external
/// assets), embedded at build time so the binary needs no companion files.
const INDEX_HTML: &str = include_str!("ui_index.html");

/// The embedded reader-visual page (the same bytes served at `GET /`).
/// Exposed so demos/tools can mount the page on their own router.
pub fn index_html() -> &'static str {
    INDEX_HTML
}

/// Build the UI router over a shared [`PdHandle`]. Split out from
/// [`serve`] so tests can drive the routes without binding a socket.
pub fn router(pd: Arc<PdHandle>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/events", get(api_events))
        .route("/api/keypad", post(api_keypad))
        .route("/api/card", post(api_card))
        .route("/api/tamper", post(api_tamper))
        .route("/api/power-cycle", post(api_power_cycle))
        .with_state(pd)
}

/// Bind `addr` and serve the reader UI until the process exits. Intended
/// to be `tokio::spawn`ed alongside the MCP transport.
pub async fn serve(pd: Arc<PdHandle>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("reader UI bind {addr} failed: {e}"))?;
    axum::serve(listener, router(pd)).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn api_state(State(pd): State<Arc<PdHandle>>) -> Json<ReaderStateView> {
    Json(pd.reader_state())
}

/// Body of a `POST /api/keypad`: one pressed key.
#[derive(serde::Deserialize)]
struct KeypadPress {
    key: String,
}

/// Inject a single keypad press. The page POSTs one of these when a key is
/// tapped; the PD surfaces it as an `osdp_KEYPAD` reply on its next POLL, so
/// the ACU under test receives the digit — the reader's keypad, driven from
/// the browser. (This is the one write the UI performs; everything else is
/// read-only.)
async fn api_keypad(State(pd): State<Arc<PdHandle>>, Json(body): Json<KeypadPress>) -> StatusCode {
    match keypad_event(&body.key) {
        Ok(ev) => {
            pd.enqueue_event(ev);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

/// Body of a `POST /api/card`: a card "tap". `value` is the 16-bit card
/// number (0..=65535); `facility` is the optional 8-bit facility code
/// (default 0).
#[derive(serde::Deserialize)]
struct CardTap {
    value: String,
    #[serde(default)]
    facility: Option<u8>,
}

/// Inject a card read. The page POSTs this when "Tap card" is pressed; the
/// PD surfaces it as an `osdp_RAW` reply on its next POLL, so the ACU under
/// test sees the presented card. The card number must fit a 26-bit Wiegand
/// credential (0..=65535).
async fn api_card(State(pd): State<Arc<PdHandle>>, Json(body): Json<CardTap>) -> StatusCode {
    let card: u32 = match body.value.trim().parse() {
        Ok(v) if v <= u16::MAX as u32 => v,
        _ => return StatusCode::BAD_REQUEST,
    };
    match card_event(body.facility.unwrap_or(0), card as u16) {
        Ok(ev) => {
            pd.enqueue_event(ev);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

/// Inject a tamper condition. The page POSTs this when "Tamper" is
/// pressed; the PD surfaces it as an `osdp_LSTATR` with the tamper bit
/// set on its next POLL. As a status report it is never aged out, so the
/// ACU learns of the tamper whenever it next polls — even after a gap.
async fn api_tamper(State(pd): State<Arc<PdHandle>>) -> StatusCode {
    pd.enqueue_event(local_status_event(1, 0));
    StatusCode::NO_CONTENT
}

/// Power-cycle the reader. The page POSTs this when "Power Cycle" is
/// pressed; the PD is torn down and rebuilt with the same parameters —
/// resetting its sequence number and dropping any Secure Channel session
/// (the ACU must re-handshake), exactly as a real reboot would. The
/// rebuild queues a non-stale power-up `osdp_LSTATR` (see
/// `pd_actor::open_pd`) for the next POLL. Returns 503 if no PD is
/// configured to cycle.
async fn api_power_cycle(State(pd): State<Arc<PdHandle>>) -> StatusCode {
    match pd.force_session_loss().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Server-Sent Events stream of reader state: a `state` event carrying the
/// current snapshot on connect, then one per LED change. EventSource on the
/// page consumes it; a missed early event can't strand a client because the
/// snapshot-on-connect always primes it.
async fn api_events(
    State(pd): State<Arc<PdHandle>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    reader_sse(pd.reader_state(), pd.subscribe_reader())
}

/// Build the reader-state SSE response from an initial snapshot and a
/// change subscription: emits the snapshot on connect, then one `state`
/// event per change. Exposed so other servers (e.g. the `reader_demo`
/// example, which owns its `ReaderState` directly) can serve the identical
/// stream without duplicating the wiring.
pub fn reader_sse(
    initial: ReaderStateView,
    rx: broadcast::Receiver<ReaderStateView>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let snapshot_on_connect = tokio_stream::once(Ok(to_event(&initial)));
    let changes = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(snap) => Some(Ok(to_event(&snap))),
        // Lagged: this client fell behind the ring; skip the gap — the next
        // change re-syncs it to the current state.
        Err(_) => None,
    });

    // KeepAlive sends periodic comment lines so idle connections (and the
    // proxies in front of them) don't time the stream out.
    Sse::new(snapshot_on_connect.chain(changes)).keep_alive(KeepAlive::default())
}

/// Encode a snapshot as a named SSE `state` event. A serialise failure
/// (shouldn't happen for this plain struct) degrades to an empty event
/// rather than tearing down the stream.
fn to_event(snapshot: &ReaderStateView) -> Event {
    Event::default()
        .event("state")
        .json_data(snapshot)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use osdp_embedded::messages::Raw;

    /// 26-bit Wiegand framing + parity for known facility/card values.
    #[test]
    fn card_event_is_26bit_wiegand_with_parity() {
        // facility 0, card 1: leading 12 bits all zero → Pe = 0; trailing
        // 12 bits = ...0001 (odd) → Po = 0. frame = data24<<1 = 2, then
        // left-aligned by 6 → 0x00000080.
        let ev = card_event(0, 1).unwrap();
        let raw = Raw::decode(&ev.payload).unwrap();
        assert_eq!(raw.bit_count, 26);
        assert_eq!(raw.format_code, 1);
        assert_eq!(raw.bit_data, &[0x00, 0x00, 0x00, 0x80]);

        // facility 1, card 0: leading 12 = ...00010000 (one 1) → Pe = 1;
        // trailing 12 all zero (even) → Po = 1. frame =
        // (1<<25) | (0x10000<<1) | 1 = 0x2020001, left-aligned by 6.
        let ev = card_event(1, 0).unwrap();
        let raw = Raw::decode(&ev.payload).unwrap();
        let expected = (0x0202_0001u32 << 6).to_be_bytes();
        assert_eq!(raw.bit_data, &expected);
    }
}
