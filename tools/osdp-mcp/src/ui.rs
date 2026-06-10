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
//!   from the browser). The only write the UI performs.
//!
//! An interactive card-read button is still deferred (see docs/PLAN.md
//! iteration 5).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use osdp_embedded::messages::{Keypad, OSDP_REPLY_KEYPAD};
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
