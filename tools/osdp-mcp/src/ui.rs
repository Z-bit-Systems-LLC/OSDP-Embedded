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
//! Two routes, both read-only:
//! - `GET /` → the self-contained HTML page (`ui_index.html`).
//! - `GET /api/state` → a JSON [`ReaderStateView`] snapshot the page polls
//!   a few times a second.
//!
//! View-only for now; an SSE push channel and interactive card/keypad
//! buttons are deferred (see docs/PLAN.md iteration 5).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};

use crate::pd_actor::PdHandle;
use crate::reader_state::ReaderStateView;

/// The reader visual page. Self-contained (inline CSS + JS, no external
/// assets), embedded at build time so the binary needs no companion files.
const INDEX_HTML: &str = include_str!("ui_index.html");

/// Build the UI router over a shared [`PdHandle`]. Split out from
/// [`serve`] so tests can drive the routes without binding a socket.
pub fn router(pd: Arc<PdHandle>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
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
