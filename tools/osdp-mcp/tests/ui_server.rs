// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Reader-visual UI server routes.
//!
//! Drives the axum `Router` in-process with `tower`'s `oneshot` — no
//! socket, no HTTP client — to confirm `GET /` serves the embedded page
//! and `GET /api/state` serves the reader snapshot (empty for a freshly
//! spawned, unconfigured PD).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use osdp_mcp::crypto::Selector;
use osdp_mcp::pd_actor::PdHandle;
use osdp_mcp::ui;
use tower::ServiceExt; // for `oneshot`

fn spawn_pd() -> Arc<PdHandle> {
    let factory = Selector::default_for_build()
        .expect("a crypto backend is compiled in")
        .factory()
        .expect("build crypto factory");
    Arc::new(PdHandle::spawn(factory, None))
}

#[tokio::test]
async fn index_serves_self_contained_page() {
    let app = ui::router(spawn_pd());

    let resp = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    // It's the reader page, and it knows where to poll.
    assert!(html.contains("OSDP Virtual Reader"));
    assert!(html.contains("/api/state"));
}

#[tokio::test]
async fn api_state_is_empty_for_fresh_pd() {
    let app = ui::router(spawn_pd());

    let resp = app
        .oneshot(Request::get("/api/state").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // A PD that has never been driven shows no LEDs.
    assert_eq!(json, serde_json::json!({ "leds": [] }));
}

#[tokio::test]
async fn api_events_is_an_sse_stream() {
    let app = ui::router(spawn_pd());

    let resp = app
        .oneshot(Request::get("/api/events").body(Body::empty()).unwrap())
        .await
        .unwrap();
    // Headers are ready immediately (snapshot-on-connect streams in the
    // body); assert the SSE content type without draining the live stream.
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/event-stream"), "content-type was {ct:?}");
}
