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
    // A PD that has never been driven shows no LEDs and no buzzers.
    assert_eq!(json, serde_json::json!({ "leds": [], "buzzers": [] }));
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

#[tokio::test]
async fn keypad_press_enqueues_a_pd_event() {
    let pd = spawn_pd();
    let app = ui::router(Arc::clone(&pd));
    assert_eq!(pd.event_queue_depth(), 0);

    // A valid key enqueues one KEYPAD event for the PD's next POLL.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/keypad")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"5"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(pd.event_queue_depth(), 1);

    // A bad key is rejected and enqueues nothing.
    let resp = app
        .oneshot(
            Request::post("/api/keypad")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"AB"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(pd.event_queue_depth(), 1);
}

#[tokio::test]
async fn tamper_enqueues_a_pd_event() {
    let pd = spawn_pd();
    let app = ui::router(Arc::clone(&pd));
    assert_eq!(pd.event_queue_depth(), 0);

    // The Tamper button enqueues one LSTATR for the PD's next POLL.
    let resp = app
        .oneshot(Request::post("/api/tamper").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(pd.event_queue_depth(), 1);
}

#[tokio::test]
async fn power_cycle_without_a_pd_reports_unavailable() {
    let pd = spawn_pd();
    let app = ui::router(Arc::clone(&pd));

    // No PD is configured on this freshly spawned actor, so there's
    // nothing to power-cycle — the route reports it rather than 500ing.
    let resp = app
        .oneshot(
            Request::post("/api/power-cycle")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn card_tap_enqueues_a_pd_event() {
    let pd = spawn_pd();
    let app = ui::router(Arc::clone(&pd));
    assert_eq!(pd.event_queue_depth(), 0);

    // A numeric card value enqueues one RAW event for the next POLL.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/card")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"12345"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(pd.event_queue_depth(), 1);

    // A non-numeric card value is rejected.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/card")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"nope"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A value that doesn't fit a 16-bit card number is rejected too.
    let resp = app
        .oneshot(
            Request::post("/api/card")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"value":"70000"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(pd.event_queue_depth(), 1);
}
