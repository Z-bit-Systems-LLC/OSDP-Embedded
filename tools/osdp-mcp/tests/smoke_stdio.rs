// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Spawns the osdp-mcp binary and drives it over stdio with the rmcp
//! client. Covers milestones 1 and 2: ping, pd_status (idle), and
//! pd_stop idempotence.
//!
//! pd_configure with a real port is intentionally NOT exercised here
//! — CI hosts don't have a serial port. The Pd / actor wiring is
//! covered by a separate library-level test (see tests/pd_actor.rs).

use rmcp::model::CallToolRequestParams;
use rmcp::transport::TokioChildProcess;
use rmcp::{object, ServiceExt};
use tokio::process::Command;

#[tokio::test]
async fn ping_and_lifecycle() -> anyhow::Result<()> {
    let exe = env!("CARGO_BIN_EXE_osdp-mcp");

    let transport = TokioChildProcess::new(Command::new(exe))?;
    let service = ().serve(transport).await?;

    // ---- ping (no args) ----
    let res = service
        .call_tool(CallToolRequestParams::new("ping"))
        .await?;
    assert_eq!(first_text(&res), "osdp-mcp pong");

    // ---- ping (with message) ----
    let res = service
        .call_tool(CallToolRequestParams::new("ping").with_arguments(object!({ "message": "hi" })))
        .await?;
    assert_eq!(first_text(&res), "osdp-mcp pong: hi");

    // ---- pd_status before any configure → idle ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    // Structured output lands in res.structured_content as JSON.
    let status = res
        .structured_content
        .as_ref()
        .expect("pd_status should return structured content");
    assert_eq!(status.get("running").and_then(|v| v.as_bool()), Some(false));
    assert!(status.get("port").map(|v| v.is_null()).unwrap_or(false));

    // ---- pd_stop on an idle PD is idempotent ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_stop"))
        .await?;
    assert_eq!(first_text(&res), "PD stopped");

    // ---- pd_status still idle after pd_stop ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    let status = res.structured_content.as_ref().unwrap();
    assert_eq!(status.get("running").and_then(|v| v.as_bool()), Some(false));

    // ---- pd_configure against a bogus port should fail loudly ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_configure").with_arguments(object!({
                "port": "this-port-does-not-exist-COM999",
                "baud": 9600,
                "address": 0
            })),
        )
        .await?;
    // Error responses come back as is_error=Some(true) with the
    // failure message in content[0].
    assert_eq!(res.is_error, Some(true));
    let text = first_text(&res);
    assert!(
        text.contains("pd_configure failed"),
        "unexpected error text: {text:?}"
    );

    // ---- get_log on a fresh server returns an empty page ----
    let res = service
        .call_tool(CallToolRequestParams::new("get_log"))
        .await?;
    let page = res.structured_content.as_ref().unwrap();
    assert_eq!(
        page.get("entries")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(0)
    );
    assert_eq!(page.get("total").and_then(|v| v.as_u64()), Some(0));

    // ---- clear_log is idempotent on an empty log ----
    let res = service
        .call_tool(CallToolRequestParams::new("clear_log"))
        .await?;
    assert_eq!(first_text(&res), "log cleared");

    // ---- wait_for_command times out cleanly when no PD is running ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("wait_for_command")
                .with_arguments(object!({ "cmd_code": 0x60, "timeout_ms": 50 })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("timeout"),
        "expected timeout message, got {:?}",
        first_text(&res)
    );

    service.cancel().await?;
    Ok(())
}

fn first_text(res: &rmcp::model::CallToolResult) -> String {
    res.content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default()
}
