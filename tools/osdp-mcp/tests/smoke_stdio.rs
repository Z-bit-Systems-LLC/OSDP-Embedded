// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Smoke test for milestone 1 — spawns the osdp-mcp binary, drives it
//! over stdio with the rmcp client, calls `ping`, and asserts the
//! banner comes back.
//!
//! Runs with the rest of the workspace tests; doesn't require any
//! external binaries beyond what cargo already builds.

use rmcp::model::CallToolRequestParams;
use rmcp::transport::TokioChildProcess;
use rmcp::{object, ServiceExt};
use tokio::process::Command;

#[tokio::test]
async fn ping_round_trip() -> anyhow::Result<()> {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests of
    // bin crates — points at the freshly-built binary, no PATH games.
    let exe = env!("CARGO_BIN_EXE_osdp-mcp");

    let transport = TokioChildProcess::new(Command::new(exe))?;
    let service = ().serve(transport).await?;

    // Default ping (no arguments).
    let res = service
        .call_tool(CallToolRequestParams::new("ping"))
        .await?;
    assert_eq!(first_text(&res), "osdp-mcp pong");

    // With a message argument.
    let res = service
        .call_tool(CallToolRequestParams::new("ping").with_arguments(object!({ "message": "hi" })))
        .await?;
    assert_eq!(first_text(&res), "osdp-mcp pong: hi");

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
