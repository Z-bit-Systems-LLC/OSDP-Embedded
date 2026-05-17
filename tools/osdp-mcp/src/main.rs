// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! osdp-mcp — MCP server that drives an osdp-embedded PD against an
//! ACU under test.
//!
//! Milestone 1: bare-bones stdio MCP service exposing one `ping` tool.
//! Validates the rmcp transport, macro expansion, and tracing-to-
//! stderr setup before any PD code is wired in.

use anyhow::Result;
use rmcp::transport::stdio;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router, ServiceExt};
use tracing_subscriber::EnvFilter;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PingArgs {
    /// Echoed back verbatim in the tool's response. Optional.
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct OsdpMcp;

// `server_handler` makes rmcp generate the ServerHandler impl
// (incl. list_tools / call_tool dispatch) directly from the #[tool]
// methods below. We'll switch to a manual impl in milestone 2 once
// the server needs to advertise capabilities beyond tools.
#[tool_router(server_handler)]
impl OsdpMcp {
    /// Liveness check. Returns a fixed banner so an MCP client can
    /// confirm the server is reachable before issuing real tools.
    #[tool(
        description = "Liveness check. Returns a banner string; useful to confirm the server is up."
    )]
    fn ping(&self, Parameters(args): Parameters<PingArgs>) -> String {
        match args.message {
            Some(m) => format!("osdp-mcp pong: {}", m),
            None => "osdp-mcp pong".to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // CRITICAL: MCP uses stdout for JSON-RPC framing; logs MUST go to
    // stderr or the client will choke on interleaved bytes.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("osdp-mcp starting (stdio transport)");

    // .inspect_err is Rust 1.76+; workspace MSRV is 1.70 so use map_err.
    let service = OsdpMcp.serve(stdio()).await.map_err(|e| {
        tracing::error!(?e, "failed to start MCP service");
        e
    })?;

    service.waiting().await?;
    Ok(())
}
