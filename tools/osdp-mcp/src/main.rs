// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! osdp-mcp — MCP server that drives an osdp-embedded PD against an
//! ACU under test.
//!
//! Milestone 2: PD actor + serial transport + lifecycle tools
//! (`pd_configure`, `pd_stop`, `pd_status`) plus the milestone-1
//! `ping` keep-alive. PDID / PDCAP defaults match `osdp-pd-mock` so
//! a freshly-configured PD behaves identically to the existing tool.

use std::sync::Arc;

use anyhow::Result;
use osdp_mcp::pd_actor::{PdHandle, PdStatus};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_router, Json, ServiceExt};
use tracing_subscriber::EnvFilter;

// ---- Tool parameter schemas ------------------------------------------

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PingArgs {
    /// Echoed back verbatim. Optional.
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PdConfigureArgs {
    /// Serial port name. Windows: "COM5". POSIX: "/dev/ttyUSB0".
    /// A virtual port (com0com pair, socat pty) works the same.
    port: String,
    /// Line rate. Defaults to 9600 (the OSDP spec's baseline).
    #[serde(default = "default_baud")]
    baud: u32,
    /// 7-bit PD address (0x00..0x7E). Defaults to 0. Broadcast
    /// (0x7F) is always accepted in addition to this one.
    #[serde(default)]
    address: u8,
}

fn default_baud() -> u32 {
    9600
}

// ---- Service ---------------------------------------------------------

#[derive(Clone)]
struct OsdpMcp {
    pd: Arc<PdHandle>,
}

impl OsdpMcp {
    fn new() -> Self {
        Self {
            pd: Arc::new(PdHandle::spawn()),
        }
    }
}

#[tool_router(server_handler)]
impl OsdpMcp {
    /// Liveness check. Returns a banner string; useful to confirm
    /// the server is up before issuing real tools.
    #[tool(description = "Liveness check. Returns a banner string.")]
    fn ping(&self, Parameters(args): Parameters<PingArgs>) -> String {
        match args.message {
            Some(m) => format!("osdp-mcp pong: {}", m),
            None => "osdp-mcp pong".to_string(),
        }
    }

    /// Bring up a PD on a serial port. Any previously-configured PD
    /// is torn down first. PDID and PDCAP currently default to the
    /// values osdp-pd-mock ships with (vendor ZBC, one of every
    /// basic capability) — per-message overrides land in a later
    /// milestone.
    #[tool(
        description = "Configure and start a PD on a serial port. Replaces any existing PD configuration."
    )]
    async fn pd_configure(
        &self,
        Parameters(args): Parameters<PdConfigureArgs>,
    ) -> Result<String, String> {
        self.pd
            .configure(args.port.clone(), args.baud, args.address)
            .await
            .map(|()| {
                format!(
                    "PD configured on {} @ {}bps addr=0x{:02X}",
                    args.port, args.baud, args.address
                )
            })
            .map_err(|e| format!("pd_configure failed: {}", e))
    }

    /// Stop the current PD. Idempotent — fine to call when nothing
    /// is configured.
    #[tool(description = "Stop the current PD, if any. Idempotent.")]
    async fn pd_stop(&self) -> Result<String, String> {
        self.pd
            .stop()
            .await
            .map(|()| "PD stopped".to_string())
            .map_err(|e| format!("pd_stop failed: {}", e))
    }

    /// Snapshot of the PD's current state (running / online / SC /
    /// most recent cmd+reply). Cheap; safe to poll.
    #[tool(
        description = "Return a JSON snapshot of the PD's state (running, online, SC, last cmd/reply)."
    )]
    async fn pd_status(&self) -> Result<Json<PdStatus>, String> {
        self.pd
            .status()
            .await
            .map(Json)
            .map_err(|e| format!("pd_status failed: {}", e))
    }
}

// ---- Main ------------------------------------------------------------

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
    let service = OsdpMcp::new().serve(stdio()).await.map_err(|e| {
        tracing::error!(?e, "failed to start MCP service");
        e
    })?;

    service.waiting().await?;
    Ok(())
}
