// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Library half of `osdp-mcp` — the building blocks the binary
//! composes. Split out so integration tests can drive the PD actor
//! and default handler directly, without going through MCP or a
//! serial port.

pub mod handler;
pub mod log;
pub mod pd_actor;
pub mod serial_transport;
