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

    // ---- pd_start before any configure → no remembered config ----
    // Nothing has been configured this process, so there's nothing to
    // restart. Must error clearly rather than silently no-op.
    let res = service
        .call_tool(CallToolRequestParams::new("pd_start"))
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("no remembered configuration"),
        "got: {:?}",
        first_text(&res)
    );

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

    // ---- pd_configure with sc_mode="scbk" but bad key length errors ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_configure").with_arguments(object!({
                "port": "ignored-bad-key-comes-first",
                "sc_mode": "scbk",
                "scbk_hex": "ABCD"   // only 2 bytes, not 16
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("32-hex-char"),
        "got: {:?}",
        first_text(&res)
    );

    // ---- pd_configure with unknown sc_mode errors ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_configure").with_arguments(object!({
                "port": "irrelevant",
                "sc_mode": "tls"
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(first_text(&res).contains("unknown sc_mode"));
    // Error message must mention the friendly aliases so an agent
    // that asked for the wrong thing can self-correct.
    assert!(
        first_text(&res).contains("install"),
        "error should hint at 'install' as an accepted value, got: {:?}",
        first_text(&res)
    );

    // ---- sc_mode synonyms all parse: "install", "Install",
    //      "scbkd", "default" all reach SCBK-D. Bad port still
    //      fails configure (which is fine — we're testing the
    //      sc_mode validation path, not the serial open).
    for alias in ["install", "Install", "SCBKD", "default", "scbk-d"] {
        let res = service
            .call_tool(
                CallToolRequestParams::new("pd_configure").with_arguments(object!({
                    "port": "bogus-COM999",
                    "sc_mode": alias,
                })),
            )
            .await?;
        // Configure fails on the serial open, NOT on sc_mode parse —
        // the error text should reflect that.
        assert_eq!(res.is_error, Some(true), "alias {alias} should pass parse");
        assert!(
            first_text(&res).contains("pd_configure failed"),
            "alias {alias} produced wrong error: {:?}",
            first_text(&res)
        );
    }

    // ---- inject_raw queues a card-read event ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("inject_raw").with_arguments(object!({
                "bit_count": 26,
                "data_hex": "DEADBEEF"
            })),
        )
        .await?;
    assert!(first_text(&res).contains("RAW queued"));

    // Bit count must match data length.
    let res = service
        .call_tool(
            CallToolRequestParams::new("inject_raw").with_arguments(object!({
                "bit_count": 26,
                "data_hex": "DE" // only 1 byte for a 4-byte payload
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(first_text(&res).contains("needs 4 bytes"));

    // ---- inject_keypad with ASCII digits ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("inject_keypad")
                .with_arguments(object!({ "digits": "1234#" })),
        )
        .await?;
    assert!(first_text(&res).contains("KEYPAD queued"));

    // ---- inject_local_status with tamper flag ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("inject_local_status")
                .with_arguments(object!({ "tamper": 1 })),
        )
        .await?;
    assert!(first_text(&res).contains("LSTATR queued"));

    // tamper must be 0 or 1.
    let res = service
        .call_tool(
            CallToolRequestParams::new("inject_local_status")
                .with_arguments(object!({ "tamper": 7 })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(first_text(&res).contains("must be 0 or 1"));

    // ---- pd_status surfaces the queue depth (3 queued, 2 failed) ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    let status = res.structured_content.as_ref().unwrap();
    assert_eq!(
        status.get("event_queue_depth").and_then(|v| v.as_u64()),
        Some(3),
        "expected 3 queued events (RAW + KEYPAD + LSTATR), got {:?}",
        status.get("event_queue_depth")
    );

    // ---- clear_events drops the queue ----
    let res = service
        .call_tool(CallToolRequestParams::new("clear_events"))
        .await?;
    assert_eq!(first_text(&res), "events cleared");
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    let status = res.structured_content.as_ref().unwrap();
    assert_eq!(
        status.get("event_queue_depth").and_then(|v| v.as_u64()),
        Some(0)
    );

    // ---- drop_next_n_replies surfaces through pd_status ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("drop_next_n_replies").with_arguments(object!({ "n": 5 })),
        )
        .await?;
    assert!(first_text(&res).contains("5 reply"));
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    let status = res.structured_content.as_ref().unwrap();
    assert_eq!(
        status.get("drop_remaining").and_then(|v| v.as_u64()),
        Some(5)
    );
    // Reset it back to 0.
    let _ = service
        .call_tool(
            CallToolRequestParams::new("drop_next_n_replies").with_arguments(object!({ "n": 0 })),
        )
        .await?;

    // ---- force_session_loss errors when no PD is configured ----
    let res = service
        .call_tool(CallToolRequestParams::new("force_session_loss"))
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("no PD configured"),
        "got: {:?}",
        first_text(&res)
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

    // ---- override tools accept input without a running PD ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("set_reply_for").with_arguments(object!({
                "cmd_code": 0x60,
                "code": 0x40,
                "payload_hex": ""
            })),
        )
        .await?;
    assert!(
        first_text(&res).contains("static override installed"),
        "got: {:?}",
        first_text(&res)
    );

    let res = service
        .call_tool(
            CallToolRequestParams::new("set_reply_script").with_arguments(object!({
                "cmd_code": 0x60,
                "cycle": true,
                "steps": [
                    { "code": 0x40, "payload_hex": "" },
                    { "code": 0x41, "payload_hex": "03" }
                ]
            })),
        )
        .await?;
    assert!(first_text(&res).contains("2 step(s)"));

    let res = service
        .call_tool(
            CallToolRequestParams::new("nak_next")
                .with_arguments(object!({ "cmd_code": 0x60, "nak_code": 0x04 })),
        )
        .await?;
    assert!(first_text(&res).contains("NAK 0x04"));

    let res = service
        .call_tool(CallToolRequestParams::new("clear_overrides"))
        .await?;
    assert_eq!(first_text(&res), "overrides cleared");

    // Bad hex should surface a clear error.
    let res = service
        .call_tool(
            CallToolRequestParams::new("set_reply_for").with_arguments(object!({
                "cmd_code": 0x60,
                "code": 0x40,
                "payload_hex": "ZZ"
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("invalid hex"),
        "got: {:?}",
        first_text(&res)
    );

    service.cancel().await?;
    Ok(())
}

/// When the operator supplies `OSDP_MCP_*` startup values, the actor
/// seeds them as the remembered config so `pd_start` can bring the PD
/// up from the startup posture even if the boot-time auto-start failed
/// (here: a bogus port that can't be opened). The tell is that
/// `pd_start` tries to *open the port* and fails with "pd_start failed"
/// — NOT "no remembered configuration", which would mean the startup
/// values never reached the actor.
#[tokio::test]
async fn pd_start_uses_startup_values() -> anyhow::Result<()> {
    let exe = env!("CARGO_BIN_EXE_osdp-mcp");

    let mut cmd = Command::new(exe);
    cmd.env("OSDP_MCP_PORT", "startup-port-does-not-exist-COM999")
        .env("OSDP_MCP_BAUD", "19200")
        .env("OSDP_MCP_ADDRESS", "5");
    let transport = TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;

    // Boot-time auto-start failed on the bogus port, so no PD is
    // running — but the startup config was seeded.
    let res = service
        .call_tool(CallToolRequestParams::new("pd_status"))
        .await?;
    let status = res.structured_content.as_ref().unwrap();
    assert_eq!(status.get("running").and_then(|v| v.as_bool()), Some(false));

    // pd_start replays the startup values: it reaches the serial open
    // (and fails there) rather than reporting nothing-to-start.
    let res = service
        .call_tool(CallToolRequestParams::new("pd_start"))
        .await?;
    assert_eq!(res.is_error, Some(true));
    let text = first_text(&res);
    assert!(
        text.contains("pd_start failed"),
        "expected a serial-open failure (startup values were replayed), got: {text:?}"
    );
    assert!(
        !text.contains("no remembered configuration"),
        "startup values did not reach the actor: {text:?}"
    );

    // ---- pd_get_pdid returns the default identity ----
    // No PD running — the PDID is process state, independent of the slot.
    let res = service
        .call_tool(CallToolRequestParams::new("pd_get_pdid"))
        .await?;
    let pdid = res.structured_content.as_ref().unwrap();
    assert_eq!(
        pdid.get("vendor_code_hex").and_then(|v| v.as_str()),
        Some("5A4243"), // "ZBC"
        "default vendor code, got {:?}",
        pdid.get("vendor_code_hex")
    );
    assert_eq!(pdid.get("model").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(pdid.get("firmware").and_then(|v| v.as_str()), Some("0.1.0"));

    // ---- pd_set_pdid partial update: only the given fields change ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_pdid").with_arguments(object!({
                "vendor_code_hex": "AC4E01",
                "serial": 305419896, // 0x12345678
                "firmware_major": 2,
                "firmware_minor": 5,
                "firmware_build": 9
            })),
        )
        .await?;
    let pdid = res.structured_content.as_ref().unwrap();
    assert_eq!(
        pdid.get("vendor_code_hex").and_then(|v| v.as_str()),
        Some("AC4E01")
    );
    assert_eq!(pdid.get("serial").and_then(|v| v.as_u64()), Some(305419896));
    assert_eq!(pdid.get("firmware").and_then(|v| v.as_str()), Some("2.5.9"));
    // model/version were not supplied — they keep the defaults.
    assert_eq!(pdid.get("model").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(pdid.get("version").and_then(|v| v.as_u64()), Some(0));

    // ---- the update persists: a fresh get reflects it ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_get_pdid"))
        .await?;
    let pdid = res.structured_content.as_ref().unwrap();
    assert_eq!(
        pdid.get("vendor_code_hex").and_then(|v| v.as_str()),
        Some("AC4E01")
    );
    assert_eq!(pdid.get("firmware").and_then(|v| v.as_str()), Some("2.5.9"));

    // ---- bad vendor_code_hex length is rejected ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_pdid")
                .with_arguments(object!({ "vendor_code_hex": "ABCD" })), // 2 bytes, not 3
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("6 hex chars"),
        "got: {:?}",
        first_text(&res)
    );

    // ---- pd_get_pdcap returns the annotated default capability set ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_get_pdcap"))
        .await?;
    let pdcap = res.structured_content.as_ref().unwrap();
    let records = pdcap
        .get("records")
        .and_then(|v| v.as_array())
        .expect("records array");
    let find = |records: &[serde_json::Value], fc: u64| -> Option<serde_json::Value> {
        records
            .iter()
            .find(|r| r.get("function_code").and_then(|v| v.as_u64()) == Some(fc))
            .cloned()
    };
    // FC4 (Reader LED Control) is annotated with its spec name.
    let fc4 = find(records, 4).expect("FC4 present in default");
    assert_eq!(
        fc4.get("function_name").and_then(|v| v.as_str()),
        Some("Reader LED Control")
    );
    // The default we ship is spec-conformant: FC3 (Card Data Format)
    // carries num_objects == 0 (spec B.4 requires it).
    let fc3 = find(records, 3).expect("FC3 present in default");
    assert_eq!(fc3.get("num_objects").and_then(|v| v.as_u64()), Some(0));

    // ---- pd_set_capability updates an existing record ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_capability").with_arguments(object!({
                "function_code": 4,
                "compliance_level": 5,
                "num_objects": 2
            })),
        )
        .await?;
    let pdcap = res.structured_content.as_ref().unwrap();
    let records = pdcap.get("records").and_then(|v| v.as_array()).unwrap();
    let fc4 = find(records, 4).unwrap();
    assert_eq!(
        fc4.get("compliance_level").and_then(|v| v.as_u64()),
        Some(5)
    );
    assert_eq!(fc4.get("num_objects").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(
        fc4.get("compliance_meaning").and_then(|v| v.as_str()),
        Some("+ RGB, colors 0-7")
    );

    // ---- validation rejects an out-of-range compliance level ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_capability").with_arguments(object!({
                "function_code": 4,
                "compliance_level": 7
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("invalid"),
        "got: {:?}",
        first_text(&res)
    );

    // ---- validation rejects a non-zero required-zero field ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_capability").with_arguments(object!({
                "function_code": 3,      // Card Data Format
                "compliance_level": 1,
                "num_objects": 1         // spec B.4: must be 0x00
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("must be 0x00"),
        "got: {:?}",
        first_text(&res)
    );

    // ---- unknown function code is rejected ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_capability").with_arguments(object!({
                "function_code": 99,
                "compliance_level": 0
            })),
        )
        .await?;
    assert_eq!(res.is_error, Some(true));
    assert!(
        first_text(&res).contains("unknown function code"),
        "got: {:?}",
        first_text(&res)
    );

    // ---- remove a record ----
    let res = service
        .call_tool(
            CallToolRequestParams::new("pd_set_capability").with_arguments(object!({
                "function_code": 5,
                "remove": true
            })),
        )
        .await?;
    let pdcap = res.structured_content.as_ref().unwrap();
    let records = pdcap.get("records").and_then(|v| v.as_array()).unwrap();
    assert!(find(records, 5).is_none(), "FC5 should be removed");

    // ---- pd_reset_pdcap restores the default ----
    let res = service
        .call_tool(CallToolRequestParams::new("pd_reset_pdcap"))
        .await?;
    let pdcap = res.structured_content.as_ref().unwrap();
    let records = pdcap.get("records").and_then(|v| v.as_array()).unwrap();
    let fc4 = find(records, 4).unwrap();
    assert_eq!(
        fc4.get("compliance_level").and_then(|v| v.as_u64()),
        Some(4),
        "reset restores the default FC4 compliance level"
    );
    assert!(find(records, 5).is_some(), "reset restores FC5");

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
