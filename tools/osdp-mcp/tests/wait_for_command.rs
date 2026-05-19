// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Verifies the `wait_for_command` notify path:
//!
//!   - returns immediately when a matching entry is already present,
//!   - blocks then wakes when a matching entry arrives, and
//!   - errors out cleanly on timeout.
//!
//! Exercises [`LogInner::find_command_at_or_after`] plus the
//! `Notify`-based recheck loop in [`PdHandle::wait_for_command`] —
//! the actual implementation lives in `src/pd_actor.rs` but we
//! reproduce the loop here against a bare [`LogInner`] so we don't
//! have to spin up the full actor.

use std::sync::Arc;
use std::time::Duration;

use osdp_mcp::log::{Direction, LogInner};

async fn wait_for_command(
    log: &Arc<LogInner>,
    cmd_code: u8,
    timeout: Duration,
    since_seq: u64,
) -> Result<u64, &'static str> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let notified = log.notify.notified();
        if let Some(entry) = log.find_command_at_or_after(since_seq, cmd_code) {
            return Ok(entry.seq);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timeout");
        }
        if tokio::time::timeout(remaining, notified).await.is_err() {
            return Err("timeout");
        }
    }
}

// Non-heartbeat codes throughout — POLL (0x60) / ACK (0x40) go to
// the push-filter counter at write time and never enter the ring,
// so they're not waitable. We use ID (0x61) as the sentinel and
// CAP (0x62) / KEYSET (0x75) as red herrings.

#[tokio::test]
async fn returns_immediately_when_entry_already_present() {
    let log = Arc::new(LogInner::new(8));
    log.push(Direction::Cmd, 0, 0x61, &[], 0);

    let seq = wait_for_command(&log, 0x61, Duration::from_millis(100), 0)
        .await
        .unwrap();
    assert_eq!(seq, 0);
}

#[tokio::test]
async fn wakes_when_matching_entry_arrives() {
    let log = Arc::new(LogInner::new(8));
    let writer = Arc::clone(&log);

    // Spawn a tick-and-push from a separate task ~25ms in the future.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        writer.push(Direction::Cmd, 0, 0x61, &[], 25);
    });

    let seq = wait_for_command(&log, 0x61, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(seq, 0);
}

#[tokio::test]
async fn times_out_when_nothing_matches() {
    let log = Arc::new(LogInner::new(8));
    let res = wait_for_command(&log, 0x61, Duration::from_millis(20), 0).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn ignores_non_matching_entries_then_wakes_for_match() {
    let log = Arc::new(LogInner::new(8));
    let writer = Arc::clone(&log);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        writer.push(Direction::Cmd, 0, 0x62, &[], 10); // CAP — wrong code
        tokio::time::sleep(Duration::from_millis(10)).await;
        writer.push(Direction::Reply, 0, 0x61, &[], 20); // wrong direction
        tokio::time::sleep(Duration::from_millis(10)).await;
        writer.push(Direction::Cmd, 0, 0x61, &[], 30); // ← this one
    });

    let seq = wait_for_command(&log, 0x61, Duration::from_millis(500), 0)
        .await
        .unwrap();
    // Should be seq 2 (the third pushed entry; the first two were
    // skipped by code/direction mismatch).
    assert_eq!(seq, 2);
}
