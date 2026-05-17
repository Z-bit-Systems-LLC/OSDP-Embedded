// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Per-command override table.
//!
//! The default [`crate::handler::DefaultHandler`] consults this table
//! before falling through to its built-in match, so an agent can pin
//! a custom reply (or sequence of replies) for any given cmd_code at
//! runtime — without rebuilding or restarting the PD.
//!
//! Three shapes are supported:
//!
//!   - **Static** — same reply for every matching command.
//!   - **Script** — pop-front queue of replies; falls back to the
//!     default behavior once exhausted (unless `cycle = true`, in
//!     which case popped steps go to the back).
//!   - (Sugar) **nak_next** — a Script of length 1 holding a NAK
//!     reply with the requested NAK error code. Convenient for
//!     "make the PD NAK the next thing, then resume normal service".
//!
//! Storage is an `Arc<Mutex<HashMap<u8, Override>>>` shared between
//! the handler (reader, called from the PD actor thread) and the MCP
//! tool methods (writers, called from the Tokio reactor). Lock
//! contention is negligible — the handler's read is microseconds,
//! the writers are user-initiated.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use osdp_embedded::messages::OSDP_REPLY_NAK;

/// One pre-baked reply: code + payload bytes ready to copy into the
/// handler's scratch buffer.
#[derive(Debug, Clone)]
pub struct OverrideReply {
    pub code: u8,
    pub payload: Vec<u8>,
}

/// What to do when an override is registered for a given cmd_code.
#[derive(Debug, Clone)]
pub enum Override {
    /// Always reply with this exact value.
    Static(OverrideReply),
    /// Queue of replies. Each handler invocation pops one from the
    /// front. When the queue empties:
    ///
    ///   - `cycle == false` (default): the override is removed and
    ///     subsequent commands fall through to the default handler.
    ///   - `cycle == true`: popped steps go to the back, so the
    ///     queue loops forever.
    Script {
        steps: VecDeque<OverrideReply>,
        cycle: bool,
    },
}

/// Shared map of cmd_code → Override. Created once at startup,
/// cloned into the handler and the PD handle.
pub type OverrideMap = Arc<Mutex<HashMap<u8, Override>>>;

pub fn new_map() -> OverrideMap {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Look up + consume one step (if any). Returns the [`OverrideReply`]
/// to send, or `None` if no override applies for this cmd_code.
///
/// Called from the handler on every accepted command, so it stays
/// `&self` on the map (locks internally).
pub fn take_for(map: &OverrideMap, cmd_code: u8) -> Option<OverrideReply> {
    let mut m = map.lock().expect("override map mutex");
    match m.get_mut(&cmd_code) {
        None => None,
        Some(Override::Static(r)) => Some(r.clone()),
        Some(Override::Script { steps, cycle }) => {
            let step = steps.pop_front()?;
            if *cycle {
                steps.push_back(step.clone());
                Some(step)
            } else if steps.is_empty() {
                // Drop the entry so future commands hit the default.
                let cloned = step;
                m.remove(&cmd_code);
                Some(cloned)
            } else {
                Some(step)
            }
        }
    }
}

/// Install (or replace) a static reply for `cmd_code`.
pub fn set_static(map: &OverrideMap, cmd_code: u8, reply: OverrideReply) {
    map.lock()
        .expect("override map mutex")
        .insert(cmd_code, Override::Static(reply));
}

/// Install (or replace) a scripted sequence for `cmd_code`.
pub fn set_script(map: &OverrideMap, cmd_code: u8, steps: Vec<OverrideReply>, cycle: bool) {
    map.lock().expect("override map mutex").insert(
        cmd_code,
        Override::Script {
            steps: steps.into(),
            cycle,
        },
    );
}

/// Convenience for "next time this cmd arrives, NAK with `nak_code`,
/// then resume default behavior". Builds a one-step script.
pub fn nak_next(map: &OverrideMap, cmd_code: u8, nak_code: u8) {
    set_script(
        map,
        cmd_code,
        vec![OverrideReply {
            code: OSDP_REPLY_NAK,
            payload: vec![nak_code],
        }],
        false,
    );
}

/// Drop every override. Subsequent commands fall straight to the
/// default handler.
pub fn clear(map: &OverrideMap) {
    map.lock().expect("override map mutex").clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(code: u8, payload: &[u8]) -> OverrideReply {
        OverrideReply {
            code,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn no_override_returns_none() {
        let m = new_map();
        assert!(take_for(&m, 0x60).is_none());
    }

    #[test]
    fn static_repeats_forever() {
        let m = new_map();
        set_static(&m, 0x60, r(0x40, b""));
        for _ in 0..5 {
            let got = take_for(&m, 0x60).unwrap();
            assert_eq!(got.code, 0x40);
        }
    }

    #[test]
    fn script_consumes_then_falls_through() {
        let m = new_map();
        set_script(&m, 0x60, vec![r(0x41, &[0x03]), r(0x40, b"")], false);
        let a = take_for(&m, 0x60).unwrap();
        assert_eq!(a.code, 0x41);
        let b = take_for(&m, 0x60).unwrap();
        assert_eq!(b.code, 0x40);
        // Exhausted — overrides should be gone now.
        assert!(take_for(&m, 0x60).is_none());
    }

    #[test]
    fn cycle_loops_forever() {
        let m = new_map();
        set_script(&m, 0x60, vec![r(0x41, &[]), r(0x40, &[])], true);
        let seq: Vec<u8> = (0..5).map(|_| take_for(&m, 0x60).unwrap().code).collect();
        assert_eq!(seq, vec![0x41, 0x40, 0x41, 0x40, 0x41]);
    }

    #[test]
    fn nak_next_replies_once_then_clears() {
        let m = new_map();
        nak_next(&m, 0x60, 0x03);
        let got = take_for(&m, 0x60).unwrap();
        assert_eq!(got.code, OSDP_REPLY_NAK);
        assert_eq!(got.payload, vec![0x03]);
        assert!(take_for(&m, 0x60).is_none());
    }

    #[test]
    fn clear_removes_all() {
        let m = new_map();
        set_static(&m, 0x60, r(0x40, b""));
        set_static(&m, 0x61, r(0x45, b""));
        clear(&m);
        assert!(take_for(&m, 0x60).is_none());
        assert!(take_for(&m, 0x61).is_none());
    }
}
