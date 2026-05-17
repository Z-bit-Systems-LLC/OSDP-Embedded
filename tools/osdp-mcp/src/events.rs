// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Event queue — pending PD-initiated reports waiting for the next
//! POLL to surface them.
//!
//! OSDP is master-slave: a PD never spontaneously transmits. When a
//! real card-read happens at the reader, the PD stashes the data and
//! reports it on the next inbound POLL (as RAW instead of ACK).
//! Same shape for keypad presses (KEYPAD) and tamper/power changes
//! (LSTATR).
//!
//! `inject_*` tools enqueue pre-baked [`OverrideReply`] values; the
//! handler pops one per POLL after the override table misses, so an
//! agent can mix scripted replies with realistic events without
//! either stomping on the other.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::overrides::OverrideReply;

/// FIFO of pending PD-initiated reports. Drains one entry per POLL.
pub type EventQueue = Arc<Mutex<VecDeque<OverrideReply>>>;

pub fn new_queue() -> EventQueue {
    Arc::new(Mutex::new(VecDeque::new()))
}

pub fn enqueue(q: &EventQueue, e: OverrideReply) {
    q.lock().expect("event queue mutex").push_back(e);
}

/// Pop the head of the queue. Called from the handler on POLL after
/// the override table has missed.
pub fn pop(q: &EventQueue) -> Option<OverrideReply> {
    q.lock().expect("event queue mutex").pop_front()
}

pub fn len(q: &EventQueue) -> usize {
    q.lock().expect("event queue mutex").len()
}

pub fn clear(q: &EventQueue) {
    q.lock().expect("event queue mutex").clear()
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
    fn fifo() {
        let q = new_queue();
        enqueue(&q, r(0x50, b"raw1"));
        enqueue(&q, r(0x53, b"kp"));
        assert_eq!(len(&q), 2);
        let a = pop(&q).unwrap();
        assert_eq!(a.code, 0x50);
        let b = pop(&q).unwrap();
        assert_eq!(b.code, 0x53);
        assert!(pop(&q).is_none());
        assert_eq!(len(&q), 0);
    }

    #[test]
    fn clear_drops_all() {
        let q = new_queue();
        enqueue(&q, r(0x50, &[]));
        enqueue(&q, r(0x53, &[]));
        clear(&q);
        assert!(pop(&q).is_none());
    }
}
