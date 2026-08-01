// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Monitored device state behind the four OSDP status queries.
//!
//! `osdp_LSTAT` / `ISTAT` / `OSTAT` / `RSTAT` ask the PD to report a
//! *condition that persists* — tamper, power, input contacts, output relays,
//! reader tamper — as distinct from an event, which is a one-shot report of
//! something that just happened. The library owns the reply layout; this
//! module owns the values, and [`crate::pd_actor`] binds it via
//! `Pd::set_status_providers`.
//!
//! Before this existed the virtual PD answered `osdp_LSTAT` with a hard-coded
//! "all clear" and NAK'd the other three with 0x03 — while its PDCAP
//! advertised one input, one output and one reader. An ACU that believed the
//! capability record and asked got an "unknown command" for a capability the
//! PD had just claimed.
//!
//! ## Events and state are separate on purpose
//!
//! Injecting a tamper does two things: it flips the condition here (so a
//! later `osdp_LSTAT` reports it) and it queues an `osdp_LSTATR` event (so
//! the next `osdp_POLL` reports the *change* unprompted). Spec 7.6 wants
//! both — the report announces the transition, the state answers the query.
//! [`crate::events`] owns the first half.
//!
//! The power-up `osdp_LSTATR` queued at PD open is deliberately event-only:
//! it announces "I just booted" with the power bit set, which is not a
//! standing power-failure condition and must not linger in the answer to
//! every later `osdp_LSTAT`.

use std::sync::{Arc, Mutex};

use osdp_embedded::messages::{
    OSDP_ISTATR_INACTIVE, OSDP_LSTATR_NORMAL, OSDP_OSTATR_ACTIVE, OSDP_OSTATR_INACTIVE,
    OSDP_RSTATR_NORMAL,
};

/// How many objects of each kind the virtual PD has. These must match the
/// `num_objects` fields in the "Secure Reader" PDCAP template
/// (`osdp_embedded::pd::Pd::pdcap_template`) — function code 1 (contact
/// status monitoring), 2 (output control) and 4 (reader LED control)
/// respectively. A status report shorter than the advertised count is a PD
/// contradicting its own capability record.
const INPUT_COUNT: usize = 1;
const OUTPUT_COUNT: usize = 1;
const READER_COUNT: usize = 1;

/// The monitored conditions the four status queries report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStatus {
    /// `OSDP_LSTATR_NORMAL` / `_TAMPER`.
    pub tamper: u8,
    /// `OSDP_LSTATR_NORMAL` / `_POWER_FAILURE`.
    pub power: u8,
    /// One `OSDP_ISTATR_*` byte per input contact.
    pub inputs: Vec<u8>,
    /// One `OSDP_OSTATR_*` byte per output relay, tracked from the
    /// `osdp_OUT` commands the ACU sends (see [`DeviceStatus::apply_output`]).
    pub outputs: Vec<u8>,
    /// One `OSDP_RSTATR_*` byte per reader.
    pub readers: Vec<u8>,
}

impl Default for DeviceStatus {
    fn default() -> Self {
        Self {
            tamper: OSDP_LSTATR_NORMAL,
            power: OSDP_LSTATR_NORMAL,
            inputs: vec![OSDP_ISTATR_INACTIVE; INPUT_COUNT],
            outputs: vec![OSDP_OSTATR_INACTIVE; OUTPUT_COUNT],
            readers: vec![OSDP_RSTATR_NORMAL; READER_COUNT],
        }
    }
}

impl DeviceStatus {
    /// Apply one `osdp_OUT` record so a later `osdp_OSTAT` reports what the
    /// ACU actually commanded rather than a constant.
    ///
    /// Spec Table 14 control codes. `0x00` is NOP and leaves the output
    /// alone — the one value that must not be treated as "off". The
    /// permanent/temporary distinction and the timer are not modelled: this
    /// is a virtual reader with no relay to hold, so both forms collapse to
    /// the state they select, and a timed operation never expires back.
    pub fn apply_output(&mut self, output_no: u8, control_code: u8) {
        let Some(slot) = self.outputs.get_mut(output_no as usize) else {
            // An output the PD never advertised; the library still ACKs the
            // command, we simply have nowhere to record it.
            return;
        };
        match control_code {
            0x01 | 0x03 => *slot = OSDP_OSTATR_INACTIVE, // permanent OFF
            0x02 | 0x04 => *slot = OSDP_OSTATR_ACTIVE,   // permanent ON
            0x05 => *slot = OSDP_OSTATR_ACTIVE,          // temporary ON
            0x06 => *slot = OSDP_OSTATR_INACTIVE,        // temporary OFF
            _ => {}                                      // 0x00 NOP, or reserved
        }
    }
}

/// Shared handle: the MCP tools and HTTP UI write it, the status provider
/// closures bound into the PD read it from inside `pd.tick()`.
pub type SharedStatus = Arc<Mutex<DeviceStatus>>;

/// A fresh status block, all conditions nominal.
pub fn shared() -> SharedStatus {
    Arc::new(Mutex::new(DeviceStatus::default()))
}

/// Record a tamper/power condition. Returns the values actually stored.
///
/// Call alongside queueing the matching `osdp_LSTATR` event — see the module
/// docs on why both are needed.
pub fn set_local(status: &SharedStatus, tamper: u8, power: u8) {
    if let Ok(mut s) = status.lock() {
        s.tamper = tamper;
        s.power = power;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_nominal_and_match_the_advertised_pdcap_counts() {
        let s = DeviceStatus::default();
        assert_eq!(s.tamper, OSDP_LSTATR_NORMAL);
        assert_eq!(s.power, OSDP_LSTATR_NORMAL);
        assert_eq!(s.inputs.len(), INPUT_COUNT);
        assert_eq!(s.outputs.len(), OUTPUT_COUNT);
        assert_eq!(s.readers.len(), READER_COUNT);
    }

    #[test]
    fn output_control_codes_map_to_ostatr_values() {
        let mut s = DeviceStatus::default();

        s.apply_output(0, 0x02); // permanent ON
        assert_eq!(s.outputs[0], OSDP_OSTATR_ACTIVE);

        s.apply_output(0, 0x00); // NOP must not clear it
        assert_eq!(s.outputs[0], OSDP_OSTATR_ACTIVE);

        s.apply_output(0, 0x01); // permanent OFF
        assert_eq!(s.outputs[0], OSDP_OSTATR_INACTIVE);

        s.apply_output(0, 0x05); // temporary ON
        assert_eq!(s.outputs[0], OSDP_OSTATR_ACTIVE);

        s.apply_output(0, 0x06); // temporary OFF
        assert_eq!(s.outputs[0], OSDP_OSTATR_INACTIVE);
    }

    #[test]
    fn an_out_of_range_output_is_ignored_rather_than_panicking() {
        let mut s = DeviceStatus::default();
        s.apply_output(200, 0x02);
        assert_eq!(s.outputs, vec![OSDP_OSTATR_INACTIVE; OUTPUT_COUNT]);
    }

    #[test]
    fn set_local_persists_for_a_later_lstat() {
        let shared = shared();
        set_local(&shared, 1, 0);
        let s = shared.lock().unwrap();
        assert_eq!(s.tamper, 1);
        assert_eq!(s.power, 0);
    }
}
