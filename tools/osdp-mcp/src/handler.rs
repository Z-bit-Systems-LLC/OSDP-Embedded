// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Application command handler that turns inbound ACU commands into
//! PD replies.
//!
//! Milestone 2 ships the "default" behavior — the same baseline the
//! [`osdp-pd-mock`](../../../tools/osdp-pd-mock/main.c) tool provides:
//! POLL → ACK, ID → PDID, CAP → PDCAP, LED / BUZ / OUT / TEXT /
//! KEYSET / COMSET → ACK, everything else → NAK (unknown command).
//!
//! Later milestones add an override table the agent can populate via
//! `set_reply_for` etc.; the override check will be wired into the
//! match below.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use osdp_embedded::messages::{
    Pdcap, PdcapRecord, Pdid, OSDP_CMD_BUZ, OSDP_CMD_CAP, OSDP_CMD_COMSET, OSDP_CMD_ID,
    OSDP_CMD_KEYSET, OSDP_CMD_LED, OSDP_CMD_OUT, OSDP_CMD_POLL, OSDP_CMD_TEXT, OSDP_REPLY_ACK,
    OSDP_REPLY_PDCAP, OSDP_REPLY_PDID,
};
use osdp_embedded::pd::{CommandHandler, Reply};

/// PD TX buffer cap as defined by the C side
/// (`OSDP_PD_TX_BUF_LEN` in pd/include/osdp/osdp_pd.h). We size the
/// scratch buffer the handler builds replies into to match — any
/// reply that doesn't fit is a programming error, not user input.
const SCRATCH_LEN: usize = 256;

/// Counters the PD actor exposes through `pd_status`. Shared with
/// the handler so it can stamp the latest cmd/reply on every call.
#[derive(Default, Debug, Clone)]
pub struct PdStats {
    pub last_command_at_ms: Option<u32>,
    pub last_reply_at_ms: Option<u32>,
    pub last_cmd_code: Option<u8>,
    pub last_reply_code: Option<u8>,
}

/// Default PDID — matches the osdp-pd-mock CLI tool so behavior is
/// consistent across the two interop harnesses. Vendor "ZBC" is a
/// placeholder; consumers should override via a future pd_set_pdid
/// tool once they want a realistic device identity.
pub fn default_pdid() -> Pdid {
    Pdid {
        vendor_code: [b'Z', b'B', b'C'],
        model: 0x01,
        version: 0x00,
        serial: 0x0000_0001,
        firmware_major: 0,
        firmware_minor: 1,
        firmware_build: 0,
    }
}

/// Default PDCAP — same minimal set as osdp-pd-mock: one contact
/// monitor / output / card-data-format / reader-LED / buzzer / text
/// output, plus four "CRC support" objects on function code 9.
pub fn default_pdcap() -> Pdcap {
    Pdcap {
        records: vec![
            PdcapRecord {
                function_code: 1,
                compliance_level: 1,
                num_objects: 1,
            }, // contact monitor
            PdcapRecord {
                function_code: 2,
                compliance_level: 1,
                num_objects: 1,
            }, // output control
            PdcapRecord {
                function_code: 3,
                compliance_level: 1,
                num_objects: 1,
            }, // card data fmt
            PdcapRecord {
                function_code: 4,
                compliance_level: 1,
                num_objects: 1,
            }, // reader LED ctrl
            PdcapRecord {
                function_code: 5,
                compliance_level: 1,
                num_objects: 1,
            }, // audible
            PdcapRecord {
                function_code: 6,
                compliance_level: 1,
                num_objects: 1,
            }, // text output
            PdcapRecord {
                function_code: 9,
                compliance_level: 1,
                num_objects: 4,
            }, // CRC support
        ],
    }
}

/// Application handler. Owns the PDID/PDCAP it reports and a scratch
/// buffer the build helpers serialize into; the `Reply.payload` slice
/// the PD copies out borrows from this buffer.
pub struct DefaultHandler {
    pub pdid: Pdid,
    pub pdcap: Pdcap,
    scratch: [u8; SCRATCH_LEN],
    stats: Arc<Mutex<PdStats>>,
    epoch: Instant,
}

impl DefaultHandler {
    pub fn new(stats: Arc<Mutex<PdStats>>) -> Self {
        Self {
            pdid: default_pdid(),
            pdcap: default_pdcap(),
            scratch: [0; SCRATCH_LEN],
            stats,
            epoch: Instant::now(),
        }
    }
}

impl CommandHandler for DefaultHandler {
    fn handle<'a>(&'a mut self, cmd_code: u8, _payload: &[u8]) -> osdp_embedded::Result<Reply<'a>> {
        let now = self.epoch.elapsed().as_millis() as u32;

        // Decide the reply (and serialise payload into scratch)
        // before touching stats — keeps the &mut self.scratch borrow
        // clean of any cross-field borrows.
        let (reply_code, payload_len) = match cmd_code {
            OSDP_CMD_POLL => (OSDP_REPLY_ACK, 0),
            OSDP_CMD_ID => {
                let n = self.pdid.build(&mut self.scratch)?;
                (OSDP_REPLY_PDID, n)
            }
            OSDP_CMD_CAP => {
                let n = self.pdcap.build(&mut self.scratch)?;
                (OSDP_REPLY_PDCAP, n)
            }
            OSDP_CMD_LED | OSDP_CMD_BUZ | OSDP_CMD_OUT | OSDP_CMD_TEXT | OSDP_CMD_KEYSET
            | OSDP_CMD_COMSET => (OSDP_REPLY_ACK, 0),
            _ => return Err(osdp_embedded::Error::NotSupported),
        };

        // Stats stamp covers both the command arrival and our reply,
        // close enough — the two events happen inside the same tick.
        if let Ok(mut s) = self.stats.lock() {
            s.last_command_at_ms = Some(now);
            s.last_cmd_code = Some(cmd_code);
            s.last_reply_at_ms = Some(now);
            s.last_reply_code = Some(reply_code);
        }

        Ok(Reply {
            code: reply_code,
            payload: &self.scratch[..payload_len],
        })
    }
}
