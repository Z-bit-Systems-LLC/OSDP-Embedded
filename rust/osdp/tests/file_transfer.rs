// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! End-to-end Rust integration test for `osdp_FILETRANSFER` handling via the
//! safe [`FileReceiver`] binding.
//!
//! Scenario (plaintext, no Secure Channel needed):
//!   1. Pair a [`Pd`] with an [`Acu`] over an in-memory wire.
//!   2. Register a [`FileReceiver`] on the PD that records each evaluated
//!      fragment and snapshots the reassembled file on completion.
//!   3. ACU streams a 6-byte file as two `osdp_FILETRANSFER` fragments.
//!   4. Assert the core reassembled the file, the receiver saw both
//!      fragments (the last flagged `complete`), and the ACU captured
//!      `osdp_FTSTAT` replies reporting proceed (0) then processed (1).
//!
//! This exercises the whole binding: the file-receiver thunk (fragment +
//! accumulated buffer slices flow back into Rust), the verdict → FTSTAT
//! mapping, and the enlarged `osdp_pd_t` ABI.

#![cfg(feature = "pd")]
#![cfg(feature = "acu")]

use std::cell::RefCell;
use std::rc::Rc;

use osdp_embedded::acu::{Acu, ReplyEvent, ReplyHandler};
use osdp_embedded::messages::{
    FileTransfer, Ftstat, OSDP_CMD_FILETRANSFER, OSDP_FTSTAT_OK, OSDP_FTSTAT_PROCESSED,
    OSDP_FT_TYPE_OPAQUE, OSDP_REPLY_FTSTAT,
};
use osdp_embedded::pd::{FileFragment, FileReceiver, FileReject, Pd};
use osdp_embedded::Transport;

// ---- In-process wire ------------------------------------------------

#[derive(Default)]
struct Wire {
    a2p: Vec<u8>,
    p2a: Vec<u8>,
}
type SharedWire = Rc<RefCell<Wire>>;

struct WireAdapter<const PD: bool> {
    wire: SharedWire,
}

impl<const PD: bool> Transport for WireAdapter<PD> {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let src = if PD { &mut w.a2p } else { &mut w.p2a };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        src.drain(..n);
        n
    }
    fn write(&mut self, buf: &[u8]) -> usize {
        let mut w = self.wire.borrow_mut();
        let dst = if PD { &mut w.p2a } else { &mut w.a2p };
        dst.extend_from_slice(buf);
        buf.len()
    }
    fn now_ms(&mut self) -> Option<u32> {
        None
    }
}

// ---- File receiver that logs fragments ------------------------------

#[derive(Default)]
struct FileLog {
    fragments: usize,
    completed: bool,
    assembled: Vec<u8>, // reassembly: whole file; streaming: built from fragments
    saw_empty_data: bool, // did any call see info.data empty (streaming)?
}

// Reassembly receiver: snapshots the whole accumulated buffer on completion.
struct CaptureReceiver {
    log: Rc<RefCell<FileLog>>,
}
impl FileReceiver for CaptureReceiver {
    fn on_fragment(&mut self, f: &FileFragment) -> Result<(), FileReject> {
        let mut l = self.log.borrow_mut();
        l.fragments += 1;
        if f.complete {
            l.completed = true;
            l.assembled = f.data.to_vec();
        }
        Ok(())
    }
}

// Streaming receiver: no buffer from the core — reconstructs the file itself
// by appending each fragment, and records that `data` is empty.
struct StreamReceiver {
    log: Rc<RefCell<FileLog>>,
}
impl FileReceiver for StreamReceiver {
    fn on_fragment(&mut self, f: &FileFragment) -> Result<(), FileReject> {
        let mut l = self.log.borrow_mut();
        l.fragments += 1;
        if f.data.is_empty() {
            l.saw_empty_data = true;
        }
        l.assembled.extend_from_slice(f.fragment);
        if f.complete {
            l.completed = true;
        }
        Ok(())
    }
}

// ---- ACU reply capture ----------------------------------------------

#[derive(Default)]
struct Captured {
    replies: Vec<(u8, u8, u8, Vec<u8>)>, // (pd_addr, cmd, reply, payload)
}
struct ReplyCapture {
    inner: Rc<RefCell<Captured>>,
}
impl ReplyHandler for ReplyCapture {
    fn on_reply(&mut self, e: &ReplyEvent<'_>) {
        self.inner.borrow_mut().replies.push((
            e.pd_address,
            e.cmd_code,
            e.reply_code,
            e.payload.to_vec(),
        ));
    }
}

fn cycle(pd: &mut Pd, acu: &mut Acu, n: usize) {
    for _ in 0..n {
        pd.tick();
        acu.tick();
    }
}

const PD_ADDRESS: u8 = 0x10;

#[test]
fn file_transfer_reassembles_and_reports_ftstat() {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let log = Rc::new(RefCell::new(FileLog::default()));

    // ---- PD side ----
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_file_receiver(
        256,
        CaptureReceiver {
            log: Rc::clone(&log),
        },
    );

    // ---- ACU side ----
    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");

    // The file: 6 bytes streamed as two fragments (4 + 2).
    let file = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

    // Fragment 1: offset 0, first 4 bytes.
    let mut p1 = [0u8; 32];
    let n1 = FileTransfer {
        ft_type: OSDP_FT_TYPE_OPAQUE,
        total_size: file.len() as u32,
        offset: 0,
        data: &file[..4],
    }
    .build(&mut p1)
    .expect("build fragment 1");
    acu.send_command(PD_ADDRESS, OSDP_CMD_FILETRANSFER, &p1[..n1])
        .expect("send fragment 1");
    cycle(&mut pd, &mut acu, 6);

    // Fragment 2: offset 4, last 2 bytes (completes the file).
    let mut p2 = [0u8; 32];
    let n2 = FileTransfer {
        ft_type: OSDP_FT_TYPE_OPAQUE,
        total_size: file.len() as u32,
        offset: 4,
        data: &file[4..],
    }
    .build(&mut p2)
    .expect("build fragment 2");
    acu.send_command(PD_ADDRESS, OSDP_CMD_FILETRANSFER, &p2[..n2])
        .expect("send fragment 2");
    cycle(&mut pd, &mut acu, 6);

    // ---- The core reassembled the file and the receiver saw it ----
    let l = log.borrow();
    assert_eq!(
        l.fragments, 2,
        "receiver should be called once per fragment"
    );
    assert!(l.completed, "final fragment must be flagged complete");
    assert_eq!(l.assembled, file, "reassembled buffer must match the file");

    // ---- The ACU captured proceed(0) then processed(1) FTSTATs ----
    let cap = captured.borrow();
    let ftstats: Vec<_> = cap
        .replies
        .iter()
        .filter(|r| r.1 == OSDP_CMD_FILETRANSFER)
        .collect();
    assert_eq!(ftstats.len(), 2, "expected one FTSTAT per fragment");
    assert_eq!(ftstats[0].2, OSDP_REPLY_FTSTAT);
    assert_eq!(ftstats[1].2, OSDP_REPLY_FTSTAT);

    let s0 = Ftstat::decode(&ftstats[0].3).expect("decode FTSTAT 1");
    assert_eq!(
        s0.status_detail, OSDP_FTSTAT_OK,
        "mid-file fragment should report proceed (0)"
    );
    let s1 = Ftstat::decode(&ftstats[1].3).expect("decode FTSTAT 2");
    assert_eq!(
        s1.status_detail, OSDP_FTSTAT_PROCESSED,
        "final fragment should report processed (1)"
    );
}

#[test]
fn file_transfer_streaming_no_buffer() {
    let wire = Rc::new(RefCell::new(Wire::default()));
    let log = Rc::new(RefCell::new(FileLog::default()));

    // ---- PD side: streaming receiver, NO buffer ----
    let mut pd = Pd::new(PD_ADDRESS);
    pd.set_transport(WireAdapter::<true> {
        wire: Rc::clone(&wire),
    });
    pd.set_file_stream(StreamReceiver {
        log: Rc::clone(&log),
    });

    // ---- ACU side ----
    let captured = Rc::new(RefCell::new(Captured::default()));
    let mut acu = Acu::new(1);
    acu.set_transport(WireAdapter::<false> {
        wire: Rc::clone(&wire),
    });
    acu.set_reply_handler(ReplyCapture {
        inner: Rc::clone(&captured),
    });
    acu.register_pd(0, PD_ADDRESS).expect("register_pd");

    let file = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

    let mut p1 = [0u8; 32];
    let n1 = FileTransfer {
        ft_type: OSDP_FT_TYPE_OPAQUE,
        total_size: file.len() as u32,
        offset: 0,
        data: &file[..4],
    }
    .build(&mut p1)
    .expect("build fragment 1");
    acu.send_command(PD_ADDRESS, OSDP_CMD_FILETRANSFER, &p1[..n1])
        .expect("send fragment 1");
    cycle(&mut pd, &mut acu, 6);

    let mut p2 = [0u8; 32];
    let n2 = FileTransfer {
        ft_type: OSDP_FT_TYPE_OPAQUE,
        total_size: file.len() as u32,
        offset: 4,
        data: &file[4..],
    }
    .build(&mut p2)
    .expect("build fragment 2");
    acu.send_command(PD_ADDRESS, OSDP_CMD_FILETRANSFER, &p2[..n2])
        .expect("send fragment 2");
    cycle(&mut pd, &mut acu, 6);

    // Streaming: core passed no buffer (data empty), but the app rebuilt the
    // file from the per-fragment bytes.
    let l = log.borrow();
    assert_eq!(l.fragments, 2);
    assert!(l.completed);
    assert!(
        l.saw_empty_data,
        "streaming mode must expose empty info.data"
    );
    assert_eq!(
        l.assembled, file,
        "fragments reassembled by the app must match"
    );

    // The ACU still saw proceed(0) then processed(1).
    let cap = captured.borrow();
    let ftstats: Vec<_> = cap
        .replies
        .iter()
        .filter(|r| r.1 == OSDP_CMD_FILETRANSFER)
        .collect();
    assert_eq!(ftstats.len(), 2);
    let s1 = Ftstat::decode(&ftstats[1].3).expect("decode final FTSTAT");
    assert_eq!(s1.status_detail, OSDP_FTSTAT_PROCESSED);
}
