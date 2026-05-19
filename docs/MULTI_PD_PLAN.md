# osdp-mcp — multi-PD on a shared serial bus

Plan for future implementation. Captured 2026-05-18 after design
discussion. Not yet started; pick this up when the priority warrants.

## Goal

Let one `osdp-mcp` process manage multiple PDs sharing a single serial
line (the realistic multidrop RS-485 case the OSDP spec is built for).
Each PD has its own address, SC config, overrides, events, drop
counter, and stats; the bus itself is shared.

## Locked decisions

- **Bring-up API: additive `pd_configure`.** First call opens the bus
  (port + baud) and adds one PD; subsequent calls add more PDs on the
  same bus. Mismatched port/baud or duplicate address → clear error.
- **Rollout: phase 1 then phase 2.** Phase 1 is an internal refactor
  that introduces the shared-bus design without changing any tool
  signatures; phase 2 exposes the multi-PD API (breaking).

## Design

One process owns one bus owns N PDs. The actor already owns one
`!Send` PD on a dedicated thread; that doesn't change. What changes
is the bus and the per-PD state. Single-threaded throughout — no
new locking.

```
┌───────── actor thread (single Tokio mpsc consumer) ─────────┐
│                                                              │
│  Box<dyn SerialPort>  ──  per-PD inbox VecDeque<u8>          │
│         │           tee     │           │                    │
│         │                   ▼           ▼                    │
│         │              Pd(0x10)    Pd(0x11)                  │
│         │              (own stats,  (own stats,              │
│         └─ write ◄─────  overrides, ─ overrides,             │
│                          events,    events,                  │
│                          dropctr)   dropctr)                 │
└──────────────────────────────────────────────────────────────┘
```

**Reads.** Once per tick the actor pulls bytes from the port and tees
them into every PD's inbox. Each PD's `Transport::read()` drains from
its own inbox. OSDP address filtering inside `Pd` means only the
addressed PD actually accepts the frame.

**Writes.** All PDs share the same serial-port handle
(`Rc<RefCell<…>>`). OSDP is strictly turn-based — the ACU addresses
one PD at a time and waits for its reply — so two PDs writing
simultaneously is impossible by protocol. No arbiter needed.

## Phase 1 — internal `SharedBus` refactor (no API change)

Goal: prove the shared-bus design while every existing test still
passes.

**Files**

- `tools/osdp-mcp/src/serial_transport.rs` → rename to `bus.rs`:
  - `SharedBus { serial: Rc<RefCell<Box<dyn SerialPort>>>, port: String, baud: u32, epoch: Instant }`
  - `PdBusTransport { inbox: Rc<RefCell<VecDeque<u8>>>, serial, epoch }`
    implementing `Transport`. Inbox cap 4096 (drop-oldest on overflow
    with a `tracing::warn!`).
  - `Bus::tick(&self, slots: &[&PdBusTransport])` reads from the wire
    once and tees into each inbox.
- `tools/osdp-mcp/src/pd_actor.rs`:
  - `Slot` gains `inbox: Rc<RefCell<VecDeque<u8>>>` and the bus is
    moved out of `open_pd` into the actor's outer state.
  - Actor's tick loop: `bus.tick(slot.inbox)` → `pd.tick()`. Slot
    count is still 1.
  - `force_session_loss` is rewritten to rebuild only the `Pd`
    struct (keep the port open) — clears the way for phase 2 where
    this can't disturb sibling PDs.
- `tools/osdp-mcp/src/lib.rs` — rename `serial_transport` → `bus` in
  the module list.

**Tests**

- All existing tests pass unchanged (`actor_loopback`, `sc_loopback`,
  `smoke_stdio`, `wait_for_command`, `handler::tests`).
- One new unit test for `SharedBus::tick` fanout (push N bytes,
  assert all subscribed inboxes received them).

**Acceptance**

- Single PD still works identically through every existing tool.
- A `force_session_loss` call doesn't close/reopen the serial port
  (verified by inspecting the new code path).

## Phase 2 — multi-PD API (breaking)

**Files**

- `tools/osdp-mcp/src/pd_actor.rs`:
  - `slots: HashMap<u8, Slot>` (was `Option<Slot>`).
  - `Cmd::Configure { port, baud, address, sc, reply }`:
    - Bus closed → open it with this port/baud, add slot.
    - Bus open with matching port/baud → add slot (error on duplicate
      address).
    - Bus open with mismatching port/baud → error
      `"bus already open on COM3@9600; stop everything first"`.
  - `Cmd::Stop { address: Option<u8>, reply }` — `Some` removes one
    slot (closes bus if it was the last); `None` tears everything
    down.
  - `Cmd::Status { reply }` returns `Vec<PdStatus>`, each tagged with
    `address`.
  - Per-PD `overrides` / `events` / `drop_remaining` / `stats` move
    from `PdHandle` to `Slot`. `PdHandle` methods take `address: u8`.
- `tools/osdp-mcp/src/log.rs`:
  - `snapshot(since_seq, limit, address: Option<u8>)` and
    `find_command_at_or_after(since_seq, cmd_code, address: Option<u8>)`.
    Log itself stays unified — one timeline across all PDs.
- `tools/osdp-mcp/src/main.rs` — tool signature changes:
  - **Add required `address`**: `set_reply_for`, `set_reply_script`,
    `nak_next`, `inject_raw`, `inject_keypad`, `inject_local_status`,
    `drop_next_n_replies`, `force_session_loss`.
  - **Add optional `address`**: `pd_stop`, `clear_overrides`,
    `clear_events`, `get_log`, `wait_for_command` (omitted = "all" or
    "any PD" depending on the verb).
  - **Return type change**: `pd_status` returns `Json<Vec<PdStatus>>`.
  - Tool docstrings updated to match.

**Tests**

- New integration `tests/multi_pd_loopback.rs`: pair 2 PDs (0x10,
  0x11) on a shared in-memory bus with one in-process `Acu`
  registering both; verify each responds to its own POLL/ID and
  ignores the other's traffic; verify overrides set on 0x10 don't
  affect 0x11.
- New unit test for `pd_actor`: configure two PDs, then
  force-session-loss on 0x10 — confirm 0x11's session state is
  untouched.

**Docs**

- `README.md` MCP section: `pd_configure` is additive, `address` is
  required on most tools, `pd_status` returns an array. Add a 2-PD
  example workflow.

## Risks / edges

- **Inbox overflow.** A slow PD that doesn't drain its inbox
  (debugger paused, long sync override callback) loses oldest bytes.
  Cap + warning is the right policy — better than
  head-of-line-blocking the wire for every other PD.
- **Per-frame framing cost.** Every PD's stream decoder processes
  every byte on the wire. With 9600 baud (~1 kB/s) and 4 PDs that's
  ~4 kB/s of frame work — negligible.
- **Bus close timing.** When the last PD on a bus is stopped, the
  port closes. If a `pd_configure` races in the same tick, the bus
  needs to re-open cleanly. Already serialized today by the actor's
  command dispatch.
- **`pd_status` cursor/version.** Snapshots are no longer
  single-document; agents that diff "before vs after" need to key by
  address. Document this in the README.

## Out of scope (for both phases)

- RS-485 direction-control GPIO. The current `SerialTransport` doesn't
  manage DE/RE pins; multi-PD doesn't add that requirement. Hardware
  that needs it ships its own adapter on a future iteration.
- Multi-bus per process. One `osdp-mcp` instance still owns one bus.
  If two physical lines are needed, run two processes (HTTP transport
  + different `--bind` makes that ergonomic).
- Per-PD PDID/PDCAP overrides. Today every PD reports the same
  defaults from `handler::default_pdid()` / `default_pdcap()`; per-PD
  overrides would be a follow-on once the multi-PD API stabilises.
