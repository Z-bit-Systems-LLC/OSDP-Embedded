# SC2 Benchmark bring-up — session notes (updated 2026-08-11)

Working notes for the live SC2 Benchmark investigation, written to be picked up
cold. Covers what shipped, what the hardware turned out to be doing, and the
57600 baud anomaly — which turned out to be our own spec-5.8 timeout and is
now fixed (§5).

Companion to [BENCHMARK_PD_PLAN.md](BENCHMARK_PD_PLAN.md), which holds the
overall plan; this file is the record of a specific debugging arc.

---

## 1. Repo state

| Branch | Head | Remote |
| --- | --- | --- |
| `main` | `7e7ec0a` fix(pd): size the spec 5.8 timeout for transports that batch their RX | **ahead by 1, NOT pushed** |
| `feature/osdp-sc2` | `afe14fd` Merge branch 'main' into feature/osdp-sc2 | **ahead by 1, NOT pushed** |
| `pair-conformance` | `262f99c` Merge branch 'feature/osdp-sc2' into pair-conformance | **ahead by 1, NOT pushed** |

`fix-short-write` was verified merged into `main` and deleted.

All three merges were clean — the fix touches `osdp_types.h`, `core/CMakeLists.txt`
and the `osdp_pd.h` timeout block, none of which the SC2/pairing branches had
diverged in.

**Uncommitted, on `pair-conformance`:** `tests/test_pd_pair.c` — four scratch
buffers resized from a hardcoded `1024` to `OSDP_FRAME_MAX_LEN`. Needed because
the test harness could not hold a fragment from a PD built with
`OSDP_PD_BUF_LEN=1440`. Test-only. (It does **not** belong on `main` — the file
does not exist there; the earlier note saying otherwise was wrong.) Plus the
diagnostic tooling in §7 item 4 and this document.

---

## 2. What shipped: the spec 5.8 inter-character timeout

**The bug.** A single byte lost on the line took the link down permanently.
The truncated frame's bytes stayed in the stream decoder, so the sender's
retransmission was parsed as the *tail* of the abandoned frame, failed its CRC,
and was answered `osdp_NAK 0x01`. Every retry met the same misalignment.

**The spec already required the fix** (5.8): *"If there is an inter-character
timeout while receiving the message the PD shall abort the receive sequence"*,
nominal 20 ms. It had never been implemented.

**The split**, because `core/` is freestanding and cannot time anything:

- `osdp_stream_pending()` (core) reports bytes held awaiting a complete frame.
- `check_interchar_timeout()` (`pd/src/pd.c`) owns the clock and aborts when
  that count stops advancing for `OSDP_PD_INTERCHAR_TIMEOUT_MS` (20, `#ifndef`
  guarded).

Comparing the *count* rather than merely its presence is what distinguishes a
stalled frame from one still arriving slowly. A transport with no `now_ms`
never aborts and behaves exactly as before.

Also in that commit: the PD drain loop now reads until the transport returns 0
instead of stopping at the first short read (a short read on a UART usually
means the rest of the frame has not clocked in yet), bounded at one stream
buffer per tick so a transport that never runs dry cannot spin.

`osdp_pd_t` grew two fields; `rust/osdp/src/sys.rs` was updated in step and the
layout guard passes.

**Verification.** 26/26 on `main`, 37/37 on the merged SC2 tree, Rust suite
green. The three new PD tests were confirmed to *fail* with the fix neutered —
not merely assumed to cover it.

**This fix is independently correct and stays**, even though it turned out not
to be the cause of the benchmark failures (see §3). On the faulty link our PD
held 6/6 where OSDP.Net's PD managed 2/3; OSDP.Net does not implement 5.8
either. Real RS-485 runs drop bytes.

> **Amended 2026-08-11.** Correct in principle, wrong in its constant: 20 ms is
> shorter than the delivery interval of a USB-serial adapter, so the abort also
> fires on frames that are arriving normally. That is the §5 anomaly, fixed in
> `7e7ec0a` by `OSDP_BUFFERED_TRANSPORT` — see §5.6.

---

## 3. The hardware, which was the actual cause

Most of the investigation chased a protocol bug that did not exist.

**The bench was FTDI (COM3, ACU) ↔ STM32 CDC-ACM (COM7, PD)** —
`VID_0483&PID_5740` on Microsoft's `usbser.sys`. That adapter silently dropped
roughly **1 byte per 40 frames** of ~500 bytes, and `ClearCommError` reported
**no** `CE_RXOVER`, `CE_FRAME` or `CE_OVERRUN` — the driver insisted it had
delivered everything.

**2026-08-10 the CDC unit was swapped for a second FTDI. The PD port is now
COM4.** Large-fragment pairing went from 1/4 to 5/5 with no code change.

Wrong turns this caused, recorded so they are not repeated:

1. "OSDP.Net's ACU cannot receive fragments over 128 bytes" — **false**. It
   handles 1426-byte fragments.
2. "The PD's receive queue is overrunning" — **false**. Zero driver errors.
3. "There is a fragment-size threshold between 384 and 448 bytes" — **false**.
   An artifact of n=1 cells against a random fault; 448 passed on retry.
4. "Large fragments are slower than small ones (19.4 s vs 7.9 s)" — **false**.
   That was retry storms. On a sound link large fragments are *faster*:
   message 2 (PD→ACU) took 3685 ms at ~107-byte fragments versus **2376 ms** at
   497-byte fragments. This settles the plan's §2.4 performance question in
   favour of large fragments; `OSDP_PAIR_MAX_FRAGMENT_SIZE` needs no change.

**Lesson for next time:** when a failure is intermittent, verify the physical
link before interpreting any protocol evidence. The cheap test is a raw
513-byte pattern written one way with the bytes counted back — settle ~300 ms
and `DiscardInBuffer` first, or the first iteration reads stale bytes and
reports a false failure.

---

## 4. Results on the good link (FTDI ↔ FTDI, COM3/COM4)

Full benchmark, `--acu-receive-size 1440`, 38400 baud, default 512-byte build:

| Phase | Result |
| --- | --- |
| 0 — interrogation | ID 64 ms, CAP 40 ms, ACURXSIZE 45 ms; PDCAP fn 10 = 512 → ACU sends 498 B fragments |
| 1 — pairing | **1/1, 6738 ms** |
| 2 — SC2 init | **5/5**, min 623 ms, median 810 ms |

Pairing timing profile (6738 ms total): message 1 on the wire 2943 ms (43.7%),
message 2 2376 ms (35.3%), message 3 1367 ms (20.3%). ML-KEM keygen + ML-DSA
sign 9.4 ms, credential verify + key derive 14.4 ms. **Post-quantum crypto is
~0.4% of the exchange; moving ~12 KB is the entire cost.**

Large-fragment sweep, 38400 baud, 512-byte build: **5/5**.

---

## 5. ANSWERED (2026-08-11): our own spec-5.8 inter-character timeout

The 57600 failure is **the PD aborting mid-frame receives of the pairing
fragments**, under `OSDP_PD_INTERCHAR_TIMEOUT_MS` — the 20 ms constant added
by the §2 fix. It is not a baud-rate property, not the ACU, and not the link.

Original observation, for reference:

| Baud | 512-byte build | 1440-byte build (1426 B fragments) |
| --- | --- | --- |
| 38400 | 5/5 | not run |
| **57600** | **0/2** | **0/2** |
| 115200 | 1/2 | 2/2 |
| 230400 | 2/2 | 2/2 |

### 5.1 The evidence

**A/B on the constant alone.** One build differing only in
`/DOSDP_PD_INTERCHAR_TIMEOUT_MS=2000`, three pairing trials per cell, PD
restarted between trials:

| Baud | 20 ms (stock) | 2000 ms |
| --- | --- | --- |
| 38400 | 3/3, 6.56–7.15 s | 3/3, 6.57–6.66 s |
| **57600** | **0/3** | **3/3, 4.68–4.72 s** |
| 115200 | 3/3, 3.09–3.89 s | 3/3, 2.84–2.91 s |

57600 flips from never working to always working, and 115200 gets both faster
and less variable — the stock build was already losing frames there and paying
for them in retries.

**Direct count of the aborts.** `osdp-pd-mock --rx-gap-stats` (added for this)
counts them exactly: on a tick that read no bytes, a residue going from >0 to 0
can only be `check_interchar_timeout` firing, and the residue is how much of a
frame it threw away. Per pairing attempt, stock build:

| Baud | aborts | outcome |
| --- | --- | --- |
| 38400 | 0–2 | passes |
| 57600 | 3–17 | fails |
| 115200 | 1–4 | passes or fails |
| 230400 | 0 | passes |

Each abort costs one ~513-byte fragment: the retained prefix is discarded, the
rest of the frame is parsed as garbage, the PD answers nothing, and the ACU
spends a reply timeout before retrying. Enough of those and OSDP.Net's 8 s
`_replyResponseTimeout` (`ControlPanel.cs:37`) expires inside message 1 —
which is exactly the reported `stage=SendingRequest: timed out after ~8–12 s`.

### 5.2 Why 20 ms is the wrong number for this transport

**RX off a USB-serial adapter does not arrive byte by byte.** It arrives in
clumps spaced by the adapter's latency timer — 16 ms on both bench ports
(`HKLM\SYSTEM\CurrentControlSet\Enum\FTDIBUS\...\Device Parameters\
LatencyTimer` = 16). The measured gap histogram has essentially **nothing
between 1 ms and 15 ms**: reads are either back-to-back within one drain loop
(<1 ms) or a whole delivery interval apart (15–30 ms).

So the 20 ms deadline sits *inside* the normal delivery interval. A frame that
is arriving perfectly can go past 20 ms with no new byte and be thrown away.
Spec 5.8's 20 ms is a wire figure for a directly-attached UART, where at 57600
a byte lands every 0.17 ms; nothing bridging through USB can honour it.

**Why 57600 is the worst.** Two effects pull against each other. The slower the
link, the more delivery boundaries fall inside one frame; the faster the link,
the more likely the whole frame lands in a single clump. At 230400 a 513-byte
frame is 22 ms on the wire and usually arrives in one or two deliveries — zero
aborts. At 38400 the FTDI's 62-byte USB packet fills in 16.1 ms, near enough to
the 16 ms latency timer that deliveries are regular and just inside the
deadline. 57600 is where the packet-fill interval (10.8 ms) and the latency
timer beat against each other, giving the most irregular spacing.

**The rates are not cleanly separated.** Across all runs on 2026-08-11, 115200
failed 2 of 6 and 38400 failed 0 of 5. Read §5's original table as "aborts
happen at every rate below 230400 and 57600 is the worst", not as a threshold.

### 5.3 A lever that looks right and is not

Polling the port faster makes it **worse**. The PD loop asks for
`serial_sleep_ms(2)` but Windows rounds a sleep up to the 15.6 ms timer
quantum, so it really looks about every 15.6 ms. Forcing a true 2 ms sleep (a
high-resolution waitable timer, now opt-in as `OSDP_PD_MOCK_SLEEP=hires`) took
38400 from 2/2 passing to **0/2**: a faster loop simply collects more
consecutive empty reads inside one delivery interval, and the deadline expires
between two clumps. The abort is driven by *when the transport delivers*, not
by how often the PD asks.

### 5.4 How big does the timeout have to be?

Measured directly, rather than reasoned from the adapter's 16 ms latency
timer — which turns out to be nowhere near the whole story. With the timeout
raised to 2 s so no abort ever fires, the **worst quiet interval observed while
the decoder was holding a partial frame**, over two pairing runs per rate:

| Baud | worst mid-frame quiet interval |
| --- | --- |
| 38400 | 47 ms |
| **57600** | **94–110 ms** |
| 115200 | 62 ms |
| 230400 | 31–32 ms |

Non-monotonic, peaking at 57600 — the same shape as the failure table, which is
what confirms the two are the same phenomenon. And when an abort does fire, the
interval that caused it is strikingly repeatable: 93 ms every time at 57600,
63 ms every time at 115200.

Candidate values, three pairing trials per rate each:

| Baud | 20 ms | 40 ms | 150 ms |
| --- | --- | --- | --- |
| 38400 | 3/3 | 3/3 | 3/3 |
| **57600** | **0/3** | **0/3** (9–13 aborts) | **3/3** |
| 115200 | 3/3 | 3/3 | 3/3 |
| 230400 | — | 3/3 | 3/3 |

**40 ms is not enough** — it clears the latency timer but not the 93 ms real
gap. At 150 ms the abort counter reads **0 across all twelve trials**, and
pairing is at its floor (57600: 4.67–4.86 s, matching the 2 s build's 4.68 s).

### 5.5 The ceiling, corrected

`osdp_pd.h:525` says the timeout "must stay well under the ACU's reply
timeout". That framing is misleading about what OSDP.Net's 200 ms actually is.
`Bus.TimeOutReadAsync` (`Bus.cs:666`) builds a **fresh**
`CancellationTokenSource(ReplyTimeout)` per read, and all three reply phases
(`WaitForStartOfMessage` / `WaitForMessageLength` / `WaitForRestOfMessage`)
loop over it. So the 200 ms is a **per-read inter-byte timeout, restarted by
every byte received** — not a budget for the whole reply. Two consequences:

- **OSDP.Net's own spec-5.8 equivalent is 200 ms.** Our 20 ms was an order of
  magnitude tighter than the implementation we interoperate with, which is why
  the PD→ACU direction never showed this failure: the ACU tolerates the same
  60–110 ms clumps that were killing us.
- The real constraint is **abort before the retransmission starts arriving**.
  The ACU's clock starts after `IdleLineDelay(commandLen)`, i.e. about when the
  command's last byte lands — the same instant the PD's stall clock starts. It
  then stays silent for the full 200 ms before giving up, plus a bus-loop
  iteration and a write. 150 ms leaves ≥50 ms of that, and the §2 recovery
  behaviour is preserved: the PD is resynchronized and ready before the retry.

So the usable window on this bench is roughly **(110, 200) ms**, and it is
narrow. That narrowness is itself the finding — a fixed wall-clock constant has
to fit between a batching transport's delivery interval and the peer's retry,
and on a USB bridge those are within 2× of each other.

### 5.6 Fixed — `OSDP_BUFFERED_TRANSPORT`

Committed to `main` as `7e7ec0a` and merged forward through
`feature/osdp-sc2` into `pair-conformance` (all three merges clean).

A compile-time flag selects between the two defaults:

```c
#ifndef OSDP_PD_INTERCHAR_TIMEOUT_MS
#  ifdef OSDP_BUFFERED_TRANSPORT
#    define OSDP_PD_INTERCHAR_TIMEOUT_MS 150U
#  else
#    define OSDP_PD_INTERCHAR_TIMEOUT_MS 20U
#  endif
#endif
```

Three decisions worth recording:

- **It describes the wire, not the role**, so it is declared in
  `core/include/osdp/osdp_types.h` and the CMake option lives on `osdp_core`
  PUBLIC — not on `osdp_pd`. The ACU implements no inter-character abort today
  (§5.7), but when it gets one it keys off this same flag instead of a second
  `OSDP_ACU_`-prefixed one. Naming it `OSDP_PD_BUFFERED_TRANSPORT` was the
  first attempt and was wrong for exactly that reason.
- **Whole-build switch, PUBLIC.** The constant is read inside `pd.c` and by
  consumers reasoning about it, so a per-target define would let the two
  disagree silently. A device is attached one way or the other.
- **Default OFF**, so a build that does not set it is byte-identical to
  before. Nothing changes for a directly-attached UART, which is the case
  spec 5.8's 20 ms is written for.

Verified: 12/12 pairing trials across 38400/57600/115200/230400 with zero
aborts; tests 44/44 on `pair-conformance` and 31/31 on `main`, each with the
flag and without.

**Still wanted: a regression test for a batching transport** — feed one frame
in clumps 100 ms apart and assert it still decodes. The existing
`m.now_ms += OSDP_PD_INTERCHAR_TIMEOUT_MS + 1` per byte (`test_pd.c:1433`)
passes at any constant, so it does not cover this.

### 5.7 The ACU has no inter-character abort at all

Turned up while deciding where the flag belongs. `acu/src/acu.c` never calls
`osdp_stream_reset`, and `scan_timeouts_and_offline` clears `slot->waiting` on
`OSDP_ACU_REPLY_TIMEOUT_MS` **without touching `acu->rx`**. So the original §2
bug — a truncated frame's bytes sitting in front of the next one, decoded
across the boundary — is still live on the ACU side, in the receive direction
for PD replies.

Not a regression and not what the flag gates; the 5.8 fix was PD-only from the
start. Logged as an open item rather than fixed here, because it is a
behaviour change on a role this session did not otherwise touch.

---

## 6. Bench setup and how to reproduce

**Hardware.** ACU on **COM3** (FTDI FT232, `FTSER2K`), PD on **COM4** (FTDI,
`FTSER2K`). Confirm with:

```pwsh
Get-CimInstance Win32_PnPEntity | ? { $_.Name -match '\(COM[0-9]+\)' } |
  Select-Object Name, Manufacturer, Service, DeviceID
```

COM7 still enumerates as the STM32 CDC device — it is the **bad** unit, not
part of the bench.

**Builds.** Prepend the VS2022 *Professional* CMake dir to `$env:PATH`.

```pwsh
$vs = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
$env:PATH = "$vs;$env:PATH"
```

| Dir | Constants |
| --- | --- |
| `build` | defaults (`OSDP_PD_BUF_LEN` 512) — 44 tests |
| `build-big1440` | `-DCMAKE_C_FLAGS="/DOSDP_PD_BUF_LEN=1440 /DOSDP_PAIR_MAX_FRAGMENT_SIZE=1440"` |
| `build-merge`, `build-main` | test-only configurations used during the fix |

**Any build driving real hardware wants `-DOSDP_BUFFERED_TRANSPORT=ON`** (§5.6).
The bench is FTDI, i.e. a batching transport, so a default build reproduces the
57600 failure by design. It is not defaulted ON for `OSDP_BUILD_TOOLS` on
purpose: the option changes a library constant that the tests link too, and
coupling it to an unrelated switch would hide that.

Both constant sets pass their full suites (44/44 and 39/39 respectively).
`OSDP_PAIR_MAX_FRAGMENT_SIZE` caps outbound pairing fragments **independently**
of `OSDP_PD_BUF_LEN`; raising only the latter leaves PD→ACU fragments at 512.

**Run a pairing trial:**

```pwsh
# PD
build\tools\osdp-pd-mock\Debug\osdp-pd-mock.exe --port COM4 --baud 38400 --address 0 --pair [-v|-vv]

# ACU (separate shell), from C:\Users\work-tower\Projects\Z-bit\OSDP-SC2-Benchmark
dotnet bin\Release\net10.0\OsdpSc2Benchmark.dll --port COM3 --baud 38400 --address 0 `
  --mode both --acu-receive-size 1440 --sc2-iterations 5 --output report.md
```

Kill the PD between runs or the port stays held. Allow ~0.7 s after starting
the PD before the ACU connects. `--acu-receive-size` controls **PD→ACU**
fragment size; the **ACU→PD** size is derived from our PDCAP fn 10.

**The OSDP.Net control PD** (headless, used to prove failures were not specific
to our stack) is in this session's scratchpad at `ControlPd/`. Rebuild with
`dotnet build ControlPd.csproj -c Release`. Two things it must do, both learned
the hard way:

- Supply a 32-byte `SecurityKey` placeholder — `SC2PdMessageSecureChannel`
  throws without one even though pairing is about to derive the real key.
- **Wait ~15 s after `OnScbkEstablished` before `StopListening`.** That callback
  fires when the PD has derived the key, *before* it sends the confirmation the
  ACU is waiting for. Tearing the port down there makes every run look like an
  ACU timeout — it did, and produced a spurious 0/6.

Control results on the **bad** link (not re-run on the good one): 2/3 at both
fragment sizes.

---

## 7. Open items

1. **Give the ACU an inter-character abort** (§5.7). It has none, and its reply
   timeout does not reset `acu->rx`, so the §2 desync is still live there.
   Behind the same `OSDP_BUFFERED_TRANSPORT` flag.
2. **Regression test for a batching transport** (§5.6) — one frame in clumps
   100 ms apart must still decode.
3. **Commit the `test_pd_pair.c` buffer resize.** Note it is NOT on `main` —
   the file only exists on the pairing branches, so the earlier note that it
   "belongs on main" was wrong.
4. **Decide what to keep of the 2026-08-11 diagnostic tooling.** Uncommitted in
   `tools/osdp-pd-mock/`: `--rx-gap-stats` (gap histogram + exact spec-5.8
   abort count), `--run-ms` (exit through the normal shutdown path so an
   unattended trial prints its summary), a timestamp on the `-vv` RX tap, and
   the opt-in `OSDP_PD_MOCK_SLEEP=hires` sleep. Note the `-vv` observer effect
   recorded there: per-byte hex to unbuffered stderr costs enough time to
   change the gaps it is measuring, and on its own turns a passing 57600 link
   into a failing one — use `--rx-gap-stats` for timing questions, not `-vv`.
5. **Re-run the OSDP.Net control PD on the good link.** Its 2/3 is from the
   faulty adapter only. The claim "our PD is more robust than the reference
   because of the 5.8 fix" rests on that comparison and deserves a clean-link
   check — if they also score 5/5 now, the fix's benefit only shows on a lossy
   link, which is a narrower statement than has been made so far.
6. **OSDP.Net `HandleMaxReplySize`** (`src/OSDP.Net/Device.cs:392`) — the base
   `Device` NAKs `osdp_ACURXSIZE` as an unknown command. The full, correct
   handling exists only in the sample `src/PDConsole/PDDevice.cs`. Planned fix
   was to lift it into the base class on their `main` and merge to their
   `feature/osdp-sc2`, then derive `PairingReplyFragmentSize` (hardcoded 128,
   `Device.cs:35`) from it. **Not started**; their repo is untouched and on
   `feature/osdp-sc2`.
7. **Two other OSDP.Net defects** surfaced by the control PD, unreported:
   `SC2PdMessageSecureChannel` requiring a 32-byte key before pairing derives
   one, and `SerialPortOsdpConnection.WriteAsync` throwing `NullReferenceException`
   if the port closes mid-reply.
8. **§2.2 thumbprint-by-reference credentials** — unstarted. **§2.1 validity
   windows** — parked at user request.
