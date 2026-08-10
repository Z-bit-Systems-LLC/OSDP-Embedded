# Completing the PD for a full SC2 Benchmark run

Status: **proposed** (awaiting sign-off; nothing below is implemented).

**Goal:** finish the PD side of this library so that a reader vendor can link
it into their firmware, flash it, and have
[OSDP-SC2-Benchmark](https://github.com/Z-bit-Systems-LLC/OSDP-SC2-Benchmark)
drive it to completion in `--mode both`.

This is *not* a new application. The PD an embedded developer loads is the
one we already ship — `osdp::core + messages + pd + pair + pd_pair` — with the
existing transport HAL and the two crypto HALs bound to their silicon. What
follows is the work remaining to make that integration possible and correct.

Reference for PD-side behaviour: OSDP.Net
[`docs/pairing-overview.md`](https://github.com/Z-bit-Systems-LLC/OSDP.Net/blob/feature/osdp-sc2/docs/pairing-overview.md)
(`feature/osdp-sc2`), reviewed 2026-08-09.

## 1. What the benchmark exercises

| Phase | Wire | Our state |
| --- | --- | --- |
| Interrogation | `osdp_ID`, `osdp_CAP` cleartext; PDCAP sets the pairing fragment size | ✅ via `osdp_pd_set_pdcap`; ⚠️ not on the legacy path (§3.4) |
| Pairing | one ML-KEM-768 / ML-DSA-44 exchange over `osdp_PAIR` 0xB0 / `osdp_PAIRR` 0x8A | ✅ protocol; ⚠️ conformance gaps (§2) |
| SC2 | five sessions, each `osdp_ID` + `osdp_CAP` + `osdp_KEYSET` | ✅ `pd_sc2.c`, KEYSET key type 0x02 |

The PD responder, the fragment driver, the key schedule, and the deterministic
cleartext→SC2 handoff are all implemented and tested (`core/src/pair/`,
`pd/src/pd_pair.c`, seven Unity suites). The handoff already matches the
overview's critical-timing rule: the SCBK is applied strictly *after* the
Result is transmitted, so the ACU's following CHLNG lands on a ready PD
without a reconnect.

Iteration 8's Phase 5 ACU driver and Phase 6 loopback are **not** on this
path — the benchmark is the ACU.

## 2. Protocol conformance gaps

These come from reading the overview against our code. None blocks a
happy-path first pairing; all four are real divergences from the reference PD.

### 2.1 Certificate validity windows are never checked — DEFERRED

**Status: open, parked for a design discussion (2026-08-10). Not a blocker for
benchmarking.**

`not_before` / `not_after` are encoded and decoded (`cert.c:21-22`, `:106-107`)
but nothing compares them to a clock. The overview says CA-based validation
"verifies that the ACU's certificate is signed by that CA **and has valid
timestamps**", so we are one check short of the reference on every pairing.

Parked rather than dropped because it needs a decision, not just code: many
readers have no RTC, and the core has no time source of its own — pairing
currently reaches a clock only through `osdp_pd_transport_t::now_ms`, which is
a millisecond uptime counter, not a wall clock, and so cannot evaluate a Unix
timestamp at all.

Starting proposal for that discussion: an optional `osdp_pair_time_cb` on the
trust anchor supplying Unix seconds. Bound, the window is enforced; NULL, it is
skipped and that is *documented* as a deliberate downgrade rather than an
oversight. Points to settle — whether NULL should instead be a hard refusal for
a CA-anchored trust config, what a PD with only a monotonic counter is supposed
to do, and whether an expired-but-otherwise-valid peer warrants its own wire
status rather than folding into AUTH_FAIL (0x01).

The benchmark is unaffected: its demo credentials are generated per run, so
they are never outside their window.

### 2.2 Thumbprint-by-reference credentials are rejected

`validate_peer` (`core/src/pair/session.c`) returns `OSDP_ERR_NOT_SUPPORTED`
for anything but `OSDP_PAIR_CRED_CERT`, even though the message codecs already
decode and size-check `OSDP_PAIR_CRED_THUMBPRINT` (`messages.c:155`, `:203`).

The overview describes the thumbprint as "a compact by-reference credential
**after initial pairing**." A first pairing sends the full cert, so the
benchmark's default run is unaffected — but re-pairing against a known ACU
fails. Closing this means matching the presented thumbprint against a cached
peer, which implies the PD stores one.

### 2.3 No re-pairing policy

OSDP.Net has a `RePairingPolicy`: with a key already present and policy
`Deny`, the PD answers status `0x03` (policy) instead of proceeding. We have
no equivalent — a paired PD will happily re-pair with anyone the trust anchor
accepts.

### 2.4 Outbound pairing fragments ignore `osdp_ACURXSIZE`

`pd/src/pd_pair.c:15` pins the outbound fragment size to a compile-time
`OSDP_PAIR_DEFAULT_FRAGMENT_SIZE` (128 bytes) and never consults the ACU's
declared receive capacity, which the core already stores for us
(`osdp_pd_acu_rx_size`).

The benchmark sets `osdp_ACURXSIZE` to 1440 and its own notes call it "the
only lever over PD → ACU fragment size." So Message 2 (~7.7 KB) leaves us in
~62 fragments of 128 bytes, one per POLL, where ~6 would do. Nothing fails —
but this is a *benchmark*, and the cost lands squarely in the PD-processing
column it exists to measure. Fix: size outbound fragments from
`min(osdp_pd_acu_rx_size, osdp_pd_max_reply_payload(pd))`, falling back to 128
when the ACU has not declared one.

### 2.5 Rejection status codes may not line up

We return `OSDP_PAIR_STATUS_POLICY` (0x03) when peer validation fails
(`session.c:163`). The overview uses 0x03 for re-pairing denial and lists
`AUTH_FAIL` (0x01) as the authentication-failure status. If that reading is
right, our credential-rejection path reports the wrong code. Worth confirming
against `PairingStatus` in OSDP.Net before changing anything — it is a
one-line fix but a wire-visible one.

## 3. What an embedded developer cannot do today

### 3.1 Neither crypto backend is shippable

The pairing HAL's only implementation is `tests/pair_test_crypto.c`, a
**`tests/`-only** CMake target (`tests/CMakeLists.txt:60-66`); the SC2 HAL's
only implementation is `tools/osdp-pd-mock/sc2_adapter.c`, tool-local. A
firmware project can link neither.

Promote both to first-class, tests-and-tools-and-firmware targets. Two
carry-over hazards:

- `osdp_pair_test_seed_push` / `_clear` are file-scope globals for KAT
  determinism. Gate them behind a define so a firmware build cannot link a
  seedable RNG.
- `tiny_aes256` publishes `AES256=1` and the `AES_*`→`AES256_*` renames as
  **PUBLIC** usage requirements, so anything linking `tiny_gcm` directly gets
  its own sources recompiled against the 256-bit key schedule — which silently
  corrupts SC1 AES-128 in the same target. The existing `pd_mock_sc2`
  isolation (own static lib, `tiny_gcm`/`tiny_kmac` PRIVATE) must be preserved
  in the move.

Both stay *reference* backends; the guidance remains "bind your hardware AES
and your vendor PQC library to the same two vtables."

### 3.2 No way to provision a device credential

`osdp_pair_local_t` wants an encoded C509 cert, and the matching ML-DSA-44
signing key must sit in the crypto HAL's `user` context. Today the only way to
produce that pair is the inline `make_cert` helper in `tests/test_pd_pair.c:53`.

A host tool (`tools/osdp-pair-provision`) should emit a C header with the
device cert, the device private key, and the trust anchor. It can regenerate
OSDP.Net's demonstration CA deterministically — seed `0x40..0x5F`, already
asserted against the published thumbprint in `tests/test_pair_crypto.c:72` —
so demo-CA-signed device certs are reproducible without contacting anything.

The overview also allows a **self-signed** device cert (issuer `"self"`,
`OSDP_C509_SELF_ISSUER` already exists), which pairs with the ACU pinning our
thumbprint. The tool should support both, since §5.1 is unresolved.

The demo CA private key must not land in a firmware image: it is derivable
from a public seed by anyone, so this is about not letting it be mistaken for
a production credential. The tool derives it at build time and emits only the
device cert, the device key, and the CA *public* key.

### 3.3 `osdp_pd_pair_t` is ~22 KB and not tunable

`OSDP_PAIR_MSG_MAX` is 8192 (`core/include/osdp/osdp_pair.h:59`) and is used
for **both** `inbuf` and `outbuf`. Unlike `OSDP_PD_BUF_LEN` and
`OSDP_STREAM_BUFFER_LEN` it is **not `#ifndef`-guarded**, so an integrator
cannot override it — against the project's own convention.

Worse, one shared ceiling wastes headroom: the PD's largest inbound message is
Msg1 at ~5.3 KB and its largest outbound is Msg2 at ~7.7 KB. Splitting into
separate inbound/outbound constants takes the struct from ~22 KB to ~14 KB
with no protocol change. On top of that sits the PQC library's own stack —
"tens of KB" for reference PQClean per `pairing-design.md` §7 — which is the
number that actually decides whether a given part can pair at all.

### 3.4 PDCAP fn 10 — the library already handles it; `osdp-pd-mock` doesn't

**The library computes fn 10 for itself.** `osdp_pd_internal_fill_reserved_pdcap`
(`pd/src/pd_pdcap.c`) derives Receive BufferSize as
`min(pd->rx_plain_cap, OSDP_STREAM_BUFFER_LEN)` and emits it LSB-then-MSB —
the CLAUDE.md encoding trap, already handled. It is one of three reserved
codes (8, 9, 10) injected into every `osdp_CAP` answer, recomputed fresh from
the PD rather than trusted from the application, and `osdp_pd_set_pdcap`
rejects an application that tries to supply them. Deriving it from
`rx_plain_cap` rather than `OSDP_PD_BUF_LEN` directly is the better choice:
it tracks the buffer actually bound, including one rebound at run time via
`osdp_pd_set_buffers`.

So a PD that binds its capabilities with `osdp_pd_set_pdcap` reports fn 10
correctly with no work at all, and needs nothing from this plan.

**The gap is the legacy path.** `handle_pdcap` only runs when
`pd->pdcap_count != 0`; with nothing bound, `osdp_CAP` falls through to
`cmd_cb` and the application hand-builds the reply. That is what
`osdp-pd-mock` still does (`tools/osdp-pd-mock/main.c:318`, over its own
`kDefaultPdcap` at `:76-89`, which has no fn 10 record).

That matters because the ACU sizes its outbound pairing fragments from the
reported receive-buffer capability and falls back to
`DefaultFragmentSize = 1024` (`Program.cs:119`) when the PD reports nothing
usable — 1024-byte fragments into a PD whose buffer defaults to 512. The fix
is migrating `osdp-pd-mock` to `osdp_pd_set_pdcap` (folded into 4.5), not new
library work.

Function code 9 currently claims compliance level 1 (AES128). SC2 has no
SIA-assigned PDCAP value — see §5.3.

## 4. Phases

### 4.0 — Validate the SC2 half on the bench (no new code)

Run `--mode sc2 --scbk <hex>` against today's `osdp-pd-mock --sc=scbk2:<hex>`
at 38400 (`--mode sc2` requires `--scbk`; there is no pairing phase to derive
one). Confirms framing, addressing, and `osdp_ACURXSIZE` handling. The KEYSET
key-type risk is already retired on paper (§5) — this is the live check.

**Done when:** a report exists with five SC2 sessions and no NAKs.

### 4.1 — Close the conformance gaps (§2) — MOSTLY DONE

- ☑ **§2.4 outbound fragment sizing.** `osdp_pd_max_fragment_payload` resolved
  once when Message 2 is queued, clamped to `OSDP_PAIR_MAX_FRAGMENT_SIZE`.
  Was a correctness bug as well as a speed one: the old fixed 128-byte payload
  overran a default-capacity ACU's declared 128-byte packet. Measured 66 polls
  at 113 bytes → 15 at 497.
- ☑ **§2.3 re-pairing policy.** `osdp_pd_pair_set_deny_repair`, default allow,
  answering POLICY (0x03). In the driver, not the session, and checked before
  authentication.
- ☑ **§2.5 rejection status.** Refused credential is now AUTH_FAIL (0x01);
  0x03 is reserved for policy declines per `PairingStatus`.
- ☐ **§2.2 thumbprint-by-reference credentials.** Independent of the rest; no
  decision needed, just implementation plus a cached-peer store.
- ⏸ **§2.1 validity windows.** Parked for discussion — see §2.1.

**Done when:** §2.2 lands and the C suite is green.

### 4.2 — Make the backends shippable (§3.1)

Move both, gate the deterministic-seed hook, preserve the `tiny_aes256`
isolation. No behaviour change.

**Done when:** all 42 C tests still pass against the relocated targets.

### 4.3 — `tools/osdp-pair-provision` (§3.2)

CA-signed and self-signed modes; emits a credentials header.

**Done when:** a generated header drives `test_pd_pair.c` in place of its
inline `make_cert`.

### 4.4 — Footprint knobs (§3.3)

`#ifndef` guard plus the inbound/outbound split; publish measured RAM, peak
stack and flash for the PD with and without `osdp::pair`.

**Done when:** a documented build overrides the constants and still passes.

### 4.5 — First full `--mode both` run

Wire pairing into `osdp-pd-mock` as the host validation vehicle — *not* as the
embedded deliverable, but because it is the fastest way to prove the stack end
to end before hardware is in the loop. Migrate it off the hand-built
`osdp_pdcap_build` path onto `osdp_pd_set_pdcap` while there, which is what
gets it fn 10 (§3.4).

**Done when:** a benchmark report covers interrogation, one pairing exchange,
and five SC2 sessions.

### 4.6 — Integration guide for reader vendors

The actual hand-off artifact: which targets to link, the two vtables to bind,
the transport HAL, provisioning, PDCAP requirements, the footprint table from
4.4, and the wiring/flags for a benchmark run. Update `docs/PLAN.md` — and fix
its stale "Iteration 8 — ... **(planned)**" heading, which sits above five
completed phases.

### 4.7 — WolfSSL backend

Iteration 8 Phase 7, the production PQC path behind the same
`osdp_pair_crypto_t`. Not needed for a benchmark run — PQClean is already
KAT-matched to OSDP.Net byte-for-byte — but needed before anyone ships.

## 5. Resolved by reading the benchmark source (2026-08-10)

**How the ACU validates our PD cert — CA-based, not pinned.** `Program.cs:645-647`:

```csharp
_acuPairingConfig = new PairingConfiguration(
    PairingCredentials.Generate(new DeviceIdentity("Z-bit Systems", "ACU-Benchmark", "BENCH-0001"), _ca),
    PairingTrustAnchor.FromCa(_ca));          // _ca = CertificateAuthority.Demo()
```

So the provisioning tool (§3.2) must emit a device certificate **signed by the
demonstration CA**. A self-signed cert with issuer `"self"` would be rejected —
`FromCa` is the only anchor configured, and there is no pinning path. Trust
runs both directions off the same demo CA, so our anchor is its public key.

**Re-pairing must default to Allow.** The report the benchmark generates warns
that "pairing between trials depends on the PD accepting re-pairing
(`RePairingPolicy.Allow`)." §2.3 should therefore ship Allow as the default and
treat Deny as opt-in, the opposite of the safer-looking choice.

**`osdp_KEYSET` uses key type 0x02.** `Program.cs:923-925` selects
`KeyType.SecureChannelBaseKeyAes256` for a 32-byte key, matching our
`OSDP_KEYSET_KEY_TYPE_SCBK_AES256`. It re-installs the *same* SCBK rather than
rotating, so no key-tracking work is implied. This retires the main risk in 4.0.

## 5b. Live pairing bring-up — status 2026-08-10

Benchmark `--mode both` against `osdp-pd-mock --pair`, COM3/COM7, 38400.

**Works:** interrogation; the ACU sizes its fragments from our PDCAP fn 10
(498 B); Message 1 transfers in 11 fragments; the PD **accepts** it — the
ACU's demo-CA certificate validates, ML-KEM encapsulation runs, Message 2 is
built and queued.

**Fails:** the ACU never accepts our first `osdp_PAIRR` fragment. It re-sends
a byte-identical POLL (same sequence), so our spec-5.9 retransmit cache
correctly replays the cached reply, and the exchange sits on fragment 0 until
the ACU times out in `AwaitingResponse`.

```
tx[512] reply 0x8A  mp total=7392 off=0 frag=497     <- repeated, offset never advances
rx[9]   FF 53 00 08 00 05 60 DA 99                   <- identical POLL each time
```

Ruled out:

- **Not the certificate.** `test_pair_interop` decodes and verifies a
  certificate OSDP.Net actually emitted, and our regenerated demo CA public
  key is byte-identical to `CertificateAuthority.Demo().PublicKey`
  (SHA-256 `6C1C6507…3CB9`).
- **Not our fragment iterator.** `osdp_mp_frag_iter_next` advances correctly
  and is covered by tests; the repetition is the retransmit cache replaying,
  which is the correct response to an identical command.
- **Not reply size alone.** Forcing small replies via `--acu-receive-size 256`
  fails the same way, just sooner.
- **Not the reply layout.** `PairData.BuildData` is
  `total(2) || offset(2) || fragLen(2) || fragment`, little-endian — what we
  emit.

Open leads, in the order worth trying:

1. Whether the ACU accepts a `osdp_PAIRR` in reply to a plain `osdp_POLL` at
   all. `ControlPanel` calls `SetReceivingMultipartMessaging(...)` around the
   collection loop, and what that changes about the poll it issues has not
   been read yet.
2. Whether our reply frame is well-formed at 511 bytes specifically — the
   largest reply this PD has ever sent. Dumping the full frame header rather
   than just the reply code would settle it.
3. Whether OSDP.Net's reply parser bounds a cleartext reply below what its
   own `osdp_ACURXSIZE` advertised.

## 6. Open questions

1. **Validity windows without an RTC (§2.1)** — is the optional-clock-hook
   proposal acceptable, given a NULL hook means no expiry enforcement?
2. **PDCAP fn 9 under SC2** — leave it at AES128 and let SC2 be discovered by
   handshake, or mint a provisional value alongside the other provisional
   constants in `osdp_pair.h`?
3. **Does the deliverable need a reference MCU port**, or is the integration
   guide plus the two reference backends enough for a reader vendor? This is
   the main thing that would expand scope beyond the phases above.

## 7. Branch placement

Most of this is pairing work and can only live on `feature/osdp-sc2` —
`core/src/pair/`, `pd/src/pd_pair.c`, `tests/pair_test_crypto.c` and all of
SC2 are absent from `main`. Three items are SC2-agnostic, exist on `main`
today in identical form, and are better done there and merged forward.

**Do on `main`, merge into sc2:**

1. **`osdp-pd-mock`'s PDCAP migration (§3.4).** Both branches carry the same
   hand-built `kDefaultPdcap` + `osdp_pdcap_build` path, and both carry
   `osdp_pd_set_pdcap`. Fixing it on `main` fixes `main`'s tool too, and the
   region is one sc2 has not diverged in, so it merges clean.
2. **The `ports/` layout, established with the SC1 backend (§3.1).**
   `aes_adapter.c` and `sc_test_aes.c` are on `main` in the same tool-local /
   tests-local form the SC2 and pairing backends are in on sc2. Creating the
   directory and moving the SC1 backend on `main` means sc2 only *adds* its
   two backends rather than inventing the layout independently — exactly the
   "both branches added the same thing at different positions, auto-merge kept
   both" duplication that bit the first main→sc2 merge.
3. **The outbound fragment-sizing helper (§2.4).** `core/src/shared/multipart.c`
   and `osdp_pd_acu_rx_size` are both on `main`, and `osdp_MFG` is a
   multi-part sender there, so a helper returning
   `min(acu_rx_size, osdp_pd_max_reply_payload(pd))` is generally useful and
   not pairing-specific. sc2 then just calls it from `pd_pair.c`; that call
   site stays an sc2 change.

**Everything else is sc2-only:** all the §2 conformance work, promotion of the
SC2 and pairing backends into `ports/`, the provisioning tool, the
`OSDP_PAIR_MSG_MAX` knobs, WolfSSL, and the stale Iteration 8 heading —
`main`'s PLAN.md has no Iteration 8 at all.

**Cost to weigh.** Per the project's test cadence, `main` commits gate on a
live OSDP.Net / ACU hardware run while feature branches gate on unit tests
with one live run at the end. Routing these three through `main` therefore
buys clean merges at the price of a bench run before they land. Item 2 is the
one worth the trade — a structural divergence is expensive to undo later.
Items 1 and 3 are small enough that doing them on sc2 instead is defensible if
you would rather not open `main`.

## 8. Risks

- **PQC stack on small parts** — tens of KB of stack during pairing on devices
  that may have 32–64 KB of RAM total. Mitigation: measure in 4.4, publish it,
  and keep "don't enable `osdp::pair`, use pre-shared SC2" a first-class path
  rather than a footnote. That path still runs benchmark phase 3.
- **Fragment sizing** — ~5.3 KB and ~7.7 KB messages through 128-byte default
  fragments; a wrong fn 10 stalls or overruns the transfer.
- **§2 changes are wire-visible.** Status codes and rejection paths are
  observable by the ACU, so 4.1 wants a live re-run of 4.0 behind it.
