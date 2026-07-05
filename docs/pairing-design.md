# OSDP-SC2 Asymmetric Device Pairing — Design & Plan

Status: **proposed** (research complete, awaiting implementation sign-off).
Oracle: OSDP.Net `feature/osdp-sc2`, HEAD `f0f102bd1` (incl. the "Pairing
live bring-up" fixes from 38400-baud RS-485 testing), `src/OSDP.Net/Pairing/`
and `docs/pairing-overview.md`.

This document is the cold-start reference for adding **certificate-based
(asymmetric) initialization** to Secure Channel 2. Read it alongside
[../CLAUDE.md](../CLAUDE.md) (locked decisions) and the SC2 section of
[PLAN.md](PLAN.md).

## 1. What this feature is (and is not)

It is **not** a change to the SCS_21..28 SC2 handshake. It is a separate,
**cleartext pairing exchange** — SIA-provisional name *"OSDP Asymmetric
Device Pairing"* — that runs **once, before any secure channel**, and whose
only output is the **32-byte SC2 SCBK**. After pairing derives the SCBK, the
existing symmetric SC2 handshake runs unchanged with that key.

```
1. ACU adds the PD UNSECURED, polls it in cleartext.
2. Pairing (osdp_PAIR 0xB0 / osdp_PAIRR 0x8A) → both sides derive a 32-byte SCBK.   ← NEW
3. ACU re-adds the PD as SC2 (SEC_BLK_DATA[0]=0x02) with the derived SCBK.
4. Existing CHLNG/CCRYPT/SCRYPT/RMAC_I (SCS_21..24) handshake with that SCBK.
5. Existing AES-256-GCM traffic (SCS_25..28), unchanged.
```

The pairing is an **EDHOC-style, fully post-quantum, mutual-auth key
agreement**. Everything in the current SC2 record layer (`core/src/sc2/`,
`pd_sc2.c`, `acu_sc2.c`) is untouched; this is a new opt-in front-end that
provisions the key those files already consume.

### Locked decisions for this feature (agreed 2026-07-05)

- **Target: full MCU, freestanding.** Same no-malloc / no-OS / caller-owned-
  buffer rules as the rest of `core/`, `pd/`, `acu/`. All PQC heavy lifting
  is HAL callbacks; the core only ever hands fixed-size caller-owned buffers
  across the boundary. Memory budget is a first-class design constraint
  (§7).
- **Multipart: scoped to pairing only.** Build a minimal 2-byte multipart
  reassembly helper dedicated to PAIR/PAIRR. Do **not** generalize to
  CRAUTH / file-transfer yet (still out of scope per CLAUDE.md).
- **Wire format: mirror OSDP.Net exactly**, byte-for-byte, so live interop
  against `feature/osdp-sc2` works now. The format is experimental / not
  SIA-assigned; a future spec change is a coordinated update to both
  codebases. All provisional codes/strings are centralized (§6) to keep
  that a small change.
- **Crypto is fully pluggable; no backend is baked in.** Every asymmetric
  and hashing primitive crosses the `osdp_pair_crypto_t` HAL (§4) — exactly
  like SC1's `osdp_sc_crypto_t` and SC2's `osdp_sc2_crypto_t`. The core
  contains zero ML-KEM / ML-DSA / SHA-3 / HKDF code. **Tests/CI use vendored
  PQClean** (ML-KEM-768 + ML-DSA-44 + SHA-256, CC0, under `vendor/pqclean/`)
  — self-contained like `tiny-*`, so the KATs run hermetically on the
  existing Linux CI with no external dependency (decided 2026-07-05 after
  confirming CI is hermetic/vendored; a WolfSSL CI step would need a
  from-source PQC build). **WolfSSL is the documented production backend and
  a live-interop target** (wolfCrypt ships native ML-KEM/ML-DSA); any other
  backend (mbedTLS + liboqs, OpenSSL 3.5+, hardware PQC) satisfies the same
  HAL and drops in with no core change. The HAL is the contract; the backend
  is the integrator's choice. PQClean's fixed-seed ML-KEM/ML-DSA public keys
  hash byte-identically to OSDP.Net's published constants, so the vendored
  test backend is confirmed interoperable with the BouncyCastle reference.

## 2. Wire protocol

### 2.1 Transport commands (cleartext, no-security SCB)

Pairing rides two experimental application messages, both with an
unsecured Security Control Block (it runs before SC exists):

| Code   | Name       | Direction   |
| ------ | ---------- | ----------- |
| `0xB0` | osdp_PAIR  | ACU → PD    |
| `0x8A` | osdp_PAIRR | PD → ACU    |

(Codes chosen to avoid the OSDP 3.0 PIV draft's tentative `0xA6`–`0xAF`
command / `0x84`–`0x89` reply ranges.)

### 2.2 Fragmentation (CRAUTH-style, 2-byte fields)

Each of the 4 logical messages is fragmented with little-endian 2-byte
multipart fields (same shape as osdp_CRAUTH/CRAUTHR). Default fragment
payload = **128 bytes**.

```
osdp_PAIR (0xB0) payload:            osdp_PAIRR (0x8A) payload:
  totalSize      u16 LE                wholeMessageLength u16 LE
  offset         u16 LE                offset             u16 LE
  fragmentSize   u16 LE                lengthOfFragment   u16 LE
  fragment bytes...                    data...
```

Reassembled payload = `messageType(1) || CBOR-body`,
`messageType ∈ {0x01, 0x02, 0x03, 0x04}`.

Flow control (from OSDP.Net `ControlPanel.PairDevice` / `Device.cs`):
- ACU sends all outbound fragments; PD ACKs each.
- ACU then drives fast polling in multipart-receive mode; PD queues its
  fragmented reply for delivery across subsequent polls.
- First fragment of Msg1 **resets** the PD pairing session (retry-friendly).
- **30-second inactivity timeout** discards a stalled session, both sides.

Message sizes (why fragmentation is mandatory):
Msg1 ≈ 5.3 KB, Msg2 ≈ 7.7 KB, Msg3 ≈ 2.5 KB, Result ≈ 60 B.

### 2.3 The four application messages

`||` = concatenation. Bodies are canonical CBOR arrays, each preceded by
its 1-byte type tag.

```
Message 1  (ACU → PD)   tag 0x01   CBOR array(6)
  version(1)=1 | suite(1)=1 | nonce_A(16) | ek_A(1184 = ML-KEM-768 encaps key)
  | credType_A(1) | cred_A            ; cred = full C509 cert OR 32-byte thumbprint

Message 2  (PD → ACU)   tag 0x02   CBOR array(3): [ core, sig_P, mac_P ]
  core = CBOR array(4): [ nonce_P(16) | ct(1088 = ML-KEM ciphertext) | credType_P(1) | cred_P ]
  sig_P(2420) = ML-DSA-44.Sign(sk_P, "OSDP-PAIR-v1-msg2" || TH2)
  mac_P(32)   = HMAC-SHA256(K_m2, TH2)

Message 3  (ACU → PD)   tag 0x03   CBOR array(2): [ sig_A, mac_A ]
  sig_A(2420) = ML-DSA-44.Sign(sk_A, "OSDP-PAIR-v1-msg3" || TH3)
  mac_A(32)   = HMAC-SHA256(K_m3, TH3)

Result     (PD → ACU)   tag 0x04   CBOR array(2): [ status(uint), mac_R(bstr) ]
  status(1)  ; 0x00 ok / 0x01 auth-fail / 0x02 persist-fail / 0x03 policy / 0x04 protocol
  mac_R(32)  = HMAC-SHA256(K_m4, TH4)   ; present only on success (empty bstr otherwise)
```

Step-by-step:
1. **ACU** generates ephemeral ML-KEM-768 keypair + `nonce_A`; sends Msg1
   with its cert.
2. **PD** validates ACU cert vs trust anchor; encapsulates to `ek_A` →
   (`ct`, shared secret `ss`); generates `nonce_P`; computes TH2; signs TH2
   (`sig_P`); derives confirmation keys; MACs TH2 (`mac_P`); sends Msg2.
3. **ACU** validates PD cert; verifies `sig_P` over TH2; decapsulates `ct`
   → `ss`; verifies `mac_P` (catches an ML-KEM shared-secret mismatch);
   signs TH3 (`sig_A`), MACs TH3 (`mac_A`); derives SCBK; sends Msg3.
4. **PD** verifies `sig_A` + `mac_A`; derives SCBK; runs the persistence
   callback; sends Result(success, `mac_R`).
5. **ACU** verifies `mac_R`; yields `PairingResult{ Scbk, PeerCertificate }`.

**Commit ordering:** PD commits only after persisting the key AND sending
success; ACU commits only after verifying `mac_R`. All HMAC/tag compares
are constant-time.

## 3. Cryptography

Fully PQC — no classical primitives anywhere (no ECDH/ECDSA/RSA/EdDSA).

| Primitive             | Algorithm                         | Sizes (bytes)                              |
| --------------------- | --------------------------------- | ------------------------------------------ |
| Key encapsulation     | **ML-KEM-768** (FIPS 203)         | seed 64, pubkey 1184, ct 1088, secret 32   |
| Signatures            | **ML-DSA-44** (FIPS 204), **deterministic** | seed 32, pubkey 1312, sig 2420   |
| KDF                   | **HKDF-SHA256** (RFC 5869)        | 32-byte outputs                            |
| Transcript hash       | **SHA-256**                       | 32                                         |
| Key confirmation      | **HMAC-SHA256**                   | 32                                         |

- ML-DSA signing is **deterministic** (reproducible demo certs / vectors).
  ML-KEM encapsulation is randomized, so the end-to-end SCBK is not a fixed
  vector — conformance is proved by the deterministic key schedule (§3.2)
  plus "both sides derive an identical SCBK."
- OSDP.Net uses BouncyCastle for all of it; we mirror the algorithms, not
  the library.

### 3.1 Certificates (C509 — CBOR, not X.509)

Canonical CBOR `[ TBS, signature ]`; TBS is an 8-element array:

```
TBS = [
  version:      1                                    ; uint
  serialNumber: bstr(8)
  issuer:       tstr                                 ; CA common name, or "self"
  validity:     [ notBefore, notAfter ]              ; two uints, Unix seconds
  subject:      [ manufacturer, model, serialNumber ]; three tstr (802.1AR IDevID)
  publicKeyAlg: 1                                    ; 1 = ML-DSA-44
  publicKey:    bstr(1312)                           ; ML-DSA-44 subject pubkey
  signatureAlg: 1
]
signature = ML-DSA-44.Sign(issuerPrivKey, "OSDP-C509-v1" || TBS_encoded)   ; 2420 B, deterministic
```

- **Thumbprint** = SHA-256 of the full canonical cert encoding (used for
  by-reference presentation, `credType=1`).
- **Self-signed**: `issuer = "self"`, signed by the subject key; trusted by
  pinning its thumbprint.

### 3.2 Key schedule (`PairingKeySchedule.cs`)

```
TH1 = SHA-256(message1_wire_bytes)          ; includes the 1-byte type tag
TH2 = SHA-256(TH1 || message2_core_bytes)   ; core = 4-element array, WITHOUT sig_P/mac_P
TH3 = SHA-256(TH2 || sig_P || mac_P)
TH4 = SHA-256(TH3 || sig_A || mac_A)

ss   = ML-KEM-768 shared secret (32 B)
PRK  = HKDF-Extract(salt = TH2, ikm = ss)
K_m2 = HKDF-Expand(PRK, "osdp-pair confirm2", 32)
K_m3 = HKDF-Expand(PRK, "osdp-pair confirm3", 32)
K_m4 = HKDF-Expand(PRK, "osdp-pair confirm4", 32)

SCBK = HKDF-Expand(HKDF-Extract(salt = TH4, ikm = ss), "osdp-pair scbk", 32)
```

Signature domain separators (prepended to the TH before signing):
`"OSDP-PAIR-v1-msg2"`, `"OSDP-PAIR-v1-msg3"`. The SCBK is bound to TH4,
which covers both nonces, both certs, both signatures, and both
confirmation MACs → unique per pairing.

### 3.3 Trust / validation (`PairingTrustAnchor.cs`, `PairingPeer.cs`)

Mutual auth: both PD and ACU present a cert. Two trust-anchor modes:
1. **CA anchor** — peer cert's ML-DSA-44 signature must verify under the
   trusted CA public key (single-level; CA signs device certs directly, no
   path building).
2. **Pinned thumbprint** — cert must be self-consistent (self-signed
   verifies with its own key) AND its SHA-256 thumbprint ∈ pinned set.

Extra gates: full-cert (`credType=0`) vs 32-byte thumbprint reference
(`credType=1`, resolved by a `resolve_peer_certificate` callback); optional
validity-window enforcement (default **off** — constrained PDs may lack an
RTC); optional `approve_peer(cert)` policy hook. **No revocation** (no
CRL/OCSP).

## 4. Module layout (proposed)

Mirrors how OSDP.Net keeps `Pairing/` decoupled, and this repo's existing
opt-in-module pattern (`osdp::dispatch`, `osdp::sc`).

```
core/include/osdp/
  osdp_pair_crypto.h   # NEW HAL: ml_kem768_{keygen,encaps,decaps},
                       #   ml_dsa44_{sign,verify}, sha256, hmac_sha256, hkdf, rand
  osdp_pair.h          # cert, key schedule, messages, transport-free sessions
  osdp_cbor.h          # canonical-CBOR lite (not crypto; lives in core)

core/src/pair/         # NEW opt-in target osdp::pair
  fragment.c           # [Phase 0 ☑] osdp_PAIR/osdp_PAIRR fragment carrier codec
  multipart.c          # [Phase 0 ☑] in-order multipart reassembler + fragment iterator
  cbor.c               # canonical-CBOR writer/reader (definite lengths, shortest int)
  cert.c               # C509 encode / decode / verify / thumbprint
  keyschedule.c        # TH1..TH4, HKDF schedule, K_m2/3/4, SCBK
  messages.c           # Msg1/2/3/Result CBOR encode / parse
  session.c            # ACU-initiator + PD-responder pure state machines

pd/src/pd_pair.c       # PD wire driver: reassembly, session drive, 30 s timeout,
                       #   on_scbk_established persistence callback
acu/src/acu_pair.c     # ACU wire driver: fragment send, reassembly, per-message timeout

vendor/pqclean/        # [Phase 1 ☑] vendored ML-KEM-768 + ML-DSA-44 + SHA-256
                       #   (CC0), self-contained like tiny-*; the hermetic CI/test
                       #   PQC backend. NEVER linked into a production core.
tests/pair_test_crypto.c # [Phase 1 ☑] osdp_pair_crypto_t over PQClean (+ HMAC/HKDF)
tools/                 # osdp-pd-mock / osdp-acu-mock gain a pairing mode; a WolfSSL
                       #   osdp_pair_crypto_t binding for live interop (Phase 7).
rust/osdp/             # safe wrapper: PairCrypto trait + pair APIs; sys.rs + build.rs grown
```

New CMake target `osdp::pair` (opt-in, linked only by apps that pair). The
whole pairing feature — including the cleartext fragment transport — lives
in this one module rather than being split into baseline command/reply
codecs, mirroring how SC1/SC2 keep their protocol-internal framing in
`osdp::sc` / the SC2 sources instead of `osdp::messages`. `osdp::core` /
`messages` / `pd` / `acu` are untouched except for the two provisional wire
codes (`OSDP_CMD_PAIR` in `osdp_commands.h`, `OSDP_REPLY_PAIRR` in
`osdp_replies.h`) so dispatch can name the frames. Both PAIR and PAIRR share
one fragment codec because their wire layout is identical.

### HAL contract (`osdp_pair_crypto_t`, sketch)

All buffers caller-owned and fixed-size; every heavy op is a callback so
the core never allocates or vendors PQC:

```c
typedef struct osdp_pair_crypto {
    osdp_status_t (*ml_kem768_keygen )(void *u, uint8_t ek[1184], uint8_t dk[/*impl*/]);
    osdp_status_t (*ml_kem768_encaps )(void *u, const uint8_t ek[1184],
                                       uint8_t ct[1088], uint8_t ss[32]);
    osdp_status_t (*ml_kem768_decaps )(void *u, const uint8_t dk[/*impl*/],
                                       const uint8_t ct[1088], uint8_t ss[32]);
    osdp_status_t (*ml_dsa44_sign    )(void *u, const uint8_t sk[/*impl*/],
                                       const uint8_t *msg, size_t len, uint8_t sig[2420]);
    osdp_status_t (*ml_dsa44_verify  )(void *u, const uint8_t pk[1312],
                                       const uint8_t *msg, size_t len, const uint8_t sig[2420]);
    osdp_status_t (*sha256)(void *u, const uint8_t *d, size_t n, uint8_t out[32]);
    osdp_status_t (*hmac_sha256)(void *u, const uint8_t *k, size_t kn,
                                 const uint8_t *d, size_t dn, uint8_t out[32]);
    osdp_status_t (*hkdf)(void *u, const uint8_t *salt, size_t sn,
                          const uint8_t *ikm, size_t in,
                          const uint8_t *info, size_t fn, uint8_t *out, size_t on);
    osdp_status_t (*rand_bytes)(void *u, uint8_t *out, size_t len);
    void *user;
} osdp_pair_crypto_t;
```

(Private-key sizes are impl-defined; the ML-DSA/ML-KEM secret keys live
behind the HAL and never cross the core boundary in a fixed layout — the
core passes an opaque pointer the consumer supplied. Final signature is
firmed up in Phase 1.)

## 5. State machines

Transport-free session structs (pure, injectable randomness), mirroring
`AcuPairingSession` / `PdPairingSession`.

**PD responder:** `Idle → AwaitMessage3 → AwaitPersist → Complete | Failed`
- process Msg1 → build Msg2 (encaps, sign, derive K_m2/3/4, mac_P)
- process Msg3 → verify sig_A + mac_A → derive SCBK → AwaitPersist
- persistence callback result → build Result (mac_R over TH4) or Failed

**ACU initiator:** `Created → AwaitMessage2 → AwaitResult → Complete | Failed`
- create Msg1 → process Msg2 (verify sig_P, decaps, verify mac_P, derive
  SCBK, emit Msg3) → process Result (verify mac_R) → PairingResult

**Opt-in gate:** a PD with no pairing config NAKs osdp_PAIR (Unknown
Command Code) → ACU sees `NotSupported`. Pure pre-shared-key SC2 and SC1
are unaffected. A pairing-capable PD advertises `osdp_PAIR` in its
capabilities and accepts the command unsecured.

Status enum (wire): `0x00 ok / 0x01 auth-fail / 0x02 persist-fail /
0x03 policy / 0x04 protocol`; local-only: cert-rejected, key-confirm-fail,
not-supported, timeout, unknown-cred-ref.

### 5.1 Deterministic cleartext→SC2 handoff (from live RS-485 testing)

The OSDP.Net "Pairing live bring-up" commit (`f0f102bd1`, 38400-baud serial)
pinned the exact handoff sequencing. These are **driver** rules (Phases
4–6); they do not affect the wire format of the transport, CBOR, C509, or
crypto layers. The whole flow — cleartext pairing, then SC2 — happens over
**one connection** with no reconnect, no sleep, and no timing delay:

- **Message 2 is delivered by polling; the Result is delivered inline.**
  The multi-fragment Message 2 (PD→ACU) is queued and sent over subsequent
  polls. The **single-fragment Result is returned directly as the PAIRR
  reply to the PAIR command that carried Message 3's final fragment** — not
  queued — precisely so it reaches the ACU *before* the PD's channel goes
  secure. Failure/rejection Results are likewise delivered inline (with no
  key applied).
- **PD ordering: send the Result, THEN activate the key.** On Message 3
  success the PD derives the SCBK, runs the persistence callback, **sends
  the cleartext Result**, and only *after that byte is on the wire* applies
  the SCBK to its running SC2 session in place and switches to
  require-security (OSDP.Net: `ActivatePairedKey` → set key, reset SC2
  context, `SecurityMode=FullSecurity`, `RequireSecurity=true`). This
  strict "reply-before-activate" order guarantees the PD is ready before the
  ACU's first `CHLNG`. In our C model this is the existing KEYSET-style
  in-place SCBK write into `pd->sc2.scbk`, staged until the Result frame is
  emitted, plus flipping the PD to "SC2 now required."
- **During pairing the PD is an unsecured but SC2-capable device.** It runs
  an SC2 channel with a placeholder key (`RequireSecurity=false`,
  `SecureChannelVersion=V2`); pairing swaps in the real SCBK. Our
  `osdp_sc2_session_t` already separates the stored SCBK from the
  established session, so this is just "write SCBK, mark SC2 required."
- **ACU: challenge immediately on the same connection.** After
  `ProcessResult` the ACU re-adds the device as SC2 with the derived key and
  issues the SC2 handshake straight away — our existing
  `osdp_acu_start_sc2_handshake`. The protocol round-trip (PD activates →
  Result → ACU receives → ACU challenges) is what enforces ordering, so no
  delay is needed.
- **The PD-side result callback surfaces the authenticated peer**, not just
  the key: OSDP.Net changed `OnScbkEstablished` to receive the full
  `PairingResult` (SCBK **+ peer identity/cert**). Our Phase-4 PD callback
  should carry an `osdp_pair_result_t { scbk, peer identity, cert
  thumbprint }` and return a persisted-ok bool.
- **Progress reporting is UX-only** (`IProgress<PairingProgress>`, ACU-side,
  weighted 0.45/0.30/0.15/0.10 across the four messages). Optional to mirror
  as an ACU driver phase/progress hook; not wire-affecting.

## 6. Provisional constants (centralized)

Because the format is not SIA-assigned, keep every provisional value in one
header so a spec reassignment is a one-file edit:

```
CMD osdp_PAIR            = 0xB0
REPLY osdp_PAIRR         = 0x8A
msg tags                 = 0x01/0x02/0x03/0x04
credType                 = 0 (cert) / 1 (thumbprint)
protocol version         = 1
cipher suite             = 1
cert sig domain          = "OSDP-C509-v1"
sig domains              = "OSDP-PAIR-v1-msg2" / "OSDP-PAIR-v1-msg3"
hkdf info                = "osdp-pair confirm2/3/4" / "osdp-pair scbk"
default fragment size    = 128
session timeout          = 30 s
```

## 7. Memory budget (MCU-freestanding constraint)

Everything is caller-owned; the wire driver reuses one inbound and one
outbound buffer. Peak steady-state buffers, per role:

| Buffer                        | PD      | ACU     |
| ----------------------------- | ------- | ------- |
| Outbound message (max Msg2)   | ~7.7 KB | ~2.5 KB (Msg3) |
| Inbound message (max Msg1)    | ~5.3 KB | ~7.7 KB (Msg2) |
| Own cert (pubkey 1312 + sig)  | ~3.8 KB | ~3.8 KB |
| Peer cert (transient)         | ~3.8 KB | ~3.8 KB |

→ order-of **~15–20 KB of caller buffers** during pairing, plus whatever
the HAL's ML-KEM/ML-DSA implementation needs on its own stack (reference
PQClean is tens of KB of stack). This is a **provisioning-time** cost, not
steady-state — the buffers can be freed/reused after pairing. Implications
to confirm in Phase 0:
- Provide compile-time `OSDP_PAIR_MSG_MAX` etc. so an integrator sizes one
  arena and the codecs bounds-check against it.
- Streaming/incremental CBOR hashing (feed fragments into SHA-256 as they
  arrive) can avoid holding a whole reassembled message purely to hash it —
  but TH computation needs specific byte ranges (message1 whole; message2
  core only), so at least the signed/hashed spans must be buffered. Decide
  buffer-vs-stream granularity in Phase 0/3.
- Tiny MCUs without the RAM simply don't enable `osdp::pair` (linker GC
  drops it); they keep pre-shared-key SC2.

## 8. Phasing

Mirrors the SC1/SC2 phase style. Deterministic parts are validated against
fixed vectors (§9) even though the full E2E SCBK is randomized.

- **Phase 0 ☑ — transport.** `core/src/pair/fragment.c` (0xB0/0x8A carrier)
  + `core/src/pair/multipart.c` (2-byte reassembler + fragment iterator) in
  `osdp::pair`; buffer-sizing constants. 18 tests: round trip + short-header
  / size-mismatch / overrun / gap / bad-total / retransmit / restart.
- **Phase 1 ☑ — crypto HAL + CBOR + C509.** `osdp_pair_crypto.h`,
  `osdp_cbor.h`/`cbor.c` (12 tests), `cert.c` (9 structural tests). Vendored
  PQClean backend (`vendor/pqclean/`, `tests/pair_test_crypto.c`) drives 8
  KATs: SHA-256 + HKDF RFC-5869 vectors, KEM round trip, C509 thumbprint +
  self-signed verify + tamper-reject, and the fixed-seed ML-DSA-44 /
  ML-KEM-768 pubkey hashes matching OSDP.Net byte-for-byte (§9).
- **Phase 2 ☑ — key schedule.** `core/src/pair/keyschedule.c`
  (`osdp_pair_derive_confirm_keys` + `osdp_pair_derive_scbk`, HKDF-SHA256).
  KAT asserts K_m2/3/4 + SCBK against the fixed vectors (§9) byte-for-byte.
  TH1..TH4 computation deferred to Phase 3 (message layer owns the spans).
- **Phase 3 ☑ — message codecs.** `core/src/pair/messages.c`: byte-exact
  CBOR encode/parse for Msg1/2/3/Result + TH1..TH4 helpers (bounded stack
  scratch over the one-shot SHA HAL). Layout + TH spans confirmed against
  OSDP.Net `f0f102bd1`. 9 codec tests + TH self-consistency.
- **Phase 4 — PD side.** `session.c` PD responder + `pd/src/pd_pair.c`
  driver (reassembly, 30 s timeout, `on_scbk_established` surfacing the peer
  identity). Opt-in gate / NAK-when-unconfigured. **Deterministic handoff
  (§5.1): deliver the Result inline, then apply the SCBK in place and flip
  to SC2-required strictly after the Result is sent.**
- **Phase 5 — ACU side.** `session.c` ACU initiator + `acu/src/acu_pair.c`
  driver (fragment send, multipart receive, per-message timeout, rejection
  surfacing).
- **Phase 6 — loopback.** `tests/test_loopback_pair.c`: both real state
  machines complete the exchange and derive an **identical SCBK**; then the
  **in-place cleartext→SC2 handoff on the same wire** (§5.1: inline Result →
  PD applies SCBK after sending → ACU challenges immediately) drives the
  existing SC2 handshake + a POLL/ACK under SCS_27 — full provisioning-
  through-operation path in-process. Untrusted-CA, tampered Msg2/Msg3, and
  persist-fail negatives.
- **Phase 7 — WolfSSL backend + live interop.** WolfSSL `osdp_pair_crypto_t`
  binding (wolfCrypt ML-KEM-768 + ML-DSA-44 + SHA-256/HMAC/HKDF) in
  `tools/` + `tests/`; tools gain a pairing mode; live-validate vs OSDP.Net
  `feature/osdp-sc2` over a serial pair. The binding is one file behind the
  HAL — swapping to mbedTLS+liboqs / OpenSSL / hardware later touches
  nothing else.
- **Phase 8 — Rust + MCP + docs.** `PairCrypto` trait + pair APIs;
  `sys.rs`/`build.rs` grown; osdp-mcp pairing option; PLAN.md + CLAUDE.md.

## 9. Test vectors (from OSDP.Net, deterministic)

- **Demo CA** seed `40 41 … 5F`;
  `SHA-256(demo CA ML-DSA-44 pubkey) = 6C1C65071979225A139B3EC84688E2688EC30FABE8CC510CB688BC435F2D3CB9`.
- **ML-KEM pubkey** (seed `00..3F`):
  `SHA-256 = 0B7934C83125C788995E2BA6BD761E33046B3E40571BE53E023309A29F398CC9`.
- **HKDF** (RFC 5869 TC1, SHA-256): PRK
  `077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5`, OKM
  `3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865`.
- **Key schedule** (fixed `ss=00..1F`, `TH2=20..3F`, `TH4=40..5F`):
  ```
  K_m2 = 94151F36DE9FEB1CC8C74D7D846FBE5EA7C5CA7FC18979623D94C890ECEAD7AB
  K_m3 = BA43E76D8870ED58D77636D397D7D722513E879026A3021F6FDD07C023384829
  K_m4 = E542E59444C0776CE69DEA4FABC862F2ABD6782A3B7D7297F7E5F418D5DDF87A
  SCBK = 8EAF7FD9DE1332FD2F3F18378B8AFB81E90E83238BA324CB7BDC3F38146835D4
  ```
- End-to-end SCBK is **not** fixed (ML-KEM encaps is randomized); prove
  conformance via the schedule above + "both sides derive identical SCBK."
- OSDP.Net session tests inject fixed seeds (`Seed64(0x01)`, nonces
  `0xA0`/`0xB0`, ML-DSA seeds `0x30`/`0x60`) and cover untrusted-CA reject
  (both directions), tampered Msg2/Msg3, and persist-fail — mirror these.

## 10. Open questions / risks

- **HAL private-key representation.** ML-KEM `dk` and ML-DSA `sk` sizes are
  impl-defined; the core should treat them as opaque consumer-owned blobs.
  Confirm the exact `osdp_pair_crypto_t` signatures in Phase 1.
- **Buffer vs stream for TH.** How much of each message must be buffered to
  compute TH1..TH4 vs. hashed incrementally as fragments arrive (§7).
- **Production backend is the integrator's.** WolfSSL is the test/tool
  backend; the HAL keeps any other (mbedTLS+liboqs, OpenSSL 3.5+, hardware
  PQC, MCU PQClean) a drop-in. Confirm WolfSSL exposes ML-KEM-768 +
  ML-DSA-44 with the deterministic ML-DSA signing the vectors assume (build
  flags / API shape) in Phase 7.
- **Provisional format churn.** Mirroring an unratified format; §6
  centralization contains the blast radius, but a SIA change means a joint
  bump with OSDP.Net.
- **This is large** (multi-KB PQC, CBOR, new multipart, new HAL, new
  codecs, both state machines, tools, Rust). Expect it to be the biggest
  single feature since SC itself; the phasing keeps each step independently
  testable.
```
