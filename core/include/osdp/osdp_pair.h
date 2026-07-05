// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PAIR_H
#define OSDP_PAIR_H

#include "osdp/osdp_pair_crypto.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* osdp_pair — OSDP-SC2 asymmetric device pairing.
 *
 * Pairing is a cleartext, pre-secure-channel exchange whose only output is
 * the 32-byte SC2 SCBK; after it completes, the existing SCS_21..28
 * handshake + record layer run unchanged with that key. It mirrors
 * OSDP.Net feature/osdp-sc2 (src/OSDP.Net/Pairing/) byte-for-byte and is a
 * self-contained, opt-in module (CMake target osdp::pair) — nothing in the
 * baseline codecs or the SC2 record layer depends on it.
 *
 * See docs/pairing-design.md for the full protocol, crypto, and plan. This
 * header grows across the implementation phases; this file currently
 * exposes only the Phase 0 transport layer:
 *
 *   - The fragment carrier codec for osdp_PAIR (0xB0) / osdp_PAIRR (0x8A).
 *   - A minimal, in-order multipart reassembler and its outbound
 *     fragmentation counterpart.
 *
 * Everything here is pure: no allocation, no globals, no I/O; all buffers
 * are caller-owned. */

/* ---- Provisional wire constants ----------------------------------------
 *
 * The pairing profile is experimental / NOT SIA-assigned; these values
 * mirror OSDP.Net feature/osdp-sc2 exactly and are centralized here so a
 * future spec reassignment is a one-file change. The OSDP command/reply
 * codes themselves live with the rest of the code set (OSDP_CMD_PAIR in
 * osdp_commands.h, OSDP_REPLY_PAIRR in osdp_replies.h). */

/* Reassembled-message type tags (first byte of the reassembled payload). */
#define OSDP_PAIR_MSG_TYPE_1       0x01U   /* Message 1  (ACU -> PD) */
#define OSDP_PAIR_MSG_TYPE_2       0x02U   /* Message 2  (PD -> ACU) */
#define OSDP_PAIR_MSG_TYPE_3       0x03U   /* Message 3  (ACU -> PD) */
#define OSDP_PAIR_MSG_TYPE_RESULT  0x04U   /* Result     (PD -> ACU) */

/* Default outbound fragment payload size and the session inactivity
 * timeout, both per the reference. */
#define OSDP_PAIR_DEFAULT_FRAGMENT_SIZE  128U
#define OSDP_PAIR_SESSION_TIMEOUT_MS     30000U

/* Recommended reassembly-buffer size. The largest pairing message
 * (Message 2, PD -> ACU) is ~7.7 KB; this bounds an integrator's single
 * caller-owned arena with headroom and is used as the on-wire sanity
 * ceiling by the reassembler. (Exact per-message sizes are pinned in the
 * message-codec phase.) */
#define OSDP_PAIR_MSG_MAX  8192U

/* ---- Fragment carrier ---------------------------------------------------
 *
 * Both osdp_PAIR and osdp_PAIRR carry an identical 6-byte header followed
 * by the fragment bytes (CRAUTH-style multipart, 2-byte little-endian
 * fields):
 *
 *   total_size    u16 LE   whole reassembled message length
 *   offset        u16 LE   byte offset of this fragment within the message
 *   fragmentSize  u16 LE   number of fragment bytes that follow (== frag_len)
 *   data ...               `fragmentSize` bytes
 *
 * The two directions share one codec because the layout is identical; the
 * caller supplies the OSDP framing and the 0xB0 / 0x8A code byte around the
 * DATA this codec produces/consumes. */

#define OSDP_PAIR_FRAG_HEADER_BYTES 6U

typedef struct osdp_pair_fragment {
    uint16_t       total_size;  /* whole reassembled message length (bytes) */
    uint16_t       offset;      /* byte offset of this fragment              */
    const uint8_t *data;        /* fragment bytes; NULL iff frag_len == 0    */
    size_t         frag_len;    /* fragment byte count (on-wire fragmentSize)*/
} osdp_pair_fragment_t;

/* Decode a single PAIR/PAIRR fragment payload (the command/reply DATA field,
 * i.e. everything after the 0xB0 / 0x8A code byte). Rejects a short header,
 * an on-wire fragmentSize that disagrees with the trailing byte count, and
 * a fragment that would extend past the declared total_size. `out->data`
 * points into `payload`. */
osdp_status_t osdp_pair_fragment_decode(const uint8_t *payload, size_t len,
                                        osdp_pair_fragment_t *out);

/* Build a single PAIR/PAIRR fragment payload into `buf`. Refuses an
 * inconsistent descriptor (fragment exceeding total_size, frag_len beyond a
 * u16, non-NULL/NULL data mismatch). On success writes 6 + frag_len bytes
 * and sets *written. */
osdp_status_t osdp_pair_fragment_build(const osdp_pair_fragment_t *in,
                                       uint8_t *buf, size_t buf_cap,
                                       size_t *written);

/* ---- Multipart reassembly (inbound) -------------------------------------
 *
 * Accumulates decoded fragments into a caller-owned buffer. Fragmentation
 * is sequential: a fragment at offset 0 (re)starts the message (retry-
 * friendly), and later fragments must be contiguous (no gaps). An exact
 * retransmit of an already-received span is idempotent. */

typedef struct osdp_pair_reasm {
    uint8_t *buf;       /* caller-owned reassembly buffer         */
    size_t   cap;       /* capacity of buf                        */
    uint16_t total;     /* declared message length (0 while idle) */
    uint16_t received;  /* contiguous bytes received so far       */
    bool     active;    /* a message is in progress               */
} osdp_pair_reasm_t;

/* Bind a caller-owned buffer to a reassembler and clear it. */
void osdp_pair_reasm_init(osdp_pair_reasm_t *r, uint8_t *buf, size_t cap);

/* Reset the reassembler to idle (keeps the bound buffer). */
void osdp_pair_reasm_reset(osdp_pair_reasm_t *r);

/* Feed one decoded fragment. Sets *complete = true once the whole message
 * has arrived (then `r->buf[0 .. r->total)` is the reassembled payload).
 * Returns OSDP_ERR_BUFFER_TOO_SMALL if the declared message exceeds the
 * bound buffer, OSDP_ERR_BAD_PAYLOAD on an inconsistent/out-of-order
 * fragment, OSDP_ERR_INVALID_ARG on a NULL argument. */
osdp_status_t osdp_pair_reasm_push(osdp_pair_reasm_t *r,
                                   const osdp_pair_fragment_t *frag,
                                   bool *complete);

/* ---- Multipart fragmentation (outbound) ---------------------------------
 *
 * Splits a whole message into successive fragment descriptors of at most
 * `max_frag` bytes each; each descriptor's `data` points into `msg`. */

typedef struct osdp_pair_frag_iter {
    const uint8_t *msg;
    size_t         msg_len;
    size_t         max_frag;
    size_t         offset;   /* offset of the next fragment */
} osdp_pair_frag_iter_t;

/* Initialise an iterator over `msg`. A zero `max_frag` is treated as the
 * default fragment size. */
void osdp_pair_frag_iter_init(osdp_pair_frag_iter_t *it,
                              const uint8_t *msg, size_t msg_len,
                              size_t max_frag);

/* Fill `frag` with the next fragment and advance; returns false when the
 * whole message has been emitted (or if `msg_len` is 0). */
bool osdp_pair_frag_iter_next(osdp_pair_frag_iter_t *it,
                              osdp_pair_fragment_t *frag);

/* ---- C509 certificate ---------------------------------------------------
 *
 * The compact CBOR "C.509" certificate used by pairing (NOT X.509). It
 * binds a device identity (802.1AR IDevID subject) to an ML-DSA-44 public
 * key and is itself ML-DSA-44 signed by an issuer (a CA, or the subject key
 * for a self-signed cert). Canonical CBOR:
 *
 *   cert = [ TBS, signature ]
 *   TBS  = [ version, serialNumber, issuer, [notBefore, notAfter],
 *            [manufacturer, model, serialNumber], pubKeyAlg, publicKey,
 *            sigAlg ]
 *   signature = ML-DSA-44.Sign(issuerKey, "OSDP-C509-v1" || TBS_encoded)
 *   thumbprint = SHA-256(cert)          (over the full canonical encoding)
 *
 * The decoder is zero-copy: pointer fields alias the input buffer, so it
 * must outlive the decoded cert. */

#define OSDP_C509_VERSION      1U   /* the only supported version           */
#define OSDP_C509_ALG_MLDSA44  1U   /* pubKeyAlg / sigAlg value             */
#define OSDP_C509_SERIAL_LEN   8U   /* issuer-assigned serial number bytes  */

/* Maximum accepted length for each identity / issuer text string, and the
 * resulting upper bound on the encoded TBS. Bounds the verify scratch and
 * keeps a hostile cert from forcing an unbounded copy. Device identity
 * fields are short in practice. */
#define OSDP_PAIR_STR_MAX      64U
#define OSDP_C509_TBS_MAX      1536U

/* Signature domain separator and the well-known self-signed issuer name. */
#define OSDP_C509_SIG_DOMAIN   "OSDP-C509-v1"
#define OSDP_C509_SELF_ISSUER  "self"

typedef struct osdp_c509_cert {
    uint64_t       version;               /* == OSDP_C509_VERSION           */
    const uint8_t *serial;                /* OSDP_C509_SERIAL_LEN bytes     */
    size_t         serial_len;
    const char    *issuer;                /* CA name, or "self"             */
    size_t         issuer_len;
    uint64_t       not_before;            /* Unix seconds                   */
    uint64_t       not_after;             /* Unix seconds                   */
    const char    *manufacturer;
    size_t         manufacturer_len;
    const char    *model;
    size_t         model_len;
    const char    *subject_serial;
    size_t         subject_serial_len;
    uint64_t       public_key_alg;        /* == OSDP_C509_ALG_MLDSA44       */
    const uint8_t *public_key;            /* OSDP_MLDSA44_PK_LEN bytes      */
    size_t         public_key_len;
    uint64_t       signature_alg;         /* == OSDP_C509_ALG_MLDSA44       */
    const uint8_t *signature;             /* OSDP_MLDSA44_SIG_LEN bytes     */
    size_t         signature_len;

    /* The exact encoded TBS byte span (the signature covers
     * "OSDP-C509-v1" || these bytes). Aliases the decode input. */
    const uint8_t *tbs;
    size_t         tbs_len;
} osdp_c509_cert_t;

/* Decode a full C509 certificate. Enforces the version, algorithm ids, and
 * the fixed ML-DSA-44 key / signature / serial sizes, and rejects identity
 * strings longer than OSDP_PAIR_STR_MAX. Pointer fields alias `buf`. */
osdp_status_t osdp_c509_decode(const uint8_t *buf, size_t len,
                               osdp_c509_cert_t *out);

/* Encode just the 8-element TBS array (the signing / verifying input, minus
 * the "OSDP-C509-v1" domain prefix). */
osdp_status_t osdp_c509_encode_tbs(const osdp_c509_cert_t *cert,
                                   uint8_t *buf, size_t buf_cap,
                                   size_t *written);

/* Encode the full certificate [ TBS, signature ]. */
osdp_status_t osdp_c509_encode(const osdp_c509_cert_t *cert,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written);

/* Compute the certificate thumbprint = SHA-256(cert_bytes) via the HAL.
 * `cert_bytes` is the full canonical certificate encoding. */
osdp_status_t osdp_c509_thumbprint(const osdp_pair_crypto_t *crypto,
                                   const uint8_t *cert_bytes, size_t cert_len,
                                   uint8_t out[OSDP_PAIR_HASH_LEN]);

/* Verify a decoded certificate's ML-DSA-44 signature under `issuer_pubkey`
 * (a CA key, or the cert's own public_key for a self-signed cert). Returns
 * OSDP_OK iff the signature is valid. */
osdp_status_t osdp_c509_verify(const osdp_pair_crypto_t *crypto,
                               const osdp_c509_cert_t *cert,
                               const uint8_t issuer_pubkey[OSDP_MLDSA44_PK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PAIR_H */
