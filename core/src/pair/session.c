// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"

#include <stdint.h>
#include <string.h>

/* ---- Shared helpers ----------------------------------------------------- */

static void copy_str(char *dst, size_t *dst_len, const char *src, size_t n)
{
    if (n > OSDP_PAIR_STR_MAX) {
        n = OSDP_PAIR_STR_MAX;
    }
    if (n > 0) {
        (void)memcpy(dst, src, n);
    }
    *dst_len = n;
}

/* ML-DSA sign / verify over (domain || transcript-hash). */
static osdp_status_t sign_th(const osdp_pair_crypto_t *c,
                             const char *domain, size_t dlen,
                             const uint8_t th[OSDP_PAIR_HASH_LEN],
                             uint8_t sig[OSDP_PAIR_SIG_LEN])
{
    uint8_t msg[32 + OSDP_PAIR_HASH_LEN];
    (void)memcpy(msg, domain, dlen);
    (void)memcpy(&msg[dlen], th, OSDP_PAIR_HASH_LEN);
    return c->ml_dsa44_sign(c->user, msg, dlen + OSDP_PAIR_HASH_LEN, sig);
}

static osdp_status_t verify_th(const osdp_pair_crypto_t *c,
                               const uint8_t pubkey[OSDP_MLDSA44_PK_LEN],
                               const char *domain, size_t dlen,
                               const uint8_t th[OSDP_PAIR_HASH_LEN],
                               const uint8_t sig[OSDP_PAIR_SIG_LEN])
{
    uint8_t msg[32 + OSDP_PAIR_HASH_LEN];
    (void)memcpy(msg, domain, dlen);
    (void)memcpy(&msg[dlen], th, OSDP_PAIR_HASH_LEN);
    return c->ml_dsa44_verify(c->user, pubkey, msg, dlen + OSDP_PAIR_HASH_LEN,
                              sig);
}

/* Constant-time-ish 32-byte compare (both inputs are locally computed /
 * received MACs; timing is not adversarially controllable here, but avoid an
 * early-exit memcmp anyway). Returns true on equal. */
static bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < OSDP_PAIR_MAC_LEN; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Validate a presented credential against the trust anchor and capture the
 * authenticated peer (public key, thumbprint, identity). Only full-cert
 * credentials are supported. Returns OSDP_ERR_BAD_CRC on a rejected cert. */
static osdp_status_t validate_peer(const osdp_pair_crypto_t *c,
                                   const osdp_pair_trust_t *t,
                                   uint64_t cred_type,
                                   const uint8_t *cred, size_t cred_len,
                                   osdp_pair_peer_t *peer)
{
    if (cred_type != OSDP_PAIR_CRED_CERT) {
        return OSDP_ERR_NOT_SUPPORTED;
    }

    osdp_c509_cert_t cert;
    osdp_status_t st = osdp_c509_decode(cred, cred_len, &cert);
    if (st != OSDP_OK) {
        return st;
    }

    if (t->ca_pubkey != NULL) {
        if (osdp_c509_verify(c, &cert, t->ca_pubkey) != OSDP_OK) {
            return OSDP_ERR_BAD_CRC;
        }
    } else if (t->pinned_thumbprints != NULL && t->pinned_count > 0) {
        /* Self-consistent (self-signed verifies with its own key) + pinned. */
        if (osdp_c509_verify(c, &cert, cert.public_key) != OSDP_OK) {
            return OSDP_ERR_BAD_CRC;
        }
        uint8_t tp[OSDP_PAIR_HASH_LEN];
        st = osdp_c509_thumbprint(c, cred, cred_len, tp);
        if (st != OSDP_OK) {
            return st;
        }
        bool pinned = false;
        for (size_t i = 0; i < t->pinned_count; i++) {
            if (memcmp(tp, t->pinned_thumbprints[i], OSDP_PAIR_HASH_LEN) == 0) {
                pinned = true;
                break;
            }
        }
        if (!pinned) {
            return OSDP_ERR_BAD_CRC;
        }
    } else {
        return OSDP_ERR_INVALID_ARG;   /* no trust anchor configured */
    }

    (void)memcpy(peer->pubkey, cert.public_key, OSDP_MLDSA44_PK_LEN);
    st = osdp_c509_thumbprint(c, cred, cred_len, peer->thumbprint);
    if (st != OSDP_OK) {
        return st;
    }
    copy_str(peer->manufacturer, &peer->manufacturer_len,
             cert.manufacturer, cert.manufacturer_len);
    copy_str(peer->model, &peer->model_len, cert.model, cert.model_len);
    copy_str(peer->serial, &peer->serial_len,
             cert.subject_serial, cert.subject_serial_len);
    return OSDP_OK;
}

/* ---- PD responder ------------------------------------------------------- */

void osdp_pair_pd_init(osdp_pair_pd_session_t *s,
                       const osdp_pair_crypto_t *crypto,
                       const osdp_pair_local_t *local,
                       const osdp_pair_trust_t *trust)
{
    (void)memset(s, 0, sizeof(*s));
    s->crypto = crypto;
    s->local  = *local;
    s->trust  = *trust;
    s->state  = OSDP_PAIR_PD_IDLE;
}

/* Emit a rejection Result and mark the session failed. */
static osdp_status_t pd_reject(osdp_pair_pd_session_t *s, uint64_t status,
                               uint8_t *out, size_t out_cap, size_t *out_len,
                               bool *is_rejection)
{
    s->state = OSDP_PAIR_PD_FAILED;
    *is_rejection = true;
    return osdp_pair_result_encode(status, NULL, 0, out, out_cap, out_len);
}

osdp_status_t osdp_pair_pd_process_msg1(osdp_pair_pd_session_t *s,
                                        const uint8_t *msg1_wire, size_t len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len, bool *is_rejection)
{
    if (s == NULL || out == NULL || out_len == NULL || is_rejection == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;
    *is_rejection = false;

    osdp_pair_msg1_t m1;
    if (osdp_pair_msg1_decode(msg1_wire, len, &m1) != OSDP_OK) {
        return pd_reject(s, OSDP_PAIR_STATUS_PROTOCOL, out, out_cap, out_len,
                         is_rejection);
    }

    /* Authenticate the ACU. */
    if (validate_peer(c, &s->trust, m1.cred_type, m1.cred, m1.cred_len,
                      &s->peer) != OSDP_OK) {
        return pd_reject(s, OSDP_PAIR_STATUS_POLICY, out, out_cap, out_len,
                         is_rejection);
    }

    uint8_t th1[OSDP_PAIR_HASH_LEN];
    osdp_status_t st = osdp_pair_th1(c, m1.wire, m1.wire_len, th1);
    if (st != OSDP_OK) {
        return st;
    }

    /* Encapsulate to the ACU's ephemeral key; keep the shared secret. */
    uint8_t ct[OSDP_MLKEM768_CT_LEN];
    st = c->ml_kem768_encaps(c->user, m1.ek, ct, s->ss);
    if (st != OSDP_OK) {
        return st;
    }
    st = c->rand_bytes(c->user, s->nonce_p, sizeof(s->nonce_p));
    if (st != OSDP_OK) {
        return st;
    }

    /* Build the Message 2 core and TH2. */
    static uint8_t core[OSDP_PAIR_CORE_MAX];
    size_t core_len = 0;
    st = osdp_pair_msg2_core_encode(s->nonce_p, sizeof(s->nonce_p),
                                    ct, sizeof(ct),
                                    OSDP_PAIR_CRED_CERT,
                                    s->local.cert, s->local.cert_len,
                                    core, sizeof(core), &core_len);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_th2(c, th1, core, core_len, s->th2);
    if (st != OSDP_OK) {
        return st;
    }

    /* Sign TH2, derive confirmation keys, MAC TH2. */
    st = sign_th(c, OSDP_PAIR_SIG_DOMAIN_MSG2,
                 sizeof(OSDP_PAIR_SIG_DOMAIN_MSG2) - 1, s->th2, s->sig_p);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_derive_confirm_keys(c, s->ss, s->th2, &s->ck);
    if (st != OSDP_OK) {
        return st;
    }
    st = c->hmac_sha256(c->user, s->ck.km2, sizeof(s->ck.km2),
                        s->th2, OSDP_PAIR_HASH_LEN, s->mac_p);
    if (st != OSDP_OK) {
        return st;
    }

    st = osdp_pair_msg2_encode(core, core_len, s->sig_p, sizeof(s->sig_p),
                               s->mac_p, sizeof(s->mac_p), out, out_cap, out_len);
    if (st != OSDP_OK) {
        return st;
    }
    s->state = OSDP_PAIR_PD_AWAIT_MSG3;
    return OSDP_OK;
}

osdp_status_t osdp_pair_pd_process_msg3(osdp_pair_pd_session_t *s,
                                        const uint8_t *msg3_wire, size_t len,
                                        bool *ok,
                                        uint8_t out_scbk[OSDP_PAIR_SCBK_LEN])
{
    if (s == NULL || ok == NULL || out_scbk == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (s->state != OSDP_PAIR_PD_AWAIT_MSG3) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;
    *ok = false;

    osdp_pair_msg3_t m3;
    if (osdp_pair_msg3_decode(msg3_wire, len, &m3) != OSDP_OK) {
        return OSDP_OK;   /* leave *ok=false; caller builds a fail Result */
    }

    uint8_t th3[OSDP_PAIR_HASH_LEN];
    osdp_status_t st = osdp_pair_th3(c, s->th2, s->sig_p, s->mac_p, th3);
    if (st != OSDP_OK) {
        return st;
    }

    if (verify_th(c, s->peer.pubkey, OSDP_PAIR_SIG_DOMAIN_MSG3,
                  sizeof(OSDP_PAIR_SIG_DOMAIN_MSG3) - 1, th3, m3.sig_a)
        != OSDP_OK) {
        return OSDP_OK;
    }

    uint8_t mac_a[OSDP_PAIR_MAC_LEN];
    st = c->hmac_sha256(c->user, s->ck.km3, sizeof(s->ck.km3),
                        th3, OSDP_PAIR_HASH_LEN, mac_a);
    if (st != OSDP_OK) {
        return st;
    }
    if (!mac_equal(mac_a, m3.mac_a)) {
        return OSDP_OK;
    }

    st = osdp_pair_th4(c, th3, m3.sig_a, m3.mac_a, s->th4);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_derive_scbk(c, s->ss, s->th4, s->scbk);
    if (st != OSDP_OK) {
        return st;
    }

    (void)memcpy(out_scbk, s->scbk, OSDP_PAIR_SCBK_LEN);
    *ok = true;
    s->state = OSDP_PAIR_PD_AWAIT_PERSIST;
    return OSDP_OK;
}

osdp_status_t osdp_pair_pd_build_result(osdp_pair_pd_session_t *s,
                                        uint64_t status,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (s == NULL || out == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;

    if (status == OSDP_PAIR_STATUS_SUCCESS) {
        uint8_t mac_r[OSDP_PAIR_MAC_LEN];
        osdp_status_t st = c->hmac_sha256(c->user, s->ck.km4, sizeof(s->ck.km4),
                                          s->th4, OSDP_PAIR_HASH_LEN, mac_r);
        if (st != OSDP_OK) {
            return st;
        }
        st = osdp_pair_result_encode(OSDP_PAIR_STATUS_SUCCESS,
                                     mac_r, sizeof(mac_r), out, out_cap, out_len);
        if (st != OSDP_OK) {
            return st;
        }
        s->state = OSDP_PAIR_PD_COMPLETE;
        return OSDP_OK;
    }

    s->state = OSDP_PAIR_PD_FAILED;
    return osdp_pair_result_encode(status, NULL, 0, out, out_cap, out_len);
}

/* ---- ACU initiator ------------------------------------------------------ */

void osdp_pair_acu_init(osdp_pair_acu_session_t *s,
                        const osdp_pair_crypto_t *crypto,
                        const osdp_pair_local_t *local,
                        const osdp_pair_trust_t *trust)
{
    (void)memset(s, 0, sizeof(*s));
    s->crypto = crypto;
    s->local  = *local;
    s->trust  = *trust;
    s->state  = OSDP_PAIR_ACU_CREATED;
}

osdp_status_t osdp_pair_acu_create_msg1(osdp_pair_acu_session_t *s,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (s == NULL || out == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;

    uint8_t ek[OSDP_MLKEM768_EK_LEN];
    osdp_status_t st = c->ml_kem768_keygen(c->user, ek);
    if (st != OSDP_OK) {
        return st;
    }
    st = c->rand_bytes(c->user, s->nonce_a, sizeof(s->nonce_a));
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_msg1_encode(s->nonce_a, sizeof(s->nonce_a), ek, sizeof(ek),
                               OSDP_PAIR_CRED_CERT,
                               s->local.cert, s->local.cert_len,
                               out, out_cap, out_len);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_th1(c, out, *out_len, s->th1);
    if (st != OSDP_OK) {
        return st;
    }
    s->state = OSDP_PAIR_ACU_AWAIT_MSG2;
    return OSDP_OK;
}

osdp_status_t osdp_pair_acu_process_msg2(osdp_pair_acu_session_t *s,
                                         const uint8_t *msg2_wire, size_t len,
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len)
{
    if (s == NULL || out == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (s->state != OSDP_PAIR_ACU_AWAIT_MSG2) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;

    osdp_pair_msg2_t m2;
    osdp_status_t st = osdp_pair_msg2_decode(msg2_wire, len, &m2);
    if (st != OSDP_OK) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return st;
    }

    /* Authenticate the PD. */
    if (validate_peer(c, &s->trust, m2.cred_type, m2.cred, m2.cred_len,
                      &s->peer) != OSDP_OK) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return OSDP_ERR_BAD_CRC;
    }

    uint8_t th2[OSDP_PAIR_HASH_LEN];
    st = osdp_pair_th2(c, s->th1, m2.core, m2.core_len, th2);
    if (st != OSDP_OK) {
        return st;
    }
    if (verify_th(c, s->peer.pubkey, OSDP_PAIR_SIG_DOMAIN_MSG2,
                  sizeof(OSDP_PAIR_SIG_DOMAIN_MSG2) - 1, th2, m2.sig_p)
        != OSDP_OK) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return OSDP_ERR_BAD_CRC;
    }

    /* Decapsulate and confirm — mac_P mismatch catches a KEM disagreement. */
    uint8_t ss[OSDP_PAIR_SS_LEN];
    st = c->ml_kem768_decaps(c->user, m2.ct, ss);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_derive_confirm_keys(c, ss, th2, &s->ck);
    if (st != OSDP_OK) {
        return st;
    }
    uint8_t mac_p[OSDP_PAIR_MAC_LEN];
    st = c->hmac_sha256(c->user, s->ck.km2, sizeof(s->ck.km2),
                        th2, OSDP_PAIR_HASH_LEN, mac_p);
    if (st != OSDP_OK) {
        return st;
    }
    if (!mac_equal(mac_p, m2.mac_p)) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return OSDP_ERR_BAD_CRC;
    }

    /* TH3, sign, MAC, build Message 3. */
    uint8_t th3[OSDP_PAIR_HASH_LEN];
    st = osdp_pair_th3(c, th2, m2.sig_p, m2.mac_p, th3);
    if (st != OSDP_OK) {
        return st;
    }
    static uint8_t sig_a[OSDP_PAIR_SIG_LEN];
    st = sign_th(c, OSDP_PAIR_SIG_DOMAIN_MSG3,
                 sizeof(OSDP_PAIR_SIG_DOMAIN_MSG3) - 1, th3, sig_a);
    if (st != OSDP_OK) {
        return st;
    }
    uint8_t mac_a[OSDP_PAIR_MAC_LEN];
    st = c->hmac_sha256(c->user, s->ck.km3, sizeof(s->ck.km3),
                        th3, OSDP_PAIR_HASH_LEN, mac_a);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_msg3_encode(sig_a, sizeof(sig_a), mac_a, sizeof(mac_a),
                               out, out_cap, out_len);
    if (st != OSDP_OK) {
        return st;
    }

    /* TH4 and the SCBK (committed only after the Result is confirmed). */
    st = osdp_pair_th4(c, th3, sig_a, mac_a, s->th4);
    if (st != OSDP_OK) {
        return st;
    }
    st = osdp_pair_derive_scbk(c, ss, s->th4, s->scbk);
    if (st != OSDP_OK) {
        return st;
    }
    s->state = OSDP_PAIR_ACU_AWAIT_RESULT;
    return OSDP_OK;
}

osdp_status_t osdp_pair_acu_process_result(osdp_pair_acu_session_t *s,
                                           const uint8_t *result_wire, size_t len,
                                           uint8_t out_scbk[OSDP_PAIR_SCBK_LEN])
{
    if (s == NULL || out_scbk == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (s->state != OSDP_PAIR_ACU_AWAIT_RESULT) {
        return OSDP_ERR_INVALID_ARG;
    }
    const osdp_pair_crypto_t *c = s->crypto;

    osdp_pair_result_t rr;
    osdp_status_t st = osdp_pair_result_decode(result_wire, len, &rr);
    if (st != OSDP_OK) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return st;
    }
    if (rr.status != OSDP_PAIR_STATUS_SUCCESS || rr.mac_len != OSDP_PAIR_MAC_LEN) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return OSDP_ERR_BAD_CRC;
    }

    uint8_t mac_r[OSDP_PAIR_MAC_LEN];
    st = c->hmac_sha256(c->user, s->ck.km4, sizeof(s->ck.km4),
                        s->th4, OSDP_PAIR_HASH_LEN, mac_r);
    if (st != OSDP_OK) {
        return st;
    }
    if (!mac_equal(mac_r, rr.mac)) {
        s->state = OSDP_PAIR_ACU_FAILED;
        return OSDP_ERR_BAD_CRC;
    }

    (void)memcpy(out_scbk, s->scbk, OSDP_PAIR_SCBK_LEN);
    s->state = OSDP_PAIR_ACU_COMPLETE;
    return OSDP_OK;
}
