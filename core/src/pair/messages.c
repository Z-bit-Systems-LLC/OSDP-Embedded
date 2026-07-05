// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"
#include "osdp/osdp_cbor.h"

#include <stdint.h>
#include <string.h>

/* ---- Encode helpers ----------------------------------------------------- */

/* Write a 1-byte type tag then a CBOR body built by `w` (initialised on
 * buf+1). Finalises and reports the total (tag + body). */
static osdp_status_t finish_tagged(uint8_t *buf, size_t buf_cap, uint8_t tag,
                                   osdp_cbor_writer_t *w, size_t *written)
{
    if (buf_cap < 1) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    size_t body_len = 0;
    osdp_status_t st = osdp_cbor_writer_finish(w, &body_len);
    if (st != OSDP_OK) {
        return st;
    }
    buf[0] = tag;
    *written = 1 + body_len;
    return OSDP_OK;
}

osdp_status_t osdp_pair_msg1_encode(const uint8_t *nonce_a, size_t nonce_a_len,
                                    const uint8_t *ek, size_t ek_len,
                                    uint64_t cred_type,
                                    const uint8_t *cred, size_t cred_len,
                                    uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (buf == NULL || written == NULL || buf_cap < 1) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, &buf[1], buf_cap - 1);
    osdp_cbor_write_array_header(&w, 6);
    osdp_cbor_write_uint(&w, OSDP_PAIR_PROTOCOL_VERSION);
    osdp_cbor_write_uint(&w, OSDP_PAIR_CIPHER_SUITE);
    osdp_cbor_write_bstr(&w, nonce_a, nonce_a_len);
    osdp_cbor_write_bstr(&w, ek, ek_len);
    osdp_cbor_write_uint(&w, cred_type);
    osdp_cbor_write_bstr(&w, cred, cred_len);
    return finish_tagged(buf, buf_cap, OSDP_PAIR_MSG_TYPE_1, &w, written);
}

osdp_status_t osdp_pair_msg2_core_encode(const uint8_t *nonce_p, size_t nonce_p_len,
                                         const uint8_t *ct, size_t ct_len,
                                         uint64_t cred_type,
                                         const uint8_t *cred, size_t cred_len,
                                         uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, buf_cap);
    osdp_cbor_write_array_header(&w, 4);
    osdp_cbor_write_bstr(&w, nonce_p, nonce_p_len);
    osdp_cbor_write_bstr(&w, ct, ct_len);
    osdp_cbor_write_uint(&w, cred_type);
    osdp_cbor_write_bstr(&w, cred, cred_len);
    return osdp_cbor_writer_finish(&w, written);
}

osdp_status_t osdp_pair_msg2_encode(const uint8_t *core, size_t core_len,
                                    const uint8_t *sig_p, size_t sig_p_len,
                                    const uint8_t *mac_p, size_t mac_p_len,
                                    uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (buf == NULL || written == NULL || buf_cap < 1) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, &buf[1], buf_cap - 1);
    osdp_cbor_write_array_header(&w, 3);
    osdp_cbor_write_bstr(&w, core, core_len);
    osdp_cbor_write_bstr(&w, sig_p, sig_p_len);
    osdp_cbor_write_bstr(&w, mac_p, mac_p_len);
    return finish_tagged(buf, buf_cap, OSDP_PAIR_MSG_TYPE_2, &w, written);
}

osdp_status_t osdp_pair_msg3_encode(const uint8_t *sig_a, size_t sig_a_len,
                                    const uint8_t *mac_a, size_t mac_a_len,
                                    uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (buf == NULL || written == NULL || buf_cap < 1) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, &buf[1], buf_cap - 1);
    osdp_cbor_write_array_header(&w, 2);
    osdp_cbor_write_bstr(&w, sig_a, sig_a_len);
    osdp_cbor_write_bstr(&w, mac_a, mac_a_len);
    return finish_tagged(buf, buf_cap, OSDP_PAIR_MSG_TYPE_3, &w, written);
}

osdp_status_t osdp_pair_result_encode(uint64_t status,
                                      const uint8_t *mac, size_t mac_len,
                                      uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (buf == NULL || written == NULL || buf_cap < 1) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, &buf[1], buf_cap - 1);
    osdp_cbor_write_array_header(&w, 2);
    osdp_cbor_write_uint(&w, status);
    osdp_cbor_write_bstr(&w, mac, mac_len);
    return finish_tagged(buf, buf_cap, OSDP_PAIR_MSG_TYPE_RESULT, &w, written);
}

/* ---- Decode helpers ----------------------------------------------------- */

/* Verify the type tag and initialise a reader over the CBOR body. */
static osdp_status_t reader_for(const uint8_t *wire, size_t len, uint8_t tag,
                                osdp_cbor_reader_t *r)
{
    if (wire == NULL || len < 1 || wire[0] != tag) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    osdp_cbor_reader_init(r, &wire[1], len - 1);
    return OSDP_OK;
}

osdp_status_t osdp_pair_msg1_decode(const uint8_t *wire, size_t len,
                                    osdp_pair_msg1_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_reader_t r;
    osdp_status_t st = reader_for(wire, len, OSDP_PAIR_MSG_TYPE_1, &r);
    if (st != OSDP_OK) {
        return st;
    }

    size_t n = 0;
    if (!osdp_cbor_read_array_header(&r, &n) || n != 6
        || !osdp_cbor_read_uint(&r, &out->version)
        || !osdp_cbor_read_uint(&r, &out->suite)
        || !osdp_cbor_read_bstr(&r, &out->nonce_a, &out->nonce_a_len)
        || !osdp_cbor_read_bstr(&r, &out->ek, &out->ek_len)
        || !osdp_cbor_read_uint(&r, &out->cred_type)
        || !osdp_cbor_read_bstr(&r, &out->cred, &out->cred_len)
        || !osdp_cbor_reader_done(&r)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (out->nonce_a_len != OSDP_PAIR_NONCE_LEN
        || out->ek_len != OSDP_MLKEM768_EK_LEN
        || (out->cred_type == OSDP_PAIR_CRED_THUMBPRINT
            && out->cred_len != OSDP_PAIR_HASH_LEN)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    out->wire     = wire;
    out->wire_len = len;
    return OSDP_OK;
}

osdp_status_t osdp_pair_msg2_decode(const uint8_t *wire, size_t len,
                                    osdp_pair_msg2_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_reader_t r;
    osdp_status_t st = reader_for(wire, len, OSDP_PAIR_MSG_TYPE_2, &r);
    if (st != OSDP_OK) {
        return st;
    }

    size_t n = 0;
    if (!osdp_cbor_read_array_header(&r, &n) || n != 3
        || !osdp_cbor_read_bstr(&r, &out->core, &out->core_len)
        || !osdp_cbor_read_bstr(&r, &out->sig_p, &out->sig_p_len)
        || !osdp_cbor_read_bstr(&r, &out->mac_p, &out->mac_p_len)
        || !osdp_cbor_reader_done(&r)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (out->sig_p_len != OSDP_PAIR_SIG_LEN
        || out->mac_p_len != OSDP_PAIR_MAC_LEN
        || out->core_len > OSDP_PAIR_CORE_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* Parse the nested core = array(4). */
    osdp_cbor_reader_t cr;
    osdp_cbor_reader_init(&cr, out->core, out->core_len);
    if (!osdp_cbor_read_array_header(&cr, &n) || n != 4
        || !osdp_cbor_read_bstr(&cr, &out->nonce_p, &out->nonce_p_len)
        || !osdp_cbor_read_bstr(&cr, &out->ct, &out->ct_len)
        || !osdp_cbor_read_uint(&cr, &out->cred_type)
        || !osdp_cbor_read_bstr(&cr, &out->cred, &out->cred_len)
        || !osdp_cbor_reader_done(&cr)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (out->nonce_p_len != OSDP_PAIR_NONCE_LEN
        || out->ct_len != OSDP_PAIR_CT_LEN
        || (out->cred_type == OSDP_PAIR_CRED_THUMBPRINT
            && out->cred_len != OSDP_PAIR_HASH_LEN)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_pair_msg3_decode(const uint8_t *wire, size_t len,
                                    osdp_pair_msg3_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_reader_t r;
    osdp_status_t st = reader_for(wire, len, OSDP_PAIR_MSG_TYPE_3, &r);
    if (st != OSDP_OK) {
        return st;
    }

    size_t n = 0;
    if (!osdp_cbor_read_array_header(&r, &n) || n != 2
        || !osdp_cbor_read_bstr(&r, &out->sig_a, &out->sig_a_len)
        || !osdp_cbor_read_bstr(&r, &out->mac_a, &out->mac_a_len)
        || !osdp_cbor_reader_done(&r)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (out->sig_a_len != OSDP_PAIR_SIG_LEN
        || out->mac_a_len != OSDP_PAIR_MAC_LEN) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

osdp_status_t osdp_pair_result_decode(const uint8_t *wire, size_t len,
                                      osdp_pair_result_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_reader_t r;
    osdp_status_t st = reader_for(wire, len, OSDP_PAIR_MSG_TYPE_RESULT, &r);
    if (st != OSDP_OK) {
        return st;
    }

    size_t n = 0;
    if (!osdp_cbor_read_array_header(&r, &n) || n != 2
        || !osdp_cbor_read_uint(&r, &out->status)
        || !osdp_cbor_read_bstr(&r, &out->mac, &out->mac_len)
        || !osdp_cbor_reader_done(&r)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (out->mac_len != 0 && out->mac_len != OSDP_PAIR_MAC_LEN) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

/* ---- Transcript hashes -------------------------------------------------- */

osdp_status_t osdp_pair_th1(const osdp_pair_crypto_t *crypto,
                            const uint8_t *msg1_wire, size_t len,
                            uint8_t out_th1[OSDP_PAIR_HASH_LEN])
{
    if (crypto == NULL || crypto->sha256 == NULL
        || msg1_wire == NULL || out_th1 == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    return crypto->sha256(crypto->user, msg1_wire, len, out_th1);
}

osdp_status_t osdp_pair_th2(const osdp_pair_crypto_t *crypto,
                            const uint8_t th1[OSDP_PAIR_HASH_LEN],
                            const uint8_t *core, size_t core_len,
                            uint8_t out_th2[OSDP_PAIR_HASH_LEN])
{
    if (crypto == NULL || crypto->sha256 == NULL
        || th1 == NULL || core == NULL || out_th2 == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (core_len > OSDP_PAIR_CORE_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }
    uint8_t scratch[OSDP_PAIR_HASH_LEN + OSDP_PAIR_CORE_MAX];
    (void)memcpy(scratch, th1, OSDP_PAIR_HASH_LEN);
    (void)memcpy(&scratch[OSDP_PAIR_HASH_LEN], core, core_len);
    return crypto->sha256(crypto->user, scratch,
                          OSDP_PAIR_HASH_LEN + core_len, out_th2);
}

/* TH3/TH4 share the shape SHA256(prev || sig(2420) || mac(32)). */
static osdp_status_t th_sig_mac(const osdp_pair_crypto_t *crypto,
                                const uint8_t prev[OSDP_PAIR_HASH_LEN],
                                const uint8_t sig[OSDP_PAIR_SIG_LEN],
                                const uint8_t mac[OSDP_PAIR_MAC_LEN],
                                uint8_t out[OSDP_PAIR_HASH_LEN])
{
    if (crypto == NULL || crypto->sha256 == NULL
        || prev == NULL || sig == NULL || mac == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    uint8_t scratch[OSDP_PAIR_HASH_LEN + OSDP_PAIR_SIG_LEN + OSDP_PAIR_MAC_LEN];
    size_t p = 0;
    (void)memcpy(&scratch[p], prev, OSDP_PAIR_HASH_LEN); p += OSDP_PAIR_HASH_LEN;
    (void)memcpy(&scratch[p], sig, OSDP_PAIR_SIG_LEN);   p += OSDP_PAIR_SIG_LEN;
    (void)memcpy(&scratch[p], mac, OSDP_PAIR_MAC_LEN);   p += OSDP_PAIR_MAC_LEN;
    return crypto->sha256(crypto->user, scratch, p, out);
}

osdp_status_t osdp_pair_th3(const osdp_pair_crypto_t *crypto,
                            const uint8_t th2[OSDP_PAIR_HASH_LEN],
                            const uint8_t sig_p[OSDP_PAIR_SIG_LEN],
                            const uint8_t mac_p[OSDP_PAIR_MAC_LEN],
                            uint8_t out_th3[OSDP_PAIR_HASH_LEN])
{
    return th_sig_mac(crypto, th2, sig_p, mac_p, out_th3);
}

osdp_status_t osdp_pair_th4(const osdp_pair_crypto_t *crypto,
                            const uint8_t th3[OSDP_PAIR_HASH_LEN],
                            const uint8_t sig_a[OSDP_PAIR_SIG_LEN],
                            const uint8_t mac_a[OSDP_PAIR_MAC_LEN],
                            uint8_t out_th4[OSDP_PAIR_HASH_LEN])
{
    return th_sig_mac(crypto, th3, sig_a, mac_a, out_th4);
}
