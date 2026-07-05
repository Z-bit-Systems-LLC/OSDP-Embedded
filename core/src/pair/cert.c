// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pair.h"
#include "osdp/osdp_cbor.h"

#include <stdint.h>
#include <string.h>

/* ---- Encoding ----------------------------------------------------------- */

/* Emit the 8-element TBS array into `w`. Shared by encode_tbs and encode. */
static void write_tbs(osdp_cbor_writer_t *w, const osdp_c509_cert_t *cert)
{
    osdp_cbor_write_array_header(w, 8);
    osdp_cbor_write_uint(w, cert->version);
    osdp_cbor_write_bstr(w, cert->serial, cert->serial_len);
    osdp_cbor_write_tstr(w, cert->issuer, cert->issuer_len);

    osdp_cbor_write_array_header(w, 2);
    osdp_cbor_write_uint(w, cert->not_before);
    osdp_cbor_write_uint(w, cert->not_after);

    osdp_cbor_write_array_header(w, 3);
    osdp_cbor_write_tstr(w, cert->manufacturer, cert->manufacturer_len);
    osdp_cbor_write_tstr(w, cert->model, cert->model_len);
    osdp_cbor_write_tstr(w, cert->subject_serial, cert->subject_serial_len);

    osdp_cbor_write_uint(w, cert->public_key_alg);
    osdp_cbor_write_bstr(w, cert->public_key, cert->public_key_len);
    osdp_cbor_write_uint(w, cert->signature_alg);
}

osdp_status_t osdp_c509_encode_tbs(const osdp_c509_cert_t *cert,
                                   uint8_t *buf, size_t buf_cap,
                                   size_t *written)
{
    if (cert == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, buf_cap);
    write_tbs(&w, cert);
    return osdp_cbor_writer_finish(&w, written);
}

osdp_status_t osdp_c509_encode(const osdp_c509_cert_t *cert,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written)
{
    if (cert == NULL || buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    osdp_cbor_writer_t w;
    osdp_cbor_writer_init(&w, buf, buf_cap);
    osdp_cbor_write_array_header(&w, 2);
    write_tbs(&w, cert);
    osdp_cbor_write_bstr(&w, cert->signature, cert->signature_len);
    return osdp_cbor_writer_finish(&w, written);
}

/* ---- Decoding ----------------------------------------------------------- */

osdp_status_t osdp_c509_decode(const uint8_t *buf, size_t len,
                               osdp_c509_cert_t *out)
{
    if (out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (buf == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    osdp_cbor_reader_t r;
    osdp_cbor_reader_init(&r, buf, len);

    size_t n = 0;
    if (!osdp_cbor_read_array_header(&r, &n) || n != 2) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* The TBS byte span starts here (right after the outer array head) and
     * runs to just before the signature bstr. */
    const size_t tbs_start = r.pos;

    if (!osdp_cbor_read_array_header(&r, &n) || n != 8) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    if (!osdp_cbor_read_uint(&r, &out->version)
        || out->version != OSDP_C509_VERSION) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_bstr(&r, &out->serial, &out->serial_len)
        || out->serial_len != OSDP_C509_SERIAL_LEN) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_tstr(&r, &out->issuer, &out->issuer_len)
        || out->issuer_len > OSDP_PAIR_STR_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    if (!osdp_cbor_read_array_header(&r, &n) || n != 2) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_uint(&r, &out->not_before)
        || !osdp_cbor_read_uint(&r, &out->not_after)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    if (!osdp_cbor_read_array_header(&r, &n) || n != 3) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_tstr(&r, &out->manufacturer, &out->manufacturer_len)
        || out->manufacturer_len > OSDP_PAIR_STR_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_tstr(&r, &out->model, &out->model_len)
        || out->model_len > OSDP_PAIR_STR_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_tstr(&r, &out->subject_serial, &out->subject_serial_len)
        || out->subject_serial_len > OSDP_PAIR_STR_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    if (!osdp_cbor_read_uint(&r, &out->public_key_alg)
        || out->public_key_alg != OSDP_C509_ALG_MLDSA44) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_bstr(&r, &out->public_key, &out->public_key_len)
        || out->public_key_len != OSDP_MLDSA44_PK_LEN) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (!osdp_cbor_read_uint(&r, &out->signature_alg)
        || out->signature_alg != OSDP_C509_ALG_MLDSA44) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* TBS complete; capture its exact bytes for verify. */
    out->tbs     = &buf[tbs_start];
    out->tbs_len = r.pos - tbs_start;
    if (out->tbs_len > OSDP_C509_TBS_MAX) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    if (!osdp_cbor_read_bstr(&r, &out->signature, &out->signature_len)
        || out->signature_len != OSDP_MLDSA44_SIG_LEN) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* Nothing may trail the certificate. */
    if (!osdp_cbor_reader_done(&r)) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    return OSDP_OK;
}

/* ---- Thumbprint / verify (HAL-backed) ----------------------------------- */

osdp_status_t osdp_c509_thumbprint(const osdp_pair_crypto_t *crypto,
                                   const uint8_t *cert_bytes, size_t cert_len,
                                   uint8_t out[OSDP_PAIR_HASH_LEN])
{
    if (crypto == NULL || crypto->sha256 == NULL
        || cert_bytes == NULL || out == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    return crypto->sha256(crypto->user, cert_bytes, cert_len, out);
}

osdp_status_t osdp_c509_verify(const osdp_pair_crypto_t *crypto,
                               const osdp_c509_cert_t *cert,
                               const uint8_t issuer_pubkey[OSDP_MLDSA44_PK_LEN])
{
    if (crypto == NULL || crypto->ml_dsa44_verify == NULL
        || cert == NULL || issuer_pubkey == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (cert->tbs == NULL || cert->signature == NULL
        || cert->signature_len != OSDP_MLDSA44_SIG_LEN
        || cert->tbs_len > OSDP_C509_TBS_MAX) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Signed message = "OSDP-C509-v1" || TBS_encoded. */
    static const char domain[] = OSDP_C509_SIG_DOMAIN;
    const size_t dom_len = sizeof(domain) - 1U;

    uint8_t msg[sizeof(domain) - 1U + OSDP_C509_TBS_MAX];
    (void)memcpy(msg, domain, dom_len);
    (void)memcpy(&msg[dom_len], cert->tbs, cert->tbs_len);

    return crypto->ml_dsa44_verify(crypto->user, issuer_pubkey,
                                   msg, dom_len + cert->tbs_len,
                                   cert->signature);
}
