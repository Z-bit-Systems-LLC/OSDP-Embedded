// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_sc2.h"

#include <string.h>

/* OSDP-SC2 frame wrap / unwrap (SCS_25..28), AES-256-GCM.
 *
 * The SC2 "MAC" is the 16-byte GCM tag; there is no rolling MAC chain
 * (SC1's mechanism). Anti-replay is a single shared message counter
 * feeding a per-message nonce. Both wrap and unwrap advance the counter
 * by one, keeping the two peers in lockstep (ACU wraps @N while the PD
 * unwraps @N, then the PD wraps its reply @N+1 while the ACU unwraps
 * @N+1, and so on).
 *
 * AAD is the frame header including the security block:
 *   SOM || ADDR || LEN(2) || CTRL || SEC_BLK_LEN || SEC_BLK_TYPE
 * i.e. every byte before the code/ciphertext — matching the annex
 * "Wrap Operation" (header = SOM||ADDR||LEN||CTRL||SEC_BLK). Pinned by
 * the annex full-frame known-answer vectors in test_sc2_wrap.c.
 *
 * SCS_27/28 (encrypted): the plaintext code||data is GCM-encrypted in
 *   place; AAD is the 7-byte header; the tag authenticates header+ct.
 * SCS_25/26 (authenticated only, dev/test): code||data are sent in the
 *   clear and folded into the AAD (header || code || data) with an
 *   empty GCM plaintext, so the tag authenticates them without
 *   encryption. Production traffic uses SCS_27/28. */

/* Scratch for the recovered plaintext during unwrap; sized to the
 * baseline message set. */
#define OSDP_SC2_UNWRAP_SCRATCH_LEN 256U

static size_t header_aad_len(const osdp_frame_t *f)
{
    /* All bytes from SOM through the end of the SCB. */
    return OSDP_FRAME_HEADER_LEN + (size_t)f->scb_length;
}

osdp_status_t osdp_sc2_wrap_frame(
    const osdp_sc2_crypto_t *crypto,
    osdp_sc2_session_t      *session,
    const osdp_frame_t      *plain_template,
    uint8_t                 *out_buf,
    size_t                   out_cap,
    size_t                  *out_len)
{
    if (crypto == NULL || crypto->aes256_gcm_encrypt == NULL ||
        session == NULL || plain_template == NULL ||
        out_buf == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *out_len = 0;
    if (!session->established) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!plain_template->has_scb ||
        osdp_scb_mac_len(plain_template->scb_type) != OSDP_SC2_TAG_LEN) {
        /* SC2 operational wrap is only for SCS_25..28. */
        return OSDP_ERR_INVALID_ARG;
    }

    const bool encrypted = osdp_scb_is_encrypted(plain_template->scb_type);

    /* Derive the per-message nonce from the current counter. */
    uint8_t nonce[OSDP_SC2_NONCE_LEN];
    osdp_status_t s = osdp_sc2_compute_nonce(
        crypto, session->keys.s_nonce, session->cuid, session->counter, nonce);
    if (s != OSDP_OK) {
        return s;
    }

    /* Build the frame with the plaintext code||data in place and a
     * zero-filled tag slot. This fixes the header bytes (LEN, CTRL,
     * SCB) that form the AAD, and lays out the region we encrypt. */
    osdp_frame_t built = *plain_template;
    uint8_t tag_placeholder[OSDP_SC2_TAG_LEN] = {0};
    built.mac     = tag_placeholder;
    built.mac_len = OSDP_SC2_TAG_LEN;

    size_t built_len = 0;
    s = osdp_frame_build(&built, out_buf, out_cap, &built_len);
    if (s != OSDP_OK) {
        return s;
    }

    /* Work relative to the SOM (the marking byte precedes it and is not
     * part of the message / AAD / CRC). */
    uint8_t *const frame     = out_buf + OSDP_FRAME_MARK_LEN;
    const size_t   frame_len = built_len - OSDP_FRAME_MARK_LEN;

    const size_t integrity_size =
        (built.integrity == OSDP_INTEGRITY_CRC) ? 2u : 1u;
    const size_t aad_len   = header_aad_len(&built);
    const size_t data_off  = aad_len;                    /* code||data start */
    const size_t data_len  = 1u + plain_template->payload_len;  /* code+data */
    const size_t tag_off   = data_off + data_len;
    const size_t crc_off   = frame_len - integrity_size;

    uint8_t tag[OSDP_SC2_TAG_LEN];
    if (encrypted) {
        /* GCM-encrypt code||data in place; AAD = 7-byte header. */
        s = crypto->aes256_gcm_encrypt(
            crypto->user, session->keys.s_enc, nonce,
            frame, aad_len,
            &frame[data_off], data_len,
            &frame[data_off], tag);
    } else {
        /* Authenticated-only: AAD = header || code||data, empty PT. */
        s = crypto->aes256_gcm_encrypt(
            crypto->user, session->keys.s_enc, nonce,
            frame, tag_off,
            NULL, 0,
            NULL, tag);
    }
    if (s != OSDP_OK) {
        return s;
    }

    /* Write the real tag over the placeholder, then recompute integrity. */
    (void)memcpy(&frame[tag_off], tag, OSDP_SC2_TAG_LEN);
    if (built.integrity == OSDP_INTEGRITY_CRC) {
        const uint16_t crc = osdp_crc16(frame, crc_off);
        frame[crc_off]     = (uint8_t)(crc & 0xFFu);
        frame[crc_off + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    } else {
        frame[crc_off] = osdp_checksum(frame, crc_off);
    }

    /* Advance the shared message counter. */
    session->counter++;

    *out_len = built_len;
    return OSDP_OK;
}

osdp_status_t osdp_sc2_unwrap_frame(
    const osdp_sc2_crypto_t *crypto,
    osdp_sc2_session_t      *session,
    const osdp_frame_t      *frame,
    uint8_t                 *code_out,
    uint8_t                 *plaintext_out,
    size_t                   plain_cap,
    size_t                  *plain_len)
{
    if (crypto == NULL || crypto->aes256_gcm_decrypt == NULL ||
        session == NULL || frame == NULL || code_out == NULL ||
        plain_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *plain_len = 0;
    if (!session->established) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!frame->has_scb ||
        osdp_scb_mac_len(frame->scb_type) != OSDP_SC2_TAG_LEN) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (frame->mac_len != OSDP_SC2_TAG_LEN || frame->mac == NULL ||
        frame->raw == NULL || frame->raw_len == 0) {
        return OSDP_ERR_INVALID_ARG;
    }

    const bool encrypted = osdp_scb_is_encrypted(frame->scb_type);

    /* Derive the nonce for the current shared counter. */
    uint8_t nonce[OSDP_SC2_NONCE_LEN];
    osdp_status_t s = osdp_sc2_compute_nonce(
        crypto, session->keys.s_nonce, session->cuid, session->counter, nonce);
    if (s != OSDP_OK) {
        return s;
    }

    /* The ciphertext (or authenticated plaintext) is code||data: the
     * decoded frame's `code` byte followed by its `payload`. In the raw
     * buffer these are contiguous starting right after the SCB. */
    const size_t aad_len  = header_aad_len(frame);
    const size_t data_len = 1u + frame->payload_len;   /* code + data */
    const uint8_t *data   = &frame->raw[aad_len];

    if (encrypted) {
        if (frame->payload_len > plain_cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        /* Decrypt code||data into a scratch, verifying the tag over the
         * 7-byte header AAD. */
        uint8_t scratch[OSDP_SC2_UNWRAP_SCRATCH_LEN];
        if (data_len > sizeof(scratch)) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        s = crypto->aes256_gcm_decrypt(
            crypto->user, session->keys.s_enc, nonce,
            frame->raw, aad_len,
            data, data_len,
            frame->mac, scratch);
        if (s != OSDP_OK) {
            return s;   /* OSDP_ERR_BAD_CRC on tag mismatch */
        }
        *code_out = scratch[0];
        if (frame->payload_len > 0 && plaintext_out != NULL) {
            (void)memcpy(plaintext_out, &scratch[1], frame->payload_len);
        }
        *plain_len = frame->payload_len;
    } else {
        /* Authenticated-only: verify the tag over header||code||data
         * (empty GCM plaintext) and hand back the cleartext. */
        s = crypto->aes256_gcm_decrypt(
            crypto->user, session->keys.s_enc, nonce,
            frame->raw, aad_len + data_len,
            NULL, 0,
            frame->mac, NULL);
        if (s != OSDP_OK) {
            return s;
        }
        if (frame->payload_len > plain_cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        *code_out = frame->code;
        if (frame->payload_len > 0 && plaintext_out != NULL) {
            (void)memcpy(plaintext_out, frame->payload, frame->payload_len);
        }
        *plain_len = frame->payload_len;
    }

    session->counter++;
    return OSDP_OK;
}
