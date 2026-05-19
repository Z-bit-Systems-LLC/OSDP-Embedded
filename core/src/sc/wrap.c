// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_sc.h"

#include <string.h>

/* Internal scratch sized to match the PD/ACU TX buffer. Holds the
 * encrypted payload between the encrypt step and the frame build for
 * SCS_17/18 frames. 256 bytes is enough for the baseline message set
 * even after worst-case padding; can grow alongside OSDP_PD_TX_BUF_LEN
 * if extended message types arrive. */
#define OSDP_SC_WRAP_SCRATCH_LEN 256U

osdp_status_t osdp_sc_wrap_frame(
    const osdp_sc_crypto_t  *crypto,
    osdp_sc_session_t       *session,
    const osdp_frame_t      *plain_template,
    uint8_t                 *out_buf,
    size_t                   out_cap,
    size_t                  *out_len)
{
    if (crypto == NULL || session == NULL ||
        plain_template == NULL || out_buf == NULL || out_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *out_len = 0;
    if (!session->established) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!plain_template->has_scb ||
        !osdp_scb_has_mac(plain_template->scb_type)) {
        /* wrap is only for SCS_15..18; handshake frames go through
         * osdp_frame_build directly. */
        return OSDP_ERR_INVALID_ARG;
    }

    /* Construct a working copy of the template that we'll mutate
     * below — point at the (possibly-encrypted) payload bytes plus
     * a placeholder MAC. */
    osdp_frame_t built = *plain_template;
    uint8_t mac_placeholder[OSDP_FRAME_MAC_LEN] = {0};
    built.mac     = mac_placeholder;
    built.mac_len = OSDP_FRAME_MAC_LEN;

    /* Project convention (spec D.1.4 interpretation): SCS_15/16 carry
     * a MAC over plaintext-only frames; SCS_17/18 add encrypted DATA.
     * The right SCB type is dictated by payload presence, not by what
     * the inbound peer happened to send — an ACU's empty SCS_15 POLL
     * can still draw a data-bearing SCS_18 reply when the PD has a
     * RAW/KEYPAD/LSTATR event to report, and vice versa. Coerce both
     * ways here so callers can pick "command direction" or "reply
     * direction" generically and let the wrap step pick plaintext-
     * vs-encrypted based on what's actually in the payload.
     *
     * Downgrade (data variant → plaintext variant when payload
     * empty) avoids the all-padding ciphertext that some ACUs
     * (notably OSDP.Net's ACUConsole) reject. Upgrade (plaintext
     * variant → data variant when payload non-empty) avoids handing
     * an SCS_15/16 frame plaintext bytes the spec doesn't allow
     * there — which would either parse as malformed on the peer or
     * confuse its MAC chain and trip session-loss detection. */
    if (built.payload_len == 0) {
        if (built.scb_type == OSDP_SCS_17) {
            built.scb_type = OSDP_SCS_15;
        } else if (built.scb_type == OSDP_SCS_18) {
            built.scb_type = OSDP_SCS_16;
        }
    } else {
        if (built.scb_type == OSDP_SCS_15) {
            built.scb_type = OSDP_SCS_17;
        } else if (built.scb_type == OSDP_SCS_16) {
            built.scb_type = OSDP_SCS_18;
        }
    }

    uint8_t encrypt_scratch[OSDP_SC_WRAP_SCRATCH_LEN];
    if (osdp_scb_is_encrypted(built.scb_type)) {
        size_t enc_len = 0;
        const osdp_status_t s = osdp_sc_encrypt_payload(
            crypto, session->keys.s_enc, session->last_inbound_mac,
            plain_template->payload, plain_template->payload_len,
            encrypt_scratch, sizeof(encrypt_scratch), &enc_len);
        if (s != OSDP_OK) {
            return s;
        }
        built.payload     = encrypt_scratch;
        built.payload_len = enc_len;
    }

    /* Build the wire bytes with the MAC slot zero-filled. The CRC
     * computed by osdp_frame_build covers the placeholder MAC, so
     * we'll need to recompute it after patching the real MAC. */
    size_t built_len = 0;
    osdp_status_t s = osdp_frame_build(&built, out_buf, out_cap,
                                       &built_len);
    if (s != OSDP_OK) {
        return s;
    }

    const size_t integrity_size =
        (built.integrity == OSDP_INTEGRITY_CRC) ? 2u : 1u;
    const size_t mac_offset =
        built_len - integrity_size - OSDP_FRAME_MAC_LEN;
    const size_t crc_offset = built_len - integrity_size;

    /* Compute the real MAC over [SOM .. last data byte). Spec D.5
     * specifies that the MAC range covers the entire message except
     * the trailing MAC and CRC bytes. */
    uint8_t mac_full[OSDP_SC_MAC_LEN];
    s = osdp_sc_compute_mac(crypto,
                            session->keys.s_mac1,
                            session->keys.s_mac2,
                            session->last_inbound_mac,
                            out_buf, mac_offset, mac_full);
    if (s != OSDP_OK) {
        return s;
    }

    /* Patch in the truncated MAC (first 4 bytes). */
    (void)memcpy(&out_buf[mac_offset], mac_full, OSDP_FRAME_MAC_LEN);

    /* Recompute integrity now that the MAC is real. */
    if (built.integrity == OSDP_INTEGRITY_CRC) {
        const uint16_t crc = osdp_crc16(out_buf, crc_offset);
        out_buf[crc_offset]     = (uint8_t)(crc & 0xFFu);
        out_buf[crc_offset + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    } else {
        out_buf[crc_offset] = osdp_checksum(out_buf, crc_offset);
    }

    /* Advance the rolling MAC chain. Outbound C-MAC (or R-MAC) is now
     * the ICV the peer will use to verify our message. */
    (void)memcpy(session->last_outbound_mac, mac_full, OSDP_SC_MAC_LEN);

    *out_len = built_len;
    return OSDP_OK;
}

osdp_status_t osdp_sc_unwrap_frame(
    const osdp_sc_crypto_t  *crypto,
    osdp_sc_session_t       *session,
    const osdp_frame_t      *frame,
    uint8_t                 *plaintext_out,
    size_t                   plain_cap,
    size_t                  *plain_len)
{
    if (crypto == NULL || session == NULL || frame == NULL ||
        plain_len == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *plain_len = 0;
    if (!session->established) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!frame->has_scb || !osdp_scb_has_mac(frame->scb_type)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (frame->mac_len != OSDP_FRAME_MAC_LEN || frame->mac == NULL) {
        /* Inconsistent: a SCS_15..18 frame must have a 4-byte MAC.
         * Should be unreachable if frame came from osdp_frame_decode
         * but check anyway. */
        return OSDP_ERR_INVALID_ARG;
    }
    if (frame->raw == NULL || frame->raw_len == 0) {
        return OSDP_ERR_INVALID_ARG;
    }

    /* Re-derive MAC offset from the raw byte layout — same formula
     * as in wrap_frame. */
    const size_t integrity_size =
        (frame->integrity == OSDP_INTEGRITY_CRC) ? 2u : 1u;
    const size_t mac_offset =
        frame->raw_len - integrity_size - OSDP_FRAME_MAC_LEN;

    uint8_t expected_mac[OSDP_SC_MAC_LEN];
    osdp_status_t s = osdp_sc_compute_mac(
        crypto, session->keys.s_mac1, session->keys.s_mac2,
        session->last_outbound_mac,    /* peer's verify ICV is our last sent */
        frame->raw, mac_offset, expected_mac);
    if (s != OSDP_OK) {
        return s;
    }
    if (memcmp(expected_mac, frame->mac, OSDP_FRAME_MAC_LEN) != 0) {
        return OSDP_ERR_BAD_CRC;
    }

    /* Decrypt or copy the payload, then advance the rolling MAC
     * AFTER decryption uses last_outbound_mac as IV (per spec). */
    if (osdp_scb_is_encrypted(frame->scb_type)) {
        s = osdp_sc_decrypt_payload(
            crypto, session->keys.s_enc, session->last_outbound_mac,
            frame->payload, frame->payload_len,
            plaintext_out, plain_cap, plain_len);
        if (s != OSDP_OK) {
            return s;
        }
    } else {
        if (frame->payload_len > plain_cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }
        if (frame->payload_len > 0) {
            if (plaintext_out == NULL) {
                return OSDP_ERR_INVALID_ARG;
            }
            (void)memcpy(plaintext_out, frame->payload, frame->payload_len);
        }
        *plain_len = frame->payload_len;
    }

    (void)memcpy(session->last_inbound_mac, expected_mac, OSDP_SC_MAC_LEN);
    return OSDP_OK;
}
