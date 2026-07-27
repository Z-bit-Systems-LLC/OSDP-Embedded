// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_checksum.h"
#include "osdp/osdp_crc.h"
#include "osdp/osdp_sc.h"

#include <string.h>

osdp_status_t osdp_sc_max_payload(const osdp_frame_t *shape,
                                  size_t buf_cap,
                                  size_t *out_max_payload)
{
    if (shape == NULL || out_max_payload == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    size_t framed = 0;
    const osdp_status_t s = osdp_frame_max_payload(shape, buf_cap, &framed);
    if (s != OSDP_OK) {
        return s;
    }

    if (!shape->has_scb || !osdp_scb_is_encrypted(shape->scb_type)) {
        /* SCS_15/16 carry the payload in the clear under a MAC — no
         * ciphertext expansion, so the framing answer stands. */
        *out_max_payload = framed;
        return OSDP_OK;
    }

    /* `framed` is how much CIPHERTEXT fits. Ciphertext is the plaintext
     * padded per spec D.4.5: always at least one byte (0x80) added, then
     * rounded up to a whole AES block. So the usable ciphertext is the
     * largest whole number of blocks that fits, and the plaintext is one
     * byte less than that — the pad marker always claims a byte, even when
     * the plaintext already lands on a block boundary. */
    const size_t whole_blocks = framed / OSDP_AES_BLOCK_LEN;
    *out_max_payload =
        (whole_blocks == 0) ? 0u : (whole_blocks * OSDP_AES_BLOCK_LEN) - 1u;
    return OSDP_OK;
}

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

    if (osdp_scb_is_encrypted(built.scb_type)) {
        /* Encrypt straight into the ciphertext's final position in `out_buf`
         * rather than through a scratch array. A fixed scratch would cap
         * every Secure Channel message at its size no matter how much output
         * capacity the caller supplied, and sizing it for the spec maximum
         * would put 1440 bytes on the stack of every wrap call — unacceptable
         * on the MCUs this library targets. Writing in place costs neither.
         *
         * osdp_frame_payload_offset owns the layout arithmetic, and
         * osdp_frame_build recognises a payload pointer that already equals
         * its destination and skips the copy. osdp_sc_encrypt_payload
         * documents that its plaintext may alias its ciphertext (it memmoves
         * before appending padding), which is what makes the SCS_17/18 case
         * — where the plaintext is elsewhere and only the padding is written
         * here — safe either way. */
        size_t payload_off = 0;
        osdp_status_t s = osdp_frame_payload_offset(&built, &payload_off);
        if (s != OSDP_OK) {
            return s;
        }
        if (payload_off >= out_cap) {
            return OSDP_ERR_BUFFER_TOO_SMALL;
        }

        size_t enc_len = 0;
        s = osdp_sc_encrypt_payload(
            crypto, session->keys.s_enc, session->last_inbound_mac,
            plain_template->payload, plain_template->payload_len,
            out_buf + payload_off, out_cap - payload_off, &enc_len);
        if (s != OSDP_OK) {
            return s;
        }
        built.payload     = out_buf + payload_off;
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

    /* osdp_frame_build prepends the spec-5.7 marking byte(s) ahead of
     * the SOM. The MAC and CRC cover only the frame (SOM..integrity) —
     * the marking is not part of the OSDP message — so work relative
     * to the SOM, exactly like the unwrap/decode side, which operates
     * on frame->raw (a SOM-based slice). out_len still carries the
     * full buffer (marking + frame) for transmission. */
    uint8_t *const frame   = out_buf + OSDP_FRAME_MARK_LEN;
    const size_t   frame_len = built_len - OSDP_FRAME_MARK_LEN;

    const size_t integrity_size =
        (built.integrity == OSDP_INTEGRITY_CRC) ? 2u : 1u;
    const size_t mac_offset =
        frame_len - integrity_size - OSDP_FRAME_MAC_LEN;
    const size_t crc_offset = frame_len - integrity_size;

    /* Compute the real MAC over [SOM .. last data byte). Spec D.5
     * specifies that the MAC range covers the entire message except
     * the trailing MAC and CRC bytes (and excludes the marking byte,
     * which is not part of the message). */
    uint8_t mac_full[OSDP_SC_MAC_LEN];
    s = osdp_sc_compute_mac(crypto,
                            session->keys.s_mac1,
                            session->keys.s_mac2,
                            session->last_inbound_mac,
                            frame, mac_offset, mac_full);
    if (s != OSDP_OK) {
        return s;
    }

    /* Patch in the truncated MAC (first 4 bytes). */
    (void)memcpy(&frame[mac_offset], mac_full, OSDP_FRAME_MAC_LEN);

    /* Recompute integrity now that the MAC is real. */
    if (built.integrity == OSDP_INTEGRITY_CRC) {
        const uint16_t crc = osdp_crc16(frame, crc_offset);
        frame[crc_offset]     = (uint8_t)(crc & 0xFFu);
        frame[crc_offset + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    } else {
        frame[crc_offset] = osdp_checksum(frame, crc_offset);
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
