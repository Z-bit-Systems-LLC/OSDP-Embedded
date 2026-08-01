// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp_PDCAP support: an advisory consistency check, a starting-point
 * default capability set, and dynamic binding for osdp_pd_internal_dispatch
 * to answer osdp_CAP directly.
 *
 * PDCAP is a set of promises. The ACU acts on them: spec §6 has it bound
 * osdp_LED record counts by function code 10, and an ACU told the PD accepts
 * 1440-byte messages will send them. A PD that advertises more than it can
 * honour does not fail loudly — it drops frames the ACU believes were
 * delivered, which surfaces later as unexplained retries.
 *
 * Most of a capability set (how many inputs, which card formats, what the
 * reader hardware is) is knowledge only the application has, so the library
 * cannot build all of PDCAP for it. What it CAN do is own the handful of
 * function codes whose truth it — not the application — knows, because they
 * describe the library's own limits or this PD instance's live state rather
 * than the device: see is_reserved_pdcap_fn's doc comment for exactly which,
 * osdp_pd_pdcap_template for the rest, and osdp_pd_set_pdcap for how the two
 * combine into what pd_dispatch.c actually answers osdp_CAP with.
 *
 * osdp_pd_check_pdcap remains independently useful and purely advisory —
 * touches no wire state, nothing calls it automatically — for an application
 * building its own records[] by hand (osdp_pd_set_pdcap not used at all).
 * Everything in this file lives in its own translation unit so a PD that
 * uses none of it does not link any of it. */

#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include "pd_internal.h"

#include <string.h>

/* PDCAP function codes this check understands (spec Annex B). Annex B in
 * the reference text this project was built from ends at function code 16
 * (OSDP Version) — there is no function code 17 or 18 to define here. */
#define PDCAP_FN_CHECK_CHARACTER          8U   /* B.9  */
#define PDCAP_FN_COMMUNICATION_SECURITY   9U   /* B.10 */
#define PDCAP_FN_RECEIVE_BUFFER_SIZE     10U   /* B.11 */
#define PDCAP_FN_LARGEST_COMBINED_MSG    11U   /* B.12 */

/* B.10: compliance byte is a bitmap of supported encryption algorithms. */
#define PDCAP_SEC_AES128 0x01U

/* Function codes 10 and 11 both encode a 16-bit size across the two trailing
 * bytes — compliance is the LSB and num_objects the MSB — rather than the
 * "compliance level" and "number of" the field names suggest everywhere else
 * in Annex B. Reading them as their names imply is the mistake this helper
 * exists to catch, so it is worth naming. */
static uint16_t record_size_value(const osdp_pdcap_record_t *r)
{
    return (uint16_t)((uint16_t)r->compliance_level |
                      ((uint16_t)r->num_objects << 8));
}

osdp_status_t osdp_pd_check_pdcap(const osdp_pd_t           *pd,
                                  const osdp_pdcap_record_t *records,
                                  size_t                     count,
                                  size_t                    *bad_index)
{
    if (pd == NULL || (count > 0 && records == NULL)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (bad_index != NULL) {
        *bad_index = 0;
    }

    const bool sc_ready = osdp_pd_internal_sc_configured(pd);

    for (size_t i = 0; i < count; i++) {
        const osdp_pdcap_record_t *r = &records[i];

        switch (r->function_code) {
        case PDCAP_FN_COMMUNICATION_SECURITY:
            /* Claiming AES128 without a crypto vtable and key bound means the
             * PD will NAK 0x05 the moment the ACU tries to open a Secure
             * Channel — having advertised that it could. */
            if ((r->compliance_level & PDCAP_SEC_AES128) != 0 && !sc_ready) {
                if (bad_index != NULL) { *bad_index = i; }
                return OSDP_ERR_NOT_SUPPORTED;
            }
            break;

        case PDCAP_FN_RECEIVE_BUFFER_SIZE: {
            const uint16_t advertised = record_size_value(r);

            /* Ceiling one: the wire. Nothing larger can be reassembled by the
             * stream decoder however the PD is configured. */
            if ((size_t)advertised > OSDP_STREAM_BUFFER_LEN) {
                if (bad_index != NULL) { *bad_index = i; }
                return OSDP_ERR_BUFFER_TOO_SMALL;
            }

            /* Ceiling two: Secure Channel. A message that size arriving as
             * SCS_17 decrypts into rx_plain, so the plaintext it could carry
             * has to fit there — otherwise the PD accepts the frame and then
             * fails to unwrap it, which looks like a MAC failure to nobody's
             * benefit. Only meaningful once SC is configured; a clear-text PD
             * hands the payload straight out of the stream buffer. */
            if (sc_ready) {
                osdp_frame_t shape;
                (void)memset(&shape, 0, sizeof(shape));
                shape.integrity  = OSDP_INTEGRITY_CRC;
                shape.has_scb    = true;
                shape.scb_length = OSDP_SCB_MIN_LEN;
                shape.scb_type   = OSDP_SCS_17;   /* encrypted command */

                size_t plaintext = 0;
                if (osdp_sc_max_payload(&shape, advertised,
                                        &plaintext) == OSDP_OK &&
                    plaintext > pd->rx_plain_cap) {
                    if (bad_index != NULL) { *bad_index = i; }
                    return OSDP_ERR_BUFFER_TOO_SMALL;
                }
            }
            break;
        }

        case PDCAP_FN_LARGEST_COMBINED_MSG: {
            /* Multi-part assembly (spec 5.10) now exists, so a non-zero value
             * is a promise the PD can keep — but only if a reassembly buffer
             * is actually bound, and only up to its capacity. Advertising
             * more than the buffer holds means the transfer is refused at the
             * first fragment, after the ACU has committed to sending it. */
            const uint16_t advertised = record_size_value(r);
            if (advertised == 0) {
                break;   /* "I do not do multi-part" — always honest */
            }
            if (pd->mfg_reasm.buf == NULL) {
                if (bad_index != NULL) { *bad_index = i; }
                return OSDP_ERR_NOT_SUPPORTED;
            }
            if ((size_t)advertised > pd->mfg_reasm.cap) {
                if (bad_index != NULL) { *bad_index = i; }
                return OSDP_ERR_BUFFER_TOO_SMALL;
            }
            break;
        }

        default:
            /* Everything else describes the device, not the library. The
             * application is the only one who can tell whether it is true. */
            break;
        }
    }

    return OSDP_OK;
}

/* Function codes the library computes for itself and never accepts from the
 * application — osdp_pd_set_pdcap rejects any of these, and pd_dispatch.c's
 * osdp_CAP handler splices the live values in on every query. Each is a fact
 * about this LIBRARY (what it links, what is bound right now), never about
 * the physical device, so there is no "application's business" half to
 * preserve the way there is for osdp_pd_check_pdcap's advisory checks:
 *
 *   fn 8  Check Character Support   always 0x01/0x00 — core/src/shared always
 *                                   links both crc16.c and checksum.c, so
 *                                   CRC-16 is unconditionally true for any
 *                                   consumer of this library.
 *   fn 9  Communication Security    compliance always 0x01 (AES128 — this
 *                                   library always supports it once SC is
 *                                   wired up at all, so it is a library
 *                                   fact like fn 8, not a per-instance
 *                                   state check). num_objects reports which
 *                                   key `pd` is actually keyed with right
 *                                   now: 0x00 once a unique operational SCBK
 *                                   has been set (osdp_pd_set_sc_scbk), else
 *                                   0x01 (still on the well-known SCBK-D, or
 *                                   no key at all). NOTE: this deviates from
 *                                   a literal reading of spec B.10, which
 *                                   describes both bytes as AES128-support
 *                                   bitmaps — the spec text is wrong about
 *                                   what num_objects means here, and this is
 *                                   the corrected encoding.
 *   fn 10 Receive BufferSize        min(pd->rx_plain_cap,
 *                                   OSDP_STREAM_BUFFER_LEN) — the same
 *                                   compiled buffer constants that already
 *                                   size the PD's working storage.
 *
 * fn 11 (Largest Combined Message) is NOT in this list — unlike the above,
 * it stays consumer-settable (see k_pdcap_template_secure_reader) and is
 * checked against pd's actual multi-part reassembly binding by
 * osdp_pd_check_pdcap, same as it always was.
 *
 * Kept as one flat list of function codes (rather than duplicating it at
 * every call site) so osdp_pd_set_pdcap's rejection and pd_dispatch.c's
 * injection can never drift apart on which codes are reserved. */
static bool is_reserved_pdcap_fn(uint8_t function_code)
{
    switch (function_code) {
    case PDCAP_FN_CHECK_CHARACTER:
    case PDCAP_FN_COMMUNICATION_SECURITY:
    case PDCAP_FN_RECEIVE_BUFFER_SIZE:
        return true;
    default:
        return false;
    }
}

/* OSDP_PDCAP_TEMPLATE_SECURE_READER: reference values for the records only
 * the application can know the truth of (card format, LEDs, buzzer,
 * downstream readers, OSDP version, multi-part size) — a pure credential
 * reader with no contact inputs, relay outputs, text display, or smart-card
 * support of its own. The reserved function codes (see above) are
 * deliberately absent — see is_reserved_pdcap_fn's doc comment. A device
 * that also has contacts/outputs/a display/smart-card support adds those
 * function codes itself before binding; this template is a floor, not a
 * ceiling.
 *
 * fn 11 defaults to 0xFFFF — the largest size the wire encoding can express
 * — rather than 0: it is a placeholder meaning "however much this PD can
 * multi-part once it has a reassembly buffer", not a claim that is honest on
 * its own. osdp_pd_check_pdcap (called from osdp_pd_set_pdcap) enforces that:
 * it is rejected until osdp_pd_set_mfg_receiver is bound, so shipping this
 * default unmodified fails loudly rather than silently advertising
 * multi-part support the PD cannot back up. Bind the receiver first, or
 * lower this to 0 / the receiver's real capacity. */
static const osdp_pdcap_record_t k_pdcap_template_secure_reader[] = {
    { 3,  1,    0 },     /* B.4  Card Data Format             */
    { 4,  4,    1 },     /* B.5  Reader LED Control           */
    { 5,  2,    1 },     /* B.6  Reader Audible Output        */
    { 11, 0xFF, 0xFF },  /* B.12 Largest Combined Msg: max    */
    { 13, 0,    1 },     /* B.14 Readers (downstream)         */
    { 16, 4,    0 },     /* B.17 OSDP Version: SIA OSDP 2.2.2 */
};

#define OSDP_PDCAP_TEMPLATE_SECURE_READER_COUNT \
    (sizeof(k_pdcap_template_secure_reader) / sizeof(k_pdcap_template_secure_reader[0]))

osdp_status_t osdp_pd_pdcap_template(osdp_pd_pdcap_template_t template,
                                     osdp_pdcap_record_t      *out,
                                     size_t                    cap,
                                     size_t                   *count)
{
    if (out == NULL || count == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    const osdp_pdcap_record_t *records;
    size_t n;

    switch (template) {
    case OSDP_PDCAP_TEMPLATE_SECURE_READER:
        records = k_pdcap_template_secure_reader;
        n = OSDP_PDCAP_TEMPLATE_SECURE_READER_COUNT;
        break;
    default:
        return OSDP_ERR_INVALID_ARG;
    }

    if (cap < n) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    (void)memcpy(out, records, n * sizeof(*records));
    *count = n;
    return OSDP_OK;
}

osdp_status_t osdp_pd_set_pdcap(osdp_pd_t                 *pd,
                                const osdp_pdcap_record_t *records,
                                size_t                     count,
                                size_t                    *bad_index)
{
    if (bad_index != NULL) {
        *bad_index = 0;
    }
    if (pd == NULL || (count > 0 && records == NULL)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (count > OSDP_PD_MAX_PDCAP_RECORDS) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    /* The reserved-function-code rule and spec conformance, one record at a
     * time. Of osdp_pd_check_pdcap's three known function codes (9, 10, 11),
     * only fn 11 can still appear here — 9 and 10 are rejected as reserved
     * below, computed instead by osdp_pd_internal_fill_reserved_pdcap. */
    for (size_t i = 0; i < count; i++) {
        if (is_reserved_pdcap_fn(records[i].function_code)) {
            if (bad_index != NULL) {
                *bad_index = i;
            }
            return OSDP_ERR_INVALID_ARG;
        }
        const osdp_status_t s = osdp_pdcap_validate_record(&records[i]);
        if (s != OSDP_OK) {
            if (bad_index != NULL) {
                *bad_index = i;
            }
            return s;
        }
    }

    /* This PD instance's actual limits — in practice, today, only fn 11's
     * "is a reassembly buffer bound, and is it big enough" case, since 9 and
     * 10 can no longer reach this point. Nothing is applied yet, so a
     * failure here leaves whatever was bound before untouched. */
    const osdp_status_t s = osdp_pd_check_pdcap(pd, records, count, bad_index);
    if (s != OSDP_OK) {
        return s;
    }

    if (count > 0) {
        (void)memcpy(pd->pdcap_records, records, count * sizeof(*records));
    }
    pd->pdcap_count = count;
    return OSDP_OK;
}

/* Fill `out[0..OSDP_PDCAP_RESERVED_COUNT)` with the library-computed
 * records (see is_reserved_pdcap_fn's doc comment) reflecting `pd`'s state
 * right now. Shared with pd_dispatch.c, which splices these into every
 * osdp_CAP reply alongside whatever osdp_pd_set_pdcap has bound. */
void osdp_pd_internal_fill_reserved_pdcap(
    const osdp_pd_t *pd, osdp_pdcap_record_t out[OSDP_PDCAP_RESERVED_COUNT])
{
    out[0].function_code    = PDCAP_FN_CHECK_CHARACTER;
    out[0].compliance_level = 0x01U;
    out[0].num_objects      = 0x00U;

    out[1].function_code    = PDCAP_FN_COMMUNICATION_SECURITY;
    out[1].compliance_level = PDCAP_SEC_AES128;
    out[1].num_objects      = pd->sc.scbk_set ? 0x00U : 0x01U;

    size_t rx_cap = pd->rx_plain_cap;
    if (rx_cap > OSDP_STREAM_BUFFER_LEN) {
        rx_cap = OSDP_STREAM_BUFFER_LEN;
    }
    out[2].function_code    = PDCAP_FN_RECEIVE_BUFFER_SIZE;
    out[2].compliance_level = (uint8_t)(rx_cap & 0xFFU);
    out[2].num_objects      = (uint8_t)((rx_cap >> 8) & 0xFFU);
}

/* Insertion sort: n is at most OSDP_PD_MAX_PDCAP_RECORDS +
 * OSDP_PDCAP_RESERVED_COUNT (17), so O(n^2) costs nothing measurable, and
 * it needs no extra storage. */
void osdp_pd_internal_sort_pdcap(osdp_pdcap_record_t *records, size_t count)
{
    for (size_t i = 1; i < count; i++) {
        const osdp_pdcap_record_t key = records[i];
        size_t j = i;
        while (j > 0 && records[j - 1].function_code > key.function_code) {
            records[j] = records[j - 1];
            j--;
        }
        records[j] = key;
    }
}

osdp_status_t osdp_pd_get_pdcap(const osdp_pd_t     *pd,
                                osdp_pdcap_record_t *out,
                                size_t               cap,
                                size_t              *count)
{
    if (pd == NULL || out == NULL || count == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (pd->pdcap_count == 0) {
        /* Nothing bound: osdp_CAP falls through to cmd_cb, so there is no
         * wire truth to report yet. */
        *count = 0;
        return OSDP_OK;
    }

    const size_t total = OSDP_PDCAP_RESERVED_COUNT + pd->pdcap_count;
    if (cap < total) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    osdp_pd_internal_fill_reserved_pdcap(pd, out);
    (void)memcpy(&out[OSDP_PDCAP_RESERVED_COUNT], pd->pdcap_records,
                pd->pdcap_count * sizeof(*pd->pdcap_records));
    osdp_pd_internal_sort_pdcap(out, total);
    *count = total;
    return OSDP_OK;
}
