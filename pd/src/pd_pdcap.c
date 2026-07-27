// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Advisory consistency check for an application's osdp_PDCAP records.
 *
 * PDCAP is a set of promises. The ACU acts on them: spec §6 has it bound
 * osdp_LED record counts by function code 10, and an ACU told the PD accepts
 * 1440-byte messages will send them. A PD that advertises more than it can
 * honour does not fail loudly — it drops frames the ACU believes were
 * delivered, which surfaces later as unexplained retries.
 *
 * The library cannot build PDCAP for the application: most of it (how many
 * inputs, which card formats, what the reader hardware is) is knowledge only
 * the application has. What the library CAN do is check the handful of
 * records whose truth it knows, because they describe the library's own
 * limits rather than the device's.
 *
 * Purely advisory and purely local: this touches no wire state, and nothing
 * calls it automatically. It lives in its own translation unit so an
 * application that never calls it does not link it. */

#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include "pd_internal.h"

#include <string.h>

/* PDCAP function codes this check understands (spec Annex B). */
#define PDCAP_FN_COMMUNICATION_SECURITY 9U   /* B.10 */
#define PDCAP_FN_RECEIVE_BUFFER_SIZE   10U   /* B.11 */
#define PDCAP_FN_LARGEST_COMBINED_MSG  11U   /* B.12 */

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

    const bool sc_ready = osdp_pd_internal_sc_configured(pd) ||
                          osdp_pd_internal_sc2_configured(pd);

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

        case PDCAP_FN_LARGEST_COMBINED_MSG:
            /* Multi-part message assembly (spec 5.10) is not implemented, so
             * any non-zero value here is a promise the PD cannot keep. Drop
             * this branch when multi-part lands and check the bound
             * reassembly buffer instead. */
            if (record_size_value(r) != 0) {
                if (bad_index != NULL) { *bad_index = i; }
                return OSDP_ERR_NOT_SUPPORTED;
            }
            break;

        default:
            /* Everything else describes the device, not the library. The
             * application is the only one who can tell whether it is true. */
            break;
        }
    }

    return OSDP_OK;
}
