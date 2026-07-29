// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_replies.h"

#include <stddef.h>

osdp_status_t osdp_pdcap_decode(const uint8_t *payload, size_t len,
                                osdp_pdcap_record_t *records,
                                size_t records_cap,
                                size_t *records_written)
{
    if (records_written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *records_written = 0;

    /* Spec 7.5: variable number of 3-byte capability records.
     * The list may be empty in principle (no caps reported) — that's
     * a valid encoding even if unusual on the wire. */
    if ((len % OSDP_PDCAP_RECORD_BYTES) != 0) {
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (len > 0 && payload == NULL) {
        return OSDP_ERR_BAD_PAYLOAD;
    }

    const size_t count = len / OSDP_PDCAP_RECORD_BYTES;
    if (count > 0 && (records == NULL || records_cap < count)) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *r = &payload[i * OSDP_PDCAP_RECORD_BYTES];
        records[i].function_code    = r[0];
        records[i].compliance_level = r[1];
        records[i].num_objects      = r[2];
    }
    *records_written = count;
    return OSDP_OK;
}

osdp_status_t osdp_pdcap_build(const osdp_pdcap_record_t *records,
                               size_t record_count,
                               uint8_t *buf, size_t buf_cap,
                               size_t *written)
{
    if (buf == NULL || written == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    *written = 0;
    if (record_count > 0 && records == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    const size_t total = record_count * OSDP_PDCAP_RECORD_BYTES;
    if (total > buf_cap) {
        return OSDP_ERR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < record_count; i++) {
        uint8_t *r = &buf[i * OSDP_PDCAP_RECORD_BYTES];
        r[0] = records[i].function_code;
        r[1] = records[i].compliance_level;
        r[2] = records[i].num_objects;
    }
    *written = total;
    return OSDP_OK;
}

/* ========================================================================
 * osdp_pdcap_validate_record — Annex B catalog
 *
 * Every function code's compliance-level and num-objects byte reduces to
 * one of four shapes once read against the spec text:
 *
 *   RANGE(max)              a contiguous enumeration 0..=max (every
 *                            "Enum" list in Annex B happens to start at
 *                            0, including the single-value ones that are
 *                            really "must be 0x00").
 *   RANGE_OR_PRIVATE(max,p) like RANGE, but values >= p are additionally
 *                            accepted as manufacturer private use (the
 *                            spec's OSDP Version field, B.17).
 *   BITMAP(mask)             only bits set in `mask` may be set.
 *   ANY                      any 0x00..0xFF value is legal (a free-form
 *                            count, or one byte of a 16-bit size split
 *                            across both fields).
 *
 * That collapse keeps the catalog a flat const table rather than the
 * tagged-union-of-string-tables a fully descriptive version would need —
 * this function only has to answer "conformant or not", not explain why.
 * ====================================================================== */

typedef enum {
    OSDP_PDCAP_FIELD_ANY = 0,
    OSDP_PDCAP_FIELD_RANGE,
    OSDP_PDCAP_FIELD_RANGE_OR_PRIVATE,
    OSDP_PDCAP_FIELD_BITMAP
} osdp_pdcap_field_kind_t;

typedef struct {
    osdp_pdcap_field_kind_t kind;
    uint8_t                 a;   /* RANGE/RANGE_OR_PRIVATE: max. BITMAP: mask. */
    uint8_t                 b;   /* RANGE_OR_PRIVATE only: private-use threshold. */
} osdp_pdcap_field_rule_t;

typedef struct {
    uint8_t                 function_code;
    osdp_pdcap_field_rule_t compliance;
    osdp_pdcap_field_rule_t num_objects;
} osdp_pdcap_catalog_entry_t;

#define OSDP_PDCAP_ANY               { OSDP_PDCAP_FIELD_ANY, 0, 0 }
#define OSDP_PDCAP_RANGE(max)        { OSDP_PDCAP_FIELD_RANGE, (max), 0 }
#define OSDP_PDCAP_ZERO              OSDP_PDCAP_RANGE(0)
#define OSDP_PDCAP_RANGE_PRIV(max, priv_from) \
    { OSDP_PDCAP_FIELD_RANGE_OR_PRIVATE, (max), (priv_from) }
#define OSDP_PDCAP_BITMAP(mask)      { OSDP_PDCAP_FIELD_BITMAP, (mask), 0 }

/* One entry per function code Annex B defines (1..17). Function code 18
 * ("Extended Capability Display") is left out on purpose — see the
 * osdp_pdcap_validate_record() doc comment in osdp_replies.h. */
static const osdp_pdcap_catalog_entry_t k_pdcap_catalog[] = {
    /* B.2  Contact Status Monitoring: 0..4, num_objects = input count. */
    { 1,  OSDP_PDCAP_RANGE(4), OSDP_PDCAP_ANY },
    /* B.3  Output Control: 0..4, num_objects = output count. */
    { 2,  OSDP_PDCAP_RANGE(4), OSDP_PDCAP_ANY },
    /* B.4  Card Data Format: 0..3, num_objects must be 0x00. */
    { 3,  OSDP_PDCAP_RANGE(3), OSDP_PDCAP_ZERO },
    /* B.5  Reader LED Control: 0..6, num_objects = LEDs per reader. */
    { 4,  OSDP_PDCAP_RANGE(6), OSDP_PDCAP_ANY },
    /* B.6  Reader Audible Output: 0..2, num_objects ignored (one per PD). */
    { 5,  OSDP_PDCAP_RANGE(2), OSDP_PDCAP_ANY },
    /* B.7  Reader Text Output: 0..3, num_objects = displays per reader. */
    { 6,  OSDP_PDCAP_RANGE(3), OSDP_PDCAP_ANY },
    /* B.8  Time Keeping (deprecated): only 0 defined, num_objects 0x00. */
    { 7,  OSDP_PDCAP_ZERO,     OSDP_PDCAP_ZERO },
    /* B.9  Check Character Support: 0..1, num_objects must be 0x00. */
    { 8,  OSDP_PDCAP_RANGE(1), OSDP_PDCAP_ZERO },
    /* B.10 Communication Security: both bytes bit0 = AES128 (support /
     * key-exchange). */
    { 9,  OSDP_PDCAP_BITMAP(0x01), OSDP_PDCAP_BITMAP(0x01) },
    /* B.11 Receive Buffer Size: 16-bit size, LSB then MSB. */
    { 10, OSDP_PDCAP_ANY, OSDP_PDCAP_ANY },
    /* B.12 Largest Combined Message Size: 16-bit size, LSB then MSB. */
    { 11, OSDP_PDCAP_ANY, OSDP_PDCAP_ANY },
    /* B.13 Smart Card Support: bit0 transparent mode, bit1 extended
     * packet; num_objects must be 0x00. */
    { 12, OSDP_PDCAP_BITMAP(0x03), OSDP_PDCAP_ZERO },
    /* B.14 Readers: compliance must be 0x00, num_objects = downstream
     * reader count. */
    { 13, OSDP_PDCAP_ZERO, OSDP_PDCAP_ANY },
    /* B.15 Biometrics: 0..3, num_objects must be 0x00. */
    { 14, OSDP_PDCAP_RANGE(3), OSDP_PDCAP_ZERO },
    /* B.16 Secure PIN Entry: 0..1, num_objects must be 0x00. */
    { 15, OSDP_PDCAP_RANGE(1), OSDP_PDCAP_ZERO },
    /* B.17 OSDP Version: 0..4 named, 0x80..0xFF private use, num_objects
     * must be 0x00. */
    { 16, OSDP_PDCAP_RANGE_PRIV(4, 0x80), OSDP_PDCAP_ZERO },
    /* B.18 Secure PD Biometrics Match Support: body missing from the
     * extracted spec text, so both bytes are accepted permissively
     * rather than guessed at. */
    { 17, OSDP_PDCAP_ANY, OSDP_PDCAP_ANY },
};

#define OSDP_PDCAP_CATALOG_LEN \
    (sizeof(k_pdcap_catalog) / sizeof(k_pdcap_catalog[0]))

static bool pdcap_field_ok(const osdp_pdcap_field_rule_t *rule, uint8_t val)
{
    switch (rule->kind) {
    case OSDP_PDCAP_FIELD_ANY:
        return true;
    case OSDP_PDCAP_FIELD_RANGE:
        return val <= rule->a;
    case OSDP_PDCAP_FIELD_RANGE_OR_PRIVATE:
        return val <= rule->a || val >= rule->b;
    case OSDP_PDCAP_FIELD_BITMAP:
        return (val & (uint8_t)~rule->a) == 0;
    default:
        return false;
    }
}

osdp_status_t osdp_pdcap_validate_record(const osdp_pdcap_record_t *record)
{
    if (record == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }

    const osdp_pdcap_catalog_entry_t *entry = NULL;
    for (size_t i = 0; i < OSDP_PDCAP_CATALOG_LEN; i++) {
        if (k_pdcap_catalog[i].function_code == record->function_code) {
            entry = &k_pdcap_catalog[i];
            break;
        }
    }
    if (entry == NULL) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!pdcap_field_ok(&entry->compliance, record->compliance_level)) {
        return OSDP_ERR_INVALID_ARG;
    }
    if (!pdcap_field_ok(&entry->num_objects, record->num_objects)) {
        return OSDP_ERR_INVALID_ARG;
    }
    return OSDP_OK;
}
