// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_pd.h"

#include "osdp/osdp_commands.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"

#include "pd_internal.h"

#include <string.h>

/* ---- Helpers ------------------------------------------------------------*/

/* Build a reply frame in `pd->tx_buf` and return its length. Mirrors
 * the inbound frame's address (with the reply flag set), sequence
 * number, and integrity mode, per spec section 5.9. */
static osdp_status_t build_reply(osdp_pd_t                *pd,
                                 const osdp_frame_t       *cmd,
                                 const osdp_pd_reply_t    *reply,
                                 size_t                   *out_len)
{
    osdp_frame_t out;
    (void)memset(&out, 0, sizeof(out));
    out.address     = pd->address;
    out.reply       = true;
    out.sequence    = cmd->sequence;
    out.integrity   = cmd->integrity;
    /* SCB-bearing replies are deferred to iteration 3 with SC. */
    out.code        = reply->code;
    out.payload     = reply->payload;
    out.payload_len = reply->payload_len;
    return osdp_frame_build(&out, pd->tx_buf, sizeof(pd->tx_buf), out_len);
}

/* Build a NAK reply with the given error code into pd->tx_buf. */
static osdp_status_t build_nak(osdp_pd_t          *pd,
                               const osdp_frame_t *cmd,
                               uint8_t             error_code,
                               size_t             *out_len)
{
    const osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_NAK,
        .payload     = &error_code,
        .payload_len = 1,
    };
    return build_reply(pd, cmd, &reply, out_len);
}

/* Apply an incoming KEYSET payload to the PD's SCBK. Called from
 * both the plaintext (pd.c) and SC (pd_sc.c) dispatch paths after
 * the application handler has ACK'd the command.
 *
 * Spec semantic: the new SCBK takes effect on the *next* handshake.
 * The existing SC session (session keys, SQN, etc.) keeps running —
 * the ACU initiates a fresh handshake when it wants to switch to
 * the rotated key. This matches how real PDs behave: KEYSET is an
 * out-of-band write to persistent storage; SC continues until
 * either side decides to re-handshake. */
osdp_status_t osdp_pd_internal_apply_keyset(osdp_pd_t     *pd,
                                            const uint8_t *payload,
                                            size_t         payload_len)
{
    osdp_keyset_cmd_t parsed;
    const osdp_status_t s = osdp_keyset_decode(payload, payload_len, &parsed);
    if (s != OSDP_OK) {
        return s;  /* malformed envelope → caller NAK's */
    }
    if (parsed.key_type != OSDP_KEYSET_KEY_TYPE_SCBK) {
        /* v2.2 baseline defines only SCBK. A recognized command carrying
         * an unusable record parameter is spec Table 47 error 0x09
         * "Unable to process command record" — NOT 0x03, which the spec
         * reserves for command codes the PD does not implement (and
         * KEYSET *is* implemented). The caller maps this onto NAK 0x09. */
        return OSDP_ERR_BAD_PAYLOAD;
    }
    if (parsed.key_length != OSDP_SC_KEY_LEN || parsed.key_data == NULL) {
        /* Wrong key size is likewise an invalid record → NAK 0x09. */
        return OSDP_ERR_BAD_PAYLOAD;
    }

    /* Overwrite the stored SCBK and mark it set. The crypto vtable,
     * cuid, scbk_d, and the live session keys (s_enc / s_mac1 /
     * s_mac2 / counters in pd->sc.session) are all left alone. */
    (void)memcpy(pd->sc.scbk, parsed.key_data, OSDP_SC_KEY_LEN);
    pd->sc.scbk_set = true;
    return OSDP_OK;
}

/* Highest legal PD address (spec 6.13 Table 22: 0x00..0x7E). 0x7F is the
 * broadcast address and is never a valid COMSET target. */
#define OSDP_PD_MAX_ADDR 0x7EU

osdp_status_t osdp_pd_internal_comset_effective(osdp_pd_t     *pd,
                                                const uint8_t *payload,
                                                size_t         payload_len,
                                                uint8_t       *eff_addr,
                                                uint32_t      *eff_baud,
                                                uint8_t       *com_payload)
{
    osdp_comset_cmd_t req;
    osdp_status_t s = osdp_comset_decode(payload, payload_len, &req);
    if (s != OSDP_OK) {
        return s;  /* malformed → caller NAK's with bad-length */
    }

    /* Seed the effective values with the request, then let the
     * application override them if it cannot comply (spec 6.13). */
    uint8_t  addr = req.address;
    uint32_t baud = req.baud_rate;
    if (pd->comset_cb != NULL) {
        pd->comset_cb(pd->comset_user, req.address, req.baud_rate,
                      &addr, &baud);
    }
    /* An out-of-range effective address means "can't comply" — keep the
     * current address rather than adopting an unaddressable value. */
    if (addr > OSDP_PD_MAX_ADDR) {
        addr = pd->address;
    }

    const osdp_com_t com = { .address = addr, .baud_rate = baud };
    size_t written = 0;
    s = osdp_com_build(&com, com_payload, OSDP_COM_PAYLOAD_BYTES, &written);
    if (s != OSDP_OK) {
        return s;
    }
    *eff_addr = addr;
    *eff_baud = baud;
    return OSDP_OK;
}

void osdp_pd_internal_apply_comset(osdp_pd_t *pd)
{
    pd->comset_pending = false;
    pd->address        = pd->comset_new_address;
    /* The address change invalidates the retransmit / SQN cache: a resend
     * of the COMSET would arrive at the old address and no longer match,
     * and the ACU will reset the sequence when it reconnects at the new
     * parameters. Drop the cache so the reconnect starts clean. */
    pd->have_last = false;
    if (pd->comset_applied_cb != NULL) {
        pd->comset_applied_cb(pd->comset_user,
                              pd->comset_new_address, pd->comset_new_baud);
    }
}

/* Handle a plaintext osdp_COMSET: compute the effective comms parameters,
 * reply osdp_COM at the CURRENT address, and stage the change so it takes
 * effect only after the reply is transmitted (spec 6.13). Returns the
 * reply length in pd->tx_buf, or a NAK on a malformed payload. */
static size_t handle_comset_plain(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    uint8_t  eff_addr = pd->address;
    uint32_t eff_baud = 0;
    uint8_t  com_payload[OSDP_COM_PAYLOAD_BYTES];
    const osdp_status_t s = osdp_pd_internal_comset_effective(
        pd, cmd->payload, cmd->payload_len, &eff_addr, &eff_baud, com_payload);
    if (s != OSDP_OK) {
        size_t n = 0;
        (void)build_nak(pd, cmd, OSDP_NAK_CMD_LENGTH, &n);
        return n;
    }

    const osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_COM,
        .payload     = com_payload,
        .payload_len = OSDP_COM_PAYLOAD_BYTES,
    };
    size_t built = 0;
    if (build_reply(pd, cmd, &reply, &built) != OSDP_OK) {
        return 0;
    }
    pd->comset_pending     = true;
    pd->comset_new_address = eff_addr;
    pd->comset_new_baud    = eff_baud;
    return built;
}

/* Exposed under a stable name (declared in pd_internal.h) so the SC
 * handlers in pd_sc.c can build NAKs without duplicating the helper.
 * Same signature as the static `build_nak` above. */
osdp_status_t osdp_pd_internal_build_nak(osdp_pd_t          *pd,
                                         const osdp_frame_t *cmd,
                                         uint8_t             error_code,
                                         size_t             *out_len)
{
    return build_nak(pd, cmd, error_code, out_len);
}

/* Send `len` bytes from `buf` via the bound transport. Short writes
 * are dropped on the floor for now; future iterations may queue or
 * report a transmission error.
 *
 * On a successful (non-empty) send, the PD is considered to have just
 * communicated: refresh last_comm_ms and set online = true so spec
 * 5.7's 8-second silence window starts over. */
static void send_bytes(osdp_pd_t *pd, const uint8_t *buf, size_t len)
{
    if (pd->transport.write == NULL || len == 0) {
        return;
    }
    const int written = pd->transport.write(pd->transport.user, buf, len);
    (void)written;

    if (pd->transport.now_ms != NULL) {
        pd->last_comm_ms = pd->transport.now_ms(pd->transport.user);
    }
    pd->online = true;
}

/* If the PD has been online but no reply has been sent for longer than
 * OSDP_PD_OFFLINE_TIMEOUT_MS, transition to offline and clear the
 * sequence-number cache so the next reconnect starts cleanly. No-op
 * when the transport does not provide a now_ms callback. */
static void check_offline_timeout(osdp_pd_t *pd)
{
    if (!pd->online || pd->transport.now_ms == NULL) {
        return;
    }
    const uint32_t now = pd->transport.now_ms(pd->transport.user);
    /* Unsigned subtraction wraps cleanly modulo 2^32, so a 49.7-day
     * monotonic wraparound doesn't spuriously trigger an offline. */
    const uint32_t elapsed = now - pd->last_comm_ms;
    if (elapsed > OSDP_PD_OFFLINE_TIMEOUT_MS) {
        pd->online    = false;
        pd->have_last = false;  /* drop SQN cache; ACU will reset SQN */
    }
}

/* Compute the reply for a fresh command into pd->tx_buf and return
 * the byte count (or 0 if the command should produce no reply at all
 * — e.g. an internal handler error). */
static size_t handle_command_into_tx(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    /* OSDP.Net parity (commit 02e478476): a CLEAR-TEXT command at
     * sequence 0 means the ACU is (re)starting the connection, so any
     * established Secure Channel session is stale and must be dropped.
     * The ACU then re-discovers the PD (osdp_CAP / osdp_ID answered in
     * the clear) and drives a fresh handshake — e.g. after osdp_KEYSET —
     * rather than the PD tearing down the session off the back of the
     * KEYSET itself. A *secure* (SCB-bearing) frame at sequence 0 is part
     * of an in-progress handshake and must NOT reset anything. */
    if (!cmd->has_scb && cmd->sequence == 0 && pd->sc.session.established) {
        osdp_sc_session_init(&pd->sc.session);
        pd->sc.got_chlng = false;
    }

    /* Secure Channel: dispatch to the SC handler if the application
     * has supplied enough configuration; otherwise fall back to the
     * historical "NAK 0x05" behaviour. */
    if (cmd->has_scb) {
        if (osdp_pd_internal_sc_configured(pd)) {
            return osdp_pd_internal_handle_sc_into_tx(pd, cmd);
        }
        size_t n = 0;
        if (build_nak(pd, cmd, OSDP_NAK_UNSUPPORTED_SCB, &n) != OSDP_OK) {
            return 0;
        }
        return n;
    }

    /* osdp_COMSET is answered by the library, not the application handler:
     * the reply is osdp_COM (not an app-chosen ACK) and the command mutates
     * pd->address, which only the state machine owns. The optional COMSET
     * hooks let the application veto/clamp the values and enact the baud
     * change once the reply has gone out. */
    if (cmd->code == OSDP_CMD_COMSET) {
        return handle_comset_plain(pd, cmd);
    }

    osdp_pd_reply_t reply = {
        .code        = OSDP_REPLY_ACK,
        .payload     = NULL,
        .payload_len = 0,
    };

    osdp_status_t app_status = OSDP_ERR_NOT_SUPPORTED;
    if (pd->cmd_cb != NULL) {
        app_status = pd->cmd_cb(pd->cmd_user,
                                cmd->code,
                                cmd->payload, cmd->payload_len,
                                &reply);
    }

    /* Mirror reader-visible commands (osdp_LED) into the LED bank so the
     * application's change callback / colour query stay current, whatever
     * the handler chose to reply. */
    osdp_pd_internal_observe_command(pd, cmd->code,
                                     cmd->payload, cmd->payload_len);

    size_t built = 0;
    osdp_status_t br;
    if (app_status == OSDP_OK) {
        /* KEYSET hook: if the app ACK'd a KEYSET, apply the new SCBK
         * before transmitting the ACK. A malformed payload demotes the
         * ACK to NAK so the ACU sees the failure. The application
         * doesn't have to know about KEYSET — its existing "ACK
         * everything I recognise" default works. */
        if (cmd->code == OSDP_CMD_KEYSET) {
            const osdp_status_t ks = osdp_pd_internal_apply_keyset(
                pd, cmd->payload, cmd->payload_len);
            if (ks != OSDP_OK) {
                /* Any malformed-but-recognized KEYSET is spec Table 47
                 * error 0x09 "Unable to process command record". */
                br = build_nak(pd, cmd, OSDP_NAK_RECORD_INVALID, &built);
                return (br == OSDP_OK) ? built : 0;
            }
        }
        br = build_reply(pd, cmd, &reply, &built);
    } else if (app_status == OSDP_ERR_NOT_SUPPORTED) {
        br = build_nak(pd, cmd, OSDP_NAK_UNKNOWN_CMD, &built);
    } else {
        /* Internal handler error — drop silently. */
        return 0;
    }

    return (br == OSDP_OK) ? built : 0;
}

/* Cache the command we just accepted alongside the reply we just
 * built, so a future byte-identical retransmit can replay the reply
 * without re-executing the command (spec 5.9). Frames whose raw
 * bytes don't fit in our cache (oversized commands) are simply not
 * cached — they'll always be processed fresh, which is conservative
 * and correct. */
static void cache_reply(osdp_pd_t          *pd,
                        const osdp_frame_t *cmd,
                        size_t              reply_len)
{
    if (reply_len > sizeof(pd->last_reply)) {
        /* Should be impossible — tx_buf and last_reply are the same
         * size — but guard anyway. */
        reply_len = sizeof(pd->last_reply);
    }
    if (reply_len > 0) {
        (void)memcpy(pd->last_reply, pd->tx_buf, reply_len);
    }
    pd->last_reply_len = reply_len;

    /* Cache the inbound command's wire bytes for retransmit detection.
     * If raw isn't available or is too large, skip caching the cmd —
     * the next frame will then bypass the cache and process fresh. */
    if (cmd->raw != NULL && cmd->raw_len > 0 &&
        cmd->raw_len <= sizeof(pd->last_cmd)) {
        (void)memcpy(pd->last_cmd, cmd->raw, cmd->raw_len);
        pd->last_cmd_len = cmd->raw_len;
    } else {
        pd->last_cmd_len = 0;
    }

    pd->last_seq  = cmd->sequence;
    pd->have_last = true;
}

/* True iff `cmd` is byte-identical to the previously accepted command,
 * which per spec 5.9 is the unambiguous marker of a retransmit. SQN
 * zero is the session-reset sentinel and never counts as a retransmit
 * regardless of cache contents. */
static bool is_retransmit(const osdp_pd_t    *pd,
                          const osdp_frame_t *cmd)
{
    if (cmd->sequence == 0 || !pd->have_last) {
        return false;
    }
    if (pd->last_cmd_len == 0 || cmd->raw == NULL) {
        return false;
    }
    if (cmd->raw_len != pd->last_cmd_len) {
        return false;
    }
    return memcmp(pd->last_cmd, cmd->raw, cmd->raw_len) == 0;
}

/* Process one accepted command frame: dispatch, build reply, cache,
 * transmit. Honours the byte-identical retransmit rule from spec 5.9. */
static void process_frame(osdp_pd_t *pd, const osdp_frame_t *cmd)
{
    if (is_retransmit(pd, cmd)) {
        if (pd->last_reply_len > 0) {
            send_bytes(pd, pd->last_reply, pd->last_reply_len);
        }
        return;
    }

    const size_t built = handle_command_into_tx(pd, cmd);
    cache_reply(pd, cmd, built);
    if (built > 0) {
        send_bytes(pd, pd->tx_buf, built);
    }

    /* osdp_COMSET: the new comms parameters take effect only AFTER the
     * osdp_COM reply has been transmitted at the old parameters (spec
     * 6.13). Apply the staged change now — this also drops the SQN cache
     * populated by cache_reply() above. */
    if (pd->comset_pending) {
        osdp_pd_internal_apply_comset(pd);
    }
}

/* ---- API ----------------------------------------------------------------*/

void osdp_pd_init(osdp_pd_t *pd, uint8_t address)
{
    if (pd == NULL) {
        return;
    }
    (void)memset(pd, 0, sizeof(*pd));
    pd->address = (uint8_t)(address & 0x7FU);
    osdp_stream_init(&pd->rx);
}

void osdp_pd_set_transport(osdp_pd_t *pd,
                           const osdp_pd_transport_t *transport)
{
    if (pd == NULL || transport == NULL) {
        return;
    }
    pd->transport = *transport;
}

void osdp_pd_set_command_handler(osdp_pd_t *pd,
                                 osdp_pd_command_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->cmd_cb   = cb;
    pd->cmd_user = user;
}

bool osdp_pd_is_online(const osdp_pd_t *pd)
{
    if (pd == NULL) {
        return false;
    }
    return pd->online;
}

/* ---- Reader LED bank -----------------------------------------------------*/

/* Monotonic clock helper. Falls back to time 0 when the transport doesn't
 * supply now_ms — in which case temporary-timer expiry and flashing simply
 * don't advance, but command-driven colour changes still resolve. */
static uint32_t pd_now_ms(const osdp_pd_t *pd)
{
    if (pd->transport.now_ms != NULL) {
        return pd->transport.now_ms(pd->transport.user);
    }
    return 0U;
}

/* Find the bank slot tracking (reader_no, led_no), claiming a free one on
 * first sighting. Returns NULL only when every slot is already in use by
 * other LEDs (oversized deployment — the extra LED is ACK'd but untracked). */
static osdp_pd_led_slot_t *pd_led_slot(osdp_pd_t *pd,
                                       uint8_t reader_no, uint8_t led_no)
{
    osdp_pd_led_slot_t *free_slot = NULL;
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        osdp_pd_led_slot_t *s = &pd->leds[i];
        if (s->used && s->reader_no == reader_no && s->led_no == led_no) {
            return s;
        }
        if (!s->used && free_slot == NULL) {
            free_slot = s;
        }
    }
    if (free_slot != NULL) {
        free_slot->used       = true;
        free_slot->reader_no  = reader_no;
        free_slot->led_no     = led_no;
        free_slot->last_color = OSDP_LED_BLACK;
        osdp_led_init(&free_slot->state);
    }
    return free_slot;
}

/* Recompute every tracked LED's displayed colour at `now` and fire the
 * change callback for any that flipped since the last report. Cheap and
 * idempotent; safe to call after every command and on every tick. */
static void pd_led_refresh(osdp_pd_t *pd, uint32_t now)
{
    if (pd->led_cb == NULL) {
        return;
    }
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        osdp_pd_led_slot_t *s = &pd->leds[i];
        if (!s->used) {
            continue;
        }
        const uint8_t color = osdp_led_color(&s->state, now);
        if (color != s->last_color) {
            s->last_color = color;
            pd->led_cb(pd->led_user, s->reader_no, s->led_no, color);
        }
    }
}

/* ---- Reader buzzer bank --------------------------------------------------*/

/* Find the buzzer slot for `reader_no`, claiming a free one on first
 * sighting. Returns NULL only when every slot is in use by other readers. */
static osdp_pd_buz_slot_t *pd_buz_slot(osdp_pd_t *pd, uint8_t reader_no)
{
    osdp_pd_buz_slot_t *free_slot = NULL;
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (s->used && s->reader_no == reader_no) {
            return s;
        }
        if (!s->used && free_slot == NULL) {
            free_slot = s;
        }
    }
    if (free_slot != NULL) {
        free_slot->used          = true;
        free_slot->reader_no     = reader_no;
        free_slot->last_sounding = false;
        osdp_buz_init(&free_slot->state);
    }
    return free_slot;
}

/* Recompute every tracked buzzer's sounding state at `now` and fire the
 * change callback for any that flipped since the last report — the beep /
 * silence edges of the pattern, including the final silence. */
static void pd_buz_refresh(osdp_pd_t *pd, uint32_t now)
{
    if (pd->buzzer_cb == NULL) {
        return;
    }
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (!s->used) {
            continue;
        }
        const bool sounding = osdp_buz_sounding(&s->state, now);
        if (sounding != s->last_sounding) {
            s->last_sounding = sounding;
            pd->buzzer_cb(pd->buzzer_user, s->reader_no, sounding,
                          s->state.tone);
        }
    }
}

/* Transparently fold an inbound command into the reader-LED / -buzzer banks.
 * A no-op for everything except osdp_LED and osdp_BUZ; for those it decodes
 * the command, applies it to the matching slot, then re-resolves state so
 * any change fires the callback. Declared in pd_internal.h so both the
 * plaintext (pd.c) and Secure Channel (pd_sc.c) dispatch paths can call it
 * with plaintext bytes. */
void osdp_pd_internal_observe_command(osdp_pd_t     *pd,
                                      uint8_t        cmd_code,
                                      const uint8_t *payload,
                                      size_t         payload_len)
{
    if (pd == NULL) {
        return;
    }

    if (cmd_code == OSDP_CMD_LED) {
        osdp_led_record_t recs[OSDP_PD_MAX_LEDS];
        size_t n = 0;
        if (osdp_led_decode(payload, payload_len, recs,
                            OSDP_PD_MAX_LEDS, &n) != OSDP_OK) {
            return;  /* malformed LED payload — leave the bank untouched */
        }
        const uint32_t now = pd_now_ms(pd);
        for (size_t i = 0; i < n; i++) {
            osdp_pd_led_slot_t *s =
                pd_led_slot(pd, recs[i].reader_no, recs[i].led_no);
            if (s != NULL) {
                osdp_led_apply(&s->state, &recs[i], now);
            }
        }
        pd_led_refresh(pd, now);
        return;
    }

    if (cmd_code == OSDP_CMD_BUZ) {
        osdp_buz_cmd_t buz;
        if (osdp_buz_decode(payload, payload_len, &buz) != OSDP_OK) {
            return;  /* malformed BUZ payload — ignore */
        }
        const uint32_t now = pd_now_ms(pd);
        osdp_pd_buz_slot_t *s = pd_buz_slot(pd, buz.reader_no);
        if (s != NULL) {
            osdp_buz_apply(&s->state, &buz, now);
        }
        pd_buz_refresh(pd, now);
        return;
    }
}

void osdp_pd_set_led_handler(osdp_pd_t *pd, osdp_pd_led_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->led_cb   = cb;
    pd->led_user = user;
}

void osdp_pd_set_buzzer_handler(osdp_pd_t *pd, osdp_pd_buzzer_cb cb, void *user)
{
    if (pd == NULL) {
        return;
    }
    pd->buzzer_cb   = cb;
    pd->buzzer_user = user;
}

void osdp_pd_set_comset_handler(osdp_pd_t                *pd,
                                osdp_pd_comset_cb         decide,
                                osdp_pd_comset_applied_cb applied,
                                void                     *user)
{
    if (pd == NULL) {
        return;
    }
    pd->comset_cb         = decide;
    pd->comset_applied_cb = applied;
    pd->comset_user       = user;
}

bool osdp_pd_buzzer_sounding(const osdp_pd_t *pd, uint8_t reader_no)
{
    if (pd == NULL) {
        return false;
    }
    const uint32_t now = pd_now_ms(pd);
    for (size_t i = 0; i < OSDP_PD_MAX_BUZZERS; i++) {
        const osdp_pd_buz_slot_t *s = &pd->buzzers[i];
        if (s->used && s->reader_no == reader_no) {
            return osdp_buz_sounding(&s->state, now);
        }
    }
    return false;
}

uint8_t osdp_pd_led_color(const osdp_pd_t *pd,
                          uint8_t reader_no, uint8_t led_no)
{
    if (pd == NULL) {
        return OSDP_LED_BLACK;
    }
    const uint32_t now = pd_now_ms(pd);
    for (size_t i = 0; i < OSDP_PD_MAX_LEDS; i++) {
        const osdp_pd_led_slot_t *s = &pd->leds[i];
        if (s->used && s->reader_no == reader_no && s->led_no == led_no) {
            return osdp_led_color(&s->state, now);
        }
    }
    return OSDP_LED_BLACK;
}

/* ---- Secure Channel configuration ---------------------------------------*/

void osdp_pd_set_sc_crypto(osdp_pd_t              *pd,
                           const osdp_sc_crypto_t *crypto)
{
    if (pd == NULL || crypto == NULL) {
        return;
    }
    pd->sc.crypto     = *crypto;
    pd->sc.crypto_set = true;
    osdp_sc_session_init(&pd->sc.session);
    pd->sc.got_chlng  = false;
}

void osdp_pd_set_sc_scbk(osdp_pd_t       *pd,
                         const uint8_t    scbk[OSDP_SC_KEY_LEN])
{
    if (pd == NULL || scbk == NULL) {
        return;
    }
    (void)memcpy(pd->sc.scbk, scbk, OSDP_SC_KEY_LEN);
    pd->sc.scbk_set = true;
}

void osdp_pd_set_sc_scbk_d(osdp_pd_t     *pd,
                           const uint8_t  scbk_d[OSDP_SC_KEY_LEN])
{
    if (pd == NULL || scbk_d == NULL) {
        return;
    }
    (void)memcpy(pd->sc.scbk_d, scbk_d, OSDP_SC_KEY_LEN);
    pd->sc.scbk_d_set = true;
}

void osdp_pd_set_sc_cuid(osdp_pd_t     *pd,
                         const uint8_t  cuid[OSDP_SC_CUID_LEN])
{
    if (pd == NULL || cuid == NULL) {
        return;
    }
    (void)memcpy(pd->sc.cuid, cuid, OSDP_SC_CUID_LEN);
    pd->sc.cuid_set = true;
}

bool osdp_pd_sc_established(const osdp_pd_t *pd)
{
    if (pd == NULL) {
        return false;
    }
    return pd->sc.session.established;
}

void osdp_pd_tick(osdp_pd_t *pd)
{
    if (pd == NULL || pd->transport.read == NULL) {
        return;
    }

    /* Check the offline timeout BEFORE consuming new bytes — keeps
     * is_online() honest even when the caller is ticking only to
     * check timing without expecting incoming traffic. */
    check_offline_timeout(pd);

    /* Drain whatever the transport has now. */
    uint8_t chunk[128];
    for (;;) {
        const int n = pd->transport.read(pd->transport.user,
                                         chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        (void)osdp_stream_feed(&pd->rx, chunk, (size_t)n);
        if ((size_t)n < sizeof(chunk)) {
            break;
        }
    }

    /* Process every fully-received frame. */
    for (;;) {
        osdp_frame_t cmd;
        const osdp_status_t r = osdp_stream_next(&pd->rx, &cmd);
        if (r == OSDP_ERR_TRUNCATED) {
            break;
        }
        if (r != OSDP_OK) {
            continue;  /* stream auto-advanced past the bad frame */
        }
        if (cmd.reply) {
            continue;  /* wrong direction for a PD */
        }
        const bool ours      = (cmd.address == pd->address);
        const bool broadcast = (cmd.address == OSDP_BROADCAST_ADDR);
        if (!ours && !broadcast) {
            continue;
        }

        process_frame(pd, &cmd);
    }

    /* Re-resolve the LED and buzzer banks so time-driven changes (LED
     * timer expiry / flash edges, buzzer beep/silence edges and end-of-
     * pattern) reach the change callbacks even on ticks that processed no
     * command. No-op without a now_ms clock. */
    const uint32_t now = pd_now_ms(pd);
    pd_led_refresh(pd, now);
    pd_buz_refresh(pd, now);
}
