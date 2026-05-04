// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp-acu-mock — interactive ACU on a serial port.
 *
 * Sibling of osdp-pd-mock, but pointing the other way: this binary
 * runs an `osdp::acu` instance on a real (or virtual) serial port and
 * drives an external PD. Pair it with OSDP.Net's PDConsole, a hardware
 * PD, or another OSDP-Embedded osdp-pd-mock instance over a com0com
 * pair to validate end-to-end interop.
 *
 * Behavior:
 *
 *   1. Opens the serial port and initialises a single-PD ACU slot.
 *   2. If --sc=scbkd or --sc=scbk:HEX32 is set, binds the SC crypto
 *      vtable + key and kicks off the handshake. Subsequent commands
 *      wait until OSDP_ACU_SC_EVENT_ESTABLISHED fires.
 *   3. Once any handshake has resolved (or immediately if SC is off),
 *      sends ID once, CAP once, then POLL on a fixed interval.
 *   4. Decoded replies print to stderr; timeouts and SC events too.
 *   5. On SESSION_LOST during operation we automatically re-issue the
 *      handshake — convenient for the "kill the PD, restart it" loop
 *      developers do during debugging.
 *
 * Layer 1 framing, sequence policing, MAC chain advancement, and
 * session lifecycle are all driven by the real osdp::acu state machine
 * via osdp_acu_tick(). This tool is just glue: argv parsing, serial
 * I/O, and a small "what to send next" scheduler.
 *
 * Like osdp-pd-mock, this is a host tool — libc, argv, stderr — but
 * the osdp::acu / osdp::core / osdp::messages it links against remain
 * freestanding. */

#include "aes_adapter.h"
#include "osdp/osdp_acu.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "serial.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Volatile flag set by Ctrl-C / SIGINT --------------------------- */

static volatile sig_atomic_t g_should_exit = 0;
static void on_signal(int sig) { (void)sig; g_should_exit = 1; }

/* ---- Defaults ------------------------------------------------------- */

#define DEFAULT_BAUD          9600U
#define DEFAULT_PD_ADDRESS    0x00U
#define DEFAULT_POLL_INTERVAL 500U   /* ms between commands              */
#define MAIN_LOOP_TICK_MS     2U     /* ~2× a 9600-baud byte             */

/* ---- Pretty-printers ------------------------------------------------ */

static const char *cmd_name(uint8_t code)
{
    switch (code) {
    case OSDP_CMD_POLL:   return "POLL";
    case OSDP_CMD_ID:     return "ID";
    case OSDP_CMD_CAP:    return "CAP";
    case OSDP_CMD_LED:    return "LED";
    case OSDP_CMD_BUZ:    return "BUZ";
    case OSDP_CMD_TEXT:   return "TEXT";
    case OSDP_CMD_OUT:    return "OUT";
    case OSDP_CMD_COMSET: return "COMSET";
    case OSDP_CMD_KEYSET: return "KEYSET";
    case OSDP_CMD_CHLNG:  return "CHLNG";
    case OSDP_CMD_SCRYPT: return "SCRYPT";
    default:              return "?";
    }
}

static const char *reply_name(uint8_t code)
{
    switch (code) {
    case OSDP_REPLY_ACK:    return "ACK";
    case OSDP_REPLY_NAK:    return "NAK";
    case OSDP_REPLY_PDID:   return "PDID";
    case OSDP_REPLY_PDCAP:  return "PDCAP";
    case OSDP_REPLY_LSTATR: return "LSTATR";
    case OSDP_REPLY_ISTATR: return "ISTATR";
    case OSDP_REPLY_OSTATR: return "OSTATR";
    case OSDP_REPLY_RSTATR: return "RSTATR";
    case OSDP_REPLY_RAW:    return "RAW";
    case OSDP_REPLY_KEYPAD: return "KEYPAD";
    case OSDP_REPLY_COM:    return "COM";
    case OSDP_REPLY_BUSY:   return "BUSY";
    case OSDP_REPLY_CCRYPT: return "CCRYPT";
    case OSDP_REPLY_RMAC_I: return "RMAC_I";
    default:                return "?";
    }
}

static void hex_dump(FILE *f, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "%s%02X", i ? " " : "", buf[i]);
    }
}

/* ---- Application state --------------------------------------------- */

/* Send-cycle state machine. The tool walks once through ID → CAP, then
 * settles into perpetual POLL on the configured interval. SC handshake
 * (if any) blocks the cycle until ESTABLISHED. */
typedef enum send_phase {
    SEND_PHASE_INIT,        /* before first command */
    SEND_PHASE_PENDING_SC,  /* SC enabled; waiting on ESTABLISHED */
    SEND_PHASE_ID,          /* next: ID */
    SEND_PHASE_CAP,         /* next: CAP */
    SEND_PHASE_POLL,        /* steady-state: POLL forever */
} send_phase_t;

typedef struct app {
    osdp_acu_t          *acu;
    uint8_t              pd_address;
    int                  verbose;
    send_phase_t         phase;
    uint32_t             last_send_ms;
    unsigned int         poll_interval_ms;
    bool                 sc_enabled;
    bool                 sc_use_default_key;
} app_t;

/* ---- Callbacks ----------------------------------------------------- */

static void on_reply(void *user, const osdp_acu_reply_event_t *e)
{
    app_t *app = (app_t *)user;

    fprintf(stderr, "<-- reply  PD 0x%02X  cmd %s -> %s",
            e->pd_address, cmd_name(e->cmd_code), reply_name(e->reply_code));
    if (e->reply_code == OSDP_REPLY_NAK && e->payload_len >= 1) {
        fprintf(stderr, "  nak_code=0x%02X", e->payload[0]);
    }
    if (e->payload_len > 0) {
        fprintf(stderr, "  payload[%zu]=", e->payload_len);
        hex_dump(stderr, e->payload, e->payload_len);
    }
    fputc('\n', stderr);
    (void)app;
}

static void on_timeout(void *user, const osdp_acu_timeout_event_t *e)
{
    app_t *app = (app_t *)user;
    fprintf(stderr, "!!  timeout PD 0x%02X cmd %s seq %u (no reply in %u ms)\n",
            e->pd_address, cmd_name(e->cmd_code), e->cmd_seq,
            OSDP_ACU_REPLY_TIMEOUT_MS);
    (void)app;
}

static void on_sc_event(void *user, const osdp_acu_sc_event_t *e)
{
    app_t *app = (app_t *)user;
    const char *kind =
        e->kind == OSDP_ACU_SC_EVENT_ESTABLISHED      ? "ESTABLISHED"
      : e->kind == OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED ? "HANDSHAKE_FAILED"
                                                      : "SESSION_LOST";
    fprintf(stderr, "**  SC event PD 0x%02X: %s\n", e->pd_address, kind);

    switch (e->kind) {
    case OSDP_ACU_SC_EVENT_ESTABLISHED:
        /* Unblock the send cycle. */
        app->phase = SEND_PHASE_ID;
        break;
    case OSDP_ACU_SC_EVENT_HANDSHAKE_FAILED:
        /* Hard stop: a key mismatch isn't going to fix itself. Fall
         * back to plaintext mode for the rest of the run so the user
         * can still see what the PD is doing. */
        fprintf(stderr,
                "  (handshake failed — falling back to plaintext mode)\n");
        app->sc_enabled = false;
        app->phase      = SEND_PHASE_ID;
        break;
    case OSDP_ACU_SC_EVENT_SESSION_LOST:
        /* Soft loss (PD reboot, MAC desync, line went silent). The
         * helpful behavior for an interop tool is to immediately
         * re-handshake so the user doesn't have to restart the run. */
        fprintf(stderr, "  (auto-restarting handshake)\n");
        app->phase = SEND_PHASE_PENDING_SC;
        const osdp_status_t r = osdp_acu_start_sc_handshake(
            app->acu, app->pd_address, app->sc_use_default_key);
        if (r != OSDP_OK) {
            fprintf(stderr,
                    "  warning: re-handshake start failed (%d); will retry "
                    "on next idle tick\n", (int)r);
        }
        break;
    }
}

/* ---- CLI ----------------------------------------------------------- */

typedef struct cli {
    const char  *port;
    unsigned int baud;
    uint8_t      pd_address;
    enum {
        SC_NONE,
        SC_SCBKD,
        SC_SCBK_CUSTOM,
    }            sc_mode;
    uint8_t      sc_custom_key[OSDP_SC_KEY_LEN];
    unsigned int poll_interval_ms;
    int          verbose;
} cli_t;

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --port NAME           serial port (default $OSDP_INTEROP_ACU_PORT)\n"
        "                          Win32 examples: COM3, \\\\\\\\.\\\\COM23\n"
        "                          POSIX examples: /dev/ttyUSB0, /dev/cu.usbserial-XXX\n"
        "  --address N           PD address to drive (0x00..0x7E, default 0x00)\n"
        "  --baud N              baud rate (default 9600)\n"
        "  --poll-interval N     ms between commands (default 500)\n"
        "  --sc=MODE             Secure Channel: 'off' (default), 'scbkd' (SCBK-D),\n"
        "                                        'scbk:HEX32' (custom 16-byte key)\n"
        "  -v / -vv              verbose: -v prints sent commands, -vv adds idle ticks\n"
        "  -h, --help            this help\n"
        "\n"
        "Behavior: opens the port, registers the PD slot, optionally negotiates SC,\n"
        "then sends ID once, CAP once, and POLL on the configured interval. Replies\n"
        "and SC events are decoded to stderr.\n",
        prog);
}

static bool parse_hex_key(const char *s, uint8_t out[OSDP_SC_KEY_LEN])
{
    if (s == NULL || strlen(s) != OSDP_SC_KEY_LEN * 2U) return false;
    for (size_t i = 0; i < OSDP_SC_KEY_LEN; i++) {
        unsigned int b;
        if (sscanf(s + i * 2, "%2x", &b) != 1) return false;
        out[i] = (uint8_t)b;
    }
    return true;
}

static bool parse_args(int argc, char **argv, cli_t *out)
{
    (void)memset(out, 0, sizeof(*out));
    out->port             = getenv("OSDP_INTEROP_ACU_PORT");
    out->baud             = DEFAULT_BAUD;
    out->pd_address       = DEFAULT_PD_ADDRESS;
    out->sc_mode          = SC_NONE;
    out->poll_interval_ms = DEFAULT_POLL_INTERVAL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (strcmp(a, "-v") == 0) {
            out->verbose = 1;
        } else if (strcmp(a, "-vv") == 0) {
            out->verbose = 2;
        } else if (strcmp(a, "--port") == 0 && i + 1 < argc) {
            out->port = argv[++i];
        } else if (strcmp(a, "--baud") == 0 && i + 1 < argc) {
            out->baud = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(a, "--address") == 0 && i + 1 < argc) {
            const unsigned long v = strtoul(argv[++i], NULL, 0);
            if (v > 0x7EU) {
                fprintf(stderr, "address out of range: 0x%lx\n", v);
                return false;
            }
            out->pd_address = (uint8_t)v;
        } else if (strcmp(a, "--poll-interval") == 0 && i + 1 < argc) {
            out->poll_interval_ms =
                (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strncmp(a, "--sc=", 5) == 0) {
            const char *mode = a + 5;
            if (strcmp(mode, "off") == 0) {
                out->sc_mode = SC_NONE;
            } else if (strcmp(mode, "scbkd") == 0) {
                out->sc_mode = SC_SCBKD;
            } else if (strncmp(mode, "scbk:", 5) == 0) {
                if (!parse_hex_key(mode + 5, out->sc_custom_key)) {
                    fprintf(stderr,
                            "--sc=scbk:HEX requires 32 hex chars (16 bytes)\n");
                    return false;
                }
                out->sc_mode = SC_SCBK_CUSTOM;
            } else {
                fprintf(stderr, "unknown --sc mode: %s\n", mode);
                return false;
            }
        } else {
            fprintf(stderr, "unknown argument: %s\n", a);
            usage(argv[0]);
            return false;
        }
    }

    if (out->port == NULL || out->port[0] == '\0') {
        fprintf(stderr,
                "no port specified — set $OSDP_INTEROP_ACU_PORT or pass --port\n");
        return false;
    }
    return true;
}

/* ---- Send-cycle scheduler ------------------------------------------ */

/* Issue the next command in the cycle, assuming the slot isn't busy.
 * Returns true if a command was actually sent (so the caller can stamp
 * `last_send_ms`). Skipped silently while a SC handshake is pending. */
static bool maybe_send_next(app_t *app)
{
    /* Don't send anything while waiting for handshake completion. */
    if (app->phase == SEND_PHASE_PENDING_SC) {
        return false;
    }
    if (osdp_acu_is_pd_busy(app->acu, app->pd_address)) {
        return false;
    }

    uint8_t       cmd     = OSDP_CMD_POLL;
    const uint8_t *payload = NULL;
    size_t        plen    = 0;

    /* CAP requires a 1-byte "reply type" payload. ID accepts an
     * optional 1-byte selector; we send the standard 0x00 selector
     * which OSDP.Net and most PDs interpret as "PDID standard". */
    static const uint8_t id_payload [1] = { 0x00 };
    static const uint8_t cap_payload[1] = { 0x00 };

    switch (app->phase) {
    case SEND_PHASE_INIT:
    case SEND_PHASE_ID:
        cmd     = OSDP_CMD_ID;
        payload = id_payload;
        plen    = sizeof(id_payload);
        break;
    case SEND_PHASE_CAP:
        cmd     = OSDP_CMD_CAP;
        payload = cap_payload;
        plen    = sizeof(cap_payload);
        break;
    case SEND_PHASE_POLL:
        cmd     = OSDP_CMD_POLL;
        payload = NULL;
        plen    = 0;
        break;
    case SEND_PHASE_PENDING_SC:
        return false;
    }

    if (app->verbose >= 1) {
        fprintf(stderr, "--> send   PD 0x%02X  %s",
                app->pd_address, cmd_name(cmd));
        if (plen > 0) {
            fprintf(stderr, "  payload[%zu]=", plen);
            hex_dump(stderr, payload, plen);
        }
        fputc('\n', stderr);
    }

    const osdp_status_t r = osdp_acu_send_command(
        app->acu, app->pd_address, cmd, payload, plen);
    if (r != OSDP_OK) {
        fprintf(stderr, "  send_command(%s) failed: %d\n",
                cmd_name(cmd), (int)r);
        return false;
    }

    /* Advance phase. ID → CAP → POLL → POLL → ... */
    if (app->phase == SEND_PHASE_INIT || app->phase == SEND_PHASE_ID) {
        app->phase = SEND_PHASE_CAP;
    } else if (app->phase == SEND_PHASE_CAP) {
        app->phase = SEND_PHASE_POLL;
    }
    return true;
}

/* ---- Main ---------------------------------------------------------- */

int main(int argc, char **argv)
{
    cli_t cli;
    if (!parse_args(argc, argv, &cli)) return 2;

    /* Open the serial port. */
    osdp_acu_transport_t transport;
    char err[256];
    serial_ctx_t *serial = serial_open(cli.port, cli.baud,
                                       &transport, err, sizeof(err));
    if (serial == NULL) {
        fprintf(stderr, "osdp-acu-mock: %s\n", err);
        return 1;
    }

    /* Application state — supplied to every callback as user. */
    app_t app = {0};
    app.pd_address       = cli.pd_address;
    app.verbose          = cli.verbose;
    app.poll_interval_ms = cli.poll_interval_ms;
    app.sc_enabled       = (cli.sc_mode != SC_NONE);
    app.sc_use_default_key = (cli.sc_mode == SC_SCBKD);
    app.phase            = app.sc_enabled
                              ? SEND_PHASE_PENDING_SC
                              : SEND_PHASE_INIT;

    /* Initialise the ACU. One slot = one PD. */
    osdp_acu_t          acu;
    osdp_acu_pd_slot_t  slots[1];
    osdp_acu_init(&acu, slots, 1U);
    osdp_acu_set_transport       (&acu, &transport);
    osdp_acu_set_reply_handler   (&acu, on_reply,    &app);
    osdp_acu_set_timeout_handler (&acu, on_timeout,  &app);
    osdp_acu_set_sc_event_handler(&acu, on_sc_event, &app);
    if (osdp_acu_register_pd(&acu, 0U, cli.pd_address) != OSDP_OK) {
        fprintf(stderr, "osdp-acu-mock: register_pd(0x%02X) failed\n",
                cli.pd_address);
        serial_close(serial);
        return 1;
    }
    app.acu = &acu;

    /* Optionally configure Secure Channel. The crypto vtable + per-PD
     * key both need to be in place before start_sc_handshake. */
    if (app.sc_enabled) {
        osdp_acu_set_sc_crypto(&acu, acu_mock_aes_crypto());
        if (cli.sc_mode == SC_SCBKD) {
            osdp_acu_set_pd_scbk_d(&acu, cli.pd_address,
                                   OSDP_SCBK_DEFAULT);
        } else { /* SC_SCBK_CUSTOM */
            osdp_acu_set_pd_scbk(&acu, cli.pd_address,
                                 cli.sc_custom_key);
        }
        const osdp_status_t r = osdp_acu_start_sc_handshake(
            &acu, cli.pd_address, app.sc_use_default_key);
        if (r != OSDP_OK) {
            fprintf(stderr,
                    "osdp-acu-mock: start_sc_handshake failed: %d\n",
                    (int)r);
            serial_close(serial);
            return 1;
        }
    }

    fprintf(stderr,
            "osdp-acu-mock: ACU on %s @ %u baud, driving PD 0x%02X,"
            " SC=%s, poll-interval=%ums (Ctrl-C to exit)\n",
            cli.port, cli.baud, cli.pd_address,
            cli.sc_mode == SC_NONE   ? "off"
          : cli.sc_mode == SC_SCBKD  ? "SCBK-D"
                                     : "SCBK (custom)",
            cli.poll_interval_ms);

    signal(SIGINT, on_signal);

    /* Main tick loop. Tick the ACU often (every 2ms). Send the next
     * command on the configured interval once the slot is idle. */
    uint32_t now = transport.now_ms(transport.user);
    app.last_send_ms = now - cli.poll_interval_ms;  /* fire immediately */

    while (!g_should_exit) {
        osdp_acu_tick(&acu);

        now = transport.now_ms(transport.user);
        const uint32_t since = now - app.last_send_ms;
        if (since >= cli.poll_interval_ms) {
            if (maybe_send_next(&app)) {
                app.last_send_ms = now;
            }
        }

        serial_sleep_ms(MAIN_LOOP_TICK_MS);
    }

    fprintf(stderr, "\nosdp-acu-mock: shutting down\n");
    serial_close(serial);
    return 0;
}
