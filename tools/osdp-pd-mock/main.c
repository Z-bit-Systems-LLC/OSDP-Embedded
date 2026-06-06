// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp-pd-mock — interactive PD on a serial port.
 *
 * Acts as an OSDP Peripheral Device on a real (or virtual) RS-485 /
 * COM port, so a developer can validate this stack against an
 * independent ACU implementation (OSDP.Net's ACUConsole, a hardware
 * controller, etc.) by wiring the two together.
 *
 * Configuration is via CLI flags or the OSDP_INTEROP_PD_PORT env var.
 * Run with --help for the full list. The application command
 * callback handles a baseline set of commands (POLL, ID, CAP, LED,
 * BUZ, OUT, TEXT, COMSET, KEYSET) so the ACU's first poll, capability
 * exchange, and basic output exercise all work out of the box.
 *
 * Secure Channel is opt-in via --sc=scbkd (the spec's well-known
 * default install key) or --sc=scbk:HEX (a custom 32-hex-char key).
 *
 * This is a host tool, not a library — it links libc, parses argv,
 * and prints to stderr. The actual PD library (osdp::pd) and core
 * (osdp::core, osdp::messages) remain freestanding-friendly. */

#include "aes_adapter.h"
#include "osdp/osdp_commands.h"
#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_pd.h"
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

#define DEFAULT_BAUD     9600U
#define DEFAULT_ADDRESS  0x00U

/* Default PDID — vendor "ZBC" (made up, replace freely) + a fixed
 * version/serial. The first 8 bytes of this layout (vendor[3] +
 * model + version + serial[0..2]) form the cUID used by Secure
 * Channel handshakes. */
static const osdp_pdid_t kDefaultPdid = {
    .vendor_code    = { 'Z', 'B', 'C' },
    .model          = 0x01,
    .version        = 0x00,
    .serial         = 0x00000001UL,   /* LE on the wire */
    .firmware_major = 0,
    .firmware_minor = 1,
    .firmware_build = 0,
};

/* Default capability set, mirroring OSDP.Net's PDConsole reference PD
 * (src/PDConsole/appsettings.json) so an ACU that interoperates with
 * PDConsole treats this mock identically. Function codes follow spec
 * Annex B (== OSDP.Net's CapabilityFunction enum).
 *
 * The Communication Security record (FC 9) is what gates Secure Channel:
 * per spec B.10 BOTH bytes are "Bit 0 = AES128 support", so the
 * key-exchange (num_objects) byte must be 0x01. The previous value 0x04
 * left bit 0 CLEAR — advertising "no AES128 key exchange" — so a
 * spec-conformant ACU would never initiate a handshake. */
static const osdp_pdcap_record_t kDefaultPdcap[] = {
    { .function_code = 1,  .compliance_level = 4, .num_objects = 1 }, /* ContactStatusMonitoring */
    { .function_code = 2,  .compliance_level = 4, .num_objects = 1 }, /* OutputControl */
    { .function_code = 3,  .compliance_level = 1, .num_objects = 1 }, /* CardDataFormat */
    { .function_code = 4,  .compliance_level = 4, .num_objects = 1 }, /* ReaderLEDControl */
    { .function_code = 5,  .compliance_level = 2, .num_objects = 1 }, /* ReaderAudibleOutput */
    { .function_code = 6,  .compliance_level = 1, .num_objects = 1 }, /* ReaderTextOutput */
    { .function_code = 8,  .compliance_level = 1, .num_objects = 1 }, /* CheckCharacterSupport */
    { .function_code = 9,  .compliance_level = 1, .num_objects = 1 }, /* CommunicationSecurity (AES128) */
    { .function_code = 12, .compliance_level = 0, .num_objects = 0 }, /* SmartCardSupport */
    { .function_code = 13, .compliance_level = 0, .num_objects = 1 }, /* Readers */
    { .function_code = 16, .compliance_level = 2, .num_objects = 0 }, /* OSDPVersion */
    { .function_code = 17, .compliance_level = 1, .num_objects = 0 }, /* ExtendedIdResponse */
};
#define DEFAULT_PDCAP_COUNT (sizeof(kDefaultPdcap) / sizeof(kDefaultPdcap[0]))

/* ---- Application command handler ------------------------------------ */

typedef struct app_state {
    osdp_pdid_t          pdid;
    osdp_pdcap_record_t  pdcap[16];
    size_t               pdcap_count;
    uint8_t              address;
    int                  verbose;

    /* Scratch for build_* outputs returned to the PD via reply.payload. */
    uint8_t              scratch[OSDP_PD_TX_BUF_LEN];
} app_state_t;

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
    case OSDP_CMD_LSTAT:  return "LSTAT";
    case OSDP_CMD_ISTAT:  return "ISTAT";
    case OSDP_CMD_OSTAT:  return "OSTAT";
    case OSDP_CMD_RSTAT:  return "RSTAT";
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

/* ---- Raw RX tap (-vv) ------------------------------------------------ *
 * The application command handler only sees decoded, non-SCB commands;
 * Secure Channel handshake frames (CHLNG/SCRYPT) and SCS_15..18 wraps
 * are consumed below it and never surface. To diagnose whether an ACU
 * is even attempting SC, -vv wraps the transport read callback and dumps
 * every inbound byte chunk as it arrives off the wire. Tools may use
 * globals; the core library never does. */
static struct {
    int (*real_read)(void *user, uint8_t *buf, size_t cap);
    int verbose;
} g_tap;

static int read_tap(void *user, uint8_t *buf, size_t cap)
{
    const int n = g_tap.real_read(user, buf, cap);
    if (n > 0 && g_tap.verbose >= 2) {
        fprintf(stderr, "    rx[%d] ", n);
        hex_dump(stderr, buf, (size_t)n);
        fputc('\n', stderr);
    }
    return n;
}

/* Look up the declared object count for a PDCAP function code (e.g. the
 * number of inputs for FC1, outputs for FC2). Status reports must carry
 * one byte per declared object, so the report length is derived from the
 * advertised capabilities. Returns `dflt` when the function code isn't
 * present in the capability set. */
static uint8_t cap_num_objects(const app_state_t *s, uint8_t fc, uint8_t dflt)
{
    for (size_t i = 0; i < s->pdcap_count; i++) {
        if (s->pdcap[i].function_code == fc) {
            return s->pdcap[i].num_objects;
        }
    }
    return dflt;
}

static osdp_status_t app_handler(void           *user,
                                 uint8_t         cmd_code,
                                 const uint8_t  *payload,
                                 size_t          payload_len,
                                 osdp_pd_reply_t *reply)
{
    app_state_t *s = (app_state_t *)user;

    if (s->verbose >= 1) {
        fprintf(stderr, "<-- recv   PD 0x%02X  cmd %s",
                s->address, cmd_name(cmd_code));
        if (payload_len > 0) {
            fprintf(stderr, "  payload[%zu]=", payload_len);
            hex_dump(stderr, payload, payload_len);
        }
        fputc('\n', stderr);
    }

    osdp_status_t r = OSDP_OK;
    switch (cmd_code) {
    case OSDP_CMD_POLL:
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        break;

    case OSDP_CMD_ID: {
        size_t built = 0;
        r = osdp_pdid_build(&s->pdid, s->scratch,
                            sizeof(s->scratch), &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_PDID;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    case OSDP_CMD_CAP: {
        size_t built = 0;
        r = osdp_pdcap_build(s->pdcap, s->pdcap_count,
                             s->scratch, sizeof(s->scratch), &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_PDCAP;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    case OSDP_CMD_LED:
    case OSDP_CMD_BUZ:
    case OSDP_CMD_OUT:
    case OSDP_CMD_TEXT:
    case OSDP_CMD_KEYSET:
    case OSDP_CMD_COMSET:
        reply->code        = OSDP_REPLY_ACK;
        reply->payload     = NULL;
        reply->payload_len = 0;
        break;

    /* Status requests must be answered with the mandated report, not an
     * ACK (spec 7.6-7.9; mirrors OSDP.Net commit d42c1cad5). We report
     * a healthy device: no tamper, no power failure, all inputs/outputs
     * inactive, all readers normal. */
    case OSDP_CMD_LSTAT: {
        const osdp_lstatr_t st = {
            .tamper = OSDP_LSTATR_NORMAL,
            .power  = OSDP_LSTATR_NORMAL,
        };
        size_t built = 0;
        r = osdp_lstatr_build(&st, s->scratch, sizeof(s->scratch), &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_LSTATR;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    case OSDP_CMD_ISTAT: {
        uint8_t statuses[256];
        const uint8_t n = cap_num_objects(s, 1 /* contact monitor */, 1);
        (void)memset(statuses, OSDP_ISTATR_INACTIVE, n);
        size_t built = 0;
        r = osdp_istatr_build(statuses, n, s->scratch, sizeof(s->scratch),
                              &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_ISTATR;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    case OSDP_CMD_OSTAT: {
        uint8_t statuses[256];
        const uint8_t n = cap_num_objects(s, 2 /* output control */, 1);
        (void)memset(statuses, OSDP_OSTATR_INACTIVE, n);
        size_t built = 0;
        r = osdp_ostatr_build(statuses, n, s->scratch, sizeof(s->scratch),
                              &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_OSTATR;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    case OSDP_CMD_RSTAT: {
        uint8_t statuses[256];
        const uint8_t n = cap_num_objects(s, 13 /* readers */, 1);
        (void)memset(statuses, OSDP_RSTATR_NORMAL, n);
        size_t built = 0;
        r = osdp_rstatr_build(statuses, n, s->scratch, sizeof(s->scratch),
                              &built);
        if (r != OSDP_OK) { r = OSDP_ERR_BAD_PAYLOAD; break; }
        reply->code        = OSDP_REPLY_RSTATR;
        reply->payload     = s->scratch;
        reply->payload_len = built;
        break;
    }

    default:
        r = OSDP_ERR_NOT_SUPPORTED;
        break;
    }

    /* Mirror the outbound reply (or framework-synthesized NAK for an
     * unsupported command) so the user can see both halves of the
     * exchange. SC handshake / SCS_15..18 wrap-unwrap happen below this
     * layer and don't surface here. */
    if (r == OSDP_OK) {
        fprintf(stderr, "--> reply  PD 0x%02X  cmd %s -> %s",
                s->address, cmd_name(cmd_code), reply_name(reply->code));
        if (reply->payload_len > 0) {
            fprintf(stderr, "  payload[%zu]=", reply->payload_len);
            hex_dump(stderr, reply->payload, reply->payload_len);
        }
        fputc('\n', stderr);
    } else if (r == OSDP_ERR_NOT_SUPPORTED) {
        fprintf(stderr,
                "--> reply  PD 0x%02X  cmd %s -> NAK  nak_code=0x03\n",
                s->address, cmd_name(cmd_code));
    }

    return r;
}

/* ---- CLI -------------------------------------------------------------- */

typedef struct cli {
    const char  *port;
    unsigned int baud;
    uint8_t      address;
    enum {
        SC_NONE,
        SC_SCBKD,
        SC_SCBK_CUSTOM
    }            sc_mode;
    uint8_t      sc_custom_key[OSDP_SC_KEY_LEN];
    int          verbose;
} cli_t;

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --port NAME        serial port (default $OSDP_INTEROP_PD_PORT)\n"
        "                       Win32 examples: COM3, \\\\\\\\.\\\\COM23\n"
        "                       POSIX examples: /dev/ttyUSB0, /dev/cu.usbserial-XXX\n"
        "  --address N        7-bit PD address (0x00..0x7E, default 0x00)\n"
        "  --baud N           baud rate (default 9600)\n"
        "  --sc=MODE          Secure Channel: 'off' (default), 'scbkd' (SCBK-D),\n"
        "                                     'scbk:HEX32' (custom 16-byte key)\n"
        "  -v / -vv           print decoded commands (-v) or every byte (-vv)\n"
        "  -h, --help         this help\n",
        prog);
}

/* Parse 32 hex chars into a 16-byte key. Returns true on success. */
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
    out->port    = getenv("OSDP_INTEROP_PD_PORT");
    out->baud    = DEFAULT_BAUD;
    out->address = DEFAULT_ADDRESS;
    out->sc_mode = SC_NONE;
    out->verbose = 0;

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
            out->address = (uint8_t)v;
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
                "no port specified — set $OSDP_INTEROP_PD_PORT or pass --port\n");
        return false;
    }
    return true;
}

/* ---- Main ------------------------------------------------------------ */

/* Derive the 8-byte cUID from a PDID per spec D.4.3: cUID is the first
 * 8 bytes of the PDID byte stream (vendor[3] + model + version +
 * serial[0..2]). */
static void cuid_from_pdid(const osdp_pdid_t *pdid,
                           uint8_t out[OSDP_SC_CUID_LEN])
{
    uint8_t pdid_bytes[OSDP_PDID_PAYLOAD_BYTES];
    size_t  built = 0;
    if (osdp_pdid_build(pdid, pdid_bytes, sizeof(pdid_bytes), &built)
            != OSDP_OK || built < OSDP_SC_CUID_LEN) {
        (void)memset(out, 0, OSDP_SC_CUID_LEN);
        return;
    }
    (void)memcpy(out, pdid_bytes, OSDP_SC_CUID_LEN);
}

int main(int argc, char **argv)
{
    cli_t cli;
    if (!parse_args(argc, argv, &cli)) return 2;

    /* Application state for the command callback. */
    app_state_t app;
    (void)memset(&app, 0, sizeof(app));
    app.pdid        = kDefaultPdid;
    app.pdcap_count = DEFAULT_PDCAP_COUNT;
    (void)memcpy(app.pdcap, kDefaultPdcap, sizeof(kDefaultPdcap));
    app.address     = cli.address;
    app.verbose     = cli.verbose;

    /* Open the serial port. */
    osdp_pd_transport_t transport;
    char err[256];
    serial_ctx_t *serial = serial_open(cli.port, cli.baud,
                                       &transport, err, sizeof(err));
    if (serial == NULL) {
        fprintf(stderr, "osdp-pd-mock: %s\n", err);
        return 1;
    }

    /* Install the raw-RX tap (-vv) by wrapping the transport's read
     * callback before the PD copies the vtable. */
    g_tap.real_read = transport.read;
    g_tap.verbose   = cli.verbose;
    transport.read  = read_tap;

    /* Initialise the PD. */
    osdp_pd_t pd;
    osdp_pd_init(&pd, cli.address);
    osdp_pd_set_transport(&pd, &transport);
    osdp_pd_set_command_handler(&pd, app_handler, &app);

    /* Optionally configure Secure Channel. The crypto vtable, the cUID
     * (derived from our PDID), and the requested key all need to be
     * set before the first inbound CHLNG / SCRYPT. */
    if (cli.sc_mode != SC_NONE) {
        uint8_t cuid[OSDP_SC_CUID_LEN];
        cuid_from_pdid(&app.pdid, cuid);
        osdp_pd_set_sc_crypto(&pd, pd_mock_aes_crypto());
        osdp_pd_set_sc_cuid  (&pd, cuid);
        if (cli.sc_mode == SC_SCBKD) {
            osdp_pd_set_sc_scbk_d(&pd, OSDP_SCBK_DEFAULT);
        } else { /* SC_SCBK_CUSTOM */
            osdp_pd_set_sc_scbk(&pd, cli.sc_custom_key);
        }
    }

    fprintf(stderr,
            "osdp-pd-mock: PD listening on %s @ %u baud, address 0x%02x,"
            " SC=%s (Ctrl-C to exit)\n",
            cli.port, cli.baud, cli.address,
            cli.sc_mode == SC_NONE   ? "off"
          : cli.sc_mode == SC_SCBKD  ? "SCBK-D"
                                     : "SCBK (custom)");

    /* Catch Ctrl-C for orderly shutdown. */
    signal(SIGINT, on_signal);

    /* Tick loop. The application command callback can't observe Secure
     * Channel (CHLNG/SCRYPT and SCS_15..18 wrap/unwrap happen below it),
     * so watch the established flag here and announce transitions. */
    bool sc_was_up = false;
    while (!g_should_exit) {
        osdp_pd_tick(&pd);

        if (cli.sc_mode != SC_NONE) {
            const bool sc_now = osdp_pd_sc_established(&pd);
            if (sc_now != sc_was_up) {
                fprintf(stderr, "=== Secure Channel %s ===\n",
                        sc_now ? "ESTABLISHED" : "torn down");
                sc_was_up = sc_now;
            }
        }

        serial_sleep_ms(2);  /* a 9600-baud byte is ~1ms; 2ms is fine */
    }

    fprintf(stderr, "\nosdp-pd-mock: shutting down\n");
    serial_close(serial);
    return 0;
}
