// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* osdp-pair-provision — issue a PD pairing credential and emit it as a C
 * header a device build can #include.
 *
 * SC2 asymmetric pairing needs three things on the PD before it can run: a
 * C509 device certificate to present, the matching ML-DSA-44 private key, and
 * a trust anchor to authenticate the ACU against. Producing that set is an
 * offline step, not something a PD does at run time, so it lives in a host
 * tool.
 *
 * The trust anchor here is the OSDP.Net DEMONSTRATION CA, which is derived
 * from the published fixed seed 0x40..0x5F and is therefore reproducible by
 * anyone. That is what makes interop testing possible without exchanging key
 * material, and exactly why the output is unfit for production: every
 * "private" key it can issue is derivable by anyone who reads this file. The
 * emitted header says so, loudly.
 *
 * The CA's private key never reaches the emitted header — only the device's
 * own certificate and key, plus the CA's PUBLIC key as the anchor. A firmware
 * image has no use for a signing key it should never wield, and one sitting
 * in a build tree invites being mistaken for a real one.
 *
 * Host-only tool: stdio and stdlib are fine here, unlike core/ and pd/. */

#include "osdp/osdp_pair.h"
#include "osdp_pair_pqclean.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SHA-256 of the demo CA's ML-DSA-44 public key, as published by OSDP.Net and
 * pinned by tests/test_pair_crypto.c. Checked after regenerating the CA: if
 * the vendored PQClean ever changes how a seed expands into a keypair, every
 * credential this tool issues would silently stop chaining to the CA the peer
 * trusts, and the failure would surface as an unexplained pairing rejection
 * on a bench. Better to refuse here. */
static const uint8_t k_demo_ca_pubkey_sha256[32] = {
    0x6C,0x1C,0x65,0x07,0x19,0x79,0x22,0x5A,0x13,0x9B,0x3E,0xC8,0x46,0x88,
    0xE2,0x68,0x8E,0xC3,0x0F,0xAB,0xE8,0xCC,0x51,0x0C,0xB6,0x88,0xBC,0x43,
    0x5F,0x2D,0x3C,0xB9,
};

#define DEMO_CA_SEED_FIRST 0x40U
#define DEMO_CA_SEED_LEN   32U
#define DEMO_CA_NAME       "OSDP-DEMO-CA"

typedef struct {
    const char *out_path;
    const char *manufacturer;
    const char *model;
    const char *serial;
    unsigned    device_seed;
    const char *guard;
} cli_t;

static void usage(void)
{
    fprintf(stderr,
        "osdp-pair-provision — issue a demo-CA-signed PD pairing credential\n"
        "\n"
        "  --out <path>            header to write (default pair_credentials.h)\n"
        "  --manufacturer <text>   subject manufacturer (default \"Z-bit Systems\")\n"
        "  --model <text>          subject model        (default \"osdp-pd-mock\")\n"
        "  --serial <text>         subject serial       (default \"PD-0001\")\n"
        "  --device-seed <0-255>   first byte of the device key seed (default 0x80).\n"
        "                          The device key is derived deterministically, so a\n"
        "                          given seed always yields the same credential.\n"
        "  --guard <IDENT>         include guard (default OSDP_PAIR_CREDENTIALS_H)\n"
        "\n"
        "Output is DEMONSTRATION material: the CA is the published OSDP.Net demo\n"
        "CA and the device key is seed-derived, so both are reproducible by\n"
        "anyone. Use for interop and benchmarking only.\n");
}

static bool parse_args(int argc, char **argv, cli_t *out)
{
    out->out_path     = "pair_credentials.h";
    out->manufacturer = "Z-bit Systems";
    out->model        = "osdp-pd-mock";
    out->serial       = "PD-0001";
    out->device_seed  = 0x80U;
    out->guard        = "OSDP_PAIR_CREDENTIALS_H";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage();
            return false;
        } else if (strcmp(a, "--out") == 0 && i + 1 < argc) {
            out->out_path = argv[++i];
        } else if (strcmp(a, "--manufacturer") == 0 && i + 1 < argc) {
            out->manufacturer = argv[++i];
        } else if (strcmp(a, "--model") == 0 && i + 1 < argc) {
            out->model = argv[++i];
        } else if (strcmp(a, "--serial") == 0 && i + 1 < argc) {
            out->serial = argv[++i];
        } else if (strcmp(a, "--guard") == 0 && i + 1 < argc) {
            out->guard = argv[++i];
        } else if (strcmp(a, "--device-seed") == 0 && i + 1 < argc) {
            out->device_seed = (unsigned)strtoul(argv[++i], NULL, 0) & 0xFFU;
        } else {
            fprintf(stderr, "unknown option: %s\n\n", a);
            usage();
            return false;
        }
    }
    return true;
}

static void fill_iota(uint8_t *buf, size_t len, uint8_t first)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(first + i);
    }
}

/* Issue a C509 certificate for `subject_pubkey`, signed by `ca`. */
static osdp_status_t issue_cert(osdp_pair_crypto_t *ca,
                                const uint8_t subject_pubkey[OSDP_MLDSA44_PK_LEN],
                                const cli_t *cli,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    static const uint8_t serial_no[OSDP_C509_SERIAL_LEN] = {1,2,3,4,5,6,7,8};
    osdp_c509_cert_t cert = {
        .version            = OSDP_C509_VERSION,
        .serial             = serial_no,
        .serial_len         = sizeof(serial_no),
        .issuer             = DEMO_CA_NAME,
        .issuer_len         = sizeof(DEMO_CA_NAME) - 1,
        /* A wide window on purpose. Nothing checks it yet (see
         * docs/BENCHMARK_PD_PLAN.md section 2.1), and a credential that
         * expires mid-bench would be a confusing way to discover that. */
        .not_before         = 1700000000ULL,
        .not_after          = 4102444800ULL,   /* 2100-01-01 */
        .manufacturer       = cli->manufacturer,
        .manufacturer_len   = strlen(cli->manufacturer),
        .model              = cli->model,
        .model_len          = strlen(cli->model),
        .subject_serial     = cli->serial,
        .subject_serial_len = strlen(cli->serial),
        .public_key_alg     = OSDP_C509_ALG_MLDSA44,
        .public_key         = subject_pubkey,
        .public_key_len     = OSDP_MLDSA44_PK_LEN,
        .signature_alg      = OSDP_C509_ALG_MLDSA44,
        .signature          = NULL,
        .signature_len      = 0,
    };

    static uint8_t tbs[OSDP_C509_TBS_MAX];
    size_t tbs_n = 0;
    osdp_status_t s = osdp_c509_encode_tbs(&cert, tbs, sizeof(tbs), &tbs_n);
    if (s != OSDP_OK) {
        return s;
    }

    /* The signature covers the domain-separated TBS, not the TBS alone. */
    static const char dom[] = OSDP_C509_SIG_DOMAIN;
    const size_t dl = sizeof(dom) - 1;
    static uint8_t signed_msg[sizeof(dom) - 1 + OSDP_C509_TBS_MAX];
    (void)memcpy(signed_msg, dom, dl);
    (void)memcpy(&signed_msg[dl], tbs, tbs_n);

    static uint8_t sig[OSDP_MLDSA44_SIG_LEN];
    s = ca->ml_dsa44_sign(ca->user, signed_msg, dl + tbs_n, sig);
    if (s != OSDP_OK) {
        return s;
    }
    cert.signature     = sig;
    cert.signature_len = sizeof(sig);

    return osdp_c509_encode(&cert, out, out_cap, out_len);
}

static void emit_bytes(FILE *f, const char *name, const uint8_t *b, size_t n)
{
    fprintf(f, "static const uint8_t %s[%zu] = {\n", name, n);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%s0x%02X,", (i % 12 == 0) ? "    " : " ", b[i]);
        if (i % 12 == 11 || i + 1 == n) {
            fputc('\n', f);
        }
    }
    fprintf(f, "};\n\n");
}

int main(int argc, char **argv)
{
    cli_t cli;
    if (!parse_args(argc, argv, &cli)) {
        return 2;
    }

    static osdp_pair_pqclean_ctx_t ca_ctx, dev_ctx;
    static osdp_pair_crypto_t      ca_crypto, dev_crypto;
    osdp_pair_pqclean_crypto_init(&ca_crypto, &ca_ctx);
    osdp_pair_pqclean_crypto_init(&dev_crypto, &dev_ctx);

    /* --- Regenerate the demo CA and verify it is the published one. ------ */
    uint8_t ca_seed[DEMO_CA_SEED_LEN];
    fill_iota(ca_seed, sizeof(ca_seed), DEMO_CA_SEED_FIRST);
    osdp_pair_pqclean_seed_clear();
    osdp_pair_pqclean_seed_push(ca_seed, sizeof(ca_seed));
    if (osdp_pair_pqclean_gen_dsa(&ca_ctx) != OSDP_OK) {
        fprintf(stderr, "error: could not generate the demo CA keypair\n");
        return 1;
    }

    uint8_t ca_hash[32];
    if (ca_crypto.sha256(ca_crypto.user, ca_ctx.dsa_pk,
                         OSDP_MLDSA44_PK_LEN, ca_hash) != OSDP_OK) {
        fprintf(stderr, "error: SHA-256 of the CA public key failed\n");
        return 1;
    }
    if (memcmp(ca_hash, k_demo_ca_pubkey_sha256, sizeof(ca_hash)) != 0) {
        fprintf(stderr,
                "error: regenerated demo CA does not match the published\n"
                "       thumbprint. Credentials issued now would not chain to\n"
                "       the CA a peer trusts. Refusing to emit.\n");
        return 1;
    }

    /* --- Device keypair, derived from its own seed. ---------------------- */
    uint8_t dev_seed[DEMO_CA_SEED_LEN];
    fill_iota(dev_seed, sizeof(dev_seed), (uint8_t)cli.device_seed);
    osdp_pair_pqclean_seed_clear();
    osdp_pair_pqclean_seed_push(dev_seed, sizeof(dev_seed));
    if (osdp_pair_pqclean_gen_dsa(&dev_ctx) != OSDP_OK) {
        fprintf(stderr, "error: could not generate the device keypair\n");
        return 1;
    }

    /* Guard against the device seed colliding with the CA's: a device holding
     * the CA key could mint credentials for anything the peer trusts. */
    if (memcmp(dev_ctx.dsa_pk, ca_ctx.dsa_pk, OSDP_MLDSA44_PK_LEN) == 0) {
        fprintf(stderr,
                "error: --device-seed reproduces the demo CA's own key.\n");
        return 1;
    }

    static uint8_t cert[OSDP_PAIR_MSG_MAX];
    size_t cert_len = 0;
    if (issue_cert(&ca_crypto, dev_ctx.dsa_pk, &cli,
                   cert, sizeof(cert), &cert_len) != OSDP_OK) {
        fprintf(stderr, "error: could not issue the device certificate\n");
        return 1;
    }

    /* --- Emit. ----------------------------------------------------------- */
    FILE *f = fopen(cli.out_path, "w");
    if (f == NULL) {
        fprintf(stderr, "error: cannot open %s for writing\n", cli.out_path);
        return 1;
    }

    fprintf(f,
        "// SPDX-License-Identifier: GPL-3.0-or-later\n"
        "// Copyright (C) 2026 Z-bit Systems, LLC\n"
        "//\n"
        "// GENERATED by osdp-pair-provision. Do not edit.\n"
        "//\n"
        "// DEMONSTRATION CREDENTIALS — NOT FOR PRODUCTION.\n"
        "// The trust anchor is the OSDP.Net demo CA, derived from the published\n"
        "// seed 0x%02X..0x%02X, and the device key below is derived from seed\n"
        "// 0x%02X.. by the same public procedure. Both are reproducible by\n"
        "// anyone; the private key here is private in name only. Suitable for\n"
        "// interop and benchmarking, and for nothing else.\n"
        "//\n"
        "// Subject: %s / %s / %s\n"
        "\n"
        "#ifndef %s\n"
        "#define %s\n"
        "\n"
        "#include <stdint.h>\n"
        "\n",
        DEMO_CA_SEED_FIRST, DEMO_CA_SEED_FIRST + DEMO_CA_SEED_LEN - 1,
        cli.device_seed,
        cli.manufacturer, cli.model, cli.serial,
        cli.guard, cli.guard);

    fprintf(f,
        "/* Subject identity, for logging. */\n"
        "#define OSDP_PAIR_CREDENTIALS_SUBJECT \"%s / %s / %s\"\n\n",
        cli.manufacturer, cli.model, cli.serial);

    fprintf(f, "/* The PD's C509 certificate, signed by the demo CA. */\n");
    emit_bytes(f, "osdp_pair_device_cert", cert, cert_len);

    fprintf(f, "/* The PD's long-term ML-DSA-44 public key. */\n");
    emit_bytes(f, "osdp_pair_device_pk", dev_ctx.dsa_pk, OSDP_MLDSA44_PK_LEN);

    fprintf(f, "/* The PD's long-term ML-DSA-44 private key. */\n");
    emit_bytes(f, "osdp_pair_device_sk", dev_ctx.dsa_sk,
               OSDP_PAIR_PQCLEAN_DSA_SK_LEN);

    fprintf(f,
        "/* Trust anchor: the demo CA's PUBLIC key. Its private half is\n"
        " * deliberately absent — a PD never signs on the CA's behalf. */\n");
    emit_bytes(f, "osdp_pair_ca_pk", ca_ctx.dsa_pk, OSDP_MLDSA44_PK_LEN);

    fprintf(f, "#endif /* %s */\n", cli.guard);
    fclose(f);

    fprintf(stderr,
            "osdp-pair-provision: wrote %s\n"
            "  demo CA verified against the published thumbprint\n"
            "  device cert %zu bytes, subject %s / %s / %s\n",
            cli.out_path, cert_len,
            cli.manufacturer, cli.model, cli.serial);
    return 0;
}
