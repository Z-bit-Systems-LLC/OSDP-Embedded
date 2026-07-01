// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "sc2_test_crypto.h"

#include "aes.h"    /* vendor/tiny-aes/aes.h, compiled here with AES256=1 */
#include "kmac.h"   /* tests/vendor/tiny-kmac */

#include <string.h>

/* ---- AES-256 single block (ECB) ----------------------------------------*/

static void aes256_block(const uint8_t key[32], const uint8_t in[16],
                         uint8_t out[16])
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    if (out != in) {
        (void)memcpy(out, in, 16);
    }
    AES_ECB_encrypt(&ctx, out);
}

static osdp_status_t adapter_ecb(
    void *user, const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    (void)user;
    aes256_block(key, in, out);
    return OSDP_OK;
}

/* ---- AES-256-GCM (CTR + GHASH over the AES-256 block) -------------------*/

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                      size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/* GF(2^128) multiply per SP 800-38D (right-shift, R = 0xe1||0^120). */
static void gf_mult(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    (void)memcpy(v, y, 16);
    for (unsigned i = 0; i < 128; i++) {
        if ((x[i >> 3] >> (7u - (i & 7u))) & 1u) {
            for (unsigned j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        const bool lsb = (v[15] & 1u) != 0u;
        for (unsigned j = 15; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xE1u;
        }
    }
    (void)memcpy(out, z, 16);
}

/* GHASH update: y = (y ^ block) * H over each 16-byte block, zero-padded. */
static void ghash(const uint8_t h[16], const uint8_t *data, size_t len,
                  uint8_t y[16])
{
    size_t off = 0;
    while (off < len) {
        uint8_t blk[16] = {0};
        size_t take = (len - off < 16u) ? (len - off) : 16u;
        (void)memcpy(blk, &data[off], take);
        for (unsigned j = 0; j < 16; j++) {
            y[j] ^= blk[j];
        }
        gf_mult(y, h, y);
        off += take;
    }
}

static void inc32(uint8_t ctr[16])
{
    for (unsigned i = 16; i-- > 12;) {
        if (++ctr[i] != 0u) {
            break;
        }
    }
}

/* GCTR: encrypt/decrypt `len` bytes with counter starting at `icb`. */
static void gctr(const uint8_t key[32], const uint8_t icb[16],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t cb[16];
    (void)memcpy(cb, icb, 16);
    size_t off = 0;
    while (off < len) {
        uint8_t ks[16];
        aes256_block(key, cb, ks);
        size_t take = (len - off < 16u) ? (len - off) : 16u;
        xor_block(&out[off], &in[off], ks, take);
        inc32(cb);
        off += take;
    }
}

static void ghash_lengths(uint8_t y[16], const uint8_t h[16],
                          uint64_t aad_bits, uint64_t ct_bits)
{
    uint8_t lenblk[16];
    for (unsigned i = 0; i < 8; i++) {
        lenblk[i]     = (uint8_t)(aad_bits >> (56u - 8u * i));
        lenblk[8 + i] = (uint8_t)(ct_bits  >> (56u - 8u * i));
    }
    for (unsigned j = 0; j < 16; j++) {
        y[j] ^= lenblk[j];
    }
    gf_mult(y, h, y);
}

static void gcm_setup(const uint8_t key[32],
                      const uint8_t nonce[12],
                      uint8_t h[16], uint8_t j0[16], uint8_t ej0[16])
{
    static const uint8_t zero[16] = {0};
    aes256_block(key, zero, h);
    (void)memcpy(j0, nonce, 12);
    j0[12] = 0x00; j0[13] = 0x00; j0[14] = 0x00; j0[15] = 0x01;
    aes256_block(key, j0, ej0);
}

static void gcm_tag(const uint8_t h[16], const uint8_t ej0[16],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len,
                    uint8_t tag[16])
{
    uint8_t s[16] = {0};
    ghash(h, aad, aad_len, s);
    ghash(h, ct, ct_len, s);
    ghash_lengths(s, h, (uint64_t)aad_len * 8u, (uint64_t)ct_len * 8u);
    xor_block(tag, s, ej0, 16);
}

static osdp_status_t adapter_gcm_encrypt(
    void *user, const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt, size_t pt_len,
    uint8_t *ct, uint8_t tag[16])
{
    (void)user;
    uint8_t h[16], j0[16], ej0[16];
    gcm_setup(key, nonce, h, j0, ej0);
    uint8_t icb[16];
    (void)memcpy(icb, j0, 16);
    inc32(icb);
    gctr(key, icb, pt, pt_len, ct);
    gcm_tag(h, ej0, aad, aad_len, ct, pt_len, tag);
    return OSDP_OK;
}

static osdp_status_t adapter_gcm_decrypt(
    void *user, const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    const uint8_t tag[16], uint8_t *pt)
{
    (void)user;
    uint8_t h[16], j0[16], ej0[16];
    gcm_setup(key, nonce, h, j0, ej0);

    uint8_t expected[16];
    gcm_tag(h, ej0, aad, aad_len, ct, ct_len, expected);

    /* Constant-time-ish compare (test code; timing isn't a concern). */
    uint8_t diff = 0;
    for (unsigned i = 0; i < 16; i++) {
        diff |= (uint8_t)(expected[i] ^ tag[i]);
    }
    if (diff != 0u) {
        return OSDP_ERR_BAD_CRC;
    }

    uint8_t icb[16];
    (void)memcpy(icb, j0, 16);
    inc32(icb);
    gctr(key, icb, ct, ct_len, pt);
    return OSDP_OK;
}

/* ---- KMAC256 -----------------------------------------------------------*/

static osdp_status_t adapter_kmac(
    void *user,
    const uint8_t *key,  size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_len)
{
    (void)user;
    tiny_kmac256(key, key_len, data, data_len, out, out_len);
    return OSDP_OK;
}

/* ---- RNG ---------------------------------------------------------------*/

static uint32_t g_prng_state = 0xCAFEBABEu;
static const uint8_t *g_fixed_rand     = NULL;
static size_t         g_fixed_rand_len = 0;

static osdp_status_t adapter_rand(void *user, uint8_t *out, size_t len)
{
    (void)user;
    if (g_fixed_rand != NULL && g_fixed_rand_len > 0) {
        for (size_t i = 0; i < len; i++) {
            out[i] = g_fixed_rand[i % g_fixed_rand_len];
        }
        return OSDP_OK;
    }
    for (size_t i = 0; i < len; i++) {
        g_prng_state = g_prng_state * 1103515245u + 12345u;
        out[i] = (uint8_t)(g_prng_state >> 16);
    }
    return OSDP_OK;
}

void sc2_test_crypto_seed_prng(uint32_t seed)
{
    g_prng_state = seed;
}

void sc2_test_crypto_set_fixed_rand(const uint8_t *buf, size_t len)
{
    g_fixed_rand     = (len > 0) ? buf : NULL;
    g_fixed_rand_len = (buf != NULL) ? len : 0;
}

static const osdp_sc2_crypto_t k_sc2_vtable = {
    .kmac256            = adapter_kmac,
    .aes256_gcm_encrypt = adapter_gcm_encrypt,
    .aes256_gcm_decrypt = adapter_gcm_decrypt,
    .aes256_ecb_encrypt = adapter_ecb,
    .rand_bytes         = adapter_rand,
    .user               = NULL,
};

const osdp_sc2_crypto_t *sc2_test_crypto(void)
{
    return &k_sc2_vtable;
}
