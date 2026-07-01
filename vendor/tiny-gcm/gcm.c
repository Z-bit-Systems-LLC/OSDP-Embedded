// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* AES-256-GCM (CTR + GHASH) over the AES-256 build of tiny-AES-c, per
 * NIST SP 800-38D. Compiled with the tiny_aes256 target, which supplies
 * AES256=1 and renames the tiny-AES public symbols to AES256_* so this
 * can coexist with the AES-128 build in one binary. Test/tool only. */

#include "gcm.h"

#include "aes.h"   /* vendor/tiny-aes/aes.h, compiled AES256 + renamed */

#include <string.h>

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

static void xor_bytes(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                      size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/* GF(2^128) multiply (right-shift, R = 0xe1||0^120). */
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
        const int lsb = v[15] & 1u;
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

static void ghash(const uint8_t h[16], const uint8_t *data, size_t len,
                  uint8_t y[16])
{
    size_t off = 0;
    while (off < len) {
        uint8_t blk[16] = {0};
        const size_t take = (len - off < 16u) ? (len - off) : 16u;
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

static void gctr(const uint8_t key[32], const uint8_t icb[16],
                 const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t cb[16];
    (void)memcpy(cb, icb, 16);
    size_t off = 0;
    while (off < len) {
        uint8_t ks[16];
        aes256_block(key, cb, ks);
        const size_t take = (len - off < 16u) ? (len - off) : 16u;
        xor_bytes(&out[off], &in[off], ks, take);
        inc32(cb);
        off += take;
    }
}

static void gcm_setup(const uint8_t key[32], const uint8_t nonce[12],
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
                    const uint8_t *ct, size_t ct_len, uint8_t tag[16])
{
    uint8_t s[16] = {0};
    ghash(h, aad, aad_len, s);
    ghash(h, ct, ct_len, s);
    uint8_t lenblk[16];
    const uint64_t aad_bits = (uint64_t)aad_len * 8u;
    const uint64_t ct_bits  = (uint64_t)ct_len * 8u;
    for (unsigned i = 0; i < 8; i++) {
        lenblk[i]     = (uint8_t)(aad_bits >> (56u - 8u * i));
        lenblk[8 + i] = (uint8_t)(ct_bits  >> (56u - 8u * i));
    }
    for (unsigned j = 0; j < 16; j++) {
        s[j] ^= lenblk[j];
    }
    gf_mult(s, h, s);
    xor_bytes(tag, s, ej0, 16);
}

void tiny_gcm256_encrypt(const uint8_t  key[32],
                         const uint8_t  nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt,  size_t pt_len,
                         uint8_t       *ct,
                         uint8_t        tag[16])
{
    uint8_t h[16], j0[16], ej0[16];
    gcm_setup(key, nonce, h, j0, ej0);
    uint8_t icb[16];
    (void)memcpy(icb, j0, 16);
    inc32(icb);
    if (pt_len > 0) {
        gctr(key, icb, pt, pt_len, ct);
    }
    gcm_tag(h, ej0, aad, aad_len, ct, pt_len, tag);
}

int tiny_gcm256_decrypt(const uint8_t  key[32],
                        const uint8_t  nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct,  size_t ct_len,
                        const uint8_t  tag[16],
                        uint8_t       *pt)
{
    uint8_t h[16], j0[16], ej0[16];
    gcm_setup(key, nonce, h, j0, ej0);

    uint8_t expected[16];
    gcm_tag(h, ej0, aad, aad_len, ct, ct_len, expected);

    uint8_t diff = 0;
    for (unsigned i = 0; i < 16; i++) {
        diff |= (uint8_t)(expected[i] ^ tag[i]);
    }
    if (diff != 0u) {
        return -1;
    }

    uint8_t icb[16];
    (void)memcpy(icb, j0, 16);
    inc32(icb);
    if (ct_len > 0) {
        gctr(key, icb, ct, ct_len, pt);
    }
    return 0;
}
