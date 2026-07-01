// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Self-contained Keccak-f[1600] + cSHAKE256 + KMAC256 for tests only.
 * Follows the public FIPS 202 (SHA-3 / SHAKE) and NIST SP 800-185
 * (cSHAKE, KMAC) algorithms. Correctness is pinned end-to-end by the
 * SC2 session-key known-answer vectors in test_sc2_primitives.c. */

#include "kmac.h"

#include <string.h>

/* ---- Keccak-f[1600] -----------------------------------------------------*/

#define KECCAK_ROUNDS 24

static uint64_t rotl64(uint64_t x, unsigned n)
{
    return (x << n) | (x >> (64u - n));
}

static const uint64_t k_rc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned k_rho[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned k_pi[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccak_f1600(uint64_t s[25])
{
    for (unsigned round = 0; round < KECCAK_ROUNDS; round++) {
        uint64_t bc[5];

        /* Theta. */
        for (unsigned i = 0; i < 5; i++) {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }
        for (unsigned i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (unsigned j = 0; j < 25; j += 5) {
                s[j + i] ^= t;
            }
        }

        /* Rho and Pi. */
        uint64_t t = s[1];
        for (unsigned i = 0; i < 24; i++) {
            unsigned j = k_pi[i];
            uint64_t tmp = s[j];
            s[j] = rotl64(t, k_rho[i]);
            t = tmp;
        }

        /* Chi. */
        for (unsigned j = 0; j < 25; j += 5) {
            for (unsigned i = 0; i < 5; i++) {
                bc[i] = s[j + i];
            }
            for (unsigned i = 0; i < 5; i++) {
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        /* Iota. */
        s[0] ^= k_rc[round];
    }
}

/* ---- Sponge (rate in bytes, arbitrary domain-suffix byte) ---------------*/

typedef struct {
    uint64_t state[25];
    uint8_t  buf[200];   /* byte view of the state for absorb/squeeze */
    size_t   rate;       /* bytes */
    size_t   pos;        /* bytes absorbed into the current block */
} keccak_ctx;

static void keccak_init(keccak_ctx *c, size_t rate)
{
    (void)memset(c, 0, sizeof(*c));
    c->rate = rate;
}

static void state_to_bytes(const uint64_t s[25], uint8_t out[200])
{
    for (unsigned i = 0; i < 25; i++) {
        uint64_t v = s[i];
        for (unsigned b = 0; b < 8; b++) {
            out[i * 8u + b] = (uint8_t)(v >> (8u * b));
        }
    }
}

static void bytes_to_state(const uint8_t in[200], uint64_t s[25])
{
    for (unsigned i = 0; i < 25; i++) {
        uint64_t v = 0;
        for (unsigned b = 0; b < 8; b++) {
            v |= (uint64_t)in[i * 8u + b] << (8u * b);
        }
        s[i] = v;
    }
}

static void keccak_absorb(keccak_ctx *c, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        c->buf[c->pos++] ^= data[i];  /* buf holds pending XOR block */
        if (c->pos == c->rate) {
            /* Fold buffered block into state and permute. */
            uint8_t tmp[200];
            state_to_bytes(c->state, tmp);
            for (size_t k = 0; k < c->rate; k++) {
                tmp[k] ^= c->buf[k];
            }
            bytes_to_state(tmp, c->state);
            keccak_f1600(c->state);
            (void)memset(c->buf, 0, sizeof(c->buf));
            c->pos = 0;
        }
    }
}

static void keccak_finalize(keccak_ctx *c, uint8_t domain)
{
    c->buf[c->pos]       ^= domain;      /* domain suffix + first pad bit */
    c->buf[c->rate - 1u] ^= 0x80u;       /* final pad bit */
    uint8_t tmp[200];
    state_to_bytes(c->state, tmp);
    for (size_t k = 0; k < c->rate; k++) {
        tmp[k] ^= c->buf[k];
    }
    bytes_to_state(tmp, c->state);
    keccak_f1600(c->state);
    c->pos = 0;
}

static void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len)
{
    size_t produced = 0;
    while (produced < len) {
        if (c->pos == 0) {
            state_to_bytes(c->state, c->buf);
        }
        size_t avail = c->rate - c->pos;
        size_t take  = (len - produced < avail) ? (len - produced) : avail;
        (void)memcpy(&out[produced], &c->buf[c->pos], take);
        c->pos += take;
        produced += take;
        if (c->pos == c->rate) {
            keccak_f1600(c->state);
            c->pos = 0;
        }
    }
}

/* ---- SP 800-185 string encodings ----------------------------------------*/

/* left_encode(x): 1 length byte + big-endian value bytes, minimum 1. */
static size_t left_encode(uint8_t out[9], uint64_t x)
{
    uint8_t tmp[8];
    size_t n = 0;
    do {
        tmp[n++] = (uint8_t)(x & 0xFFu);
        x >>= 8;
    } while (x != 0);
    out[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        out[1u + i] = tmp[n - 1u - i];   /* big-endian */
    }
    return n + 1u;
}

/* right_encode(x): big-endian value bytes + 1 trailing length byte. */
static size_t right_encode(uint8_t out[9], uint64_t x)
{
    uint8_t tmp[8];
    size_t n = 0;
    do {
        tmp[n++] = (uint8_t)(x & 0xFFu);
        x >>= 8;
    } while (x != 0);
    for (size_t i = 0; i < n; i++) {
        out[i] = tmp[n - 1u - i];
    }
    out[n] = (uint8_t)n;
    return n + 1u;
}

/* SHAKE256 rate = 136 bytes (capacity 512). cSHAKE256 shares it. */
#define CSHAKE256_RATE 136u

/* Absorb encode_string(s) = left_encode(bitlen) || s. */
static void absorb_encoded_string(keccak_ctx *c,
                                  const uint8_t *s, size_t s_len)
{
    uint8_t enc[9];
    size_t enc_len = left_encode(enc, (uint64_t)s_len * 8u);
    keccak_absorb(c, enc, enc_len);
    if (s_len > 0) {
        keccak_absorb(c, s, s_len);
    }
}

/* cSHAKE256 with function-name N and customization S, absorbing the
 * bytepad(encode_string(N)||encode_string(S), rate) prefix, then the
 * caller keeps absorbing X via the returned context. Domain suffix for
 * the customized path is 0x04 (bits "00" + pad start). */
static void cshake256_begin(keccak_ctx *c,
                            const uint8_t *n, size_t n_len,
                            const uint8_t *s, size_t s_len)
{
    keccak_init(c, CSHAKE256_RATE);

    /* bytepad(...) = left_encode(w) || encode_string(N) || encode_string(S)
     * then zero-pad to a multiple of w. We absorb the pieces and then
     * pad by absorbing zero bytes to the block boundary. */
    uint8_t wenc[9];
    size_t wlen = left_encode(wenc, CSHAKE256_RATE);
    keccak_absorb(c, wenc, wlen);
    absorb_encoded_string(c, n, n_len);
    absorb_encoded_string(c, s, s_len);

    /* Zero-pad to the rate boundary (bytepad). Absorbing 0x00 bytes is a
     * genuine XOR of zero — it only advances position / triggers the
     * permutation at the boundary. */
    if (c->pos != 0) {
        size_t pad = CSHAKE256_RATE - c->pos;
        uint8_t z[CSHAKE256_RATE];
        (void)memset(z, 0, pad);
        keccak_absorb(c, z, pad);
    }
}

void tiny_kmac256(const uint8_t *key,  size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t       *out,  size_t out_len)
{
    static const uint8_t kmac_name[4] = { 'K', 'M', 'A', 'C' };

    keccak_ctx c;
    /* KMAC256(K,X,L,S) = cSHAKE256(bytepad(encode_string(K),136) || X
     *                              || right_encode(L*8), L, "KMAC", S).
     * Here S is empty. */
    cshake256_begin(&c, kmac_name, sizeof(kmac_name), NULL, 0);

    /* newX prefix: bytepad(encode_string(K), 136). */
    uint8_t wenc[9];
    size_t wlen = left_encode(wenc, CSHAKE256_RATE);
    keccak_absorb(&c, wenc, wlen);
    absorb_encoded_string(&c, key, key_len);
    if (c.pos != 0) {
        size_t pad = CSHAKE256_RATE - c.pos;
        uint8_t z[CSHAKE256_RATE];
        (void)memset(z, 0, pad);
        keccak_absorb(&c, z, pad);
    }

    /* X = data. */
    if (data_len > 0) {
        keccak_absorb(&c, data, data_len);
    }

    /* right_encode(L) with L the requested output length in bits. */
    uint8_t renc[9];
    size_t rlen = right_encode(renc, (uint64_t)out_len * 8u);
    keccak_absorb(&c, renc, rlen);

    keccak_finalize(&c, 0x04u);   /* cSHAKE customized domain suffix */
    keccak_squeeze(&c, out, out_len);
}
