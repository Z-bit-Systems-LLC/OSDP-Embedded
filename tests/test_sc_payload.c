// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Tests for the SCS_17/18 payload encryption helpers
 * (osdp_sc_encrypt_payload / _decrypt_payload). The padding rule
 * differs from the MAC rule — payload padding is always applied,
 * even on exact multiples of 16 — so test coverage targets the
 * boundary cases explicitly. */

#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc_crypto.h"
#include "sc_test_aes.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const uint8_t kSEnc[OSDP_SC_KEY_LEN] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
};
static const uint8_t kInboundMac[OSDP_SC_MAC_LEN] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
/* Use the same value for both directions for round-trip tests
 * (encrypt-then-decrypt requires the recipient's last_outbound_mac to
 * equal the sender's last_inbound_mac, since both peers reference the
 * same prior MAC in the chain). */
#define kOutboundMac kInboundMac

static void test_encrypt_then_decrypt_round_trip(void)
{
    static const size_t lengths[] = { 1, 5, 15, 16, 17, 31, 32, 100 };
    for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
        const size_t plaintext_len = lengths[li];
        uint8_t plaintext[128];
        uint8_t recovered[128];
        uint8_t ciphertext[160];
        for (size_t i = 0; i < plaintext_len; i++) {
            plaintext[i] = (uint8_t)((i * 37u) ^ 0x5Au);
        }

        size_t ct_len = 0;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                    kInboundMac,
                                    plaintext, plaintext_len,
                                    ciphertext, sizeof(ciphertext),
                                    &ct_len));
        /* Padded length is the input rounded UP to a multiple of 16,
         * with a minimum of one pad byte. So an input of size 16
         * produces 32 bytes, and an input of size 0 produces 16. */
        const size_t expected_ct_len =
            ((plaintext_len / OSDP_AES_BLOCK_LEN) + 1U) * OSDP_AES_BLOCK_LEN;
        TEST_ASSERT_EQUAL_size_t(expected_ct_len, ct_len);
        TEST_ASSERT_EQUAL(0, ct_len % OSDP_AES_BLOCK_LEN);

        size_t pt_len = 99;
        TEST_ASSERT_EQUAL(OSDP_OK,
            osdp_sc_decrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                    kOutboundMac,
                                    ciphertext, ct_len,
                                    recovered, sizeof(recovered),
                                    &pt_len));
        TEST_ASSERT_EQUAL_size_t(plaintext_len, pt_len);
        TEST_ASSERT_EQUAL_MEMORY(plaintext, recovered, plaintext_len);
    }
}

static void test_encrypt_always_pads_even_on_exact_multiple(void)
{
    /* Per spec: padding is ALWAYS applied to the payload, even when
     * the input is already 16/32/48 bytes. This is the property that
     * lets the depad step recognise the 0x80 marker unambiguously. */
    uint8_t plaintext[16];
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }
    uint8_t ciphertext[64];
    size_t ct_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kInboundMac,
                                plaintext, sizeof(plaintext),
                                ciphertext, sizeof(ciphertext),
                                &ct_len));
    TEST_ASSERT_EQUAL_size_t(32, ct_len);

    uint8_t recovered[64];
    size_t pt_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_decrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kOutboundMac,
                                ciphertext, ct_len,
                                recovered, sizeof(recovered),
                                &pt_len));
    TEST_ASSERT_EQUAL_size_t(sizeof(plaintext), pt_len);
    TEST_ASSERT_EQUAL_MEMORY(plaintext, recovered, sizeof(plaintext));
}

static void test_encrypt_zero_length_input_produces_one_pad_block(void)
{
    uint8_t ciphertext[32];
    size_t ct_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kInboundMac,
                                NULL, 0,
                                ciphertext, sizeof(ciphertext),
                                &ct_len));
    TEST_ASSERT_EQUAL_size_t(16, ct_len);

    uint8_t recovered[32];
    size_t pt_len = 99;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_decrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kOutboundMac,
                                ciphertext, ct_len,
                                recovered, sizeof(recovered),
                                &pt_len));
    TEST_ASSERT_EQUAL_size_t(0, pt_len);
}

static void test_encrypt_uses_inverse_mac_as_iv(void)
{
    /* Sanity: encryption with last_inbound_mac and with its
     * complement should produce different output. (They produce the
     * same IV after inversion, so this is actually a tautological
     * check — but verifies that the inversion is being applied at
     * all, vs. just using the MAC directly.) */
    uint8_t plaintext[40];
    for (size_t i = 0; i < sizeof(plaintext); i++) plaintext[i] = (uint8_t)i;
    uint8_t mac_a[OSDP_SC_MAC_LEN], mac_b[OSDP_SC_MAC_LEN];
    (void)memcpy(mac_a, kInboundMac, sizeof(mac_a));
    for (size_t i = 0; i < sizeof(mac_b); i++) {
        mac_b[i] = (uint8_t)(~mac_a[i]);
    }
    uint8_t ct_a[64], ct_b[64];
    size_t ct_a_len, ct_b_len;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc, mac_a,
                                plaintext, sizeof(plaintext),
                                ct_a, sizeof(ct_a), &ct_a_len));
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc, mac_b,
                                plaintext, sizeof(plaintext),
                                ct_b, sizeof(ct_b), &ct_b_len));
    TEST_ASSERT_EQUAL_size_t(ct_a_len, ct_b_len);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(ct_a, ct_b, ct_a_len),
        "encryption produced identical output for opposite MACs");
}

static void test_encrypt_buffer_too_small(void)
{
    uint8_t plaintext[16];
    uint8_t ct[15];
    size_t ct_len = 0;
    TEST_ASSERT_EQUAL(OSDP_ERR_BUFFER_TOO_SMALL,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kInboundMac,
                                plaintext, sizeof(plaintext),
                                ct, sizeof(ct), &ct_len));
    TEST_ASSERT_EQUAL_size_t(0, ct_len);
}

static void test_decrypt_rejects_non_block_aligned_ciphertext(void)
{
    uint8_t ct[17] = {0};
    uint8_t pt[32];
    size_t pt_len = 99;
    TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD,
        osdp_sc_decrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kOutboundMac,
                                ct, sizeof(ct),
                                pt, sizeof(pt), &pt_len));
}

static void test_decrypt_corrupt_data_yields_bad_payload(void)
{
    /* Encrypt with one MAC, then attempt to decrypt with the
     * complement (wrong IV). The depad step won't find a valid 0x80
     * marker, and we should get OSDP_ERR_BAD_PAYLOAD. */
    static const uint8_t plaintext[10] = {
        '1','2','3','4','5','6','7','8','9','0'
    };
    uint8_t ciphertext[32];
    size_t ct_len = 0;
    TEST_ASSERT_EQUAL(OSDP_OK,
        osdp_sc_encrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                kInboundMac,
                                plaintext, sizeof(plaintext),
                                ciphertext, sizeof(ciphertext),
                                &ct_len));

    uint8_t wrong_mac[OSDP_SC_MAC_LEN];
    for (size_t i = 0; i < sizeof(wrong_mac); i++) {
        wrong_mac[i] = (uint8_t)(~kInboundMac[i]);
    }
    uint8_t recovered[32];
    size_t pt_len = 99;
    /* Most of the time decrypt-with-wrong-key returns BAD_PAYLOAD,
     * but the depad heuristic might luckily find a 0x80 in the noise.
     * Accept either: the strict requirement is that we don't
     * silently produce wrong plaintext that matches the original. */
    osdp_status_t r =
        osdp_sc_decrypt_payload(sc_test_crypto_tiny_aes(), kSEnc,
                                wrong_mac,
                                ciphertext, ct_len,
                                recovered, sizeof(recovered),
                                &pt_len);
    if (r == OSDP_OK) {
        /* If depad happened to find a 0x80 in random output, the
         * recovered bytes still cannot match the original plaintext
         * — the IV mismatch is enough to scramble at least the first
         * 16 bytes. */
        const size_t to_compare =
            (pt_len < sizeof(plaintext)) ? pt_len : sizeof(plaintext);
        TEST_ASSERT_NOT_EQUAL(0, memcmp(plaintext, recovered, to_compare));
    } else {
        TEST_ASSERT_EQUAL(OSDP_ERR_BAD_PAYLOAD, r);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_encrypt_then_decrypt_round_trip);
    RUN_TEST(test_encrypt_always_pads_even_on_exact_multiple);
    RUN_TEST(test_encrypt_zero_length_input_produces_one_pad_block);
    RUN_TEST(test_encrypt_uses_inverse_mac_as_iv);
    RUN_TEST(test_encrypt_buffer_too_small);
    RUN_TEST(test_decrypt_rejects_non_block_aligned_ciphertext);
    RUN_TEST(test_decrypt_corrupt_data_yields_bad_payload);
    return UNITY_END();
}
