// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* The PQClean pairing port's entropy contract, exercised against the PLAIN
 * target — the one a tool or a firmware build links, without
 * OSDP_PAIR_PQCLEAN_DETERMINISTIC.
 *
 * Every key this backend produces is drawn from PQCLEAN_randombytes, which
 * PQClean leaves to the integrator. The failure mode worth a test is the
 * quiet one: a consumer that forgets to install a source, and gets working
 * keys anyway because something defaulted. Then the device pairs, the ACU is
 * satisfied, and the SCBK is predictable. So the property under test is that
 * key generation FAILS with no source installed.
 *
 * This is why the KAT build is a separate target rather than a run-time flag:
 * with the seed queue compiled in there is always a fallback, and this test
 * could not observe the absence of one. */

#include "osdp_pair_pqclean.h"
#include "unity.h"

#include <string.h>

static osdp_pair_pqclean_ctx_t ctx;
static int                     rand_calls;

void setUp(void)
{
    (void)memset(&ctx, 0, sizeof(ctx));
    rand_calls = 0;
    osdp_pair_pqclean_set_rand(NULL);
}
void tearDown(void) {}

/* Not a CSPRNG — this test is about the wiring, not the entropy quality. */
static int counting_rand(uint8_t *out, size_t n)
{
    rand_calls++;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(i * 7u + 3u);
    }
    return 0;
}

static int failing_rand(uint8_t *out, size_t n)
{
    (void)out; (void)n;
    rand_calls++;
    return -1;
}

/* With no source installed, key generation must fail rather than produce a
 * key from an improvised stream. */
static void test_keygen_fails_with_no_entropy_source(void)
{
    TEST_ASSERT_NOT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&ctx));
    TEST_ASSERT_FALSE(ctx.has_dsa);
}

/* Installing one makes it work, and the port really does route through it. */
static void test_keygen_uses_the_installed_source(void)
{
    osdp_pair_pqclean_set_rand(counting_rand);
    TEST_ASSERT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&ctx));
    TEST_ASSERT_TRUE(ctx.has_dsa);
    TEST_ASSERT_GREATER_THAN_INT(0, rand_calls);
}

/* A source that reports failure is propagated, not swallowed — an exhausted
 * or unavailable TRNG must not silently yield a key. */
static void test_entropy_failure_propagates(void)
{
    osdp_pair_pqclean_set_rand(failing_rand);
    TEST_ASSERT_NOT_EQUAL(OSDP_OK, osdp_pair_pqclean_gen_dsa(&ctx));
    TEST_ASSERT_FALSE(ctx.has_dsa);
    TEST_ASSERT_GREATER_THAN_INT(0, rand_calls);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_keygen_fails_with_no_entropy_source);
    RUN_TEST(test_keygen_uses_the_installed_source);
    RUN_TEST(test_entropy_failure_propagates);
    return UNITY_END();
}
